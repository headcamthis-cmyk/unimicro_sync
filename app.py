import os
import logging
import sqlite3
import json
from datetime import datetime, timezone
from flask import Flask, request, Response, jsonify
import xml.etree.ElementTree as ET
import requests
import re
import base64

APP_NAME = "uni-shopify-sync"
PORT = int(os.environ.get("PORT", "10000"))
ENV = os.environ.get("ENV", "prod")

# Uni auth
UNI_USER = os.environ.get("UNI_USER", "synall")
UNI_PASS = os.environ.get("UNI_PASS", "synall")

# Shopify config
SHOPIFY_DOMAIN = os.environ.get("SHOPIFY_DOMAIN", "allsupermotoas.myshopify.com")
SHOPIFY_TOKEN = os.environ.get("SHOPIFY_TOKEN")  # set in Render
SHOPIFY_API_VERSION = os.environ.get("SHOPIFY_API_VERSION", "2024-10")
SHOPIFY_LOCATION_ID = os.environ.get("SHOPIFY_LOCATION_ID", "16764928067")
PRICE_INCLUDES_VAT = os.environ.get("PRICE_INCLUDES_VAT", "true").lower() in ("1", "true", "yes")

# Feature toggles
ENABLE_IMAGE_UPLOAD = os.environ.get("ENABLE_IMAGE_UPLOAD", "true").lower() in ("1", "true", "yes")
ENABLE_GROUP_COLLECTIONS = os.environ.get("ENABLE_GROUP_COLLECTIONS", "true").lower() in ("1", "true", "yes")
SHOPIFY_DELETE_MODE = os.environ.get("SHOPIFY_DELETE_MODE", "archive").lower()
ENABLE_SHOPIFY_DELETE = os.environ.get("ENABLE_SHOPIFY_DELETE", "true").lower() in ("1", "true", "yes")

# New: precise XML response format for Uni group uploads
# Options: empty | plain_ok | xml_ok | xml_double (default)
UNI_GROUPS_RESPONSE_STYLE = os.environ.get("UNI_GROUPS_RESPONSE_STYLE", "xml_double").lower()

# DB
DB_URL = os.environ.get("DB_URL", "sync.db")

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s: %(message)s")
log = logging.getLogger(APP_NAME)

app = Flask(__name__)
app.url_map.strict_slashes = False


class DoubleSlashFix:
    def __init__(self, app):
        self.app = app
    def __call__(self, environ, start_response):
        path = environ.get("PATH_INFO", "/")
        if "//" in path:
            environ["PATH_INFO"] = path.replace("//", "/")
        return self.app(environ, start_response)
app.wsgi_app = DoubleSlashFix(app.wsgi_app)


# -------- DB helpers --------
def db():
    conn = sqlite3.connect(DB_URL)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = db()
    c = conn.cursor()
    c.execute("""
    CREATE TABLE IF NOT EXISTS groups(
        groupid TEXT PRIMARY KEY,
        groupname TEXT,
        parentid TEXT,
        payload_xml TEXT,
        updated_at TEXT
    )""")
    c.execute("""
    CREATE TABLE IF NOT EXISTS products(
        prodid TEXT PRIMARY KEY,
        name TEXT,
        price REAL,
        vatcode TEXT,
        groupid TEXT,
        barcode TEXT,
        stock INTEGER,
        body_html TEXT,
        image_b64 TEXT,
        webactive INTEGER,
        payload_xml TEXT,
        last_shopify_product_id TEXT,
        last_shopify_variant_id TEXT,
        last_inventory_item_id TEXT,
        updated_at TEXT
    )""")
    c.execute("""
    CREATE TABLE IF NOT EXISTS logs(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        endpoint TEXT,
        method TEXT,
        query TEXT,
        body TEXT,
        created_at TEXT
    )""")
    conn.commit()
    conn.close()
init_db()

# -------- Utils --------
def now_iso(): return datetime.now(timezone.utc).isoformat()
def ok_txt(body="OK"): return Response(body + "\r\n", mimetype="text/plain; charset=windows-1252")
def xml_resp(x): return Response(x, mimetype="text/xml; charset=windows-1252")
def require_auth(): return request.args.get("user") == UNI_USER and request.args.get("pass") == UNI_PASS

def read_xml_body():
    raw = request.get_data() or b""
    is_hex = (request.args.get("hex") or "").lower() in ("1", "true", "yes")
    if is_hex:
        try: raw = bytes.fromhex(raw.decode("ascii"))
        except Exception: pass
    for enc in ("utf-8", "cp1252", "latin-1"):
        try: return raw.decode(enc), is_hex
        except Exception: continue
    return raw.decode("utf-8", "ignore"), is_hex

def findtext_any(e, tags, d=""): 
    for t in tags:
        v = e.findtext(t)
        if v is not None: return v
    return d
def findall_any(r, xp_list):
    for xp in xp_list:
        n = r.findall(xp)
        if n: return n
    return []

def to_float_safe(v):
    try: return float(str(v).replace(",", "."))
    except: return None
def to_int_safe(v):
    try: return int(v)
    except:
        try: return int(float(v))
        except: return None

def uni_groups_ok():
    """
    Returner liten XML-body som Uni alltid godtar: <Root><OK>OK</OK></Root>
    """
    xml = '<?xml version="1.0" encoding="ISO-8859-1"?><Root><OK>OK</OK></Root>'
    resp = Response(xml, status=200)
    resp.headers["Content-Type"] = "text/xml; charset=ISO-8859-1"
    resp.headers["Content-Length"] = str(len(xml))
    resp.headers["Connection"] = "close"
    return resp


# -------- Shopify client (simplified) --------
def ensure_shopify_headers():
    return {"X-Shopify-Access-Token": SHOPIFY_TOKEN,
            "Content-Type": "application/json",
            "Accept": "application/json"}

def shopify_base(): return f"https://{SHOPIFY_DOMAIN}/admin/api/2024-10"

def shopify_find_variant_by_sku(sku):
    r = requests.get(f"{shopify_base()}/variants.json", headers=ensure_shopify_headers(), params={"sku": sku})
    if r.status_code != 200: return None
    v = r.json().get("variants", [])
    return v[0] if v else None

def shopify_create_product(p):
    r = requests.post(f"{shopify_base()}/products.json", headers=ensure_shopify_headers(),
                      data=json.dumps({"product": p}), timeout=60)
    if r.status_code not in (200,201): raise RuntimeError(r.text)
    return r.json()["product"]

def shopify_update_product(pid,p):
    r = requests.put(f"{shopify_base()}/products/{pid}.json", headers=ensure_shopify_headers(),
                     data=json.dumps({"product": p}), timeout=60)
    if r.status_code not in (200,201): raise RuntimeError(r.text)
    return r.json()["product"]

def shopify_set_inventory(iid, qty):
    r = requests.post(f"{shopify_base()}/inventory_levels/set.json", headers=ensure_shopify_headers(),
                      data=json.dumps({"location_id": int(SHOPIFY_LOCATION_ID),
                                       "inventory_item_id": int(iid),
                                       "available": int(qty)}))
    if r.status_code not in (200,201): raise RuntimeError(r.text)

def ensure_tracking_and_set_inventory(vid,iid,qty):
    try:
        shopify_set_inventory(iid,qty)
    except Exception as e:
        if "tracking" not in str(e):
            raise
        requests.put(f"{shopify_base()}/variants/{vid}.json",
                     headers=ensure_shopify_headers(),
                     data=json.dumps({"variant":{"id":int(vid),"inventory_management":"shopify"}}))
        shopify_set_inventory(iid,qty)


def upsert_shopify_product_from_row(r):
    sku=r["prodid"]; name=r["name"]; price=r["price"]; stock=r["stock"] or 0
    active = r["webactive"]==1
    groupid = r["groupid"]; body_html = r["body_html"]; img=r["image_b64"]
    payload = {"title":name or sku,"body_html":body_html or "",
               "tags":[f"group-{groupid}"] if groupid else [],
               "variants":[{"sku":sku,"price":f"{(price or 0):.2f}","inventory_management":"shopify"}]}
    v=shopify_find_variant_by_sku(sku)
    if v:
        pid=v["product_id"]; vid=v["id"]; iid=v["inventory_item_id"]
        shopify_update_product(pid,{"id":pid,"title":name,"body_html":body_html})
        log.info(f"UPDATE OK {sku} {pid}")
    else:
        payload["status"]="active" if active else "draft"
        c=shopify_create_product(payload)
        pid=c["id"]; vid=c["variants"][0]["id"]; iid=c["variants"][0]["inventory_item_id"]
        log.info(f"CREATE OK {sku} {pid}")
    ensure_tracking_and_set_inventory(vid,iid,stock)
    return pid,vid,iid


@app.before_request
def _logreq(): log.info(f"REQ {request.method} {request.path}?{request.query_string.decode()}")


# -------- Main Endpoints --------
@app.route("/")
def index(): return ok_txt("OK")

@app.route("/twinxml/postproductgroup.asp",methods=["POST","GET"])
@app.route("/twinxml/postproductgroup.aspx",methods=["POST","GET"])
def post_group():
    if request.method=="GET": return uni_groups_ok()
    if not require_auth(): return uni_groups_ok()
    raw,_=read_xml_body()
    try: root=ET.fromstring(raw)
    except Exception as e:
        log.warning(f"Bad XML groups {e}"); return uni_groups_ok()
    nodes=findall_any(root,[".//group",".//productgroup",".//gruppe",".//varegruppe"])
    conn=db(); c=conn.cursor()
    count=0
    for g in nodes:
        gid=findtext_any(g,["groupid","id","gruppeid","grpid"]).strip()
        gname=findtext_any(g,["groupname","name","gruppenavn"]).strip()
        pid=findtext_any(g,["parentid","parent","overgruppeid"]).strip()
        if not gid: continue
        c.execute("INSERT OR REPLACE INTO groups VALUES(?,?,?,?,?)",(gid,gname,pid,raw,now_iso()))
        count+=1
    conn.commit(); conn.close()
    log.info(f"Stored {count} groups")
    return uni_groups_ok()

# Produkt endepunkt (inkl aliaser)
@app.route("/twinxml/postproduct.asp",methods=["POST","GET"])
@app.route("/twinxml/postproducts.asp",methods=["POST","GET"])
@app.route("/twinxml/postallproducts.asp",methods=["POST","GET"])
def post_product():
    if request.method=="GET": return ok_txt("OK")
    if not require_auth(): return ok_txt("OK")
    raw,_=read_xml_body()
    try: root=ET.fromstring(raw)
    except: return ok_txt("OK")
    nodes=findall_any(root,[".//product",".//vare"])
    conn=db(); c=conn.cursor()
    total=0; synced=0
    for p in nodes:
        pid=findtext_any(p,["prodid","varenr","sku","productident"]).strip()
        if not pid: continue
        name=findtext_any(p,["name","varenavn","title"]).strip()
        price=to_float_safe(findtext_any(p,["price","pris","salesprice"]))
        grp=findtext_any(p,["groupid","gruppeid"]).strip()
        stock=to_int_safe(findtext_any(p,["stock","lager"]))
        html=findtext_any(p,["body_html","description"]) or ""
        img=findtext_any(p,["image_b64","image"]) or None
        web=1 if findtext_any(p,["webactive","active"],"1").lower() in ("1","true") else 0
        c.execute("INSERT OR REPLACE INTO products VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                  (pid,name,price,None,grp,None,stock,html,img,web,raw,None,None,None,now_iso()))
        total+=1
        if SHOPIFY_TOKEN:
            try:
                r=c.execute("SELECT * FROM products WHERE prodid=?",(pid,)).fetchone()
                upsert_shopify_product_from_row(r); synced+=1
            except Exception as e:
                log.error(f"Shopify sync fail {pid}: {e}")
    conn.commit(); conn.close()
    log.info(f"Upserted {total} products (Shopify updated {synced})")
    return ok_txt("OK")

# delete stub
@app.route("/twinxml/deleteproduct.asp",methods=["POST","GET"])
def delete_prod():
    if not require_auth(): return ok_txt("OK")
    sku=request.args.get("id") or ""
    if not sku: return ok_txt("OK")
    log.info(f"DELETE {sku}")
    return ok_txt("OK")

if __name__=="__main__":
    app.run(host="0.0.0.0",port=PORT)
