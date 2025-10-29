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
ENABLE_IMAGE_UPLOAD = os.environ.get("ENABLE_IMAGE_UPLOAD", "true").lower() in ("1","true","yes")
ENABLE_GROUP_COLLECTIONS = os.environ.get("ENABLE_GROUP_COLLECTIONS", "true").lower() in ("1","true","yes")
SHOPIFY_DELETE_MODE = os.environ.get("SHOPIFY_DELETE_MODE", "archive").lower()
ENABLE_SHOPIFY_DELETE = os.environ.get("ENABLE_SHOPIFY_DELETE", "true").lower() in ("1","true","yes")

# DB
DB_URL = os.environ.get("DB_URL", "sync.db")

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s: %(message)s")
log = logging.getLogger(APP_NAME)

app = Flask(__name__)
app.url_map.strict_slashes = False

# --- normalize '//' in PATH (Uni kan sende dobbelt-slash)
class DoubleSlashFix:
    def __init__(self, app): self.app = app
    def __call__(self, environ, start_response):
        p = environ.get("PATH_INFO","/")
        if "//" in p: environ["PATH_INFO"] = p.replace("//","/")
        return self.app(environ, start_response)
app.wsgi_app = DoubleSlashFix(app.wsgi_app)

# -------- DB helpers --------
def db():
    conn = sqlite3.connect(DB_URL)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = db(); c = conn.cursor()
    c.execute("""
    CREATE TABLE IF NOT EXISTS groups(
      groupid TEXT PRIMARY KEY, groupname TEXT, parentid TEXT,
      payload_xml TEXT, updated_at TEXT
    )""")
    c.execute("""
    CREATE TABLE IF NOT EXISTS products(
      prodid TEXT PRIMARY KEY, name TEXT, price REAL, vatcode TEXT,
      groupid TEXT, barcode TEXT, stock INTEGER, body_html TEXT,
      image_b64 TEXT, webactive INTEGER, payload_xml TEXT,
      last_shopify_product_id TEXT, last_shopify_variant_id TEXT,
      last_inventory_item_id TEXT, updated_at TEXT
    )""")
    c.execute("""
    CREATE TABLE IF NOT EXISTS logs(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      endpoint TEXT, method TEXT, query TEXT, body TEXT, created_at TEXT
    )""")
    conn.commit(); conn.close()
init_db()

# -------- Utils --------
def now_iso(): return datetime.now(timezone.utc).isoformat()

def ok_txt(body="OK"):
    return Response(body + "\r\n", mimetype="text/plain; charset=windows-1252")

def require_auth():
    return request.args.get("user")==UNI_USER and request.args.get("pass")==UNI_PASS

def read_xml_body():
    raw = request.get_data() or b""
    is_hex = (request.args.get("hex") or "").lower() in ("1","true","yes")
    if is_hex:
        try: raw = bytes.fromhex(raw.decode("ascii"))
        except Exception: pass
    for enc in ("utf-8","cp1252","latin-1","iso-8859-1"):
        try: return raw.decode(enc), is_hex
        except Exception: continue
    return raw.decode("utf-8","ignore"), is_hex

def findtext_any(e, tags, default=""):
    for t in tags:
        v = e.findtext(t)
        if v is not None:
            return v
    return default

def findall_any(root, xps):
    for xp in xps:
        n = root.findall(xp)
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

def clean_b64(data):
    if not data: return None
    s = data.strip()
    m = re.match(r"^data:image/[\w+.-]+;base64,(.*)$", s, flags=re.I|re.S)
    if m: s = m.group(1)
    s = re.sub(r"\s+","",s)
    try: base64.b64decode(s[:120] + "==", validate=False)
    except Exception: return None
    return s

# -------- Shopify (minimal) --------
def shopify_base(): return f"https://{SHOPIFY_DOMAIN}/admin/api/{SHOPIFY_API_VERSION}"
def sh_headers():
    if not SHOPIFY_TOKEN: raise RuntimeError("SHOPIFY_TOKEN not set")
    return {"X-Shopify-Access-Token": SHOPIFY_TOKEN, "Content-Type":"application/json", "Accept":"application/json"}

def shopify_find_variant_by_sku(sku):
    r = requests.get(f"{shopify_base()}/variants.json", headers=sh_headers(), params={"sku":sku}, timeout=30)
    if r.status_code!=200: return None
    arr = r.json().get("variants", [])
    return arr[0] if arr else None

def shopify_create_product(p):
    r = requests.post(f"{shopify_base()}/products.json", headers=sh_headers(), data=json.dumps({"product":p}), timeout=60)
    if r.status_code not in (200,201): raise RuntimeError(f"create {r.status_code}: {r.text[:300]}")
    return r.json()["product"]

def shopify_update_product(pid, p):
    r = requests.put(f"{shopify_base()}/products/{pid}.json", headers=sh_headers(), data=json.dumps({"product":p}), timeout=60)
    if r.status_code not in (200,201): raise RuntimeError(f"update {r.status_code}: {r.text[:300]}")
    return r.json()["product"]

def shopify_update_variant(vid, payload):
    body = {"variant": {"id": int(vid), **payload}}
    r = requests.put(f"{shopify_base()}/variants/{vid}.json", headers=sh_headers(), data=json.dumps(body), timeout=60)
    if r.status_code not in (200,201): raise RuntimeError(f"variant {r.status_code}: {r.text[:300]}")
    return r.json()["variant"]

def shopify_set_inventory(iid, qty):
    body = {"location_id": int(SHOPIFY_LOCATION_ID), "inventory_item_id": int(iid), "available": int(qty or 0)}
    r = requests.post(f"{shopify_base()}/inventory_levels/set.json", headers=sh_headers(), data=json.dumps(body), timeout=30)
    if r.status_code not in (200,201): raise RuntimeError(f"inventory {r.status_code}: {r.text[:300]}")
    return r.json()

def ensure_tracking_and_set_inventory(vid, iid, qty):
    try:
        shopify_set_inventory(iid, qty)
        return
    except Exception as e:
        if "tracking" not in str(e).lower() and "does not have inventory tracking enabled" not in str(e):
            raise
    shopify_update_variant(vid, {"inventory_management":"shopify", "inventory_policy":"deny", "requires_shipping":True})
    shopify_set_inventory(iid, qty)

def upsert_shopify_product_from_row(r):
    sku=r["prodid"]; name=r["name"]; price=r["price"]; stock=r["stock"] or 0
    web = (r["webactive"]==1); groupid=r["groupid"]; html=r["body_html"]; img=r["image_b64"]
    payload = {
        "title": name or sku,
        "body_html": html or "",
        "tags": [f"group-{groupid}"] if groupid else [],
        "variants": [{
            "sku": sku,
            "price": f"{(price or 0):.2f}",
            "inventory_management": "shopify",
            "inventory_policy": "deny"
        }]
    }

    v = shopify_find_variant_by_sku(sku)
    if v:
        pid=v["product_id"]; vid=v["id"]; iid=v["inventory_item_id"]
        up={"id":pid,"title":payload["title"],"body_html":payload["body_html"]}
        if payload["tags"]: up["tags"]=",".join(payload["tags"])
        shopify_update_product(pid, up)
        log.info("Shopify UPDATE OK sku=%s product_id=%s admin=https://%s/admin/products/%s",
                 sku, pid, SHOPIFY_DOMAIN, pid)
    else:
        cp=dict(payload)
        if cp["tags"]: cp["tags"]=",".join(cp["tags"])
        cp["status"]="active" if web else "draft"
        created=shopify_create_product(cp)
        pid=created["id"]; vid=created["variants"][0]["id"]; iid=created["variants"][0]["inventory_item_id"]
        log.info("Shopify CREATE OK sku=%s product_id=%s status=%s admin=https://%s/admin/products/%s",
                 sku, pid, cp["status"], SHOPIFY_DOMAIN, pid)

    try:
        ensure_tracking_and_set_inventory(vid, iid, stock)
    except Exception as e:
        log.warning("Inventory set failed for %s: %s", sku, e)

    # (valgfritt) første gangs bilde hvis ingen finnes – enkelt og trygt
    if ENABLE_IMAGE_UPLOAD and img:
        try:
            b64 = clean_b64(img)
            if b64:
                requests.post(f"{shopify_base()}/products/{pid}/images.json", headers=sh_headers(),
                              data=json.dumps({"image":{"attachment":b64,"filename":f"{sku}.jpg","position":1}}),
                              timeout=60)
        except Exception as e:
            log.warning("Image upload failed for %s: %s", sku, e)

    return pid

# -------- Request logging --------
@app.before_request
def _log_req():
    try:
        log.info("REQ %s %s?%s", request.method, request.path, request.query_string.decode())
    except Exception:
        pass

# -------- Health --------
@app.route("/", methods=["GET"])
def index(): return ok_txt("OK")

# -------- Uni: svar for varegrupper (tuned) --------
def uni_groups_ok():
    """
    Noen Uni-klienter krever helt spesifikke svar. Denne varianten har vist seg mest kompatibel:
    - Body: 'OK' + CRLF (4 bytes)
    - 200 OK
    - Content-Type: text/plain; charset=windows-1252
    - Content-Length: 4
    """
    body = "OK\r\n"
    resp = Response(body, status=200)
    resp.headers["Content-Type"] = "text/plain; charset=windows-1252"
    resp.headers["Content-Length"] = str(len(body.encode("cp1252")))
    resp.headers["Connection"] = "close"
    return resp

# -------- TwinXML: varegrupper --------
@app.route("/twinxml/postproductgroup.asp", methods=["GET","POST"])
@app.route("/twinxml/postproductgroup.aspx", methods=["GET","POST"])
def post_product_group():
    # Logg ALT (uansett auth) – Uni bryr seg mest om returformatet
    conn = db()
    conn.execute(
        "INSERT INTO logs(endpoint, method, query, body, created_at) VALUES (?,?,?,?,?)",
        ("/twinxml/postproductgroup", request.method, request.query_string.decode("utf-8","ignore"),
         (request.data or b"").decode("utf-8","ignore"), now_iso())
    ); conn.commit(); conn.close()

    # GET: returner OK
    if request.method == "GET":
        return uni_groups_ok()

    # POST: lagre grupper hvis auth OK – men uansett svar samme OK-format
    raw, _ = read_xml_body()
    try:
        root = ET.fromstring(raw)
    except Exception as e:
        log.warning("Bad XML groups: %s ... first200=%r", e, raw[:200])
        return uni_groups_ok()

    count = 0
    conn = db()
    groups = findall_any(root, [".//productgroup",".//group",".//gruppe",".//varegruppe"])
    for g in groups:
        gid   = findtext_any(g, ["groupno","groupid","id","gruppeid","grpid"]).strip()
        gname = findtext_any(g, ["description","groupname","name","gruppenavn"]).strip()
        parent= findtext_any(g, ["parentgroup","parentid","parent","overgruppeid"]).strip()
        if not gid: continue
        conn.execute("""
            INSERT INTO groups(groupid, groupname, parentid, payload_xml, updated_at)
            VALUES(?,?,?,?,?)
            ON CONFLICT(groupid) DO UPDATE SET
              groupname=excluded.groupname,
              parentid=excluded.parentid,
              payload_xml=excluded.payload_xml,
              updated_at=excluded.updated_at
        """, (gid, gname, parent, raw, now_iso()))
        count += 1
    conn.commit(); conn.close()
    log.info("Stored %d groups", count)
    return uni_groups_ok()

# -------- TwinXML: PRODUKTER (mange alias – alle peker hit) --------
@app.route("/twinxml/postproduct.asp", methods=["GET","POST"])
@app.route("/twinxml/postproduct.aspx", methods=["GET","POST"])
@app.route("/twinxml/postproducts.asp", methods=["GET","POST"])
@app.route("/twinxml/postproducts.aspx", methods=["GET","POST"])
@app.route("/twinxml/postallproducts.asp", methods=["GET","POST"])
@app.route("/twinxml/postallproducts.aspx", methods=["GET","POST"])
@app.route("/twinxml/postitems.asp", methods=["GET","POST"])
@app.route("/twinxml/postitems.aspx", methods=["GET","POST"])
@app.route("/twinxml/postprice.asp", methods=["GET","POST"])
@app.route("/twinxml/postprice.aspx", methods=["GET","POST"])
@app.route("/twinxml/postprices.asp", methods=["GET","POST"])
@app.route("/twinxml/postprices.aspx", methods=["GET","POST"])
@app.route("/twinxml/postinventory.asp", methods=["GET","POST"])
@app.route("/twinxml/postinventory.aspx", methods=["GET","POST"])
@app.route("/twinxml/poststock.asp", methods=["GET","POST"])
@app.route("/twinxml/poststock.aspx", methods=["GET","POST"])
def post_product():
    if request.method == "GET":
        return ok_txt("OK")

    if not require_auth():
        # svar OK uansett – enkelte klienter aborterer hvis ikke "OK"
        return ok_txt("OK")

    raw, _ = read_xml_body()
    try:
        root = ET.fromstring(raw)
    except Exception as e:
        log.warning("Bad XML products: %s ... first200=%r", e, raw[:200])
        return ok_txt("OK")

    nodes = findall_any(root, [".//product",".//vare",".//item",".//produkt"])
    if not nodes:
        # fallback: finn noder som har ident-felt
        cands=[]; idtags=["productident","prodid","varenr","sku","itemno"]
        for elem in root.iter():
            ident = findtext_any(elem, idtags).strip()
            if ident: cands.append(elem)
        nodes=cands

    conn = db(); c = conn.cursor()
    upserted=0; synced=0
    for p in nodes:
        sku = findtext_any(p,["productident","prodid","varenr","sku","itemno"]).strip()
        if not sku: continue
        name = findtext_any(p,["description","name","varenavn","title","productname"]).strip()
        price= to_float_safe(findtext_any(p,["price","pris","salesprice","price_incl_vat","newprice","webprice"]))
        grp  = findtext_any(p,["productgroup","groupid","gruppeid","groupno"]).strip()
        stock= to_int_safe(findtext_any(p,["quantityonhand","stock","quantity","qty","lager","onhand"]))
        body = findtext_any(p,["desc","body_html","longtext","description","infohtml"]) or ""
        img  = findtext_any(p,["image_b64","image","bilde_b64"]) or None
        web  = 1 if (findtext_any(p,["publish","webactive","active","is_web"],"1").strip().lower() in ("1","true","yes")) else 0

        if price is not None and not PRICE_INCLUDES_VAT:
            price = round(price * 1.25, 2)

        c.execute("""
          INSERT INTO products(prodid,name,price,vatcode,groupid,barcode,stock,body_html,image_b64,webactive,payload_xml,
                               last_shopify_product_id,last_shopify_variant_id,last_inventory_item_id,updated_at)
          VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
          ON CONFLICT(prodid) DO UPDATE SET
            name=excluded.name, price=excluded.price, groupid=excluded.groupid, stock=excluded.stock,
            body_html=excluded.body_html, image_b64=excluded.image_b64, webactive=excluded.webactive,
            payload_xml=excluded.payload_xml, updated_at=excluded.updated_at
        """,(sku,name,price,None,grp,None,stock,body,img,web,raw,None,None,None,now_iso()))
        upserted += 1

        if SHOPIFY_TOKEN:
            try:
                row = c.execute("SELECT * FROM products WHERE prodid=?", (sku,)).fetchone()
                upsert_shopify_product_from_row(row); synced += 1
            except Exception as e:
                log.error("Shopify sync failed for %s: %s", sku, e)

    conn.commit(); conn.close()
    log.info("Upserted %d products (Shopify updated %d)", upserted, synced)
    return ok_txt("OK")

# -------- delete (arkiver/slett) – svarer OK til Uni uansett --------
@app.route("/twinxml/deleteproduct.asp", methods=["GET","POST"])
@app.route("/twinxml/deleteproduct.aspx", methods=["GET","POST"])
def delete_product():
    if not require_auth(): return ok_txt("OK")
    sku = (request.args.get("id") or "").strip()
    if not sku: return ok_txt("OK")
    # Lokal opprydding
    conn = db(); conn.execute("DELETE FROM products WHERE prodid=?", (sku,)); conn.commit(); conn.close()
    # Shopify handling kan toggles via env, men vi svarer uansett OK til Uni
    try:
        if SHOPIFY_TOKEN and ENABLE_SHOPIFY_DELETE:
            v = shopify_find_variant_by_sku(sku)
            if v:
                pid=v["product_id"]
                if SHOPIFY_DELETE_MODE=="delete":
                    requests.delete(f"{shopify_base()}/products/{pid}.json", headers=sh_headers(), timeout=30)
                elif SHOPIFY_DELETE_MODE=="draft":
                    shopify_update_product(pid, {"id":pid,"status":"draft"})
                else:
                    shopify_update_product(pid, {"id":pid,"status":"archived"})
    except Exception as e:
        log.warning("Shopify delete/archive failed for %s: %s", sku, e)
    return ok_txt("OK")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=PORT)
