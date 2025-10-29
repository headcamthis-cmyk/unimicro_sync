import os
import logging
import sqlite3
import json
from datetime import datetime, timezone
from flask import Flask, request, Response
import xml.etree.ElementTree as ET
import requests
import re
import base64
import binascii

APP_NAME = "uni-shopify-sync"
PORT = int(os.environ.get("PORT", "10000"))

# ---------- Uni auth ----------
UNI_USER = os.environ.get("UNI_USER", "synall")
UNI_PASS = os.environ.get("UNI_PASS", "synall")

# ---------- Shopify ----------
SHOPIFY_DOMAIN = os.environ.get("SHOPIFY_DOMAIN", "allsupermotoas.myshopify.com")
SHOPIFY_TOKEN = os.environ.get("SHOPIFY_TOKEN")  # settes i Render
SHOPIFY_API_VERSION = os.environ.get("SHOPIFY_API_VERSION", "2024-10")
SHOPIFY_LOCATION_ID = os.environ.get("SHOPIFY_LOCATION_ID", "16764928067")
PRICE_INCLUDES_VAT = os.environ.get("PRICE_INCLUDES_VAT", "true").lower() in ("1", "true", "yes")

# Feature toggles
ENABLE_IMAGE_UPLOAD = os.environ.get("ENABLE_IMAGE_UPLOAD", "false").lower() in ("1","true","yes")  # default AV
SHOPIFY_DELETE_MODE = os.environ.get("SHOPIFY_DELETE_MODE", "archive").lower()  # archive|delete|draft
ENABLE_SHOPIFY_DELETE = os.environ.get("ENABLE_SHOPIFY_DELETE", "true").lower() in ("1","true","yes")

# “Senere” (valgfrie) funksjoner – default AV
FORCE_NEW_PRODUCT_PER_SKU = os.environ.get("FORCE_NEW_PRODUCT_PER_SKU", "false").lower() in ("1","true","yes")
PLACEHOLDER_IMAGE_URL = os.environ.get("PLACEHOLDER_IMAGE_URL")
SEO_DEFAULT_TITLE_TEMPLATE = os.environ.get("SEO_DEFAULT_TITLE_TEMPLATE")  # f.eks: "{title} | AllSupermoto AS"
SEO_DEFAULT_DESC_TEMPLATE = os.environ.get("SEO_DEFAULT_DESC_TEMPLATE")    # f.eks: "Kjøp {title} raskt & trygt hos ASM."
DEFAULT_BODY_HTML = os.environ.get("DEFAULT_BODY_HTML")                    # f.eks: "<p>Standard beskrivelse…</p>"

# ---------- DB ----------
DB_URL = os.environ.get("DB_URL", "sync.db")

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s: %(message)s")
log = logging.getLogger(APP_NAME)

app = Flask(__name__)
app.url_map.strict_slashes = False

# ---- normalize '//' i PATH (Uni kan sende dobbelt-slash)
class DoubleSlashFix:
    def __init__(self, app): self.app = app
    def __call__(self, environ, start_response):
        p = environ.get("PATH_INFO","/")
        if "//" in p: environ["PATH_INFO"] = p.replace("//","/")
        return self.app(environ, start_response)
app.wsgi_app = DoubleSlashFix(app.wsgi_app)

# ---------- DB helpers ----------
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
      image_b64 TEXT, webactive INTEGER, vendor TEXT, payload_xml TEXT,
      last_shopify_product_id TEXT, last_shopify_variant_id TEXT,
      last_inventory_item_id TEXT, updated_at TEXT
    )""")
    # Prøv å legge til vendor-kolonnen hvis gammel DB mangler den
    try:
        c.execute("ALTER TABLE products ADD COLUMN vendor TEXT")
    except Exception:
        pass
    conn.commit(); conn.close()
init_db()

# ---------- Utils ----------
def now_iso(): return datetime.now(timezone.utc).isoformat()

def ok_txt(body="OK"):
    return Response(body + "\r\n", mimetype="text/plain; charset=windows-1252")

def require_auth():
    return request.args.get("user")==UNI_USER and request.args.get("pass")==UNI_PASS

def read_xml_body():
    raw = request.get_data() or b""
    is_hex_param = (request.args.get("hex") or "").lower() in ("1","true","yes")
    if is_hex_param:
        try: raw = bytes.fromhex(raw.decode("ascii"))
        except Exception: pass
    for enc in ("utf-8","cp1252","latin-1","iso-8859-1"):
        try: return raw.decode(enc), is_hex_param
        except Exception: continue
    return raw.decode("utf-8","ignore"), is_hex_param

HEX_RE = re.compile(r"^[0-9a-fA-F]+$")

def maybe_hex_to_text(s: str) -> str:
    if not s: return s
    st = s.strip()
    if len(st) >= 2 and len(st) % 2 == 0 and HEX_RE.fullmatch(st) is not None:
        try:
            b = binascii.unhexlify(st)
            for enc in ("iso-8859-1","cp1252","utf-8"):
                try: return b.decode(enc)
                except Exception: continue
            return b.decode("utf-8","ignore")
        except Exception:
            return s
    return s

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

# ---------- Shopify ----------
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
        shopify_set_inventory(iid, qty); return
    except Exception as e:
        if "tracking" not in str(e).lower() and "does not have inventory tracking enabled" not in str(e):
            raise
    shopify_update_variant(vid, {"inventory_management":"shopify", "inventory_policy":"deny", "requires_shipping":True})
    shopify_set_inventory(iid, qty)

def shopify_upsert_product_metafields(pid: int, meta: dict):
    if not meta:
        return
    try:
        for key, val in meta.items():
            if val is None or val == "":
                continue
            body = {"metafield": {
                "namespace": "uni", "key": key, "value": str(val), "type": "single_line_text_field"
            }}
            requests.post(f"{shopify_base()}/products/{int(pid)}/metafields.json",
                          headers=sh_headers(), data=json.dumps(body), timeout=30)
    except Exception as e:
        log.warning("Metafields upsert failed for product %s: %s", pid, e)

# ---------- Request logging ----------
@app.before_request
def _log_req():
    try:
        ref = request.headers.get("Referer", "-")
        log.info("REQ %s %s?%s  Referer=%s", request.method, request.path,
                 request.query_string.decode(errors="ignore"), ref)
    except Exception:
        pass

# ---------- Health ----------
@app.route("/", methods=["GET"])
def index(): return ok_txt("OK")

# ---------- status/orders/productlist ----------
@app.route("/twinxml/status.asp", methods=["GET","POST","HEAD"])
def status_asp():
    lastupdate = request.args.get("lastupdate", "")
    xml = ('<?xml version="1.0" encoding="ISO-8859-1"?>'
           "<Root><OK>OK</OK><shopname>ASM Shopify</shopname>"
           "<supportsimages>1</supportsimages>"
           "<supportscustomers>1</supportscustomers>"
           "<supportsorders>1</supportsorders>"
           "<supportsstock>1</supportsstock>"
           "<supportsproducts>1</supportsproducts>"
           "<supportsproductgroups>1</supportsproductgroups>"
           "<supportsdeletes>1</supportsdeletes>"
           f"<echo_lastupdate>{lastupdate}</echo_lastupdate></Root>")
    resp = Response(xml, status=200)
    resp.headers["Content-Type"] = "text/xml; charset=ISO-8859-1"
    resp.headers["Connection"] = "close"
    return resp

@app.route("/twinxml/orders.asp", methods=["GET","POST","HEAD"])
def orders_asp():
    xml = '<?xml version="1.0" encoding="ISO-8859-1"?><Root><orders count="0"></orders></Root>'
    return Response(xml, mimetype="text/xml; charset=ISO-8859-1")

@app.route("/twinxml/singleorder.asp", methods=["GET","POST","HEAD"])
def singleorder_asp():
    xml = '<?xml version="1.0" encoding="ISO-8859-1"?><Root><order/></Root>'
    return Response(xml, mimetype="text/xml; charset=ISO-8859-1")

@app.route("/twinxml/productlist.asp", methods=["GET","POST","HEAD"])
def productlist_asp():
    xml = '<?xml version="1.0" encoding="ISO-8859-1"?><Root><OK>OK</OK><products count="0"></products></Root>'
    return Response(xml, mimetype="text/xml; charset=ISO-8859-1")

# ---------- misc stubs ----------
@app.route("/twinxml/postfiles.asp", methods=["GET","POST","HEAD"])
def postfiles_asp():
    return Response("OK\r\n", mimetype="text/plain; charset=windows-1252")

@app.route("/twinxml/postdiscountsystem.asp", methods=["GET","POST","HEAD"])
def postdiscountsystem_asp():
    return Response("OK\r\n", mimetype="text/plain; charset=windows-1252")

@app.route("/twinxml/deletetable.asp", methods=["GET","POST","HEAD"])
def deletetable_asp():
    name = (request.args.get("name") or "").lower()
    logging.info("Uni requested deletetable for: %s", name)
    return Response("OK\r\n", mimetype="text/plain; charset=windows-1252")

@app.route("/twinxml/postdiscount.asp", methods=["GET","POST","HEAD"])
@app.route("/twinxml/postdiscount.aspx", methods=["GET","POST","HEAD"])
def postdiscount_asp():
    return post_product()

# ---------- varegrupper ----------
def uni_groups_ok():
    body = "OK\r\n"
    resp = Response(body, status=200)
    resp.headers["Content-Type"] = "text/plain; charset=windows-1252"
    resp.headers["Content-Length"] = str(len(body.encode("cp1252")))
    resp.headers["Connection"] = "close"
    return resp

@app.route("/twinxml/postproductgroup.asp", methods=["GET","POST"])
@app.route("/twinxml/postproductgroup.aspx", methods=["GET","POST"])
def post_product_group():
    conn = db()
    conn.execute("INSERT INTO logs(endpoint, method, query, body, created_at) VALUES (?,?,?,?,?)",
                 ("/twinxml/postproductgroup", request.method, request.query_string.decode("utf-8","ignore"),
                  (request.data or b"").decode("utf-8","ignore"), now_iso()))
    conn.commit(); conn.close()

    if request.method == "GET":
        return uni_groups_ok()

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

# ---------- produkter (alias) ----------
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
        return ok_txt("OK")

    raw, _ = read_xml_body()
    try:
        root = ET.fromstring(raw)
    except Exception as e:
        log.warning("Bad XML products: %s ... first200=%r", e, raw[:200])
        return ok_txt("OK")

    nodes = findall_any(root, [".//product",".//vare",".//item",".//produkt"])
    if not nodes:
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

        # Navn
        name  = findtext_any(p,["description","name","varenavn","title","productname","varenavn1"]).strip()
        name2 = findtext_any(p,["varenavn2","alt01"]).strip()
        name3 = findtext_any(p,["varenavn3","alt07"]).strip()
        full_title = (name + (" " + " ".join([t for t in [name2, name3] if t]) if (name2 or name3) else "")) or sku

        # Beskrivelse (kan være hex)
        longdesc = findtext_any(p,["longdesc","longtext","description_long","desc","body_html","infohtml","produktbeskrivelse"]) or ""
        longdesc = maybe_hex_to_text(longdesc)
        if not longdesc and DEFAULT_BODY_HTML:
            longdesc = DEFAULT_BODY_HTML

        # Grupper / lager
        grp   = findtext_any(p,["productgroup","groupid","gruppeid","groupno","varegruppe"]).strip()
        stock = to_int_safe(findtext_any(p,["quantityonhand","stock","quantity","qty","lager","onhand","antall"]))

        # Priser
        price         = to_float_safe(findtext_any(p,["price","pris","salesprice","price_incl_vat","newprice","webprice","pris1","standard utpris"]))
        ordinaryprice = to_float_safe(findtext_any(p,["ordinaryprice","pris2"]))  # compare_at_price hvis > price
        if price is not None and not PRICE_INCLUDES_VAT:
            price = round(price * 1.25, 2)

        # Vendor (produsent/leverandør)
        vendor = findtext_any(p,["vendor","produsent","leverandor","leverandør","manufacturer","brand","supplier"]).strip()

        # Barcode/EAN (valgfritt)
        ean = findtext_any(p,["ean","ean_nr","ean_nr.ean","alt02"]).strip()

        # Bilde (vi laster ikke opp med mindre Uni faktisk sender det)
        img_b64  = findtext_any(p,["image_b64","image","bilde_b64"]) or None
        if img_b64:
            img_b64 = clean_b64(img_b64)

        # SEO templates (valgfritt)
        seo_title = SEO_DEFAULT_TITLE_TEMPLATE.format(title=full_title, sku=sku, vendor=vendor) if SEO_DEFAULT_TITLE_TEMPLATE else None
        seo_desc  = SEO_DEFAULT_DESC_TEMPLATE.format(title=full_title, sku=sku, vendor=vendor) if SEO_DEFAULT_DESC_TEMPLATE else None

        # Persist lokalt
        c.execute("""
          INSERT INTO products(prodid,name,price,vatcode,groupid,barcode,stock,body_html,image_b64,webactive,vendor,payload_xml,
                               last_shopify_product_id,last_shopify_variant_id,last_inventory_item_id,updated_at)
          VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
          ON CONFLICT(prodid) DO UPDATE SET
            name=excluded.name, price=excluded.price, groupid=excluded.groupid, stock=excluded.stock,
            body_html=excluded.body_html, image_b64=excluded.image_b64, vendor=excluded.vendor,
            payload_xml=excluded.payload_xml, updated_at=excluded.updated_at
        """,(sku,full_title,price,None,grp,ean,stock,longdesc,img_b64,1,vendor,raw,None,None,None,now_iso()))
        upserted += 1

        # ---------- Shopify sync ----------
        if SHOPIFY_TOKEN:
            try:
                # Finn eksisterende variant via SKU (med mulighet til å tvinge nytt produkt per SKU)
                v = None if FORCE_NEW_PRODUCT_PER_SKU else shopify_find_variant_by_sku(sku)

                variant_payload = {
                    "sku": sku,
                    "price": f"{(price or 0):.2f}",
                    "inventory_management": "shopify",
                    "inventory_policy": "deny",
                    "requires_shipping": True
                }
                if ordinaryprice and price and ordinaryprice > price:
                    variant_payload["compare_at_price"] = f"{ordinaryprice:.2f}"
                if ean:
                    variant_payload["barcode"] = ean

                product_payload = {
                    "title": full_title,
                    "body_html": longdesc or "",
                    "vendor": vendor or None,
                    "tags": [t for t in [f"group-{grp}" if grp else None] if t],
                    "variants": [variant_payload]
                }
                # Vi sender ikke images med mindre vi faktisk har b64 fra Uni
                # (unngår tilfeldige/eksisterende bilder). Hvis du senere vil ha placeholder,
                # sett PLACEHOLDER_IMAGE_URL.
                images_to_attach = []
                if ENABLE_IMAGE_UPLOAD and img_b64:
                    images_to_attach.append({"attachment": img_b64, "filename": f"{sku}.jpg", "position": 1})
                elif PLACEHOLDER_IMAGE_URL and not v:
                    images_to_attach.append({"src": PLACEHOLDER_IMAGE_URL, "position": 1})
                if images_to_attach:
                    product_payload["images"] = images_to_attach

                # CREATE/UPDATE
                if v:
                    pid=v["product_id"]; vid=v["id"]; iid=v["inventory_item_id"]
                    up={"id":pid,"title":product_payload["title"],"body_html":product_payload["body_html"]}
                    if product_payload.get("vendor"): up["vendor"] = product_payload["vendor"]
                    if product_payload["tags"]: up["tags"]=",".join(product_payload["tags"])
                    if seo_title or seo_desc:
                        up["metafields"] = []
                        if seo_title: up["metafields"].append({"namespace":"global","key":"title_tag","type":"single_line_text_field","value":seo_title})
                        if seo_desc:  up["metafields"].append({"namespace":"global","key":"description_tag","type":"single_line_text_field","value":seo_desc})
                    shopify_update_product(pid, up)
                    log.info("Shopify UPDATE OK sku=%s product_id=%s admin=https://%s/admin/products/%s",
                             sku, pid, SHOPIFY_DOMAIN, pid)
                else:
                    cp=dict(product_payload)
                    cp["tags"] = ",".join([t for t in cp.get("tags", []) if t])
                    cp["status"]="active"  # alle varer som kommer fra Uni = web-aktive
                    created=shopify_create_product(cp)
                    pid=created["id"]; vid=created["variants"][0]["id"]; iid=created["variants"][0]["inventory_item_id"]
                    log.info("Shopify CREATE OK sku=%s product_id=%s status=%s admin=https://%s/admin/products/%s",
                             sku, pid, cp["status"], SHOPIFY_DOMAIN, pid)

                # Inventory
                try:
                    ensure_tracking_and_set_inventory(vid, iid, stock)
                except Exception as e:
                    log.warning("Inventory set failed for %s: %s", sku, e)

                # Metafields: lagre vendor også i uni-namespace (lett å debugge)
                shopify_upsert_product_metafields(pid, {"vendor": vendor or ""})

                synced += 1

            except Exception as e:
                log.error("Shopify sync failed for %s: %s", sku, e)

    conn.commit(); conn.close()
    log.info("Upserted %d products (Shopify updated %d)", upserted, synced)
    return ok_txt("OK")

# ---------- delete ----------
@app.route("/twinxml/deleteproduct.asp", methods=["GET","POST"])
@app.route("/twinxml/deleteproduct.aspx", methods=["GET","POST"])
def delete_product():
    if not require_auth(): return ok_txt("OK")
    sku = (request.args.get("id") or "").strip()
    if not sku: return ok_txt("OK")
    conn = db(); conn.execute("DELETE FROM products WHERE prodid=?", (sku,)); conn.commit(); conn.close()
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

# ---------- (stubs) ----------
@app.route("/twinxml/deleteproductgroup.asp", methods=["GET","POST"])
def delete_product_group():
    return ok_txt("OK")

@app.route("/twinxml/deleteall.asp", methods=["GET","POST"])
def delete_all():
    try:
        conn = db()
        conn.execute("DELETE FROM products"); conn.execute("DELETE FROM groups")
        conn.commit(); conn.close()
    except Exception:
        pass
    return ok_txt("OK")

# ---------- fallback for feilkonfigurert "asp"/".asp" ----------
@app.route("/twinxml/asp", methods=["GET","POST","HEAD"])
@app.route("/twinxml/.asp", methods=["GET","POST","HEAD"])
def bare_asp_placeholder():
    logging.warning("Placeholder ASP hit. Likely a blank filename in Uni Sideadministrasjon. QS=%s",
                    request.query_string.decode("utf-8","ignore"))
    xml = '<?xml version="1.0" encoding="ISO-8859-1"?><Root><OK>OK</OK></Root>'
    return Response(xml, mimetype="text/xml; charset=ISO-8859-1")

# ---------- Catch-all ----------
@app.route("/twinxml/<path:rest>", methods=["GET", "POST", "HEAD"])
def twinxml_fallback(rest):
    try:
        qs = request.query_string.decode("utf-8", "ignore")
    except Exception:
        qs = ""
    path_l = rest.lower()
    is_upload = (
        path_l.startswith("post") or
        "product" in path_l or "item" in path_l or
        "price" in path_l or "stock" in path_l or
        "inventory" in path_l or "discount" in path_l
    )
    logging.warning("TwinXML FALLBACK hit: /twinxml/%s?%s  (upload=%s)", rest, qs, is_upload)
    if is_upload and request.method in ("POST","GET"):
        return post_product()
    return ok_txt("OK")

# ---------- Main ----------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=PORT)
