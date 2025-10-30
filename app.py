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
SHOPIFY_TOKEN = os.environ.get("SHOPIFY_TOKEN")  # set in Render
SHOPIFY_API_VERSION = os.environ.get("SHOPIFY_API_VERSION", "2024-10")
SHOPIFY_LOCATION_ID = os.environ.get("SHOPIFY_LOCATION_ID", "16764928067")

# ---------- Pricing behavior ----------
UNI_PRICE_IS_NET = os.environ.get("UNI_PRICE_IS_NET", "true").lower() in ("1", "true", "yes")
VAT_RATE = float(os.environ.get("VAT_RATE", "0.25"))

# ---------- Feature toggles ----------
ENABLE_IMAGE_UPLOAD = os.environ.get("ENABLE_IMAGE_UPLOAD", "false").lower() in ("1", "true", "yes")
PLACEHOLDER_IMAGE_URL = os.environ.get("PLACEHOLDER_IMAGE_URL")

# SEO / body defaults (optional)
SEO_DEFAULT_TITLE_TEMPLATE = os.environ.get("SEO_DEFAULT_TITLE_TEMPLATE")
SEO_DEFAULT_DESC_TEMPLATE = os.environ.get("SEO_DEFAULT_DESC_TEMPLATE")
DEFAULT_BODY_HTML = os.environ.get("DEFAULT_BODY_HTML")

# Debug: log discovered XML fields for first N products each request
LOG_SNIFF_FIELDS = os.environ.get("LOG_SNIFF_FIELDS", "true").lower() in ("1", "true", "yes")
SNIFF_MAX_PRODUCTS = int(os.environ.get("SNIFF_MAX_PRODUCTS", "3"))

# Robust variant scan cap (fallback after GraphQL)
FIND_SKU_MAX_VARIANTS = int(os.environ.get("FIND_SKU_MAX_VARIANTS", "3000"))

# ---------- DB ----------
DB_URL = os.environ.get("DB_URL", "sync.db")

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s: %(message)s")
log = logging.getLogger(APP_NAME)

app = Flask(__name__)
app.url_map.strict_slashes = False

# ---- normalize '//' in PATH (Uni sometimes posts with double slash)
class DoubleSlashFix:
    def __init__(self, app):
        self.app = app
    def __call__(self, environ, start_response):
        p = environ.get("PATH_INFO", "/")
        if "//" in p:
            environ["PATH_INFO"] = p.replace("//", "/")
        return self.app(environ, start_response)
app.wsgi_app = DoubleSlashFix(app.wsgi_app)

# ---------- DB helpers ----------
def db():
    conn = sqlite3.connect(DB_URL)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = db(); c = conn.cursor()
    try:
        c.execute("PRAGMA journal_mode=WAL;")
        c.execute("PRAGMA synchronous=NORMAL;")
    except Exception:
        pass
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
    c.execute("""
    CREATE TABLE IF NOT EXISTS logs(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      endpoint TEXT, method TEXT, query TEXT, body TEXT, created_at TEXT
    )""")
    try:
        c.execute("ALTER TABLE products ADD COLUMN vendor TEXT")
    except Exception:
        pass
    conn.commit(); conn.close()
init_db()

def ensure_logs_table(conn):
    conn.execute("""
    CREATE TABLE IF NOT EXISTS logs(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      endpoint TEXT, method TEXT, query TEXT, body TEXT, created_at TEXT
    )""")
    conn.commit()

def safe_log(endpoint: str, method: str, query: str, body: str):
    try:
        conn = db()
        ensure_logs_table(conn)
        conn.execute(
            "INSERT INTO logs(endpoint, method, query, body, created_at) VALUES (?,?,?,?,?)",
            (endpoint, method, query, body, now_iso())
        )
        conn.commit()
    except Exception as e:
        logging.warning("Skipping logs insert: %s", e)
    finally:
        try: conn.close()
        except: pass

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

def one_line(s: str | None) -> str | None:
    if not s:
        return None
    return re.sub(r"[\r\n]+", " ", str(s)).strip()

# ---------- Tag helpers ----------
def norm_tag(tag: str) -> str:
    return (tag.split('}', 1)[-1] if '}' in tag else tag).lower()

def node_text_or_attr(node: ET.Element) -> str:
    txt = (getattr(node, "text", "") or "").strip()
    if txt:
        return txt
    for k in ("value","val","text","t"):
        v = node.attrib.get(k)
        if v and v.strip():
            return v.strip()
    return ""

def findtext_ci_direct(elem: ET.Element, names):
    wanted=[]
    for n in names:
        n=n.strip().lower()
        wanted.append((n[:-1], True) if n.endswith('*') else (n, False))
    for child in list(elem):
        t = norm_tag(child.tag)
        for base, pref in wanted:
            if (t.startswith(base) if pref else t == base):
                v = node_text_or_attr(child)
                if v:
                    return v
    return ""

def findtext_ci_any(elem: ET.Element, names):
    wanted=[]
    for n in names:
        n=n.strip().lower()
        wanted.append((n[:-1], True) if n.endswith('*') else (n, False))
    for node in elem.iter():
        t = norm_tag(getattr(node, "tag", ""))
        for base, pref in wanted:
            if (t.startswith(base) if pref else t == base):
                v = node_text_or_attr(node)
                if v:
                    return v
    return ""

def extract_title(p: ET.Element, sku: str) -> str:
    title = findtext_ci_direct(p, [
        "description","descrip*","name","title","productname",
        "varenavn","varenavn1","varenavn2","varenavn3","name1"
    ]) or findtext_ci_any(p, [
        "description","descrip*","name","title","productname",
        "varenavn","varenavn1","varenavn2","varenavn3","name1"
    ])
    if not title:
        alt01 = findtext_ci_any(p, ["alt01"]) or ""
        alt07 = findtext_ci_any(p, ["alt07"]) or ""
        title = alt01 or alt07 or sku
    return title  # never append SKU

def extract_best_price(p: ET.Element):
    priority = [
        "webprice","price_incl_vat","salesprice","pris1","price","pris",
        "ordinaryprice","pris2","newprice","netprice"
    ]
    found = {}
    any_first = None
    for node in p.iter():
        t = norm_tag(getattr(node,"tag",""))
        if ("price" in t) or ("pris" in t):
            val = to_float_safe(node_text_or_attr(node))
            if val is not None:
                if not any_first:
                    any_first = (val, t)
                found[t] = val if t not in found else found[t]
    for key in priority:
        for t,v in found.items():
            if t == key:
                return v, t
    return (any_first if any_first else (None, None))

# ---------- Shopify ----------
def shopify_base(): return f"https://{SHOPIFY_DOMAIN}/admin/api/{SHOPIFY_API_VERSION}"

def sh_headers():
    if not SHOPIFY_TOKEN: raise RuntimeError("SHOPIFY_TOKEN not set")
    return {"X-Shopify-Access-Token": SHOPIFY_TOKEN, "Content-Type":"application/json", "Accept":"application/json"}

def parse_gid(gid: str, kind: str) -> int | None:
    """
    Convert a Shopify GID to numeric id. kind: 'ProductVariant', 'Product', 'InventoryItem'
    """
    if not gid: return None
    m = re.match(rf"^gid://shopify/{re.escape(kind)}/(\d+)$", str(gid))
    return int(m.group(1)) if m else None

def shopify_find_variant_by_sku(sku):
    """
    Robust lookup preferring GraphQL exact match, then REST:
      1) GraphQL: productVariants(query: "sku:...") -> exact match
      2) REST: /variants.json?sku=... (verify)
      3) REST: paginated scan up to FIND_SKU_MAX_VARIANTS
    Returns a dict with keys: id, product_id, inventory_item_id, sku
    """
    target = (sku or "").strip()
    if not target:
        return None

    # ---- 1) GraphQL exact query ----
    try:
        gql_url = f"{shopify_base()}/graphql.json"
        headers = {"X-Shopify-Access-Token": SHOPIFY_TOKEN, "Content-Type": "application/json", "Accept": "application/json"}
        query = """
        query ($q: String!) {
          productVariants(first: 1, query: $q) {
            edges {
              node {
                id
                sku
                product { id }
                inventoryItem { id }
              }
            }
          }
        }
        """
        payload = {"query": query, "variables": {"q": f"sku:{target}"}}
        r = requests.post(gql_url, headers=headers, data=json.dumps(payload), timeout=30)
        if r.status_code == 200:
            data = r.json()
            edges = (((data or {}).get("data") or {}).get("productVariants") or {}).get("edges", [])
            for e in edges:
                node = (e or {}).get("node") or {}
                if (node.get("sku") or "").strip() == target:
                    vid = parse_gid(node.get("id"), "ProductVariant")
                    pid = parse_gid(((node.get("product") or {}).get("id")), "Product")
                    iid = parse_gid(((node.get("inventoryItem") or {}).get("id")), "InventoryItem")
                    if vid and pid:
                        return {"id": vid, "product_id": pid, "inventory_item_id": iid, "sku": target}
        else:
            logging.warning("GraphQL variant lookup failed %s: %s", r.status_code, r.text[:200])
    except Exception as e:
        logging.warning("GraphQL lookup error for SKU %r: %s", target, e)

    # ---- 2) REST filtered (verify) ----
    base = shopify_base()
    headers = sh_headers()
    try:
        r = requests.get(f"{base}/variants.json", headers=headers, params={"sku": target, "limit": 250}, timeout=30)
        if r.status_code == 200:
            arr = r.json().get("variants", [])
            for v in arr:
                if (v.get("sku") or "").strip() == target:
                    return v
            if arr:
                logging.warning("Shopify ignored ?sku= filter for %r; falling back to full scan.", target)
        else:
            logging.warning("variants.json?sku=… returned %s: %s", r.status_code, r.text[:200])
    except Exception as e:
        logging.warning("SKU filtered lookup failed for %r: %s", target, e)

    # ---- 3) REST paginated scan ----
    scanned = 0
    since_id = 0
    while scanned < FIND_SKU_MAX_VARIANTS:
        try:
            r = requests.get(f"{base}/variants.json", headers=headers, params={"since_id": since_id, "limit": 250}, timeout=30)
            if r.status_code != 200:
                logging.warning("variants scan stopped (status %s): %s", r.status_code, r.text[:200])
                break
            arr = r.json().get("variants", [])
            if not arr:
                break
            for v in arr:
                scanned += 1
                if (v.get("sku") or "").strip() == target:
                    return v
            since_id = arr[-1]["id"]
        except Exception as e:
            logging.warning("variants scan error after %d scanned: %s", scanned, e)
            break

    logging.info("SKU %r not found after scanning %d variants.", target, scanned)
    return None

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
    if not meta: return
    try:
        for key, val in meta.items():
            if val is None or val == "": continue
            body = {"metafield": {
                "namespace": "uni", "key": key, "value": str(val), "type": "single_line_text_field"
            }}
            requests.post(f"{shopify_base()}/products/{int(pid)}/metafields.json",
                          headers=sh_headers(), data=json.dumps(body), timeout=30)
    except Exception as e:
        log.warning("Metafields upsert failed for product %s: %s", pid, e)

def one_line(s):  # override annotation for brevity in SEO helper
    if not s: return None
    return re.sub(r"[\r\n]+", " ", str(s)).strip()

def shopify_set_seo(pid: int, title: str | None = None, desc: str | None = None):
    try:
        for key, val in (("title_tag", title), ("description_tag", desc)):
            val = one_line(val)
            if not val: continue
            body = {"metafield": {
                "namespace": "global", "key": key, "type": "single_line_text_field", "value": val
            }}
            requests.post(f"{shopify_base()}/products/{int(pid)}/metafields.json",
                          headers=sh_headers(), data=json.dumps(body), timeout=30)
    except Exception as e:
        log.warning("SEO metafields failed for product %s: %s", pid, e)

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

# ---------- product groups (return literal "true") ----------
def uni_groups_ok():
    body = "true"
    resp = Response(body, status=200)
    resp.headers["Content-Type"] = "text/plain; charset=windows-1252"
    resp.headers["Content-Length"] = str(len(body.encode("cp1252")))
    resp.headers["Connection"] = "close"
    return resp

@app.route("/twinxml/postproductgroup.asp", methods=["GET","POST"])
@app.route("/twinxml/postproductgroup.aspx", methods=["GET","POST"])
def post_product_group():
    safe_log("/twinxml/postproductgroup",
             request.method,
             request.query_string.decode("utf-8","ignore"),
             (request.data or b"").decode("utf-8","ignore"))

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
    groups = root.findall(".//productgroup") or root.findall(".//group") or root.findall(".//gruppe") or root.findall(".//varegruppe")
    for g in groups:
        gid   = (g.findtext("groupno") or g.findtext("groupid") or g.findtext("id") or g.findtext("gruppeid") or g.findtext("grpid") or "").strip()
        gname = (g.findtext("description") or g.findtext("groupname") or g.findtext("name") or g.findtext("gruppenavn") or "").strip()
        parent= (g.findtext("parentgroup") or g.findtext("parentid") or g.findtext("parent") or g.findtext("overgruppeid") or "").strip()
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

# ---------- products ----------
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

    nodes = (root.findall(".//product") or root.findall(".//vare") or
             root.findall(".//item") or root.findall(".//produkt"))
    if not nodes:
        cands=[]; idtags=["productident","prodid","varenr","sku","itemno"]
        for elem in root.iter():
            ident = ""
            for t in idtags:
                v = elem.findtext(t)
                if v: ident = v.strip(); break
            if ident: cands.append(elem)
        nodes=cands

    conn = db(); c = conn.cursor()
    upserted=0; synced=0

    if LOG_SNIFF_FIELDS:
        for i, probe in enumerate(nodes[:SNIFF_MAX_PRODUCTS]):
            snap = []
            for n in probe.iter():
                tag = norm_tag(getattr(n,"tag",""))
                val = node_text_or_attr(n)
                if val:
                    snap.append(f"{tag}={val[:80]}")
            log.info("SNIFF[%d]: %s", i+1, "; ".join(snap[:40]))

    for p in nodes:
        sku = (findtext_ci_any(p,["productident","prodid","varenr","sku","itemno"]) or "").strip()
        if not sku: continue

        # Title (no SKU appended)
        name  = extract_title(p, sku)
        name2 = (findtext_ci_any(p,["varenavn2","alt01"]) or "").strip()
        name3 = (findtext_ci_any(p,["varenavn3","alt07"]) or "").strip()
        full_title = (name + (" " + " ".join([t for t in [name2, name3] if t]) if (name2 or name3) else "")) or sku

        longdesc = (findtext_ci_any(p,["longdesc","longtext","description_long","desc","body_html","infohtml","produktbeskrivelse"]) or "")
        longdesc = maybe_hex_to_text(longdesc)
        if not longdesc and DEFAULT_BODY_HTML:
            longdesc = DEFAULT_BODY_HTML

        grp   = (findtext_ci_any(p,["productgroup","groupid","gruppeid","groupno","varegruppe"]) or "").strip()
        stock = to_int_safe(findtext_ci_any(p, ["quantityonhand","stock","quantity","qty","lager","onhand","antall"]))

        price_raw, price_src = extract_best_price(p)
        price = price_raw
        ordinaryprice = to_float_safe(findtext_ci_any(p, ["ordinaryprice", "pris2"]))

        def brutto(val):
            if val is None:
                return None
            return round(val * (1.0 + VAT_RATE), 2) if UNI_PRICE_IS_NET else round(val, 2)

        price = brutto(price)
        if ordinaryprice is not None:
            ordinaryprice = brutto(ordinaryprice)

        vendor = (findtext_ci_any(p,["vendor","produsent","leverandor","leverandør","manufacturer","brand","supplier"]) or "").strip()
        ean = (findtext_ci_any(p,["ean","ean_nr","ean_nr.ean","alt02"]) or "").strip()

        img_b64  = findtext_ci_any(p,["image_b64","image","bilde_b64"]) or None
        if img_b64:
            img_b64 = clean_b64(img_b64)

        seo_title = SEO_DEFAULT_TITLE_TEMPLATE.format(title=full_title, sku=sku, vendor=vendor) if SEO_DEFAULT_TITLE_TEMPLATE else None
        seo_desc  = SEO_DEFAULT_DESC_TEMPLATE.format(title=full_title, sku=sku, vendor=vendor) if SEO_DEFAULT_DESC_TEMPLATE else None

        log.info("PARSED sku=%s title=%r price=%s (src=%s) ordinary=%s stock=%s vendor=%r group=%r",
                 sku, full_title, price, price_src, ordinaryprice, stock, vendor, grp)

        # Persist locally
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

        # ---------- Shopify: UPDATE if exists, otherwise CREATE ----------
        if not SHOPIFY_TOKEN:
            continue

        try:
            v = shopify_find_variant_by_sku(sku)

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

            images_to_attach = []
            if ENABLE_IMAGE_UPLOAD and img_b64:
                images_to_attach.append({"attachment": img_b64, "filename": f"{sku}.jpg", "position": 1})
            elif PLACEHOLDER_IMAGE_URL and not v:
                images_to_attach.append({"src": PLACEHOLDER_IMAGE_URL, "position": 1})
            if images_to_attach:
                product_payload["images"] = images_to_attach

            pid = vid = iid = None

            if v:
                # UPDATE existing product
                pid=v["product_id"]; vid=v["id"]; iid=v.get("inventory_item_id")
                up={"id":pid,"title":product_payload["title"],"body_html":product_payload["body_html"]}
                if product_payload.get("vendor"): up["vendor"] = product_payload["vendor"]
                if product_payload["tags"]:
                    up["tags"] = ",".join(product_payload["tags"])
                shopify_update_product(pid, up)
                log.info("Shopify UPDATE OK sku=%s product_id=%s admin=https://%s/admin/products/%s",
                         sku, pid, SHOPIFY_DOMAIN, pid)
            else:
                # CREATE new product
                cp=dict(product_payload)
                if cp["tags"]:
                    cp["tags"] = ",".join(cp["tags"])
                cp["status"]="active"
                created=shopify_create_product(cp)
                pid=created["id"]; vid=created["variants"][0]["id"]; iid=created["variants"][0]["inventory_item_id"]
                log.info("Shopify CREATE OK sku=%s product_id=%s status=%s admin=https://%s/admin/products/%s",
                         sku, pid, cp["status"], SHOPIFY_DOMAIN, pid)

            # Always update variant and inventory
            variant_update = {"price": f"{(price or 0):.2f}", "sku": sku}
            if ordinaryprice and price and ordinaryprice > price:
                variant_update["compare_at_price"] = f"{ordinaryprice:.2f}"
            if ean:
                variant_update["barcode"] = ean
            try:
                shopify_update_variant(vid, variant_update)
            except Exception as e:
                log.warning("Variant price update failed for %s: %s", sku, e)

            try:
                ensure_tracking_and_set_inventory(vid, iid, stock)
            except Exception as e:
                log.warning("Inventory set failed for %s: %s", sku, e)

            shopify_upsert_product_metafields(pid, {"vendor": vendor or ""})
            shopify_set_seo(pid, seo_title, seo_desc)

            c.execute(
                "UPDATE products SET last_shopify_product_id=?, last_shopify_variant_id=?, last_inventory_item_id=?, updated_at=? WHERE prodid=?",
                (pid, vid, iid, now_iso(), sku)
            )
            conn.commit()
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
    return ok_txt("OK")

# ---------- reset map ----------
@app.route("/twinxml/resetmap.asp", methods=["GET","POST"])
def resetmap():
    if not require_auth(): return ok_txt("OK")
    sku = (request.args.get("id") or "").strip()
    if not sku: return ok_txt("OK")
    conn = db()
    conn.execute("""
        UPDATE products
           SET last_shopify_product_id=NULL,
               last_shopify_variant_id=NULL,
               last_inventory_item_id=NULL
         WHERE prodid=?""", (sku,))
    conn.commit(); conn.close()
    return ok_txt("OK")

# ---------- stubs ----------
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

# ---------- fallback for blank filenames ----------
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
