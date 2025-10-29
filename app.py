import os
import logging
import sqlite3
import json
from datetime import datetime, timezone
from flask import Flask, request, Response, jsonify
import xml.etree.ElementTree as ET
import requests

APP_NAME = "uni-shopify-sync"
PORT = int(os.environ.get("PORT", "10000"))
ENV = os.environ.get("ENV", "prod")

# Uni auth
UNI_USER = os.environ.get("UNI_USER", "synall")
UNI_PASS = os.environ.get("UNI_PASS", "synall")

# Shopify
SHOPIFY_DOMAIN = os.environ.get("SHOPIFY_DOMAIN", "asmshop.no")
SHOPIFY_TOKEN = os.environ.get("SHOPIFY_TOKEN")  # sett i Render
SHOPIFY_API_VERSION = os.environ.get("SHOPIFY_API_VERSION", "2024-10")
SHOPIFY_LOCATION_ID = os.environ.get("SHOPIFY_LOCATION_ID", "16764928067")
PRICE_INCLUDES_VAT = os.environ.get("PRICE_INCLUDES_VAT", "true").lower() in ("1", "true", "yes")

# DB
DB_URL = os.environ.get("DB_URL", "sync.db")

# Logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s: %(message)s")
log = logging.getLogger(APP_NAME)

# Flask app
app = Flask(__name__)
app.url_map.strict_slashes = False  # tolerate trailing slashes


# -------- WSGI middleware: normalize '//' in PATH before routing --------
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
    cur = conn.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS groups (
        groupid TEXT PRIMARY KEY,
        groupname TEXT,
        parentid TEXT,
        payload_xml TEXT,
        updated_at TEXT
    )""")
    cur.execute("""
    CREATE TABLE IF NOT EXISTS products (
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
    cur.execute("""
    CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        endpoint TEXT,
        method TEXT,
        query TEXT,
        body TEXT,
        created_at TEXT
    )""")
    cur.execute("""
    CREATE TABLE IF NOT EXISTS orders_inbox (
        id TEXT PRIMARY KEY,
        payload_xml TEXT,
        status INTEGER DEFAULT 10, -- 10=ny/åpen, 20=importert
        created_at TEXT,
        updated_at TEXT
    )""")
    conn.commit()
    conn.close()

init_db()


# -------- Utils --------
def now_iso():
    return datetime.now(timezone.utc).isoformat()

def ok_txt(body="OK"):
    # Viktig: CRLF + windows-1252 for maksimal Uni-kompat
    return Response((body + "\r\n"), mimetype="text/plain; charset=windows-1252")

def xml_resp(xml_str: str):
    return Response(xml_str, mimetype="text/xml; charset=windows-1252")

def require_auth():
    return (request.args.get("user") == UNI_USER and request.args.get("pass") == UNI_PASS)

def save_log(endpoint):
    try:
        conn = db()
        conn.execute(
            "INSERT INTO logs(endpoint, method, query, body, created_at) VALUES (?,?,?,?,?)",
            (endpoint, request.method, request.query_string.decode("utf-8", "ignore"),
             request.data.decode("utf-8", "ignore"), now_iso())
        )
        conn.commit()
        conn.close()
    except Exception as e:
        log.warning("save_log failed: %s", e)

def to_float_safe(val):
    try:
        return float(str(val).replace(",", "."))
    except Exception:
        return None

def to_int_safe(val):
    try:
        return int(val)
    except Exception:
        try:
            return int(float(val))
        except Exception:
            return None

# ---- handle hex=true + tolerant XML tags ----
def read_xml_body():
    """
    Leser rå body og dekoder hvis hex=true.
    Prøver fornuftige encodings (utf-8, cp1252, latin-1).
    Returnerer (decoded_xml_str, was_hex: bool)
    """
    raw = request.get_data() or b""
    is_hex = (request.args.get("hex") or "").lower() in ("1", "true", "yes")
    if is_hex:
        try:
            raw = bytes.fromhex(raw.decode("ascii"))
        except Exception:
            # fall back hvis ikke ekte hex
            pass
    for enc in ("utf-8", "cp1252", "latin-1"):
        try:
            return raw.decode(enc), is_hex
        except Exception:
            continue
    return raw.decode("utf-8", "ignore"), is_hex

def findtext_any(elem, candidates, default=""):
    for tag in candidates:
        v = elem.findtext(tag)
        if v is not None:
            return v
    return default

def findall_any(root, candidates_xpath):
    for xp in candidates_xpath:
        nodes = root.findall(xp)
        if nodes:
            return nodes
    return []


# -------- Shopify client (minimal) --------
def ensure_shopify_headers():
    if not SHOPIFY_TOKEN:
        raise RuntimeError("SHOPIFY_TOKEN is not configured")
    return {
        "X-Shopify-Access-Token": SHOPIFY_TOKEN,
        "Content-Type": "application/json",
        "Accept": "application/json",
    }

def shopify_base():
    return f"https://{SHOPIFY_DOMAIN}/admin/api/{SHOPIFY_API_VERSION}"

def shopify_find_variant_by_sku(sku):
    headers = ensure_shopify_headers()
    url = f"{shopify_base()}/variants.json"
    r = requests.get(url, headers=headers, params={"sku": sku}, timeout=30)
    if r.status_code != 200:
        log.warning("Shopify variants lookup failed %s: %s", r.status_code, r.text[:500])
        return None
    variants = r.json().get("variants", [])
    return variants[0] if variants else None

def shopify_get_product(product_id):
    headers = ensure_shopify_headers()
    url = f"{shopify_base()}/products/{product_id}.json"
    r = requests.get(url, headers=headers, timeout=30)
    if r.status_code != 200:
        log.warning("Shopify get product failed %s: %s", r.status_code, r.text[:500])
        return None
    return r.json().get("product")

def shopify_create_product(payload):
    headers = ensure_shopify_headers()
    url = f"{shopify_base()}/products.json"
    r = requests.post(url, headers=headers, data=json.dumps({"product": payload}), timeout=60)
    if r.status_code not in (200, 201):
        raise RuntimeError(f"Shopify create product failed {r.status_code}: {r.text[:500]}")
    return r.json()["product"]

def shopify_update_product(product_id, payload):
    headers = ensure_shopify_headers()
    url = f"{shopify_base()}/products/{product_id}.json"
    r = requests.put(url, headers=headers, data=json.dumps({"product": payload}), timeout=60)
    if r.status_code not in (200, 201):
        raise RuntimeError(f"Shopify update product failed {r.status_code}: {r.text[:500]}")
    return r.json()["product"]

def shopify_set_inventory(inventory_item_id, available):
    headers = ensure_shopify_headers()
    url = f"{shopify_base()}/inventory_levels/set.json"
    body = {
        "location_id": int(SHOPIFY_LOCATION_ID),
        "inventory_item_id": int(inventory_item_id),
        "available": int(available or 0),
    }
    r = requests.post(url, headers=headers, data=json.dumps(body), timeout=30)
    if r.status_code not in (200, 201):
        raise RuntimeError(f"Shopify inventory set failed {r.status_code}: {r.text[:500]}")
    return r.json()

def upsert_shopify_product_from_row(row):
    sku = row["prodid"]
    name = row["name"]
    price = row["price"]
    body_html = row["body_html"]
    barcode = row["barcode"]
    stock = row["stock"] or 0
    webactive = "active" if (row["webactive"] == 1) else "draft"

    payload = {
        "title": name or sku,
        "body_html": body_html or "",
        "status": webactive,
        "tags": [f"group-{row['groupid']}"] if row["groupid"] else [],
        "variants": [{
            "sku": sku,
            "price": f"{(price or 0):.2f}",
            "barcode": barcode or None
        }]
    }

    variant = shopify_find_variant_by_sku(sku)
    if variant:
        product_id = variant["product_id"]
        variant_id = variant["id"]
        inventory_item_id = variant["inventory_item_id"]
        update_payload = {
            "id": product_id,
            "title": payload["title"],
            "body_html": payload["body_html"],
            "status": payload["status"],
            "tags": ",".join(payload["tags"]) if payload["tags"] else ""
        }
        shopify_update_product(product_id, update_payload)
    else:
        created = shopify_create_product(payload)
        product_id = created["id"]
        variant_id = created["variants"][0]["id"]
        inventory_item_id = created["variants"][0]["inventory_item_id"]

    try:
        shopify_set_inventory(inventory_item_id, stock)
    except Exception as e:
        log.warning("Inventory set failed for %s: %s", sku, e)

    return product_id, variant_id, inventory_item_id


# -------- Request logging --------
@app.before_request
def _log_req():
    try:
        log.info("REQ %s %s?%s", request.method, request.path, request.query_string.decode())
    except Exception:
        pass


# -------- Health/root/debug --------
@app.route("/", methods=["GET"])
def index():
    return ok_txt("OK")

@app.route("/healthz", methods=["GET"])
def healthz():
    return jsonify({"status": "ok", "time": now_iso(), "env": ENV})

@app.route("/debug/last", methods=["GET"])
def debug_last():
    conn = db()
    rows = conn.execute("SELECT * FROM logs ORDER BY id DESC LIMIT 5").fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


# -------- TwinXML: varegrupper --------
@app.route("/twinxml/postproductgroup.asp", methods=["GET","POST"])
@app.route("/twinxml/postproductgroup.aspx", methods=["GET","POST"])
def post_product_group():
    save_log("/twinxml/postproductgroup")
    if not require_auth():
        return ok_txt("ERROR:AUTH")
    if request.method == "GET":
        # enkelte oppsett tester GET; svar "OK"
        return ok_txt("OK")

    raw, was_hex = read_xml_body()
    try:
        root = ET.fromstring(raw)
    except Exception as e:
        log.warning("Bad XML groups (hex=%s): %s ... first200=%r", was_hex, e, raw[:200])
        return ok_txt("ERROR:XML")

    count = 0
    conn = db()
    group_nodes = findall_any(root, [
        ".//group", ".//productgroup", ".//gruppe", ".//varegruppe"
    ])
    for g in group_nodes:
        groupid   = (findtext_any(g, ["groupid","id","gruppeid","grpid"]).strip())
        groupname = (findtext_any(g, ["groupname","name","gruppenavn"]).strip())
        parentid  = (findtext_any(g, ["parentid","parent","overgruppeid"]).strip())
        if not groupid:
            continue
        conn.execute("""
            INSERT INTO groups(groupid, groupname, parentid, payload_xml, updated_at)
            VALUES(?,?,?,?,?)
            ON CONFLICT(groupid) DO UPDATE SET
              groupname=excluded.groupname,
              parentid=excluded.parentid,
              payload_xml=excluded.payload_xml,
              updated_at=excluded.updated_at
        """, (groupid, groupname, parentid, raw, now_iso()))
        count += 1
    conn.commit()
    conn.close()

    if count == 0:
        log.warning("No groups parsed (hex=%s). First200=%r", was_hex, raw[:200])

    log.info("Stored %d groups", count)
    return ok_txt("OK")


# -------- TwinXML: produkter --------
@app.route("/twinxml/postproduct.asp", methods=["GET","POST"])
@app.route("/twinxml/postproduct.aspx", methods=["GET","POST"])
def post_product():
    save_log("/twinxml/postproduct")
    if not require_auth():
        return ok_txt("ERROR:AUTH")
    if request.method == "GET":
        return ok_txt("OK")  # tåler GET-test

    raw, was_hex = read_xml_body()
    try:
        root = ET.fromstring(raw)
    except Exception as e:
        log.warning("Bad XML products (hex=%s): %s ... first200=%r", was_hex, e, raw[:200])
        return ok_txt("ERROR:XML")

    total_upsert = 0
    total_shopify = 0
    conn = db()

    # Finn produkter (flere varianter støttes)
    product_nodes = findall_any(root, [
        ".//product", ".//vare", ".//item", ".//produkt"
    ])
    if not product_nodes:
        # fallback hvis direkte under root
        product_nodes = list(root.findall("./product"))

    for p in product_nodes:
        # Varenr / SKU (Uni kan bruke 'productident')
        prodid    = (findtext_any(p, [
            "prodid", "varenr", "sku", "itemno", "productident"
        ]).strip())
        if not prodid:
            # logg første 200 tegn for feilsøk
            snippet = ET.tostring(p, encoding="unicode")[:200]
            log.warning("Product without prodid/SKU. First200=%r", snippet)
            continue

        # Navn / beskrivelse (Uni bruker noen ganger 'descrip')
        name      = (findtext_any(p, [
            "name", "varenavn", "title", "description", "productname", "descrip"
        ]).strip())

        # Pris (inkl. mva hvis PRICE_INCLUDES_VAT=True)
        price     = to_float_safe(findtext_any(p, [
            "price", "pris", "salesprice", "price_incl_vat", "newprice", "webprice"
        ]))

        vatcode   = (findtext_any(p, ["vatcode", "mvakode"]).strip())

        # Varegruppe
        groupid   = (findtext_any(p, [
            "groupid", "gruppeid", "grpid", "productgroup", "groupno"
        ]).strip())

        # Strekkode
        barcode   = (findtext_any(p, ["barcode", "ean"]).strip())

        # Lager
        stock     = to_int_safe(findtext_any(p, [
            "stock", "quantity", "qty", "lager", "onhand"
        ]))

        # HTML-beskrivelse (lang)
        body_html = findtext_any(p, [
            "body_html", "longtext", "description", "desc", "infohtml"
        ]) or ""

        # Bilde som base64 (hvis Uni sender det)
        image_b64 = findtext_any(p, ["image_b64", "image", "bilde_b64"]) or None

        # Aktivert for web
        webactive = 1 if (findtext_any(p, ["webactive", "active", "is_web"], "1").strip().lower() in ("1", "true", "yes")) else 0

        # MVA-håndtering dersom pris er eks. mva i Uni
        if price is not None and not PRICE_INCLUDES_VAT:
            price = round(price * 1.25, 2)

        # Skriv til DB
        conn.execute("""
            INSERT INTO products(prodid, name, price, vatcode, groupid, barcode, stock, body_html,
                                 image_b64, webactive, payload_xml, updated_at)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(prodid) DO UPDATE SET
              name=excluded.name,
              price=excluded.price,
              vatcode=excluded.vatcode,
              groupid=excluded.groupid,
              barcode=excluded.barcode,
              stock=excluded.stock,
              body_html=excluded.body_html,
              image_b64=excluded.image_b64,
              webactive=excluded.webactive,
              payload_xml=excluded.payload_xml,
              updated_at=excluded.updated_at
        """, (prodid, name, price, vatcode, groupid, barcode, stock, body_html,
              image_b64, webactive, raw, now_iso()))
        total_upsert += 1

        # Direkte til Shopify (hvis token er satt)
        if SHOPIFY_TOKEN:
            try:
                row = conn.execute("SELECT * FROM products WHERE prodid=?", (prodid,)).fetchone()
                product_id, variant_id, inventory_item_id = upsert_shopify_product_from_row(row)
                conn.execute("""
                    UPDATE products
                    SET last_shopify_product_id=?, last_shopify_variant_id=?, last_inventory_item_id=?
                    WHERE prodid=?
                """, (str(product_id), str(variant_id), str(inventory_item_id), prodid))
                total_shopify += 1
            except Exception as e:
                log.error("Shopify sync failed for %s: %s", prodid, e)

    conn.commit()
    conn.close()

    if total_upsert == 0:
        log.warning("No products parsed after tag fallbacks (hex=%s). First200=%r", was_hex, raw[:200])

    log.info("Upserted %d products (Shopify updated %d)", total_upsert, total_shopify)
    return ok_txt("OK")


# -------- TwinXML: ordre (MVP stub) --------
@app.route("/twinxml/orders.asp", methods=["GET"])
@app.route("/twinxml/orders.aspx", methods=["GET"])
def orders_list():
    save_log("/twinxml/orders")
    if not require_auth():
        # Returner tom liste i stedet for 401 – noen Uni-oppsett blir sære.
        return xml_resp("<orders></orders>")
    return xml_resp("<orders></orders>")  # tom liste er OK for Uni

@app.route("/twinxml/singleorder.asp", methods=["GET"])
@app.route("/twinxml/singleorder.aspx", methods=["GET"])
def single_order():
    save_log("/twinxml/singleorder")
    if not require_auth():
        return ok_txt("ERROR:AUTH")
    order_id = (request.args.get("id") or "").strip()
    if not order_id:
        return ok_txt("ERROR:NOID")

    conn = db()
    row = conn.execute("SELECT * FROM orders_inbox WHERE id=?", (order_id,)).fetchone()
    conn.close()

    if not row:
        xml = f"<order><id>{order_id}</id><status>10</status><lines></lines></order>"
        return xml_resp(xml)
    return xml_resp(row["payload_xml"])

@app.route("/twinxml/updateorder.asp", methods=["GET"])
@app.route("/twinxml/updateorder.aspx", methods=["GET"])
def update_order():
    save_log("/twinxml/updateorder")
    if not require_auth():
        return ok_txt("ERROR:AUTH")
    order_id = (request.args.get("id") or "").strip()
    status = int(request.args.get("status") or "20")
    if not order_id:
        return ok_txt("ERROR:NOID")

    conn = db()
    conn.execute("""
        INSERT INTO orders_inbox (id, payload_xml, status, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET status=excluded.status, updated_at=excluded.updated_at
    """, (order_id, f"<order><id>{order_id}</id><status>{status}</status></order>", status, now_iso(), now_iso()))
    conn.commit()
    conn.close()
    return ok_txt("OK")


# -------- Main --------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=PORT)
