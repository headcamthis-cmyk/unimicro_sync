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

UNI_USER = os.environ.get("UNI_USER", "synall")
UNI_PASS = os.environ.get("UNI_PASS", "synall")

SHOPIFY_DOMAIN = os.environ.get("SHOPIFY_DOMAIN", "asmshop.no")
SHOPIFY_TOKEN = os.environ.get("SHOPIFY_TOKEN")
SHOPIFY_API_VERSION = os.environ.get("SHOPIFY_API_VERSION", "2024-10")
SHOPIFY_LOCATION_ID = os.environ.get("SHOPIFY_LOCATION_ID", "16764928067")
PRICE_INCLUDES_VAT = os.environ.get("PRICE_INCLUDES_VAT", "true").lower() == "true"

DB_URL = os.environ.get("DB_URL", "sync.db")

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s: %(message)s")
log = logging.getLogger(APP_NAME)

app = Flask(__name__)
app.url_map.strict_slashes = False  # tolerate trailing slash diffs

# ------------ DB ------------
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
    # Minimal lagring av "ordre" (for test av Uni-orderflyt)
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

# ------------ Utils ------------
def now_iso():
    return datetime.now(timezone.utc).isoformat()

def ok_txt(body="OK"):
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
    try: return float(str(val).replace(",", "."))
    except Exception: return None

def to_int_safe(val):
    try: return int(val)
    except Exception:
        try: return int(float(val))
        except Exception: return None

# ------------ Shopify client (minimal) ------------
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
        existing = shopify_get_product(product_id) or {}
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

# ------------ Request logging & path normalisering ------------
@app.before_request
def _log_and_normalize():
    raw_path = request.environ.get("RAW_URI") or request.full_path or request.path
    log.info("REQ %s %s?%s", request.method, request.path, request.query_string.decode())
    # Tolerer // i path ved å “proxy-route” manuelt til riktige views
    if "//" in request.path:
        # vi oversetter på stedet (uten redirect) ved å sette PATH_INFO
        normalized = request.path.replace("//", "/")
        request.environ["PATH_INFO"] = normalized  # Flask ruter på PATH_INFO
        log.info("Normalized path %r -> %r", request.path, normalized)

@app.route("/healthz", methods=["GET"])
def healthz():
    return jsonify({"status": "ok", "time": now_iso(), "env": ENV})

@app.route("/debug/last", methods=["GET"])
def debug_last():
    conn = db()
    rows = conn.execute("SELECT * FROM logs ORDER BY id DESC LIMIT 5").fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

# ------------ TwinXML: varegrupper ------------
@app.route("/twinxml/postproductgroup.asp", methods=["POST"])
@app.route("/twinxml/postproductgroup.aspx", methods=["POST"])
def post_product_group():
    save_log("/twinxml/postproductgroup")
    if not require_auth():
        return ok_txt("ERROR:AUTH")
    raw = request.data.decode("utf-8", "ignore")
    try:
        root = ET.fromstring(raw)
    except Exception as e:
        log.warning("Bad XML groups: %s", e)
        return ok_txt("ERROR:XML")

    count = 0
    conn = db()
    for g in root.findall(".//group"):
        groupid = (g.findtext("groupid") or "").strip()
        groupname = (g.findtext("groupname") or "").strip()
        parentid = (g.findtext("parentid") or "").strip()
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
    log.info("Stored %d groups", count)
    return ok_txt("OK")

# ------------ TwinXML: produkter ------------
@app.route("/twinxml/postproduct.asp", methods=["POST"])
@app.route("/twinxml/postproduct.aspx", methods=["POST"])
def post_product():
    save_log("/twinxml/postproduct")
    if not require_auth():
        return ok_txt("ERROR:AUTH")

    raw = request.data.decode("utf-8", "ignore")
    try:
        root = ET.fromstring(raw)
    except Exception as e:
        log.warning("Bad XML products: %s", e)
        return ok_txt("ERROR:XML")

    total_upsert = 0
    total_shopify = 0
    conn = db()
    for p in root.findall(".//product"):
        prodid = (p.findtext("prodid") or "").strip()
        if not prodid:
            continue
        name = (p.findtext("name") or "").strip()
        price = to_float_safe(p.findtext("price"))
        vatcode = (p.findtext("vatcode") or "").strip()
        groupid = (p.findtext("groupid") or "").strip()
        barcode = (p.findtext("barcode") or "").strip()
        stock = to_int_safe(p.findtext("stock"))
        body_html = p.findtext("description") or p.findtext("body_html") or ""
        image_b64 = p.findtext("image_b64") or None
        webactive = 1 if (p.findtext("webactive") or "1").strip().lower() in ("1","true") else 0

        if price is not None and not PRICE_INCLUDES_VAT:
            price = round(price * 1.25, 2)

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
    log.info("Upserted %d products (Shopify updated %d)", total_upsert, total_shopify)
    return ok_txt("OK")

# ------------ TwinXML: ordre (MVP stub som svarer korrekt) ------------
# Liste "klare" ordrer
@app.route("/twinxml/orders.asp", methods=["GET"])
@app.route("/twinxml/orders.aspx", methods=["GET"])
def orders_list():
    save_log("/twinxml/orders")
    if not require_auth():
        # Noen oppsett forventer 200 med tom liste; vi svarer tom liste for auth-feil også,
        # men du kan endre til ERROR:AUTH hvis Uni faktisk feiler på det.
        return xml_resp("<orders></orders>")
    # I MVP har vi ikke en faktisk kø fra Shopify, så vi svarer tom liste:
    # Vil du teste flyten, legg manuelt inn en fake ordre i orders_inbox.
    return xml_resp("<orders></orders>")

# Enkeltordre henting
@app.route("/twinxml/singleorder.asp", methods=["GET"])
@app.route("/twinxml/singleorder.aspx", methods=["GET"])
def single_or_
