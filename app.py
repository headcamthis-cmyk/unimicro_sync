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

# Shopify
SHOPIFY_DOMAIN = os.environ.get("SHOPIFY_DOMAIN", "allsupermotoas.myshopify.com")
SHOPIFY_TOKEN = os.environ.get("SHOPIFY_TOKEN")  # sett i Render
SHOPIFY_API_VERSION = os.environ.get("SHOPIFY_API_VERSION", "2024-10")
SHOPIFY_LOCATION_ID = os.environ.get("SHOPIFY_LOCATION_ID", "16764928067")
PRICE_INCLUDES_VAT = os.environ.get("PRICE_INCLUDES_VAT", "true").lower() in ("1", "true", "yes")

# Feature toggles
ENABLE_IMAGE_UPLOAD = os.environ.get("ENABLE_IMAGE_UPLOAD", "true").lower() in ("1","true","yes")
ENABLE_GROUP_COLLECTIONS = os.environ.get("ENABLE_GROUP_COLLECTIONS", "true").lower() in ("1","true","yes")
SHOPIFY_DELETE_MODE = os.environ.get("SHOPIFY_DELETE_MODE", "archive").lower()  # archive|delete|draft
ENABLE_SHOPIFY_DELETE = os.environ.get("ENABLE_SHOPIFY_DELETE", "true").lower() in ("1","true","yes")

# NEW: kontroll på hva gruppe-endepunktet svarer (for Uni-kompat)
# values: "empty" (default, tom respons), "plain_ok", "xml_ok"
UNI_GROUPS_RESPONSE_STYLE = os.environ.get("UNI_GROUPS_RESPONSE_STYLE", "empty").lower()

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
        status INTEGER DEFAULT 10,
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

def clean_b64(data):
    if not data:
        return None
    s = data.strip()
    m = re.match(r"^data:image/[\w+.-]+;base64,(.*)$", s, flags=re.IGNORECASE | re.DOTALL)
    if m:
        s = m.group(1)
    s = re.sub(r"\s+", "", s)
    try:
        base64.b64decode(s[:120] + "==", validate=False)
    except Exception:
        return None
    return s

# ---- handle hex=true + tolerant XML tags ----
def read_xml_body():
    raw = request.get_data() or b""
    is_hex = (request.args.get("hex") or "").lower() in ("1", "true", "yes")
    if is_hex:
        try:
            raw = bytes.fromhex(raw.decode("ascii"))
        except Exception:
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

# -------- Shopify client --------
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
    clean = {k: v for k, v in payload.items() if v is not None and v != ""}
    r = requests.put(url, headers=headers, data=json.dumps({"product": clean}), timeout=60)
    if r.status_code not in (200, 201):
        raise RuntimeError(f"Shopify update product failed {r.status_code}: {r.text[:500]}")
    return r.json()["product"]

def shopify_update_variant(variant_id, payload):
    headers = ensure_shopify_headers()
    url = f"{shopify_base()}/variants/{variant_id}.json"
    clean = {k: v for k, v in payload.items() if v is not None and v != ""}
    wrapper = {"variant": {"id": int(variant_id), **clean}}
    r = requests.put(url, headers=headers, data=json.dumps(wrapper), timeout=60)
    if r.status_code not in (200, 201):
        raise RuntimeError(f"Shopify update variant failed {r.status_code}: {r.text[:500]}")
    return r.json()["variant"]

def shopify_delete_product(product_id):
    headers = ensure_shopify_headers()
    url = f"{shopify_base()}/products/{product_id}.json"
    r = requests.delete(url, headers=headers, timeout=60)
    if r.status_code not in (200, 201, 204) and r.status_code != 404:
        raise RuntimeError(f"Shopify delete product failed {r.status_code}: {r.text[:500]}")
    return True

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

def shopify_get_images(product_id):
    headers = ensure_shopify_headers()
    url = f"{shopify_base()}/products/{product_id}/images.json"
    r = requests.get(url, headers=headers, timeout=30)
    if r.status_code != 200:
        log.warning("Shopify get images failed %s: %s", r.status_code, r.text[:500])
        return []
    return r.json().get("images", [])

def shopify_add_image(product_id, image_b64, filename=None, position=None, alt=None):
    headers = ensure_shopify_headers()
    url = f"{shopify_base()}/products/{product_id}/images.json"
    payload = {"image": {"attachment": image_b64}}
    if filename:
        payload["image"]["filename"] = filename
    if position is not None:
        payload["image"]["position"] = int(position)
    if alt:
        payload["image"]["alt"] = alt
    r = requests.post(url, headers=headers, data=json.dumps(payload), timeout=60)
    if r.status_code not in (200, 201):
        raise RuntimeError(f"Shopify add image failed {r.status_code}: {r.text[:500]}")
    return r.json()["image"]

def shopify_create_smart_collection_for_group(groupid):
    headers = ensure_shopify_headers()
    url = f"{shopify_base()}/smart_collections.json"
    title = f"Group {groupid}"
    handle = f"group-{groupid}"
    body = {
        "smart_collection": {
            "title": title,
            "handle": handle,
            "rules": [
                {"column": "tag", "relation": "equals", "condition": handle}
            ],
            "disjunctive": False,
            "published": True
        }
    }
    r = requests.post(url, headers=headers, data=json.dumps(body), timeout=60)
    if r.status_code in (200, 201):
        sc = r.json().get("smart_collection", {})
        log.info("Smart collection created for %s (id=%s)", handle, sc.get("id"))
        return sc
    if r.status_code == 422:
        log.info("Smart collection likely exists for %s (422).", handle)
        return None
    raise RuntimeError(f"Shopify create smart collection failed {r.status_code}: {r.text[:500]}")

def ensure_tracking_and_set_inventory(variant_id, inventory_item_id, stock):
    try:
        shopify_set_inventory(inventory_item_id, stock)
        return
    except RuntimeError as e:
        if "does not have inventory tracking enabled" not in str(e):
            raise
    shopify_update_variant(variant_id, {
        "inventory_management": "shopify",
        "inventory_policy": "deny",
        "requires_shipping": True
    })
    shopify_set_inventory(inventory_item_id, stock)

def upsert_shopify_product_from_row(row):
    sku = row["prodid"]
    name = row["name"]
    price = row["price"]
    body_html = row["body_html"]
    barcode = row["barcode"]
    stock = row["stock"] or 0
    is_active = (row["webactive"] == 1)
    groupid = row["groupid"]
    image_b64_raw = row["image_b64"]

    product_payload = {
        "title": name or sku,
        "body_html": body_html or "",
        "tags": [f"group-{groupid}"] if groupid else [],
        "variants": [{
            "sku": sku,
            "price": f"{(price or 0):.2f}",
            "barcode": barcode or None,
            "inventory_management": "shopify",
            "inventory_policy": "deny"
        }]
    }

    variant = shopify_find_variant_by_sku(sku)
    if variant:
        product_id = variant["product_id"]
        variant_id = variant["id"]
        inventory_item_id = variant["inventory_item_id"]

        update_payload = {
            "id": product_id,
            "title": product_payload["title"],
            "body_html": product_payload["body_html"],
        }
        if product_payload["tags"]:
            update_payload["tags"] = ",".join(product_payload["tags"])

        shopify_update_product(product_id, update_payload)
        log.info("Shopify UPDATE OK sku=%s product_id=%s admin=%s",
                 sku, product_id, f"https://{SHOPIFY_DOMAIN}/admin/products/{product_id}")
    else:
        create_payload = dict(product_payload)
        if create_payload["tags"]:
            create_payload["tags"] = ",".join(create_payload["tags"])
        create_payload["status"] = "active" if is_active else "draft"

        created = shopify_create_product(create_payload)
        product_id = created["id"]
        variant_id = created["variants"][0]["id"]
        inventory_item_id = created["variants"][0]["inventory_item_id"]
        log.info("Shopify CREATE OK sku=%s product_id=%s status=%s admin=%s",
                 sku, product_id, create_payload["status"],
                 f"https://{SHOPIFY_DOMAIN}/admin/products/{product_id}")

    if ENABLE_GROUP_COLLECTIONS and groupid:
        try:
            shopify_create_smart_collection_for_group(groupid)
        except Exception as e:
            log.warning("Smart collection create failed for group %s: %s", groupid, e)

    try:
        ensure_tracking_and_set_inventory(variant_id, inventory_item_id, stock)
    except Exception as e:
        log.warning("Inventory set failed for %s after enabling tracking: %s", sku, e)

    if ENABLE_IMAGE_UPLOAD and image_b64_raw:
        try:
            images = shopify_get_images(product_id)
            if not images:
                cleaned = clean_b64(image_b64_raw)
                if cleaned:
                    fname = f"{sku}.jpg"
                    shopify_add_image(product_id, cleaned, filename=fname, position=1, alt=name or sku)
                    log.info("Uploaded image for sku=%s product_id=%s", sku, product_id)
                else:
                    log.warning("image_b64 for %s not valid base64; skipped.", sku)
            else:
                log.info("Product %s already has %d image(s); skipping upload.", product_id, len(images))
        except Exception as e:
            log.warning("Image upload failed for %s: %s", sku, e)

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

@app.route("/debug/shopify/variant/<sku>", methods=["GET"])
def dbg_shopify_variant(sku):
    try:
        v = shopify_find_variant_by_sku(sku)
        if not v:
            return jsonify({"found": False}), 404
        pid = v["product_id"]
        return jsonify({
            "found": True,
            "variant_id": v["id"],
            "product_id": pid,
            "admin_url": f"https://{SHOPIFY_DOMAIN}/admin/products/{pid}"
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/debug/shopify/product/<int:pid>", methods=["GET"])
def dbg_shopify_product(pid):
    try:
        p = shopify_get_product(pid)
        if not p:
            return jsonify({"found": False}), 404
        return jsonify({
            "found": True,
            "id": p["id"],
            "title": p.get("title"),
            "status": p.get("status"),
            "tags": p.get("tags"),
            "variants": [{"id": v["id"], "sku": v.get("sku")} for v in p.get("variants", [])],
            "admin_url": f"https://{SHOPIFY_DOMAIN}/admin/products/{p['id']}"
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# -------- Helper for Uni groups OK style --------
def uni_groups_ok():
    if UNI_GROUPS_RESPONSE_STYLE == "plain_ok":
        return Response("OK", mimetype="text/plain; charset=windows-1252")
    if UNI_GROUPS_RESPONSE_STYLE == "xml_ok":
        return Response("<OK/>", mimetype="text/xml; charset=windows-1252")
    # default: tom respons (Content-Length: 0)
    return Response(status=200, mimetype="text/plain; charset=windows-1252")

# -------- TwinXML: varegrupper --------
@app.route("/twinxml/postproductgroup.asp", methods=["GET","POST"])
@app.route("/twinxml/postproductgroup.aspx", methods=["GET","POST"])
def post_product_group():
    save_log("/twinxml/postproductgroup")

    if request.method == "GET":
        return uni_groups_ok()

    if not require_auth():
        return uni_groups_ok()

    raw, was_hex = read_xml_body()
    try:
        root = ET.fromstring(raw)
    except Exception as e:
        log.warning("Bad XML groups (hex=%s): %s ... first200=%r", was_hex, e, raw[:200])
        return uni_groups_ok()

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

    log.info("Stored %d groups", count)
    return uni_groups_ok()

# -------- TwinXML: produkter (create/update) --------
# Alias som noen Uni-oppsett bruker ved “Last opp alle varer”
@app.route("/twinxml/postproduct.asp", methods=["GET","POST"])
@app.route("/twinxml/postproduct.aspx", methods=["GET","POST"])
@app.route("/twinxml/postproducts.asp", methods=["GET","POST"])
@app.route("/twinxml/postproducts.aspx", methods=["GET","POST"])
@app.route("/twinxml/postallproducts.asp", methods=["GET","POST"])
@app.route("/twinxml/postallproducts.aspx", methods=["GET","POST"])
def post_product():
    save_log("/twinxml/postproduct")
    if not require_auth():
        return ok_txt("OK")
    if request.method == "GET":
        return ok_txt("OK")

    raw, was_hex = read_xml_body()
    try:
        root = ET.fromstring(raw)
    except Exception as e:
        log.warning("Bad XML products (hex=%s): %s ... first200=%r", was_hex, e, raw[:200])
        return ok_txt("OK")

    total_upsert = 0
    total_shopify = 0
    conn = db()

    product_nodes = findall_any(root, [
        ".//product", ".//vare", ".//item", ".//produkt"
    ])
    if not product_nodes:
        candidates = []
        id_tags = ["prodid","varenr","sku","itemno","productident"]
        for elem in root.iter():
            if not list(elem):
                continue
            ident = findtext_any(elem, id_tags).strip()
            if ident:
                candidates.append(elem)
        product_nodes = candidates

    if not product_nodes:
        log.warning("No product-like nodes found (hex=%s). First200=%r", was_hex, raw[:200])
        return ok_txt("OK")

    for p in product_nodes:
        prodid = (findtext_any(p, ["prodid","varenr","sku","itemno","productident"]).strip())
        if not prodid:
            snippet = ET.tostring(p, encoding="unicode")[:200]
            log.warning("Product-like node without ident. First200=%r", snippet)
            continue

        name      = (findtext_any(p, ["name","varenavn","title","description","productname","descrip"]).strip())
        price     = to_float_safe(findtext_any(p, ["price","pris","salesprice","price_incl_vat","newprice","webprice"]))
        vatcode   = (findtext_any(p, ["vatcode","mvakode"]).strip())
        groupid   = (findtext_any(p, ["groupid","gruppeid","grpid","productgroup","groupno"]).strip())
        barcode   = (findtext_any(p, ["barcode","ean"]).strip())
        stock     = to_int_safe(findtext_any(p, ["stock","quantity","qty","lager","onhand"]))
        body_html = findtext_any(p, ["body_html","longtext","description","desc","infohtml","descrip"]) or ""
        image_b64 = findtext_any(p, ["image_b64","image","bilde_b64"]) or None
        webactive = 1 if (findtext_any(p, ["webactive","active","is_web"], "1").strip().lower() in ("1","true","yes")) else 0

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

# -------- TwinXML: delete product --------
@app.route("/twinxml/deleteproduct.asp", methods=["GET","POST"])
@app.route("/twinxml/deleteproduct.aspx", methods=["GET","POST"])
def delete_product():
    save_log("/twinxml/deleteproduct")
    if not require_auth():
        return ok_txt("OK")

    sku = (request.args.get("id") or request.values.get("id") or "").strip()
    if not sku:
        return ok_txt("OK")

    conn = db()
    conn.execute("DELETE FROM products WHERE prodid=?", (sku,))
    conn.commit()
    conn.close()

    if SHOPIFY_TOKEN and ENABLE_SHOPIFY_DELETE:
        try:
            variant = shopify_find_variant_by_sku(sku)
            if variant:
                product_id = variant["product_id"]
                inv_item_id = variant["inventory_item_id"]
                try:
                    shopify_set_inventory(inv_item_id, 0)
                except Exception as e:
                    log.info("Inventory zeroing for %s skipped/failed: %s", sku, e)

                mode = SHOPIFY_DELETE_MODE
                if mode == "delete":
                    shopify_delete_product(product_id)
                    log.info("Shopify DELETE product_id=%s sku=%s", product_id, sku)
                elif mode == "draft":
                    shopify_update_product(product_id, {"id": product_id, "status": "draft"})
                    log.info("Shopify set DRAFT product_id=%s sku=%s", product_id, sku)
                else:
                    shopify_update_product(product_id, {"id": product_id, "status": "archived"})
                    log.info("Shopify ARCHIVE product_id=%s sku=%s", product_id, sku)
            else:
                log.info("Shopify variant not found for sku=%s (already removed?)", sku)
        except Exception as e:
            log.warning("Shopify delete/archive failed for %s: %s", sku, e)
    else:
        if not ENABLE_SHOPIFY_DELETE:
            log.info("ENABLE_SHOPIFY_DELETE=false; OK returned without touching Shopify for sku=%s", sku)

    return ok_txt("OK")

# -------- TwinXML: ordre (MVP stub) --------
@app.route("/twinxml/orders.asp", methods=["GET"])
@app.route("/twinxml/orders.aspx", methods=["GET"])
def orders_list():
    save_log("/twinxml/orders")
    if not require_auth():
        return xml_resp("<orders></orders>")
    return xml_resp("<orders></orders>")

@app.route("/twinxml/singleorder.asp", methods=["GET"])
@app.route("/twinxml/singleorder.aspx", methods=["GET"])
def single_order():
    save_log("/twinxml/singleorder")
    if not require_auth():
        return ok_txt("OK")
    order_id = (request.args.get("id") or "").strip()
    if not order_id:
        return ok_txt("OK")
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
        return ok_txt("OK")
    order_id = (request.args.get("id") or "").strip()
    status = int(request.args.get("status") or "20")
    if not order_id:
        return ok_txt("OK")
    conn = db()
    conn.execute("""
        INSERT INTO orders_inbox (id, payload_xml, status, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET status=excluded.status, updated_at=excluded.updated_at
    """, (order_id, f"<order><id>{order_id}</id><status>{status}</status></order>", status, now_iso(), now_iso()))
    conn.commit()
    conn.close()
    return ok_txt("OK")

# -------- TwinXML: separate bilder (stub – svarer OK) --------
@app.route("/twinxml/postimages.asp", methods=["GET","POST"])
@app.route("/twinxml/postimages.aspx", methods=["GET","POST"])
def post_images_stub():
    save_log("/twinxml/postimages")
    return ok_txt("OK")

# -------- Main --------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=PORT)
