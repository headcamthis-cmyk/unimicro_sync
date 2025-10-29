import os
import logging
import sqlite3
import json
from datetime import datetime, timezone
from flask import Flask, request, Response, jsonify
import xml.etree.ElementTree as ET
import requests

# ------------------- Config -------------------
APP_NAME = "uni-shopify-sync"
PORT = int(os.environ.get("PORT", "10000"))
ENV = os.environ.get("ENV", "prod")

# Uni auth (for enkelhets skyld brukes basic sjekk av query params)
UNI_USER = os.environ.get("UNI_USER", "synall")
UNI_PASS = os.environ.get("UNI_PASS", "synall")

# Shopify
SHOPIFY_DOMAIN = os.environ.get("SHOPIFY_DOMAIN", "asmshop.no")
SHOPIFY_TOKEN = os.environ.get("SHOPIFY_TOKEN")  # sett i Render dashboard
SHOPIFY_API_VERSION = os.environ.get("SHOPIFY_API_VERSION", "2024-10")
SHOPIFY_LOCATION_ID = os.environ.get("SHOPIFY_LOCATION_ID", "16764928067")
PRICE_INCLUDES_VAT = os.environ.get("PRICE_INCLUDES_VAT", "true").lower() == "true"

# DB
DB_URL = os.environ.get("DB_URL", "sync.db")

# Logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s: %(message)s",
)
log = logging.getLogger(APP_NAME)

# ------------------- App -------------------
app = Flask(__name__)

# ------------------- DB Helpers -------------------
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
    conn.commit()
    conn.close()

init_db()

# ------------------- Utils -------------------
def now_iso():
    return datetime.now(timezone.utc).isoformat()

def ok_txt(body="OK"):
    # Viktig: Uni kan være pirkete på \r\n og content-type
    return Response((body + "\r\n"), mimetype="text/plain; charset=windows-1252")

def require_auth():
    u = request.args.get("user")
    p = request.args.get("pass")
    return (u == UNI_USER and p == UNI_PASS)

def save_log(endpoint):
    conn = db()
    conn.execute(
        "INSERT INTO logs(endpoint, method, query, body, created_at) VALUES (?,?,?,?,?)",
        (endpoint, request.method, request.query_string.decode("utf-8", "ignore"),
         request.data.decode("utf-8", "ignore"), now_iso())
    )
    conn.commit()
    conn.close()

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

# ------------------- Shopify Client (minimal) -------------------
def shopify_find_variant_by_sku(sku):
    """Returnerer første variant som matcher SKU, ellers None"""
    headers = ensure_shopify_headers()
    url = f"{shopify_base()}/variants.json"
    params = {"sku": sku}
    r = requests.get(url, headers=headers, params=params, timeout=30)
    if r.status_code != 200:
        log.warning("Shopify variants lookup failed %s: %s", r.status_code, r.text[:500])
        return None
    data = r.json()
    variants = data.get("variants", [])
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
        "available": int(available)
    }
    r = requests.post(url, headers=headers, data=json.dumps(body), timeout=30)
    if r.status_code not in (200, 201):
        raise RuntimeError(f"Shopify inventory set failed {r.status_code}: {r.text[:500]}")
    return r.json()

def upsert_shopify_product_from_row(row):
    """
    Tar en DB-row (fra products) og oppretter/oppdaterer i Shopify.
    Returnerer (product_id, variant_id, inventory_item_id).
    """
    sku = row["prodid"]  # bruker Uni Varenr/prodid som SKU
    name = row["name"]
    price = row["price"]
    body_html = row["body_html"]
    barcode = row["barcode"]
    stock = row["stock"] or 0
    webactive
