"""
Uni Micro → Shopify sync (Render-ready)

This revision is the last known-good Flask app that actually CREATED
Shopify products and product groups (custom collections) from Uni Micro's
TwinXML posts. It focuses on:
  • /twinxml/postproductgroup.aspx  → Upsert Custom Collection
  • /twinxml/postproduct.aspx       → Upsert Product (+variant) by SKU, assign to collection, set inventory + price

Notes
-----
• Basic auth: username/password = synall / synall (adjust below if needed)
• Render: set environment vars in the service (DO NOT hardcode secrets):
    SHOPIFY_DOMAIN      e.g. "asmshop.no" (or "allsupermotoas.myshopify.com")
    SHOPIFY_TOKEN       e.g. "shpat_***"
    SHOPIFY_API_VERSION e.g. "2024-10"
    SHOPIFY_LOCATION_ID e.g. "16764928067"
• Returns plain text with CRLF (\r\n) because Uni Micro can be picky
• Idempotency is by SKU for products; for collections by ProductGroupNo
• Minimal error handling with clear logs (INFO level)

Procfile (create this as a separate file on Render):
  web: gunicorn -w 2 -k gthread -t 120 app:app

requirements.txt (create separately):
  Flask==3.0.3
  gunicorn==23.0.0
  requests==2.32.3

"""
from __future__ import annotations
import os
import logging
from typing import Dict, List, Optional, Tuple
from flask import Flask, request, Response
import xml.etree.ElementTree as ET
import requests

app = Flask(__name__)
logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s: %(message)s')

# -------- Shopify config --------
# OPTION A (recommended): set these as Render Environment Variables
#   SHOPIFY_DOMAIN (e.g. asmshop.no or allsupermotoas.myshopify.com)
#   SHOPIFY_TOKEN  (Admin API access token from your custom app)
#   SHOPIFY_API_VERSION (e.g. 2024-10)
#   SHOPIFY_LOCATION_ID (numeric location id for inventory)
# OPTION B: hardcode below (only for testing/dev). These are used if env vars are missing.
_HARDCODED_SHOPIFY_DOMAIN = "asmshop.no"                 # or "allsupermotoas.myshopify.com"
_HARDCODED_SHOPIFY_TOKEN = "YOUR_SHOPIFY_ACCESS_TOKEN"   # replace for local tests only
_HARDCODED_API_VERSION   = "2024-10"
_HARDCODED_LOCATION_ID   = "16764928067"                 # your Shopify location id

SHOPIFY_DOMAIN = (os.environ.get('SHOPIFY_DOMAIN') or _HARDCODED_SHOPIFY_DOMAIN).strip()
SHOPIFY_TOKEN = (os.environ.get('SHOPIFY_TOKEN') or _HARDCODED_SHOPIFY_TOKEN).strip()
SHOPIFY_API_VERSION = (os.environ.get('SHOPIFY_API_VERSION') or _HARDCODED_API_VERSION).strip()
SHOPIFY_LOCATION_ID = (os.environ.get('SHOPIFY_LOCATION_ID') or _HARDCODED_LOCATION_ID).strip()

if not SHOPIFY_TOKEN or SHOPIFY_TOKEN == "YOUR_SHOPIFY_ACCESS_TOKEN":
    logging.warning("SHOPIFY_TOKEN is not set (or still placeholder) — API calls will fail!")

BASE_URL = f"https://{SHOPIFY_DOMAIN}/admin/api/{SHOPIFY_API_VERSION}"

session = requests.Session()
session.headers.update({
    'X-Shopify-Access-Token': SHOPIFY_TOKEN,
    'Content-Type': 'application/json',
    'Accept': 'application/json',
})

# -------- Utils --------
def is_authenticated(username: str, password: str) -> bool:
    return username == 'synall' and password == 'synall'


def ok_txt(body: str = "OK") -> Response:
    # exact plain text + CRLF; UM can be picky about line endings
    return Response(body + "\r\n", mimetype="text/plain; charset=windows-1252")


@app.before_request
def _log_every_request():
    try:
        logging.info(f"REQ {request.method} {request.path}")
    except Exception:
        pass


def _auth_fail() -> Response:
    return Response("NOT AUTHORIZED\r\n", status=401, mimetype="text/plain; charset=windows-1252")


# -------- XML helpers --------
def _parse_xml(body: bytes) -> ET.Element:
    try:
        return ET.fromstring(body)
    except ET.ParseError as e:
        logging.exception("XML parse error")
        raise


def _txt(el: Optional[ET.Element]) -> str:
    return (el.text or '').strip() if el is not None else ''


# -------- Shopify REST helpers --------
def _shopify_get(path: str, params: Optional[dict] = None):
    r = session.get(BASE_URL + path, params=params, timeout=30)
    if r.status_code >= 400:
        logging.error("GET %s failed: %s %s", path, r.status_code, r.text[:500])
    return r


def _shopify_post(path: str, json: dict):
    r = session.post(BASE_URL + path, json=json, timeout=30)
    if r.status_code >= 400:
        logging.error("POST %s failed: %s %s", path, r.status_code, r.text[:500])
    return r


def _shopify_put(path: str, json: dict):
    r = session.put(BASE_URL + path, json=json, timeout=30)
    if r.status_code >= 400:
        logging.error("PUT %s failed: %s %s", path, r.status_code, r.text[:500])
    return r


# -------- Collections (Product Groups) --------
def upsert_custom_collection_by_pg(pg_no: str, name: str, parent_pg_no: str = "") -> Optional[int]:
    """Create or update a Custom Collection to represent a Uni Micro product group.
    Strategy: title = f"PG {pg_no} – {name}" so we can look it up deterministically.
    We also store metafield unimicro.product_group_no = pg_no.
    Returns collection_id or None.
    """
    title = f"PG {pg_no} – {name}".strip()

    # Try to find by title (REST supports title param for collections)
    r = _shopify_get("/custom_collections.json", params={"title": title, "limit": 1})
    if r.ok:
        data = r.json().get("custom_collections", [])
        if data:
            col = data[0]
            cid = col["id"]
            logging.info("Found existing collection %s (%s)", title, cid)
            # Ensure metafield is set
            set_collection_metafield(cid, namespace="unimicro", key="product_group_no", value=pg_no)
            if parent_pg_no:
                set_collection_metafield(cid, namespace="unimicro", key="parent_product_group_no", value=parent_pg_no)
            return int(cid)

    # Create if not found
    payload = {
        "custom_collection": {
            "title": title,
            "published": True,
        }
    }
    r = _shopify_post("/custom_collections.json", json=payload)
    if not r.ok:
        return None
    col = r.json()["custom_collection"]
    cid = int(col["id"])
    logging.info("Created collection %s (%s)", title, cid)

    # Metafields
    set_collection_metafield(cid, namespace="unimicro", key="product_group_no", value=pg_no)
    if parent_pg_no:
        set_collection_metafield(cid, namespace="unimicro", key="parent_product_group_no", value=parent_pg_no)
    return cid


def set_collection_metafield(collection_id: int, namespace: str, key: str, value: str):
    payload = {
        "metafield": {
            "namespace": namespace,
            "key": key,
            "type": "single_line_text_field",
            "value": str(value),
            # owner will be inferred from POST path
        }
    }
    _shopify_post(f"/collections/{collection_id}/metafields.json", json=payload)


# -------- Products --------
def find_variant_by_sku(sku: str) -> Tuple[Optional[int], Optional[int], Optional[int]]:
    """Return (product_id, variant_id, inventory_item_id) for an existing variant by SKU.
    Uses REST /variants.json?sku=...
    """
    r = _shopify_get("/variants.json", params={"sku": sku, "limit": 1})
    if not r.ok:
        return (None, None, None)
    variants = r.json().get("variants", [])
    if not variants:
        return (None, None, None)
    v = variants[0]
    return (int(v["product_id"]), int(v["id"]), int(v["inventory_item_id"]))


def create_simple_product(title: str, body_html: str, sku: str, price: str, barcode: str = "", vendor: str = "", product_type: str = "") -> Tuple[int, int, int]:
    payload = {
        "product": {
            "title": title,
            "body_html": body_html or None,
            "vendor": vendor or None,
            "product_type": product_type or None,
            "published": True,
            "variants": [
                {
                    "sku": sku,
                    "price": str(price),
                    "barcode": barcode or None,
                    "inventory_management": "shopify",
                    "requires_shipping": True,
                }
            ]
        }
    }
    r = _shopify_post("/products.json", json=payload)
    r.raise_for_status()
    p = r.json()["product"]
    v = p["variants"][0]
    return int(p["id"]), int(v["id"]), int(v["inventory_item_id"])


def update_variant_price(variant_id: int, price: str):
    payload = {"variant": {"id": variant_id, "price": str(price)}}
    _shopify_put(f"/variants/{variant_id}.json", json=payload)


def set_inventory(inventory_item_id: int, available: int):
    if not SHOPIFY_LOCATION_ID:
        logging.error("SHOPIFY_LOCATION_ID not set; cannot set inventory levels")
        return
    payload = {
        "location_id": int(SHOPIFY_LOCATION_ID),
        "inventory_item_id": int(inventory_item_id),
        "available": int(available)
    }
    _shopify_post("/inventory_levels/set.json", json=payload)


def assign_product_to_collection(product_id: int, collection_id: int):
    payload = {"collect": {"product_id": int(product_id), "collection_id": int(collection_id)}}
    r = _shopify_post("/collects.json", json=payload)
    if r.status_code == 422 and 'already' in r.text.lower():
        # already assigned — ignore
        return


# -------- TwinXML endpoints --------
@app.post('/twinxml/postproductgroup.aspx')
def post_productgroup():
    # Basic auth via query (?username=&password=) OR headers
    user = request.args.get('username', '') or request.authorization.username if request.authorization else ''
    pw = request.args.get('password', '') or request.authorization.password if request.authorization else ''
    if not is_authenticated(user, pw):
        return _auth_fail()

    root = _parse_xml(request.data)

    # Accept either a single <ProductGroup> or container <ArrayOfProductGroup><ProductGroup/></...>
    product_groups = []
    if root.tag.endswith('ArrayOfProductGroup'):
        product_groups = list(root.findall('.//ProductGroup'))
    elif root.tag.endswith('ProductGroup'):
        product_groups = [root]
    else:
        # Fallback: try to gather children named ProductGroup regardless
        product_groups = list(root.findall('.//ProductGroup'))

    created, updated, failed = 0, 0, 0

    for pg in product_groups:
        pg_no = _txt(pg.find('ProductGroupNo')) or _txt(pg.find('ProductGroupID'))
        name = _txt(pg.find('ProductGroupName')) or _txt(pg.find('Name'))
        parent_pg = _txt(pg.find('ParentProductGroupNo')) or _txt(pg.find('ParentID'))

        if not pg_no or not name:
            logging.error("Skipping ProductGroup with missing number or name: %s", ET.tostring(pg)[:200])
            failed += 1
            continue
        cid = upsert_custom_collection_by_pg(pg_no, name, parent_pg)
        if cid:
            # Simple heuristic: treat as updated if existed
            # (We checked by title first; if found, we returned early.)
            # To detect created vs updated precisely we could return a flag; keep it simple.
            updated += 1
        else:
            failed += 1

    msg = f"OK ProductGroups processed={len(product_groups)} updated={updated} failed={failed}"
    logging.info(msg)
    return ok_txt(msg)


@app.post('/twinxml/postproduct.aspx')
def post_product():
    # Basic auth via query (?username=&password=) OR headers
    user = request.args.get('username', '') or request.authorization.username if request.authorization else ''
    pw = request.args.get('password', '') or request.authorization.password if request.authorization else ''
    if not is_authenticated(user, pw):
        return _auth_fail()

    root = _parse_xml(request.data)

    # Accept either <ArrayOfProduct><Product/> or a single <Product>
    products = []
    if root.tag.endswith('ArrayOfProduct'):
        products = list(root.findall('.//Product'))
    elif root.tag.endswith('Product'):
        products = [root]
    else:
        products = list(root.findall('.//Product'))

    processed, created, updated, failed = 0, 0, 0, 0

    for p in products:
        sku = _txt(p.find('ProductNo')) or _txt(p.find('No')) or _txt(p.find('SKU'))
        title = _txt(p.find('ProductName')) or _txt(p.find('Name'))
        desc = _txt(p.find('Description'))
        price = _txt(p.find('Price')) or _txt(p.find('SalesPrice')) or '0'
        barcode = _txt(p.find('EAN')) or _txt(p.find('Barcode'))
        vendor = _txt(p.find('Supplier')) or _txt(p.find('Vendor'))
        product_type = _txt(p.find('ProductGroupName')) or _txt(p.find('Type'))
        pg_no = _txt(p.find('ProductGroupNo')) or _txt(p.find('GroupNo'))
        stock_txt = _txt(p.find('Stock')) or _txt(p.find('Quantity')) or '0'
        try:
            stock = int(float(stock_txt))
        except Exception:
            stock = 0

        if not sku or not title:
            logging.error("Skipping Product with missing SKU or title: %s", ET.tostring(p)[:200])
            failed += 1
            continue

        try:
            existing = find_variant_by_sku(sku)
            prod_id, var_id, inv_item_id = existing
            if prod_id is None:
                # Create new product
                prod_id, var_id, inv_item_id = create_simple_product(title=title, body_html=desc, sku=sku, price=str(price), barcode=barcode, vendor=vendor, product_type=product_type)
                created += 1
                logging.info("Created product %s (variant %s) for SKU %s", prod_id, var_id, sku)
            else:
                # Update price on existing variant
                update_variant_price(var_id, str(price))
                updated += 1
                logging.info("Updated price for SKU %s (variant %s)", sku, var_id)

            # Inventory
            if inv_item_id:
                set_inventory(inv_item_id, stock)

            # Assign to collection if we have a ProductGroupNo
            if pg_no:
                cid = upsert_custom_collection_by_pg(pg_no, product_type or f"Group {pg_no}")
                if cid:
                    assign_product_to_collection(prod_id, cid)
        except Exception:
            logging.exception("Failed upsert for SKU %s", sku)
            failed += 1
            continue

        processed += 1

    msg = f"OK Products processed={processed} created={created} updated={updated} failed={failed}"
    logging.info(msg)
    return ok_txt(msg)


# Optional: health check for Render
@app.get('/health')
def health():
    return ok_txt("OK")


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 10000)))
