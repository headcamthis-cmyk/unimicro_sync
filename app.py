from flask import Flask, request, Response
import logging
import xml.etree.ElementTree as ET
import requests
import os

app = Flask(__name__)
logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s: %(message)s')

# -------- Shopify config --------
SHOPIFY_DOMAIN = 'allsupermotoas.myshopify.com'
SHOPIFY_TOKEN = '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'
SHOPIFY_API_VERSION = '2024-10'
SHOPIFY_LOCATION_ID = '16764928067'  # inventory location

# -------- Utils --------
def is_authenticated(username, password):
    return username == 'synall' and password == 'synall'

def ok():
    return Response('OK', mimetype='text/plain')

@app.before_request
def _log_every_request():
    try:
        logging.info(f"REQ {request.method} {request.path}?{request.query_string.decode(errors='ignore')}")
    except Exception:
        pass

@app.route('/')
def index():
    return "Uni Micro Sync API is running."

def shopify_headers(json=True):
    h = {"X-Shopify-Access-Token": SHOPIFY_TOKEN}
    if json:
        h["Content-Type"] = "application/json"
    return h

def _parse_xml(raw_bytes, what="payload"):
    try:
        return ET.fromstring(raw_bytes)
    except ET.ParseError as e:
        logging.warning(f"{what}: primary parse failed ({e}); trying utf-8 fallback")
        return ET.fromstring(raw_bytes.decode('utf-8', errors='replace'))

def _gettext(node, *names):
    # Try direct and nested; case-/namespace-tolerant
    for n in names:
        el = node.find(n) or node.find(n.lower()) or node.find(f".//{n}")
        if el is not None and el.text and el.text.strip():
            return el.text.strip()
    for child in node.iter():
        tag = child.tag.split('}', 1)[-1].lower()
        for n in names:
            if tag == n.lower() and child.text and child.text.strip():
                return child.text.strip()
    return None

# -------- Shopify helpers --------
def get_existing_collections():
    url = f"https://{SHOPIFY_DOMAIN}/admin/api/{SHOPIFY_API_VERSION}/custom_collections.json"
    r = requests.get(url, headers=shopify_headers())
    if r.status_code == 200:
        return {c['handle']: c['id'] for c in r.json().get('custom_collections', [])}
    logging.warning(f"Failed to fetch collections: {r.status_code} - {r.text}")
    return {}

def create_collection(title, handle):
    url = f"https://{SHOPIFY_DOMAIN}/admin/api/{SHOPIFY_API_VERSION}/custom_collections.json"
    data = {"custom_collection": {"title": title, "handle": handle}}
    r = requests.post(url, headers=shopify_headers(), json=data)
    if r.status_code in (200, 201):
        logging.info(f"Created collection: {title} (handle: {handle})")
    else:
        logging.warning(f"Create collection failed for {title}: {r.status_code} - {r.text}")

def find_product_by_sku(sku):
    url = f"https://{SHOPIFY_DOMAIN}/admin/api/{SHOPIFY_API_VERSION}/products.json?limit=250"
    r = requests.get(url, headers=shopify_headers(json=False))
    if r.status_code == 200:
        for product in r.json().get('products', []):
            for variant in product.get('variants', []):
                if variant.get('sku') == sku:
                    return {
                        "product_id": product['id'],
                        "variant_id": variant['id'],
                        "inventory_item_id": variant['inventory_item_id'],
                        "current_price": variant['price']
                    }
    else:
        logging.warning(f"find_product_by_sku failed: {r.status_code} - {r.text}")
    return None

def create_product(title, sku, price):
    url = f"https://{SHOPIFY_DOMAIN}/admin/api/{SHOPIFY_API_VERSION}/products.json"
    data = {
        "product": {
            "title": title,
            "status": "active",
            "variants": [{
                "sku": sku,
                "price": str(price),
                "inventory_management": "shopify"
            }]
        }
    }
    r = requests.post(url, headers=shopify_headers(), json=data)
    if r.status_code in (200, 201):
        product = r.json()['product']
        variant = product['variants'][0]
        logging.info(f"Created product '{title}' (SKU {sku}) id={product['id']}")
        return product['id'], variant['inventory_item_id']
    logging.warning(f"Create product failed: {r.status_code} - {r.text}")
    return None, None

def update_product_price(variant_id, new_price):
    url = f"https://{SHOPIFY_DOMAIN}/admin/api/{SHOPIFY_API_VERSION}/variants/{variant_id}.json"
    data = {"variant": {"id": variant_id, "price": str(new_price)}}
    r = requests.put(url, headers=shopify_headers(), json=data)
    if r.status_code == 200:
        logging.info(f"Updated price for variant {variant_id} -> {new_price}")
    else:
        logging.warning(f"Update price failed: {r.status_code} - {r.text}")

def assign_product_to_collection(product_id, collection_id):
    url = f"https://{SHOPIFY_DOMAIN}/admin/api/{SHOPIFY_API_VERSION}/collects.json"
    data = {"collect": {"product_id": product_id, "collection_id": collection_id}}
    r = requests.post(url, headers=shopify_headers(), json=data)
    if r.status_code in (200, 201):
        logging.info(f"Assigned product {product_id} to collection {collection_id}")
    else:
        logging.warning(f"Assign to collection failed: {r.status_code} - {r.text}")

def update_inventory_level(inventory_item_id, quantity):
    url = f"https://{SHOPIFY_DOMAIN}/admin/api/{SHOPIFY_API_VERSION}/inventory_levels/set.json"
    data = {"location_id": SHOPIFY_LOCATION_ID, "inventory_item_id": inventory_item_id, "available": int(quantity)}
    r = requests.post(url, headers=shopify_headers(), json=data)
    if r.status_code in (200, 201):
        logging.info(f"Stock set inventory_item_id={inventory_item_id} -> {quantity}")
    else:
        logging.warning(f"Inventory update failed: {r.status_code} - {r.text}")

# -------- Handlers (core logic reused by multiple routes) --------
def _handle_product_post():
    username = request.args.get('user'); password = request.args.get('pass')
    if not is_authenticated(username, password):
        return Response('Unauthorized', status=401)

    raw = request.get_data()
    if request.method == 'GET' or not raw or not raw.strip():
        logging.info("Product endpoint called with empty body/preflight; returning OK")
        return ok()

    root = _parse_xml(raw, "product xml")
    collections = get_existing_collections()
    logging.info(f"Loaded {len(collections)} collections")

    total = created = updated = skipped = 0

    # Optional visibility: how many <product> nodes?
    count_products = 0
    for node in root.iter():
        if node.tag.split('}', 1)[-1].lower() == 'product':
            count_products += 1
    logging.info(f"Detected {count_products} <product> nodes")

    for p in root.iter():
        if p.tag.split('}', 1)[-1].lower() != 'product':
            continue
        total += 1

        sku = _gettext(p, "productno", "productident", "articleno", "itemno", "sku")
        title = _gettext(p, "description", "name", "title")
        price = _gettext(p, "price", "salesprice", "price1")
        qty_text = _gettext(p, "quantityonhand", "stock", "instock", "physicalstock", "qty")
        group_id = _gettext(p, "productgroup", "productgroupno", "groupno", "groupid", "pgid", "qvalue")

        quantity = None
        if qty_text is not None:
            try:
                quantity = int(float(qty_text.replace(',', '.')))
            except Exception:
                quantity = None

        missing = [k for k, v in {"sku": sku, "title": title, "price": price, "group_id": group_id, "quantity": quantity}.items() if v in (None, "")]
        if missing:
            skipped += 1
            logging.warning(f"Skipping product; missing {missing}. Children: {[c.tag for c in p]}")
            continue

        handle = f"group-{group_id}".lower().replace(" ", "-")
        collection_id = collections.get(handle)
        if not collection_id:
            skipped += 1
            logging.warning(f"No collection for handle '{handle}' (group_id={group_id}). Skipping SKU {sku}.")
            continue

        try:
            price_norm = str(float(str(price).replace(',', '.')))
        except Exception:
            price_norm = str(price)

        existing = find_product_by_sku(sku)
        if existing:
            if str(existing['current_price']) != price_norm:
                update_product_price(existing['variant_id'], price_norm)
            if quantity is not None:
                update_inventory_level(existing['inventory_item_id'], quantity)
            assign_product_to_collection(existing['product_id'], collection_id)
            updated += 1
        else:
            product_id, inventory_item_id = create_product(title, sku, price_norm)
            if product_id:
                assign_product_to_collection(product_id, collection_id)
            if inventory_item_id is not None and quantity is not None:
                update_inventory_level(inventory_item_id, quantity)
            created += 1

    logging.info(f"Products processed: total={total}, created={created}, updated={updated}, skipped={skipped}")
    return ok()

def _handle_productgroup_post():
    username = request.args.get('user'); password = request.args.get('pass')
    if not is_authenticated(username, password):
        return Response('Unauthorized', status=401)

    raw = request.get_data()
    if request.method == 'GET' or not raw or not raw.strip():
        logging.info("ProductGroup endpoint called with empty body/preflight; returning OK")
        return ok()

    root = _parse_xml(raw, "product group xml")

    existing = get_existing_collections()
    for pg in root.findall(".//productgroup"):
        gid_el = pg.find("id") or pg.find("groupno") or pg.find("qvalue")
        title_el = pg.find("description")
        if gid_el is None or title_el is None:
            logging.warning(f"Skipping productgroup; missing id/description. Children: {[c.tag for c in pg]}")
            continue

        group_id = gid_el.text.strip()
        title = title_el.text.strip()
        handle = f"group-{group_id}".lower().replace(" ", "-")

        if handle in existing:
            logging.info(f"Collection '{handle}' already exists. Skipping.")
            continue
        create_collection(title, handle)

    return ok()

def _handle_files_post():
    username = request.args.get('user'); password = request.args.get('pass')
    if not is_authenticated(username, password):
        return Response('Unauthorized', status=401)
    try:
        if 'file' in request.files:
            f = request.files['file']
            blob = f.read()
            sku = request.form.get('productno') or request.form.get('articleno') or request.form.get('itemno') or ''
            logging.info(f"Image received path={request.path} for SKU '{sku}': filename={f.filename}, size={len(blob)} bytes")
            # TODO: attach to Shopify product image
        else:
            raw = request.get_data()
            logging.info(f"Image upload (no multipart) path={request.path} size={len(raw)} bytes")
        return ok()
    except Exception as e:
        logging.exception(f"postfiles failed: {e}")
        return Response('ERROR', mimetype='text/plain', status=500)

# -------- Route aliases --------
# Accept .asp/.aspx and common path variants (including accidental double 'twinxml').

# PRODUCTS (single product)
@app.route('/twinxml/postproduct.asp', methods=['GET','POST'])
@app.route('/twinxml/postproduct.aspx', methods=['GET','POST'])
@app.route('/postproduct.asp', methods=['GET','POST'])
@app.route('/postproduct.aspx', methods=['GET','POST'])
@app.route('/product/twinxml/postproduct.asp', methods=['GET','POST'])
@app.route('/product/twinxml/postproduct.aspx', methods=['GET','POST'])
@app.route('/twinxml/twinxml/postproduct.asp', methods=['GET','POST'])
@app.route('/twinxml/twinxml/postproduct.aspx', methods=['GET','POST'])
def postproduct_router():
    return _handle_product_post()

# PRODUCTS (bulk / list variants → same handler)
@app.route('/twinxml/productlist.asp', methods=['GET','POST'])
@app.route('/twinxml/productlist.aspx', methods=['GET','POST'])
@app.route('/productlist.asp', methods=['GET','POST'])
@app.route('/productlist.aspx', methods=['GET','POST'])
@app.route('/twinxml/postproductlist.asp', methods=['GET','POST'])
@app.route('/twinxml/postproductlist.aspx', methods=['GET','POST'])
@app.route('/postproductlist.asp', methods=['GET','POST'])
@app.route('/postproductlist.aspx', methods=['GET','POST'])
@app.route('/twinxml/products.asp', methods=['GET','POST'])
@app.route('/twinxml/products.aspx', methods=['GET','POST'])
@app.route('/products.asp', methods=['GET','POST'])
@app.route('/products.aspx', methods=['GET','POST'])
@app.route('/product/twinxml/productlist.asp', methods=['GET','POST'])
@app.route('/product/twinxml/productlist.aspx', methods=['GET','POST'])
@app.route('/product/twinxml/postproductlist.asp', methods=['GET','POST'])
@app.route('/product/twinxml/postproductlist.aspx', methods=['GET','POST'])
@app.route('/product/twinxml/products.asp', methods=['GET','POST'])
@app.route('/product/twinxml/products.aspx', methods=['GET','POST'])
@app.route('/twinxml/twinxml/productlist.asp', methods=['GET','POST'])
@app.route('/twinxml/twinxml/productlist.aspx', methods=['GET','POST'])
@app.route('/twinxml/twinxml/postproductlist.asp', methods=['GET','POST'])
@app.route('/twinxml/twinxml/postproductlist.aspx', methods=['GET','POST'])
@app.route('/twinxml/twinxml/products.asp', methods=['GET','POST'])
@app.route('/twinxml/twinxml/products.aspx', methods=['GET','POST'])
def productlist_router():
    return _handle_product_post()

# PRODUCT GROUPS
@app.route('/twinxml/postproductgroup.asp', methods=['GET','POST'])
@app.route('/twinxml/postproductgroup.aspx', methods=['GET','POST'])
@app.route('/postproductgroup.asp', methods=['GET','POST'])
@app.route('/postproductgroup.aspx', methods=['GET','POST'])
@app.route('/product/twinxml/postproductgroup.asp', methods=['GET','POST'])
@app.route('/product/twinxml/postproductgroup.aspx', methods=['GET','POST'])
@app.route('/twinxml/twinxml/postproductgroup.asp', methods=['GET','POST'])
@app.route('/twinxml/twinxml/postproductgroup.aspx', methods=['GET','POST'])
def postproductgroup_router():
    return _handle_productgroup_post()

# FILES / IMAGES
@app.route('/twinxml/postfiles.asp', methods=['POST'])
@app.route('/twinxml/postfiles.aspx', methods=['POST'])
@app.route('/postfiles.asp', methods=['POST'])
@app.route('/postfiles.aspx', methods=['POST'])
@app.route('/product/twinxml/postfiles.asp', methods=['POST'])
@app.route('/product/twinxml/postfiles.aspx', methods=['POST'])
@app.route('/twinxml/twinxml/postfiles.asp', methods=['POST'])
@app.route('/twinxml/twinxml/postfiles.aspx', methods=['POST'])
def postfiles_router():
    return _handle_files_post()

# STATUS (no-op OK)
@app.route('/twinxml/status.asp', methods=['GET','POST'])
@app.route('/twinxml/status.aspx', methods=['GET','POST'])
@app.route('/status.asp', methods=['GET','POST'])
@app.route('/status.aspx', methods=['GET','POST'])
@app.route('/product/twinxml/status.asp', methods=['GET','POST'])
@app.route('/product/twinxml/status.aspx', methods=['GET','POST'])
@app.route('/twinxml/twinxml/status.asp', methods=['GET','POST'])
@app.route('/twinxml/twinxml/status.aspx', methods=['GET','POST'])
def status():
    return ok()

# ORDERS placeholder (return minimal XML so UM doesn't abort)
def _orders_ok_xml():
    return Response("<Orders/>", mimetype="text/xml")

@app.route('/twinxml/orders.asp', methods=['GET','POST'])
@app.route('/twinxml/orders.aspx', methods=['GET','POST'])
@app.route('/orders.asp', methods=['GET','POST'])
@app.route('/orders.aspx', methods=['GET','POST'])
@app.route('/product/twinxml/orders.asp', methods=['GET','POST'])
@app.route('/product/twinxml/orders.aspx', methods=['GET','POST'])
@app.route('/twinxml/twinxml/orders.asp', methods=['GET','POST'])
@app.route('/twinxml/twinxml/orders.aspx', methods=['GET','POST'])
def orders():
    return _orders_ok_xml()

# ---- FINAL catch-all + loud logging ----------------------------------------
def _looks_like_product(name: str) -> bool:
    n = name.lower()
    return any(k in n for k in [
        "postproduct", "productlist", "products", "postproductlist", "product",
        "postarticle", "articles", "article",
        "postitem", "items", "item",
        "uploadproduct", "sendproduct", "exportproducts"
    ])

def _looks_like_group(name: str) -> bool:
    n = name.lower()
    return any(k in n for k in ["productgroup", "postproductgroup", "groups", "group"])

@app.route('/twinxml/<path:name>.asp', methods=['GET','POST'])
@app.route('/twinxml/<path:name>.aspx', methods=['GET','POST'])
@app.route('/product/twinxml/<path:name>.asp', methods=['GET','POST'])
@app.route('/product/twinxml/<path:name>.aspx', methods=['GET','POST'])
@app.route('/twinxml/twinxml/<path:name>.asp', methods=['GET','POST'])
@app.route('/twinxml/twinxml/<path:name>.aspx', methods=['GET','POST'])
def twinxml_fallback(name):
    logging.info(f"FALLBACK hit name='{name}' method={request.method} len={request.content_length}")
    try:
        if _looks_like_product(name):
            logging.info("→ Routing to _handle_product_post() from fallback")
            return _handle_product_post()
        if _looks_like_group(name):
            logging.info("→ Routing to _handle_productgroup_post() from fallback")
            return _handle_productgroup_post()
        n = name.lower()
        if "order" in n:
            logging.info("→ Returning empty <Orders/> (fallback)")
            return Response("<Orders/>", mimetype="text/xml")
        if "status" in n:
            logging.info("→ Returning OK (status fallback)")
            return ok()
    except Exception:
        logging.exception(f"twinxml_fallback error for name='{name}'")
    # Default: don't fail UM preflights
    return ok()

# Entrypoint
if __name__
