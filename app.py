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
    # Try direct and nested; case- and namespace-tolerant
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
def _get_from_node(node, names, attr_names=None):
    # try child elements by name (any depth, any case)
    v = _gettext(node, *names)
    if v:
        return v
    # try attributes on matching child elements
    if attr_names:
        want = {n.lower() for n in names}
        for child in node.iter():
            tag = child.tag.split('}', 1)[-1].lower()
            if tag in want:
                for a in attr_names:
                    if a in child.attrib and child.attrib[a].strip():
                        return child.attrib[a].strip()
    # try attributes on the product node itself
    if attr_names:
        for a in attr_names:
            if a in node.attrib and node.attrib[a].strip():
                return node.attrib[a].strip()
    return None

# inside _handle_product_post(), for each <product> p:
sku = _get_from_node(p,
    ["productno","productident","articleno","itemno","sku"],
    ["id","no","sku"]
)
title = _get_from_node(p,
    ["description","name","title"],
    ["description","name","title"]
)
price = _get_from_node(p,
    ["price","salesprice","price1","netprice"],
    ["price","salesprice","netprice","value"]
)
qty_text = _get_from_node(p,
    ["quantityonhand","quantity","stock","instock","physicalstock","qty"],
    ["quantity","qty","stock","onhand","value"]
)
group_id = _get_from_node(p,
    ["productgroup","productgroupno","groupno","groupid","pgid","qvalue"],
    ["productgroup","groupno","groupid","pgid","qvalue"]
)

quantity = None
if qty_text not in (None, ""):
    try:
        quantity = int(float(str(qty_text).replace(',', '.')))
    except Exception:
        quantity = None

# only require SKU, title, price and group_id
missing = [k for k, v in {
    "sku": sku, "title": title, "price": price, "group_id": group_id
}.items() if v in (None, "")]
if missing:
    skipped += 1
    logging.warning(f"Skipping product; missing {missing}. Children: {[c.tag.split('}',1)[-1] for c in p]}")
    continue
def _handle_productgroup_post():
    username = request.args.get('user'); password = request.args.get('pass')
    if not is_authenticated(username, password):
        return Response('Unauthorized', status=401)

    raw = request.get_data()
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
# Per Uni docs, twinxml is appended automatically and default names are .asp (but can be .aspx). Support all combos. :contentReference[oaicite:2]{index=2}

# PRODUCTS
@app.route('/twinxml/postproduct.asp', methods=['POST'])
@app.route('/twinxml/postproduct.aspx', methods=['POST'])
@app.route('/postproduct.asp', methods=['POST'])
@app.route('/postproduct.aspx', methods=['POST'])
@app.route('/product/twinxml/postproduct.asp', methods=['POST'])
@app.route('/product/twinxml/postproduct.aspx', methods=['POST'])
def postproduct_router():
    return _handle_product_post()

# PRODUCT GROUPS
@app.route('/twinxml/postproductgroup.asp', methods=['POST'])
@app.route('/twinxml/postproductgroup.aspx', methods=['POST'])
@app.route('/postproductgroup.asp', methods=['POST'])
@app.route('/postproductgroup.aspx', methods=['POST'])
@app.route('/product/twinxml/postproductgroup.asp', methods=['POST'])
@app.route('/product/twinxml/postproductgroup.aspx', methods=['POST'])
def postproductgroup_router():
    return _handle_productgroup_post()

# FILES / IMAGES
@app.route('/twinxml/postfiles.asp', methods=['POST'])
@app.route('/twinxml/postfiles.aspx', methods=['POST'])
@app.route('/postfiles.asp', methods=['POST'])
@app.route('/postfiles.aspx', methods=['POST'])
@app.route('/product/twinxml/postfiles.asp', methods=['POST'])
@app.route('/product/twinxml/postfiles.aspx', methods=['POST'])
def postfiles_router():
    return _handle_files_post()

# STATUS
@app.route('/twinxml/status.asp', methods=['GET', 'POST'])
@app.route('/twinxml/status.aspx', methods=['GET', 'POST'])
@app.route('/status.asp', methods=['GET', 'POST'])
@app.route('/status.aspx', methods=['GET', 'POST'])
@app.route('/product/twinxml/status.asp', methods=['GET', 'POST'])
@app.route('/product/twinxml/status.aspx', methods=['GET', 'POST'])
def status():
    return ok()

# ORDERS placeholder (still “OK”)
@app.route('/twinxml/orders.asp', methods=['GET', 'POST'])
@app.route('/orders.asp', methods=['GET', 'POST'])
@app.route('/product/twinxml/orders.asp', methods=['GET', 'POST'])
def orders():
    return ok()

# Entrypoint
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
