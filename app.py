from flask import Flask, request, Response
import logging
import xml.etree.ElementTree as ET
import requests
import os

app = Flask(__name__)
logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s: %(message)s')

# === Shopify config ===
SHOPIFY_DOMAIN = 'allsupermotoas.myshopify.com'
SHOPIFY_TOKEN = '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'
SHOPIFY_API_VERSION = '2024-10'
SHOPIFY_LOCATION_ID = '16764928067'  # inventory location

# === Helpers ===
def is_authenticated(username, password):
    return username == 'synall' and password == 'synall'

def ok():
    # Uni expects literally "OK" (no XML wrapper)
    return Response('OK', mimetype='text/plain')

@app.route('/')
def index():
    return "Uni Micro Sync API is running."

def shopify_headers(json=True):
    h = {"X-Shopify-Access-Token": SHOPIFY_TOKEN}
    if json:
        h["Content-Type"] = "application/json"
    return h

def get_existing_collections():
    # NOTE: Not paginated yet—fine for a small number of collections
    url = f"https://{SHOPIFY_DOMAIN}/admin/api/{SHOPIFY_API_VERSION}/custom_collections.json"
    r = requests.get(url, headers=shopify_headers())
    if r.status_code == 200:
        collections = r.json().get('custom_collections', [])
        return {c['handle']: c['id'] for c in collections}
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
    # Basic: scan first 250 products. (Can optimize later with /variants?sku=)
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
    data = {
        "location_id": SHOPIFY_LOCATION_ID,
        "inventory_item_id": inventory_item_id,
        "available": int(quantity)
    }
    r = requests.post(url, headers=shopify_headers(), json=data)
    if r.status_code in (200, 201):
        logging.info(f"Stock set inventory_item_id={inventory_item_id} -> {quantity}")
    else:
        logging.warning(f"Inventory update failed: {r.status_code} - {r.text}")

# === TwinXML: Products ===
@app.route('/product/twinxml/postproduct.aspx', methods=['POST'])
def post_product():
    username = request.args.get('user')
    password = request.args.get('pass')
    if not is_authenticated(username, password):
        return Response('Unauthorized', status=401)

    try:
        raw = request.get_data()  # keep bytes; honor encoding in XML decl
        logging.info("Authorized product POST received.")
        logging.info(f"Request headers: {dict(request.headers)}")

        # Parse XML (UTF-8/UTF-16 tolerant)
        try:
            root = ET.fromstring(raw)
        except ET.ParseError as e:
            root = ET.fromstring(raw.decode('utf-8', errors='replace'))
            logging.warning(f"XML parsed after utf-8 fallback. Original error: {e}")

        def gettext(node, *names):
            """Get first matching child text by any of the provided tag names (namespace/case tolerant)."""
            # direct matches
            for n in names:
                el = node.find(n) or node.find(n.lower()) or node.find(f".//{n}")
                if el is not None and el.text and el.text.strip():
                    return el.text.strip()
            # scan children ignoring namespaces
            for child in node.iter():
                tag = child.tag.split('}', 1)[-1].lower()
                for n in names:
                    if tag == n.lower() and child.text and child.text.strip():
                        return child.text.strip()
            return None

        collections = get_existing_collections()
        logging.info(f"Loaded {len(collections)} collections")

        total = created = updated = skipped = 0

        # Iterate any <product> nodes anywhere
        for p in root.iter():
            if p.tag.split('}', 1)[-1].lower() != 'product':
                continue
            total += 1

            sku = gettext(p, "productno", "productident", "articleno", "itemno", "sku")
            title = gettext(p, "description", "name", "title")
            price = gettext(p, "price", "salesprice", "price1")
            qty_text = gettext(p, "quantityonhand", "stock", "instock", "physicalstock", "qty")
            group_id = gettext(p, "productgroup", "productgroupno", "groupno", "groupid", "pgid", "qvalue")

            # normalize quantity
            quantity = None
            if qty_text is not None:
                try:
                    quantity = int(float(qty_text.replace(',', '.')))
                except Exception:
                    quantity = None

            # required fields
            missing = [k for k, v in {
                "sku": sku, "title": title, "price": price, "group_id": group_id, "quantity": quantity
            }.items() if v in (None, "")]
            if missing:
                skipped += 1
                logging.warning(f"Skipping product; missing {missing}. Child tags: {[c.tag for c in p]}")
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

    except Exception as e:
        logging.exception(f"Failed to process product XML: {e}")
        return Response('ERROR', mimetype='text/plain', status=500)

# === TwinXML: Product Groups -> Shopify Collections ===
@app.route('/product/twinxml/postproductgroup.aspx', methods=['POST'])
def post_productgroup():
    username = request.args.get('user')
    password = request.args.get('pass')
    if not is_authenticated(username, password):
        return Response('Unauthorized', status=401)

    try:
        raw = request.get_data()
        logging.info("Authorized productgroup POST received.")

        try:
            root = ET.fromstring(raw)
        except ET.ParseError as e:
            root = ET.fromstring(raw.decode('utf-8', errors='replace'))
            logging.warning(f"Group XML parsed after utf-8 fallback. Original error: {e}")

        existing = get_existing_collections()

        # handle any nesting: .//productgroup
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

    except Exception as e:
        logging.exception(f"Failed to process product group XML: {e}")
        return Response('ERROR', mimetype='text/plain', status=500)

# === TwinXML: Image upload (stub) ===
@app.route('/product/twinxml/postfiles.aspx', methods=['POST'])
def post_files():
    username = request.args.get('user')
    password = request.args.get('pass')
    if not is_authenticated(username, password):
        return Response('Unauthorized', status=401)

    try:
        if 'file' in request.files:
            f = request.files['file']
            blob = f.read()
            sku = request.form.get('productno') or request.form.get('articleno') or request.form.get('itemno') or ''
            logging.info(f"Image received for SKU '{sku}': filename={f.filename}, size={len(blob)} bytes")
            # TODO: attach to Shopify product images (optional next step)
        else:
            raw = request.get_data()
            logging.info(f"Image upload (no multipart) size={len(raw)} bytes")
        return ok()
    except Exception as e:
        logging.exception(f"postfiles.aspx failed: {e}")
        return Response('ERROR', mimetype='text/plain', status=500)

# === TwinXML: Status (optional) ===
@app.route('/product/twinxml/status.aspx', methods=['GET', 'POST'])
def status():
    return ok()

# === Placeholder for orders ===
@app.route('/product/twinxml/orders.aspx', methods=['GET'])
def get_orders():
    return ok()  # or 'No orders' if you prefer

# === Entrypoint ===
if __name__ == '__main__':
    # Port 5000 is common on Render/Heroku-ish setups
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
