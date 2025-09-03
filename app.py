from flask import Flask, request, Response
import logging
import xml.etree.ElementTree as ET
import requests
from datetime import datetime

app = Flask(__name__)
logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s: %(message)s')

SHOPIFY_DOMAIN = 'allsupermotoas.myshopify.com'
SHOPIFY_TOKEN = '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'
SHOPIFY_API_VERSION = '2024-10'
SHOPIFY_LOCATION_ID = '16764928067'

def is_authenticated(username, password):
    return username == 'synall' and password == 'synall'

@app.route('/')
def index():
    return "Uni Micro Sync API is running."

def get_existing_collections():
    url = f"https://{SHOPIFY_DOMAIN}/admin/api/{SHOPIFY_API_VERSION}/custom_collections.json"
    headers = {
        "X-Shopify-Access-Token": SHOPIFY_TOKEN,
        "Content-Type": "application/json"
    }
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        collections = response.json().get('custom_collections', [])
        return {c['handle']: c['id'] for c in collections}
    return {}

def create_collection(title, handle):
    url = f"https://{SHOPIFY_DOMAIN}/admin/api/{SHOPIFY_API_VERSION}/custom_collections.json"
    headers = {
        "X-Shopify-Access-Token": SHOPIFY_TOKEN,
        "Content-Type": "application/json"
    }
    data = {
        "custom_collection": {
            "title": title,
            "handle": handle
        }
    }
    response = requests.post(url, json=data, headers=headers)
    if response.status_code in [200, 201]:
        logging.info(f"Created collection: {title} (Handle: {handle})")
    else:
        logging.warning(f"Failed to create collection {title}: {response.status_code} - {response.text}")

def find_product_by_sku(sku):
    url = f"https://{SHOPIFY_DOMAIN}/admin/api/{SHOPIFY_API_VERSION}/products.json?limit=250"
    headers = {"X-Shopify-Access-Token": SHOPIFY_TOKEN}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        products = response.json().get('products', [])
        for product in products:
            for variant in product.get('variants', []):
                if variant['sku'] == sku:
                    return {
                        "product_id": product['id'],
                        "variant_id": variant['id'],
                        "inventory_item_id": variant['inventory_item_id'],
                        "current_price": variant['price']
                    }
    return None

def create_product(title, sku, price):
    url = f"https://{SHOPIFY_DOMAIN}/admin/api/{SHOPIFY_API_VERSION}/products.json"
    headers = {
        "X-Shopify-Access-Token": SHOPIFY_TOKEN,
        "Content-Type": "application/json"
    }
    data = {
        "product": {
            "title": title,
            "variants": [{
                "sku": sku,
                "price": price,
                "inventory_management": "shopify"
            }]
        }
    }
    response = requests.post(url, json=data, headers=headers)
    if response.status_code == 201:
        product = response.json()['product']
        variant = product['variants'][0]
        return product['id'], variant['inventory_item_id']
    logging.warning(f"Failed to create product: {response.status_code} - {response.text}")
    return None, None

def update_product_price(variant_id, new_price):
    url = f"https://{SHOPIFY_DOMAIN}/admin/api/{SHOPIFY_API_VERSION}/variants/{variant_id}.json"
    headers = {"X-Shopify-Access-Token": SHOPIFY_TOKEN}
    data = {"variant": {"id": variant_id, "price": new_price}}
    response = requests.put(url, json=data, headers=headers)
    if response.status_code == 200:
        logging.info(f"Updated price for variant {variant_id} to {new_price}")
    else:
        logging.warning(f"Failed to update price for variant {variant_id}: {response.status_code} - {response.text}")

def assign_product_to_collection(product_id, collection_id):
    url = f"https://{SHOPIFY_DOMAIN}/admin/api/{SHOPIFY_API_VERSION}/collects.json"
    headers = {
        "X-Shopify-Access-Token": SHOPIFY_TOKEN,
        "Content-Type": "application/json"
    }
    data = {
        "collect": {
            "product_id": product_id,
            "collection_id": collection_id
        }
    }
    response = requests.post(url, json=data, headers=headers)
    if response.status_code == 201:
        logging.info(f"Assigned product {product_id} to collection {collection_id}")
    else:
        logging.warning(f"Failed to assign product to collection: {response.status_code} - {response.text}")

def update_inventory_level(inventory_item_id, quantity):
    url = f"https://{SHOPIFY_DOMAIN}/admin/api/{SHOPIFY_API_VERSION}/inventory_levels/set.json"
    headers = {
        "X-Shopify-Access-Token": SHOPIFY_TOKEN,
        "Content-Type": "application/json"
    }
    data = {
        "location_id": SHOPIFY_LOCATION_ID,
        "inventory_item_id": inventory_item_id,
        "available": quantity
    }
    response = requests.post(url, json=data, headers=headers)
    if response.status_code in [200, 201]:
        logging.info(f"Stock updated for inventory_item_id={inventory_item_id} to quantity={quantity}")
    else:
        logging.warning(f"Failed to update stock: {response.status_code} - {response.text}")

@app.route('/product/twinxml/postproduct.aspx', methods=['POST'])
def post_product():
    username = request.args.get('user')
    password = request.args.get('pass')

    if not is_authenticated(username, password):
        return Response('Unauthorized', status=401)

    try:
        xml_data = request.data.decode('utf-8', errors='replace')
        logging.info("Authorized product POST received.")
        logging.info(f"Product XML:\n{xml_data}")

        root = ET.fromstring(xml_data)
        collections = get_existing_collections()

        for product in root.findall("product"):
            sku_elem = product.find("productno") or product.find("productident")
            title_elem = product.find("description")
            price_elem = product.find("price")
            group_elem = product.find("productgroup")
            quantity_elem = product.find("quantityonhand")

            if None in (sku_elem, title_elem, price_elem, group_elem, quantity_elem):
                logging.warning("Skipping product due to missing field(s):")
                continue

            sku = sku_elem.text
            title = title_elem.text
            price = price_elem.text
            group_id = group_elem.text
            quantity = int(float(quantity_elem.text.replace(',', '.')))

            logging.info(f"Parsed product: SKU={sku}, Title={title}, Price={price}, Group ID={group_id}, Quantity={quantity}")

            handle = f"group-{group_id}".lower().replace(" ", "-")
            collection_id = collections.get(handle)

            if not collection_id:
                logging.warning(f"No collection found for group ID {group_id} (handle: {handle}). Skipping product {sku}.")
                continue

            existing_product = find_product_by_sku(sku)
            if existing_product:
                logging.info(f"Product with SKU {sku} exists, checking for updates.")
                if str(existing_product['current_price']) != str(price):
                    update_product_price(existing_product['variant_id'], price)
                update_inventory_level(existing_product['inventory_item_id'], quantity)
                assign_product_to_collection(existing_product['product_id'], collection_id)
            else:
                product_id, inventory_item_id = create_product(title, sku, price)
                if product_id:
                    assign_product_to_collection(product_id, collection_id)
                if inventory_item_id:
                    update_inventory_level(inventory_item_id, quantity)

    except Exception as e:
        logging.error(f"Failed to process product XML: {e}")
        return Response('<response>Error processing XML</response>', mimetype='text/xml')

    return Response('<response>OK</response>', mimetype='text/xml')

@app.route('/product/twinxml/postproduct.aspx', methods=['POST'])
def post_product():
    username = request.args.get('user')
    password = request.args.get('pass')
    if not is_authenticated(username, password):
        return Response('Unauthorized', status=401)

    try:
        raw = request.data  # keep bytes; let the XML parser handle declared encoding
        logging.info("Authorized product POST received.")
        logging.info(f"Request headers: {dict(request.headers)}")

        # Parse, tolerating utf-8/utf-16 and namespaces
        try:
            root = ET.fromstring(raw)
        except ET.ParseError as e:
            # As a fallback, try decoding to utf-8 explicitly
            root = ET.fromstring(raw.decode('utf-8', errors='replace'))
            logging.warning(f"XML parsed after utf-8 fallback. Original error: {e}")

        # Helper: case-insensitive tag fetch with multiple aliases
        def gettext(node, *names):
            for n in names:
                # try exact, lowercase, and namespace-agnostic
                el = node.find(n)
                if el is None:
                    el = node.find(n.lower())
                if el is None:
                    el = node.find(f".//{n}")  # in case of nested field
                if el is not None and el.text is not None:
                    t = el.text.strip()
                    if t != "":
                        return t
            # namespace-insensitive scan
            for child in node.iter():
                tag = child.tag.split('}', 1)[-1].lower() if '}' in child.tag else child.tag.lower()
                for n in names:
                    if tag == n.lower():
                        if child.text and child.text.strip():
                            return child.text.strip()
            return None

        # Preload collections once
        collections = get_existing_collections()
        logging.info(f"Loaded {len(collections)} collections for handle lookup")

        total = 0
        created = 0
        updated = 0
        skipped = 0

        # Find all product nodes anywhere in the tree
        for p in root.iter():
            if p.tag.split('}', 1)[-1].lower() != 'product':
                continue
            total += 1

            sku = gettext(p, "productno", "productident", "articleno", "itemno", "sku")
            title = gettext(p, "description", "name", "title")
            price = gettext(p, "price", "salesprice", "price1")
            qty_text = gettext(p, "quantityonhand", "stock", "instock", "physicalstock", "qty")
            group_id = gettext(p, "productgroup", "productgroupno", "groupno", "groupid", "pgid", "qvalue")

            # Convert quantity safely
            quantity = None
            if qty_text is not None:
                try:
                    quantity = int(float(qty_text.replace(',', '.')))
                except Exception:
                    pass

            # Log why we skip
            missing = [k for k, v in {
                "sku": sku, "title": title, "price": price, "group_id": group_id, "quantity": quantity
            }.items() if v in (None, "")]
            if missing:
                skipped += 1
                logging.warning(f"Skipping product due to missing field(s) {missing}. Raw children tags: {[c.tag for c in p]}")
                continue

            # Collection handle
            handle = f"group-{group_id}".lower().replace(" ", "-")
            collection_id = collections.get(handle)
            if not collection_id:
                skipped += 1
                logging.warning(f"Collection not found for handle '{handle}' (group_id={group_id}). Create group first or adjust mapping.")
                continue

            # Price normalization
            price_norm = str(float(str(price).replace(',', '.')))

            # Create or update
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
                if inventory_item_id and quantity is not None:
                    update_inventory_level(inventory_item_id, quantity)
                created += 1

        logging.info(f"Products processed: total={total}, created={created}, updated={updated}, skipped={skipped}")
        return Response('<response>OK</response>', mimetype='text/xml')

    except Exception as e:
        logging.exception(f"Failed to process product XML: {e}")
        return Response('<response>Error processing XML</response>', mimetype='text/xml', status=500)

    return Response('<response>OK</response>', mimetype='text/xml')

@app.route('/product/twinxml/orders.aspx', methods=['GET'])
def get_orders():
    return Response('<response>No orders processing implemented</response>', mimetype='text/xml')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
