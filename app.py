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

            product_id, inventory_item_id = create_product(title, sku, price)
            if product_id:
                assign_product_to_collection(product_id, collection_id)
            if inventory_item_id:
                update_inventory_level(inventory_item_id, quantity)

    except Exception as e:
        logging.error(f"Failed to process product XML: {e}")
        return Response('<response>Error processing XML</response>', mimetype='text/xml')

    return Response('<response>OK</response>', mimetype='text/xml')

@app.route('/product/twinxml/postproductgroup.aspx', methods=['POST'])
def post_productgroup():
    username = request.args.get('user')
    password = request.args.get('pass')

    if not is_authenticated(username, password):
        return Response('Unauthorized', status=401)

    try:
        xml_data = request.data.decode('utf-8', errors='replace')
        logging.info("Authorized productgroup POST received.")
        logging.info(f"Product Group XML:\n{xml_data}")

        root = ET.fromstring(xml_data)
        existing_collections = get_existing_collections()

        for pg in root.findall("productgroup"):
            group_id = pg.find("id").text
            title = pg.find("description").text
            handle = f"group-{group_id}".lower().replace(" ", "-")

            if handle in existing_collections:
                logging.info(f"Collection with handle '{handle}' already exists. Skipping creation.")
                continue

            create_collection(title, handle)

    except Exception as e:
        logging.error(f"Failed to process product group XML: {e}")
        return Response('<response>Error processing XML</response>', mimetype='text/xml')

    return Response('<response>OK</response>', mimetype='text/xml')

@app.route('/product/twinxml/orders.aspx', methods=['GET'])
def get_orders():
    return Response('<response>No orders processing implemented</response>', mimetype='text/xml')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
