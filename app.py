from flask import Flask, request, Response
import logging
import xml.etree.ElementTree as ET
import requests
from datetime import datetime
import time

app = Flask(__name__)
logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s: %(message)s')

SHOPIFY_DOMAIN = 'allsupermotoas.myshopify.com'
SHOPIFY_TOKEN = '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'
SHOPIFY_API_VERSION = '2024-10'


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
                "price": price
            }]
        }
    }
    response = requests.post(url, json=data, headers=headers)
    if response.status_code == 201:
        return response.json()['product']['id']
    logging.warning(f"Failed to create product: {response.status_code} - {response.text}")
    return None


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


@app.route('/product/twinxml/postproduct.aspx', methods=['POST'])
def post_product():
    username = request.args.get('user')
    password = request.args.get('pass')

    if not is_authenticated(username, password):
        return Response('Unauthorized', status=401)

    try:
        xml_data = request.data.decode('utf-8', errors='replace')
        root = ET.fromstring(xml_data)
        collections = get_existing_collections()

        for product in root.findall("product"):
            sku = product.find("productno").text
            title = product.find("description").text
            price = product.find("price").text
            group_id = product.find("productgroup").text

            handle = f"group-{group_id}".lower().replace(" ", "-")
            collection_id = collections.get(handle)

            if not collection_id:
                logging.warning(f"No collection found for group ID {group_id} (handle: {handle}). Skipping product {sku}.")
                continue

            product_id = create_product(title, sku, price)
            if product_id:
                assign_product_to_collection(product_id, collection_id)

    except Exception as e:
        logging.error(f"Failed to process product XML: {e}")
        return Response('<response>Error processing XML</response>', mimetype='text/xml')

    return Response('<response>OK</response>', mimetype='text/xml')


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
