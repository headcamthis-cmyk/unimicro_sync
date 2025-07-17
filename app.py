from flask import Flask, request, Response
import logging
import xml.etree.ElementTree as ET
import requests

app = Flask(__name__)
logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s: %(message)s')

SHOPIFY_DOMAIN = 'allsupermotoas.myshopify.com'
SHOPIFY_TOKEN = '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'
SHOPIFY_API_VERSION = '2024-10'


def is_authenticated(username, password):
    return username == 'synall' and password == 'synall'


def find_product_by_sku(sku):
    url = f"https://{SHOPIFY_DOMAIN}/admin/api/{SHOPIFY_API_VERSION}/products.json?fields=id,variants&limit=250"
    headers = {"X-Shopify-Access-Token": SHOPIFY_TOKEN}

    response = requests.get(url, headers=headers)
    if response.status_code != 200:
        logging.error(f"Failed to fetch products: {response.status_code} - {response.text}")
        return None

    products = response.json().get('products', [])
    for product in products:
        for variant in product.get('variants', []):
            if variant['sku'] == sku:
                return {
                    'product_id': product['id'],
                    'variant_id': variant['id'],
                    'inventory_item_id': variant['inventory_item_id']
                }
    return None


def update_stock_level(inventory_item_id, available_quantity):
    # First fetch the location ID
    location_url = f"https://{SHOPIFY_DOMAIN}/admin/api/{SHOPIFY_API_VERSION}/locations.json"
    headers = {"X-Shopify-Access-Token": SHOPIFY_TOKEN}
    loc_response = requests.get(location_url, headers=headers)

    if loc_response.status_code != 200:
        logging.error(f"Failed to fetch locations: {loc_response.status_code} - {loc_response.text}")
        return False

    locations = loc_response.json().get('locations', [])
    if not locations:
        logging.error("No locations found in Shopify store.")
        return False

    location_id = locations[0]['id']

    url = f"https://{SHOPIFY_DOMAIN}/admin/api/{SHOPIFY_API_VERSION}/inventory_levels/set.json"
    payload = {
        "location_id": location_id,
        "inventory_item_id": inventory_item_id,
        "available": int(available_quantity)
    }

    stock_response = requests.post(url, json=payload, headers=headers)
    if stock_response.status_code == 200:
        logging.info(f"Successfully updated stock for inventory item {inventory_item_id} to {available_quantity}")
        return True
    else:
        logging.error(f"Failed to update stock: {stock_response.status_code} - {stock_response.text}")
        return False


@app.route('/product/twinxml/updatestock.aspx', methods=['POST'])
def update_stock():
    username = request.args.get('user')
    password = request.args.get('pass')

    if not is_authenticated(username, password):
        return Response('Unauthorized', status=401)

    try:
        xml_data = request.data.decode('utf-8', errors='replace')
        logging.info("Authorized stock update POST received.")
        logging.info(f"Stock XML:\n{xml_data}")

        root = ET.fromstring(xml_data)

        for product in root.findall("product"):
            sku_elem = product.find("productident")
            quantity_elem = product.find("quantityonhand")

            if sku_elem is None or quantity_elem is None:
                logging.warning("Skipping product with missing SKU or quantityonhand")
                continue

            sku = sku_elem.text
            quantity = quantity_elem.text.replace(',', '.')  # Handle comma decimal if present
            quantity = int(float(quantity))

            product_info = find_product_by_sku(sku)

            if product_info:
                update_stock_level(product_info['inventory_item_id'], quantity)
            else:
                logging.warning(f"No matching Shopify product found for SKU {sku}. Skipping stock update.")

    except Exception as e:
        logging.error(f"Failed to process stock update XML: {e}")
        return Response('<response>Error processing stock XML</response>', mimetype='text/xml')

    return Response('<response>Stock update complete</response>', mimetype='text/xml')


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
