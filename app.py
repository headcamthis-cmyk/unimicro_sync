from flask import Flask, request, Response
import xml.etree.ElementTree as ET
import requests

app = Flask(__name__)

USERNAME = "synall"
PASSWORD = "synall"

SHOPIFY_STORE = "asmshop.no"
SHOPIFY_TOKEN = "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"
SHOPIFY_API_URL = f"https://{SHOPIFY_STORE}/admin/api/2024-01"

def check_auth(auth):
    if auth and auth.username == USERNAME and auth.password == PASSWORD:
        return True
    # Fallback to query parameters
    user = request.args.get('user')
    password = request.args.get('pass')
    return user == USERNAME and password == PASSWORD

def find_product_by_sku(sku):
    url = f"{SHOPIFY_API_URL}/products.json?fields=id,title,variants"
    headers = {
        "X-Shopify-Access-Token": SHOPIFY_TOKEN
    }
    response = requests.get(url, headers=headers)
    if response.status_code != 200:
        print(f"Failed to fetch products: {response.text}")
        return None

    products = response.json().get('products', [])
    for product in products:
        for variant in product.get('variants', []):
            if variant.get('sku') == sku:
                return product, variant
    return None, None

@app.route('/product', defaults={'path': ''}, methods=['POST'])
@app.route('/product/<path:path>', methods=['POST'])
def product(path):
    auth = request.authorization
    if not check_auth(auth):
        return Response("Unauthorized", status=401)

    data = request.data.decode('utf-8')
    print(f"Received product XML on path /product/{path}:")
    print(data)

    try:
         root = ET.fromstring(data)
        for product in root.findall(".//Product"):
            sku = product.findtext("SKU")
            title = product.findtext("ProductName")
            description = product.findtext("Description")
            price = product.findtext("Price")
            stock = int(product.findtext("Stock", "0"))

            if not sku:
                print("Skipping product without SKU.")
                continue

            existing_product, existing_variant = find_product_by_sku(sku)

            headers = {
                "X-Shopify-Access-Token": SHOPIFY_TOKEN,
                "Content-Type": "application/json"
            }

            if existing_product:
                # Update product details
                product_id = existing_product['id']
                variant_id = existing_variant['id']

                update_product_payload = {
                    "product": {
                        "id": product_id,
                        "body_html": description
                    }
                }
                update_variant_payload = {
                    "variant": {
                        "id": variant_id,
                        "price": price,
                        "inventory_quantity": stock
                    }
                }

                update_product_url = f"{SHOPIFY_API_URL}/products/{product_id}.json"
                update_variant_url = f"{SHOPIFY_API_URL}/variants/{variant_id}.json"

                resp1 = requests.put(update_product_url, json=update_product_payload, headers=headers)
                resp2 = requests.put(update_variant_url, json=update_variant_payload, headers=headers)

                print(f"Updated product {title} (SKU: {sku}): Product Resp: {resp1.status_code}, Variant Resp: {resp2.status_code}")

            else:
                # Create new product
                product_payload = {
                    "product": {
                        "title": title,
                        "body_html": description,
                        "variants": [
                            {
                                "price": price,
                                "sku": sku,
                                "inventory_quantity": stock
                            }
                        ]
                    }
                }

                create_url = f"{SHOPIFY_API_URL}/products.json"
                resp = requests.post(create_url, json=product_payload, headers=headers)
                print(f"Created new product {title} (SKU: {sku}): Status {resp.status_code}")

        return Response("Products processed and synced to Shopify.", status=200)

    except ET.ParseError:
        return Response("Invalid XML format.", status=400)
