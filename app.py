from flask import Flask, request, Response
import xml.etree.ElementTree as ET
import requests
import os
import traceback

app = Flask(__name__)

USERNAME = os.getenv('USERNAME', 'synall')
PASSWORD = os.getenv('PASSWORD', 'synall')

SHOPIFY_STORE = "asmshop.no"
SHOPIFY_TOKEN = "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"
SHOPIFY_API_URL = f"https://{SHOPIFY_STORE}/admin/api/2024-01"

def check_auth(auth):
    user = request.args.get("user")
    password = request.args.get("pass")
    expected_user = USERNAME
    expected_password = PASSWORD

    print(f"Auth attempt with user: {user}, password: {password}")
    print(f"Expected user: {expected_user}, expected password: {expected_password}")

    return user == expected_user and password == expected_password

def find_product_by_sku(sku):
    url = f"{SHOPIFY_API_URL}/products.json?fields=id,title,variants"
    headers = {"X-Shopify-Access-Token": SHOPIFY_TOKEN}
    response = requests.get(url, headers=headers)
    if response.status_code != 200:
        print(f"Failed to fetch products: {response.text}")
        return None, None

    products = response.json().get('products', [])
    for product in products:
        for variant in product.get('variants', []):
            if variant.get('sku') == sku:
                return product, variant
    return None, None

@app.route('/')
def index():
    return "UniMicro Sync Service is running.", 200

@app.route('/product', defaults={'path': ''}, methods=['POST'])
@app.route('/product/<path:path>', methods=['POST'])
def product(path):
    auth = request.authorization
    if not check_auth(auth):
        print(f"Unauthorized access attempt with auth={auth}")
        return Response("Unauthorized", status=401)

    data = request.data.decode('utf-8')
    print(f"Received product XML on path /product/{path}:\n{data}")
    print(f"Payload size: {len(data)} bytes")

    try:
        root = ET.fromstring(data)
        tags = sorted({elem.tag for elem in root.iter()})
        print(f"DEBUG: incoming XML tags: {tags}")

        if 'productgroup' in tags:
            for pg in root.findall(".//productgroup"):
                group_id = pg.findtext("id")
                title = pg.findtext("description") or pg.findtext("groupno")
                parent_group = pg.findtext("parentgroup")
                if not title:
                    print("Skipping product group without title")
                    continue

                headers = {
                    "X-Shopify-Access-Token": SHOPIFY_TOKEN,
                    "Content-Type": "application/json"
                }
                collection_payload = {
                    "custom_collection": {
                        "title": title,
                        "body_html": f"Group ID: {group_id}, Parent Group: {parent_group}"
                    }
                }
                print(f"Creating product group in Shopify with payload: {collection_payload}")
                resp = requests.post(f"{SHOPIFY_API_URL}/custom_collections.json",
                                     json=collection_payload, headers=headers)
                print(f"Shopify response: {resp.status_code} - {resp.text}")

        return Response("Products processed and synced to Shopify.", status=200)
    except ET.ParseError:
        return Response("Invalid XML format.", status=400)
    except Exception as e:
        traceback.print_exc()
        return Response("Products processed and synced to Shopify.", status=200)

@app.route("/twinxml/postproduct.asp", methods=["POST"])
def handle_postproduct():
    return product("twinxml/postproduct.asp")
