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
    logging.info(f"Fetching existing collections from Shopify URL: {url}")
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        collections = response.json().get('custom_collections', [])
        return {c['handle']: c['id'] for c in collections}
    logging.error(f"Failed to fetch existing collections: {response.status_code} - {response.text}")
    return {}

def create_collection(title, handle, retries=3):
    url = f"https://{SHOPIFY_DOMAIN}/admin/api/{SHOPIFY_API_VERSION}/custom_collections.json"
    headers = {
        "X-Shopify-Access-Token": SHOPIFY_TOKEN,
        "Content-Type": "application/json"
    }

    data = {
        "custom_collection": {
            "title": title,
            "handle": handle,
            "published_at": datetime.utcnow().isoformat() + 'Z'
        }
    }

    logging.info("Attempting to create Shopify collection:")
    logging.info(f"- HTTP Method: POST")
    logging.info(f"- URL: {url}")
    logging.info(f"- Headers: {headers}")
    logging.info(f"- Payload: {data}")

    for attempt in range(retries):
        try:
            response = requests.post(url, json=data, headers=headers)
            logging.info(f"Shopify API response code: {response.status_code}")
            logging.info(f"Shopify API response body: {response.text}")

            if response.status_code in [200, 201]:
                json_response = response.json()

                if 'custom_collection' in json_response:
                    created_collection = json_response['custom_collection']
                    logging.info(f"Successfully created collection: {created_collection['title']} (ID: {created_collection['id']})")
                    return verify_collection_exists(handle)

                elif 'custom_collections' in json_response:
                    for collection in json_response['custom_collections']:
                        if collection['handle'] == handle:
                            logging.info(f"Collection already exists with handle '{handle}'. Skipping creation.")
                            return True

                    logging.warning(f"Handle '{handle}' not found in returned collections. Attempting verification step.")
                    return verify_collection_exists(handle)

                else:
                    logging.warning("Unexpected JSON structure in Shopify response. Attempting verification step.")
                    return verify_collection_exists(handle)

            else:
                logging.warning(f"Unexpected status code when creating collection: {response.status_code}")
                if attempt < retries - 1:
                    logging.info(f"Retrying... (attempt {attempt + 2})")
                    time.sleep(1)
                else:
                    logging.warning(f"Response text: {response.text}")
                    return False

        except Exception as e:
            logging.exception(f"Exception occurred while creating Shopify collection: {e}")
            if attempt < retries - 1:
                logging.info(f"Retrying after exception... (attempt {attempt + 2})")
                time.sleep(1)
            else:
                return False

def verify_collection_exists(handle, retries=2, delay=2):
    """
    Re-fetch collections to verify if the specified handle exists.
    Retries verification a few times with a delay to account for API lag.
    """
    for attempt in range(retries + 1):
        logging.info(f"Verifying existence of collection with handle '{handle}' (attempt {attempt + 1})...")
        collections = get_existing_collections()
        if handle in collections:
            logging.info(f"Verification success: Collection '{handle}' exists with ID {collections[handle]}.")
            return True
        if attempt < retries:
            logging.info(f"Handle '{handle}' not found. Retrying after {delay} seconds...")
            time.sleep(delay)

    logging.warning(f"Verification failed: Collection with handle '{handle}' does not exist after {retries + 1} attempts.")
    return False

@app.route('/product/twinxml/postproductgroup.aspx', methods=['POST'])
def post_productgroup():
    username = request.args.get('user')
    password = request.args.get('pass')
    logging.info(f"Incoming request to /product/twinxml/postproductgroup.aspx with user={username}")

    if not is_authenticated(username, password):
        logging.warning(f"Unauthorized attempt on productgroup endpoint with user={username}")
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

            created = create_collection(title, handle)
            if created:
                logging.info(f"Confirmed creation of Shopify collection for product group: {title}")
                existing_collections[handle] = True
            else:
                logging.warning(f"Failed to create or verify Shopify collection for product group: {title}")

    except Exception as e:
        logging.error(f"Failed to process product group XML: {e}")
        return Response('<response>Error processing XML</response>', mimetype='text/xml')

    return Response("<response>OK</response>", mimetype='text/xml')

@app.route('/product/twinxml/postproduct.aspx', methods=['POST'])
def post_product():
    username = request.args.get('user')
    password = request.args.get('pass')
    logging.info(f"Incoming request to /product/twinxml/postproduct.aspx with user={username}")

    if not is_authenticated(username, password):
        logging.warning(f"Unauthorized attempt on product endpoint with user={username}")
        return Response('Unauthorized', status=401)

    try:
        xml_data = request.data.decode('utf-8', errors='replace')
        logging.info("Authorized product POST received.")
        logging.info(f"Product XML:\n{xml_data}")
    except Exception as e:
        logging.error(f"Failed to decode product XML: {e}")
        return Response('<response>Error processing XML</response>', mimetype='text/xml')

    return Response("<response>OK</response>", mimetype='text/xml')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
