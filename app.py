from flask import Flask, request, Response
import logging
import xml.etree.ElementTree as ET
import requests

app = Flask(__name__)
logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s: %(message)s')

SHOPIFY_DOMAIN = 'asmshop.no'
SHOPIFY_TOKEN = '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'

def is_authenticated(username, password):
    return username == 'synall' and password == 'synall'

@app.route('/')
def index():
    return "Uni Micro Sync API is running."

def create_or_update_collection(group_id, title):
    url = f"https://{SHOPIFY_DOMAIN}/admin/api/2023-01/custom_collections.json"
    headers = {
        "X-Shopify-Access-Token": SHOPIFY_TOKEN,
        "Content-Type": "application/json"
    }

    data = {
        "custom_collection": {
            "title": title,
            "handle": f"group-{group_id}"
        }
    }

    response = requests.post(url, json=data, headers=headers)
    logging.info(f"Shopify API response: {response.status_code} - {response.text}")
    return response.status_code == 201 or response.status_code == 200

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
        for pg in root.findall("productgroup"):
            group_id = pg.find("id").text
            title = pg.find("description").text

            success = create_or_update_collection(group_id, title)
            if not success:
                logging.warning(f"Failed to sync group {group_id} ({title}) to Shopify")

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
