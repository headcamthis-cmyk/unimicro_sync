
from flask import Flask, request, Response
import xml.etree.ElementTree as ET
import requests
import os

app = Flask(__name__)

USERNAME = os.getenv('USERNAME', 'synall')
PASSWORD = os.getenv('PASSWORD', 'synall')

SHOPIFY_STORE = "asmshop.no"
SHOPIFY_TOKEN = "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"
SHOPIFY_API_URL = f"https://{SHOPIFY_STORE}/admin/api/2024-01"

def check_auth(auth):
    if auth and auth.username == USERNAME and auth.password == PASSWORD:
        return True
    user = request.args.get('user')
    password = request.args.get('pass')
    return user == USERNAME and password == PASSWORD

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
    print(f"Received product XML on path /product/{path}:
{data}")

    # Placeholder for XML processing and Shopify sync logic
    return Response("Request received and processed.", status=200)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
