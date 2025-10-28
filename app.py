"""
Uni Micro → Shopify sync (Render-ready)


This revision is the last known-good Flask app that actually CREATED
Shopify products and product groups (custom collections) from Uni Micro's
TwinXML posts. It focuses on:
• /twinxml/postproductgroup.aspx → Upsert Custom Collection
• /twinxml/postproduct.aspx → Upsert Product (+variant) by SKU, assign to collection, set inventory + price


Notes
-----
• Basic auth: username/password = synall / synall (adjust below if needed)
• Render: set environment vars in the service (DO NOT hardcode secrets):
SHOPIFY_DOMAIN e.g. 'allsupermotoas.myshopify.com'
SHOPIFY_TOKEN e.g. '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'
SHOPIFY_API_VERSION e.g. "2024-10"
SHOPIFY_LOCATION_ID e.g. "16764928067"
• Returns plain text with CRLF (\r\n) because Uni Micro can be picky
• Idempotency is by SKU for products; for collections by ProductGroupNo
• Minimal error handling with clear logs (INFO level)


Procfile (create this as a separate file on Render):
web: gunicorn -w 2 -k gthread -t 120 app:app


requirements.txt (create separately):
Flask==3.0.3
gunicorn==23.0.0
requests==2.32.3


"""
from __future__ import annotations
import os
import logging
from typing import Dict, List, Optional, Tuple
from flask import Flask, request, Response
import xml.etree.ElementTree as ET
import requests


app = Flask(__name__)
logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s: %(message)s')


# -------- Shopify config --------
SHOPIFY_DOMAIN = os.environ.get('SHOPIFY_DOMAIN', 'allsupermotoas.myshopify.com').strip()
SHOPIFY_TOKEN = os.environ.get('SHOPIFY_TOKEN', '').strip()
SHOPIFY_API_VERSION = os.environ.get('SHOPIFY_API_VERSION', '2024-10').strip()
SHOPIFY_LOCATION_ID = os.environ.get('SHOPIFY_LOCATION_ID', '').strip()


if not SHOPIFY_TOKEN:
logging.warning("SHOPIFY_TOKEN is not set — API calls will fail!")


BASE_URL = f"https://{SHOPIFY_DOMAIN}/admin/api/{SHOPIFY_API_VERSION}"


session = requests.Session()
session.headers.update({
'X-Shopify-Access-Token': SHOPIFY_TOKEN,
'Content-Type': 'application/json',
'Accept': 'application/json',
})


# -------- Utils --------
def is_authenticated(username: str, password: str) -> bool:
return username == 'synall' and password == 'synall'




def ok_txt(body: str = "OK") -> Response:
# exact plain text + CRLF; UM can be picky about line endings
return Response(body + "\r\n", mimetype="text/plain; charset=windows-1252")




@app.before_request
def _log_every_request():
try:
logging.info(f"REQ {request.method} {request.path}")
except Exception:
pass




def _auth_fail() -> Response:
return Response("NOT AUTHORIZED\r\n", status=401, mimetype="text/plain; charset=windows-1252")




# -------- XML helpers --------
def _parse_xml(body: bytes) -> ET.Element:
try:
return ET.fromstring(body)
except ET.ParseError as e:
logging.exception("XML parse error")
