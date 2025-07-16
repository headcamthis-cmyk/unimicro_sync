from flask import Flask, request, Response
import xml.etree.ElementTree as ET

app = Flask(__name__)

USERNAME = "synall"
PASSWORD = "your_password_here"

@app.route("/unimicro-feed", methods=["POST"])
def receive_xml():
    auth = request.authorization
    if not auth or auth.username != USERNAME or auth.password != PASSWORD:
        return Response("Unauthorized", status=401)

    try:
        xml_data = request.data
        root = ET.fromstring(xml_data)

        for product in root.findall(".//Product"):
            sku = product.findtext("SKU")
            stock = product.findtext("Stock")
            print(f"Received: SKU={sku}, Stock={stock}")

        return Response("XML received and processed", status=200)
    except ET.ParseError:
        return Response("Malformed XML", status=400)
