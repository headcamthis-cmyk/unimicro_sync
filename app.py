from flask import Flask, request, Response
import logging

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)

# Simple authentication function
def is_authenticated(username, password):
    return username == 'synall' and password == 'synall'

@app.route('/')
def index():
    return "Uni Micro Sync API is running."

@app.route('/product/twinxml/postproductgroup.aspx', methods=['POST'])
def post_productgroup():
    username = request.args.get('user')
    password = request.args.get('pass')

    if not is_authenticated(username, password):
        logging.warning("Unauthorized attempt to upload product groups.")
        return Response('Unauthorized', status=401)

    xml_data = request.data.decode('utf-8')
    logging.info("Authorized productgroup POST received.")
    logging.info(f"Product Group XML:\n{xml_data}")

    return Response("<response>OK</response>", mimetype='text/xml')

@app.route('/product/twinxml/postproduct2.aspx', methods=['POST'])
def post_product():
    username = request.args.get('user')
    password = request.args.get('pass')

    if not is_authenticated(username, password):
        logging.warning("Unauthorized attempt to upload products.")
        return Response('Unauthorized', status=401)

    xml_data = request.data.decode('utf-8')
    logging.info("Authorized product POST received.")
    logging.info(f"Product XML:\n{xml_data}")

    return Response("<response>OK</response>", mimetype='text/xml')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
