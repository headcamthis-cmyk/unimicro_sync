from flask import Flask, request, Response
import logging

app = Flask(__name__)
logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s: %(message)s')

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
    logging.info(f"Incoming request to /product/twinxml/postproductgroup.aspx with user={username}")

    if not is_authenticated(username, password):
        logging.warning(f"Unauthorized attempt on productgroup endpoint with user={username}")
        return Response('Unauthorized', status=401)

    try:
        xml_data = request.data.decode('utf-8', errors='replace')
        logging.info("Authorized productgroup POST received.")
        logging.info(f"Product Group XML:\n{xml_data}")
    except Exception as e:
        logging.error(f"Failed to decode productgroup XML: {e}")
        return Response('<response>Error processing XML</response>', mimetype='text/xml')

    return Response("<response>OK</response>", mimetype='text/xml')

@app.route('/product/twinxml/postproduct.aspx', methods=['POST'])
def post_product():
    username = request.args.get('user')
    password = request.args.get('pass')
    logging.info(f"Incoming request to /product/twinxml/postproduct2.aspx with user={username}")

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
