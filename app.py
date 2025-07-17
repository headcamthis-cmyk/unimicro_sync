from flask import Flask, request, Response
from functools import wraps
from datetime import datetime
import xml.etree.ElementTree as ET
import os

app = Flask(__name__)

# Basic auth configuration
USERNAME = os.environ.get('APP_USERNAME', 'synall')
PASSWORD = os.environ.get('APP_PASSWORD', 'synall')

def check_auth(username, password):
    return username == USERNAME and password == PASSWORD

def authenticate():
    return Response('Could not verify your access level for that URL.\n'
                    'You have to login with proper credentials', 401,
                    {'WWW-Authenticate': 'Basic realm="Login Required"'})

def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            return authenticate()
        return f(*args, **kwargs)
    return decorated

def save_xml(data, prefix):
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f'unimicro_{prefix}_{timestamp}.xml'
    with open(filename, 'wb') as f:
        f.write(data)
    return filename

@app.route('/product/postproductgroup.aspx', methods=['POST'])
@requires_auth
def post_productgroup():
    xml_data = request.data
    filename = save_xml(xml_data, 'productgroup_feed')
    print(f'PRODUCTGROUP XML saved as {filename}')
    return '<response>OK</response>'

@app.route('/product/postproduct2.aspx', methods=['POST'])
@requires_auth
def post_product():
    xml_data = request.data
    filename = save_xml(xml_data, 'product_feed')
    print(f'PRODUCT XML saved as {filename}')
    return '<response>Products processed and synced to Shopify.</response>'

@app.route('/product/postfiles.aspx', methods=['POST'])
@requires_auth
def post_files():
    xml_data = request.data
    filename = save_xml(xml_data, 'mediafiles')
    print(f'MEDIAFILES XML saved as {filename}')
    return '<response>OK</response>'

@app.route('/status.aspx', methods=['GET'])
def status():
    return '<response>OK</response>'

@app.route('/', defaults={'path': ''}, methods=['GET', 'POST'])
@app.route('/<path:path>', methods=['GET', 'POST'])
def catch_all(path):
    print(f'Unhandled Request: {request.method} {request.path}')
    return Response('<response>Not Found</response>', status=404)

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
