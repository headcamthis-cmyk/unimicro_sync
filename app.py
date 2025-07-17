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

@app.route('/product/twinxml/postproductgroup.aspx', methods=['POST'])
def post_productgroup():
    user = request.args.get('user')
    password = request.args.get('pass')

    if user == 'synall' and password == 'synall':
        print("Authorized productgroup POST received.")
        return Response("<response>OK</response>", mimetype='application/xml')
    else:
        print("Unauthorized access attempt to productgroup endpoint.")
        return Response("Unauthorized", status=401)

@app.route('/product/twinxml/postproduct2.aspx', methods=['POST'])
def post_productgroup():
    user = request.args.get('user')
    password = request.args.get('pass')

    if user == 'synall' and password == 'synall':
        print("Authorized productgroup POST received.")
        return Response("<response>OK</response>", mimetype='application/xml')
    else:
        print("Unauthorized access attempt to productgroup endpoint.")
        return Response("Unauthorized", status=401)

@app.route('/product/twinxml/postfiles.aspx', methods=['POST'])
def post_productgroup():
    user = request.args.get('user')
    password = request.args.get('pass')

    if user == 'synall' and password == 'synall':
        print("Authorized productgroup POST received.")
        return Response("<response>OK</response>", mimetype='application/xml')
    else:
        print("Unauthorized access attempt to productgroup endpoint.")
        return Response("Unauthorized", status=401)

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
