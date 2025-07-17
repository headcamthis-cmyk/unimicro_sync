from flask import Flask, request, Response, abort
from functools import wraps
import os
import datetime
from werkzeug.security import safe_str_cmp

# Credentials from Uni Micro V3 config
USERNAME = 'synall'
PASSWORD = 'synall'  # Replace with the actual password from Uni Micro

app = Flask(__name__)

def check_auth(username, password):
    return safe_str_cmp(username, USERNAME) and safe_str_cmp(password, PASSWORD)

def authenticate():
    return Response(
        'Could not verify your access level for that URL.\n'
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

@app.route('/product', methods=['POST'])
@requires_auth
def receive_xml():
    xml_data = request.data.decode('utf-8')
    
    timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f'unimicro_feed_{timestamp}.xml'
    
    with open(filename, 'w', encoding='utf-8') as f:
        f.write(xml_data)

    print(f'XML feed saved as {filename}')
    
    return Response('<response>OK</response>', mimetype='application/xml')

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 10000))
    app.run(host='0.0.0.0', port=port)
