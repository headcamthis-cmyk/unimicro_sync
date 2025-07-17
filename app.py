from flask import Flask, request, Response, abort
from functools import wraps
import os
import datetime
import secrets

USERNAME = 'synall'
PASSWORD = 'synall'  # Replace with the actual password

app = Flask(__name__)

@app.route('/product/twinxml/postproductgroup.aspx', methods=['POST'])
def receive_xml():
    user = request.args.get('user')
    passwd = request.args.get('pass')

    if user != USERNAME or passwd != PASSWORD:
        return Response('Unauthorized', status=401)

    xml_data = request.data.decode('utf-8')

    # Log the entire XML content
    print("===== START OF XML DATA =====")
    print(xml_data)
    print("===== END OF XML DATA =====")

    timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f'unimicro_feed_{timestamp}.xml'

    with open(filename, 'w', encoding='utf-8') as f:
        f.write(xml_data)

    print(f'XML feed saved as {filename}')

    return Response('<response>OK</response>', mimetype='application/xml')


@app.route('/', defaults={'path': ''}, methods=['GET', 'POST'])
@app.route('/<path:path>', methods=['GET', 'POST'])
def catch_all(path):
    print(f"Unhandled request to path: /{path}")
    return Response('Not Found', status=404)


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 10000))
    app.run(host='0.0.0.0', port=port)
