from flask import Flask, request, Response
import os
import datetime
import secrets

USERNAME = 'synall'
PASSWORD = 'synall'  # Replace with the actual password

app = Flask(__name__)

def is_authenticated():
    user = request.args.get('user')
    passwd = request.args.get('pass')
    return user == USERNAME and passwd == PASSWORD

def save_and_log_xml(xml_data, label):
    print(f"===== START OF {label} XML =====")
    print(xml_data)
    print(f"===== END OF {label} XML =====")

    timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f'unimicro_{label.lower()}_feed_{timestamp}.xml'

    with open(filename, 'w', encoding='utf-8') as f:
        f.write(xml_data)

    print(f'{label} XML feed saved as {filename}')


@app.route('/product/twinxml/postproductgroup.aspx', methods=['POST'])
def receive_productgroup():
    if not is_authenticated():
        return Response('Unauthorized', status=401)

    xml_data = request.data.decode('utf-8', errors='replace')
    save_and_log_xml(xml_data, 'PRODUCTGROUP')
    return Response('<response>OK</response>', mimetype='application/xml')


@app.route('/product/twinxml/postproduct.aspx', methods=['POST'])
def receive_product():
    if not is_authenticated():
        return Response('Unauthorized', status=401)

    xml_data = request.data.decode('utf-8', errors='replace')
    save_and_log_xml(xml_data, 'PRODUCT')
    return Response('<response>OK</response>', mimetype='application/xml')


@app.route('/product/twinxml/postproduct2.aspx', methods=['POST'])
def receive_product2():
    if not is_authenticated():
        return Response('Unauthorized', status=401)

    xml_data = request.data.decode('utf-8', errors='replace')
    save_and_log_xml(xml_data, 'PRODUCT2')
    return Response('<response>OK</response>', mimetype='application/xml')


@app.route('/', defaults={'path': ''}, methods=['GET', 'POST'])
@app.route('/<path:path>', methods=['GET', 'POST'])
def catch_all(path):
    print(f"Unhandled request to path: /{path}")
    
    if request.method == 'POST':
        print("===== POST BODY =====")
        print(request.data.decode('utf-8', errors='replace'))
        print("=====================")
        
    return Response('Not Found', status=404)


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 10000))
    app.run(host='0.0.0.0', port=port)
