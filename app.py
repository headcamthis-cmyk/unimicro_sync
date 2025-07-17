from flask import Flask, request, Response
import os
import datetime
import secrets

USERNAME = 'synall'
PASSWORD = 'synall'

app = Flask(__name__)

def is_authenticated():
    user = request.args.get('user')
    passwd = request.args.get('pass')
    return user == USERNAME and passwd == PASSWORD

def save_and_log(label):
    xml_data = request.data.decode('utf-8', errors='replace')

    print(f"===== START OF {label} XML =====")
    print(xml_data)
    print(f"===== END OF {label} XML =====")

    timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f'unimicro_{label.lower()}_feed_{timestamp}.xml'

    with open(filename, 'w', encoding='utf-8') as f:
        f.write(xml_data)

    print(f'{label} XML saved as {filename}')
    return Response('<response>OK</response>', mimetype='application/xml')


@app.route('/product/twinxml/postproductgroup.aspx', methods=['POST'])
def post_product_group():
    if not is_authenticated():
        return Response('Unauthorized', status=401)
    return save_and_log('PRODUCTGROUP')


@app.route('/product/twinxml/postproduct.aspx', methods=['POST'])
def post_product():
    if not is_authenticated():
        return Response('Unauthorized', status=401)
    return save_and_log('PRODUCT')


@app.route('/product/twinxml/postproduct2.aspx', methods=['POST'])
def post_product2():
    if not is_authenticated():
        return Response('Unauthorized', status=401)
    return save_and_log('PRODUCT2')


@app.route('/product/twinxml/poststock.aspx', methods=['POST'])
def post_stock():
    if not is_authenticated():
        return Response('Unauthorized', status=401)
    return save_and_log('STOCK')


@app.route('/product/twinxml/postprice.aspx', methods=['POST'])
def post_price():
    if not is_authenticated():
        return Response('Unauthorized', status=401)
    return save_and_log('PRICE')


@app.route('/product/twinxml/orders.aspx', methods=['GET'])
def get_orders():
    if not is_authenticated():
        return Response('Unauthorized', status=401)
    empty_orders_xml = '<?xml version="1.0" encoding="iso-8859-1"?><Root></Root>'
    return Response(empty_orders_xml, mimetype='application/xml')


@app.route('/', defaults={'path': ''}, methods=['GET', 'POST'])
@app.route('/<path:path>', methods=['GET', 'POST'])
def catch_all(path):
    print("===== Unhandled Request =====")
    print(f"Method: {request.method}")
    print(f"Full Path: {request.full_path}")
    print(f"Headers: {dict(request.headers)}")
    if request.method == 'POST':
        print("===== POST BODY =====")
        print(request.data.decode('utf-8', errors='replace'))
        print("=====================")
    print("===== End of Unhandled Request =====")
    return Response('Not Found', status=404)


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 10000))
    app.run(host='0.0.0.0', port=port)