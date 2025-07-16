from flask import Flask, request, Response

app = Flask(__name__)

USERNAME = "synall"
PASSWORD = "your_password_here"

def check_auth(auth):
    return auth and auth.username == USERNAME and auth.password == PASSWORD

@app.route('/productgroup', defaults={'path': ''}, methods=['POST'])
@app.route('/productgroup/<path:path>', methods=['POST'])
def product_group(path):
    auth = request.authorization
    if not check_auth(auth):
        return Response("Unauthorized", status=401)

    data = request.data.decode('utf-8')
    print(f"Received product group XML on path /productgroup/{path}:")
    print(data)

    return Response("Product group received", status=200)


@app.route('/product', defaults={'path': ''}, methods=['POST'])
@app.route('/product/<path:path>', methods=['POST'])
def product(path):
    auth = request.authorization
    if not check_auth(auth):
        return Response("Unauthorized", status=401)

    data = request.data.decode('utf-8')
    print(f"Received product XML on path /product/{path}:")
    print(data)

    return Response("Product received", status=200)


@app.route('/customer', defaults={'path': ''}, methods=['POST'])
@app.route('/customer/<path:path>', methods=['POST'])
def customer(path):
    auth = request.authorization
    if not check_auth(auth):
        return Response("Unauthorized", status=401)

    data = request.data.decode('utf-8')
    print(f"Received customer XML on path /customer/{path}:")
    print(data)

    return Response("Customer received", status=200)


@app.route('/order', defaults={'path': ''}, methods=['POST'])
@app.route('/order/<path:path>', methods=['POST'])
def order(path):
    auth = request.authorization
    if not check_auth(auth):
        return Response("Unauthorized", status=401)

    data = request.data.decode('utf-8')
    print(f"Received order XML on path /order/{path}:")
    print(data)

    return Response("Order received", status=200)
