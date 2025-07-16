from flask import Flask, request, Response

app = Flask(__name__)

USERNAME = "synall"
PASSWORD = "synall"

def check_auth(auth):
    return auth and auth.username == USERNAME and auth.password == PASSWORD

@app.route('/productgroup', methods=['POST'])
def product_group():
    auth = request.authorization
    if not check_auth(auth):
        return Response("Unauthorized", status=401)
    
    data = request.data.decode('utf-8')
    print("Received product group XML:")
    print(data)

    return Response("Product group received", status=200)

@app.route('/product', methods=['POST'])
def product():
    auth = request.authorization
    if not check_auth(auth):
        return Response("Unauthorized", status=401)
    
    data = request.data.decode('utf-8')
    print("Received product XML:")
    print(data)

    return Response("Product received", status=200)

@app.route('/customer', methods=['POST'])
def customer():
    auth = request.authorization
    if not check_auth(auth):
        return Response("Unauthorized", status=401)

    data = request.data.decode('utf-8')
    print("Received customer XML:")
    print(data)

    return Response("Customer received", status=200)

@app.route('/order', methods=['POST'])
def order():
    auth = request.authorization
    if not check_auth(auth):
        return Response("Unauthorized", status=401)

    data = request.data.decode('utf-8')
    print("Received order XML:")
    print(data)

    return Response("Order received", status=200)
