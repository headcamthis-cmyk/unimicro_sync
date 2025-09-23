from flask import Flask, request, Response
import logging
import xml.etree.ElementTree as ET
import requests
import os

app = Flask(__name__)
logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s: %(message)s')

# -------- Shopify config --------
SHOPIFY_DOMAIN = 'allsupermotoas.myshopify.com'
SHOPIFY_TOKEN = os.environ.get('SHOPIFY_TOKEN', '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')
SHOPIFY_API_VERSION = '2024-10'
SHOPIFY_LOCATION_ID = '16764928067'  # inventory location

# -------- Utils --------
def is_authenticated(username, password):
    return username == 'synall' and password == 'synall'

def ok_xml(body="OK", count=None):
    """
    Return minimal, well-formed XML with the correct content type.
    If count is provided, include it both as attribute and inner text for maximum compatibility.
    """
    if count is not None:
        xml = f'<OK count="{int(count)}">{int(count)}</OK>'
    else:
        xml = f"<OK>{body}</OK>"
    return Response(xml, mimetype="text/xml")

@app.before_request
def _log_every_request():
    try:
        logging.info(f"REQ {request.method} {request.path}?{request.query_string.decode(errors='ignore')}")
    except Exception:
        pass

@app.route('/')
def index():
    return "Uni Micro Sync API is running."

def shopify_headers(json=True):
    h = {"X-Shopify-Access-Token": SHOPIFY_TOKEN}
    if json:
        h["Content-Type"] = "application/json"
    return h

def _parse_xml(raw_bytes, what="payload"):
    try:
        return ET.fromstring(raw_bytes)
    except ET.ParseError as e:
        logging.warning(f"{what}: primary parse failed ({e}); trying utf-8 fallback")
        return ET.fromstring(raw_bytes.decode('utf-8', errors='replace'))

def _gettext(node, *names):
    # Try direct and nested; case-/namespace-tolerant
    for n in names:
        el = node.find(n) or node.find(n.lower()) or node.find(f".//{n}")
        if el is not None and el.text and el.text.strip():
            return el.text.strip()
    for child in node.iter():
        tag = child.tag.split('}', 1)[-1].lower()
        for n in names:
            if tag == n.lower() and child.text and child.text.strip():
                return child.text.strip()
    return None

def _get_from_node(node, names, attr_names=None):
    """Return a value for any of the tag names OR attributes (case/namespace tolerant)."""
    # child elements (any depth)
    v = _gettext(node, *names)
    if v:
        return v
    # attributes on matching child elements
    if attr_names:
        want = {n.lower() for n in names}
        for child in node.iter():
            tag = child.tag.split('}', 1)[-1].lower()
            if tag in want:
                for a in attr_names:
                    if a in child.attrib and child.attrib[a].strip():
                        return child.attrib[a].strip()
    # attributes on the node itself
    if attr_names:
        for a in attr_names:
            if a in node.attrib and node.attrib[a].strip():
                return node.attrib[a].strip()
    return None

def _get_from_extendedinfo(node, key_names: set):
    """
    Look inside <extendedinfo> for attributes like qname/name/key with values in qvalue/value/text.
    Returns the first matching value for any key in key_names.
    """
    # find the <extendedinfo> block first
    ext = None
    for child in node.iter():
        if child.tag.split('}', 1)[-1].lower() == 'extendedinfo':
            ext = child
            break
    if ext is None:
        return None

    keys_lower = {k.lower() for k in key_names}
    for e in ext.iter():
        attrs = { (k or '').lower(): (v.strip() if isinstance(v, str) else v) for k, v in e.attrib.items() }
        name = attrs.get('qname') or attrs.get('name') or attrs.get('key') or attrs.get('field') or attrs.get('id')
        if name and name.lower() in keys_lower:
            val = attrs.get('qvalue') or attrs.get('value') or (e.text.strip() if e.text else None)
            if val not in (None, ''):
                return val
    return None

# -------- Shopify helpers --------
def get_existing_collections():
    url = f"https://{SHOPIFY_DOMAIN}/admin/api/{SHOPIFY_API_VERSION}/custom_collections.json"
    r = requests.get(url, headers=shopify_headers())
    if r.status_code == 200:
        return {c['handle']: c['id'] for c in r.json().get('custom_collections', [])}
    logging.warning(f"Failed to fetch collections: {r.status_code} - {r.text}")
    return {}

def create_collection(title, handle):
    url = f"https://{SHOPIFY_DOMAIN}/admin/api/{SHOPIFY_API_VERSION}/custom_collections.json"
    data = {"custom_collection": {"title": title, "handle": handle}}
    r = requests.post(url, headers=shopify_headers(), json=data)
    if r.status_code in (200, 201):
        logging.info(f"Created collection: {title} (handle: {handle})")
    else:
        logging.warning(f"Create collection failed for {title}: {r.status_code} - {r.text}")

def find_product_by_sku(sku):
    url = f"https://{SHOPIFY_DOMAIN}/admin/api/{SHOPIFY_API_VERSION}/products.json?limit=250"
    r = requests.get(url, headers=shopify_headers(json=False))
    if r.status_code == 200:
        for product in r.json().get('products', []):
            for variant in product.get('variants', []):
                if variant.get('sku') == sku:
                    return {
                        "product_id": product['id'],
                        "variant_id": variant['id'],
                        "inventory_item_id": variant['inventory_item_id'],
                        "current_price": variant['price']
                    }
    else:
        logging.warning(f"find_product_by_sku failed: {r.status_code} - {r.text}")
    return None

def create_product(title, sku, price):
    url = f"https://{SHOPIFY_DOMAIN}/admin/api/{SHOPIFY_API_VERSION}/products.json"
    data = {
        "product": {
            "title": title,
            "status": "active",
            "variants": [{
                "sku": sku,
                "price": str(price),
                "inventory_management": "shopify"
            }]
        }
    }
    r = requests.post(url, headers=shopify_headers(), json=data)
    if r.status_code in (200, 201):
        product = r.json()['product']
        variant = product['variants'][0]
        logging.info(f"Created product '{title}' (SKU {sku}) id={product['id']}")
        return product['id'], variant['inventory_item_id']
    logging.warning(f"Create product failed: {r.status_code} - {r.text}")
    return None, None

def update_product_price(variant_id, new_price):
    url = f"https://{SHOPIFY_DOMAIN}/admin/api/{SHOPIFY_API_VERSION}/variants/{variant_id}.json"
    data = {"variant": {"id": variant_id, "price": str(new_price)}}
    r = requests.put(url, headers=shopify_headers(), json=data)
    if r.status_code == 200:
        logging.info(f"Updated price for variant {variant_id} -> {new_price}")
    else:
        logging.warning(f"Update price failed: {r.status_code} - {r.text}")

def assign_product_to_collection(product_id, collection_id):
    url = f"https://{SHOPIFY_DOMAIN}/admin/api/{SHOPIFY_API_VERSION}/collects.json"
    data = {"collect": {"product_id": product_id, "collection_id": collection_id}}
    r = requests.post(url, headers=shopify_headers(), json=data)
    if r.status_code in (200, 201):
        logging.info(f"Assigned product {product_id} to collection {collection_id}")
    else:
        logging.warning(f"Assign to collection failed: {r.status_code} - {r.text}")

def update_inventory_level(inventory_item_id, quantity):
    url = f"https://{SHOPIFY_DOMAIN}/admin/api/{SHOPIFY_API_VERSION}/inventory_levels/set.json"
    data = {"location_id": SHOPIFY_LOCATION_ID, "inventory_item_id": inventory_item_id, "available": int(quantity)}
    r = requests.post(url, headers=shopify_headers(), json=data)
    if r.status_code in (200, 201):
        logging.info(f"Stock set inventory_item_id={inventory_item_id} -> {quantity}")
    else:
        logging.warning(f"Inventory update failed: {r.status_code} - {r.text}")

# -------- Handlers --------
def _handle_product_post():
    username = request.args.get('user'); password = request.args.get('pass')
    if not is_authenticated(username, password):
        return Response('Unauthorized', status=401)

    raw = request.get_data()
    if request.method == 'GET' or not raw or not raw.strip():
        logging.info("Product endpoint called with empty body/preflight; returning OK (xml)")
        return ok_xml()

    root = _parse_xml(raw, "product xml")
    collections = get_existing_collections()
    logging.info(f"Loaded {len(collections)} collections")

    total = created = updated = skipped = 0

    # Count products for visibility
    count_products = 0
    for node in root.iter():
        if node.tag.split('}', 1)[-1].lower() == 'product':
            count_products += 1
    logging.info(f"Detected {count_products} <product> nodes")

    for p in root.iter():
        if p.tag.split('}', 1)[-1].lower() != 'product':
            continue
        total += 1

        # Primary extraction
        sku = _get_from_node(p, ["productno","productident","articleno","itemno","sku"], ["id","no","sku"])
        title = _get_from_node(p, ["description","name","title"], ["description","name","title"])
        price = _get_from_node(p, ["price","salesprice","price1","netprice"], ["price","salesprice","netprice","value"])
        qty_text = _get_from_node(p, ["quantityonhand","quantity","stock","instock","physicalstock","qty"], ["quantity","qty","stock","onhand","value"])
        group_id = _get_from_node(p, ["productgroup","productgroupno","groupno","groupid","pgid","qvalue"], ["productgroup","groupno","groupid","pgid","qvalue"])

        # Fallbacks via <extendedinfo>
        if not title:
            title = _get_from_extendedinfo(p, {"description","name","title"})
        if not price:
            price = _get_from_extendedinfo(p, {"price","salesprice","price1","netprice"})
        if not group_id:
            group_id = _get_from_extendedinfo(p, {"productgroup","productgroupno","groupno","groupid","pgid","qvalue"})
        if qty_text in (None, ""):
            qty_text = _get_from_extendedinfo(p, {"quantityonhand","quantity","stock","instock","physicalstock","qty"})

        # Quantity is optional
        quantity = None
        if qty_text not in (None, ""):
            try:
                quantity = int(float(str(qty_text).replace(',', '.')))
            except Exception:
                quantity = None

        # Detect inventory-only payloads (e.g., Source=UniStorageSync): SKU + quantity, but no title/price/group
        inventory_only = (sku not in (None, "")) and (quantity is not None) and not any([title, price, group_id])

        if inventory_only:
            existing = find_product_by_sku(sku)
            if existing:
                update_inventory_level(existing['inventory_item_id'], quantity)
                updated += 1
                continue
            else:
                logging.warning(f"Inventory-only payload for SKU '{sku}', but product not found in Shopify. Skipping create.")
                skipped += 1
                continue

        # Non-inventory-only:
        # For updates/creates we need at least SKU and (title or price).
        if not sku or (not title and not price):
            child_names = [c.tag.split('}',1)[-1] for c in p]
            logging.warning(f"Skipping product; missing required fields (need sku and title or price). Children: {child_names}")
            skipped += 1
            continue

        # Normalize price if present
        price_norm = None
        if price not in (None, ""):
            try:
                price_norm = str(float(str(price).replace(',', '.')))
            except Exception:
                price_norm = str(price)

        # Resolve collection if group is present; otherwise proceed without assigning
        collection_id = None
        if group_id not in (None, ""):
            handle = f"group-{str(group_id).strip()}".lower().replace(" ", "-")
            collection_id = collections.get(handle)
            if not collection_id:
                logging.info(f"No Shopify collection for handle '{handle}'. Will proceed without assignment.")

        existing = find_product_by_sku(sku)
        if existing:
            if price_norm is not None and str(existing.get('current_price')) != price_norm:
                update_product_price(existing['variant_id'], price_norm)
            if quantity is not None:
                update_inventory_level(existing['inventory_item_id'], quantity)
            if collection_id:
                assign_product_to_collection(existing['product_id'], collection_id)
            updated += 1
        else:
            # To create we need a title; default price to 0 if absent
            if not title:
                logging.warning(f"Cannot create product SKU '{sku}' without a title. Skipping.")
                skipped += 1
                continue
            create_price = price_norm if price_norm is not None else "0"
            product_id, inventory_item_id = create_product(title, sku, create_price)
            if product_id and collection_id:
                assign_product_to_collection(product_id, collection_id)
            if inventory_item_id is not None and quantity is not None:
                update_inventory_level(inventory_item_id, quantity)
            created += 1

    logging.info(f"Products processed: total={total}, created={created}, updated={updated}, skipped={skipped}")
    # Reply with how many <product> nodes were present; UM batch flows often expect a positive number.
    return ok_xml(count=count_products)

def _handle_productgroup_post():
    username = request.args.get('user'); password = request.args.get('pass')
    if not is_authenticated(username, password):
        return Response('Unauthorized', status=401)

    raw = request.get_data()
    # Return a positive OK even for probes/empty to let UM continue
    if request.method == 'GET' or not raw or not raw.strip():
        logging.info("ProductGroup probe/empty payload -> replying OK:1 (xml)")
        return ok_xml(count=1)

    root = _parse_xml(raw, "product group xml")

    found = 0
    created = 0
    existing = get_existing_collections()

    for node in root.iter():
        if node.tag.split('}', 1)[-1].lower() != 'productgroup':
            continue
        found += 1

        group_id = (
            _gettext(node, "id","groupno","groupid","qvalue","no")
            or next((node.attrib[k] for k in ("id","groupno","groupid","qvalue","no")
                     if k in node.attrib and node.attrib[k].strip()), None)
        )
        title = (
            _gettext(node, "description","name","title")
            or next((node.attrib[k] for k in ("description","name","title")
                     if k in node.attrib and node.attrib[k].strip()), None)
        )

        if not group_id or not title:
            logging.warning("Skipping productgroup; missing id/description (after tolerant lookup)")
            continue

        handle = f"group-{group_id.strip()}".lower().replace(" ", "-")
        if handle not in existing:
            create_collection(title.strip(), handle)
            existing[handle] = True
            created += 1

    resp_count = found or created or 1
    logging.info(f"ProductGroup reply OK:{resp_count} (found={found}, created={created})")
    return ok_xml(count=resp_count)

def _handle_files_post():
    username = request.args.get('user'); password = request.args.get('pass')
    if not is_authenticated(username, password):
        return Response('Unauthorized', status=401)
    try:
        if 'file' in request.files:
            f = request.files['file']
            blob = f.read()
            sku = request.form.get('productno') or request.form.get('articleno') or request.form.get('itemno') or ''
            logging.info(f"Image received path={request.path} for SKU '{sku}': filename={f.filename}, size={len(blob)} bytes")
            # TODO: attach to Shopify product image
        else:
            raw = request.get_data()
            logging.info(f"Image upload (no multipart) path={request.path} size={len(raw)} bytes")
        return ok_xml()
    except Exception as e:
        logging.exception(f"postfiles failed: {e}")
        return Response('<ERROR/>', mimetype='text/xml', status=500)

# -------- Route aliases --------
# PRODUCTS (single)
@app.route('/twinxml/postproduct.asp', methods=['GET','POST'])
@app.route('/twinxml/postproduct.aspx', methods=['GET','POST'])
@app.route('/postproduct.asp', methods=['GET','POST'])
@app.route('/postproduct.aspx', methods=['GET','POST'])
@app.route('/product/twinxml/postproduct.asp', methods=['GET','POST'])
@app.route('/product/twinxml/postproduct.aspx', methods=['GET','POST'])
@app.route('/twinxml/twinxml/postproduct.asp', methods=['GET','POST'])
@app.route('/twinxml/twinxml/postproduct.aspx', methods=['GET','POST'])
def postproduct_router():
    return _handle_product_post()

# PRODUCTS (bulk/list → same handler)
@app.route('/twinxml/productlist.asp', methods=['GET','POST'])
@app.route('/twinxml/productlist.aspx', methods=['GET','POST'])
@app.route('/productlist.asp', methods=['GET','POST'])
@app.route('/productlist.aspx', methods=['GET','POST'])
@app.route('/twinxml/postproductlist.asp', methods=['GET','POST'])
@app.route('/twinxml/postproductlist.aspx', methods=['GET','POST'])
@app.route('/postproductlist.asp', methods=['GET','POST'])
@app.route('/postproductlist.aspx', methods=['GET','POST'])
@app.route('/twinxml/products.asp', methods=['GET','POST'])
@app.route('/twinxml/products.aspx', methods=['GET','POST'])
@app.route('/products.asp', methods=['GET','POST'])
@app.route('/products.aspx', methods=['GET','POST'])
@app.route('/product/twinxml/productlist.asp', methods=['GET','POST'])
@app.route('/product/twinxml/productlist.aspx', methods=['GET','POST'])
@app.route('/product/twinxml/postproductlist.asp', methods=['GET','POST'])
@app.route('/product/twinxml/postproductlist.aspx', methods=['GET','POST'])
@app.route('/product/twinxml/products.asp', methods=['GET','POST'])
@app.route('/product/twinxml/products.aspx', methods=['GET','POST'])
@app.route('/twinxml/twinxml/productlist.asp', methods=['GET','POST'])
@app.route('/twinxml/twinxml/productlist.aspx', methods=['GET','POST'])
@app.route('/twinxml/twinxml/postproductlist.asp', methods=['GET','POST'])
@app.route('/twinxml/twinxml/postproductlist.aspx', methods=['GET','POST'])
@app.route('/twinxml/twinxml/products.asp', methods=['GET','POST'])
@app.route('/twinxml/twinxml/products.aspx', methods=['GET','POST'])
def productlist_router():
    return _handle_product_post()

# PRODUCT GROUPS
@app.route('/twinxml/postproductgroup.asp', methods=['GET','POST'])
@app.route('/twinxml/postproductgroup.aspx', methods=['GET','POST'])
@app.route('/postproductgroup.asp', methods=['GET','POST'])
@app.route('/postproductgroup.aspx', methods=['GET','POST'])
@app.route('/product/twinxml/postproductgroup.asp', methods=['GET','POST'])
@app.route('/product/twinxml/postproductgroup.aspx', methods=['GET','POST'])
@app.route('/twinxml/twinxml/postproductgroup.asp', methods=['GET','POST'])
@app.route('/twinxml/twinxml/postproductgroup.aspx', methods=['GET','POST'])
def postproductgroup_router():
    return _handle_productgroup_post()

# FILES / IMAGES
@app.route('/twinxml/postfiles.asp', methods=['POST'])
@app.route('/twinxml/postfiles.aspx', methods=['POST'])
@app.route('/postfiles.asp', methods=['POST'])
@app.route('/postfiles.aspx', methods=['POST'])
@app.route('/product/twinxml/postfiles.asp', methods=['POST'])
@app.route('/product/twinxml/postfiles.aspx', methods=['POST'])
@app.route('/twinxml/twinxml/postfiles.asp', methods=['POST'])
@app.route('/twinxml/twinxml/postfiles.aspx', methods=['POST'])
def postfiles_router():
    return _handle_files_post()

# STATUS
@app.route('/twinxml/status.asp', methods=['GET','POST'])
@app.route('/twinxml/status.aspx', methods=['GET','POST'])
@app.route('/status.asp', methods=['GET','POST'])
@app.route('/status.aspx', methods=['GET','POST'])
@app.route('/product/twinxml/status.asp', methods=['GET','POST'])
@app.route('/product/twinxml/status.aspx', methods=['GET','POST'])
@app.route('/twinxml/twinxml/status.asp', methods=['GET','POST'])
@app.route('/twinxml/twinxml/status.aspx', methods=['GET','POST'])
def status():
    return ok_xml()

# ORDERS placeholder (return minimal XML so UM doesn’t abort)
def _orders_ok_xml():
    return Response("<Orders/>", mimetype="text/xml")

@app.route('/twinxml/orders.asp', methods=['GET','POST'])
@app.route('/twinxml/orders.aspx', methods=['GET','POST'])
@app.route('/orders.asp', methods=['GET','POST'])
@app.route('/orders.aspx', methods=['GET','POST'])
@app.route('/product/twinxml/orders.asp', methods=['GET','POST'])
@app.route('/product/twinxml/orders.aspx', methods=['GET','POST'])
@app.route('/twinxml/twinxml/orders.asp', methods=['GET','POST'])
@app.route('/twinxml/twinxml/orders.aspx', methods=['GET','POST'])
def orders():
    return _orders_ok_xml()

# ---- Fallbacks to catch any odd paths/casing -------------------------------
def _looks_like_product(name: str) -> bool:
    n = name.lower()
    return any(k in n for k in [
        "postproduct", "productlist", "products", "postproductlist", "product",
        "postarticle", "articles", "article", "postitem", "items", "item",
        "uploadproduct", "sendproduct", "exportproducts"
    ])

def _looks_like_group(name: str) -> bool:
    n = name.lower()
    return any(k in n for k in ["productgroup", "postproductgroup", "groups", "group"])

@app.route('/twinxml/<path:name>.asp', methods=['GET','POST'])
@app.route('/twinxml/<path:name>.aspx', methods=['GET','POST'])
@app.route('/product/twinxml/<path:name>.asp', methods=['GET','POST'])
@app.route('/product/twinxml/<path:name>.aspx', methods=['GET','POST'])
@app.route('/twinxml/twinxml/<path:name>.asp', methods=['GET','POST'])
@app.route('/twinxml/twinxml/<path:name>.aspx', methods=['GET','POST'])
def twinxml_fallback(name):
    logging.info(f"FALLBACK hit name='{name}' method={request.method} len={request.content_length}")
    try:
        if _looks_like_product(name):
            logging.info("→ Routing to _handle_product_post() from fallback")
            return _handle_product_post()
        if _looks_like_group(name):
            logging.info("→ Routing to _handle_productgroup_post() from fallback")
            return _handle_productgroup_post()
        n = name.lower()
        if "order" in n:
            return _orders_ok_xml()
        if "status" in n:
            return ok_xml()
    except Exception:
        logging.exception(f"twinxml_fallback error for name='{name}'")
    return ok_xml()

# Super fallback (any path)
@app.route('/<path:anything>', methods=['GET','POST'])
def any_fallback(anything):
    p = request.path
    lower = p.lower()
    logging.info(f"SUPER_FALLBACK hit path='{p}' method={request.method} len={request.content_length}")
    try:
        if _looks_like_product(lower):
            logging.info("→ SUPER_FALLBACK routing to _handle_product_post()")
            return _handle_product_post()
        if _looks_like_group(lower):
            logging.info("→ SUPER_FALLBACK routing to _handle_productgroup_post()")
            return _handle_productgroup_post()
        if "order" in lower:
            return _orders_ok_xml()
        if "status" in lower:
            return ok_xml()
    except Exception:
        logging.exception(f"any_fallback error for path='{p}'")
    return ok_xml()

# Entrypoint (unused on gunicorn, harmless locally)
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
