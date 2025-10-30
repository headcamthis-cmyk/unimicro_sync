# app.py
import os, logging, json, time, html, base64, re
from typing import Dict, Any, Optional, List, Tuple
from flask import Flask, request, Response, jsonify
import requests
import xml.etree.ElementTree as ET

app = Flask(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s: %(message)s")

# ----------------------------
# ENV / Config
# ----------------------------
SHOPIFY_DOMAIN   = os.environ.get("SHOPIFY_DOMAIN", "allsupermotoas.myshopify.com")
SHOPIFY_TOKEN    = os.environ.get("SHOPIFY_TOKEN")  # set in Render
SHOPIFY_API_VER  = os.environ.get("SHOPIFY_API_VERSION", "2024-10")
SHOPIFY_LOC_ID   = os.environ.get("SHOPIFY_LOCATION_ID", "")  # optional

# Behavior toggles
STRICT_UPDATE_ONLY     = os.environ.get("STRICT_UPDATE_ONLY", "true").lower() == "true"
ALLOW_CREATE           = os.environ.get("ALLOW_CREATE", "false").lower() == "true"  # ignored if STRICT_UPDATE_ONLY=true
UNI_PRICE_IS_NET       = os.environ.get("UNI_PRICE_IS_NET", "true").lower() == "true"
VAT_RATE               = float(os.environ.get("VAT_RATE", "0.25"))
ENABLE_IMAGE_UPLOAD    = os.environ.get("ENABLE_IMAGE_UPLOAD", "true").lower() == "true"
PLACEHOLDER_IMAGE_URL  = os.environ.get("PLACEHOLDER_IMAGE_URL", "").strip()

# Default description block
DEFAULT_BODY_MODE      = os.environ.get("DEFAULT_BODY_MODE", "append")  # append | prepend | replace
DEFAULT_BODY_HTML      = os.environ.get("DEFAULT_BODY_HTML", "").strip()

# SEO templates
SEO_DEFAULT_TITLE_TEMPLATE = os.environ.get(
    "SEO_DEFAULT_TITLE_TEMPLATE",
    "{vendor} - {title} | {sku} | AllSupermoto AS"
)
SEO_DEFAULT_DESC_TEMPLATE = os.environ.get(
    "SEO_DEFAULT_DESC_TEMPLATE",
    "{vendor} {title} – Rask levering fra AllSupermoto AS. SKU {sku}."
)

# GraphQL page size for variant lookups
FIND_SKU_GQL_FIRST     = int(os.environ.get("FIND_SKU_GQL_FIRST", "50"))    # how many variants per page
FIND_SKU_GQL_RETRIES   = int(os.environ.get("FIND_SKU_GQL_RETRIES", "2"))   # retry if empty result

# ----------------------------
# Shopify helpers
# ----------------------------
def _headers() -> Dict[str, str]:
    return {
        "X-Shopify-Access-Token": SHOPIFY_TOKEN,
        "Content-Type": "application/json"
    }

def _url(path: str) -> str:
    return f"https://{SHOPIFY_DOMAIN}/admin/api/{SHOPIFY_API_VER}{path}"

def shopify_get_product(pid: int) -> Dict[str, Any]:
    r = requests.get(_url(f"/products/{pid}.json"), headers=_headers(), timeout=30)
    r.raise_for_status()
    return r.json()["product"]

def shopify_update_product(pid: int, product_payload: Dict[str, Any]) -> Dict[str, Any]:
    r = requests.put(_url(f"/products/{pid}.json"), headers=_headers(),
                     data=json.dumps({"product": product_payload}), timeout=30)
    if r.status_code >= 300:
        raise RuntimeError(f"update {r.status_code}: {r.text}")
    return r.json()["product"]

def shopify_create_product(product_payload: Dict[str, Any]) -> Dict[str, Any]:
    r = requests.post(_url("/products.json"), headers=_headers(),
                      data=json.dumps({"product": product_payload}), timeout=30)
    if r.status_code >= 300:
        raise RuntimeError(f"create {r.status_code}: {r.text}")
    return r.json()["product"]

def shopify_update_variant(variant_id: int, payload: Dict[str, Any]) -> Dict[str, Any]:
    r = requests.put(_url(f"/variants/{variant_id}.json"), headers=_headers(),
                     data=json.dumps({"variant": payload}), timeout=30)
    if r.status_code >= 300:
        raise RuntimeError(f"variant update {r.status_code}: {r.text}")
    return r.json()["variant"]

def shopify_set_inventory(inventory_item_id: int, available: Optional[int]) -> None:
    if not SHOPIFY_LOC_ID or available is None:
        return
    payload = {
        "location_id": int(SHOPIFY_LOC_ID),
        "inventory_item_id": int(inventory_item_id),
        "available": int(available)
    }
    r = requests.post(_url("/inventory_levels/set.json"), headers=_headers(),
                      data=json.dumps(payload), timeout=30)
    # 422 when inventory is not tracked; log softly
    if r.status_code >= 300:
        logging.warning("Inventory set failed: %s", r.text)

def shopify_product_images(pid: int) -> List[Dict[str, Any]]:
    r = requests.get(_url(f"/products/{pid}/images.json"), headers=_headers(), timeout=30)
    r.raise_for_status()
    return r.json().get("images", [])

def shopify_add_placeholder_image(pid: int, force: bool = False):
    if not ENABLE_IMAGE_UPLOAD or not PLACEHOLDER_IMAGE_URL:
        return
    try:
        imgs = shopify_product_images(pid)
        if not force:
            # Skip if any image exists
            if imgs:
                # Also skip if any equals our placeholder (extra safety)
                for im in imgs:
                    src = (im.get("src") or "").strip()
                    if src and PLACEHOLDER_IMAGE_URL and src.split("?")[0] == PLACEHOLDER_IMAGE_URL.split("?")[0]:
                        return
                return
        # Still here? Attach placeholder
        body = {"image": {"src": PLACEHOLDER_IMAGE_URL, "position": 1}}
        r = requests.post(_url(f"/products/{pid}/images.json"), headers=_headers(),
                          data=json.dumps(body), timeout=30)
        if r.status_code >= 300:
            logging.warning("Add image failed: %s", r.text)
    except Exception as e:
        logging.warning("Image attach error: %s", e)

def shopify_set_seo(pid: int, title: str, desc: str):
    payload = {
        "id": pid,
        "metafields_global_title_tag": title[:70],  # Shopify truncs at ~70
        "metafields_global_description_tag": desc[:320]
    }
    try:
        shopify_update_product(pid, payload)
    except Exception as e:
        logging.warning("SEO update failed: %s", e)

def gql(query: str, variables: Dict[str, Any]) -> Dict[str, Any]:
    url = f"https://{SHOPIFY_DOMAIN}/admin/api/{SHOPIFY_API_VER}/graphql.json"
    r = requests.post(url, headers=_headers(), data=json.dumps({"query": query, "variables": variables}), timeout=40)
    r.raise_for_status()
    return r.json()

def find_variant_by_sku_gql(sku: str) -> Optional[Tuple[int, int, int]]:
    """
    Returns (product_id, variant_id, inventory_item_id) or None.
    """
    sku = (sku or "").strip()
    if not sku:
        return None

    query = """
    query FindVar($query:String!, $first:Int!) {
      productVariants(first:$first, query:$query) {
        edges {
          node {
            id
            sku
            product { id }
            inventoryItem { id }
          }
        }
      }
    }
    """
    for attempt in range(1, FIND_SKU_GQL_RETRIES + 1):
        data = gql(query, {"query": f"sku:{json.dumps(sku)}", "first": FIND_SKU_GQL_FIRST})
        edges = data.get("data", {}).get("productVariants", {}).get("edges", [])
        if edges:
            node = edges[0]["node"]
            vid = int(node["id"].split("/")[-1])
            pid = int(node["product"]["id"].split("/")[-1])
            iid = int(node["inventoryItem"]["id"].split("/")[-1])
            return (pid, vid, iid)
        logging.warning("GraphQL lookup: 200 OK but empty for SKU '%s' (attempt %d)", sku, attempt)
        time.sleep(0.2)
    return None

# ----------------------------
# Uni XML parsing
# ----------------------------
def parse_bool_text(t: Optional[str]) -> bool:
    return (t or "").strip() in ("1", "true", "True", "yes", "on")

def clean_num(val: Optional[str]) -> Optional[float]:
    if val is None:
        return None
    s = (val or "").strip()
    if not s:
        return None
    # convert "1 234,56" -> "1234.56"
    s = s.replace(" ", "")
    if "," in s and "." in s:
        # assume comma is thousand sep
        s = s.replace(",", "")
    s = s.replace(",", ".")
    try:
        return float(s)
    except:
        return None

def parse_products_from_xml(xml_bytes: bytes, hex_mode: bool) -> List[Dict[str, Any]]:
    # In Uni, longdesc is hex when hex=true
    root = ET.fromstring(xml_bytes.decode("iso-8859-1", errors="ignore"))
    out = []
    for p in root.findall(".//product"):
        sku = (p.findtext("productident") or "").strip()
        title = (p.findtext("description") or "").strip()
        alt1  = (p.findtext("alt01") or "").strip()
        alt2  = (p.findtext("alt02") or "").strip()
        group = (p.findtext("productgroup") or "").strip()
        vendor= (p.findtext("alt06") or "").strip()  # we repurpose alt06 as vendor if present
        # prices
        netprice = clean_num(p.findtext("netprice"))
        price    = clean_num(p.findtext("price"))
        ordinary = clean_num(p.findtext("ordinaryprice"))
        qty_on_hand = clean_num(p.findtext("quantityonhand"))
        publish = parse_bool_text(p.findtext("publish"))

        # description
        longdesc = p.findtext("longdesc") or ""
        if hex_mode and longdesc:
            try:
                longdesc = bytes.fromhex(longdesc).decode("iso-8859-1", errors="ignore")
            except Exception:
                pass

        # choose a title
        full_title = title or alt1 or alt2 or sku
        if full_title == sku:
            logging.warning("Title fallback to SKU for %s (no title-like fields found)", sku)

        # choose price (add VAT if Uni is net)
        chosen = price if price is not None else netprice
        price_inc = None
        price_src = None
        if chosen is not None:
            price_inc = chosen * (1 + VAT_RATE) if UNI_PRICE_IS_NET else chosen
            price_src = "price" if price is not None else "netprice"

        out.append({
            "sku": sku,
            "title": full_title,
            "longdesc": longdesc,
            "price": price_inc,
            "price_src": price_src,
            "ordinary": ordinary,
            "stock": int(qty_on_hand) if qty_on_hand is not None else None,
            "vendor": vendor,
            "group": group,
            "publish": publish
        })
    return out

# ----------------------------
# Text utils
# ----------------------------
def merge_body(existing_html: str, default_html: str, mode: str) -> str:
    a = (existing_html or "").strip()
    b = (default_html or "").strip()
    if not b:
        return a
    if mode == "replace":
        return b
    if mode == "prepend":
        return b + ("\n\n" + a if a else "")
    # append
    return (a + "\n\n" + b) if a else b

# ----------------------------
# Main TwinXML endpoints
# ----------------------------
@app.before_request
def _log_req():
    try:
        logging.info("REQ %s %s  Referer=%s", request.method, request.path + (f"?{request.query_string.decode('utf-8','ignore')}" if request.query_string else ""), request.headers.get("Referer","-"))
    except Exception:
        pass

@app.route("/", methods=["GET","HEAD"])
def root_ok():
    return Response("OK", mimetype="text/plain")

@app.route("/twinxml/postproductgroup.asp", methods=["POST"])
def post_product_group():
    # Uni only needs "OK" back; we still parse and store to show we got it.
    body = (request.data or b"").decode("iso-8859-1", errors="ignore")
    try:
        root = ET.fromstring(body)
        groups = root.findall(".//productgroup")
        logging.info("Stored %d groups", len(groups))
    except Exception:
        logging.info("Stored 0 groups")
    # send plain "OK"
    return Response("OK", mimetype="text/plain")

@app.route("/twinxml/status.asp", methods=["POST","GET"])
def status_asp():
    # some UM builds ping this
    resp = Response('<?xml version="1.0" encoding="ISO-8859-1"?><OK>OK</OK>', mimetype="text/xml")
    resp.headers["Content-Type"] = "text/xml; charset=ISO-8859-1"
    return resp

@app.route("/twinxml/postproduct.asp", methods=["POST"])
def post_product():
    # hex=true means longdesc is hex
    hex_mode = (request.args.get("hex","").lower() == "true")
    xml_str = (request.data or b"")
    products = parse_products_from_xml(xml_str, hex_mode)
    # quick sniff logging of a few first products
    for idx, p in enumerate(products[:3], start=1):
        logging.info("SNIFF[%d]: productident=%s; description=%s; netprice=%s; price=%s; productgroup=%s; publish=%s",
                     idx, p["sku"], p["title"], p["price_src"]=="netprice", p["price"], p["group"], p["publish"])

    updated = 0
    created = 0

    for p in products:
        sku      = p["sku"]
        if not sku:
            continue
        title    = p["title"]
        price    = p["price"]
        regular  = p["ordinary"]
        stock    = p["stock"]
        vendor   = (p["vendor"] or "").strip()
        group    = (p["group"] or "").strip()

        logging.info("PARSED sku=%s title='%s' price=%s (src=%s) ordinary=%s stock=%s vendor='%s' group='%s'",
                     sku, title, price, p["price_src"], regular, stock, vendor, group)

        look = find_variant_by_sku_gql(sku)
        if not look:
            # If strict update only, skip creating
            if STRICT_UPDATE_ONLY or not ALLOW_CREATE:
                logging.warning("STRICT_UPDATE_ONLY: Not creating missing SKU '%s' (skipping create).", sku)
                continue

            # CREATE
            opts_variant = {
                "sku": sku,
                "price": f"{price:.2f}" if price is not None else "0.00",
                "inventory_management": "shopify",
                "taxable": True
            }
            if stock is not None and SHOPIFY_LOC_ID:
                # We set stock after create via inventory API
                pass

            # compose body_html
            body_html = merge_body("", DEFAULT_BODY_HTML, "replace" if DEFAULT_BODY_MODE=="replace" else "append")
            prod_payload = {
                "title": title,
                "body_html": body_html,
                "vendor": vendor or None,
                "status": "active" if p["publish"] else "draft",
                "tags": ",".join([t for t in (["group-" + group] if group else [])]),
                "variants": [opts_variant],
                "images": [{"src": PLACEHOLDER_IMAGE_URL}] if (ENABLE_IMAGE_UPLOAD and PLACEHOLDER_IMAGE_URL) else []
            }

            try:
                newp = shopify_create_product(prod_payload)
                pid  = newp["id"]
                vid  = newp["variants"][0]["id"]
                iid  = newp["variants"][0]["inventory_item_id"]
                # inventory
                if stock is not None:
                    shopify_set_inventory(iid, stock)
                # SEO
                vendor_for_seo = vendor or "Ukjent leverandør"
                seo_title = SEO_DEFAULT_TITLE_TEMPLATE.format(title=title, sku=sku, vendor=vendor_for_seo)
                seo_desc  = SEO_DEFAULT_DESC_TEMPLATE.format(title=title, sku=sku, vendor=vendor_for_seo)
                shopify_set_seo(pid, seo_title, seo_desc)
                logging.info("Shopify CREATE OK sku=%s product_id=%s status=%s admin=https://%s/admin/products/%s",
                             sku, pid, newp.get("status","active"), SHOPIFY_DOMAIN, pid)
                created += 1
            except Exception as e:
                logging.error("Shopify create failed for %s: %s", sku, e)
            continue

        # UPDATE
        pid, vid, iid = look
        # pull current product once (for vendor fallback + body merge decision)
        try:
            existing = shopify_get_product(pid)
        except Exception as e:
            logging.warning("Fetch existing product failed for %s: %s", sku, e)
            existing = {}

        existing_vendor = (existing.get("vendor") or "").strip() or None
        vendor_for_seo  = vendor or existing_vendor or "Ukjent leverandør"

        # body_html merge
        existing_body = existing.get("body_html") or ""
        merged_body   = merge_body(existing_body, DEFAULT_BODY_HTML, DEFAULT_BODY_MODE)

        # title stays as parsed Uni title (no SKU suffixing)
        product_payload = {
            "id": pid,
            "title": title,
            "vendor": vendor or existing_vendor,
            "body_html": merged_body,
            "status": "active" if p["publish"] else "draft"
        }
        # keep tags minimal; you can extend this later
        if group:
            product_payload["tags"] = f"group-{group}"

        # apply product update
        try:
            shopify_update_product(pid, product_payload)
        except Exception as e:
            logging.error("Shopify update product failed for %s: %s", sku, e)
            continue

        # variant update (price etc.)
        variant_payload = {"id": vid}
        if price is not None:
            variant_payload["price"] = f"{price:.2f}"
        # inventory (stock)
        if stock is not None:
            shopify_set_inventory(iid, stock)

        try:
            shopify_update_variant(vid, variant_payload)
        except Exception as e:
            logging.error("Shopify update variant failed for %s: %s", sku, e)

        # SEO after ensuring vendor fallback
        try:
            seo_title = SEO_DEFAULT_TITLE_TEMPLATE.format(title=title, sku=sku, vendor=vendor_for_seo)
            seo_desc  = SEO_DEFAULT_DESC_TEMPLATE.format(title=title, sku=sku, vendor=vendor_for_seo)
            shopify_set_seo(pid, seo_title, seo_desc)
        except Exception as e:
            logging.warning("SEO set failed %s: %s", sku, e)

        # Placeholder image: only if ZERO images and not already present
        if ENABLE_IMAGE_UPLOAD and PLACEHOLDER_IMAGE_URL:
            shopify_add_placeholder_image(pid, force=False)

        logging.info("Shopify UPDATE OK sku=%s product_id=%s admin=https://%s/admin/products/%s",
                     sku, pid, SHOPIFY_DOMAIN, pid)
        updated += 1

    logging.info("Upserted %d products (Shopify updated %d, created %d)", updated+created, updated, created)
    return Response("OK", mimetype="text/plain")

# ----------------------------
# (Optional) Bulk category helper (GraphQL)
# ----------------------------
# If you want to bulk-assign a fixed taxonomy category (e.g. “Motor Vehicle Suspension Parts”)
# you can call this endpoint once with your taxonomy node id.
# 1) Get the node id at: https://shopify.dev/docs/api/admin-graphql/latest/enums/ProductTaxonomyNodeId
#    or by querying GraphQL in your store.
# 2) POST /admin/set_category?gid=gid://shopify/ProductTaxonomyNode/XXXXXXXX
#    (You can also pass ?limit=500 to stop early during testing.)
ADMIN_KEY = os.environ.get("ADMIN_KEY")  # optional simple guard

@app.route("/admin/set_category", methods=["POST"])
def admin_set_category():
    if ADMIN_KEY and request.headers.get("X-Admin-Key") != ADMIN_KEY:
        return Response("forbidden", status=403)
    gid  = request.args.get("gid","").strip()
    if not gid:
        return Response("Missing ?gid=taxonomy_node_gid", status=400)

    limit = int(request.args.get("limit","0"))  # 0 = no limit
    batch = 50
    cursor = None
    count = 0

    query = """
    query Next($first:Int!, $after:String) {
      products(first:$first, after:$after) {
        edges { cursor node { id title } }
        pageInfo { hasNextPage }
      }
    }
    """
    mutation = """
    mutation SetCat($id:ID!, $gid:ID!) {
      productUpdate(input:{id:$id, productCategory:{productTaxonomyNodeId:$gid}}) {
        product { id }
        userErrors { field message }
      }
    }
    """

    while True:
        data = gql(query, {"first": batch, "after": cursor})
        edges = data.get("data", {}).get("products", {}).get("edges", [])
        if not edges:
            break
        for e in edges:
            pid_gid = e["node"]["id"]
            try:
                m = gql(mutation, {"id": pid_gid, "gid": gid})
                errs = m.get("data", {}).get("productUpdate", {}).get("userErrors", [])
                if errs:
                    logging.warning("Category set error %s: %s", pid_gid, errs)
            except Exception as ex:
                logging.warning("Category set failed %s: %s", pid_gid, ex)
            count += 1
            if limit and count >= limit:
                logging.info("Category set done (limit reached): %d", count)
                return jsonify({"updated": count})
        if not data["data"]["products"]["pageInfo"]["hasNextPage"]:
            break
        cursor = edges[-1]["cursor"]

    logging.info("Category set done: %d", count)
    return jsonify({"updated": count})

# ----------------------------
# Run (Render uses gunicorn)
# ----------------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT","8000")))
