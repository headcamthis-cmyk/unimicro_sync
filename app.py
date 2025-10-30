import os, json, logging, sqlite3, re, base64
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List, Tuple
from flask import Flask, request, Response

import requests
import xml.etree.ElementTree as ET

# -------------------------------
# Flask & logging
# -------------------------------
app = Flask(__name__)
logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)s: %(message)s",
)

# -------------------------------
# ENV / Config
# -------------------------------
SHOPIFY_DOMAIN = os.getenv("SHOPIFY_DOMAIN", "allsupermotoas.myshopify.com")
SHOPIFY_TOKEN  = os.getenv("SHOPIFY_TOKEN", "").strip()
SHOPIFY_API    = os.getenv("SHOPIFY_API_VERSION", "2024-10")
SHOPIFY_LOCATION_ID = os.getenv("SHOPIFY_LOCATION_ID", "").strip()

# Pricing & behavior
APPLY_VAT   = os.getenv("APPLY_VAT", "true").lower() == "true"
VAT_RATE    = float(os.getenv("VAT_RATE", "0.25"))  # 25%
STRICT_UPDATE_ONLY = os.getenv("STRICT_UPDATE_ONLY", "true").lower() == "true"
ALLOW_CREATE       = os.getenv("ALLOW_CREATE", "false").lower() == "true"  # ignored if STRICT_UPDATE_ONLY is true

# Placeholder image (idempotent)
ENABLE_IMAGE_UPLOAD   = os.getenv("ENABLE_IMAGE_UPLOAD", "true").lower() == "true"
PLACEHOLDER_IMAGE_URL = os.getenv("PLACEHOLDER_IMAGE_URL", "").strip()

# SEO templates
SEO_DEFAULT_TITLE_TEMPLATE = os.getenv(
    "SEO_TITLE_TEMPLATE",
    "{vendor} - {title} | {sku} | AllSupermoto AS",
)
SEO_DEFAULT_DESC_TEMPLATE = os.getenv(
    "SEO_DESC_TEMPLATE",
    "{title} ({sku}) fra {vendor}. Rask levering fra AllSupermoto AS. Alle priser inkl. mva.",
)

# Default body_html
DEFAULT_BODY_HTML = os.getenv(
    "DEFAULT_BODY_HTML",
    """<p>Originaldel. Rask levering fra AllSupermoto AS (Stavanger).</p>
<ul>
<li>Alle priser inkl. mva</li>
<li>Klikk &amp; hent på lager når tilgjengelig</li>
</ul>
<p>Usikker på kompatibilitet? Kontakt oss – vi hjelper deg!</p>"""
)

# GraphQL retries for SKU lookups
GQL_SKU_RETRIES = int(os.getenv("GQL_SKU_RETRIES", "2"))

# -------------------------------
# SQLite (safe, minimal)
# -------------------------------
DB_PATH = os.getenv("DB_PATH", "data.db")

def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = db()
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            endpoint TEXT, method TEXT, query TEXT, body TEXT,
            created_at TEXT
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS product_groups (
            groupono TEXT PRIMARY KEY,
            description TEXT
        )
    """)
    conn.commit()
    conn.close()

init_db()

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

# -------------------------------
# Shopify helpers
# -------------------------------
def _headers() -> Dict[str, str]:
    return {
        "Content-Type": "application/json",
        "X-Shopify-Access-Token": SHOPIFY_TOKEN,
    }

def _url(path: str) -> str:
    return f"https://{SHOPIFY_DOMAIN}/admin/api/{SHOPIFY_API}{path}"

def _gql(query: str, variables: Dict[str, Any]) -> Dict[str, Any]:
    r = requests.post(
        f"https://{SHOPIFY_DOMAIN}/admin/api/{SHOPIFY_API}/graphql.json",
        headers=_headers(),
        data=json.dumps({"query": query, "variables": variables}),
        timeout=30,
    )
    if r.status_code >= 300:
        raise RuntimeError(f"GraphQL {r.status_code}: {r.text}")
    return r.json()

def shopify_get_product(pid: int) -> Dict[str, Any]:
    r = requests.get(_url(f"/products/{pid}.json"), headers=_headers(), timeout=20)
    if r.status_code != 200:
        raise RuntimeError(f"get product {pid} failed: {r.status_code} {r.text}")
    return r.json().get("product", {})

def shopify_set_seo(pid: int, title: str, desc: str):
    body = {"product": {"id": pid, "metafields_global_title_tag": title[:70], "metafields_global_description_tag": desc[:320]}}
    r = requests.put(_url(f"/products/{pid}.json"), headers=_headers(), data=json.dumps(body), timeout=20)
    if r.status_code >= 300:
        logging.warning("SEO set failed pid=%s: %s", pid, r.text)

def shopify_product_images(pid: int) -> List[Dict[str, Any]]:
    r = requests.get(_url(f"/products/{pid}/images.json"), headers=_headers(), timeout=20)
    if r.status_code != 200:
        return []
    return r.json().get("images", [])

def _placeholder_flag_get(pid: int) -> bool:
    try:
        r = requests.get(
            _url("/metafields.json") + f"?owner_resource=product&owner_id={pid}&namespace=asm&key=placeholder_seeded",
            headers=_headers(),
            timeout=20,
        )
        if r.status_code == 200:
            arr = r.json().get("metafields", [])
            if arr:
                return (arr[0].get("value") or "").lower() == "true"
    except Exception as e:
        logging.warning("Metafield check failed (pid=%s): %s", pid, e)
    return False

def _placeholder_flag_set(pid: int):
    try:
        payload = {
            "metafield": {
                "namespace": "asm",
                "key": "placeholder_seeded",
                "type": "boolean",
                "value": "true",
                "owner_resource": "product",
                "owner_id": pid,
            }
        }
        r = requests.post(_url("/metafields.json"), headers=_headers(), data=json.dumps(payload), timeout=20)
        if r.status_code >= 300 and r.status_code != 422:
            logging.warning("Metafield set failed (pid=%s): %s", pid, r.text)
    except Exception as e:
        logging.warning("Metafield set error (pid=%s): %s", pid, e)

def shopify_add_placeholder_image(pid: int, force: bool = False):
    if not ENABLE_IMAGE_UPLOAD or not PLACEHOLDER_IMAGE_URL:
        return
    try:
        if not force and _placeholder_flag_get(pid):
            return

        imgs = shopify_product_images(pid)
        base_ph = PLACEHOLDER_IMAGE_URL.split("?")[0]
        if not force:
            for im in imgs:
                src = (im.get("src") or "").split("?")[0]
                if src:
                    if src == base_ph:
                        _placeholder_flag_set(pid)
                        return
                    # any image present = do nothing
                    return

        r = requests.post(
            _url(f"/products/{pid}/images.json"),
            headers=_headers(),
            data=json.dumps({"image": {"src": PLACEHOLDER_IMAGE_URL, "position": 1}}),
            timeout=30,
        )
        if r.status_code >= 300:
            logging.warning("Add image failed: %s", r.text)
            return
        _placeholder_flag_set(pid)
    except Exception as e:
        logging.warning("Image attach error (pid=%s): %s", pid, e)

def shopify_update_product(pid: int, payload: Dict[str, Any]) -> bool:
    r = requests.put(_url(f"/products/{pid}.json"), headers=_headers(), data=json.dumps({"product": payload}), timeout=30)
    if r.status_code >= 300:
        logging.error("Shopify update product failed %s: %s", r.status_code, r.text)
        return False
    return True

def shopify_update_variant(variant_id: int, payload: Dict[str, Any]) -> bool:
    r = requests.put(_url(f"/variants/{variant_id}.json"), headers=_headers(), data=json.dumps({"variant": payload}), timeout=30)
    if r.status_code >= 300:
        logging.error("Shopify update variant failed %s: %s", r.status_code, r.text)
        return False
    return True

def shopify_create_product(create_payload: Dict[str, Any]) -> Optional[int]:
    r = requests.post(_url("/products.json"), headers=_headers(), data=json.dumps({"product": create_payload}), timeout=40)
    if r.status_code >= 300:
        logging.error("Shopify create failed %s: %s", r.status_code, r.text)
        return None
    pid = r.json().get("product", {}).get("id")
    return pid

def shopify_find_variant_by_sku(sku: str) -> Tuple[Optional[int], Optional[int]]:
    """Return (product_id, variant_id) using GraphQL SKU search, with small retry."""
    query = """
    query($sku:String!){
      productVariants(first: 1, query: $sku) {
        edges { node { id product { id } } }
      }
    }"""
    for attempt in range(1, GQL_SKU_RETRIES + 1):
        try:
            data = _gql(query, {"sku": f"sku:{sku}"})
            edges = data.get("data", {}).get("productVariants", {}).get("edges", [])
            if edges:
                node = edges[0]["node"]
                vid = int(node["id"].split("/")[-1])
                pid = int(node["product"]["id"].split("/")[-1])
                return pid, vid
            else:
                logging.warning("GraphQL lookup: 200 OK but empty for SKU '%s' (attempt %d)", sku, attempt)
        except Exception as e:
            logging.warning("GraphQL error for SKU '%s' (attempt %d): %s", sku, attempt, e)
    return (None, None)

# -------------------------------
# Uni parsing helpers
# -------------------------------
def _get_text(elem: Optional[ET.Element]) -> str:
    return (elem.text or "").strip() if elem is not None else ""

def _float_or_none(tx: str) -> Optional[float]:
    if tx is None:
        return None
    s = tx.strip()
    if not s:
        return None
    # Uni sometimes sends 123,45
    s = s.replace(" ", "").replace("\xa0", "")
    s = s.replace(",", ".")
    try:
        return float(s)
    except:
        return None

def parse_uni_products(root: ET.Element) -> List[Dict[str, Any]]:
    out = []
    for prod in root.findall(".//product"):
        sku = _get_text(prod.find("productident"))
        title = _get_text(prod.find("description")) or _get_text(prod.find("alt01")) or _get_text(prod.find("alt07"))
        group = _get_text(prod.find("productgroup"))
        vendor = _get_text(prod.find("alt02")) or _get_text(prod.find("vendor"))

        netprice = _float_or_none(_get_text(prod.find("netprice")))
        price    = _float_or_none(_get_text(prod.find("price")))
        ordinary = _float_or_none(_get_text(prod.find("ordinaryprice")))
        stock    = _float_or_none(_get_text(prod.find("quantityonhand")))
        publish  = _get_text(prod.find("publish")).lower() == "1"

        # Longdesc may be hex (when hex=true). Try decode if it looks hex-ish.
        longdesc_raw = _get_text(prod.find("longdesc"))
        body_html = ""
        if longdesc_raw:
            if re.fullmatch(r"[0-9A-Fa-f]+", longdesc_raw) and len(longdesc_raw) % 2 == 0:
                try:
                    body_html = base64.b16decode(longdesc_raw.upper()).decode("iso-8859-1", "ignore")
                except Exception:
                    body_html = longdesc_raw
            else:
                body_html = longdesc_raw

        # Price picking: prefer 'price' (gross or net, depends on UNI), else fallback to netprice
        chosen_price = price if price is not None else netprice
        price_src = "price" if price is not None else ("netprice" if netprice is not None else "none")

        out.append({
            "sku": sku,
            "title": title,
            "group": group,
            "vendor": vendor,
            "price": chosen_price,
            "price_src": price_src,
            "ordinary": ordinary,
            "stock": stock,
            "publish": publish,
            "body_html": body_html,
        })
    return out

# -------------------------------
# Business helpers
# -------------------------------
def apply_vat_if_needed(p: Dict[str, Any]) -> Optional[float]:
    val = p["price"]
    if val is None:
        return None
    if APPLY_VAT:
        return round(val * (1.0 + VAT_RATE), 2)
    return round(val, 2)

def merge_body_html(existing: str, default_html: str) -> str:
    existing = (existing or "").strip()
    if existing:
        return existing
    return default_html

def resolve_vendor_for_seo(vendor_hint: Optional[str], pid: int) -> str:
    if vendor_hint and vendor_hint.strip():
        return vendor_hint.strip()
    try:
        sp = shopify_get_product(pid)
        current = (sp.get("vendor") or "").strip()
        if current:
            return current
    except Exception as e:
        logging.warning("Could not fetch product to resolve vendor (pid=%s): %s", pid, e)
    return "Ukjent leverandør"

# -------------------------------
# TwinXML endpoints
# -------------------------------
def ok_txt(body="OK"):
    return Response((body + "\r\n").encode("iso-8859-1"), mimetype="text/plain; charset=ISO-8859-1")

@app.before_request
def _log_every_request():
    logging.info("REQ %s %s  Referer=%s", request.method, request.path + (f"?{request.query_string.decode('utf-8','ignore')}" if request.query_string else ""), request.headers.get("Referer","-"))

@app.route("/", methods=["GET","HEAD"])
def root_ok():
    return ok_txt("OK")

@app.route("/twinxml/status.asp", methods=["GET","POST"])
def status_asp():
    return ok_txt("OK")

@app.route("/twinxml/orders.aspx", methods=["GET"])
def orders_stub():
    return ok_txt("OK")

@app.route("/twinxml/postproductgroup.asp", methods=["POST"])
def post_product_group():
    body = (request.data or b"").decode("iso-8859-1", "ignore")
    try:
        root = ET.fromstring(body)
        cnt = 0
        conn = db(); cur = conn.cursor()
        for g in root.findall(".//productgroup"):
            grpno = _get_text(g.find("groupno"))
            desc  = _get_text(g.find("description"))
            if grpno:
                cur.execute("""
                    INSERT INTO product_groups(groupono, description)
                    VALUES(?,?)
                    ON CONFLICT(groupono) DO UPDATE SET description=excluded.description
                """, (grpno, desc))
                cnt += 1
        conn.commit(); conn.close()
        logging.info("Stored %d groups", cnt)
    except Exception as e:
        logging.warning("Group parse failed: %s", e)

    # <<< IMPORTANT: reply as XML >>>
    xml = '<?xml version="1.0" encoding="ISO-8859-1"?><OK>OK</OK>'
    return Response(xml.encode("iso-8859-1"),
                    mimetype="text/xml; charset=ISO-8859-1")

@app.route("/twinxml/postproduct.asp", methods=["POST"])
def post_product():
    # Parse XML (hex=true from Uni)
    raw = (request.data or b"").decode("iso-8859-1", "ignore")
    try:
        root = ET.fromstring(raw)
    except Exception as e:
        logging.error("XML parse error: %s", e)
        return ok_txt("OK")

    products = parse_uni_products(root)
    upserted = 0

    for p in products:
        sku = p["sku"]
        title_from_uni = (p["title"] or "").strip()
        # Title: use given title; never auto-append SKU
        title = title_from_uni if title_from_uni else sku

        # Price with VAT uplift if configured
        price_gross = apply_vat_if_needed(p)
        ordinary_gross = apply_vat_if_needed({"price": p["ordinary"]}) if p["ordinary"] is not None else None

        vendor = (p["vendor"] or "").strip()
        body_html = merge_body_html(p["body_html"], DEFAULT_BODY_HTML)
        group = (p["group"] or "").strip()

        logging.info("PARSED sku=%s title='%s' price=%s (src=%s) ordinary=%s stock=%s vendor='%s' group='%s'",
                     sku, title, price_gross, p["price_src"], ordinary_gross, p["stock"], vendor, group)

        # Find existing by SKU
        pid, vid = shopify_find_variant_by_sku(sku)

        # ------------------ UPDATE ------------------
        if pid and vid:
            # Only include vendor if Uni sent one; never clear Shopify's existing vendor.
            product_payload = {
                "id": pid,
                "title": title,
                "body_html": body_html,
                "status": "active" if p["publish"] else "draft",
            }
            if vendor:
                product_payload["vendor"] = vendor
            if group:
                product_payload["tags"] = f"group-{group}"

            ok_prod = shopify_update_product(pid, product_payload)

            # Variant price
            if price_gross is not None:
                variant_payload = {"id": vid, "price": price_gross}
                shopify_update_variant(vid, variant_payload)

            # SEO with final vendor
            vendor_for_seo = resolve_vendor_for_seo(vendor, pid)
            seo_title = SEO_DEFAULT_TITLE_TEMPLATE.format(title=title, sku=sku, vendor=vendor_for_seo)
            seo_desc  = SEO_DEFAULT_DESC_TEMPLATE.format(title=title, sku=sku, vendor=vendor_for_seo)
            shopify_set_seo(pid, seo_title, seo_desc)

            # Placeholder image only if none present & not previously attached
            if ENABLE_IMAGE_UPLOAD and PLACEHOLDER_IMAGE_URL:
                shopify_add_placeholder_image(pid, force=False)

            upserted += 1
            logging.info("Shopify UPDATE OK sku=%s product_id=%s admin=https://%s/admin/products/%s",
                         sku, pid, SHOPIFY_DOMAIN, pid)
            continue

        # ------------------ CREATE ------------------
        if STRICT_UPDATE_ONLY:
            logging.warning("STRICT_UPDATE_ONLY: Not creating missing SKU '%s' (skipping create).", sku)
            continue

        if not ALLOW_CREATE:
            logging.warning("Creation disabled (ALLOW_CREATE=false). Missing SKU '%s' skipped.", sku)
            continue

        # Build create payload
        product_create = {
            "title": title,
            "body_html": body_html,
            "status": "active" if p["publish"] else "draft",
            "variants": [{
                "sku": sku,
                "price": price_gross if price_gross is not None else 0,
                "inventory_management": "shopify",
                "taxable": True
            }],
            "tags": f"group-{group}" if group else None,
        }
        if vendor:
            product_create["vendor"] = vendor
        # Attach placeholder only at create if configured
        if ENABLE_IMAGE_UPLOAD and PLACEHOLDER_IMAGE_URL:
            product_create["images"] = [{"src": PLACEHOLDER_IMAGE_URL}]

        new_pid = shopify_create_product(product_create)
        if not new_pid:
            continue

        # Mark placeholder attached once
        if ENABLE_IMAGE_UPLOAD and PLACEHOLDER_IMAGE_URL:
            _placeholder_flag_set(new_pid)

        # SEO
        vendor_for_seo = resolve_vendor_for_seo(vendor, new_pid)
        seo_title = SEO_DEFAULT_TITLE_TEMPLATE.format(title=title, sku=sku, vendor=vendor_for_seo)
        seo_desc  = SEO_DEFAULT_DESC_TEMPLATE.format(title=title, sku=sku, vendor=vendor_for_seo)
        shopify_set_seo(new_pid, seo_title, seo_desc)

        upserted += 1
        logging.info("Shopify CREATE OK sku=%s product_id=%s status=%s admin=https://%s/admin/products/%s",
                     sku, new_pid, "active" if p["publish"] else "draft", SHOPIFY_DOMAIN, new_pid)

    logging.info("Upserted %d products (Shopify updated %d)", upserted, upserted)
    return ok_txt("OK")

# -------------------------------
# Run (for local testing)
# -------------------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5000")))
