# app.py
# Uni Micro -> Shopify updater (STRICT_UPDATE_ONLY)
# - Exposes UM endpoints (.asp/.aspx/none) and always returns exact "OK\r\n" (windows-1252)
# - Parses UM product payloads (hex XML tolerated), enqueues updates
# - Background workers update Shopify: title, tags (generated), SEO (metafields), price, stock, placeholder image
# - Alt text for placeholder = SKU
# - Preloads SKU cache at boot to avoid "skipping" on existing products
# - Flask 3 compatible (no before_first_request)

import os, logging, time, re, json, html, threading, queue
from typing import Dict, Any, Optional, List, Tuple
from flask import Flask, request, Response, jsonify
import requests
import xml.etree.ElementTree as ET

# ----------------------------------
# App & logging
# ----------------------------------
app = Flask(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s: %(message)s")

# ----------------------------------
# Env / Config (defaults are safe)
# ----------------------------------
SHOPIFY_DOMAIN      = os.environ.get("SHOPIFY_DOMAIN", "allsupermotoas.myshopify.com")
SHOPIFY_TOKEN       = os.environ.get("SHOPIFY_TOKEN", "")
SHOPIFY_API_VERSION = os.environ.get("SHOPIFY_API_VERSION", "2024-10")
SHOPIFY_LOC_ID      = os.environ.get("SHOPIFY_LOCATION_ID", "")  # inventory location id (string)

UNI_USER            = os.environ.get("UNI_USER", "synall")
UNI_PASS            = os.environ.get("UNI_PASS", "synall")

# Behavior
STRICT_UPDATE_ONLY  = os.environ.get("STRICT_UPDATE_ONLY", "true").lower() == "true"
PRELOAD_SKU_CACHE   = os.environ.get("PRELOAD_SKU_CACHE", "true").lower() == "true"
WORKER_THREADS      = int(os.environ.get("WORKER_THREADS", "4"))
MAX_QUEUE_SIZE      = int(os.environ.get("MAX_QUEUE_SIZE", "5000"))
STOP_AFTER_N        = int(os.environ.get("STOP_AFTER_N", "0"))   # 0 = unlimited
QPS                 = float(os.environ.get("QPS", "1.6"))        # total API calls per second (soft rate)
KILL_SWITCH_DEFAULT = os.environ.get("KILL_SWITCH", "false").lower() == "true"

# Content
DEFAULT_VENDOR      = os.environ.get("DEFAULT_VENDOR", "Ukjent leverandør")
DEFAULT_SEO_DESC    = os.environ.get("DEFAULT_SEO_DESC", "AllSupermoto AS – originale deler og tilbehør.")
DEFAULT_BODY_HTML   = os.environ.get("DEFAULT_BODY_HTML", "<p>Originale deler fra ASM.</p>")
DEFAULT_BODY_MODE   = os.environ.get("DEFAULT_BODY_MODE", "fallback")  # fallback|replace|append
TAG_MAX             = int(os.environ.get("TAG_MAX", "8"))
PLACEHOLDER_IMAGE_URL = os.environ.get("PLACEHOLDER_IMAGE_URL", "").strip()

# Admin
ADMIN_TOKEN         = os.environ.get("ADMIN_TOKEN", "")  # optional for /admin/toggle etc.

# Network
SESSION = requests.Session()
SESSION.headers.update({
    "User-Agent": "ASM-UniMicro-Sync/1.0",
    "X-Shopify-Access-Token": SHOPIFY_TOKEN
})

# ----------------------------------
# Globals (state)
# ----------------------------------
task_q: "queue.Queue[dict]" = queue.Queue(maxsize=MAX_QUEUE_SIZE)
metrics = {
    "queued": 0,
    "dropped": 0,
    "updated": 0,
    "skipped_noop": 0,
    "skipped_cache_miss": 0,
    "workers": 0,
    "preload_done": False,
    "cache_size": 0,
}
kill_switch = KILL_SWITCH_DEFAULT
accept_counter = 0
_started = False

# SKU -> (product_id, variant_id, inventory_item_id, has_product_image:bool)
SKU_CACHE: Dict[str, Tuple[int, int, int, bool]] = {}

# ----------------------------------
# Helpers
# ----------------------------------
def um_ok():
    return Response("OK\r\n", mimetype="text/plain; charset=windows-1252")

def _log_um_request(tag: str):
    try:
        raw = request.get_data(cache=True) or b""
        logging.info(f"{tag}: method={request.method} len={len(raw)} ct={request.headers.get('Content-Type','-')}")
    except Exception as e:
        logging.warning(f"{tag}: failed to log body: {e}")

def _sleep_for_rate():
    # Basic soft rate-limit: sleep 1/QPS between calls
    if QPS > 0:
        time.sleep(max(0.0, 1.0 / QPS))

def shopify_path(path: str) -> str:
    if not path.startswith("/"):
        path = "/" + path
    return f"https://{SHOPIFY_DOMAIN}{path}"

def sreq(method: str, path: str, json_body: Optional[dict]=None, params: Optional[dict]=None) -> requests.Response:
    url = shopify_path(path)
    for attempt in range(3):
        try:
            _sleep_for_rate()
            resp = SESSION.request(method, url, json=json_body, params=params, timeout=30)
            if resp.status_code in (429, 430, 520, 521, 522, 523, 524):
                # Rate/edge retry
                retry_after = int(resp.headers.get("Retry-After", "1"))
                time.sleep(min(5, retry_after))
                continue
            return resp
        except requests.RequestException as e:
            logging.warning(f"Shopify request error {method} {path}: {e}; retry {attempt+1}/3")
            time.sleep(1.0 + attempt)
    return resp  # last

def parse_link_next(link_header: str) -> Optional[str]:
    # Parse Shopify Link header for page_info rel="next"
    # Example: <https://.../products.json?limit=250&page_info=abcd>; rel="next"
    if not link_header:
        return None
    for part in link_header.split(","):
        part = part.strip()
        if 'rel="next"' in part:
            m = re.search(r'<([^>]+)>', part)
            if m:
                url = m.group(1)
                m2 = re.search(r'[?&]page_info=([^&]+)', url)
                if m2:
                    return m2.group(1)
    return None

def text_of(node: ET.Element, names: List[str]) -> Optional[str]:
    names_l = [n.lower() for n in names]
    for child in list(node):
        tag = child.tag.split("}")[-1].lower()
        if tag in names_l:
            val = (child.text or "").strip()
            if val != "":
                return val
    # also check attributes by names
    for k, v in node.attrib.items():
        if k.lower() in names_l and v:
            return v.strip()
    return None

def to_float(s: Optional[str]) -> Optional[float]:
    if not s:
        return None
    try:
        # normalize comma/space
        s2 = s.replace(" ", "").replace(",", ".")
        return float(s2)
    except:
        return None

def to_int(s: Optional[str]) -> Optional[int]:
    if s is None:
        return None
    try:
        return int(float(s))
    except:
        try:
            return int(s)
        except:
            return None

def clean_tags(s: str) -> List[str]:
    # Simple tag generator: from title + vendor words (letters/digits only), length limit
    words = re.split(r"[^0-9a-zA-ZæøåÆØÅ]+", s)
    uniq = []
    for w in words:
        w = w.strip()
        if not w:
            continue
        if len(w) < 2:
            continue
        if w not in uniq:
            uniq.append(w)
        if len(uniq) >= TAG_MAX:
            break
    return uniq

def ensure_seo(product_id: int, seo_title: str, seo_desc: str):
    # Metafields: namespace=global keys=title_tag/description_tag
    body = {
        "metafield": {
            "namespace": "global",
            "key": "title_tag",
            "type": "single_line_text_field",
            "value": seo_title[:70]  # Google displays ~60-70 chars
        }
    }
    r1 = sreq("POST", f"/admin/api/{SHOPIFY_API_VERSION}/products/{product_id}/metafields.json", json_body=body)
    if r1.status_code == 422:
        # Maybe exists -> update via PUT after fetching id
        mf = sreq("GET", f"/admin/api/{SHOPIFY_API_VERSION}/products/{product_id}/metafields.json",
                  params={"namespace":"global","key":"title_tag"})
        if mf.ok:
            arr = mf.json().get("metafields", [])
            if arr:
                mid = arr[0]["id"]
                sreq("PUT", f"/admin/api/{SHOPIFY_API_VERSION}/metafields/{mid}.json",
                     json_body={"metafield":{"id": mid, "value": seo_title[:70]}})
    # description
    body2 = {
        "metafield": {
            "namespace": "global",
            "key": "description_tag",
            "type": "single_line_text_field",
            "value": seo_desc[:320]
        }
    }
    r2 = sreq("POST", f"/admin/api/{SHOPIFY_API_VERSION}/products/{product_id}/metafields.json", json_body=body2)
    if r2.status_code == 422:
        mf = sreq("GET", f"/admin/api/{SHOPIFY_API_VERSION}/products/{product_id}/metafields.json",
                  params={"namespace":"global","key":"description_tag"})
        if mf.ok:
            arr = mf.json().get("metafields", [])
            if arr:
                mid = arr[0]["id"]
                sreq("PUT", f"/admin/api/{SHOPIFY_API_VERSION}/metafields/{mid}.json",
                     json_body={"metafield":{"id": mid, "value": seo_desc[:320]}})

def ensure_placeholder_image(product_id: int, has_image: bool, sku: str):
    if has_image:
        return
    if not PLACEHOLDER_IMAGE_URL:
        return
    body = {"image": {"src": PLACEHOLDER_IMAGE_URL, "alt": sku}}
    r = sreq("POST", f"/admin/api/{SHOPIFY_API_VERSION}/products/{product_id}/images.json", json_body=body)
    if not r.ok:
        logging.warning(f"image add failed pid={product_id} status={r.status_code} {r.text}")

def set_inventory(inventory_item_id: int, available: int):
    if not SHOPIFY_LOC_ID:
        return
    body = {"location_id": int(SHOPIFY_LOC_ID), "inventory_item_id": inventory_item_id, "available": int(max(0, available))}
    r = sreq("POST", f"/admin/api/{SHOPIFY_API_VERSION}/inventory_levels/set.json", json_body=body)
    if not r.ok:
        logging.warning(f"inventory set failed item={inventory_item_id} status={r.status_code} {r.text}")

def update_variant_price(variant_id: int, price: Optional[float]):
    if price is None:
        return
    body = {"variant": {"id": variant_id, "price": round(price, 2)}}
    r = sreq("PUT", f"/admin/api/{SHOPIFY_API_VERSION}/variants/{variant_id}.json", json_body=body)
    if not r.ok:
        logging.warning(f"price update failed vid={variant_id} status={r.status_code} {r.text}")

def update_product_fields(product_id: int, title: Optional[str], tags: List[str], body_html_mode: str, body_html_default: str):
    payload: Dict[str, Any] = {"id": product_id}
    if title:
        payload["title"] = title[:255]
    tag_string = ",".join(tags) if tags else None

    # body_html handling
    body_html_to_set: Optional[str] = None
    if body_html_mode == "replace":
        body_html_to_set = body_html_default
    elif body_html_mode == "append":
        # need current body to append
        r = sreq("GET", f"/admin/api/{SHOPIFY_API_VERSION}/products/{product_id}.json", params={"fields":"id,body_html,tags"})
        if r.ok:
            cur = r.json().get("product", {})
            cur_body = cur.get("body_html") or ""
            cur_tags = cur.get("tags") or ""
            if tag_string:
                # Merge tags with existing
                merged = set([t.strip() for t in cur_tags.split(",") if t.strip()])
                for t in tags:
                    merged.add(t)
                tag_string = ",".join(sorted(merged))
            body_html_to_set = (cur_body or "") + body_html_default
        else:
            body_html_to_set = body_html_default
    else:  # fallback
        # only set if empty (one GET required to check)
        r = sreq("GET", f"/admin/api/{SHOPIFY_API_VERSION}/products/{product_id}.json", params={"fields":"id,body_html,tags"})
        if r.ok:
            cur = r.json().get("product", {})
            cur_body = cur.get("body_html")
            cur_tags = cur.get("tags") or ""
            if not cur_body:
                body_html_to_set = body_html_default
            # Merge tags with existing
            if tag_string:
                merged = set([t.strip() for t in cur_tags.split(",") if t.strip()])
                for t in tags:
                    merged.add(t)
                tag_string = ",".join(sorted(merged))
        else:
            # on failure, do minimal update without body
            pass

    if body_html_to_set is not None:
        payload["body_html"] = body_html_to_set

    if tag_string is not None:
        payload["tags"] = tag_string

    r2 = sreq("PUT", f"/admin/api/{SHOPIFY_API_VERSION}/products/{product_id}.json", json_body={"product": payload})
    if not r2.ok:
        logging.warning(f"product update failed pid={product_id} status={r2.status_code} {r2.text}")

def preload_sku_cache():
    global SKU_CACHE
    if not SHOPIFY_TOKEN:
        logging.warning("No SHOPIFY_TOKEN set; cannot preload cache.")
        return
    logging.info("Preloading SKU cache from Shopify...")
    params = {"limit": 250, "fields": "id,variants,image,vendor"}
    next_page = None
    while True:
        if next_page:
            params = {"limit": 250, "fields": "id,variants,image,vendor", "page_info": next_page}
        r = sreq("GET", f"/admin/api/{SHOPIFY_API_VERSION}/products.json", params=params)
        if not r.ok:
            logging.warning(f"preload failed status={r.status_code} {r.text}")
            break
        data = r.json().get("products", [])
        for p in data:
            pid = int(p["id"])
            has_img = bool(p.get("image"))
            for v in p.get("variants", []):
                sku = (v.get("sku") or "").strip()
                if not sku:
                    continue
                vid = int(v["id"])
                inv_item = int(v.get("inventory_item_id") or 0)
                SKU_CACHE[sku] = (pid, vid, inv_item, has_img)
        metrics["cache_size"] = len(SKU_CACHE)
        next_page = parse_link_next(r.headers.get("Link", ""))
        if not next_page:
            break
    metrics["preload_done"] = True
    logging.info(f"Preload complete. Variants cached: {len(SKU_CACHE)}")

# ----------------------------------
# Payload parsing (UM XML, hex tolerated)
# ----------------------------------
def decode_um_payload(raw: bytes, hex_flag: bool) -> bytes:
    if hex_flag:
        try:
            # UM sends lowercase hex sometimes
            return bytes.fromhex(raw.decode("ascii"))
        except Exception as e:
            logging.warning(f"hex decode failed: {e}")
            return raw
    return raw

def parse_um_products(raw_xml: bytes) -> List[dict]:
    items: List[dict] = []
    try:
        root = ET.fromstring(raw_xml)
    except ET.ParseError as e:
        # try to salvage by stripping BOM or odd chars
        raw2 = raw_xml.strip()
        try:
            root = ET.fromstring(raw2)
        except Exception as e2:
            logging.warning(f"XML parse failed: {e}; second try: {e2}")
            return items

    # Heuristic: find nodes that look like "product"
    candidates = []
    for node in root.iter():
        tag = node.tag.split("}")[-1].lower()
        if tag in ("product","item","varerow","row","linje","vare","produkt"):
            # very likely product nodes
            candidates.append(node)

    if not candidates:
        # fallback: use direct children
        candidates = list(root)

    for n in candidates:
        sku = text_of(n, ["sku","itemno","varenr","varenummer","artnr","partno","productno","productid","externalid"])
        title = text_of(n, ["title","name","productname","varenavn","beskrivelse","description"])
        price = to_float(text_of(n, ["price","unitprice","listprice","pris","salgspris","grossprice"]))
        stock = to_int(text_of(n, ["stock","qty","quantity","onhand","lager","bestand","antall"]))
        reserved = to_int(text_of(n, ["reserved","alloc","allocated","reservert","res"]))
        vendor = text_of(n, ["vendor","brand","leverandor","manufacturer","produsent","mfr"])
        group  = text_of(n, ["group","productgroup","gruppe","kategori","categoryid"])

        if not sku:
            continue

        items.append({
            "sku": sku.strip(),
            "title": (title or "").strip(),
            "price": price,
            "stock": stock or 0,
            "reserved": reserved or 0,
            "vendor": (vendor or "").strip(),
            "group": (group or "").strip()
        })
    return items

# ----------------------------------
# Worker logic
# ----------------------------------
def process_product_update(it: dict):
    sku = it.get("sku")
    if not sku:
        return
    entry = SKU_CACHE.get(sku)
    if not entry:
        if STRICT_UPDATE_ONLY:
            metrics["skipped_cache_miss"] += 1
            logging.warning(f"STRICT_UPDATE_ONLY: SKU '{sku}' not found in cache. Skipping.")
            return
        else:
            # Optional: on-demand lookup by SKU (slow). We won't create anyway.
            r = sreq("GET", f"/admin/api/{SHOPIFY_API_VERSION}/variants.json", params={"sku": sku})
            if r.ok:
                arr = r.json().get("variants", [])
                if arr:
                    v = arr[0]
                    pid = int(v["product_id"])
                    vid = int(v["id"])
                    inv = int(v.get("inventory_item_id") or 0)
                    # fetch product image presence quickly
                    rp = sreq("GET", f"/admin/api/{SHOPIFY_API_VERSION}/products/{pid}.json", params={"fields":"id,image"})
                    has_img = False
                    if rp.ok:
                        has_img = bool(rp.json().get("product", {}).get("image"))
                    SKU_CACHE[sku] = (pid, vid, inv, has_img)
                    entry = SKU_CACHE[sku]
            if not entry:
                metrics["skipped_cache_miss"] += 1
                logging.warning(f"Lookup by SKU failed: '{sku}'. Skipping.")
                return

    pid, vid, inv_item, has_img = entry
    title = it.get("title") or None
    vendor = it.get("vendor") or DEFAULT_VENDOR
    group  = it.get("group") or ""
    price  = it.get("price")
    stock  = max(0, int(it.get("stock") or 0) - int(it.get("reserved") or 0))

    # Tags (self-generated)
    tag_source = f"{vendor} {group} {title or ''}"
    tags = clean_tags(tag_source)

    # SEO
    seo_title = f"{vendor} - {(title or sku)[:55]} | {sku} | AllSupermoto AS"
    seo_desc  = f"{DEFAULT_SEO_DESC} {title or ''}".strip()

    # 1) product title/tags/body
    update_product_fields(pid, title, tags, DEFAULT_BODY_MODE, DEFAULT_BODY_HTML)

    # 2) SEO metafields
    ensure_seo(pid, seo_title, seo_desc)

    # 3) Price (variant)
    update_variant_price(vid, price)

    # 4) Inventory
    set_inventory(inv_item, stock)

    # 5) Placeholder image if product has none
    ensure_placeholder_image(pid, has_img, sku)

    # Local flag: if we added image, mark product as having one to avoid re-adding
    if not has_img and PLACEHOLDER_IMAGE_URL:
        SKU_CACHE[sku] = (pid, vid, inv_item, True)

    metrics["updated"] += 1
    logging.info(f"UPDATED sku={sku} pid={pid} vid={vid} price={price} stock={stock} tags={len(tags)}")

def worker_loop(idx: int):
    while True:
        it = task_q.get()
        if it is None:
            break
        try:
            process_product_update(it)
        except Exception as e:
            logging.exception(f"worker {idx} error: {e}")
        finally:
            task_q.task_done()

def start_workers():
    global _started
    if _started:
        return
    _started = True
    # Preload cache
    if PRELOAD_SKU_CACHE:
        threading.Thread(target=preload_sku_cache, daemon=True).start()
    # Workers
    for i in range(max(1, WORKER_THREADS)):
        threading.Thread(target=worker_loop, args=(i+1,), daemon=True).start()
        metrics["workers"] += 1
    logging.info(f"Workers started: {metrics['workers']} / queue size {MAX_QUEUE_SIZE}")

# Start immediately on import (Flask 3 safe under gunicorn worker)
start_workers()

# ----------------------------------
# UM Routes (asp/aspx/none) with exact OK\r\n
# ----------------------------------
@app.route("/twinxml/postproductgroup", methods=["GET","POST"])
@app.route("/twinxml/postproductgroup.asp", methods=["GET","POST"])
@app.route("/twinxml/postproductgroup.aspx", methods=["GET","POST"])
def um_postproductgroup():
    _log_um_request("UM postproductgroup")
    # We don't parse here; UM only needs OK
    return um_ok()

@app.route("/twinxml/orders", methods=["GET","POST"])
@app.route("/twinxml/orders.asp", methods=["GET","POST"])
@app.route("/twinxml/orders.aspx", methods=["GET","POST"])
def um_orders():
    _log_um_request("UM orders")
    return um_ok()

@app.route("/twinxml/postproduct", methods=["GET","POST"])
@app.route("/twinxml/postproduct.asp", methods=["GET","POST"])
@app.route("/twinxml/postproduct.aspx", methods=["GET","POST"])
def um_postproduct():
    global accept_counter
    _log_um_request("UM postproduct")
    # ACK immediately
    resp = um_ok()

    # Drop if kill switch
    if kill_switch:
        logging.warning("KILL_SWITCH active: dropping incoming postproduct payload.")
        return resp

    # Decode & parse asynchronously
    try:
        raw = request.get_data(cache=True) or b""
        hex_flag = (request.args.get("hex","false").lower() == "true")
        decoded = decode_um_payload(raw, hex_flag)
        items = parse_um_products(decoded)
        for it in items:
            if STOP_AFTER_N and accept_counter >= STOP_AFTER_N:
                break
            try:
                task_q.put_nowait(it)
                accept_counter += 1
                metrics["queued"] += 1
            except queue.Full:
                metrics["dropped"] += 1
                logging.warning("Queue full; dropping item.")
        logging.info(f"Enqueued {len(items)} items (accepted_total={accept_counter})")
    except Exception as e:
        logging.exception(f"failed to parse/enqueue: {e}")
    return resp

# Ensure exact headers for UM responses
@app.after_request
def _after(resp):
    if request.path.startswith("/twinxml/"):
        resp.headers["Connection"] = "close"
        resp.headers["Content-Type"] = "text/plain; charset=windows-1252"
    return resp

# ----------------------------------
# Admin / health
# ----------------------------------
@app.route("/admin/health")
def admin_health():
    state = {
        "ok": True,
        "strict_update_only": STRICT_UPDATE_ONLY,
        "preload_cache": PRELOAD_SKU_CACHE,
        "cache_size": metrics["cache_size"],
        "preload_done": metrics["preload_done"],
        "workers": metrics["workers"],
        "queue_size": task_q.qsize(),
        "queued": metrics["queued"],
        "dropped": metrics["dropped"],
        "updated": metrics["updated"],
        "skipped_noop": metrics["skipped_noop"],
        "skipped_cache_miss": metrics["skipped_cache_miss"],
        "qps": QPS,
        "tag_max": TAG_MAX,
        "default_body_mode": DEFAULT_BODY_MODE,
        "kill_switch": kill_switch,
        "stop_after_n": STOP_AFTER_N,
        "max_queue_size": MAX_QUEUE_SIZE,
        "placehldr": bool(PLACEHOLDER_IMAGE_URL),
    }
    return jsonify(state)

def _admin_auth_ok(req) -> bool:
    if not ADMIN_TOKEN:
        return True
    return (req.args.get("token") == ADMIN_TOKEN)

@app.route("/admin/toggle_kill")
def admin_toggle_kill():
    global kill_switch
    if not _admin_auth_ok(request):
        return jsonify({"ok": False, "error": "unauthorized"}), 403
    v = request.args.get("on")
    if v is not None:
        kill_switch = (v.lower() in ("1","true","yes","on"))
    else:
        kill_switch = not kill_switch
    return jsonify({"ok": True, "kill_switch": kill_switch})

@app.route("/admin/set_stop")
def admin_set_stop():
    global STOP_AFTER_N
    if not _admin_auth_ok(request):
        return jsonify({"ok": False, "error": "unauthorized"}), 403
    try:
        STOP_AFTER_N = int(request.args.get("n","0"))
    except:
        STOP_AFTER_N = 0
    return jsonify({"ok": True, "stop_after_n": STOP_AFTER_N})

# Root 404 (Render health ping may hit /)
@app.route("/")
def root_404():
    return Response("<h1>Not Found</h1>", status=404)

# -------------------------------
# Local run (for dev)
# -------------------------------
if __name__ == "__main__":
    # For local testing only
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT","10000")), debug=True)
