# app.py
import os
import logging
import html
import urllib.parse
import threading
import queue
import time
from typing import Dict, Any, Optional, List, Tuple

import xml.etree.ElementTree as ET
import requests
from flask import Flask, request, jsonify, make_response

# -----------------------------------------------------------------------------
# Flask & Logging
# -----------------------------------------------------------------------------
app = Flask(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s: %(message)s")

# -----------------------------------------------------------------------------
# ENV / Config
# -----------------------------------------------------------------------------
SHOPIFY_DOMAIN   = os.environ.get("SHOPIFY_DOMAIN", "allsupermotoas.myshopify.com")
SHOPIFY_TOKEN    = os.environ.get("SHOPIFY_TOKEN")  # required
SHOPIFY_API_VER  = os.environ.get("SHOPIFY_API_VERSION", "2024-10")
SHOPIFY_LOC_ID   = os.environ.get("SHOPIFY_LOCATION_ID", "")  # inventory location id (optional but recommended)

# Behavior toggles
# You said "do not create products ever" -> set STRICT_UPDATE_ONLY=true (enforced in code too)
STRICT_UPDATE_ONLY     = True if os.environ.get("STRICT_UPDATE_ONLY", "true").lower() == "true" else False
ALLOW_CREATE           = False  # hard override; we never create products
PRELOAD_SKU_CACHE      = os.environ.get("PRELOAD_SKU_CACHE", "true").lower() == "true"
KILL_SWITCH            = os.environ.get("KILL_SWITCH", "false").lower() == "true"   # hard stop for all upserts

# Throughput / stability
ACK_FIRST_THEN_WORK    = os.environ.get("ACK_FIRST_THEN_WORK", "true").lower() == "true"  # return OK immediately
WORKER_THREADS         = int(os.environ.get("WORKER_THREADS", "4"))
MAX_QUEUE_SIZE         = int(os.environ.get("MAX_QUEUE_SIZE", "5000"))  # number of product dicts buffered
CONNECTION_CLOSE       = os.environ.get("CONNECTION_CLOSE", "true").lower() == "true"     # add Connection: close

# Shopify rate limit (global QPS across all threads)
try:
    QPS = float(os.environ.get("QPS", "2"))  # safe default
    if QPS <= 0: QPS = 2.0
except:
    QPS = 2.0

# Content controls
PLACEHOLDER_IMAGE_URL  = os.environ.get("PLACEHOLDER_IMAGE_URL", "").strip()
DEFAULT_VENDOR         = os.environ.get("DEFAULT_VENDOR", "Ukjent leverandør")
DEFAULT_SEO_DESC       = os.environ.get("DEFAULT_SEO_DESC", "KTM deler og tilbehør fra AllSupermoto AS")

# Legacy content knobs you asked to keep
DEFAULT_BODY_HTML      = os.environ.get("DEFAULT_BODY_HTML", "").strip()
DEFAULT_BODY_MODE      = os.environ.get("DEFAULT_BODY_MODE", "fallback").strip().lower()  # fallback | replace | append
try:
    TAG_MAX = int(os.environ.get("TAG_MAX", "0"))  # 0 = no tags
except:
    TAG_MAX = 0

# -----------------------------------------------------------------------------
# Global SKU cache and helpers
# -----------------------------------------------------------------------------
# exact SKU -> (product_id, variant_id)
SKU_CACHE: Dict[str, Tuple[int, int]] = {}

def log_cache_size(prefix: str = "SKU cache"):
    try:
        logging.info(f"{prefix}: {len(SKU_CACHE)} variants")
    except Exception:
        pass

# -----------------------------------------------------------------------------
# Global Shopify rate limiter
# -----------------------------------------------------------------------------
class RateLimiter:
    def __init__(self, qps: float):
        self.min_interval = 1.0 / max(0.1, qps)
        self._lock = threading.Lock()
        self._t_last = 0.0

    def acquire(self):
        with self._lock:
            now = time.time()
            wait = self._t_last + self.min_interval - now
            if wait > 0:
                time.sleep(wait)
                now = time.time()
            self._t_last = now

_rate = RateLimiter(QPS)

def shopify_request(method: str, path: str, params: Optional[Dict]=None, payload: Optional[Dict]=None, timeout: int=30):
    """Minimal Shopify REST helper with global QPS throttle"""
    _rate.acquire()
    url = f"https://{SHOPIFY_DOMAIN}/admin/api/{SHOPIFY_API_VER}{path}"
    headers = {
        "X-Shopify-Access-Token": SHOPIFY_TOKEN,
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    resp = requests.request(method.upper(), url, headers=headers, params=params, json=payload, timeout=timeout)
    # crude retry on 429
    if resp.status_code == 429:
        retry_after = float(resp.headers.get("Retry-After", "2"))
        time.sleep(max(1.0, retry_after))
        _rate.acquire()
        resp = requests.request(method.upper(), url, headers=headers, params=params, json=payload, timeout=timeout)
    return resp

def warm_sku_cache(max_pages: int = 9999):
    """Preload all variants -> SKU into SKU_CACHE."""
    global SKU_CACHE
    if not SHOPIFY_TOKEN:
        logging.warning("CACHE WARMUP skipped: missing SHOPIFY_TOKEN")
        return
    headers = {
        "X-Shopify-Access-Token": SHOPIFY_TOKEN,
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    base = f"https://{SHOPIFY_DOMAIN}/admin/api/{SHOPIFY_API_VER}/variants.json"
    params = {"limit": 250, "fields": "id,sku,product_id"}
    SKU_CACHE.clear()
    next_url = base + "?" + urllib.parse.urlencode(params)
    page = 0

    while next_url and page < max_pages:
        _rate.acquire()
        r = requests.get(next_url, headers=headers, timeout=30)
        if r.status_code != 200:
            logging.warning(f"CACHE WARMUP: HTTP {r.status_code} -> {r.text[:300]}")
            break
        data = r.json().get("variants", [])
        for v in data:
            sku = (v.get("sku") or "").strip()
            if sku:
                SKU_CACHE[sku] = (int(v["product_id"]), int(v["id"]))
        # pagination via Link header (page_info)
        link = r.headers.get("Link", "")
        next_url = None
        if 'rel="next"' in link:
            try:
                parts = [p.strip() for p in link.split(",")]
                for p in parts:
                    if 'rel="next"' in p:
                        left = p.split("<", 1)[1]
                        next_url = left.split(">", 1)[0]
                        break
            except Exception:
                next_url = None
        page += 1

    log_cache_size("Warmup complete. SKU cache")

def find_variant_by_sku_live(sku: str) -> Optional[Tuple[int, int]]:
    """On-demand REST lookup by exact SKU; returns (product_id, variant_id) or None."""
    if not SHOPIFY_TOKEN:
        return None
    base = f"https://{SHOPIFY_DOMAIN}/admin/api/{SHOPIFY_API_VER}/variants.json"
    headers = {
        "X-Shopify-Access-Token": SHOPIFY_TOKEN,
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    for candidate in (sku, "".join(sku.split())):
        params = {"limit": 1, "sku": candidate}
        url = base + "?" + urllib.parse.urlencode(params)
        _rate.acquire()
        r = requests.get(url, headers=headers, timeout=20)
        if r.status_code != 200:
            logging.warning(f"SKU LIVE LOOKUP '{candidate}': HTTP {r.status_code} -> {r.text[:200]}")
            continue
        variants = r.json().get("variants", [])
        if variants:
            v = variants[0]
            found = (int(v["product_id"]), int(v["id"]))
            SKU_CACHE[sku] = found
            if candidate != sku:
                SKU_CACHE[candidate] = found
            logging.info(f"SKU LIVE LOOKUP hit for '{sku}' -> product {found[0]} / variant {found[1]}")
            return found
    return None

# -----------------------------------------------------------------------------
# Utils
# -----------------------------------------------------------------------------
def ok_txt(body: str = "OK"):
    # exact plain text + CRLF; UM can be picky about line endings
    resp = make_response(body + "\r\n")
    resp.mimetype = "text/plain"
    resp.charset = "windows-1252"
    if CONNECTION_CLOSE:
        resp.headers["Connection"] = "close"
    # tiny content avoids client buffering stalls
    resp.headers["Content-Length"] = str(len((body + "\\r\\n").encode("cp1252", errors="ignore")))
    return resp

def parse_um_xml(xml_text: str) -> List[Dict[str, Any]]:
    """Parse Uni Micro postproduct payload into list of dicts with fields:
    sku, title, price, compare_at, stock, vendor, group, cost, description (optional)
    """
    items: List[Dict[str, Any]] = []
    try:
        root = ET.fromstring(xml_text)
    except Exception as e:
        logging.warning(f"XML parse failed: {e}")
        return items

    product_nodes = root.findall(".//PRODUCT") or root.findall(".//Product") or root.findall(".//PRODUKT") or list(root)

    def get_text(node: ET.Element, *tags: str) -> str:
        for t in tags:
            el = node.find(t)
            if el is not None and el.text is not None:
                return el.text.strip()
        return ""

    for p in product_nodes:
        sku = get_text(p, "SKU", "sku", "ARTNR", "artnr", "PRODUCTNO", "ProductNumber", "Varenr", "varenr", "ItemNo")
        title = get_text(p, "TITLE", "title", "NAME", "Name", "Produktnavn", "produktnavn", "DESCRIPTION1", "desc1")
        price = get_text(p, "PRICE", "price", "Pris", "pris", "RetailPrice")
        compare_at = get_text(p, "COMPARE_AT_PRICE", "compare_at_price", "OriginalPrice", "oldprice")
        stock = get_text(p, "STOCK", "stock", "Qty", "qty", "OnHand", "onhand", "Lager", "lager")
        reserved = get_text(p, "RESERVED", "reserved", "Res", "res")
        vendor = get_text(p, "VENDOR", "vendor", "Brand", "brand", "Leverandor", "leverandor")
        group = get_text(p, "GROUP", "group", "ProductGroup", "Gruppe", "gruppe")
        cost = get_text(p, "COST", "cost", "Innpris", "innpris")
        desc = get_text(p, "LONGDESC", "Description", "description", "BESKRIVELSE", "beskrivelse")

        sku = (sku or "").strip()
        title = (title or "").strip() or sku

        def to_float(x):
            try:
                return float(str(x).replace(",", "."))
            except:
                return 0.0

        def to_int(x):
            try:
                return int(float(str(x).replace(",", ".")))
            except:
                return 0

        price_f = to_float(price)
        compare_f = to_float(compare_at) if compare_at else None
        stock_i = to_int(stock)
        res_i = to_int(reserved)
        available = max(0, stock_i - res_i)

        item = {
            "sku": sku,
            "title": title,
            "price": price_f,
            "compare_at": compare_f,
            "stock": stock_i,
            "reserved": res_i,
            "available": available,
            "vendor": vendor.strip() if vendor else "",
            "group": group.strip() if group else "",
            "cost": to_float(cost) if cost else None,
            "description": desc or "",
        }
        items.append(item)
    return items

def ensure_product_images(product_id: int, sku: str):
    """Upload placeholder image only if product has no images. Alt text = SKU."""
    if not PLACEHOLDER_IMAGE_URL:
        return
    r = shopify_request("GET", f"/products/{product_id}.json", params={"fields": "id,images"})
    if r.status_code != 200:
        logging.warning(f"IMG CHECK: HTTP {r.status_code} {r.text[:200]}")
        return
    images = r.json().get("product", {}).get("images", [])
    if images:
        return  # already has an image
    payload = {"image": {"src": PLACEHOLDER_IMAGE_URL, "alt": sku}}
    r2 = shopify_request("POST", f"/products/{product_id}/images.json", payload=payload)
    if r2.status_code not in (200, 201):
        logging.warning(f"IMG UPLOAD: HTTP {r2.status_code} {r2.text[:200]}")
    else:
        logging.info(f"IMG UPLOAD: placeholder added for product {product_id} (alt={sku})")

def build_seo(vendor: str, title: str, sku: str, description: Optional[str]) -> Dict[str, Any]:
    v = (vendor or "").strip() or DEFAULT_VENDOR
    t = f"{v} - {title} | {sku} | AllSupermoto AS"
    d = (description or DEFAULT_SEO_DESC or "").strip()
    return {"seo": {"title": t[:70], "description": d[:320]}}

def build_body_html(desc: str) -> str:
    """Combine incoming description with DEFAULT_BODY_HTML per DEFAULT_BODY_MODE.
       - fallback: use incoming if present else default
       - replace: ignore incoming and always use default
       - append: incoming first (escaped) + default (raw) appended
    """
    incoming = (desc or "").strip()
    default_html = DEFAULT_BODY_HTML or ""
    mode = DEFAULT_BODY_MODE
    if mode == "replace":
        return default_html
    if mode == "append":
        if incoming:
            return f"{html.escape(incoming)}\n\n{default_html}" if default_html else html.escape(incoming)
        return default_html
    # fallback (default)
    if incoming:
        return html.escape(incoming)
    return default_html

def build_tags(vendor: str, group: str, sku: str) -> Optional[List[str]]:
    if TAG_MAX <= 0:
        return None
    tags: List[str] = []
    if vendor.strip():
        tags.append(vendor.strip())
    if group.strip():
        tags.append(f"group-{group.strip()}")
    # keep tags compact; avoid SKU as tag to prevent explosion
    if len(tags) > TAG_MAX:
        tags = tags[:TAG_MAX]
    return tags

def update_variant_price_stock(variant_id: int, price: float, compare_at: Optional[float], available: int):
    # Price / compare_at
    variant_payload: Dict[str, Any] = {"variant": {"id": variant_id, "price": round(price, 2)}}
    if compare_at is not None and compare_at > price:
        variant_payload["variant"]["compare_at_price"] = round(compare_at, 2)
    r = shopify_request("PUT", f"/variants/{variant_id}.json", payload=variant_payload)
    if r.status_code not in (200, 201):
        logging.warning(f"VARIANT UPDATE: HTTP {r.status_code} {r.text[:200]}")

    # Inventory (if location id is provided)
    if SHOPIFY_LOC_ID:
        r2 = shopify_request("GET", f"/variants/{variant_id}.json", params={"fields": "id,inventory_item_id"})
        if r2.status_code == 200:
            inv_item_id = r2.json().get("variant", {}).get("inventory_item_id")
            if inv_item_id:
                payload = {
                    "location_id": int(SHOPIFY_LOC_ID),
                    "inventory_item_id": int(inv_item_id),
                    "available": int(available),
                }
                r3 = shopify_request("POST", "/inventory_levels/set.json", payload=payload)
                if r3.status_code not in (200, 201):
                    logging.warning(f"INV SET: HTTP {r3.status_code} {r3.text[:200]}")
        else:
            logging.warning(f"GET VARIANT (inventory_item_id) failed: HTTP {r2.status_code} {r2.text[:200]}")

def update_product(product_id: int, variant_id: int, item: Dict[str, Any]):
    vendor = item.get("vendor") or DEFAULT_VENDOR
    tags = build_tags(vendor, item.get("group",""), item["sku"]) or []
    product_payload: Dict[str, Any] = {
        "product": {
            "id": product_id,
            "title": item["title"] or item["sku"],
            "vendor": vendor,
            "body_html": build_body_html(item.get("description") or ""),
            **build_seo(vendor, item["title"] or item["sku"], item["sku"], item.get("description")),
        }
    }
    if tags:
        product_payload["product"]["tags"] = ", ".join(tags)

    r = shopify_request("PUT", f"/products/{product_id}.json", payload=product_payload)
    if r.status_code not in (200, 201):
        logging.warning(f"UPDATE PRODUCT: HTTP {r.status_code} {r.text[:300]}")

    # variant price + stock
    update_variant_price_stock(variant_id, item["price"], item.get("compare_at"), item.get("available", 0))

    # placeholder image if none
    ensure_product_images(product_id, item["sku"])

# -----------------------------------------------------------------------------
# Async work queue
# -----------------------------------------------------------------------------
WORK_Q: "queue.Queue[Dict[str, Any]]" = queue.Queue(maxsize=MAX_QUEUE_SIZE)
STATS = {"queued": 0, "updated": 0, "skipped_noop": 0, "skipped_cache_miss": 0, "dropped": 0}
WORKERS: list[threading.Thread] = []

def worker_loop(idx: int):
    logging.info(f"Worker {idx} started")
    while True:
        item = WORK_Q.get()
        if item is None:
            logging.info(f"Worker {idx} stopping")
            break
        try:
            if KILL_SWITCH:
                STATS["skipped_noop"] += 1
                continue

            sku = (item.get("sku") or "").strip()
            if not sku:
                STATS["skipped_noop"] += 1
                continue

            ids = SKU_CACHE.get(sku) or find_variant_by_sku_live(sku)
            if not ids:
                # update-only policy: never create; just skip cache-miss
                STATS["skipped_cache_miss"] += 1
                continue

            product_id, variant_id = ids
            update_product(product_id, variant_id, item)
            STATS["updated"] += 1
        except Exception as e:
            logging.warning(f"Worker {idx} error: {e}")
        finally:
            WORK_Q.task_done()

def start_workers(n: int):
    global WORKERS
    if WORKERS:
        return
    for i in range(n):
        t = threading.Thread(target=worker_loop, args=(i+1,), daemon=True)
        t.start()
        WORKERS.append(t)

def stop_workers():
    for _ in WORKERS:
        WORK_Q.put(None)

# -----------------------------------------------------------------------------
# Request logging & connection handling
# -----------------------------------------------------------------------------
@app.before_request
def _log_every_request():
    try:
        ref = request.headers.get("Referer", "-")
        logging.info(f"REQ {request.method} {request.path}?{request.query_string.decode('latin-1')}  Referer={ref}")
    except Exception:
        pass

@app.after_request
def _after(resp):
    if CONNECTION_CLOSE:
        resp.headers["Connection"] = "close"
    return resp

@app.before_first_request
def _boot_before_first_request():
    try:
        boot_once()
    except Exception as e:
        logging.warning(f"boot_once() failed in before_first_request: {e}")


# -----------------------------------------------------------------------------
# Admin endpoints
# -----------------------------------------------------------------------------
@app.route("/admin/health", methods=["GET"])
def health():
    return jsonify({
        "ok": True,
        "cache_size": len(SKU_CACHE),
        "strict_update_only": True,
        "allow_create": False,
        "preload_cache": PRELOAD_SKU_CACHE,
        "kill_switch": KILL_SWITCH,
        "queued": STATS["queued"],
        "updated": STATS["updated"],
        "skipped_noop": STATS["skipped_noop"],
        "skipped_cache_miss": STATS["skipped_cache_miss"],
        "dropped": STATS["dropped"],
        "workers": len(WORKERS),
        "queue_size": WORK_Q.qsize(),
        "max_queue_size": MAX_QUEUE_SIZE,
        "qps": QPS,
        "default_body_mode": DEFAULT_BODY_MODE,
        "tag_max": TAG_MAX,
    })

@app.route("/admin/refresh_sku_cache", methods=["POST", "GET"])
def refresh_sku_cache():
    warm_sku_cache()
    return jsonify({"ok": True, "count": len(SKU_CACHE)})

@app.route("/admin/kill", methods=["POST"])
def admin_kill():
    global KILL_SWITCH
    KILL_SWITCH = True
    return jsonify({"ok": True, "kill_switch": True})

@app.route("/admin/revive", methods=["POST"])
def admin_revive():
    global KILL_SWITCH
    KILL_SWITCH = False
    return jsonify({"ok": True, "kill_switch": False})

# -----------------------------------------------------------------------------
# Uni Micro endpoints
# -----------------------------------------------------------------------------
def _maybe_decode_hex_body(raw: bytes) -> str:
    qs = request.args.to_dict(flat=True)
    is_hex = (qs.get("hex", "") or "").lower() == "true"
    if is_hex:
        try:
            hex_str = raw.decode("latin-1").strip()
            data = bytes.fromhex(hex_str)
            try:
                return data.decode("cp1252", errors="replace")
            except:
                return data.decode("utf-8", errors="replace")
        except Exception as e:
            logging.warning(f"HEX decode failed: {e}")
            return raw.decode("utf-8", errors="replace")
    else:
        try:
            return raw.decode("cp1252", errors="replace")
        except:
            return raw.decode("utf-8", errors="replace")

def enqueue_items(items: List[Dict[str, Any]]):
    added = 0
    for it in items:
        try:
            WORK_Q.put_nowait(it)
            STATS["queued"] += 1
            added += 1
        except queue.Full:
            STATS["dropped"] += 1
            # We still ACK UM to avoid it freezing, but we record drops
    return added

@app.route("/twinxml/postproduct.asp", methods=["POST"])
def postproduct():
    raw = request.get_data(cache=False, as_text=False)
    text = _maybe_decode_hex_body(raw)

    items = parse_um_xml(text)
    added = enqueue_items(items)

    qs = request.args.to_dict(flat=True)
    last_flag = (qs.get("last", "") or "").lower() == "true"
    total = qs.get("total")
    sessionid = qs.get("sessionid")

    logging.info(f"BATCH: queued {added}/{len(items)} items | queue={WORK_Q.qsize()}/{MAX_QUEUE_SIZE} | last={last_flag} total={total} session={sessionid}")
    return ok_txt("OK")

# Explicitly stop any deleteproduct attempts (we don't support it)
@app.route("/twinxml/postdeleteproduct.asp", methods=["POST", "GET"])
def postdeleteproduct():
    logging.warning("DELETEPRODUCT received -> telling UM to stop (feature disabled).")
    return ok_txt("STOP")

@app.route("/twinxml/<path:subpath>", methods=["POST", "GET"])
def twinxml_catchall(subpath: str):
    if "deleteproduct" in subpath.lower():
        logging.warning(f"DELETE route '{subpath}' -> STOP")
        return ok_txt("STOP")
    if "postproduct" in subpath.lower():
        return postproduct()
    return ok_txt("OK")

# -----------------------------------------------------------------------------
# Startup
# -----------------------------------------------------------------------------
STARTED = False
START_LOCK = None

try:
    import threading as _t
    START_LOCK = _t.Lock()
except Exception:
    class _Dummy:
        def __enter__(self): pass
        def __exit__(self, *a): pass
    START_LOCK = _Dummy()


def boot_once():
    global STARTED
    with START_LOCK:
        if STARTED:
            return
        STARTED = True
        boot()

def boot():
    logging.info(f"Shopify domain: {SHOPIFY_DOMAIN} | API ver: {SHOPIFY_API_VER} | QPS={QPS}")
    if PRELOAD_SKU_CACHE:
        try:
            warm_sku_cache()
        except Exception as e:
            logging.warning(f"CACHE WARMUP failed: {e}")
    else:
        log_cache_size("Startup (no warmup). Current SKU cache")
    start_workers(WORKER_THREADS)

if os.environ.get("BOOT_IMMEDIATELY", "true").lower() == "true":
    try:
        boot_once()
    except Exception as e:
        logging.warning(f"boot_once() at import failed: {e}")

if __name__ == "__main__":
    port = int(os.environ.get("PORT", "10000"))
    app.run(host="0.0.0.0", port=port, threaded=True)
