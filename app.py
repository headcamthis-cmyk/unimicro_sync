# app.py
import os, logging, json, time, html, base64, re, threading
from typing import Dict, Any, Optional, List, Tuple
from flask import Flask, request, Response, jsonify
import requests
import xml.etree.ElementTree as ET
from queue import Queue

# -----------------------------------------------------------------------------
# Flask & logging
# -----------------------------------------------------------------------------
app = Flask(__name__)
logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"),
                    format="%(asctime)s %(levelname)s: %(message)s")

# -----------------------------------------------------------------------------
# ENV / Config
# -----------------------------------------------------------------------------
SHOPIFY_DOMAIN        = os.environ.get("SHOPIFY_DOMAIN", "allsupermotoas.myshopify.com")
SHOPIFY_TOKEN         = os.environ.get("SHOPIFY_TOKEN")  # required
SHOPIFY_API_VERSION   = os.environ.get("SHOPIFY_API_VERSION", "2024-10")
SHOPIFY_LOCATION_ID   = os.environ.get("SHOPIFY_LOCATION_ID", "")   # required for inventory

# Behavior toggles
STRICT_UPDATE_ONLY    = os.environ.get("STRICT_UPDATE_ONLY", "true").lower() == "true"
ALLOW_CREATE          = os.environ.get("ALLOW_CREATE", "false").lower() == "true"  # ignored if STRICT_UPDATE_ONLY
PRELOAD_CACHE         = os.environ.get("PRELOAD_CACHE", "true").lower() == "true"
HYBRID_LOOKUP         = os.environ.get("HYBRID_LOOKUP", "true").lower() == "true"
KILL_SWITCH_DEFAULT   = os.environ.get("KILL_SWITCH", "false").lower() == "true"
DEFAULT_BODY_MODE     = os.environ.get("DEFAULT_BODY_MODE", "append").lower()  # "append" | "replace" | "skip"
TAG_MAX               = int(os.environ.get("TAG_MAX", "8"))
QPS                   = float(os.environ.get("QPS", "2"))
STOP_AFTER_N          = int(os.environ.get("STOP_AFTER_N", "0"))  # 0 = unlimited
MAX_QUEUE_SIZE        = int(os.environ.get("MAX_QUEUE_SIZE", "8000"))
WORKERS               = int(os.environ.get("WORKER_THREADS", str(os.cpu_count() or 4)))
CACHE_SIZE_LIMIT      = int(os.environ.get("CACHE_SIZE_LIMIT", "0"))  # 0 = unlimited

# Placeholder image
PLACEHOLDER_URL       = os.environ.get("PLACEHOLDER_URL", "").strip()  # public URL to a PNG/JPG
PLACEHOLDER_ALT_MODE  = os.environ.get("PLACEHOLDER_ALT_MODE", "sku")  # "sku" | "const"
PLACEHOLDER_ALT_CONST = os.environ.get("PLACEHOLDER_ALT", "ASM placeholder")

# SEO
SEO_TITLE_PREFIX      = os.environ.get("SEO_TITLE_PREFIX", "")
SEO_TITLE_SUFFIX      = os.environ.get("SEO_TITLE_SUFFIX", " | AllSupermoto AS")
SEO_DESC_SUFFIX       = os.environ.get("SEO_DESC_SUFFIX", "")

# Safety
if not SHOPIFY_TOKEN:
    logging.warning("SHOPIFY_TOKEN is missing - Shopify calls will fail.")

# -----------------------------------------------------------------------------
# Globals / Metrics
# -----------------------------------------------------------------------------
METRICS: Dict[str, Any] = {
    "ok": True,
    "queue_size": 0,
    "queued": 0,
    "updated": 0,
    "dropped": 0,
    "skipped_cache_miss": 0,
    "skipped_noop": 0,
    "cache_size": 0,
    "preload_done": False,
    "placehldr": bool(PLACEHOLDER_URL),
    "default_body_mode": DEFAULT_BODY_MODE,
    "tag_max": TAG_MAX,
    "qps": QPS,
    "strict_update_only": STRICT_UPDATE_ONLY,
    "max_queue_size": MAX_QUEUE_SIZE,
    "workers": WORKERS,
    "stop_after_n": STOP_AFTER_N,
}

KILL_SWITCH = KILL_SWITCH_DEFAULT

# SKU cache: sku -> (product_id, variant_id, inventory_item_id, has_image, product_vendor)
SKU_CACHE: Dict[str, Tuple[str, str, str, bool, str]] = {}

# Rate limiter (global)
_next_call = 0.0
_rate_lock = threading.Lock()

def _ratelimit():
    global _next_call
    with _rate_lock:
        now = time.time()
        wait = _next_call - now
        if wait > 0:
            time.sleep(wait)
        _next_call = max(now, _next_call) + 1.0 / max(QPS, 0.1)

# HTTP helpers
def _shopify_headers():
    return {
        "X-Shopify-Access-Token": SHOPIFY_TOKEN or "",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }

def _s_get(url: str, params: Optional[dict]=None, timeout=30):
    _ratelimit()
    return requests.get(url, headers=_shopify_headers(), params=params or {}, timeout=timeout)

def _s_put(url: str, payload: dict, timeout=30):
    _ratelimit()
    return requests.put(url, headers=_shopify_headers(), data=json.dumps(payload), timeout=timeout)

def _s_post(url: str, payload: dict, timeout=30):
    _ratelimit()
    return requests.post(url, headers=_shopify_headers(), data=json.dumps(payload), timeout=timeout)

# -----------------------------------------------------------------------------
# Preload Catalog on Startup (Flask 3 safe)
# -----------------------------------------------------------------------------
_PRELOAD_THREAD_STARTED = False

# --- replace your preload worker with this version ---
def _preload_catalog_worker():
    logging.info("PRELOAD: started")
    added = 0
    try:
        base = f"https://{SHOPIFY_DOMAIN}/admin/api/{SHOPIFY_API_VERSION}/products.json"
        params = {"limit": 250, "fields": "id,images,variants,vendor"}
        since_id = None
        while True:
            if since_id:
                params["since_id"] = since_id
            resp = _s_get(base, params=params)
            if resp.status_code != 200:
                logging.warning(f"PRELOAD: GET products failed {resp.status_code} {resp.text[:300]}")
                break
            data = resp.json() or {}
            products = data.get("products", [])
            if not products:
                break
            for p in products:
                pid = str(p["id"])
                has_image = bool(p.get("images"))
                vendor = (p.get("vendor") or "").strip()
                for v in (p.get("variants") or []):
                    sku = (v.get("sku") or "").strip()
                    if not sku:
                        continue
                    SKU_CACHE[sku] = (
                        pid,
                        str(v["id"]),
                        str(v["inventory_item_id"]),
                        has_image,
                        vendor,
                    )
                    added += 1
                    if CACHE_SIZE_LIMIT and len(SKU_CACHE) >= CACHE_SIZE_LIMIT:
                        break
                if CACHE_SIZE_LIMIT and len(SKU_CACHE) >= CACHE_SIZE_LIMIT:
                    break
            since_id = products[-1]["id"]
            METRICS["cache_size"] = len(SKU_CACHE)
            if CACHE_SIZE_LIMIT and len(SKU_CACHE) >= CACHE_SIZE_LIMIT:
                break
        METRICS["preload_done"] = True
        METRICS["cache_size"] = len(SKU_CACHE)
        logging.info(f"PRELOAD: done. cached {added} SKUs (total keys: {len(SKU_CACHE)})")
    except Exception as e:
        logging.exception(f"PRELOAD: crashed: {e}")
    finally:
        # make sure metrics are correct even if we crashed mid-way
        METRICS["cache_size"] = len(SKU_CACHE)
        if added > 0:
            METRICS["preload_done"] = True

# --- replace your /admin/health route with this version ---
@app.get("/admin/health")
def admin_health():
    # Keep health reflective of reality even if another thread updated the cache
    METRICS.update({
        "cache_size": len(SKU_CACHE),
        "preload_done": METRICS.get("preload_done", False) or (len(SKU_CACHE) > 0),
        "queue_size": 0,
        "default_body_mode": DEFAULT_BODY_MODE,
        "tag_max": TAG_MAX,
        "qps": QPS,
        "strict_update_only": STRICT_UPDATE_ONLY,
        "max_queue_size": MAX_QUEUE_SIZE,
        "workers": WORKERS,
        "stop_after_n": STOP_AFTER_N,
        "placehldr": bool(PLACEHOLDER_URL),
    })
    return jsonify(METRICS)

def _start_preloader_once():
    global _PRELOAD_THREAD_STARTED
    if _PRELOAD_THREAD_STARTED or not PRELOAD_CACHE:
        return
    _PRELOAD_THREAD_STARTED = True
    t = threading.Thread(target=_preload_catalog_worker, name="sku-preload", daemon=True)
    t.start()

# Start immediately on import
_start_preloader_once()

def _search_variant_by_sku(sku: str) -> Optional[Tuple[str, str, str, bool, str]]:
    """Search small page for this SKU to avoid skips while preload happens."""
    try:
        url = f"https://{SHOPIFY_DOMAIN}/admin/api/{SHOPIFY_API_VERSION}/products.json"
        # No native sku: filter in REST; fetch a few and match in app
        params = {"limit": 50, "fields": "id,images,variants,vendor"}
        r = _s_get(url, params=params)
        if r.status_code != 200:
            return None
        for p in (r.json() or {}).get("products", []):
            has_image = bool(p.get("images"))
            vendor = (p.get("vendor") or "").strip()
            for v in (p.get("variants") or []):
                if (v.get("sku") or "").strip() == sku:
                    return (str(p["id"]), str(v["id"]), str(v["inventory_item_id"]), has_image, vendor)
    except Exception:
        logging.exception(f"Hybrid lookup error for {sku}")
    return None

def resolve_sku(sku: str) -> Optional[Tuple[str, str, str, bool, str]]:
    row = SKU_CACHE.get(sku)
    if row:
        return row
    if HYBRID_LOOKUP:
        found = _search_variant_by_sku(sku)
        if found:
            SKU_CACHE[sku] = found
            METRICS["cache_size"] = len(SKU_CACHE)
            return found
    METRICS["skipped_cache_miss"] = METRICS.get("skipped_cache_miss", 0) + 1
    return None

# -----------------------------------------------------------------------------
# Utils: XML parsing & helpers
# -----------------------------------------------------------------------------
def _ok_txt(body="OK"):
    # Uni can be picky about line endings
    return Response(body + "\r\n", mimetype="text/plain; charset=windows-1252")

def _decode_body(req: request) -> bytes:
    raw = req.data or b""
    if not raw:
        return raw
    # Some Uni payloads come as hex=true query param
    if request.args.get("hex", "false").lower() == "true":
        try:
            raw = bytes.fromhex(raw.decode("ascii"))
        except Exception:
            logging.warning("HEX decode failed, using raw body.")
    return raw

def _parse_products_xml(xml_bytes: bytes) -> List[Dict[str, Any]]:
    """Parse minimal fields from Uni 'postproduct.asp' XML."""
    out = []
    if not xml_bytes:
        return out
    try:
        root = ET.fromstring(xml_bytes)
    except Exception as e:
        logging.exception(f"XML parse failed: {e}")
        return out
    for item in root.findall(".//product"):
        sku = (item.findtext("sku") or "").strip()
        if not sku:
            continue
        title = (item.findtext("title") or "").strip()
        price = _to_float(item.findtext("price"))
        compare_at = _to_float(item.findtext("compare_at"))
        stock = _to_int(item.findtext("stock"))
        reserved = _to_int(item.findtext("reserved"))
        vendor = (item.findtext("vendor") or "").strip()
        group = (item.findtext("group") or "").strip()
        desc = (item.findtext("description") or "").strip()
        available = max(0, stock - reserved)
        out.append({
            "sku": sku, "title": title, "price": price, "compare_at": compare_at,
            "available": available, "vendor": vendor, "group": group, "desc": desc
        })
    return out

def _to_float(x: Optional[str]) -> Optional[float]:
    if x is None:
        return None
    try:
        # handle both "," and "." decimals
        return float(str(x).replace(",", "."))
    except:
        return None

def _to_int(x: Optional[str]) -> int:
    if x is None:
        return 0
    try:
        return int(float(str(x).replace(",", ".")))
    except:
        return 0

def _gen_tags(row: Dict[str, Any]) -> List[str]:
    tokens = re.findall(r"[A-Za-z0-9\-]+", (row.get("title") or "") + " " + (row.get("group") or ""))
    tags = []
    seen = set()
    for t in tokens:
        t = t.upper()
        if t in seen: continue
        seen.add(t)
        tags.append(t)
        if len(tags) >= TAG_MAX:
            break
    # include vendor if present
    v = (row.get("vendor") or "").strip()
    if v and v.upper() not in seen and len(tags) < TAG_MAX:
        tags.append(v.upper())
    return tags

def _seo_title(title: str, vendor: str, sku: str) -> str:
    base = title.strip() if title else sku
    pieces = [SEO_TITLE_PREFIX, (vendor or "Ukjent leverandør"), base, SEO_TITLE_SUFFIX]
    return " ".join([p for p in pieces if p]).strip()

def _seo_desc(title: str, sku: str) -> str:
    base = f"{title} | {sku}".strip(" |")
    if SEO_DESC_SUFFIX:
        base = f"{base} {SEO_DESC_SUFFIX}"
    # Shopify truncates ~320 chars
    return base[:300]

def _placeholder_alt(sku: str) -> str:
    if PLACEHOLDER_ALT_MODE == "sku":
        return sku
    return PLACEHOLDER_ALT_CONST

# -----------------------------------------------------------------------------
# Shopify updaters
# -----------------------------------------------------------------------------
def update_product(row: Dict[str, Any]) -> bool:
    """
    Updates a product strictly by existing SKU.
    - title, vendor
    - price (first variant)
    - inventory level
    - tags
    - SEO title/description
    - body_html append/replace/skip
    - add placeholder image if product has none
    Returns True if Shopify was updated, False if skipped.
    """
    sku = row["sku"]
    found = resolve_sku(sku)
    if not found:
        if STRICT_UPDATE_ONLY:
            logging.warning(f"STRICT_UPDATE_ONLY: SKU '{sku}' not found. Skipping.")
            return False
        if not ALLOW_CREATE:
            logging.warning(f"CREATE disabled and SKU '{sku}' missing. Skipping.")
            return False
        # Not creating by request
        return False

    product_id, variant_id, inventory_item_id, has_image, vendor_cached = found
    # Title & vendor
    title = row.get("title") or sku
    vendor = (row.get("vendor") or vendor_cached or "").strip()
    tags = _gen_tags(row)

    # Build product update payload
    product_payload = {
        "product": {
            "id": product_id,
            "title": title,
            "vendor": vendor,
            "tags": ", ".join(tags),
            # SEO fields
            "metafields_global_title_tag": _seo_title(title, vendor, sku),
            "metafields_global_description_tag": _seo_desc(title, sku),
        }
    }

    # Description policy
    desc = (row.get("desc") or "").strip()
    if desc:
        if DEFAULT_BODY_MODE == "replace":
            product_payload["product"]["body_html"] = desc
        elif DEFAULT_BODY_MODE == "append":
            # Get existing to append safely
            try:
                purl = f"https://{SHOPIFY_DOMAIN}/admin/api/{SHOPIFY_API_VERSION}/products/{product_id}.json"
                pr = _s_get(purl, params={"fields": "id,body_html"})
                if pr.status_code == 200:
                    cur = (pr.json().get("product", {}) or {}).get("body_html") or ""
                    if desc not in (cur or ""):
                        joined = (cur or "") + (("<br/>" if cur else "") + desc)
                        product_payload["product"]["body_html"] = joined
                else:
                    # fallback set
                    product_payload["product"]["body_html"] = desc
            except Exception:
                product_payload["product"]["body_html"] = desc
        else:
            # skip
            pass

    # Send product update
    purl = f"https://{SHOPIFY_DOMAIN}/admin/api/{SHOPIFY_API_VERSION}/products/{product_id}.json"
    pr = _s_put(purl, product_payload)
    if pr.status_code not in (200):
        logging.warning(f"Product update failed SKU {sku}: {pr.status_code} {pr.text[:300]}")

    # Price (variant)
    price = row.get("price")
    compare_at = row.get("compare_at")
    var_changed = False
    if price is not None or compare_at is not None:
        vurl = f"https://{SHOPIFY_DOMAIN}/admin/api/{SHOPIFY_API_VERSION}/variants/{variant_id}.json"
        vp = {"variant": { "id": int(variant_id) }}
        if price is not None:
            vp["variant"]["price"] = round(float(price), 2)
            var_changed = True
        if compare_at is not None and compare_at > 0:
            vp["variant"]["compare_at_price"] = round(float(compare_at), 2)
            var_changed = True
        if var_changed:
            vr = _s_put(vurl, vp)
            if vr.status_code not in (200):
                logging.warning(f"Variant update failed SKU {sku}: {vr.status_code} {vr.text[:300]}")

    # Inventory
    if SHOPIFY_LOCATION_ID and row.get("available") is not None:
        inv_url = f"https://{SHOPIFY_DOMAIN}/admin/api/{SHOPIFY_API_VERSION}/inventory_levels/set.json"
        inv_payload = {
            "location_id": int(SHOPIFY_LOCATION_ID),
            "inventory_item_id": int(inventory_item_id),
            "available": int(row["available"]),
        }
        ir = _s_post(inv_url, inv_payload)
        if ir.status_code not in (200, 201):
            logging.warning(f"Inventory set failed SKU {sku}: {ir.status_code} {ir.text[:300]}")

    # Placeholder image if none
    if PLACEHOLDER_URL and not has_image:
        try:
            img_url = f"https://{SHOPIFY_DOMAIN}/admin/api/{SHOPIFY_API_VERSION}/products/{product_id}/images.json"
            # Double-check to avoid duplicates
            check = _s_get(img_url, params={"fields": "id,src"})
            already = False
            if check.status_code == 200:
                for im in (check.json() or {}).get("images", []):
                    if im.get("src") == PLACEHOLDER_URL:
                        already = True
                        break
            if not already:
                up = {
                    "image": {
                        "src": PLACEHOLDER_URL,
                        "alt": _placeholder_alt(sku)
                    }
                }
                ir = _s_post(img_url, up)
                if ir.status_code not in (200, 201):
                    logging.warning(f"Image add failed SKU {sku}: {ir.status_code} {ir.text[:300]}")
            # mark cache as having image
            SKU_CACHE[sku] = (product_id, variant_id, inventory_item_id, True, vendor)
        except Exception:
            logging.exception(f"Image upload error for {sku}")

    METRICS["updated"] += 1
    return True

# -----------------------------------------------------------------------------
# Request queue (simple inline processing; Uni calls are sequential anyway)
# -----------------------------------------------------------------------------
def process_rows(rows: List[Dict[str, Any]]) -> Tuple[int, int, int]:
    """Returns (updated, skipped_noop, skipped_cache_miss)"""
    updated = skipped_noop = skipped_cache = 0
    count = 0
    for row in rows:
        if KILL_SWITCH:
            logging.warning("KILL_SWITCH active - aborting batch")
            break
        if STOP_AFTER_N and count >= STOP_AFTER_N:
            logging.info(f"STOP_AFTER_N={STOP_AFTER_N} reached.")
            break
        ok = update_product(row)
        if ok:
            updated += 1
        else:
            # differentiate cache miss vs. noop if you like
            if row["sku"] not in SKU_CACHE and not HYBRID_LOOKUP:
                skipped_cache += 1
            else:
                skipped_noop += 1
        count += 1
    return updated, skipped_noop, skipped_cache

# -----------------------------------------------------------------------------
# Routes: Uni Micro TwinXML endpoints
# -----------------------------------------------------------------------------
@app.before_request
def _log_every_request():
    try:
        logging.info(f"REQ {request.method} {request.path}?{request.query_string.decode('utf-8', 'ignore') or ''}  Referer={request.headers.get('Referer','-')}")
    except Exception:
        pass

@app.route("/")
def root_404():
    return Response("<h1>Not Found</h1>", status=404, mimetype="text/html")

@app.get("/admin/health")
def admin_health():
    METRICS.update({
        "queue_size": 0,
        "default_body_mode": DEFAULT_BODY_MODE,
        "tag_max": TAG_MAX,
        "qps": QPS,
        "strict_update_only": STRICT_UPDATE_ONLY,
        "max_queue_size": MAX_QUEUE_SIZE,
        "workers": WORKERS,
        "stop_after_n": STOP_AFTER_N,
        "placehldr": bool(PLACEHOLDER_URL),
    })
    return jsonify(METRICS)

@app.post("/admin/kill")
def admin_kill():
    global KILL_SWITCH
    KILL_SWITCH = True
    return jsonify({"ok": True, "kill_switch": True})

@app.post("/admin/resume")
def admin_resume():
    global KILL_SWITCH
    KILL_SWITCH = False
    return jsonify({"ok": True, "kill_switch": False})

@app.get("/admin/preload")
def admin_preload():
    if METRICS.get("preload_done"):
        return jsonify({"ok": True, "already_done": True, "cache_size": METRICS.get("cache_size", 0)})
    _start_preloader_once()
    return jsonify({"ok": True, "started": True})

# --- Product GROUPS (we accept & OK so Uni continues) ---
@app.post("/twinxml/postproductgroup.asp")
def post_product_groups():
    body = _decode_body(request)
    # Parse if needed; for now we just log count
    try:
        root = ET.fromstring(body) if body else None
        groups = len(root.findall(".//group")) if root is not None else 0
        logging.info(f"Got {groups} product groups.")
    except Exception:
        logging.info("Got 0 product groups.")
    return _ok_txt("OK")

# --- Products feed ---
@app.post("/twinxml/postproduct.asp")
def post_product():
    # Early kill or delete short-circuit
    if KILL_SWITCH:
        return _ok_txt("OK")
    # If Uni tries to send deleteproduct here, short-circuit
    if "delete" in (request.args.get("action","") or "").lower():
        logging.info("Delete action received - STRICT stop (no-op).")
        return _ok_txt("OK")

    body = _decode_body(request)
    rows = _parse_products_xml(body)
    logging.info(f"Parsed {len(rows)} products from payload.")
    up, noop, miss = process_rows(rows)
    logging.info(f"Upserted {len(rows)} products (Shopify updated {up}, skipped no-ops {noop}, skipped cache-miss {miss})")
    return _ok_txt("OK")

# --- Orders (optional placeholder to avoid 404 noise) ---
@app.route("/twinxml/orders.asp", methods=["GET","POST"])
def orders_passthrough():
    # Not implemented; just OK to keep Uni happy
    return _ok_txt("OK")

# --- Safety: explicit delete endpoint guard (if Uni calls postdeleteproduct.asp) ---
@app.post("/twinxml/postdeleteproduct.asp")
def post_delete_guard():
    logging.info("Delete product payload received - blocked by policy.")
    return _ok_txt("OK")

# -----------------------------------------------------------------------------
# Gunicorn entry
# -----------------------------------------------------------------------------
if __name__ == "__main__":
    # For local testing
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "10000")), threaded=True)
