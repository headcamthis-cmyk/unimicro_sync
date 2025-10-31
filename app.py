
# app.py
import os
import time
import json
import logging
import threading
import queue
import html
import base64
import re
from typing import Dict, Any, Optional, List, Tuple
from flask import Flask, request, Response, jsonify
import requests
import xml.etree.ElementTree as ET

# -----------------------------------------------------
# Flask / Logging
# -----------------------------------------------------
app = Flask(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s: %(message)s")

# -----------------------------------------------------
# Helpers
# -----------------------------------------------------
def env_bool(name: str, default: bool) -> bool:
    val = os.environ.get(name, str(default)).strip().lower()
    return val in ("1", "true", "yes", "y", "on")

def env_float(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, str(default)))
    except Exception:
        return default

def env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, str(default)))
    except Exception:
        return default

def ok_txt(body: str = "OK") -> Response:
    # Uni can be picky about mimetype + CRLF
    return Response(body + "\r\n", mimetype="text/plain; charset=windows-1252")

def is_authenticated(username: Optional[str], password: Optional[str]) -> bool:
    return (username or "") == os.environ.get("UNI_USER", "synall") and (password or "") == os.environ.get("UNI_PASS", "synall")

def get_qparam(name: str, default: Optional[str] = None) -> Optional[str]:
    v = request.args.get(name)
    if v is None:
        v = request.form.get(name, default)
    return v

# -----------------------------------------------------
# ENV / Config
# -----------------------------------------------------
SHOPIFY_DOMAIN       = os.environ.get("SHOPIFY_DOMAIN", "allsupermotoas.myshopify.com")
SHOPIFY_TOKEN        = os.environ.get("SHOPIFY_TOKEN", "")
SHOPIFY_API_VERSION  = os.environ.get("SHOPIFY_API_VERSION", "2024-10")
SHOPIFY_LOC_ID       = os.environ.get("SHOPIFY_LOCATION_ID", "").strip()

# Behavior toggles
STRICT_UPDATE_ONLY   = env_bool("STRICT_UPDATE_ONLY", True)   # never create
ALLOW_CREATE         = False  # hard-locked per user request
PRELOAD_SKU_CACHE    = env_bool("PRELOAD_SKU_CACHE", True)
KILL_SWITCH          = env_bool("KILL_SWITCH", False)
STOP_AFTER_N         = env_int("STOP_AFTER_N", 0)             # 0 = unlimited per request
MAX_QUEUE_SIZE       = env_int("MAX_QUEUE_SIZE", 5000)
WORKER_THREADS       = env_int("WORKER_THREADS", 4)
QPS                  = env_float("QPS", 1.6)                  # global limiter across threads

# Content / SEO
DEFAULT_VENDOR       = os.environ.get("DEFAULT_VENDOR", "Ukjent leverandør")
DEFAULT_SEO_DESC     = os.environ.get("DEFAULT_SEO_DESC", "AllSupermoto AS – originale deler og tilbehør.")
DEFAULT_BODY_HTML    = os.environ.get("DEFAULT_BODY_HTML", "<p>Originale deler fra ASM.</p>")
DEFAULT_BODY_MODE    = os.environ.get("DEFAULT_BODY_MODE", "fallback")  # fallback|replace|append
TAG_MAX              = env_int("TAG_MAX", 8)
PLACEHOLDER_IMAGE_URL= os.environ.get("PLACEHOLDER_IMAGE_URL", "").strip()  # optional

# Server behavior
ACK_FIRST_THEN_WORK  = env_bool("ACK_FIRST_THEN_WORK", True)
CONNECTION_CLOSE     = env_bool("CONNECTION_CLOSE", True)
BOOT_IMMEDIATELY     = env_bool("BOOT_IMMEDIATELY", True)

# -----------------------------------------------------
# Shopify REST helpers
# -----------------------------------------------------
def shopify_rest(method: str, path: str, **kwargs) -> requests.Response:
    url = f"https://{SHOPIFY_DOMAIN}/admin/api/{SHOPIFY_API_VERSION}/{path.lstrip('/')}"
    headers = kwargs.pop("headers", {})
    headers["X-Shopify-Access-Token"] = SHOPIFY_TOKEN
    headers["Content-Type"] = "application/json"
    if CONNECTION_CLOSE:
        headers["Connection"] = "close"
    resp = requests.request(method, url, headers=headers, timeout=30, **kwargs)
    if resp.status_code >= 400:
        logging.warning("Shopify %s %s -> %s %s", method, path, resp.status_code, resp.text[:500])
    return resp

# -----------------------------------------------------
# SKU Cache (id -> variant info) for STRICT_UPDATE_ONLY
# -----------------------------------------------------
# Map SKU -> (product_id, variant_id, has_images: bool)
SKU_CACHE: Dict[str, Tuple[int, int, bool]] = {}
CACHE_LOCK = threading.Lock()

def preload_sku_cache():
    if not SHOPIFY_TOKEN:
        logging.warning("No SHOPIFY_TOKEN set; cannot preload SKU cache.")
        return
    try:
        logging.info("Preloading SKU cache from Shopify...")
        count = 0
        next_page = None
        base = f"products.json?limit=250&fields=id,variants,image"
        while True:
            path = base + (f"&page_info={next_page}" if next_page else "")
            r = shopify_rest("GET", path)
            if r.status_code != 200:
                break
            data = r.json() or {}
            products = data.get("products", [])
            if not products:
                break
            with CACHE_LOCK:
                for p in products:
                    pid = p.get("id")
                    has_images = bool(p.get("image"))
                    for v in p.get("variants", []):
                        sku = (v.get("sku") or "").strip()
                        vid = v.get("id")
                        if sku:
                            SKU_CACHE[sku] = (pid, vid, has_images)
                            count += 1
            # pagination via Link header
            link = r.headers.get("Link") or r.headers.get("link")
            next_page = None
            if link:
                for part in link.split(","):
                    if 'rel="next"' in part:
                        m = re.search(r"page_info=([^>;]+)", part)
                        if m:
                            next_page = m.group(1)
            if not next_page:
                break
        logging.info("Preloaded %d SKUs.", count)
    except Exception as e:
        logging.exception("Failed preloading SKU cache: %s", e)

def get_cached_variant(sku: str) -> Optional[Tuple[int, int, bool]]:
    with CACHE_LOCK:
        return SKU_CACHE.get(sku)

# -----------------------------------------------------
# Global QPS limiter (token bucket-ish)
# -----------------------------------------------------
_qps_lock = threading.Lock()
_last_call = 0.0

def throttle_qps():
    global _last_call
    if QPS <= 0:
        return
    intend_gap = 1.0 / QPS
    with _qps_lock:
        now = time.time()
        gap = now - _last_call
        if gap < intend_gap:
            time.sleep(intend_gap - gap)
        _last_call = time.time()

# -----------------------------------------------------
# Work queue / workers
# -----------------------------------------------------
WORK_Q: "queue.Queue[Dict[str, Any]]" = queue.Queue(maxsize=MAX_QUEUE_SIZE)
STATS = {
    "queued": 0,
    "updated": 0,
    "skipped_noop": 0,
    "skipped_cache_miss": 0,
    "dropped": 0,
}

def update_shopify_product(parsed: Dict[str, Any]):
    sku = parsed["sku"]
    price = parsed.get("price")
    compare_at = parsed.get("compare_at")
    available = parsed.get("available")
    title = parsed.get("title") or ""
    vendor = parsed.get("vendor") or DEFAULT_VENDOR
    tags = parsed.get("tags") or []

    # Only update if SKU exists
    cv = get_cached_variant(sku)
    if not cv:
        if STRICT_UPDATE_ONLY:
            logging.warning("STRICT_UPDATE_ONLY: SKU '%s' not found (cache). Skipping.", sku)
            STATS["skipped_cache_miss"] += 1
            return
        logging.warning("Creation disabled and SKU '%s' missing. Skipping.", sku)
        STATS["skipped_cache_miss"] += 1
        return

    product_id, variant_id, has_images = cv

    # Price / Inventory updates
    # 1) Variant price
    body = {"variant": {"id": variant_id}}
    if price is not None:
        body["variant"]["price"] = round(float(price), 2)
    if compare_at is not None:
        body["variant"]["compare_at_price"] = round(float(compare_at), 2)

    throttle_qps()
    r = shopify_rest("PUT", f"variants/{variant_id}.json", json=body)
    if r.status_code in (200, 201):
        # Inventory (if location provided)
        if SHOPIFY_LOC_ID and available is not None:
            try:
                throttle_qps()
                shopify_rest("POST", "inventory_levels/set.json", json={
                    "location_id": int(SHOPIFY_LOC_ID),
                    "inventory_item_id": r.json()["variant"]["inventory_item_id"],
                    "available": int(available),
                })
            except Exception:
                logging.exception("Inventory update failed for SKU %s", sku)

        # Product meta (title/vendor/tags/seo)
        p_updates = {}
        if title:
            p_updates["title"] = title
        if vendor:
            p_updates["vendor"] = vendor
        if tags:
            p_updates["tags"] = ",".join(tags[:TAG_MAX])

        # SEO title
        if vendor or title or sku:
            seo_title = " - ".join([x for x in [vendor, title] if x]) + (f" | {sku} | AllSupermoto AS")
            p_updates.setdefault("metafields_global_title_tag", seo_title[:70])
        p_updates.setdefault("metafields_global_description_tag", DEFAULT_SEO_DESC[:320])

        if p_updates:
            throttle_qps()
            shopify_rest("PUT", f"products/{product_id}.json", json={"product": {"id": product_id, **p_updates}})

        # Placeholder image if none
        if PLACEHOLDER_IMAGE_URL and not has_images:
            try:
                throttle_qps()
                shopify_rest("POST", f"products/{product_id}/images.json", json={
                    "image": {"src": PLACEHOLDER_IMAGE_URL, "alt": sku}
                })
            except Exception:
                logging.exception("Failed to upload placeholder image for %s", sku)

        STATS["updated"] += 1
    else:
        logging.warning("Variant update failed for %s: %s %s", sku, r.status_code, r.text[:200])

def worker_loop(idx: int):
    logging.info("Worker %d started.", idx)
    while True:
        try:
            item = WORK_Q.get()
            if item is None:
                break
            if KILL_SWITCH:
                logging.warning("KILL_SWITCH active; dropping task.")
                STATS["dropped"] += 1
                continue
            update_shopify_product(item)
        except Exception:
            logging.exception("Worker exception")
        finally:
            WORK_Q.task_done()

def ensure_workers():
    if getattr(ensure_workers, "_started", False):
        return
    ensure_workers._started = True  # type: ignore
    for i in range(max(1, WORKER_THREADS)):
        t = threading.Thread(target=worker_loop, args=(i+1,), daemon=True)
        t.start()

# -----------------------------------------------------
# XML payload parsing
# -----------------------------------------------------
def parse_uni_product_xml(xml_text: str) -> List[Dict[str, Any]]:
    items: List[Dict[str, Any]] = []
    try:
        root = ET.fromstring(xml_text)
    except Exception:
        # fallback: try per-line fragments
        for line in xml_text.splitlines():
            line = line.strip()
            if not line or not line.startswith("<"):
                continue
            try:
                root = ET.fromstring(line)
                break
            except Exception:
                continue
        else:
            raise

    for it in root.findall(".//item") + root.findall(".//product"):
        sku = (it.findtext("sku") or it.findtext("artnr") or "").strip()
        if not sku:
            sku = (it.attrib.get("sku") or it.attrib.get("artnr") or "").strip()
        title = (it.findtext("title") or it.findtext("name") or "").strip()
        vendor = (it.findtext("vendor") or it.findtext("brand") or "").strip()
        price = it.findtext("price")
        compare_at = it.findtext("compare_at")
        stock = it.findtext("stock") or it.findtext("saldo") or "0"
        reserved = it.findtext("reserved") or "0"
        tags = []
        for tg in it.findall(".//tag"):
            if tg.text:
                tags.append(tg.text.strip())

        try:
            stock_i = int(float(stock))
        except Exception:
            stock_i = 0
        try:
            reserved_i = int(float(reserved))
        except Exception:
            reserved_i = 0

        available = max(0, stock_i - reserved_i)

        parsed = {
            "sku": sku,
            "title": title,
            "vendor": vendor,
            "price": float(price) if price else None,
            "compare_at": float(compare_at) if compare_at else None,
            "available": available,
            "tags": tags,
        }
        logging.info("PARSED sku=%s title=%r price=%s compare_at=%s stock=%s reserved=%s -> available=%s vendor=%r",
                     sku, title, parsed["price"], parsed["compare_at"], stock, reserved, available, vendor)
        items.append(parsed)
    return items

def parse_uni_group_xml(xml_text: str) -> List[Dict[str, Any]]:
    groups: List[Dict[str, Any]] = []
    try:
        root = ET.fromstring(xml_text)
    except Exception:
        return groups
    for g in root.findall(".//group") + root.findall(".//varegruppe"):
        gid = (g.findtext("id") or g.findtext("gruppeid") or g.attrib.get("id") or "").strip()
        name = (g.findtext("name") or g.findtext("gruppenavn") or g.attrib.get("name") or "").strip()
        parent = (g.findtext("parent") or g.findtext("parentid") or "").strip()
        groups.append({"id": gid, "name": name, "parent": parent})
    return groups

# -----------------------------------------------------
# Routes
# -----------------------------------------------------
@app.before_request
def _log_every_request():
    try:
        logging.info("REQ %s %s  Referer=%s", request.method, request.full_path or request.path, request.headers.get("Referer", "-"))
    except Exception:
        pass

@app.after_request
def _add_conn_close(resp: Response):
    if CONNECTION_CLOSE:
        resp.headers["Connection"] = "close"
    return resp

@app.route("/")
def root_404():
    return Response("<!doctype html><title>Not Found</title>Not Found", status=404, mimetype="text/html")

@app.get("/admin/health")
def admin_health():
    ensure_workers()
    with CACHE_LOCK:
        cache_size = len(SKU_CACHE)
    payload = {
        "ok": True,
        "kill_switch": KILL_SWITCH,
        "strict_update_only": STRICT_UPDATE_ONLY,
        "allow_create": ALLOW_CREATE,
        "preload_cache": PRELOAD_SKU_CACHE,
        "cache_size": cache_size,
        "qps": QPS,
        "workers": WORKER_THREADS,
        "max_queue_size": MAX_QUEUE_SIZE,
        "queue_size": WORK_Q.qsize(),
        "queued": STATS["queued"],
        "updated": STATS["updated"],
        "skipped_noop": STATS["skipped_noop"],
        "skipped_cache_miss": STATS["skipped_cache_miss"],
        "dropped": STATS["dropped"],
        "default_body_mode": DEFAULT_BODY_MODE,
        "tag_max": TAG_MAX,
        "stop_after_n": STOP_AFTER_N,
    }
    return jsonify(payload)

@app.route("/twinxml/orders.asp", methods=["GET", "POST"])
def twin_orders():
    u = get_qparam("user")
    p = get_qparam("pass")
    if not is_authenticated(u, p):
        return Response("Unauthorized\r\n", status=401, mimetype="text/plain")
    return ok_txt("OK")

@app.post("/twinxml/postproductgroup.asp")
def twin_post_productgroup():
    u = get_qparam("user")
    p = get_qparam("pass")
    if not is_authenticated(u, p):
        return Response("Unauthorized\r\n", status=401, mimetype="text/plain")

    xml_text = request.get_data(as_text=True) or ""
    try:
        groups = parse_uni_group_xml(xml_text)
        logging.info("Got %d product groups.", len(groups))
        return ok_txt("OK")
    except Exception:
        logging.exception("Failed to parse product groups")
        return ok_txt("OK")

@app.post("/twinxml/postproduct.asp")
def twin_post_product():
    ensure_workers()
    u = get_qparam("user")
    p = get_qparam("pass")
    if not is_authenticated(u, p):
        return Response("Unauthorized\r\n", status=401, mimetype="text/plain")

    # ignore deleteproduct
    if "deleteproduct" in (request.path or "").lower():
        logging.warning("Delete product payload detected. Ignoring by policy.")
        return ok_txt("OK")

    xml_text = request.get_data(as_text=True) or ""
    try:
        items = parse_uni_product_xml(xml_text)
    except Exception:
        logging.exception("Failed to parse product XML")
        return ok_txt("OK")

    max_items = STOP_AFTER_N if STOP_AFTER_N > 0 else len(items)
    accepted = 0
    for it in items[:max_items]:
        if KILL_SWITCH:
            logging.warning("KILL_SWITCH is on; dropping incoming items.")
            STATS["dropped"] += 1
            continue
        try:
            WORK_Q.put_nowait(it)
            STATS["queued"] += 1
            accepted += 1
        except queue.Full:
            STATS["dropped"] += 1
            logging.warning("Queue full; dropping sku=%s", it.get("sku"))

    logging.info("Accepted %d / %d items this request.", accepted, len(items))
    return ok_txt("OK")

# -----------------------------------------------------
# Boot-time tasks
# -----------------------------------------------------
def _boot():
    ensure_workers()
    if PRELOAD_SKU_CACHE:
        preload_sku_cache()

if env_bool("BOOT_IMMEDIATELY", True):
    threading.Thread(target=_boot, daemon=True).start()

# -----------------------------------------------------
# Main (local)
# -----------------------------------------------------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", "10000"))
    app.run(host="0.0.0.0", port=port, threaded=True)
