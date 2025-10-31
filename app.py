# app.py
import os, logging, json, time, html, re, threading, queue
from typing import Dict, Any, Optional, List
from flask import Flask, request, Response, jsonify
import requests

# ---------------------------------------------------------------------------------
# App & logging
# ---------------------------------------------------------------------------------
app = Flask(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s: %(message)s")

# ---------------------------------------------------------------------------------
# Env / Config
# ---------------------------------------------------------------------------------
SHOPIFY_DOMAIN   = os.environ.get("SHOPIFY_DOMAIN", "allsupermotoas.myshopify.com")
SHOPIFY_TOKEN    = os.environ.get("SHOPIFY_TOKEN", "")
SHOPIFY_API_VER  = os.environ.get("SHOPIFY_API_VERSION", "2024-10")
SHOPIFY_LOC_ID   = os.environ.get("SHOPIFY_LOCATION_ID", "")  # optional

# Behavior toggles
STRICT_UPDATE_ONLY     = os.environ.get("STRICT_UPDATE_ONLY", "true").lower() == "true"
PRELOAD_SKU_CACHE      = os.environ.get("PRELOAD_SKU_CACHE", "true").lower() == "true"
ALLOW_CREATE           = False  # FORCE disabled as requested (never create products)
KILL_SWITCH            = os.environ.get("KILL_SWITCH", "false").lower() == "true"
ACK_FIRST_THEN_WORK    = os.environ.get("ACK_FIRST_THEN_WORK", "true").lower() == "true"
CONNECTION_CLOSE       = os.environ.get("CONNECTION_CLOSE", "true").lower() == "true"
STOP_AFTER_N           = int(os.environ.get("STOP_AFTER_N", "0"))  # 0 = unlimited; cap per incoming batch

# Content knobs
DEFAULT_VENDOR         = os.environ.get("DEFAULT_VENDOR", "Ukjent leverandør")
DEFAULT_SEO_DESC       = os.environ.get("DEFAULT_SEO_DESC", "KTM deler og tilbehør fra AllSupermoto AS")
DEFAULT_BODY_HTML      = os.environ.get("DEFAULT_BODY_HTML", "<p>Original KTM-deler fra ASM.</p>")
DEFAULT_BODY_MODE      = os.environ.get("DEFAULT_BODY_MODE", "fallback")  # fallback|replace|append
TAG_MAX                = int(os.environ.get("TAG_MAX", "8"))
PLACEHOLDER_IMAGE_URL  = os.environ.get("PLACEHOLDER_IMAGE_URL", "")

# Throughput
WORKER_THREADS         = int(os.environ.get("WORKER_THREADS", "4"))
MAX_QUEUE_SIZE         = int(os.environ.get("MAX_QUEUE_SIZE", "5000"))
QPS                    = float(os.environ.get("QPS", "1.6"))
BOOT_IMMEDIATELY       = os.environ.get("BOOT_IMMEDIATELY", "true").lower() == "true"

# ---------------------------------------------------------------------------------
# Globals / State
# ---------------------------------------------------------------------------------
STARTED = False
START_LOCK = threading.Lock()

metrics = {
    "queued": 0,
    "dropped": 0,
    "updated": 0,
    "skipped_cache_miss": 0,
    "skipped_noop": 0,
    "allow_create": ALLOW_CREATE,
    "strict_update_only": STRICT_UPDATE_ONLY,
    "preload_cache": PRELOAD_SKU_CACHE,
    "kill_switch": KILL_SWITCH,
    "qps": QPS,
    "tag_max": TAG_MAX,
    "default_body_mode": DEFAULT_BODY_MODE,
    "workers": 0,
    "cache_size": 0,
    "max_queue_size": MAX_QUEUE_SIZE,
    "stop_after_n": STOP_AFTER_N,
}

job_q: "queue.Queue[Optional[dict]]" = queue.Queue(maxsize=MAX_QUEUE_SIZE)
sku_cache: Dict[str, Dict[str, Any]] = {}  # sku -> {product_id, variant_id, has_image, vendor}

# Token-bucket rate limiter shared by all workers
rate_lock = threading.Lock()
tokens = QPS
last_fill = time.time()

def _rate_wait():
    """Global QPS limiter across all threads."""
    global tokens, last_fill
    if QPS <= 0:  # disabled
        return
    while True:
        with rate_lock:
            now = time.time()
            refill = (now - last_fill) * QPS
            if refill > 0:
                tokens = min(QPS, tokens + refill)
                last_fill = now
            if tokens >= 1.0:
                tokens -= 1.0
                return
        time.sleep(0.02)

# ---------------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------------
def is_authenticated(username: str, password: str) -> bool:
    # Uni Micro test creds per your setup
    return username == "synall" and password == "synall"

def ok_txt(body="OK"):
    headers = {}
    if CONNECTION_CLOSE:
        headers["Connection"] = "close"
    return Response((body + "\r\n"), mimetype="text/plain; charset=windows-1252", headers=headers)

def _shopify_headers():
    return {
        "X-Shopify-Access-Token": SHOPIFY_TOKEN,
        "Content-Type": "application/json",
        "Accept": "application/json",
    }

def _shopify_get(path: str, params: Optional[dict] = None):
    url = f"https://{SHOPIFY_DOMAIN}/admin/api/{SHOPIFY_API_VER}{path}"
    _rate_wait()
    r = requests.get(url, headers=_shopify_headers(), params=params or {}, timeout=30)
    return r

def _shopify_put(path: str, payload: dict):
    url = f"https://{SHOPIFY_DOMAIN}/admin/api/{SHOPIFY_API_VER}{path}"
    _rate_wait()
    r = requests.put(url, headers=_shopify_headers(), data=json.dumps(payload), timeout=30)
    return r

def _shopify_post(path: str, payload: dict):
    url = f"https://{SHOPIFY_DOMAIN}/admin/api/{SHOPIFY_API_VER}{path}"
    _rate_wait()
    r = requests.post(url, headers=_shopify_headers(), data=json.dumps(payload), timeout=30)
    return r

def _safe_vendor(v: Optional[str]) -> str:
    v = (v or "").strip()
    return v or DEFAULT_VENDOR

def _cap_tags(tags: List[str]) -> List[str]:
    if TAG_MAX <= 0:
        return []
    out: List[str] = []
    for t in tags:
        if t and t not in out:
            out.append(t[:64])  # Shopify short tags
        if len(out) >= TAG_MAX:
            break
    return out

# ---------------------------------------------------------------------------------
# SKU cache
# ---------------------------------------------------------------------------------
def _cache_put(sku: str, product_id: int, variant_id: int, has_image: bool, vendor: str):
    sku_cache[sku] = {
        "product_id": product_id,
        "variant_id": variant_id,
        "has_image": has_image,
        "vendor": vendor or "",
    }

def _preload_sku_cache():
    # Load all variants into sku_cache.
    if not SHOPIFY_TOKEN:
        logging.warning("No SHOPIFY_TOKEN; cannot preload cache")
        return
    page_info = None
    count = 0
    while True:
        params = {
            "limit": 250,
            "fields": "id,title,variants,images,vendor",
        }
        if page_info:
            params["page_info"] = page_info
        r = _shopify_get("/products.json", params=params)
        if r.status_code != 200:
            logging.warning(f"Preload products failed {r.status_code}: {r.text[:200]}")
            break
        data = r.json().get("products", [])
        if not data:
            break
        for p in data:
            pid = p.get("id")
            vendor = p.get("vendor") or ""
            imgs = p.get("images") or []
            has_img = len(imgs) > 0
            for v in p.get("variants", []):
                sku = (v.get("sku") or "").strip()
                vid = v.get("id")
                if sku and pid and vid:
                    _cache_put(sku, int(pid), int(vid), has_img, vendor)
                    count += 1
        link = r.headers.get("Link", "")
        if 'rel="next"' in link:
            m = re.search(r'<[^>]*[?&]page_info=([^&>]+)[^>]*>; rel="next"', link)
            if m:
                page_info = m.group(1)
                continue
        break
    metrics["cache_size"] = len(sku_cache)
    logging.info(f"Preloaded {count} variants into cache")

def _lookup_sku_live(sku: str) -> Optional[Dict[str, Any]]:
    # Single-sku lookup when cache-miss.
    r = _shopify_get("/variants.json", params={"limit": 1, "sku": sku})
    if r.status_code == 200:
        arr = r.json().get("variants", [])
        if arr:
            v = arr[0]
            vid = int(v["id"])
            pid = int(v["product_id"])
            pr = _shopify_get(f"/products/{pid}.json")
            has_img = False
            vendor = ""
            if pr.status_code == 200:
                p = pr.json().get("product", {})
                vendor = p.get("vendor") or ""
                has_img = bool(p.get("image") or (p.get("images") or []))
            _cache_put(sku, pid, vid, has_img, vendor)
            metrics["cache_size"] = len(sku_cache)
            return sku_cache.get(sku)
    logging.warning(f"Live lookup miss for SKU {sku}: {r.status_code} {r.text[:120]}")
    return None

# ---------------------------------------------------------------------------------
# Shopify update ops
# ---------------------------------------------------------------------------------
def _ensure_placeholder_image(product_id: int, sku: str, has_image: bool) -> None:
    if has_image or not PLACEHOLDER_IMAGE_URL:
        return
    payload = {"image": {"src": PLACEHOLDER_IMAGE_URL, "alt": sku}}  # alt text = SKU
    r = _shopify_post(f"/products/{product_id}/images.json", payload)
    if r.status_code not in (200, 201):
        logging.warning(f"Add placeholder image failed {r.status_code}: {r.text[:200]}")

def _build_body_html(uni_desc: Optional[str]) -> str:
    uni_desc = (uni_desc or "").strip()
    if DEFAULT_BODY_MODE == "replace":
        return DEFAULT_BODY_HTML
    if DEFAULT_BODY_MODE == "append":
        return (f"<p>{html.escape(uni_desc)}</p>" if uni_desc else "") + DEFAULT_BODY_HTML
    # fallback
    return uni_desc if uni_desc else DEFAULT_BODY_HTML

def _make_tags(vendor: str, group: Optional[str]) -> List[str]:
    tags: List[str] = []
    if vendor:
        tags.append(vendor)
    if group:
        tags.append(f"group-{group}")
    return _cap_tags(tags)

def update_shopify_from_uni(sku: str, title: str, price: Optional[float], compare_at: Optional[float],
                            available: int, vendor_in: Optional[str], group: Optional[str],
                            description: Optional[str]) -> bool:
    # Returns True if updated, False if skipped.
    sku = (sku or "").strip()
    if not sku:
        return False

    rec = sku_cache.get(sku) or _lookup_sku_live(sku)
    if not rec:
        metrics["skipped_cache_miss"] += 1
        logging.warning(f"STRICT_UPDATE_ONLY: SKU '{sku}' not found. Skipping.")
        return False

    product_id = rec["product_id"]
    variant_id = rec["variant_id"]
    has_image = rec.get("has_image", False)
    vendor = _safe_vendor(vendor_in or rec.get("vendor", ""))

    # Price / inventory
    variant_updates: Dict[str, Any] = {}
    if price is not None:
        variant_updates["price"] = round(float(price), 2)
    if compare_at is not None:
        variant_updates["compare_at_price"] = round(float(compare_at), 2)

    if variant_updates:
        r = _shopify_put(f"/variants/{variant_id}.json", {"variant": {"id": variant_id, **variant_updates}})
        if r.status_code not in (200, 201):
            logging.warning(f"variant update failed {r.status_code}: {r.text[:200]}")

    if SHOPIFY_LOC_ID and available is not None:
        # inventory set using inventory_item_id
        vr = _shopify_get(f"/variants/{variant_id}.json")
        if vr.status_code == 200:
            inv_item = vr.json().get("variant", {}).get("inventory_item_id")
            if inv_item:
                payload = {"location_id": int(SHOPIFY_LOC_ID), "inventory_item_id": int(inv_item), "available": int(available)}
                ir = _shopify_post("/inventory_levels/set.json", payload)
                if ir.status_code not in (200, 201):
                    logging.warning(f"inventory set failed {ir.status_code}: {ir.text[:200]}")

    body_html = _build_body_html(description)
    product_payload: Dict[str, Any] = {
        "product": {
            "id": product_id,
            "title": title[:255] if title else None,
            "vendor": vendor,
            "body_html": body_html,
            "tags": ", ".join(_make_tags(vendor, group)),
        }
    }
    product_payload["product"] = {k: v for k, v in product_payload["product"].items() if v is not None}
    pr = _shopify_put(f"/products/{product_id}.json", product_payload)
    if pr.status_code not in (200, 201):
        logging.warning(f"product update failed {pr.status_code}: {pr.text[:200]}")

    # SEO
    seo_title = f"{vendor} - {title} | {sku} | AllSupermoto AS".strip()
    seo_desc = DEFAULT_SEO_DESC[:320]
    _shopify_put(f"/products/{product_id}.json",
                 {"product": {"id": product_id, "metafields_global_title_tag": seo_title[:70],
                              "metafields_global_description_tag": seo_desc}})

    _ensure_placeholder_image(product_id, sku, has_image)

    metrics["updated"] += 1
    return True

# ---------------------------------------------------------------------------------
# Worker
# ---------------------------------------------------------------------------------
def worker_main(idx: int):
    logging.info(f"Worker {idx} started")
    while True:
        job = job_q.get()
        if job is None:
            break
        try:
            if KILL_SWITCH:
                logging.warning("KILL_SWITCH is true; dropping job")
                metrics["dropped"] += 1
            else:
                update_shopify_from_uni(**job)
        except Exception as e:
            logging.exception(f"worker error: {e}")
        finally:
            job_q.task_done()

# ---------------------------------------------------------------------------------
# Boot (Flask 3-safe)
# ---------------------------------------------------------------------------------
def boot():
    if PRELOAD_SKU_CACHE:
        _preload_sku_cache()
    for i in range(WORKER_THREADS):
        t = threading.Thread(target=worker_main, args=(i+1,), daemon=True)
        t.start()
    metrics["workers"] = WORKER_THREADS
    logging.info(f"Boot complete: workers={WORKER_THREADS}, preload={PRELOAD_SKU_CACHE}, qps={QPS}, stop_after_n={STOP_AFTER_N}")

def boot_once():
    global STARTED
    with START_LOCK:
        if STARTED:
            return
        STARTED = True
        boot()

if BOOT_IMMEDIATELY:
    try:
        boot_once()
    except Exception as e:
        logging.warning(f"boot_once() at import failed: {e}")

@app.before_request
def _ensure_boot_started():
    try:
        if not STARTED:
            boot_once()
    except Exception as e:
        logging.warning(f"boot_once() in before_request failed: {e}")

# ---------------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------------
@app.after_request
def _after(resp):
    if CONNECTION_CLOSE:
        resp.headers["Connection"] = "close"
    return resp

@app.route("/admin/health", methods=["GET"])
def health():
    out = dict(metrics)
    out["queue_size"] = job_q.qsize()
    return jsonify({"ok": True, **out})

@app.route("/", methods=["GET", "HEAD"])
def root_index():
    return Response("Not Found\r\n", status=404, mimetype="text/plain; charset=windows-1252")

def _parse_uni_xml(xml_text: str) -> List[Dict[str, Any]]:
    # Tolerant parser for Uni payloads.
    items: List[Dict[str, Any]] = []
    for m in re.finditer(r"<produkt\b[^>]*>(.*?)</produkt>", xml_text, flags=re.DOTALL | re.IGNORECASE):
        block = m.group(1)
        def gx(tag):
            mm = re.search(rf"<{tag}[^>]*>(.*?)</{tag}>", block, flags=re.DOTALL | re.IGNORECASE)
            return (mm.group(1).strip() if mm else "")
        sku = gx("varenr") or gx("sku") or gx("artnr")
        title = gx("navn") or gx("title") or gx("beskrivelse")[:80]
        price = gx("pris") or gx("price")
        price_f = float(price.replace(",", ".").strip()) if price else None
        compare_at = gx("veilpris") or gx("compareat") or ""
        cmp_f = float(compare_at.replace(",", ".").strip()) if compare_at else None
        stock = gx("antall") or gx("lager") or ""
        reserved = gx("reservert") or "0"
        try:
            available = max(0, int(float(stock) - float(reserved)))
        except Exception:
            available = 0
        vendor = gx("leverandor") or gx("vendor")
        group = gx("gruppe") or gx("productgroup") or gx("gruppeid") or ""
        desc = gx("beskrivelse") or gx("description")
        action = gx("action").lower()
        items.append({
            "sku": sku, "title": title, "price": price_f, "compare_at": cmp_f,
            "available": available, "vendor_in": vendor, "group": group, "description": desc,
            "action": action,
        })
    return items

@app.route("/twinxml/postproduct.asp", methods=["POST"])
def postproduct():
    user = request.args.get("user", "")
    pw = request.args.get("pass", "")
    if not is_authenticated(user, pw):
        return Response("Unauthorized\r\n", status=401, mimetype="text/plain")

    raw = request.get_data(as_text=False) or b""
    body = raw.decode("utf-8", errors="ignore")
    if request.args.get("hex", "false").lower() == "true":
        try:
            body = bytes.fromhex(body).decode("utf-8", errors="ignore")
        except Exception:
            pass

    if ACK_FIRST_THEN_WORK:
        resp = ok_txt("OK")
    else:
        resp = None

    items = _parse_uni_xml(body)

    # Hard stop on deleteproduct
    if any((it.get("action") or "").lower() == "deleteproduct" for it in items):
        logging.info("Received deleteproduct action -> telling Uni to stop (skip)")
        return ok_txt("STOP")

    # Apply STOP_AFTER_N cap per incoming batch
    if STOP_AFTER_N > 0 and len(items) > STOP_AFTER_N:
        items = items[:STOP_AFTER_N]
        logging.info(f"STOP_AFTER_N active: truncating batch to first {STOP_AFTER_N} items")

    enq = 0
    for it in items:
        if not it.get("sku"):
            continue
        job = {k: it[k] for k in ["sku","title","price","compare_at","available","vendor_in","group","description"]}
        try:
            job_q.put_nowait(job)
            metrics["queued"] += 1
            enq += 1
        except queue.Full:
            metrics["dropped"] += 1

    logging.info(f"Accepted {len(items)} items (enqueued {enq}, queue={job_q.qsize()})")
    if resp is not None:
        return resp
    else:
        for _ in range(enq):
            j = job_q.get()
            try:
                update_shopify_from_uni(**j)
            finally:
                job_q.task_done()
        return ok_txt("OK")

# ---------------------------------------------------------------------------------
# Main (dev)
# ---------------------------------------------------------------------------------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", "10000"))
    app.run(host="0.0.0.0", port=port, threaded=True)
