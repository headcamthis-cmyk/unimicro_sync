# app.py
import os
import logging
import json
import time
import html
import base64
import re
import urllib.parse
import threading
import queue
from typing import Dict, Any, Optional, List, Tuple

import xml.etree.ElementTree as ET
import requests
from flask import Flask, request, Response, jsonify, make_response

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
STRICT_UPDATE_ONLY     = os.environ.get("STRICT_UPDATE_ONLY", "true").lower() == "true"
ALLOW_CREATE           = os.environ.get("ALLOW_CREATE", "false").lower() == "true"  # ignored if STRICT_UPDATE_ONLY=true
PRELOAD_SKU_CACHE      = os.environ.get("PRELOAD_SKU_CACHE", "true").lower() == "true"
KILL_SWITCH            = os.environ.get("KILL_SWITCH", "false").lower() == "true"   # hard stop for all upserts

# Throughput / stability
ACK_FIRST_THEN_WORK    = os.environ.get("ACK_FIRST_THEN_WORK", "true").lower() == "true"  # return OK immediately, process in workers
WORKER_THREADS         = int(os.environ.get("WORKER_THREADS", "4"))
MAX_QUEUE_SIZE         = int(os.environ.get("MAX_QUEUE_SIZE", "5000"))  # number of product dicts buffered
CONNECTION_CLOSE       = os.environ.get("CONNECTION_CLOSE", "true").lower() == "true"     # add Connection: close to avoid UM keepalive hangs

# Content controls
PLACEHOLDER_IMAGE_URL  = os.environ.get("PLACEHOLDER_IMAGE_URL", "").strip()
DEFAULT_VENDOR         = os.environ.get("DEFAULT_VENDOR", "Ukjent leverandør")
DEFAULT_SEO_DESC       = os.environ.get("DEFAULT_SEO_DESC", "KTM deler og tilbehør fra AllSupermoto AS")

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

def shopify_request(method: str, path: str, params: Optional[Dict]=None, payload: Optional[Dict]=None, timeout: int=30):
    """Minimal Shopify REST helper"""
    url = f"https://{SHOPIFY_DOMAIN}/admin/api/{SHOPIFY_API_VER}{path}"
    headers = {
        "X-Shopify-Access-Token": SHOPIFY_TOKEN,
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
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
    """On-demand REST lookup by SKU; returns (product_id, variant_id) or None."""
    if not SHOPIFY_TOKEN:
        return None
    base = f"https://{SHOPIFY_DOMAIN}/admin/api/{SHOPIFY_API_VER}/variants.json"
    headers = {
        "X-Shopify-Access-Token": SHOPIFY_TOKEN,
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    for candidate in (sku, "".join(sku.split())):
        q = {"limit": 1, "sku": candidate}
        url = base + "?" + urllib.parse.urlencode(q)
        r = requests.get(url, headers=headers, timeout=20)
        if r.status_code != 200:
            logging.warning(f"SKU LIVE LOOKUP '{candidate}': HTTP {r.status_code} -> {r.text[:200]}")
            continue
        variants = r.json().get("variants", [])
        if variants:
            v = variants[0]
            found = (int(v["product_id"]), int(v["id"]))
            # cache it for subsequent hits
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

    # candidates for product nodes
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

        # Simple normalizations
        sku = (sku or "").strip()
        title = (title or "").strip() or sku
        try:
            price_f = float(str(price).replace(",", ".") or "0")
        except:
            price_f = 0.0
        try:
            compare_f = float(str(compare_at).replace(",", ".")) if compare_at else None
        except:
            compare_f = None
        def to_int(x):
            try:
                return int(float(str(x).replace(",", ".")))
            except:
                return 0
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
            "cost": float(str(cost).replace(",", ".")) if cost else None,
            "description": desc,
        }
        items.append(item)
    return items

def ensure_product_images(product_id: int, sku: str):
    """Upload placeholder image only if product has no images. Alt text = SKU."""
    if not PLACEHOLDER_IMAGE_URL:
        return
    # get product to check images
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
    v = vendor.strip() or DEFAULT_VENDOR
    t = f"{v} - {title} | {sku} | AllSupermoto AS"
    d = (description or DEFAULT_SEO_DESC or "").strip()
    # Shopify 2024-10 supports seo keys directly on product
    return {"seo": {"title": t[:70], "description": d[:320]}}

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
        # fetch inventory_item_id
        r2 = shopify_request("GET", f"/variants/{variant_id}.json", params={"fields": "id,inventory_item_id"})
        if r2.status_code == 200:
            inv_item_id = r2.json().get("variant", {}).get("inventory_item_id")
            if inv_item_id:
                # set available quantity
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

def create_product(item: Dict[str, Any]) -> Optional[Tuple[int, int]]:
    vendor = item.get("vendor") or DEFAULT_VENDOR
    product_payload: Dict[str, Any] = {
        "product": {
            "title": item["title"] or item["sku"],
            "vendor": vendor,
            "status": "active",
            "body_html": html.escape(item.get("description") or ""),
            **build_seo(vendor, item["title"] or item["sku"], item["sku"], item.get("description")),
            "variants": [{
                "sku": item["sku"],
                "price": round(item["price"], 2),
                **({"compare_at_price": round(item["compare_at"], 2)} if item.get("compare_at") else {}),
                "inventory_management": "shopify",
            }],
        }
    }
    r = shopify_request("POST", "/products.json", payload=product_payload)
    if r.status_code not in (200, 201):
        logging.warning(f"CREATE PRODUCT: HTTP {r.status_code} {r.text[:300]}")
        return None
    prod = r.json().get("product", {})
    pid = int(prod["id"])
    vid = int(prod["variants"][0]["id"])

    # inventory
    update_variant_price_stock(vid, item["price"], item.get("compare_at"), item.get("available", 0))

    # image (placeholder only if none)
    ensure_product_images(pid, item["sku"])

    # cache
    SKU_CACHE[item["sku"]] = (pid, vid)
    return (pid, vid)

def update_product(product_id: int, variant_id: int, item: Dict[str, Any]):
    vendor = item.get("vendor") or DEFAULT_VENDOR
    # product updates (title, vendor, seo, description)
    product_payload: Dict[str, Any] = {
        "product": {
            "id": product_id,
            "title": item["title"] or item["sku"],
            "vendor": vendor,
            "body_html": html.escape(item.get("description") or ""),
            **build_seo(vendor, item["title"] or item["sku"], item["sku"], item.get("description")),
        }
    }
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
STATS = {"queued": 0, "updated": 0, "created": 0, "skipped_noop": 0, "skipped_cache_miss": 0, "dropped": 0}
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
                if STRICT_UPDATE_ONLY or not ALLOW_CREATE:
                    STATS["skipped_cache_miss"] += 1
                    continue
                created = create_product(item)
                if created:
                    STATS["created"] += 1
                else:
                    STATS["skipped_noop"] += 1
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

# -----------------------------------------------------------------------------
# Admin endpoints
# -----------------------------------------------------------------------------
@app.route("/admin/health", methods=["GET"])
def health():
    return jsonify({
        "ok": True,
        "cache_size": len(SKU_CACHE),
        "strict_update_only": STRICT_UPDATE_ONLY,
        "allow_create": ALLOW_CREATE,
        "preload_cache": PRELOAD_SKU_CACHE,
        "kill_switch": KILL_SWITCH,
        "queued": STATS["queued"],
        "updated": STATS["updated"],
        "created": STATS["created"],
        "skipped_noop": STATS["skipped_noop"],
        "skipped_cache_miss": STATS["skipped_cache_miss"],
        "dropped": STATS["dropped"],
        "workers": len(WORKERS),
        "queue_size": WORK_Q.qsize(),
        "max_queue_size": MAX_QUEUE_SIZE,
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
        # body is hex-encoded string; decode to bytes then to text
        try:
            hex_str = raw.decode("latin-1").strip()
            data = bytes.fromhex(hex_str)
            # UM often uses cp1252
            try:
                return data.decode("cp1252", errors="replace")
            except:
                return data.decode("utf-8", errors="replace")
        except Exception as e:
            logging.warning(f"HEX decode failed: {e}")
            return raw.decode("utf-8", errors="replace")
    else:
        # assume text already
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

    # Parse and queue
    items = parse_um_xml(text)
    added = enqueue_items(items)

    qs = request.args.to_dict(flat=True)
    last_flag = (qs.get("last", "") or "").lower() == "true"
    total = qs.get("total")
    sessionid = qs.get("sessionid")

    logging.info(f"BATCH: queued {added}/{len(items)} items | queue={WORK_Q.qsize()}/{MAX_QUEUE_SIZE} | last={last_flag} total={total} session={sessionid}")

    # If ACK-first mode, return immediately; workers will continue
    # This avoids UM UI timeouts/freezes on very large uploads.
    return ok_txt("OK")

# Explicitly stop any deleteproduct attempts (we don't support it)
@app.route("/twinxml/postdeleteproduct.asp", methods=["POST", "GET"])
def postdeleteproduct():
    logging.warning("DELETEPRODUCT received -> telling UM to stop (feature disabled).")
    return ok_txt("STOP")

# Some UM variants use different path names; catch-all that rejects deletes safely.
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
def boot():
    logging.info(f"Shopify domain: {SHOPIFY_DOMAIN} | API ver: {SHOPIFY_API_VER}")
    if PRELOAD_SKU_CACHE:
        try:
            warm_sku_cache()
        except Exception as e:
            logging.warning(f"CACHE WARMUP failed: {e}")
    else:
        log_cache_size("Startup (no warmup). Current SKU cache")
    start_workers(WORKER_THREADS)

if __name__ == "__main__":
    boot()
    port = int(os.environ.get("PORT", "10000"))
    app.run(host="0.0.0.0", port=port, threaded=True)
