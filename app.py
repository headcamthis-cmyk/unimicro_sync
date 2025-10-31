# app.py
import os
import logging
import sqlite3
import json
from datetime import datetime, timezone
from flask import Flask, request, Response, stream_with_context
import xml.etree.ElementTree as ET
import requests
import re
import base64
import binascii
import time
import random

APP_NAME = "uni-shopify-sync"
PORT = int(os.environ.get("PORT", "10000"))

# ---------- Uni auth ----------
UNI_USER = os.environ.get("UNI_USER", "synall")
UNI_PASS = os.environ.get("UNI_PASS", "synall")

# ---------- Admin key (optional) ----------
ADMIN_KEY = os.environ.get("ADMIN_KEY", "")

# ---------- Shopify ----------
SHOPIFY_DOMAIN = os.environ.get("SHOPIFY_DOMAIN", "allsupermotoas.myshopify.com")
SHOPIFY_TOKEN = os.environ.get("SHOPIFY_TOKEN")  # set in Render
SHOPIFY_API_VERSION = os.environ.get("SHOPIFY_API_VERSION", "2024-10")
SHOPIFY_LOCATION_ID = os.environ.get("SHOPIFY_LOCATION_ID", "16764928067")

# ---------- Pricing behavior ----------
UNI_PRICE_IS_NET = os.environ.get("UNI_PRICE_IS_NET", "true").lower() in ("1", "true", "yes")
VAT_RATE = float(os.environ.get("VAT_RATE", "0.25"))  # 25% default

# ---------- COST behavior ----------
UNI_COST_IS_NET = os.environ.get("UNI_COST_IS_NET", "true").lower() in ("1", "true", "yes")

# ---------- Images ----------
ENABLE_IMAGE_UPLOAD = os.environ.get("ENABLE_IMAGE_UPLOAD", "false").lower() in ("1", "true", "yes")
PLACEHOLDER_IMAGE_URL = os.environ.get("PLACEHOLDER_IMAGE_URL") or os.environ.get("PLACEHOLDER_URL")
PLACEHOLDER_ALT = os.environ.get("PLACEHOLDER_ALT", "ASM placeholder")

# ---------- Create / Update strategy ----------
STRICT_UPDATE_ONLY = os.environ.get("STRICT_UPDATE_ONLY", "true").lower() in ("1", "true", "yes")
# FIND_EXISTING_MODE: "cache_only" | "cache_then_lookup"
FIND_EXISTING_MODE = os.environ.get("FIND_EXISTING_MODE")
if not FIND_EXISTING_MODE:
    FIND_EXISTING_MODE = "cache_only" if STRICT_UPDATE_ONLY else "cache_then_lookup"

# ---------- Canary / batch controls ----------
STOP_AFTER_N = int(os.environ.get("STOP_AFTER_N", "0"))  # 0 = no limit
DRY_RUN = os.environ.get("DRY_RUN", "false").lower() in ("1", "true", "yes")

# ---------- SEO defaults ----------
SEO_DEFAULT_TITLE_TEMPLATE = os.environ.get(
    "SEO_DEFAULT_TITLE_TEMPLATE",
    "{title} | {vendor} | {sku} – AllSupermoto AS"
)
SEO_DEFAULT_DESC_TEMPLATE = os.environ.get(
    "SEO_DEFAULT_DESC_TEMPLATE",
    "Kjøp {title} fra {vendor} hos AllSupermoto AS. Varenummer {sku}. Rask levering og god pris."
)

# ---------- Product description defaults ----------
# DEFAULT_BODY_MODE: one of: "missing" (default), "append", "replace"
DEFAULT_BODY_MODE = os.environ.get("DEFAULT_BODY_MODE", "missing").strip().lower()
DEFAULT_BODY_HTML = os.environ.get("DEFAULT_BODY_HTML", """
<p>Original del / tilbehør. Rask levering fra AllSupermoto AS (Stavanger).</p>
""".strip())

# ---------- Tag generation ----------
TAG_MAX = int(os.environ.get("TAG_MAX", "10"))
TAG_MIN_LEN = int(os.environ.get("TAG_MIN_LEN", "3"))
DEFAULT_STOPWORDS = "for,med,til,og,eller,den,det,et,en,av,på,i,mm,inkl,inch,sw,os,tdc,sae"
EXTRA_STOPWORDS = os.environ.get("TAG_STOPWORDS", "")
STOPWORDS = {w.strip().lower() for w in (DEFAULT_STOPWORDS + "," + EXTRA_STOPWORDS).split(",") if w.strip()}

# REST scan cap (only used if we allow scanning)
FIND_SKU_MAX_VARIANTS = int(os.environ.get("FIND_SKU_MAX_VARIANTS", "0"))  # default 0 (off) for speed

# ---------- DB ----------
DB_URL = os.environ.get("DB_URL", "sync.db")

# ---------- New runtime throttles / light mode ----------
LIGHT_MODE = os.environ.get("LIGHT_MODE", "false").lower() in ("1", "true", "yes")
STORE_RAW_XML = os.environ.get("STORE_RAW_XML", "true").lower() in ("1", "true", "yes")
LOG_SNIFF_FIELDS = os.environ.get("LOG_SNIFF_FIELDS", "false").lower() in ("1", "true", "yes")

# ---------- Hardcoded Kill Switch (no env) ----------
KILL_KEY = "asmstop2025"                 # change if you want
KILL_FILE = "/mnt/data/SYNC_KILLED"      # create this file to kill; delete to resume

def is_killed() -> bool:
    return os.path.exists(KILL_FILE)

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s: %(message)s")
log = logging.getLogger(APP_NAME)


# --- Auto-seed config ---
AUTO_SEED_CACHE_ON_START = (os.environ.get("AUTO_SEED_CACHE_ON_START","true").lower() in ("1","true","yes"))
AUTO_SEED_LIMIT = int(os.environ.get("AUTO_SEED_LIMIT","250"))           # per page, 250 max by Shopify
AUTO_SEED_FLUSH_EVERY = int(os.environ.get("AUTO_SEED_FLUSH_EVERY","500"))
AUTO_SEED_RESUME = (os.environ.get("AUTO_SEED_RESUME","true").lower() in ("1","true","yes"))
AUTO_SEED_DELAY = float(os.environ.get("AUTO_SEED_DELAY","2.0"))         # seconds before starting after import
app = Flask(__name__)
_init_limit_tables()
app.url_map.strict_slashes = False

# ---- normalize '//' in PATH
class DoubleSlashFix:
    def __init__(self, app): self.app = app
    def __call__(self, environ, start_response):
        p = environ.get("PATH_INFO", "/")
        if "//" in p: environ["PATH_INFO"] = p.replace("//", "/")
        return self.app(environ, start_response)
app.wsgi_app = DoubleSlashFix(app.wsgi_app)

# ---------- DB helpers ----------
def db():
    conn = sqlite3.connect(DB_URL)
    conn.row_factory = sqlite3.Row
    return conn
# --- Session limit helpers ---
def _init_limit_tables():
    try:
        conn = db(); cur = conn.cursor()
        cur.execute("""CREATE TABLE IF NOT EXISTS run_limit(
            sessionid TEXT PRIMARY KEY,
            processed INTEGER NOT NULL DEFAULT 0
        )""")
        conn.commit(); conn.close()
    except Exception as e:
        logging.getLogger("limits").warning("Could not init run_limit table: %s", e)

def _get_processed_for_session(sessionid: str) -> int:
    conn = db(); cur = conn.cursor()
    row = cur.execute("SELECT processed FROM run_limit WHERE sessionid=?", (sessionid,)).fetchone()
    conn.close()
    return int(row["processed"]) if row and row["processed"] is not None else 0

def _bump_processed_for_session(sessionid: str, delta: int):
    conn = db(); cur = conn.cursor()
    cur.execute("""INSERT INTO run_limit(sessionid, processed) VALUES(?, ?)
                   ON CONFLICT(sessionid) DO UPDATE SET processed=run_limit.processed + excluded.processed""",
                (sessionid, int(delta)))
    conn.commit(); conn.close()


def init_db():
    conn = db(); c = conn.cursor()
    try:
        c.execute("PRAGMA journal_mode=WAL;")
        c.execute("PRAGMA synchronous=NORMAL;")
    except Exception:
        pass
    c.execute("""
    CREATE TABLE IF NOT EXISTS groups(
      groupid TEXT PRIMARY KEY, groupname TEXT, parentid TEXT,
      payload_xml TEXT, updated_at TEXT
    )""")
    c.execute("""
    CREATE TABLE IF NOT EXISTS products(
      prodid TEXT PRIMARY KEY, name TEXT, price REAL, vatcode TEXT,
      groupid TEXT, barcode TEXT, stock INTEGER, reserved INTEGER,
      body_html TEXT, image_b64 TEXT, webactive INTEGER, vendor TEXT,
      payload_xml TEXT,
      last_shopify_product_id TEXT, last_shopify_variant_id TEXT,
      last_inventory_item_id TEXT,
      last_compare_at_price REAL,
      last_tags TEXT,
      last_cost REAL,
      updated_at TEXT
    )""")
    c.execute("""
    CREATE TABLE IF NOT EXISTS logs(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      endpoint TEXT, method TEXT, query TEXT, body TEXT, created_at TEXT
    )""")
    for alter in [
        "ALTER TABLE products ADD COLUMN last_compare_at_price REAL",
        "ALTER TABLE products ADD COLUMN last_tags TEXT",
        "ALTER TABLE products ADD COLUMN reserved INTEGER",
        "ALTER TABLE products ADD COLUMN vendor TEXT",
        "ALTER TABLE products ADD COLUMN last_cost REAL",
    ]:
        try: c.execute(alter)
        except Exception: pass
    conn.commit(); conn.close()
init_db()

def ensure_logs_table(conn):
    conn.execute("""
    CREATE TABLE IF NOT EXISTS logs(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      endpoint TEXT, method TEXT, query TEXT, body TEXT, created_at TEXT
    )""")
    conn.commit()

def safe_log(endpoint: str, method: str, query: str, body: str):
    try:
        conn = db()
        ensure_logs_table(conn)
        conn.execute(
            "INSERT INTO logs(endpoint, method, query, body, created_at) VALUES (?,?,?,?,?)",
            (endpoint, method, query, body, now_iso())
        )
        conn.commit()
    except Exception as e:
        logging.warning("Skipping logs insert: %s", e)
    finally:
        try: conn.close()
        except: pass

# ---------- Utils ----------
def now_iso(): return datetime.now(timezone.utc).isoformat()

# Uni-vennlig OK med Connection: close + riktig length
def ok_txt(body="OK"):
    data = (body + "\r\n").encode("cp1252", errors="ignore")
    resp = Response(data, status=200, mimetype="text/plain; charset=windows-1252")
    resp.headers["Content-Length"] = str(len(data))
    resp.headers["Connection"] = "close"
    return resp

def require_auth(): return request.args.get("user")==UNI_USER and request.args.get("pass")==UNI_PASS
def require_admin():
    key = request.args.get("key", "")
    if ADMIN_KEY:
        return key == ADMIN_KEY
    return require_auth()

def read_xml_body():
    raw = request.get_data() or b""
    is_hex_param = (request.args.get("hex") or "").lower() in ("1","true","yes")
    if is_hex_param:
        try: raw = bytes.fromhex(raw.decode("ascii"))
        except Exception: pass
    for enc in ("utf-8","cp1252","latin-1","iso-8859-1"):
        try: return raw.decode(enc), is_hex_param
        except Exception: continue
    return raw.decode("utf-8","ignore"), is_hex_param

HEX_RE = re.compile(r"^[0-9a-fA-F]+$")

def maybe_hex_to_text(s: str) -> str:
    if not s: return s
    st = s.strip()
    if len(st) >= 2 and len(st) % 2 == 0 and HEX_RE.fullmatch(st) is not None:
        try:
            b = binascii.unhexlify(st)
            for enc in ("iso-8859-1","cp1252","utf-8"):
                try: return b.decode(enc)
                except Exception: continue
            return b.decode("utf-8","ignore")
        except Exception:
            return s
    return s

def to_float_safe(v):
    try: return float(str(v).replace(",", "."))
    except: return None

def to_int_safe(v):
    try: return int(v)
    except:
        try: return int(float(str(v).replace(",", ".")))
        except: return None

def clean_b64(data):
    if not data: return None
    s = data.strip()
    m = re.match(r"^data:image/[\w+.-]+;base64,(.*)$", s, flags=re.I|re.S)
    if m: s = m.group(1)
    s = re.sub(r"\s+","",s)
    try: base64.b64decode(s[:120] + "==", validate=False)
    except Exception: return None
    return s

def one_line(s: str | None) -> str | None:
    if not s: return None
    return re.sub(r"[\r\n]+", " ", str(s)).strip()

# ---------- Tag helpers ----------
def norm_tag(tag: str) -> str:
    return (tag.split('}', 1)[-1] if '}' in tag else tag).lower()

def node_text_or_attr(node: ET.Element) -> str:
    txt = (getattr(node, "text", "") or "").strip()
    if txt:
        return txt
    for k in ("value","val","text","t"):
        v = node.attrib.get(k)
        if v and v.strip():
            return v.strip()
    return ""

def findtext_ci_direct(elem: ET.Element, names):
    wanted=[]
    for n in names:
        n=n.strip().lower()
        wanted.append((n[:-1], True) if n.endswith('*') else (n, False))
    for child in list(elem):
        t = norm_tag(child.tag)
        for base, pref in wanted:
            if (t.startswith(base) if pref else t == base):
                v = node_text_or_attr(child)
                if v:
                    return v
    return ""

def findtext_ci_any(elem: ET.Element, names):
    wanted=[]
    for n in names:
        n=n.strip().lower()
        wanted.append((n[:-1], True) if n.endswith('*') else (n, False))
    for node in elem.iter():
        t = norm_tag(getattr(node, "tag", ""))
        for base, pref in wanted:
            if (t.startswith(base) if pref else t == base):
                v = node_text_or_attr(node)
                if v:
                    return v
    return ""

def extract_title(p: ET.Element, sku: str) -> str:
    title = findtext_ci_direct(p, [
        "description","descrip*","name","title","productname",
        "varenavn","varenavn1","varenavn2","varenavn3","name1"
    ]) or findtext_ci_any(p, [
        "description","descrip*","name","title","productname",
        "varenavn","varenavn1","varenavn2","varenavn3","name1"
    ])
    if not title:
        alt01 = findtext_ci_any(p, ["alt01"]) or ""
        alt07 = findtext_ci_any(p, ["alt07"]) or ""
        title = alt01 or alt07 or sku
    return title

def extract_best_price(p: ET.Element):
    priority = [
        "webprice","price_incl_vat","salesprice","pris1","price","pris",
        "ordinaryprice","pris2","newprice","netprice"
    ]
    found = {}
    any_first = None
    for node in p.iter():
        t = norm_tag(getattr(node,"tag",""))
        if ("price" in t) or ("pris" in t):
            val = to_float_safe(node_text_or_attr(node))
            if val is not None:
                if not any_first:
                    any_first = (val, t)
                found[t] = val if t not in found else found[t]
    for key in priority:
        for t,v in found.items():
            if t == key:
                return v, t
    return (any_first if any_first else (None, None))

def extract_cost(p: ET.Element):
    candidates = [
        "cost", "costprice", "purchaseprice", "purchase_price",
        "innkjøpspris", "innkjopspris", "innpris", "innkjøp", "innkjop",
        "dealerprice", "purchase", "kostpris", "kost", "inn_kost",
        "cost_net", "costnett", "kost_netto", "net_cost"
    ]
    incl_vat_candidates = [
        "cost_incl_vat", "kost_inkl_mva", "costinclvat", "purchaseprice_incl_vat"
    ]
    found = {}
    for node in p.iter():
        t = norm_tag(getattr(node, "tag", ""))
        v = to_float_safe(node_text_or_attr(node))
        if v is None: continue
        if t in candidates and t not in found:
            found[t] = v
    if found:
        for t in candidates:
            if t in found:
                val = found[t]
                return (val if UNI_COST_IS_NET else round(val / (1.0 + VAT_RATE), 4), t)
    for node in p.iter():
        t = norm_tag(getattr(node, "tag", ""))
        v = to_float_safe(node_text_or_attr(node))
        if v is None: continue
        if t in incl_vat_candidates:
            net = round(v / (1.0 + VAT_RATE), 4)
            return (net, t)
    return (None, None)

def slugify_simple(s: str) -> str:
    s = (s or "").strip().lower()
    s = re.sub(r"[^a-z0-9\s\-_/]", "", s)
    s = re.sub(r"[\s/]+", "-", s)
    s = re.sub(r"-+", "-", s)
    return s.strip("-_")

def generate_tags(title: str, vendor: str, group_id: str, group_name: str, sku: str, ean: str) -> list[str]:
    tags = []
    if vendor: tags.append(vendor.strip())
    if group_id: tags.append(f"group-{group_id.strip()}")
    if group_name:
        gn = slugify_simple(group_name)
        if gn and len(gn) >= TAG_MIN_LEN:
            tags.append(gn)
    if sku: tags.append(sku.strip())
    if ean: tags.append(ean.strip())
    raw_tokens = re.split(r"[\s\-/_,.;:()\[\]]+", title or "")
    for tok in raw_tokens:
        t = tok.strip()
        if not t: continue
        low = t.lower()
        if low in STOPWORDS: continue
        if len(low) < TAG_MIN_LEN and not re.fullmatch(r"[A-Z0-9]{2,6}", t): continue
        if re.fullmatch(r"\d{1,2}(mm|cm|inch|in)$", low):
            tags.append(low); continue
        if len(low) >= TAG_MIN_LEN or re.fullmatch(r"[A-Z0-9]{2,6}", t):
            tags.append(low)
    seen=set(); final=[]
    for t in tags:
        k=t.lower()
        if k in seen: continue
        seen.add(k); final.append(t)
        if len(final) >= TAG_MAX: break
    return final

# ---------- Shopify rate limit + retry wrapper ----------
SESSION = requests.Session()
LAST_CALL_TS = 0.0
QPS = float(os.environ.get("QPS", "1.6"))
MIN_INTERVAL = 1.0 / max(QPS, 0.1)
MAX_RETRIES = int(os.environ.get("RETRY_MAX", "6"))

def _pre_sleep():
    global LAST_CALL_TS
    now = time.time()
    wait = LAST_CALL_TS + MIN_INTERVAL - now
    if wait > 0:
        time.sleep(wait)

def _post_mark():
    global LAST_CALL_TS
    LAST_CALL_TS = time.time()

def shopify_base():
    return f"https://{SHOPIFY_DOMAIN}/admin/api/{SHOPIFY_API_VERSION}"

def sh_headers():
    if not SHOPIFY_TOKEN: raise RuntimeError("SHOPIFY_TOKEN not set")
    return {
        "X-Shopify-Access-Token": SHOPIFY_TOKEN,
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Connection": "keep-alive",
    }

def shopify_request(method: str, path: str, **kwargs) -> requests.Response:
    url = f"{shopify_base()}{path}"
    headers = kwargs.pop("headers", {})
    headers.update(sh_headers())
    backoff = 0.6  # base seconds

    for attempt in range(1, MAX_RETRIES + 1):
        _pre_sleep()
        resp = SESSION.request(method.upper(), url, headers=headers, timeout=60, **kwargs)
        _post_mark()

        cl = resp.headers.get("X-Shopify-Shop-Api-Call-Limit")
        if cl:
            try:
                used, cap = map(int, cl.split("/"))
                if used >= cap - 5:
                    time.sleep(1.2 + random.uniform(0, 0.3))
            except Exception:
                pass

        if resp.status_code < 400:
            return resp

        if resp.status_code == 429:
            ra = resp.headers.get("Retry-After")
            if ra:
                try: sleep_s = float(ra)
                except ValueError: sleep_s = 1.0
            else:
                sleep_s = min(10.0, backoff * (2 ** (attempt - 1))) + random.uniform(0, 0.4)
            logging.warning("429 rate limit. Sleeping %.2fs (attempt %d/%d)", sleep_s, attempt, MAX_RETRIES)
            time.sleep(sleep_s); continue

        if 500 <= resp.status_code < 600:
            sleep_s = min(10.0, backoff * (2 ** (attempt - 1))) + random.uniform(0, 0.4)
            logging.warning("Shopify %s. Sleeping %.2fs (attempt %d/%d)", resp.status_code, sleep_s, attempt, MAX_RETRIES)
            time.sleep(sleep_s); continue

        return resp

    return resp

def shopify_graphql(payload: dict) -> requests.Response:
    url = f"{shopify_base()}/graphql.json"
    headers = sh_headers()
    _pre_sleep()
    resp = SESSION.post(url, headers=headers, data=json.dumps(payload), timeout=60)
    _post_mark()
    return resp

def parse_gid(gid: str, kind: str) -> int | None:
    if not gid: return None
    m = re.match(rf"^gid://shopify/{re.escape(kind)}/(\d+)$", str(gid))
    return int(m.group(1)) if m else None



def _i0(x):
    try:
        return int(x)
    except Exception:
        return 0
def shopify_get_product(pid: int):
    r = shopify_request("GET", f"/products/{pid}.json")
    if r.status_code != 200:
        raise RuntimeError(f"get product {r.status_code}: {r.text[:200]}")
    return r.json()["product"]

def shopify_product_images(pid: int):
    r = shopify_request("GET", f"/products/{pid}/images.json")
    if r.status_code != 200:
        raise RuntimeError(f"images {r.status_code}: {r.text[:200]}")
    return r.json().get("images", [])

def shopify_add_placeholder_image(pid: int):
    if not ENABLE_IMAGE_UPLOAD or not PLACEHOLDER_IMAGE_URL:
        return
    try:
        imgs = shopify_product_images(pid)
        if imgs:
            # any image exists -> skip placeholder
            for img in imgs:
                alt = (img.get("alt") or "").lower()
                if PLACEHOLDER_ALT.lower() in alt:
                    return
            return
        body = {"image": {"src": PLACEHOLDER_IMAGE_URL, "position": 1, "alt": (sku or PLACEHOLDER_ALT)}}
        r = shopify_request("POST", f"/products/{pid}/images.json", data=json.dumps(body))
        if r.status_code not in (200, 201):
            logging.warning("Placeholder image upload failed for %s: %s %s", pid, r.status_code, r.text[:200])
        else:
            logging.info("Placeholder image attached to product %s", pid)
    except Exception as e:
        logging.warning("Placeholder image attach error for %s: %s", pid, e)

def shopify_create_product(p):
    if DRY_RUN:
        logging.info("[DRY_RUN] Would CREATE product with title=%r", p.get("title"))
        return {"id": 0, "variants": [{"id": 0, "inventory_item_id": 0}]}
    r = shopify_request("POST", f"/products.json", data=json.dumps({"product":p}))
    if r.status_code not in (200,201): raise RuntimeError(f"create {r.status_code}: {r.text[:300]}")
    return r.json()["product"]

def shopify_update_product(pid, p):
    if DRY_RUN:
        logging.info("[DRY_RUN] Would UPDATE product_id=%s", pid)
        return {"id": pid}
    r = shopify_request("PUT", f"/products/{pid}.json", data=json.dumps({"product":p}))
    if r.status_code not in (200,201): raise RuntimeError(f"update {r.status_code}: {r.text[:300]}")
    return r.json()["product"]

def shopify_update_variant(vid, payload):
    if DRY_RUN:
        logging.info("[DRY_RUN] Would UPDATE variant_id=%s payload=%s", vid, payload)
        return {"id": vid}
    body = {"variant": {"id": int(vid), **payload}}
    r = shopify_request("PUT", f"/variants/{vid}.json", data=json.dumps(body))
    if r.status_code not in (200,201): raise RuntimeError(f"variant {r.status_code}: {r.text[:300]}")
    return r.json()["variant"]

def shopify_set_inventory(iid, qty):
    if DRY_RUN:
        logging.info("[DRY_RUN] Would SET inventory iid=%s available=%s", iid, qty)
        return {"inventory_level": {"available": qty}}
    body = {"location_id": int(SHOPIFY_LOCATION_ID), "inventory_item_id": int(iid), "available": int(qty or 0)}
    r = shopify_request("POST", f"/inventory_levels/set.json", data=json.dumps(body))
    if r.status_code not in (200,201): raise RuntimeError(f"inventory {r.status_code}: {r.text[:300]}")
    return r.json()

def ensure_tracking_and_set_inventory(vid, iid, qty):
    try:
        shopify_set_inventory(iid, qty); return
    except Exception as e:
        if "tracking" not in str(e).lower() and "does not have inventory tracking enabled" not in str(e):
            raise
    shopify_update_variant(vid, {"inventory_management":"shopify", "inventory_policy":"deny", "requires_shipping":True})
    shopify_set_inventory(iid, qty)

# ---- Inventory Item cost (robust)
def shopify_update_inventory_cost(iid: int, cost: float):
    """
    Update InventoryItem cost ("Cost per item") and verify it.
    Tries REST first; if the value doesn't persist, falls back to GraphQL.
    Requires token scopes: write_inventory (+ read_inventory to verify).
    """
    if iid is None or cost is None:
        return

    body = {"inventory_item": {"id": int(iid), "cost": f"{float(cost):.2f}"}}
    if DRY_RUN:
        logging.info("[DRY_RUN] Would UPDATE inventory_item cost iid=%s cost=%s", iid, body["inventory_item"]["cost"])
        return

    r = shopify_request("PUT", f"/inventory_items/{int(iid)}.json", data=json.dumps(body))
    if r.status_code in (200, 201):
        try:
            g = shopify_request("GET", f"/inventory_items/{int(iid)}.json")
            if g.status_code == 200:
                got = ((g.json() or {}).get("inventory_item") or {}).get("cost")
                if got is not None and str(got) == f"{float(cost):.2f}":
                    logging.info("InventoryItem %s cost verified at %s", iid, got)
                    return
                else:
                    logging.warning("InventoryItem %s cost not verified (got=%r, want=%s). Trying GraphQL.",
                                    iid, got, f"{float(cost):.2f}")
        except Exception as e:
            logging.warning("InventoryItem %s cost verify failed: %s. Trying GraphQL.", iid, e)
    else:
        if r.status_code in (401, 403):
            logging.error("InventoryItem cost update forbidden (HTTP %s). Check token has write_inventory.", r.status_code)
        else:
            logging.warning("InventoryItem cost update via REST failed %s: %s", r.status_code, r.text[:200])

    # GraphQL fallback
    try:
        gid = f"gid://shopify/InventoryItem/{int(iid)}"
        gql = {
            "query": """
              mutation InvItemCost($id: ID!, $cost: Float!) {
                inventoryItemUpdate(id: $id, input: { cost: $cost }) {
                  inventoryItem { id unitCost { amount } }
                  userErrors { field message }
                }
              }
            """,
            "variables": {"id": gid, "cost": float(cost)}
        }
        resp = shopify_graphql(gql)
        if resp.status_code == 200:
            data = resp.json() or {}
            errs = (((data.get("data") or {}).get("inventoryItemUpdate") or {}).get("userErrors") or [])
            if errs:
                logging.warning("GraphQL inventoryItemUpdate userErrors for iid=%s: %s", iid, errs)
            else:
                amt = (((data.get("data") or {}).get("inventoryItemUpdate") or {})
                       .get("inventoryItem") or {}).get("unitCost", {}).get("amount")
                logging.info("InventoryItem %s cost set via GraphQL to %s", iid, amt)
        else:
            logging.warning("GraphQL inventoryItemUpdate HTTP %s: %s", resp.status_code, resp.text[:200])
    except Exception as e:
        logging.error("GraphQL inventoryItemUpdate failed for iid=%s: %s", iid, e)

def shopify_upsert_product_metafields(pid: int, meta: dict):
    if not meta or LIGHT_MODE:  # gated in light mode
        return
    try:
        for key, val in meta.items():
            if val is None or val == "": continue
            body = {"metafield": {
                "namespace": "uni", "key": key, "value": str(val), "type": "single_line_text_field"
            }}
            if DRY_RUN:
                logging.info("[DRY_RUN] Would UPSERT metafield %s=%r for product %s", key, val, pid)
                continue
            shopify_request("POST", f"/products/{int(pid)}/metafields.json", data=json.dumps(body))
    except Exception as e:
        log.warning("Metafields upsert failed for product %s: %s", pid, e)

def shopify_set_seo(pid: int, title: str | None = None, desc: str | None = None):
    if LIGHT_MODE:  # gated in light mode
        return
    try:
        for key, val in (("title_tag", title), ("description_tag", desc)):
            val = one_line(val)
            if not val: continue
            body = {"metafield": {
                "namespace": "global", "key": key, "type": "single_line_text_field", "value": val
            }}
            if DRY_RUN:
                logging.info("[DRY_RUN] Would SET SEO %s for product %s -> %r", key, pid, val)
                continue
            shopify_request("POST", f"/products/{int(pid)}/metafields.json", data=json.dumps(body))
    except Exception as e:
        log.warning("SEO metafields failed for product %s: %s", pid, e)

# ---------- SKU lookup ----------
def shopify_find_variant_by_sku(sku):
    """
    Optimized lookup:
    - Always try local cache first (O(1)).
    - If FIND_EXISTING_MODE == 'cache_only': return None if not cached (fast path).
    - If FIND_EXISTING_MODE == 'cache_then_lookup': try GraphQL, then variants?sku=, (optional) scan.
    """
    target = (sku or "").strip()
    if not target:
        return None

    # 0) Local cache first
    try:
        conn = db()
        row = conn.execute(
            "SELECT last_shopify_product_id, last_shopify_variant_id, last_inventory_item_id "
            "FROM products WHERE prodid=?", (target,)
        ).fetchone()
        conn.close()
        if row and row["last_shopify_variant_id"]:
            return {
                "id": int(row["last_shopify_variant_id"]),
                "product_id": int(row["last_shopify_product_id"]) if row["last_shopify_product_id"] else None,
                "inventory_item_id": int(row["last_inventory_item_id"]) if row["last_inventory_item_id"] else None,
                "sku": target
            }
    except Exception as e:
        logging.warning("Local SKU cache lookup failed for %r: %s", target, e)

    # Fast exit for speed if STRICT_UPDATE_ONLY / cache_only
    if FIND_EXISTING_MODE == "cache_only":
        return None

    # 1) GraphQL exact query (2 tries)
    for attempt in range(2):
        try:
            query = """
            query ($q: String!) {
              productVariants(first: 1, query: $q) {
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
            payload = {"query": query, "variables": {"q": f"sku:{target}"}}
            r = shopify_graphql(payload)
            if r.status_code == 200:
                data = r.json()
                edges = (((data or {}).get("data") or {}).get("productVariants") or {}).get("edges", [])
                if edges:
                    node = (edges[0] or {}).get("node") or {}
                    if (node.get("sku") or "").strip() == target:
                        vid = parse_gid(node.get("id"), "ProductVariant")
                        pid = parse_gid(((node.get("product") or {}).get("id")), "Product")
                        iid = parse_gid(((node.get("inventoryItem") or {}).get("id")), "InventoryItem")
                        if vid and pid:
                            return {"id": vid, "product_id": pid, "inventory_item_id": iid, "sku": target}
                else:
                    logging.warning("GraphQL lookup: 200 OK but empty for SKU %r (attempt %d)", target, attempt+1)
            else:
                logging.warning("GraphQL lookup failed for %r: %s %s", target, r.status_code, r.text[:200])
                if r.status_code in (401,403):
                    break
        except Exception as e:
            logging.warning("GraphQL error for %r (attempt %d): %s", target, attempt+1, e)

    # 2) REST ?sku= (can be flaky, but cheap)
    try:
        r = shopify_request("GET", f"/variants.json", params={"sku": target, "limit": 250})
        if r.status_code == 200:
            arr = r.json().get("variants", [])
            for v in arr:
                if (v.get("sku") or "").strip() == target:
                    return v
            if arr:
                logging.warning("Shopify ignored ?sku= for %r; scan disabled unless FIND_SKU_MAX_VARIANTS>0", target)
        else:
            logging.warning("variants.json?sku=… returned %s: %s", r.status_code, r.text[:200])
    except Exception as e:
        logging.warning("SKU filtered lookup failed for %r: %s", target, e)

    # 3) Full scan (usually off for speed)
    max_scan = FIND_SKU_MAX_VARIANTS
    if max_scan and max_scan > 0:
        scanned = 0
        since_id = 0
        while scanned < max_scan:
            try:
                r = shopify_request("GET", f"/variants.json", params={"since_id": since_id, "limit": 250})
                if r.status_code != 200:
                    logging.warning("variants scan stopped (status %s): %s", r.status_code, r.text[:200])
                    break
                arr = r.json().get("variants", [])
                if not arr:
                    break
                for v in arr:
                    scanned += 1
                    if (v.get("sku") or "").strip() == target:
                        return v
                since_id = arr[-1]["id"]
            except Exception as e:
                logging.warning("variants scan error after %d scanned: %s", scanned, e)
                break
        logging.info("SKU %r not found after scanning %d variants.", target, scanned)

    return None

# ---------- Request logging ----------
@app.before_request
def _log_req():
    try:
        ref = request.headers.get("Referer", "-")
        log.info("REQ %s %s?%s  Referer=%s", request.method, request.path,
                 request.query_string.decode(errors="ignore"), ref)
    except Exception:
        pass

# ---------- Global Kill: short-circuit everything except admin ----------
@app.before_request
def _kill_guard():
    # allow admin endpoints even when killed
    if request.path.startswith("/admin"):
        return None
    if is_killed():
        return Response(b"STOPPED\r\n", status=503, mimetype="text/plain; charset=windows-1252")

# ---------- Health ----------
@app.route("/", methods=["GET"])
def index(): return ok_txt("OK")

# ---------- status/orders/productlist ----------
@app.route("/twinxml/status.asp", methods=["GET","POST","HEAD"])
def status_asp():
    lastupdate = request.args.get("lastupdate", "")
    xml = ('<?xml version="1.0" encoding="ISO-8859-1"?>'
           "<Root><OK>OK</OK><shopname>ASM Shopify</shopname>"
           "<supportsimages>1</supportsimages>"
           "<supportscustomers>1</supportscustomers>"
           "<supportsorders>1</supportsorders>"
           "<supportsstock>1</supportsstock>"
           "<supportsproducts>1</supportsproducts>"
           "<supportsproductgroups>1</supportsproductgroups>"
           # IMPORTANT: tell Uni we DO NOT support deletes
           "<supportsdeletes>0</supportsdeletes>"
           f"<echo_lastupdate>{lastupdate}</echo_lastupdate></Root>")
    resp = Response(xml, status=200)
    resp.headers["Content-Type"] = "text/xml; charset=ISO-8859-1"
    resp.headers["Connection"] = "close"
    return resp

@app.route("/twinxml/orders.asp", methods=["GET","POST","HEAD"])
def orders_asp():
    xml = '<?xml version="1.0" encoding="ISO-8859-1"?><Root><orders count="0"></orders></Root>'
    return Response(xml, mimetype="text/xml; charset=ISO-8859-1")

@app.route("/twinxml/singleorder.asp", methods=["GET","POST","HEAD"])
def singleorder_asp():
    xml = '<?xml version="1.0" encoding="ISO-8859-1"?><Root><order/></Root>'
    return Response(xml, mimetype="text/xml; charset=ISO-8859-1")

@app.route("/twinxml/productlist.asp", methods=["GET","POST","HEAD"])
def productlist_asp():
    xml = '<?xml version="1.0" encoding="ISO-8859-1"?><Root><OK>OK</OK><products count="0"></products></Root>'
    return Response(xml, mimetype="text/xml; charset=ISO-8859-1")

# ---------- misc stubs ----------
@app.route("/twinxml/postfiles.asp", methods=["GET","POST","HEAD"])
def postfiles_asp():
    return ok_txt("OK")

@app.route("/twinxml/postdiscountsystem.asp", methods=["GET","POST","HEAD"])
def postdiscountsystem_asp():
    return ok_txt("OK")

@app.route("/twinxml/deletetable.asp", methods=["GET","POST","HEAD"])
def deletetable_asp():
    name = (request.args.get("name") or "").lower()
    logging.info("Uni requested deletetable for: %s", name)
    # Do not encourage delete flows; just acknowledge
    return ok_txt("OK")

@app.route("/twinxml/postdiscount.asp", methods=["GET","POST","HEAD"])
@app.route("/twinxml/postdiscount.aspx", methods=["GET","POST","HEAD"])
def postdiscount_asp():
    return post_product()

# ---------- product groups (return literal "true") ----------
def uni_groups_ok():
    if hit_limit:
        return ok_txt("OK")
    body = b"true"
    resp = Response(body, status=200, mimetype="text/plain; charset=windows-1252")
    resp.headers["Content-Length"] = str(len(body))
    resp.headers["Connection"] = "close"
    return resp

@app.route("/twinxml/postproductgroup.asp", methods=["GET","POST"])
@app.route("/twinxml/postproductgroup.aspx", methods=["GET","POST"])
def post_product_group():
    safe_log("/twinxml/postproductgroup",
             request.method,
             request.query_string.decode("utf-8","ignore"),
             (request.data or b"").decode("utf-8","ignore"))

    if request.method == "GET":
        return uni_groups_ok()

    raw, _ = read_xml_body()
    try:
        root = ET.fromstring(raw)
    except Exception as e:
        log.warning("Bad XML groups: %s ... first200=%r", e, raw[:200])
        return uni_groups_ok()

    count = 0
    conn = db()
    groups = root.findall(".//productgroup") or root.findall(".//group") or root.findall(".//gruppe") or root.findall(".//varegruppe")
    for g in groups:
        gid   = (g.findtext("groupno") or g.findtext("groupid") or g.findtext("id") or g.findtext("gruppeid") or g.findtext("grpid") or "").strip()
        gname = (g.findtext("description") or g.findtext("groupname") or g.findtext("name") or g.findtext("gruppenavn") or "").strip()
        parent= (g.findtext("parentgroup") or g.findtext("parentid") or g.findtext("parent") or g.findtext("overgruppeid") or "").strip()
        if not gid: continue
        conn.execute("""
            INSERT INTO groups(groupid, groupname, parentid, payload_xml, updated_at)
            VALUES(?,?,?,?,?)
            ON CONFLICT(groupid) DO UPDATE SET
              groupname=excluded.groupname,
              parentid=excluded.parentid,
              payload_xml=excluded.payload_xml,
              updated_at=excluded.updated_at
        """, (gid, gname, parent, (raw if STORE_RAW_XML else None), now_iso()))
        count += 1
    conn.commit(); conn.close()
    log.info("Stored %d groups", count)
    return uni_groups_ok()

# ---------- products ----------
@app.route("/twinxml/postproduct.asp", methods=["GET","POST"])
@app.route("/twinxml/postproduct.aspx", methods=["GET","POST"])
@app.route("/twinxml/postproducts.asp", methods=["GET","POST"])
@app.route("/twinxml/postproducts.aspx", methods=["GET","POST"])
@app.route("/twinxml/postallproducts.asp", methods=["GET","POST"])
@app.route("/twinxml/postallproducts.aspx", methods=["GET","POST"])
@app.route("/twinxml/postitems.asp", methods=["GET","POST"])
@app.route("/twinxml/postitems.aspx", methods=["GET","POST"])
@app.route("/twinxml/postprice.asp", methods=["GET","POST"])
@app.route("/twinxml/postprice.aspx", methods=["GET","POST"])
@app.route("/twinxml/postprices.asp", methods=["GET","POST"])
@app.route("/twinxml/postprices.aspx", methods=["GET","POST"])
@app.route("/twinxml/postinventory.asp", methods=["GET","POST"])
@app.route("/twinxml/postinventory.aspx", methods=["GET","POST"])
@app.route("/twinxml/poststock.asp", methods=["GET","POST"])
@app.route("/twinxml/poststock.aspx", methods=["GET","POST"])
def post_product():
    sessionid = request.args.get("sessionid") or request.args.get("sessionId") or ""
    current_total = _get_processed_for_session(sessionid) if (STOP_AFTER_N > 0 and sessionid) else 0
    if STOP_AFTER_N > 0 and sessionid and current_total >= STOP_AFTER_N:
        logging.getLogger("limits").info(f"Session {sessionid} already reached STOP_AFTER_N={STOP_AFTER_N} (total={current_total}). Returning OK.")
        return ok_txt("OK")
    if request.method == "GET":
        # Uni forventer "true" når den health-checker via GET i noen oppsett
        if hit_limit:
        return ok_txt("OK")
    body = b"true"
        resp = Response(body, status=200, mimetype="text/plain; charset=windows-1252")
        resp.headers["Content-Length"] = str(len(body))
        resp.headers["Connection"] = "close"
        return resp

    if not require_auth():
        if hit_limit:
        return ok_txt("OK")
    body = b"true"
        resp = Response(body, status=200, mimetype="text/plain; charset=windows-1252")
        resp.headers["Content-Length"] = str(len(body))
        resp.headers["Connection"] = "close"
        return resp

    raw, _ = read_xml_body()
    try:
        root = ET.fromstring(raw)
    except Exception as e:
        log.warning("Bad XML products: %s ... first200=%r", e, raw[:200])
        if hit_limit:
        return ok_txt("OK")
    body = b"true"
        resp = Response(body, status=200, mimetype="text/plain; charset=windows-1252")
        resp.headers["Content-Length"] = str(len(body))
        resp.headers["Connection"] = "close"
        return resp

    nodes = (root.findall(".//product") or root.findall(".//vare") or
             root.findall(".//item") or root.findall(".//produkt"))
    if not nodes:
        cands=[]; idtags=["productident","prodid","varenr","sku","itemno"]
        for elem in root.iter():
            ident = ""
            for t in idtags:
                v = elem.findtext(t)
                if v: ident = v.strip(); break
            if ident: cands.append(elem)
        nodes=cands

    conn = db(); c = conn.cursor()
    upserted=0; synced=0; processed=0; skipped_noops=0; skipped_cache_miss=0; hit_limit=False

    # Optional field sniff (light)
    if LOG_SNIFF_FIELDS:
        for i, probe in enumerate(nodes[:2]):
            snap = []
            for n in probe.iter():
                tag = norm_tag(getattr(n,"tag",""))
                val = node_text_or_attr(n)
                if val: snap.append(f"{tag}={val[:80]}")
            log.info("SNIFF[%d]: %s", i+1, "; ".join(snap[:25]))

    # Load groups map (for tag generation)
    group_map = {}
    try:
        cur = conn.cursor()
        for row in cur.execute("SELECT groupid, groupname FROM groups"):
            group_map[row["groupid"]] = row["groupname"]
    except Exception:
        pass

    for p in nodes:
        if STOP_AFTER_N > 0 and (processed + current_total) >= STOP_AFTER_N:
            log.info("STOP_AFTER_N reached (%d). Stopping early.", STOP_AFTER_N)
            hit_limit = True
            break
        processed += 1
            if STOP_AFTER_N > 0 and sessionid:
                _bump_processed_for_session(sessionid, 1)
            if STOP_AFTER_N > 0 and sessionid:
                _bump_processed_for_session(sessionid, 1)

        sku = (findtext_ci_any(p,["productident","prodid","varenr","sku","itemno"]) or "").strip()
        if not sku: continue

        # ---- Build intended state ----
        name  = extract_title(p, sku)
        name2 = (findtext_ci_any(p,["varenavn2","alt01"]) or "").strip()
        name3 = (findtext_ci_any(p,["varenavn3","alt07"]) or "").strip()
        full_title = (name + (" " + " ".join([t for t in [name2, name3] if t]) if (name2 or name3) else "")) or sku

        longdesc = (findtext_ci_any(p,["longdesc","longtext","description_long","desc","body_html","infohtml","produktbeskrivelse"]) or "")
        longdesc = maybe_hex_to_text(longdesc)

        if LIGHT_MODE:
            body_html = longdesc or ""  # keep light for speed/memory
        else:
            if DEFAULT_BODY_MODE == "replace":
                body_html = DEFAULT_BODY_HTML
            elif DEFAULT_BODY_MODE == "append":
                body_html = f"{longdesc}\n\n{DEFAULT_BODY_HTML}" if longdesc else DEFAULT_BODY_HTML
            else:
                body_html = longdesc or DEFAULT_BODY_HTML

        grp   = (findtext_ci_any(p,["productgroup","groupid","gruppeid","groupno","varegruppe"]) or "").strip()
        stock = to_int_safe(findtext_ci_any(p, ["quantityonhand","stock","quantity","qty","lager","onhand","antall"])) or 0
        reserved = to_int_safe(findtext_ci_any(p, ["reservert","reserved","committed","backorder"])) or 0
        available = max(0, int(stock) - int(reserved))

        price_raw, price_src = extract_best_price(p)
        def brutto(val):
            if val is None: return None
            return round(val * (1.0 + VAT_RATE), 2) if UNI_PRICE_IS_NET else round(val, 2)
        price = brutto(price_raw)

        ordinaryprice = to_float_safe(findtext_ci_any(p, ["ordinaryprice", "pris2"]))
        compare_at = None
        if ordinaryprice is not None:
            ordinaryprice = brutto(ordinaryprice)
            if price and ordinaryprice and ordinaryprice > price:
                compare_at = round(ordinaryprice, 2)

        vendor = (findtext_ci_any(p,["vendor","produsent","leverandor","leverandør","manufacturer","brand","supplier"]) or "").strip()
        ean = (findtext_ci_any(p,["ean","ean_nr","ean_nr.ean","alt02"]) or "").strip()

        cost_net, cost_src = extract_cost(p)

        img_b64  = findtext_ci_any(p,["image_b64","image","bilde_b64"]) or None
        if img_b64: img_b64 = clean_b64(img_b64)

        group_name = group_map.get(grp, "") if grp else ""

        if LIGHT_MODE:
            tags_list = []
            tags_csv = ""
        else:
            tags_list = generate_tags(full_title, vendor, grp, group_name, sku, ean)
            tags_csv = ",".join(tags_list) if tags_list else ""

        log.info(
            "PARSED sku=%s title=%r price=%s (src=%s) compare_at=%s stock=%s reserved=%s -> available=%s vendor=%r group=%r cost=%s (src=%s)",
            sku, full_title, price, price_src, compare_at, stock, reserved, available, vendor, grp, cost_net, cost_src
        )

        # ---- NO-OP detection ----
        prev = c.execute(
            "SELECT name, price, stock, reserved, body_html, vendor, last_compare_at_price, last_tags, last_cost, "
            "       last_shopify_product_id, last_shopify_variant_id, last_inventory_item_id, barcode "
            "  FROM products WHERE prodid=?",
            (sku,)
        ).fetchone()

        def f2(x): return None if x is None else round(float(x), 2)

        is_new = prev is None
        changed_title = is_new or (prev["name"] or "") != (full_title or "")
        changed_body  = is_new or (prev["body_html"] or "") != (body_html or "")
        changed_vendor= is_new or (prev["vendor"] or "") != (vendor or "")
        changed_price = is_new or f2(prev["price"]) != f2(price)
        changed_cmp   = is_new or f2(prev["last_compare_at_price"]) != f2(compare_at)
        changed_cost  = is_new or f2(prev["last_cost"]) != f2(cost_net)
        prev_avail = (max(0, _i0(prev["stock"]) - _i0(prev["reserved"])) if prev else None)
        changed_av  = is_new or int((prev_avail if prev_avail is not None else -1)) != int(available)
        changed_tags= is_new or (prev["last_tags"] or "") != (tags_csv or "")
        changed_bar = is_new or (prev["barcode"] or "") != (ean or "")

        needs_shopify = (changed_title or changed_body or changed_vendor or
                         changed_price or changed_cmp or changed_av or changed_tags or changed_cost or changed_bar)

        if not needs_shopify:
            skipped_noops += 1
            c.execute("UPDATE products SET updated_at=? WHERE prodid=?", (now_iso(), sku))
            conn.commit()
            log.info("NO-OP: sku=%s unchanged (incl. cost).", sku)
            continue

        # ---- Persist intended state ----
        c.execute("""
          INSERT INTO products(prodid,name,price,vatcode,groupid,barcode,stock,reserved,body_html,image_b64,webactive,vendor,payload_xml,
                               last_shopify_product_id,last_shopify_variant_id,last_inventory_item_id,last_compare_at_price,last_tags,last_cost,updated_at)
          VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
          ON CONFLICT(prodid) DO UPDATE SET
            name=excluded.name, price=excluded.price, groupid=excluded.groupid, stock=excluded.stock,
            reserved=excluded.reserved, body_html=excluded.body_html, image_b64=excluded.image_b64, vendor=excluded.vendor,
            payload_xml=excluded.payload_xml, last_compare_at_price=excluded.last_compare_at_price, last_tags=excluded.last_tags,
            last_cost=excluded.last_cost, updated_at=excluded.updated_at
        """,(sku,full_title,price,None,grp,ean,stock,reserved,body_html,img_b64,1,vendor,(raw if STORE_RAW_XML else None),
             prev["last_shopify_product_id"] if prev else None,
             prev["last_shopify_variant_id"] if prev else None,
             prev["last_inventory_item_id"] if prev else None,
             compare_at, tags_csv, cost_net, now_iso()))
        upserted += 1

        # ---------- Shopify: find existing ----------
        if not SHOPIFY_TOKEN:
            continue

        v = shopify_find_variant_by_sku(sku)
        if not v:
            if STRICT_UPDATE_ONLY:
                skipped_cache_miss += 1
                log.warning("STRICT_UPDATE_ONLY: SKU %r not found%s. Skipping.",
                            sku, " (cache-only mode)" if FIND_EXISTING_MODE=="cache_only" else "")
                continue
            log.warning("Create disabled; skipping SKU %r (not found).", sku)
            continue

        pid=v["product_id"]; vid=v["id"]; iid=v.get("inventory_item_id")

        # Flags (minimerer API-kall)
        do_product_update = (changed_title or changed_body or changed_vendor or ((not LIGHT_MODE) and changed_tags))
        do_variant_update = (changed_price or changed_cmp or changed_bar)
        do_inventory_set  = changed_av
        do_cost_update    = changed_cost and (cost_net is not None)

        # Product update
        if do_product_update:
            up={"id":pid,"title":full_title,"body_html":body_html or ""}
            if vendor: up["vendor"] = vendor
            if (not LIGHT_MODE) and tags_list: up["tags"] = ",".join(tags_list)
            shopify_update_product(pid, up)
            log.info("Shopify UPDATE OK sku=%s product_id=%s admin=https://%s/admin/products/%s",
                     sku, pid, SHOPIFY_DOMAIN, pid)

            # SEO (ikke i LIGHT_MODE)
            if not LIGHT_MODE and (changed_title or changed_vendor):
                final_vendor = (vendor or "Ukjent leverandør").strip() or "Ukjent leverandør"
                seo_title = SEO_DEFAULT_TITLE_TEMPLATE.format(title=full_title, sku=sku, vendor=final_vendor)
                seo_desc  = SEO_DEFAULT_DESC_TEMPLATE.format(title=full_title, sku=sku, vendor=final_vendor)
                shopify_set_seo(pid, seo_title, seo_desc)

            # Placeholder-bilde (ikke i LIGHT_MODE)
            if not LIGHT_MODE and ENABLE_IMAGE_UPLOAD and PLACEHOLDER_IMAGE_URL:
                try: shopify_add_placeholder_image(pid)
                except Exception as e: logging.warning("Placeholder attach on update failed for %s: %s", sku, e)

        # Variant (pris / compare_at / barcode)
        if do_variant_update and vid:
            vp = {"price": f"{(price or 0):.2f}", "sku": sku}
            if compare_at: vp["compare_at_price"] = f"{compare_at:.2f}"
            if ean: vp["barcode"] = ean
            shopify_update_variant(vid, vp)

        # Inventory (available = stock - reserved)
        if do_inventory_set and iid:
            try:
                ensure_tracking_and_set_inventory(vid, iid, available)
            except Exception as e:
                log.warning("Inventory set failed for %s: %s", sku, e)

        # Cost per item
        if do_cost_update and iid:
            try:
                shopify_update_inventory_cost(iid, float(cost_net))
            except Exception as e:
                log.warning("Cost update failed for %s (iid=%s): %s", sku, iid, e)

        # Cache IDs
        c.execute(
            "UPDATE products SET last_shopify_product_id=?, last_shopify_variant_id=?, last_inventory_item_id=?, "
            "last_compare_at_price=?, last_tags=?, last_cost=?, updated_at=? WHERE prodid=?",
            (pid, vid, iid, compare_at, tags_csv, cost_net, now_iso(), sku)
        )
        conn.commit()
        synced += 1

    conn.commit(); conn.close()
    log.info("Upserted %d products (Shopify updated %d, skipped no-ops %d, skipped cache-miss %d)",
             upserted, synced, skipped_noops, skipped_cache_miss)

    # --- Tell Uni whether to continue or stop ---
if hit_limit:
    return ok_txt("OK")

body = b"true"
resp = Response(body, status=200, mimetype="text/plain; charset=windows-1252")
resp.headers["Content-Length"] = str(len(body))
resp.headers["Connection"] = "close"
return resp

# --- Uni -> "delete product" (we ignore + do NOT return 'true') ---
@app.route("/twinxml/deleteproduct.asp", methods=["POST", "GET", "HEAD"])
def uni_delete_product():
    sku = (request.args.get("id") or "").strip()
    logging.info(f"UNI requested delete for %r — ignored (NO Shopify delete).", sku)
    # We return a plain OK (not 'true') so Uni doesn't treat this like a chained batch step.
    return ok_txt("OK")

# ---------- reset map ----------
@app.route("/twinxml/resetmap.asp", methods=["GET","POST"])
def resetmap():
    if not require_auth(): return ok_txt("OK")
    sku = (request.args.get("id") or "").strip()
    if not sku: return ok_txt("OK")
    conn = db()
    conn.execute("""
        UPDATE products
           SET last_shopify_product_id=NULL,
               last_shopify_variant_id=NULL,
               last_inventory_item_id=NULL
         WHERE prodid=?""", (sku,))
    conn.commit(); conn.close()
    return ok_txt("OK")

# ---------- Admin: streaming seed cache with resume ----------
@app.route("/admin/seed_cache", methods=["GET","POST"])
def admin_seed_cache():
    key = request.args.get("key","")
    if ADMIN_KEY and key != ADMIN_KEY:
        return Response(b"Forbidden\r\n", status=403, mimetype="text/plain")

    limit = int(request.args.get("limit", "250"))          # variants per page (250 max)
    flush_every = int(request.args.get("flush_every", "500"))
    resume = (request.args.get("resume", "1").lower() in ("1","true","yes"))

    def stream():
        conn = db(); cur = conn.cursor()
        try:
            since_id = 0
            if resume:
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS seed_checkpoint(
                        id INTEGER PRIMARY KEY CHECK (id=1),
                        since_id INTEGER
                    )""")
                row = cur.execute("SELECT since_id FROM seed_checkpoint WHERE id=1").fetchone()
                if row and row["since_id"]:
                    since_id = int(row["since_id"] or 0)

            scanned = 0
            total_scanned = 0
            yield f"Starting seed (resume={resume}) from since_id={since_id}\n".encode("utf-8")

            while True:
                r = shopify_request("GET", f"/variants.json",
                                    params={"since_id": since_id, "limit": min(limit, 250)})
                if r.status_code != 200:
                    yield f"Error {r.status_code}: {r.text[:200]}\n".encode("utf-8")
                    break
                arr = r.json().get("variants", [])
                if not arr:
                    yield b"Done. No more variants.\n"
                    break

                for v in arr:
                    sku = (v.get("sku") or "").strip()
                    if not sku:
                        continue
                    pid = v.get("product_id"); vid = v.get("id"); iid = v.get("inventory_item_id")
                    cur.execute("""
                        INSERT INTO products(prodid,name,price,vatcode,groupid,barcode,stock,reserved,body_html,image_b64,webactive,vendor,payload_xml,
                                             last_shopify_product_id,last_shopify_variant_id,last_inventory_item_id,last_compare_at_price,last_tags,last_cost,updated_at)
                        VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                        ON CONFLICT(prodid) DO UPDATE SET
                          last_shopify_product_id=excluded.last_shopify_product_id,
                          last_shopify_variant_id=excluded.last_shopify_variant_id,
                          last_inventory_item_id=excluded.last_inventory_item_id,
                          updated_at=excluded.updated_at
                    """,(sku,None,None,None,None,None,None,None,None,None,1,None,None,pid,vid,iid,None,None,None,now_iso()))
                    scanned += 1; total_scanned += 1
                    since_id = v.get("id") or since_id

                    if scanned >= flush_every:
                        conn.commit()
                        if resume:
                            cur.execute("""INSERT INTO seed_checkpoint(id, since_id)
                                           VALUES(1, ?)
                                           ON CONFLICT(id) DO UPDATE SET since_id=excluded.since_id""",
                                        (since_id,))
                            conn.commit()
                        yield f"Seeded +{scanned} (total={total_scanned}) — since_id={since_id}\n".encode("utf-8")
                        scanned = 0

                conn.commit()
                if resume:
                    cur.execute("""INSERT INTO seed_checkpoint(id, since_id)
                                   VALUES(1, ?)
                                   ON CONFLICT(id) DO UPDATE SET since_id=excluded.since_id""",
                                (since_id,))
                    conn.commit()
                yield f"Page committed — since_id={since_id}, total={total_scanned}\n".encode("utf-8")

            conn.commit()
            if resume:
                row = cur.execute("SELECT since_id FROM seed_checkpoint WHERE id=1").fetchone()
                last = (row["since_id"] if row else None)
                yield f"Finished. Last checkpoint since_id={last}\n".encode("utf-8")
            else:
                yield b"Finished (no checkpoint saved).\n"
        except Exception as e:
            yield f"ERROR: {e}\n".encode("utf-8")
        finally:
            conn.close()

    resp = Response(stream_with_context(stream()), mimetype="text/plain; charset=utf-8")
    resp.headers["Cache-Control"] = "no-cache"
    return resp

# ---------- Admin: Kill / Resume ----------
@app.route("/admin/kill", methods=["GET","POST"])
def admin_kill():
    if request.args.get("key") != KILL_KEY:
        return Response(b"Forbidden\r\n", status=403, mimetype="text/plain; charset=windows-1252")
    try:
        with open(KILL_FILE, "w") as f:
            f.write(now_iso())
    except Exception as e:
        return Response(f"ERROR: {e}\r\n".encode("utf-8"), status=500, mimetype="text/plain")
    return Response(b"KILLED\r\n", status=200, mimetype="text/plain; charset=windows-1252")

@app.route("/admin/resume", methods=["GET","POST"])
def admin_resume():
    if request.args.get("key") != KILL_KEY:
        return Response(b"Forbidden\r\n", status=403, mimetype="text/plain; charset=windows-1252")
    try:
        if os.path.exists(KILL_FILE):
            os.remove(KILL_FILE)
    except Exception as e:
        return Response(f"ERROR: {e}\r\n".encode("utf-8"), status=500, mimetype="text/plain")
    return Response(b"RESUMED\r\n", status=200, mimetype="text/plain; charset=windows-1252")

# ---------- misc stubs ----------
@app.route("/twinxml/deleteproductgroup.asp", methods=["GET","POST"])
def delete_product_group():
    # We acknowledge but do not cascade any delete-like behavior
    return ok_txt("OK")

@app.route("/twinxml/deleteall.asp", methods=["GET","POST"])
def delete_all():
    try:
        conn = db()
        conn.execute("DELETE FROM products"); conn.execute("DELETE FROM groups")
        conn.commit(); conn.close()
    except Exception:
        pass
    return ok_txt("OK")

# ---------- fallback for blank filenames ----------
@app.route("/twinxml/asp", methods=["GET","POST","HEAD"])
@app.route("/twinxml/.asp", methods=["GET","POST","HEAD"])
def bare_asp_placeholder():
    logging.warning("Placeholder ASP hit. Likely a blank filename in Uni Sideadministrasjon. QS=%s",
                    request.query_string.decode("utf-8","ignore"))
    xml = '<?xml version="1.0" encoding="ISO-8859-1"?><Root><OK>OK</OK></Root>'
    return Response(xml, mimetype="text/xml; charset=ISO-8859-1")

# ---------- Catch-all ----------
@app.route("/twinxml/<path:rest>", methods=["GET", "POST", "HEAD"])
def twinxml_fallback(rest):
    try:
        qs = request.query_string.decode("utf-8", "ignore")
    except Exception:
        qs = ""
    path_l = rest.lower()

    # Explicitly exclude deletes from being treated like uploads
    if path_l.startswith("delete") or "delete" in path_l:
        logging.warning("Delete-related endpoint hit: /twinxml/%s?%s — acknowledging only.", rest, qs)
        return ok_txt("OK")

    is_upload = (
        path_l.startswith("post") or
        ("product" in path_l) or ("item" in path_l) or
        ("price" in path_l) or ("stock" in path_l) or
        ("inventory" in path_l) or ("discount" in path_l)
    )
    logging.warning("TwinXML FALLBACK hit: /twinxml/%s?%s  (upload=%s)", rest, qs, is_upload)
    if is_upload and request.method in ("POST","GET"):
        return post_product()
    return ok_txt("OK")

# ---------- Auto-seed SKU cache on startup ----------
def _auto_seed_cache_logger():
    return logging.getLogger("auto_seed")

def _auto_seed_cache_once():
    log = _auto_seed_cache_logger()
    try:
        import threading, time, fcntl, json
        lock_path = "/tmp/asm_auto_seed.lock"
        fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o644)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except Exception:
            log.info("Another worker is already seeding; skipping.")
            return

        conn = db(); cur = conn.cursor()
        since_id = 0
        if AUTO_SEED_RESUME:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS seed_checkpoint(
                    id INTEGER PRIMARY KEY CHECK (id=1),
                    since_id INTEGER
                )""")
            row = cur.execute("SELECT since_id FROM seed_checkpoint WHERE id=1").fetchone()
            if row and row["since_id"]:
                since_id = int(row["since_id"] or 0)

        scanned = 0
        total_scanned = 0
        log.info("Auto-seed starting (resume=%s) from since_id=%s", AUTO_SEED_RESUME, since_id)

        while True:
            r = shopify_request("GET", f"/variants.json",
                                params={"since_id": since_id, "limit": min(AUTO_SEED_LIMIT, 250)})
            if r.status_code != 200:
                log.error("Error %s: %s", r.status_code, r.text[:200])
                break
            arr = r.json().get("variants", [])
            if not arr:
                log.info("Auto-seed done. No more variants.")
                break

            for v in arr:
                sku = (v.get("sku") or "").strip()
                if not sku:
                    continue
                pid = v.get("product_id"); vid = v.get("id"); iid = v.get("inventory_item_id")
                cur.execute("""
                    INSERT INTO products(prodid,name,price,vatcode,groupid,barcode,stock,reserved,body_html,image_b64,webactive,vendor,payload_xml,last_shopify_product_id,last_shopify_variant_id,last_inventory_item_id,last_compare_at_price,last_tags,last_cost,updated_at)
                    VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                    ON CONFLICT(prodid) DO UPDATE SET
                      last_shopify_product_id=excluded.last_shopify_product_id,
                      last_shopify_variant_id=excluded.last_shopify_variant_id,
                      last_inventory_item_id=excluded.last_inventory_item_id,
                      updated_at=excluded.updated_at
                """,(sku,None,None,None,None,None,None,None,None,None,1,None,None,pid,vid,iid,None,None,None,now_iso()))
                scanned += 1; total_scanned += 1
                since_id = v.get("id") or since_id

                if scanned >= AUTO_SEED_FLUSH_EVERY:
                    conn.commit()
                    if AUTO_SEED_RESUME:
                        cur.execute("""INSERT INTO seed_checkpoint(id, since_id)
                                       VALUES(1, ?)
                                       ON CONFLICT(id) DO UPDATE SET since_id=excluded.since_id""",
                                    (since_id,))
                        conn.commit()
                    log.info("Auto-seed progress — since_id=%s, total=%s", since_id, total_scanned)
                    scanned = 0

            conn.commit()
            if AUTO_SEED_RESUME:
                cur.execute("""INSERT INTO seed_checkpoint(id, since_id)
                               VALUES(1, ?)
                               ON CONFLICT(id) DO UPDATE SET since_id=excluded.since_id""",
                            (since_id,))
                conn.commit()
            log.info("Auto-seed page committed — since_id=%s, total=%s", since_id, total_scanned)

        conn.commit(); conn.close()
        log.info("Preload complete. Variants cached: %s", total_scanned)
    except Exception as e:
        log = _auto_seed_cache_logger()
        log.exception("Auto-seed failed: %s", e)

if AUTO_SEED_CACHE_ON_START:
    import threading, time
    def _starter():
        time.sleep(AUTO_SEED_DELAY)
        _auto_seed_cache_once()
    try:
        threading.Thread(target=_starter, daemon=True).start()
    except Exception as _e:
        logging.getLogger("auto_seed").warning("Failed to start auto-seed thread: %s", _e)

# ---------- Main ----------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=PORT)
