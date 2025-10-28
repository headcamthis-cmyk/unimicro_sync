#!/usr/bin/env python3
# server.py
# Flask app to capture Uni Micro "last opp alle produkter" POST payloads for debugging.
# Save to disk + log headers/query params + try to decode hex payloads.
# Returns "OK\r\n" with windows-1252 charset to match Uni Micro expectations.

import os
import sys
import logging
from datetime import datetime
from flask import Flask, request, Response, jsonify
import binascii
import xml.dom.minidom

# Configuration
PORT = int(os.environ.get("PORT", 5000))
SAVE_DIR = os.environ.get("UM_SAVE_DIR", "/tmp/um_payloads")
os.makedirs(SAVE_DIR, exist_ok=True)

# Logging setup
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s: %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger("uni-micro-capture")

app = Flask(__name__)

def timestamp():
    return datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")

def safe_filename(prefix, ext="txt"):
    ts = timestamp()
    return f"{prefix}_{ts}.{ext}"

def try_pretty_xml(raw_bytes):
    try:
        s = raw_bytes.decode("utf-8")
    except UnicodeDecodeError:
        try:
            s = raw_bytes.decode("windows-1252")
        except Exception:
            return None
    try:
        dom = xml.dom.minidom.parseString(s)
        pretty = dom.toprettyxml(indent="  ", encoding="utf-8")
        # pretty is bytes (because encoding specified)
        return pretty
    except Exception:
        return None

@app.route("/", methods=["GET"])
def index():
    return (
        "Uni Micro payload capture endpoint.\n"
        "POST to /twinxml/postproduct or /twinxml/postproduct.asp\n",
        200,
    )

def save_file(path, data, mode="wb"):
    with open(path, mode) as f:
        f.write(data)
    logger.info(f"Saved: {path}")

def make_ok_response(body="OK"):
    # exact plain text + CRLF; windows-1252 charset
    resp = Response(body + "\r\n", mimetype="text/plain; charset=windows-1252")
    return resp

@app.route("/twinxml/postproduct", methods=["GET", "POST"])
@app.route("/twinxml/postproduct.asp", methods=["GET", "POST"])
def capture():
    req = request
    # Collect metadata
    remote_addr = request.remote_addr
    method = request.method
    headers = dict(request.headers)
    query_params = request.args.to_dict(flat=False)  # keep repeated params if present

    logger.info(f"Received {method} {request.path} from {remote_addr}")
    logger.info(f"Query params: {query_params}")
    logger.info(f"Headers: { {k: headers.get(k) for k in ['User-Agent','Content-Type','Content-Length','Authorization']} }")

    raw_body = request.get_data()  # bytes, raw payload

    # Save raw body
    raw_name = safe_filename("raw_payload", "bin")
    raw_path = os.path.join(SAVE_DIR, raw_name)
    save_file(raw_path, raw_body, mode="wb")

    saved_files = {"raw": raw_path}

    # If content-type looks like multipart/form-data, save as-is and also try to parse parts (not auto-parsing here).
    ctype = headers.get("Content-Type", "")
    if "multipart/form-data" in ctype.lower():
        # Save raw already helps; optionally also save as .multipart.txt
        mp_name = safe_filename("multipart_payload", "txt")
        mp_path = os.path.join(SAVE_DIR, mp_name)
        try:
            save_file(mp_path, raw_body, mode="wb")
            saved_files["multipart"] = mp_path
        except Exception as e:
            logger.warning(f"Couldn't save multipart payload copy: {e}")

    # If query contains hex=true, attempt to hex-decode the body
    try:
        hex_flag = any(k.lower() == "hex" and "true" in [v.lower() for v in query_params[k]] for k in query_params)
    except Exception:
        hex_flag = False

    if hex_flag:
        logger.info("Detected hex=true in query params — attempting hex decode.")
        try:
            # remove whitespace/newlines just in case
            hexstr = raw_body.decode("ascii", errors="ignore").strip()
            decoded = binascii.unhexlify(hexstr)
            dec_name = safe_filename("hex_decoded", "bin")
            dec_path = os.path.join(SAVE_DIR, dec_name)
            save_file(dec_path, decoded, mode="wb")
            saved_files["hex_decoded"] = dec_path

            # Try to pretty-print XML if it is XML
            pretty = try_pretty_xml(decoded)
            if pretty:
                pretty_name = dec_path + ".pretty.xml"
                save_file(pretty_name, pretty, mode="wb")
                saved_files["pretty_xml"] = pretty_name
        except Exception as e:
            logger.exception("Hex decode failed: %s", e)

    # Try to interpret raw as XML and pretty print
    pretty = try_pretty_xml(raw_body)
    if pretty:
        pretty_name = os.path.join(SAVE_DIR, safe_filename("pretty_xml", "xml"))
        save_file(pretty_name, pretty, mode="wb")
        saved_files["pretty_xml_raw"] = pretty_name

    # Also record headers+query metadata as json-like text
    meta_name = os.path.join(SAVE_DIR, safe_filename("meta", "txt"))
    meta_contents = []
    meta_contents.append(f"time_utc: {timestamp()}")
    meta_contents.append(f"path: {request.path}")
    meta_contents.append(f"remote_addr: {remote_addr}")
    meta_contents.append("query_params:")
    for k, vals in query_params.items():
        meta_contents.append(f"  {k}: {vals}")
    meta_contents.append("headers:")
    for k, v in headers.items():
        meta_contents.append(f"  {k}: {v}")
    meta_contents.append(f"saved_files: {saved_files}")
    meta_text = "\n".join(meta_contents).encode("utf-8")
    save_file(meta_name, meta_text, mode="wb")
    saved_files["meta"] = meta_name

    # Log summary for Render logs
    logger.info(f"Saved files summary: {saved_files}")

    # Return exact OK response (some Uni Micro setups expect CRLF and windows-1252)
    return make_ok_response("OK")

if __name__ == "__main__":
    logger.info(f"Starting uni-micro-capture server on 0.0.0.0:{PORT}, writing payloads to {SAVE_DIR}")
    # Use threaded server; in Render production they run via gunicorn recommended below.
    app.run(host="0.0.0.0", port=PORT, threaded=True)
