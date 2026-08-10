"""
ZeroOSINTx v2.0 — entrypoint.

Run:  python main.py
Then open http://127.0.0.1:8420 in a browser.
"""
from __future__ import annotations

from flask import Flask, jsonify, request, send_from_directory

from config import settings, key_status, set_key
from modules import username, email_intel, phone_intel, domain_intel, ip_intel, geo, threat, tools, reports, fun_realtime, exif_tool, live_dashboard, techstack, attack_map, radar, webscan

app = Flask(__name__, static_folder="static", template_folder="templates")

# Endpoints that represent an actual "scan" the user ran, counted for the
# live dashboard's session stats. Utility/meta endpoints are excluded.
_SCAN_PATHS = {
    "/api/username", "/api/email", "/api/phone", "/api/domain", "/api/webscan", "/api/ip",
    "/api/geo", "/api/threat", "/api/fun", "/api/tools/hash-id",
    "/api/tools/hash-reputation", "/api/tools/mac-vendor",
    "/api/tools/url-reputation", "/api/tools/dorks", "/api/tools/exif",
    "/api/techstack",
}


@app.before_request
def _count_scans():
    if request.method == "POST" and request.path in _SCAN_PATHS:
        live_dashboard.record_scan()


@app.errorhandler(Exception)
def handle_unexpected_error(exc):
    """Safety net: without this, an uncaught exception in any route returns
    Flask's default HTML error page, which breaks the frontend's
    `resp.json()` call (that's the 'Unexpected token <' error). Every route
    should already return a clean error envelope via modules/utils.py, but
    this guarantees JSON no matter what."""
    from werkzeug.exceptions import HTTPException
    if isinstance(exc, HTTPException):
        return jsonify(status="error", reason=exc.description or str(exc)), exc.code
    app.logger.exception("Unhandled exception")
    return jsonify(status="error", reason=str(exc), source="server"), 500


def _target() -> str:
    return (request.json or {}).get("target", "").strip()


@app.get("/")
def index():
    return send_from_directory("templates", "index.html")


@app.get("/api/health")
def health():
    return jsonify(ok=True, version="2.0")


@app.post("/api/username")
def api_username():
    return jsonify(username.hunt(_target()))


@app.post("/api/email")
def api_email():
    return jsonify(email_intel.investigate(_target()))


@app.post("/api/phone")
def api_phone():
    return jsonify(phone_intel.investigate(_target()))


@app.post("/api/domain")
def api_domain():
    body = request.json or {}
    birth_year = body.get("birth_year")
    try:
        birth_year = int(birth_year) if birth_year not in (None, "") else None
    except (TypeError, ValueError):
        birth_year = None
    return jsonify(domain_intel.investigate(_target(), birth_year=birth_year))


@app.post("/api/webscan")
def api_webscan():
    return jsonify(webscan.scan(_target()))


@app.post("/api/ip")
def api_ip():
    return jsonify(ip_intel.investigate(_target()))


@app.post("/api/techstack")
def api_techstack():
    return jsonify(techstack.fingerprint(_target()))


@app.post("/api/geo")
def api_geo():
    return jsonify(geo.mega_scan(_target()))


@app.post("/api/threat")
def api_threat():
    return jsonify(threat.feed_snapshot())


@app.post("/api/fun")
def api_fun():
    location_query = _target()
    if not location_query:
        return jsonify(fun_realtime.scan(None, None))
    loc = geo.resolve_location(location_query)
    if loc["status"] != "ok":
        return jsonify(loc)
    lat, lon = loc["data"]["lat"], loc["data"]["lon"]
    result = fun_realtime.scan(lat, lon)
    result["data"]["location"] = loc
    return jsonify(result)


@app.post("/api/tools/hash-id")
def api_hash_id():
    return jsonify(tools.identify_hash(_target()))


@app.post("/api/tools/hash-reputation")
def api_hash_rep():
    return jsonify(tools.hash_reputation(_target()))


@app.post("/api/tools/mac-vendor")
def api_mac_vendor():
    return jsonify(tools.mac_vendor(_target()))


@app.post("/api/tools/url-reputation")
def api_url_rep():
    return jsonify(tools.url_reputation(_target()))


@app.post("/api/tools/dorks")
def api_dorks():
    return jsonify(tools.generate_dorks(_target()))


@app.post("/api/tools/exif")
def api_exif():
    """Reads EXIF metadata from an uploaded image (multipart form field
    'image'). Self-check utility only — operates on the file this request
    carries, no target/handle lookup involved."""
    if "image" not in request.files:
        return jsonify(status="error", reason="no file uploaded (field 'image')", source="exif-tool")
    f = request.files["image"]
    return jsonify(exif_tool.extract(f.read(), filename=f.filename or "upload"))


@app.get("/api/live")
def api_live():
    """Polling endpoint for the live dashboard tab — short-TTL cached, safe
    to call every few seconds from the frontend."""
    return jsonify(live_dashboard.snapshot())


@app.get("/api/attack-map")
def api_attack_map():
    """Polling endpoint for the live attack map — geolocated recent IOCs
    from ThreatFox/URLhaus, short-TTL cached server-side."""
    return jsonify(attack_map.snapshot())


@app.get("/api/radar")
def api_radar():
    """Polling endpoint for the ISS/planes mini radar widget. Optional
    ?lat=&lon= to center the plane search, or ?place=City for a location
    name (resolved the same way /api/fun does); omit both for ISS-only."""
    lat = request.args.get("lat", type=float)
    lon = request.args.get("lon", type=float)
    place = request.args.get("place", type=str)
    if place and (lat is None or lon is None):
        lat, lon = radar.resolve_place_cached(place, geo.resolve_location)
    return jsonify(radar.sweep(lat, lon))


@app.post("/api/report")
def api_report():
    body = request.json or {}
    path = reports.save(
        target=body.get("target", "unknown"),
        module=body.get("module", "scan"),
        data=body.get("data", {}),
        fmt=body.get("format", "html"),
    )
    return jsonify(ok=True, path=path)


@app.get("/api/settings")
def api_settings_get():
    return jsonify(ok=True, keys=key_status())


@app.post("/api/settings")
def api_settings_post():
    body = request.json or {}
    field_name = body.get("field", "")
    value = body.get("value", "")
    result = set_key(field_name, value)
    return jsonify(result)


if __name__ == "__main__":
    print(f"[ZeroOSINTx] serving on http://{settings.host}:{settings.port}")
    app.run(host=settings.host, port=settings.port, debug=settings.debug)
