"""Fun Realtime — carried over from the original ZeroOSINTx CLI, plus ship
radar. Global, non-targeted, informational realtime feeds (ISS position,
plane traffic, ship/vessel traffic in a region, space weather). Nothing here
is about a specific person."""
from __future__ import annotations

import json
import time

from config import settings
from modules.utils import http_session, ok, skipped, failed

try:
    import websocket  # from `websocket-client`
    HAVE_WEBSOCKET = True
except ImportError:
    HAVE_WEBSOCKET = False


def iss_position() -> dict:
    resp = http_session().get("http://api.open-notify.org/iss-now.json", timeout=settings.request_timeout)
    if resp.status_code != 200:
        return skipped("unavailable", source="open-notify")
    try:
        data = resp.json()
        pos = data.get("iss_position", {})
        return ok({"lat": pos.get("latitude"), "lon": pos.get("longitude"), "timestamp": data.get("timestamp")}, source="open-notify")
    except Exception as exc:  # noqa: BLE001
        return failed(str(exc), source="open-notify")


def planes_overhead(lat: float, lon: float, box: float = 1.0) -> dict:
    params = {"lamin": lat - box, "lamax": lat + box, "lomin": lon - box, "lomax": lon + box}
    resp = http_session().get("https://opensky-network.org/api/states/all", params=params, timeout=8)
    if resp.status_code == 429:
        return skipped("rate limited by OpenSky", source="opensky-network")
    if resp.status_code != 200:
        return skipped("unavailable", source="opensky-network")
    try:
        states = resp.json().get("states") or []
        planes = [
            {"callsign": (s[1] or "").strip() or "Unknown", "origin_country": s[2], "lat": s[6], "lon": s[5], "altitude_m": s[7]}
            for s in states[:15]
        ]
        return ok({"count": len(planes), "planes": planes}, source="opensky-network")
    except Exception as exc:  # noqa: BLE001
        return failed(str(exc), source="opensky-network")


def ships_overhead(lat: float, lon: float, box: float = 1.0, listen_seconds: float = 5.0, max_ships: int = 15) -> dict:
    """Live vessel positions near a point, via AISstream.io's public AIS
    relay. Requires a free API key (unlike OpenSky, there's no keyless
    global AIS feed) — degrades gracefully without one."""
    if not settings.aisstream_api_key:
        return skipped("no AISstream key configured (ZOX_AISSTREAM_KEY) — free key at aisstream.io", source="aisstream.io")
    if not HAVE_WEBSOCKET:
        return skipped("`websocket-client` package not installed", source="aisstream.io")

    bbox = [[lat - box, lon - box], [lat + box, lon + box]]
    subscribe_message = {"APIKey": settings.aisstream_api_key, "BoundingBoxes": [bbox]}
    ships: dict[str, dict] = {}

    try:
        ws = websocket.create_connection("wss://stream.aisstream.io/v0/stream", timeout=listen_seconds)
        ws.send(json.dumps(subscribe_message))
        deadline = time.time() + listen_seconds
        while time.time() < deadline and len(ships) < max_ships:
            ws.settimeout(max(0.5, deadline - time.time()))
            try:
                raw = ws.recv()
            except Exception:
                break
            try:
                msg = json.loads(raw)
            except Exception:
                continue
            if msg.get("MessageType") == "PositionReport":
                report = msg.get("Message", {}).get("PositionReport", {})
                meta = msg.get("MetaData", {})
                mmsi = str(meta.get("MMSI") or report.get("UserID") or "")
                if mmsi:
                    ships[mmsi] = {
                        "mmsi": mmsi,
                        "name": (meta.get("ShipName") or "").strip() or "Unknown",
                        "lat": report.get("Latitude"),
                        "lon": report.get("Longitude"),
                        "speed_knots": report.get("Sog"),
                        "course": report.get("Cog"),
                    }
        ws.close()
    except Exception as exc:  # noqa: BLE001
        return failed(str(exc), source="aisstream.io")

    return ok({"count": len(ships), "ships": list(ships.values())}, source="aisstream.io")


def space_weather() -> dict:
    resp = http_session().get("https://services.swpc.noaa.gov/products/noaa-scales.json", timeout=settings.request_timeout)
    if resp.status_code != 200:
        return skipped("unavailable", source="noaa-swpc")
    try:
        data = resp.json()
        current = data[1] if isinstance(data, list) and len(data) > 1 else (data[0] if data else {})
        return ok(current, source="noaa-swpc")
    except Exception as exc:  # noqa: BLE001
        return failed(str(exc), source="noaa-swpc")


def scan(lat: float | None, lon: float | None) -> dict:
    windy_link = f"https://www.windy.com/{lat}/{lon}?radar,{lat},{lon},8" if lat is not None else None
    nasa_link = (
        f"https://worldview.earthdata.nasa.gov/?v={lon-5},{lat-5},{lon+5},{lat+5}&l=VIIRS_Black_Marble"
        if lat is not None and lon is not None else None
    )
    return ok(
        {
            "iss_position": iss_position(),
            "planes_overhead": planes_overhead(lat, lon) if lat is not None and lon is not None else skipped("no coordinates provided"),
            "ships_overhead": ships_overhead(lat, lon) if lat is not None and lon is not None else skipped("no coordinates provided"),
            "weather_radar_link": windy_link,
            "night_lights_link": nasa_link,
            "space_weather": space_weather(),
        },
        source="fun_realtime.scan",
    )
