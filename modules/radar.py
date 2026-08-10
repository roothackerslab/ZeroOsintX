"""Mini radar — a fast, cached ISS + planes-overhead feed for the animated
radar-sweep widget. Reuses modules/fun_realtime.py's existing ISS/OpenSky
calls (nothing new fetched), just split out from the full fun_realtime.scan()
so the radar widget can poll frequently without dragging along the slower
ships/space-weather lookups.
"""
from __future__ import annotations

import threading
import time

from modules.utils import ok
from modules import fun_realtime

_CACHE_TTL = 8.0
_cache_lock = threading.Lock()
_cache: dict | None = None
_cache_key: tuple | None = None
_cache_time = 0.0

_PLACE_TTL = 300.0
_place_lock = threading.Lock()
_place_cache: dict[str, tuple[float, float, float]] = {}  # name -> (lat, lon, resolved_at)


def resolve_place_cached(place: str, resolver) -> tuple[float | None, float | None]:
    """Wraps geo.resolve_location with a 5-minute cache keyed by the place
    string, so a radar widget polling every few seconds doesn't re-hit
    Nominatim's rate-limited geocoder on every tick."""
    key = place.strip().lower()
    now = time.time()
    with _place_lock:
        cached = _place_cache.get(key)
        if cached and (now - cached[2]) < _PLACE_TTL:
            return cached[0], cached[1]

    loc = resolver(place)
    if loc["status"] != "ok":
        return None, None
    lat, lon = loc["data"]["lat"], loc["data"]["lon"]
    with _place_lock:
        _place_cache[key] = (lat, lon, now)
    return lat, lon


def _build(lat: float | None, lon: float | None) -> dict:
    return {
        "iss_position": fun_realtime.iss_position(),
        "planes_overhead": (
            fun_realtime.planes_overhead(lat, lon)
            if lat is not None and lon is not None
            else {"status": "skipped", "reason": "no coordinates provided", "source": None}
        ),
        "center": {"lat": lat, "lon": lon},
    }


def sweep(lat: float | None = None, lon: float | None = None) -> dict:
    global _cache, _cache_key, _cache_time
    key = (round(lat, 2) if lat is not None else None, round(lon, 2) if lon is not None else None)
    with _cache_lock:
        now = time.time()
        if _cache is not None and _cache_key == key and (now - _cache_time) < _CACHE_TTL:
            return _cache

    data = _build(lat, lon)
    result = ok(data, source="radar.sweep")

    with _cache_lock:
        _cache = result
        _cache_key = key
        _cache_time = time.time()
    return result
