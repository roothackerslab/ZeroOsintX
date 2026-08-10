"""Live dashboard — powers the sidebar's 'live' tab, which polls this on an
interval and renders an auto-refreshing overview instead of a manual
run-once query. Aggregates a few fast, global (non-targeted) signals —
ISS position, space weather, a handful of the latest threat-intel items —
plus local session stats (uptime, scans run this session).

Short TTL cache so multiple browser polls (or multiple browser tabs) don't
re-hit the upstream free APIs faster than necessary.
"""
from __future__ import annotations

import threading
import time

from modules.utils import ok
from modules import fun_realtime, threat

_CACHE_TTL = 12.0
_cache_lock = threading.Lock()
_cache: dict | None = None
_cache_time = 0.0

_stats_lock = threading.Lock()
_stats = {"scans_run": 0, "started_at": time.time()}


def record_scan() -> None:
    """Called once per module scan the user runs, so the live dashboard can
    show a running count for the current session."""
    with _stats_lock:
        _stats["scans_run"] += 1


def _build_snapshot() -> dict:
    with _stats_lock:
        uptime = round(time.time() - _stats["started_at"])
        scans_run = _stats["scans_run"]

    return {
        "iss_position": fun_realtime.iss_position(),
        "space_weather": fun_realtime.space_weather(),
        "recent_malware_iocs": threat.threatfox_recent(limit=5),
        "recent_malicious_urls": threat.urlhaus_recent(limit=5),
        "session": {"uptime_seconds": uptime, "scans_run": scans_run},
    }


def snapshot() -> dict:
    global _cache, _cache_time
    with _cache_lock:
        now = time.time()
        if _cache is not None and (now - _cache_time) < _CACHE_TTL:
            return _cache

    data = _build_snapshot()
    result = ok(data, source="live_dashboard.snapshot")

    with _cache_lock:
        _cache = result
        _cache_time = time.time()
    return result
