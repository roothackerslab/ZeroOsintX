"""Live attack map — takes the same public threat-intel feeds already used
by modules/threat.py (ThreatFox, URLhaus) and geolocates the malicious IPs
in them so the frontend can plot them as animated points on a world map.

This is purely aggregation + geolocation of infrastructure IOCs that are
already published by abuse.ch — no per-person data, nothing new fetched
that threat.py doesn't already fetch. Short TTL cache since the frontend
polls this on an interval.
"""
from __future__ import annotations

import ipaddress
import re
import socket
import threading
import time
from urllib.parse import urlparse

from config import settings
from modules.utils import http_session, ok, skipped, failed
from modules import threat

_CACHE_TTL = 20.0
_cache_lock = threading.Lock()
_cache: dict | None = None
_cache_time = 0.0

_IP_PORT_RE = re.compile(r"^(\d{1,3}(?:\.\d{1,3}){3}):\d+$")


def _extract_ip(ioc: str, ioc_type: str | None) -> str | None:
    """Pull a bare IPv4 address out of a ThreatFox IOC, if there is one."""
    if not ioc:
        return None
    m = _IP_PORT_RE.match(ioc)
    candidate = m.group(1) if m else ioc
    try:
        ipaddress.ip_address(candidate)
        return candidate
    except ValueError:
        return None


def _resolve_host(url: str, timeout: float = 2.0) -> str | None:
    """Best-effort, short-timeout hostname->IP resolution for URLhaus entries
    (most URLhaus entries are hostnames, not bare IPs). Failures are just
    skipped — this map is decorative, not a guarantee of full coverage."""
    try:
        host = urlparse(url).hostname
        if not host:
            return None
        try:
            ipaddress.ip_address(host)
            return host
        except ValueError:
            pass
        old_timeout = socket.getdefaulttimeout()
        socket.setdefaulttimeout(timeout)
        try:
            return socket.gethostbyname(host)
        finally:
            socket.setdefaulttimeout(old_timeout)
    except Exception:
        return None


def _collect_candidate_points(limit: int) -> list[dict]:
    """Gather up to `limit` {ip, malware/threat, ioc_type} entries from the
    two abuse.ch feeds, deduplicated by IP."""
    points: dict[str, dict] = {}

    fx = threat.threatfox_recent(limit=limit)
    if fx["status"] == "ok":
        for item in fx["data"]:
            ip = _extract_ip(item.get("ioc", ""), item.get("type"))
            if ip and ip not in points:
                points[ip] = {"ip": ip, "label": item.get("malware") or "malware IOC", "feed": "threatfox"}

    if len(points) < limit:
        uh = threat.urlhaus_recent(limit=limit)
        if uh["status"] == "ok":
            for item in uh["data"]:
                if len(points) >= limit:
                    break
                url = item.get("url") or ""
                ip = _resolve_host(url)
                if ip and ip not in points:
                    points[ip] = {"ip": ip, "label": item.get("threat") or "malicious URL", "feed": "urlhaus"}

    return list(points.values())[:limit]


def _batch_geolocate(candidates: list[dict]) -> list[dict]:
    """One request to ip-api.com's free batch endpoint instead of N
    individual lookups — same data source ip_intel.py already uses."""
    if not candidates:
        return []
    payload = [{"query": c["ip"], "fields": "status,lat,lon,country,city,query"} for c in candidates]
    resp = http_session().post(
        "http://ip-api.com/batch",
        json=payload,
        timeout=settings.request_timeout,
    )
    if resp.status_code != 200:
        return []
    by_ip = {c["ip"]: c for c in candidates}
    out = []
    for row in resp.json():
        if row.get("status") != "success":
            continue
        meta = by_ip.get(row.get("query"), {})
        out.append(
            {
                "ip": row.get("query"),
                "lat": row.get("lat"),
                "lon": row.get("lon"),
                "country": row.get("country"),
                "city": row.get("city"),
                "label": meta.get("label", "IOC"),
                "feed": meta.get("feed", "unknown"),
            }
        )
    return out


def _build_snapshot(limit: int) -> dict:
    candidates = _collect_candidate_points(limit)
    points = _batch_geolocate(candidates)
    return {"count": len(points), "points": points, "generated_at": time.time()}


def snapshot(limit: int = 40) -> dict:
    global _cache, _cache_time
    with _cache_lock:
        now = time.time()
        if _cache is not None and (now - _cache_time) < _CACHE_TTL:
            return _cache

    try:
        data = _build_snapshot(limit)
        result = ok(data, source="attack_map (threatfox + urlhaus + ip-api.com)")
    except Exception as exc:  # noqa: BLE001
        result = failed(str(exc), source="attack_map")

    with _cache_lock:
        _cache = result
        _cache_time = time.time()
    return result
