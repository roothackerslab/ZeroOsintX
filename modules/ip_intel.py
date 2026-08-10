"""IP address intelligence.

Informational lookups only (geolocation, ASN/ISP, reverse DNS, public
blacklist/reputation status). Deliberately excludes active port scanning —
see EXCLUDED_FEATURES.md — since probing arbitrary hosts' open ports is
reconnaissance for exploitation, not passive intelligence.
"""
from __future__ import annotations

import socket

from config import settings
from modules.utils import http_session, ok, skipped, failed


def geolocation(ip: str) -> dict:
    resp = http_session().get(
        f"http://ip-api.com/json/{ip}?fields=status,message,country,regionName,city,zip,lat,lon,isp,org,as,mobile,proxy,hosting,query",
        timeout=settings.request_timeout,
    )
    if resp.status_code != 200:
        return failed(f"HTTP {resp.status_code}", source="ip-api.com")
    data = resp.json()
    if data.get("status") != "success":
        return failed(data.get("message", "lookup failed"), source="ip-api.com")
    return ok(
        {
            "ip": data.get("query"),
            "country": data.get("country"),
            "region": data.get("regionName"),
            "city": data.get("city"),
            "isp": data.get("isp"),
            "org": data.get("org"),
            "asn": data.get("as"),
            "is_mobile": data.get("mobile"),
            "is_proxy_or_vpn": data.get("proxy"),
            "is_hosting_datacenter": data.get("hosting"),
        },
        source="ip-api.com",
    )


def reverse_dns(ip: str) -> dict:
    try:
        host = socket.gethostbyaddr(ip)[0]
        return ok({"hostname": host}, source="reverse-dns")
    except socket.herror:
        return ok({"hostname": None}, source="reverse-dns")
    except Exception as exc:  # noqa: BLE001
        return failed(str(exc), source="reverse-dns")


def blacklist_status(ip: str) -> dict:
    """Checks a handful of public DNSBL zones — a standard, passive
    reputation signal (does this IP appear on known spam/abuse lists)."""
    zones = ["zen.spamhaus.org", "bl.spamcop.net", "b.barracudacentral.org"]
    reversed_ip = ".".join(reversed(ip.split(".")))
    listed_on = []
    for zone in zones:
        query = f"{reversed_ip}.{zone}"
        try:
            socket.gethostbyname(query)
            listed_on.append(zone)
        except socket.gaierror:
            continue
        except Exception:
            continue
    return ok({"listed_on": listed_on, "is_listed": bool(listed_on)}, source="dnsbl")


def abuseipdb(ip: str) -> dict:
    if not settings.abuseipdb_api_key:
        return skipped("no AbuseIPDB key configured (ZOX_ABUSEIPDB_KEY)", source="abuseipdb")
    resp = http_session().get(
        "https://api.abuseipdb.com/api/v2/check",
        params={"ipAddress": ip, "maxAgeInDays": 90},
        headers={"Key": settings.abuseipdb_api_key, "Accept": "application/json"},
        timeout=settings.request_timeout,
    )
    if resp.status_code == 200:
        d = resp.json().get("data", {})
        return ok(
            {
                "abuse_confidence_score": d.get("abuseConfidenceScore"),
                "total_reports": d.get("totalReports"),
                "country": d.get("countryCode"),
                "is_tor": d.get("isTor"),
            },
            source="abuseipdb",
        )
    return failed(f"HTTP {resp.status_code}", source="abuseipdb")


def investigate(ip: str) -> dict:
    ip = ip.strip()
    return ok(
        {
            "ip": ip,
            "geolocation": geolocation(ip),
            "reverse_dns": reverse_dns(ip),
            "blacklist": blacklist_status(ip),
            "abuseipdb": abuseipdb(ip),
        },
        source="ip.investigate",
    )
