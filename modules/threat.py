"""Threat intelligence feeds — standard defensive-security data: known
malware indicators, malicious URLs, published CVEs, and file/URL reputation
lookups against public/free security databases."""
from __future__ import annotations

from config import settings
from modules.utils import http_session, ok, skipped, failed


def threatfox_recent(limit: int = 15) -> dict:
    resp = http_session().post(
        "https://threatfox-api.abuse.ch/api/v1/",
        json={"query": "get_iocs", "days": 1},
        timeout=settings.request_timeout,
    )
    if resp.status_code != 200:
        return failed(f"HTTP {resp.status_code}", source="threatfox")
    body = resp.json()
    data = body.get("data", []) if isinstance(body.get("data"), list) else []
    items = [
        {"ioc": d.get("ioc"), "type": d.get("ioc_type"), "malware": d.get("malware_printable")}
        for d in data[:limit]
    ]
    return ok(items, source="threatfox (abuse.ch)")


def urlhaus_recent(limit: int = 15) -> dict:
    resp = http_session().get("https://urlhaus-api.abuse.ch/v1/urls/recent/", timeout=settings.request_timeout)
    if resp.status_code != 200:
        return failed(f"HTTP {resp.status_code}", source="urlhaus")
    urls = resp.json().get("urls", [])[:limit]
    items = [{"url": u.get("url"), "threat": u.get("threat"), "tags": u.get("tags")} for u in urls]
    return ok(items, source="urlhaus (abuse.ch)")


def recent_cves(limit: int = 10) -> dict:
    headers = {"apiKey": settings.nvd_api_key} if settings.nvd_api_key else {}
    resp = http_session().get(
        "https://services.nvd.nist.gov/rest/json/cves/2.0",
        params={"resultsPerPage": limit},
        headers=headers,
        timeout=settings.request_timeout + 4,
    )
    if resp.status_code == 403 or resp.status_code == 429:
        return skipped("rate limited (unauthenticated NVD access is strict)", source="nvd")
    if resp.status_code != 200:
        return failed(f"HTTP {resp.status_code}", source="nvd")
    vulns = resp.json().get("vulnerabilities", [])
    items = []
    for v in vulns:
        cve = v.get("cve", {})
        desc = next((d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"), "")
        items.append({"id": cve.get("id"), "summary": desc[:200]})
    return ok(items, source="nvd")


def virustotal_hash(file_hash: str) -> dict:
    if not settings.virustotal_api_key:
        return skipped("no VirusTotal key configured (ZOX_VT_KEY)", source="virustotal")
    resp = http_session().get(
        f"https://www.virustotal.com/api/v3/files/{file_hash}",
        headers={"x-apikey": settings.virustotal_api_key},
        timeout=settings.request_timeout,
    )
    if resp.status_code == 200:
        stats = resp.json()["data"]["attributes"]["last_analysis_stats"]
        return ok(stats, source="virustotal")
    if resp.status_code == 404:
        return ok({"found": False}, source="virustotal")
    return failed(f"HTTP {resp.status_code}", source="virustotal")


def urlhaus_url_lookup(url: str) -> dict:
    resp = http_session().post(
        "https://urlhaus-api.abuse.ch/v1/url/", data={"url": url}, timeout=settings.request_timeout
    )
    if resp.status_code != 200:
        return failed(f"HTTP {resp.status_code}", source="urlhaus")
    body = resp.json()
    if body.get("query_status") != "ok":
        return ok({"listed": False}, source="urlhaus")
    return ok({"listed": True, "threat": body.get("threat"), "tags": body.get("tags")}, source="urlhaus")


def feed_snapshot() -> dict:
    return ok(
        {
            "malware_iocs": threatfox_recent(),
            "malicious_urls": urlhaus_recent(),
            "recent_cves": recent_cves(),
        },
        source="threat.feed_snapshot",
    )
