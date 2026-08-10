"""Web scan — a focused "when was this domain registered, when does it
expire, how old is it" summary.

This is deliberately a thin wrapper around domain_intel's WHOIS lookup and
age-trivia helper, not a new data source: same public WHOIS data, just
surfaced as its own quick-glance card instead of buried inside the full
domain-intelligence report. Same authorized-use scope as domain_intel —
you administer this domain, or you have explicit permission to assess it.
"""
from __future__ import annotations

from datetime import datetime, timezone

from modules import domain_intel
from modules.utils import ok, skipped


def _expiry_status(days_left: int | None) -> str:
    if days_left is None:
        return "unknown"
    if days_left < 0:
        return "expired"
    if days_left <= 30:
        return "critical"
    if days_left <= 90:
        return "warning"
    return "healthy"


def scan(domain: str) -> dict:
    domain = domain.strip().lower().replace("https://", "").replace("http://", "").rstrip("/")

    whois_result = domain_intel.whois_lookup(domain)
    if whois_result["status"] != "ok":
        return whois_result

    w = whois_result["data"]
    raw_creation = w.get("_creation_date_raw")
    created = domain_intel._coerce_date(raw_creation)
    expires = domain_intel._coerce_date(w.get("expiration_date"))

    today = datetime.now(timezone.utc).date()
    age_days = (today - created).days if created else None
    days_until_expiry = (expires - today).days if expires else None

    age_block = domain_intel.domain_age_trivia(raw_creation)
    facts = age_block["data"]["facts"] if age_block["status"] == "ok" else []

    return ok(
        {
            "domain": domain,
            "registrar": w.get("registrar"),
            "org": w.get("org"),
            "registered_on": str(created) if created else None,
            "expires_on": str(expires) if expires else None,
            "age_days": age_days,
            "age_years": age_days // 365 if age_days is not None else None,
            "days_until_expiry": days_until_expiry,
            "expiry_status": _expiry_status(days_until_expiry),
            "status_codes": w.get("status"),
            "name_servers": w.get("name_servers"),
            "facts": facts,
        },
        source="webscan",
    )
