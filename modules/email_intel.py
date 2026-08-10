"""Email OSINT: reputation + mail-security posture.

Scope: this is aimed at checking an address's security posture (does the
domain have SPF/DKIM/DMARC, is the address disposable, what's its public
reputation score) — the kind of thing you'd run on your own address or a
domain you administer. It reports HIBP's public *breach count* only (never
breach contents/passwords), and only when a key is configured.
"""
from __future__ import annotations

import hashlib
import re

import dns.resolver

from config import settings
from modules.utils import http_session, ok, skipped, failed

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

# Small, well-known sample of disposable-email domains. Not exhaustive by
# design — a full list is a cat-and-mouse blocklist better maintained by a
# dedicated service; this catches the obvious cases.
DISPOSABLE_DOMAINS = {
    "mailinator.com", "guerrillamail.com", "10minutemail.com", "tempmail.com",
    "throwawaymail.com", "yopmail.com", "trashmail.com", "fakeinbox.com",
    "getnada.com", "sharklasers.com", "dispostable.com",
}


def validate_format(email: str) -> dict:
    valid = bool(EMAIL_RE.match(email))
    return ok({"email": email, "syntactically_valid": valid}, source="email.format")


def gravatar(email: str) -> dict:
    h = hashlib.md5(email.strip().lower().encode()).hexdigest()
    url = f"https://www.gravatar.com/avatar/{h}?d=404"
    resp = http_session().get(url, timeout=settings.request_timeout)
    has_gravatar = resp.status_code == 200
    return ok({"has_gravatar": has_gravatar, "hash": h}, source="gravatar")


def emailrep(email: str) -> dict:
    resp = http_session().get(
        f"https://emailrep.io/{email}",
        headers={"Accept": "application/json"},
        timeout=settings.request_timeout,
    )
    if resp.status_code == 200:
        return ok(resp.json(), source="emailrep.io")
    if resp.status_code == 429:
        return skipped("rate limited", source="emailrep.io")
    return failed(f"HTTP {resp.status_code}", source="emailrep.io")


def hibp_breach_count(email: str) -> dict:
    if not settings.hibp_api_key:
        return skipped("no HIBP API key configured (ZOX_HIBP_KEY)", source="haveibeenpwned")
    resp = http_session().get(
        f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}",
        headers={"hibp-api-key": settings.hibp_api_key},
        timeout=settings.request_timeout,
    )
    if resp.status_code == 200:
        breaches = resp.json()
        return ok({"breach_count": len(breaches), "breach_names": [b["Name"] for b in breaches]}, source="haveibeenpwned")
    if resp.status_code == 404:
        return ok({"breach_count": 0, "breach_names": []}, source="haveibeenpwned")
    if resp.status_code == 429:
        return skipped("rate limited", source="haveibeenpwned")
    return failed(f"HTTP {resp.status_code}", source="haveibeenpwned")


def disposable_check(email: str) -> dict:
    domain = email.split("@")[-1].lower()
    return ok({"domain": domain, "likely_disposable": domain in DISPOSABLE_DOMAINS}, source="disposable-list")


def _txt_records(domain: str) -> list[str]:
    try:
        answers = dns.resolver.resolve(domain, "TXT", lifetime=settings.request_timeout)
        return ["".join(r.decode() if isinstance(r, bytes) else str(r) for r in rec.strings) for rec in answers]
    except Exception:
        return []


def mail_auth_records(domain: str) -> dict:
    try:
        mx = dns.resolver.resolve(domain, "MX", lifetime=settings.request_timeout)
        mx_hosts = sorted(str(r.exchange).rstrip(".") for r in mx)
    except Exception:
        mx_hosts = []

    spf = [t for t in _txt_records(domain) if t.lower().startswith("v=spf1")]
    dmarc = _txt_records(f"_dmarc.{domain}")
    # DKIM selector isn't standardized/discoverable without knowing the
    # selector the domain uses, so we just report common default selectors.
    dkim_found = []
    for selector in ("default", "google", "selector1", "selector2", "k1"):
        recs = _txt_records(f"{selector}._domainkey.{domain}")
        if recs:
            dkim_found.append({"selector": selector, "record": recs[0][:120]})

    return ok(
        {
            "domain": domain,
            "mx_records": mx_hosts,
            "spf": spf[0] if spf else None,
            "dmarc": dmarc[0] if dmarc else None,
            "dkim_selectors_found": dkim_found,
        },
        source="dns",
    )


def investigate(email: str) -> dict:
    email = email.strip()
    if not EMAIL_RE.match(email):
        return failed("not a syntactically valid email")
    domain = email.split("@")[-1]
    return ok(
        {
            "email": email,
            "format": validate_format(email)["data"],
            "gravatar": gravatar(email),
            "reputation": emailrep(email),
            "breach_summary": hibp_breach_count(email),
            "disposable": disposable_check(email),
            "domain_mail_security": mail_auth_records(domain),
        },
        source="email.investigate",
    )
