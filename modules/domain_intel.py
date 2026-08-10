"""Domain & infrastructure intelligence.

This targets infrastructure (a domain/host you administer or are assessing
with authorization), not a person — WHOIS, DNS, TLS posture, subdomains via
public Certificate Transparency logs (crt.sh), and basic security-header
hygiene. Standard, widely-used defensive-security checks.
"""
from __future__ import annotations

import socket
import ssl
from datetime import date, datetime, timezone

import dns.resolver

from config import settings
from modules.utils import http_session, ok, skipped, failed, parallel_map

try:
    import whois as pywhois
    HAVE_WHOIS = True
except ImportError:
    HAVE_WHOIS = False

try:
    from dateutil import parser as dateutil_parser
    HAVE_DATEUTIL = True
except ImportError:
    HAVE_DATEUTIL = False


# Public, well-known dates used only as fun size-of-reference points for the
# domain-age trivia below — no per-person data involved.
_MILESTONES: list[tuple[str, date]] = [
    ("Google was founded", date(1998, 9, 4)),
    ("Windows XP was released", date(2001, 10, 25)),
    ("Facebook was founded", date(2004, 2, 4)),
    ("YouTube launched", date(2005, 2, 14)),
    ("Twitter's first tweet", date(2006, 3, 21)),
    ("the first iPhone shipped", date(2007, 6, 29)),
    ("Bitcoin's genesis block was mined", date(2009, 1, 3)),
    ("the first iPad shipped", date(2010, 4, 3)),
    ("Instagram launched", date(2010, 10, 6)),
    ("ChatGPT's public launch", date(2022, 11, 30)),
]


def _coerce_date(value) -> date | None:
    """python-whois can hand back a datetime, a list of datetimes (some
    registrars report more than one), a plain string, or None depending on
    the TLD's WHOIS server. Normalize all of that into a single date."""
    if value is None:
        return None
    if isinstance(value, (list, tuple)):
        value = value[0] if value else None
        if value is None:
            return None
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, date):
        return value
    if isinstance(value, str):
        try:
            if HAVE_DATEUTIL:
                return dateutil_parser.parse(value).date()
            return datetime.fromisoformat(value.split("+")[0].strip()).date()
        except Exception:
            return None
    return None


def whois_lookup(domain: str) -> dict:
    if not HAVE_WHOIS:
        return failed("`python-whois` not installed", source="whois")
    try:
        w = pywhois.whois(domain, timeout=settings.request_timeout)
        return ok(
            {
                "registrar": w.registrar,
                "creation_date": str(w.creation_date),
                "expiration_date": str(w.expiration_date),
                "name_servers": w.name_servers,
                "status": w.status,
                "org": getattr(w, "org", None),
                "_creation_date_raw": w.creation_date,  # internal use by age_trivia; stripped before response
            },
            source="whois",
        )
    except Exception as exc:  # noqa: BLE001
        return failed(str(exc), source="whois")


def domain_age_trivia(creation_date_raw, birth_year: int | None = None) -> dict:
    """Fun, non-technical framing of WHOIS creation_date: how old the domain
    is and what well-known internet milestones it predates or postdates.
    `birth_year` is entirely optional and only used if the person chooses to
    type it in on the frontend — never inferred or assumed."""
    created = _coerce_date(creation_date_raw)
    if created is None:
        return skipped("no creation date available for this domain", source="domain-age-trivia")

    today = datetime.now(timezone.utc).date()
    age_days = (today - created).days
    if age_days < 0:
        return skipped("creation date is in the future (registrar reporting quirk)", source="domain-age-trivia")
    age_years = age_days // 365
    remainder_days = age_days % 365

    older_than = [label for label, d in _MILESTONES if created < d]
    younger_than = [label for label, d in _MILESTONES if created >= d]

    facts = [f"{age_years} years and {remainder_days} days old ({age_days} days total)"]
    if older_than:
        facts.append("Registered before: " + "; ".join(older_than[-3:]))
    if younger_than:
        facts.append("Registered after: " + "; ".join(younger_than[:2]))

    if birth_year:
        try:
            approx_birth = date(int(birth_year), 1, 1)
            if created < approx_birth:
                facts.append(f"Registered before you were born (~{(approx_birth - created).days // 365} years earlier) 👴")
            else:
                facts.append(f"You're older than this domain by about {(created - approx_birth).days // 365} years")
        except (TypeError, ValueError):
            pass

    return ok(
        {
            "registered_on": str(created),
            "age_days": age_days,
            "age_years": age_years,
            "older_than": older_than,
            "younger_than": younger_than,
            "facts": facts,
        },
        source="domain-age-trivia",
    )


def dns_records(domain: str) -> dict:
    out: dict[str, list[str]] = {}
    for rtype in ("A", "AAAA", "MX", "NS", "TXT", "CNAME"):
        try:
            answers = dns.resolver.resolve(domain, rtype, lifetime=settings.request_timeout)
            out[rtype] = [str(r).rstrip(".") for r in answers]
        except Exception:
            out[rtype] = []
    return ok(out, source="dns")


def ssl_certificate(domain: str, port: int = 443) -> dict:
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, port), timeout=settings.request_timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
        not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        days_left = (not_after - datetime.now(timezone.utc)).days
        issuer = dict(x[0] for x in cert.get("issuer", []))
        return ok(
            {
                "issuer": issuer.get("organizationName") or issuer.get("commonName"),
                "expires": cert["notAfter"],
                "days_until_expiry": days_left,
                "subject_alt_names": [v for k, v in cert.get("subjectAltName", []) if k == "DNS"],
            },
            source="tls",
        )
    except Exception as exc:  # noqa: BLE001
        return failed(str(exc), source="tls")


def subdomains_via_ct(domain: str) -> dict:
    """crt.sh queries public Certificate Transparency logs — this is data
    the domain owner already published by requesting a TLS cert; it's the
    standard, non-intrusive way to enumerate subdomains."""
    resp = http_session().get(
        f"https://crt.sh/?q=%25.{domain}&output=json", timeout=settings.request_timeout + 4
    )
    if resp.status_code != 200:
        return failed(f"HTTP {resp.status_code}", source="crt.sh")
    try:
        rows = resp.json()
    except Exception:
        return failed("could not parse crt.sh response", source="crt.sh")
    names = set()
    for row in rows:
        for name in row.get("name_value", "").split("\n"):
            name = name.strip().lstrip("*.")
            if name.endswith(domain):
                names.add(name)
    return ok({"count": len(names), "subdomains": sorted(names)[:200]}, source="crt.sh")


def security_headers(domain: str) -> dict:
    resp = http_session().get(f"https://{domain}", timeout=settings.request_timeout, allow_redirects=True)
    headers = resp.headers
    checklist = [
        "Strict-Transport-Security", "Content-Security-Policy",
        "X-Frame-Options", "X-Content-Type-Options",
        "Referrer-Policy", "Permissions-Policy",
    ]
    present = {h: headers.get(h) for h in checklist if h in headers}
    missing = [h for h in checklist if h not in headers]
    server_banner = headers.get("Server")
    powered_by = headers.get("X-Powered-By")
    return ok(
        {
            "present": present,
            "missing": missing,
            "server_banner": server_banner,
            "x_powered_by": powered_by,
        },
        source="security-headers",
    )


def robots_and_sitemap(domain: str) -> dict:
    robots = http_session().get(f"https://{domain}/robots.txt", timeout=settings.request_timeout)
    sitemap = http_session().get(f"https://{domain}/sitemap.xml", timeout=settings.request_timeout)
    return ok(
        {
            "robots_txt": robots.text[:2000] if robots.status_code == 200 else None,
            "sitemap_present": sitemap.status_code == 200,
        },
        source="robots/sitemap",
    )


def investigate(domain: str, birth_year: int | None = None) -> dict:
    domain = domain.strip().lower().replace("https://", "").replace("http://", "").rstrip("/")

    # Each of these is an independent network call — run them concurrently
    # instead of one after another so a slow/timing-out check (whois is the
    # usual culprit, up to 10s) doesn't stack with the others and make the
    # whole scan take a minute or more.
    checks = {
        "whois": lambda: whois_lookup(domain),
        "dns": lambda: dns_records(domain),
        "tls": lambda: ssl_certificate(domain),
        "subdomains": lambda: subdomains_via_ct(domain),
        "security_headers": lambda: security_headers(domain),
        "robots_sitemap": lambda: robots_and_sitemap(domain),
    }
    names = list(checks.keys())
    results = parallel_map(lambda name: checks[name](), names)
    by_name = dict(zip(names, results))

    whois_result = by_name["whois"]
    raw_creation = None
    if whois_result["status"] == "ok":
        raw_creation = whois_result["data"].pop("_creation_date_raw", None)

    return ok(
        {
            "domain": domain,
            "whois": whois_result,
            "age_trivia": domain_age_trivia(raw_creation, birth_year=birth_year),
            "dns": by_name["dns"],
            "tls": by_name["tls"],
            "subdomains": by_name["subdomains"],
            "security_headers": by_name["security_headers"],
            "robots_sitemap": by_name["robots_sitemap"],
        },
        source="domain.investigate",
    )
