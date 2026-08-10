"""General-purpose security research utilities."""
from __future__ import annotations

import re

from config import settings
from modules.utils import http_session, ok, failed
from modules.threat import urlhaus_url_lookup, virustotal_hash

HASH_PATTERNS = [
    (re.compile(r"^[a-fA-F0-9]{32}$"), "MD5"),
    (re.compile(r"^[a-fA-F0-9]{40}$"), "SHA-1"),
    (re.compile(r"^[a-fA-F0-9]{64}$"), "SHA-256"),
    (re.compile(r"^[a-fA-F0-9]{96}$"), "SHA-384"),
    (re.compile(r"^[a-fA-F0-9]{128}$"), "SHA-512"),
]


def identify_hash(value: str) -> dict:
    value = value.strip()
    matches = [name for pattern, name in HASH_PATTERNS if pattern.match(value)]
    return ok({"value": value, "possible_types": matches or ["unknown / not a common hash length"]}, source="hash-id")


def hash_reputation(file_hash: str) -> dict:
    return ok({"virustotal": virustotal_hash(file_hash)}, source="tools.hash_reputation")


def mac_vendor(mac: str) -> dict:
    mac_clean = mac.strip()
    resp = http_session().get(f"https://api.macvendors.com/{mac_clean}", timeout=settings.request_timeout)
    if resp.status_code == 200:
        return ok({"mac": mac_clean, "vendor": resp.text}, source="macvendors.com")
    if resp.status_code == 404:
        return ok({"mac": mac_clean, "vendor": None}, source="macvendors.com")
    return failed(f"HTTP {resp.status_code}", source="macvendors.com")


def url_reputation(url: str) -> dict:
    return ok({"urlhaus": urlhaus_url_lookup(url)}, source="tools.url_reputation")


DORK_TEMPLATES = {
    "exposed_files": 'site:{d} (filetype:pdf OR filetype:docx OR filetype:xlsx OR filetype:sql OR filetype:log)',
    "login_pages": 'site:{d} (inurl:login OR inurl:admin OR inurl:signin)',
    "exposed_config": 'site:{d} (ext:env OR ext:yml OR ext:conf OR inurl:wp-config)',
    "indexed_directories": 'site:{d} intitle:"index of"',
    "error_messages": 'site:{d} ("SQL syntax" OR "stack trace" OR "warning: mysql")',
    "subdomains": 'site:*.{d} -site:www.{d}',
}


def generate_dorks(domain: str) -> dict:
    """Builds standard reconnaissance dork queries for a domain you're
    authorized to assess — this only constructs search-engine query strings,
    it doesn't execute anything against a target."""
    domain = domain.strip().lower()
    return ok({name: tmpl.format(d=domain) for name, tmpl in DORK_TEMPLATES.items()}, source="dork-generator")
