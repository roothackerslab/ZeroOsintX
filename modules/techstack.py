"""CMS / tech-stack fingerprinting.

Fetches a single homepage response for a domain and matches its headers,
cookies, and HTML against a small signature set (CMS platforms, ecommerce
platforms, JS frameworks/libraries, analytics, CDNs, web servers,
languages). One GET request — no crawling, no per-page enumeration. Same
scope as the rest of domain_intel: infrastructure you administer or are
assessing with authorization, not a person.
"""
from __future__ import annotations

import re

from config import settings
from modules.utils import http_session, ok, failed

# Each signature: (name, category, [regex-on-lowercased-html], [(header_name, value_regex)], [cookie_name_substring])
# A match on ANY of its checks counts as a detection.
SIGNATURES: list[dict] = [
    # --- CMS ---
    {"name": "WordPress", "category": "cms", "html": [r"wp-content/|wp-includes/", r'generator["\']?\s*content=["\']wordpress'], "headers": [("link", r"wp-json")]},
    {"name": "Drupal", "category": "cms", "html": [r"drupal\.settings", r'generator["\']?\s*content=["\']drupal'], "headers": [("x-drupal-cache", r".*"), ("x-generator", r"drupal")]},
    {"name": "Joomla", "category": "cms", "html": [r"/media/jui/", r'generator["\']?\s*content=["\']joomla']},
    {"name": "Wix", "category": "cms", "html": [r"static\.wixstatic\.com"], "headers": [("x-wix-request-id", r".*")]},
    {"name": "Squarespace", "category": "cms", "html": [r"squarespace\.com"], "headers": [("server", r"squarespace")]},
    {"name": "Webflow", "category": "cms", "html": [r"webflow\.com", r'generator["\']?\s*content=["\']webflow']},
    {"name": "Ghost", "category": "cms", "html": [r'generator["\']?\s*content=["\']ghost']},

    # --- Ecommerce ---
    {"name": "Shopify", "category": "ecommerce", "html": [r"cdn\.shopify\.com"], "headers": [("x-shopify-stage", r".*")]},
    {"name": "WooCommerce", "category": "ecommerce", "html": [r"woocommerce"]},
    {"name": "Magento", "category": "ecommerce", "html": [r"mage\.cookies", r"/skin/frontend/"]},
    {"name": "BigCommerce", "category": "ecommerce", "html": [r"cdn\d*\.bigcommerce\.com"]},

    # --- Frameworks ---
    {"name": "Next.js", "category": "framework", "html": [r"__next_data__", r"/_next/static/"]},
    {"name": "Nuxt.js", "category": "framework", "html": [r"__nuxt__", r"/_nuxt/"]},
    {"name": "Express", "category": "framework", "headers": [("x-powered-by", r"express")]},
    {"name": "ASP.NET", "category": "framework", "headers": [("x-powered-by", r"asp\.net"), ("x-aspnet-version", r".*")]},
    {"name": "Django", "category": "framework", "headers": [("x-frame-options", r"sameorigin.*django")], "html": [r"csrfmiddlewaretoken"]},
    {"name": "Laravel", "category": "framework", "html": [r"laravel_session"]},
    {"name": "Ruby on Rails", "category": "framework", "headers": [("x-powered-by", r"phusion passenger")], "html": [r"csrf-param"]},

    # --- JS libraries ---
    {"name": "React", "category": "javascript_library", "html": [r"data-reactroot", r"react-dom"]},
    {"name": "Vue.js", "category": "javascript_library", "html": [r"__vue__|vue\.js|vue\.min\.js"]},
    {"name": "Angular", "category": "javascript_library", "html": [r"ng-version"]},
    {"name": "jQuery", "category": "javascript_library", "html": [r"jquery(?:-|\.)([0-9.]+)?(?:\.min)?\.js"]},
    {"name": "Alpine.js", "category": "javascript_library", "html": [r"alpinejs|x-data="]},

    # --- CSS frameworks ---
    {"name": "Bootstrap", "category": "css_framework", "html": [r"bootstrap(?:\.min)?\.css|bootstrap(?:\.min)?\.js"]},
    {"name": "Tailwind CSS", "category": "css_framework", "html": [r"tailwind(?:\.min)?\.css|tailwindcss"]},

    # --- Analytics / marketing ---
    {"name": "Google Analytics", "category": "analytics", "html": [r"google-analytics\.com/analytics\.js|gtag\(['\"]config"]},
    {"name": "Google Tag Manager", "category": "analytics", "html": [r"googletagmanager\.com/gtm\.js"]},
    {"name": "Meta Pixel", "category": "analytics", "html": [r"connect\.facebook\.net.*fbevents\.js"]},
    {"name": "HubSpot", "category": "marketing", "html": [r"js\.hs-scripts\.com|hubspot"]},
    {"name": "Hotjar", "category": "analytics", "html": [r"static\.hotjar\.com"]},

    # --- Payments / security widgets ---
    {"name": "Stripe", "category": "payment", "html": [r"js\.stripe\.com"]},
    {"name": "PayPal", "category": "payment", "html": [r"paypal\.com/sdk/js"]},
    {"name": "reCAPTCHA", "category": "security", "html": [r"google\.com/recaptcha|gstatic\.com/recaptcha"]},
    {"name": "Cloudflare Turnstile", "category": "security", "html": [r"challenges\.cloudflare\.com/turnstile"]},

    # --- CDN / edge ---
    {"name": "Cloudflare", "category": "cdn", "headers": [("cf-ray", r".*"), ("server", r"cloudflare")]},
    {"name": "Amazon CloudFront", "category": "cdn", "headers": [("x-amz-cf-id", r".*"), ("via", r"cloudfront")]},
    {"name": "Fastly", "category": "cdn", "headers": [("x-served-by", r"cache-"), ("via", r"varnish")]},
    {"name": "Akamai", "category": "cdn", "headers": [("server", r"akamaighost")]},

    # --- Web servers / languages ---
    {"name": "Nginx", "category": "web_server", "headers": [("server", r"nginx")]},
    {"name": "Apache", "category": "web_server", "headers": [("server", r"apache")]},
    {"name": "Microsoft IIS", "category": "web_server", "headers": [("server", r"microsoft-iis")]},
    {"name": "LiteSpeed", "category": "web_server", "headers": [("server", r"litespeed")]},
    {"name": "PHP", "category": "programming_language", "headers": [("x-powered-by", r"php")]},
]

_GENERATOR_RE = re.compile(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']', re.IGNORECASE)
_JQUERY_VERSION_RE = re.compile(r"jquery[-.]([0-9]+\.[0-9]+\.[0-9]+)", re.IGNORECASE)


def _normalize_url(target: str) -> str:
    target = target.strip()
    if not re.match(r"^https?://", target, re.IGNORECASE):
        target = f"https://{target}"
    return target.rstrip("/")


def fingerprint(target: str) -> dict:
    url = _normalize_url(target)
    try:
        resp = http_session().get(url, timeout=settings.request_timeout, allow_redirects=True)
    except Exception as exc:  # noqa: BLE001
        return failed(str(exc), source="techstack")

    if resp.status_code >= 400:
        return failed(f"HTTP {resp.status_code}", source="techstack")

    headers = {k.lower(): v for k, v in resp.headers.items()}
    html = resp.text.lower() if resp.text else ""
    cookies = list(resp.cookies.keys())

    detected: list[dict] = []
    for sig in SIGNATURES:
        hit = False
        for pattern in sig.get("html", []):
            if re.search(pattern, html, re.IGNORECASE):
                hit = True
                break
        if not hit:
            for header_name, value_pattern in sig.get("headers", []):
                value = headers.get(header_name)
                if value and re.search(value_pattern, value, re.IGNORECASE):
                    hit = True
                    break
        if not hit:
            for cookie_substr in sig.get("cookies", []):
                if any(cookie_substr.lower() in c.lower() for c in cookies):
                    hit = True
                    break
        if hit:
            detected.append({"name": sig["name"], "category": sig["category"]})

    by_category: dict[str, list[str]] = {}
    for d in detected:
        by_category.setdefault(d["category"], []).append(d["name"])

    generator_match = _GENERATOR_RE.search(resp.text or "")
    jquery_version_match = _JQUERY_VERSION_RE.search(html)

    return ok(
        {
            "url": url,
            "final_url": resp.url,
            "status_code": resp.status_code,
            "server_header": headers.get("server"),
            "x_powered_by": headers.get("x-powered-by"),
            "generator_meta_tag": generator_match.group(1) if generator_match else None,
            "jquery_version": jquery_version_match.group(1) if jquery_version_match else None,
            "detected_count": len(detected),
            "detected": detected,
            "by_category": by_category,
        },
        source="techstack",
    )
