# ZeroOSINTx v2.0

**by Mughal_hacker · roothackerslab**

A modular OSINT/security-research toolkit with a terminal-styled web dashboard.
Rebuilt from the original single-file CLI into a proper package: a Flask
backend, one module per intel category, and a browser GUI instead of a menu
loop.

> ⚠️ **Authorized use only.** This tool is built for checking your own
> accounts/domains/infrastructure, or targets you have explicit permission to
> assess. See `EXCLUDED_FEATURES.md` for what was deliberately left out and
> why — several items from the original feature wishlist cross from "OSINT"
> into person-tracking and were cut on purpose, not by oversight.

## What's here

| Module | What it does |
|---|---|
| **Username** | Checks handle existence across 30 platforms (presence only, no scraping) |
| **Email** | Gravatar, EmailRep reputation, HIBP breach *count* (key optional), disposable-domain check, SPF/DKIM/DMARC |
| **Phone** | Carrier, region, line type, timezone from number format |
| **Domain** | WHOIS, DNS records, TLS cert, subdomains via crt.sh (CT logs), security headers, robots/sitemap |
| **IP** | Geolocation, ASN/ISP, reverse DNS, DNSBL blacklist status, AbuseIPDB (key optional) |
| **Geo scan** | Weather, nearby amenities, Wikipedia summary, UK street-crime stats, recent earthquakes |
| **Threat feed** | ThreatFox IOCs, URLhaus malicious URLs, NVD recent CVEs |
| **Fun realtime** | ISS position, planes overhead (OpenSky), ships overhead (AISstream, key optional), live weather radar / night-lights links, NOAA space weather |
| **Tools** | Hash identifier, VirusTotal hash reputation, MAC vendor lookup, URLhaus URL reputation, Google dork generator |

Every module returns a uniform envelope (`ok` / `skipped` / `error`) so a
dead or rate-limited API degrades gracefully instead of crashing a scan.
Reports export to HTML, JSON, CSV, or Markdown from the dashboard.

## Install

```bash
pip install -r requirements.txt
```

## Run

```bash
python main.py
```

Open **http://127.0.0.1:8420**.

## API keys

None are required — everything works with free/keyless APIs out of the box.
Open the ⚙ **settings** button (bottom of the sidebar) in the dashboard to
paste in free keys for the optional modules (HaveIBeenPwned, VirusTotal,
AbuseIPDB, NVD, AISstream). Keys are saved locally to
`instance/api_keys.local.json`, which is gitignored — they never leave your
machine except to call that key's own API.

Environment variables still work too, if you'd rather set them outside the
GUI (useful for headless/server runs): `ZOX_HIBP_KEY`, `ZOX_VT_KEY`,
`ZOX_ABUSEIPDB_KEY`, `ZOX_NVD_KEY`, `ZOX_AISSTREAM_KEY`. A key saved in the
GUI takes precedence over the matching environment variable.

## Project structure

```
ZeroOSINTx/
├── main.py                # Flask app + API routes
├── config.py               # settings, API keys from env
├── modules/
│   ├── utils.py             # shared HTTP session, result envelope, thread pool
│   ├── username.py
│   ├── email_intel.py
│   ├── phone_intel.py
│   ├── domain_intel.py
│   ├── ip_intel.py
│   ├── geo.py
│   ├── threat.py
│   ├── fun_realtime.py
│   ├── tools.py
│   └── reports.py           # HTML/JSON/CSV/Markdown export
├── templates/index.html
├── static/{style.css,app.js}
├── instance/                # created at runtime; holds your saved API keys (gitignored)
└── reports/                 # exports land here
```

## License

See `LICENSE`.
