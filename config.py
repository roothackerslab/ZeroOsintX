"""
ZeroOSINTx configuration.

All API keys are optional. Every module degrades gracefully (returns a
"skipped, no key configured" result) when a key is missing rather than
crashing.

Keys can come from two places, in this order of precedence:
  1. A key entered in the GUI's Settings panel (saved to instance/api_keys.local.json,
     which is gitignored — never committed).
  2. An environment variable (ZOX_HIBP_KEY, ZOX_VT_KEY, etc.), useful for
     server/headless deployments.
"""
from __future__ import annotations

import json
import os
import threading
from dataclasses import dataclass, field, fields

_LOCK = threading.Lock()
_INSTANCE_DIR = "instance"
_KEYS_FILE = os.path.join(_INSTANCE_DIR, "api_keys.local.json")

# key_field_name -> (env var name, display label, where to get a free key)
KEY_REGISTRY: dict[str, dict[str, str]] = {
    "hibp_api_key": {
        "env": "ZOX_HIBP_KEY", "label": "HaveIBeenPwned",
        "help": "email breach-count checks — key at haveibeenpwned.com/API/Key",
    },
    "virustotal_api_key": {
        "env": "ZOX_VT_KEY", "label": "VirusTotal",
        "help": "file hash reputation — free key at virustotal.com",
    },
    "abuseipdb_api_key": {
        "env": "ZOX_ABUSEIPDB_KEY", "label": "AbuseIPDB",
        "help": "IP abuse/reputation score — free key at abuseipdb.com",
    },
    "nvd_api_key": {
        "env": "ZOX_NVD_KEY", "label": "NVD (NIST)",
        "help": "higher CVE-feed rate limit — free key at nvd.nist.gov/developers/request-an-api-key",
    },
    "aisstream_api_key": {
        "env": "ZOX_AISSTREAM_KEY", "label": "AISstream",
        "help": "live ship/vessel radar — free key at aisstream.io",
    },
}


def _env(name: str) -> str | None:
    val = os.getenv(name, "").strip()
    return val or None


def _load_local_keys() -> dict[str, str]:
    if not os.path.exists(_KEYS_FILE):
        return {}
    try:
        with open(_KEYS_FILE) as f:
            return json.load(f)
    except Exception:
        return {}


def _save_local_keys(data: dict[str, str]) -> None:
    os.makedirs(_INSTANCE_DIR, exist_ok=True)
    with open(_KEYS_FILE, "w") as f:
        json.dump(data, f, indent=2)


@dataclass
class Settings:
    # --- Optional API keys (all free-tier services) ---
    hibp_api_key: str | None = field(default_factory=lambda: _env("ZOX_HIBP_KEY"))
    virustotal_api_key: str | None = field(default_factory=lambda: _env("ZOX_VT_KEY"))
    abuseipdb_api_key: str | None = field(default_factory=lambda: _env("ZOX_ABUSEIPDB_KEY"))
    nvd_api_key: str | None = field(default_factory=lambda: _env("ZOX_NVD_KEY"))
    aisstream_api_key: str | None = field(default_factory=lambda: _env("ZOX_AISSTREAM_KEY"))

    # --- Networking ---
    request_timeout: float = 6.0
    max_worker_threads: int = 16
    user_agent: str = "ZeroOSINTx/2.0 (+authorized-research)"

    # --- Paths ---
    reports_dir: str = "reports"

    # --- App ---
    host: str = "127.0.0.1"
    port: int = 8420
    debug: bool = False

    def __post_init__(self) -> None:
        # GUI-saved keys take precedence over env vars.
        for field_name, saved_value in _load_local_keys().items():
            if field_name in KEY_REGISTRY and saved_value:
                setattr(self, field_name, saved_value)


settings = Settings()


def key_status() -> list[dict]:
    """Public-safe view for the GUI: which keys are configured (never
    returns the actual key value) and where each came from."""
    local = _load_local_keys()
    out = []
    for field_name, meta in KEY_REGISTRY.items():
        value = getattr(settings, field_name)
        source = "gui" if local.get(field_name) else ("env" if _env(meta["env"]) else None)
        out.append(
            {
                "field": field_name,
                "label": meta["label"],
                "help": meta["help"],
                "configured": bool(value),
                "source": source,
            }
        )
    return out


def set_key(field_name: str, value: str) -> dict:
    if field_name not in KEY_REGISTRY:
        return {"ok": False, "error": f"unknown key field: {field_name}"}
    with _LOCK:
        local = _load_local_keys()
        value = value.strip()
        if value:
            local[field_name] = value
            setattr(settings, field_name, value)
        else:
            local.pop(field_name, None)
            setattr(settings, field_name, _env(KEY_REGISTRY[field_name]["env"]))
        _save_local_keys(local)
    return {"ok": True}
