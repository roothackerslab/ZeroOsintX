"""Phone number intelligence — metadata derivable from the number's format
itself (country, carrier block, line type, timezone). Deliberately excludes
WhatsApp/Telegram/Signal registration checks and CNAM/caller-ID lookups,
which exist specifically to tie a number to a real identity — see
EXCLUDED_FEATURES.md.
"""
from __future__ import annotations

from modules.utils import ok, failed, skipped

try:
    import phonenumbers
    from phonenumbers import carrier, geocoder, timezone as pn_timezone
    from phonenumbers import PhoneNumberType
    HAVE_PHONENUMBERS = True
except ImportError:
    HAVE_PHONENUMBERS = False

# phonenumbers.number_type() returns a plain int (PhoneNumberType has no
# real Enum, just int class attributes), so str(result) gives back a bare
# number like "1" instead of a readable name. Build the reverse lookup once.
_LINE_TYPE_NAMES = {}
if HAVE_PHONENUMBERS:
    _LINE_TYPE_NAMES = {
        value: name
        for name, value in vars(PhoneNumberType).items()
        if not name.startswith("_") and isinstance(value, int)
    }


def investigate(raw_number: str) -> dict:
    if not HAVE_PHONENUMBERS:
        return skipped("`phonenumbers` package not installed", source="phone.investigate")

    try:
        num = phonenumbers.parse(raw_number, None)
    except phonenumbers.NumberParseException as exc:
        return failed(f"could not parse number: {exc}")

    if not phonenumbers.is_valid_number(num):
        return ok({"valid": False, "raw": raw_number}, source="phone.investigate")

    return ok(
        {
            "valid": True,
            "e164": phonenumbers.format_number(num, phonenumbers.PhoneNumberFormat.E164),
            "international": phonenumbers.format_number(num, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
            "country_code": num.country_code,
            "region": geocoder.description_for_number(num, "en"),
            "carrier": carrier.name_for_number(num, "en") or None,
            "line_type": _LINE_TYPE_NAMES.get(phonenumbers.number_type(num), "UNKNOWN"),
            "possible_timezones": list(pn_timezone.time_zones_for_number(num)),
        },
        source="phone.investigate",
    )
