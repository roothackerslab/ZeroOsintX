"""EXIF metadata reader — a self-check utility.

Upload an image and see exactly what metadata is embedded in it (camera
make/model, timestamp, software, orientation, and GPS coordinates if
present). This is meant for checking your *own* photos before you post them
— e.g. "did my phone embed GPS coordinates in this picture" — not for
extracting metadata from someone else's images to locate them. It only ever
operates on a file the user explicitly uploads in this request; there is no
target/username/handle lookup here.
"""
from __future__ import annotations

from io import BytesIO

from modules.utils import ok, failed

try:
    from PIL import Image
    from PIL.ExifTags import TAGS, GPSTAGS
    HAVE_PIL = True
except ImportError:
    HAVE_PIL = False


def _convert_to_degrees(value) -> float:
    d, m, s = value
    return float(d) + float(m) / 60.0 + float(s) / 3600.0


def _gps_to_latlon(gps_info: dict) -> dict | None:
    try:
        lat = _convert_to_degrees(gps_info["GPSLatitude"])
        if gps_info.get("GPSLatitudeRef", "N") in ("S", "s"):
            lat = -lat
        lon = _convert_to_degrees(gps_info["GPSLongitude"])
        if gps_info.get("GPSLongitudeRef", "E") in ("W", "w"):
            lon = -lon
        return {"lat": round(lat, 6), "lon": round(lon, 6)}
    except (KeyError, TypeError, ZeroDivisionError):
        return None


def _jsonable(value):
    """EXIF values can be IFDRational, bytes, tuples of rationals, etc. —
    coerce to something json.dumps can handle without crashing."""
    if isinstance(value, bytes):
        try:
            return value.decode("utf-8", errors="replace").strip("\x00")
        except Exception:  # noqa: BLE001
            return repr(value)
    if isinstance(value, (tuple, list)):
        return [_jsonable(v) for v in value]
    if isinstance(value, dict):
        return {str(k): _jsonable(v) for k, v in value.items()}
    try:
        # IFDRational and similar support float()
        return float(value) if hasattr(value, "numerator") else value
    except Exception:  # noqa: BLE001
        return str(value)


def extract(file_bytes: bytes, filename: str = "upload") -> dict:
    """Reads EXIF metadata out of an uploaded image's raw bytes. Pure
    read-only inspection of the file the caller provided — no network calls,
    no lookup of anything beyond this one file."""
    if not HAVE_PIL:
        return failed("Pillow not installed — run: pip install Pillow", source="exif-tool")
    if not file_bytes:
        return failed("no file provided", source="exif-tool")

    try:
        img = Image.open(BytesIO(file_bytes))
        img.verify()
        img = Image.open(BytesIO(file_bytes))  # re-open: verify() consumes the parser
    except Exception as exc:  # noqa: BLE001
        return failed(f"not a readable image: {exc}", source="exif-tool")

    result = {
        "filename": filename,
        "format": img.format,
        "mode": img.mode,
        "width": img.width,
        "height": img.height,
        "size_bytes": len(file_bytes),
        "has_exif": False,
        "camera": {},
        "timestamps": {},
        "software": None,
        "orientation": None,
        "gps": None,
        "other_tags": {},
    }

    raw_exif = getattr(img, "_getexif", lambda: None)()
    if not raw_exif:
        return ok(result, source="exif-tool")

    result["has_exif"] = True
    tags = {}
    gps_info_raw = {}
    for tag_id, value in raw_exif.items():
        tag_name = TAGS.get(tag_id, str(tag_id))
        if tag_name == "GPSInfo" and isinstance(value, dict):
            for gps_id, gps_val in value.items():
                gps_info_raw[GPSTAGS.get(gps_id, str(gps_id))] = gps_val
            continue
        tags[tag_name] = _jsonable(value)

    result["camera"] = {
        "make": tags.pop("Make", None),
        "model": tags.pop("Model", None),
        "lens_model": tags.pop("LensModel", None),
    }
    result["timestamps"] = {
        "datetime_original": tags.pop("DateTimeOriginal", None),
        "datetime_digitized": tags.pop("DateTimeDigitized", None),
        "datetime": tags.pop("DateTime", None),
    }
    result["software"] = tags.pop("Software", None)
    result["orientation"] = tags.pop("Orientation", None)

    if gps_info_raw:
        result["gps"] = _gps_to_latlon(gps_info_raw) or {"raw": _jsonable(gps_info_raw)}

    # whatever's left over, keep as a flat "other tags" dump (skip binary blobs)
    result["other_tags"] = {
        k: v for k, v in tags.items()
        if isinstance(v, (str, int, float, list)) and k not in ("MakerNote", "UserComment")
    }

    return ok(result, source="exif-tool (local read — nothing sent anywhere)")
