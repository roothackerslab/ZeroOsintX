"""Geo-OSINT: place-level (not person-level) intelligence for a city name or
lat,lon. Carried over from the original ZeroOSINTx with the same free APIs.
"""
from __future__ import annotations

from config import settings
from modules.utils import http_session, ok, failed


def resolve_location(query: str) -> dict:
    if "," in query and all(p.strip().replace(".", "").replace("-", "").isdigit() for p in query.split(",", 1)):
        lat, lon = (float(p) for p in query.split(",", 1))
        return ok({"lat": lat, "lon": lon, "display_name": query}, source="input")
    try:
        resp = http_session().get(
            "https://nominatim.openstreetmap.org/search",
            params={"q": query, "format": "json", "limit": 1},
            timeout=settings.request_timeout,
        )
        if resp.status_code != 200 or not resp.json():
            return failed("location not found", source="nominatim")
        r = resp.json()[0]
        return ok({"lat": float(r["lat"]), "lon": float(r["lon"]), "display_name": r["display_name"]}, source="nominatim")
    except Exception as exc:  # noqa: BLE001
        return failed(str(exc), source="nominatim")


def weather(lat: float, lon: float) -> dict:
    try:
        resp = http_session().get(
            "https://api.open-meteo.com/v1/forecast",
            params={"latitude": lat, "longitude": lon, "current_weather": "true"},
            timeout=settings.request_timeout,
        )
        if resp.status_code != 200:
            return failed(f"HTTP {resp.status_code}", source="open-meteo")
        return ok(resp.json().get("current_weather", {}), source="open-meteo")
    except Exception as exc:  # noqa: BLE001
        return failed(str(exc), source="open-meteo")


def nearby_points_of_interest(lat: float, lon: float, radius: int = 1200) -> dict:
    categories = {
        "hospital": 'amenity=hospital', "police": 'amenity=police',
        "school": 'amenity=school', "bank": 'amenity=bank',
        "fuel": 'amenity=fuel', "hotel": 'tourism=hotel',
    }
    query_parts = "".join(f'node[{tag}](around:{radius},{lat},{lon});' for tag in categories.values())
    overpass_query = f"[out:json][timeout:10];({query_parts});out center 40;"
    try:
        resp = http_session().post(
            "https://overpass-api.de/api/interpreter", data={"data": overpass_query}, timeout=15
        )
        if resp.status_code != 200:
            return failed(f"HTTP {resp.status_code}", source="overpass")
        elements = resp.json().get("elements", [])
        grouped: dict[str, list[str]] = {c: [] for c in categories}
        for el in elements:
            tags = el.get("tags", {})
            name = tags.get("name", "Unnamed")
            for cat, tagexpr in categories.items():
                key, val = tagexpr.split("=")
                if tags.get(key) == val:
                    grouped[cat].append(name)
        return ok(grouped, source="overpass")
    except Exception as exc:  # noqa: BLE001
        return failed(str(exc), source="overpass")


def wikipedia_summary(query: str) -> dict:
    try:
        resp = http_session().get(
            f"https://en.wikipedia.org/api/rest_v1/page/summary/{query.replace(' ', '_')}",
            timeout=settings.request_timeout,
        )
        if resp.status_code != 200:
            return failed("no summary found", source="wikipedia")
        d = resp.json()
        return ok({"title": d.get("title"), "extract": d.get("extract")}, source="wikipedia")
    except Exception as exc:  # noqa: BLE001
        return failed(str(exc), source="wikipedia")


def crime_rate(lat: float, lon: float, display_name: str) -> dict:
    try:
        resp = http_session().get(
            "https://data.police.uk/api/crimes-street/all-crime",
            params={"lat": lat, "lng": lon}, timeout=settings.request_timeout,
        )
        if resp.status_code == 200:
            crimes = resp.json()
            categories: dict[str, int] = {}
            for c in crimes:
                cat = c.get("category", "other")
                categories[cat] = categories.get(cat, 0) + 1
            return ok({"total": len(crimes), "by_category": categories}, source="data.police.uk")
    except Exception as exc:  # noqa: BLE001
        return failed(str(exc), source="data.police.uk")
    city = display_name.split(",")[0].strip().replace(" ", "-")
    return ok({"numbeo_link": f"https://www.numbeo.com/crime/in/{city}"}, source="numbeo (no free UK-style API for this region)")


def earthquakes_recent() -> dict:
    try:
        resp = http_session().get(
            "https://earthquake.usgs.gov/earthquakes/feed/v1.0/summary/2.5_week.geojson",
            timeout=settings.request_timeout,
        )
        if resp.status_code != 200:
            return failed(f"HTTP {resp.status_code}", source="usgs")
        features = resp.json().get("features", [])[:10]
        return ok(
            [{"place": f["properties"]["place"], "mag": f["properties"]["mag"]} for f in features],
            source="usgs",
        )
    except Exception as exc:  # noqa: BLE001
        return failed(str(exc), source="usgs")


def mega_scan(location_query: str) -> dict:
    loc = resolve_location(location_query)
    if loc["status"] != "ok":
        return loc
    lat, lon, display_name = loc["data"]["lat"], loc["data"]["lon"], loc["data"]["display_name"]
    return ok(
        {
            "location": loc["data"],
            "weather": weather(lat, lon),
            "nearby": nearby_points_of_interest(lat, lon),
            "wikipedia": wikipedia_summary(location_query),
            "crime": crime_rate(lat, lon, display_name),
            "earthquakes_this_week": earthquakes_recent(),
        },
        source="geo.mega_scan",
    )
