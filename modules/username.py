"""Username existence check across platforms.

Scope, deliberately: this answers "does a profile URL with this handle
respond?" via a HEAD/GET status check. It does NOT scrape bio text, avatars,
follower counts, or post content — that crosses from "does this handle
exist" into building a profile of a specific account holder, which this
project excludes on principle (see EXCLUDED_FEATURES.md).
"""
from __future__ import annotations

from config import settings
from modules.utils import http_session, ok, failed, parallel_map

# name -> URL template. Kept to platforms whose profile pages return a
# reliable 200/404 signal without needing auth.
PLATFORMS: dict[str, str] = {
    "GitHub": "https://github.com/{u}",
    "GitLab": "https://gitlab.com/{u}",
    "Reddit": "https://www.reddit.com/user/{u}/about.json",
    "Twitter/X": "https://x.com/{u}",
    "Instagram": "https://www.instagram.com/{u}/",
    "TikTok": "https://www.tiktok.com/@{u}",
    "Threads": "https://www.threads.net/@{u}",
    "YouTube": "https://www.youtube.com/@{u}",
    "Twitch": "https://www.twitch.tv/{u}",
    "Steam": "https://steamcommunity.com/id/{u}",
    "SoundCloud": "https://soundcloud.com/{u}",
    "Medium": "https://medium.com/@{u}",
    "Dev.to": "https://dev.to/{u}",
    "Behance": "https://www.behance.net/{u}",
    "Dribbble": "https://dribbble.com/{u}",
    "Vimeo": "https://vimeo.com/{u}",
    "Tumblr": "https://{u}.tumblr.com",
    "Keybase": "https://keybase.io/{u}",
    "HackerNews": "https://news.ycombinator.com/user?id={u}",
    "Patreon": "https://www.patreon.com/{u}",
    "Pinterest": "https://www.pinterest.com/{u}/",
    "Telegram": "https://t.me/{u}",
    "Facebook": "https://www.facebook.com/{u}",
    "Codepen": "https://codepen.io/{u}",
    "Replit": "https://replit.com/@{u}",
    "npm": "https://www.npmjs.com/~{u}",
    "PyPI": "https://pypi.org/user/{u}/",
    "Docker Hub": "https://hub.docker.com/u/{u}",
    "Product Hunt": "https://www.producthunt.com/@{u}",
    "Letterboxd": "https://letterboxd.com/{u}/",
}


def _check_one(name_url: tuple[str, str], username: str) -> dict:
    name, template = name_url
    url = template.format(u=username)
    try:
        resp = http_session().get(
            url, timeout=settings.request_timeout, allow_redirects=True
        )
        exists = resp.status_code == 200
        # Some sites (Reddit et al.) return 200 with a "not found" JSON body
        # instead of a real 404 — treat obviously tiny/error bodies as absent.
        if exists and len(resp.content) < 60:
            exists = False
        return {
            "platform": name,
            "url": url,
            "exists": exists,
            "status_code": resp.status_code,
        }
    except Exception as exc:  # noqa: BLE001
        return {"platform": name, "url": url, "exists": None, "error": str(exc)}


def hunt(username: str) -> dict:
    username = username.strip().lstrip("@")
    if not username:
        return failed("empty username")
    results = parallel_map(lambda kv: _check_one(kv, username), PLATFORMS.items())
    results.sort(key=lambda r: (r.get("exists") is not True, r["platform"]))
    found = [r for r in results if r.get("exists")]
    return ok(
        {
            "username": username,
            "checked": len(results),
            "found_count": len(found),
            "results": results,
        },
        source="username.hunt",
    )
