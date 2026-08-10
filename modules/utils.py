"""Shared helpers used across every module: a pooled HTTP session, a uniform
result envelope, and a small parallel-map helper for scan modules."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Callable, Iterable, TypeVar

import requests

from config import settings

T = TypeVar("T")
R = TypeVar("R")

_session: requests.Session | None = None


def http_session() -> requests.Session:
    """A single pooled requests.Session, reused everywhere (connection reuse
    instead of a fresh TCP/TLS handshake per call)."""
    global _session
    if _session is None:
        s = requests.Session()
        s.headers.update({"User-Agent": settings.user_agent})
        _session = s
    return _session


def ok(data: Any, source: str | None = None) -> dict:
    return {"status": "ok", "data": data, "source": source}


def skipped(reason: str, source: str | None = None) -> dict:
    return {"status": "skipped", "reason": reason, "source": source}


def failed(reason: str, source: str | None = None) -> dict:
    return {"status": "error", "reason": reason, "source": source}


def safe_get(url: str, **kwargs) -> dict:
    """GET wrapped in try/except with a fixed timeout — a dead or slow API
    returns a `skipped`/`error` envelope instead of raising."""
    kwargs.setdefault("timeout", settings.request_timeout)
    try:
        resp = http_session().get(url, **kwargs)
        if resp.status_code == 200:
            return ok(resp)
        if resp.status_code == 429:
            return skipped(f"rate limited ({resp.status_code})")
        if resp.status_code in (401, 403):
            return skipped(f"auth required ({resp.status_code})")
        return failed(f"HTTP {resp.status_code}")
    except requests.exceptions.Timeout:
        return skipped("timed out")
    except requests.exceptions.RequestException as exc:
        return failed(str(exc))


def parallel_map(fn: Callable[[T], R], items: Iterable[T], max_workers: int | None = None) -> list[R]:
    """Run fn over items concurrently, preserving no particular order but
    collecting every result (exceptions become error envelopes)."""
    items = list(items)
    max_workers = max_workers or min(settings.max_worker_threads, max(1, len(items)))
    results: list[R] = []
    if not items:
        return results
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(fn, item): item for item in items}
        for future in as_completed(futures):
            try:
                results.append(future.result())
            except Exception as exc:  # noqa: BLE001 - module boundary, must not crash the scan
                results.append(failed(str(exc)))  # type: ignore[arg-type]
    return results


def timed(fn: Callable[[], R]) -> tuple[R, float]:
    start = time.perf_counter()
    result = fn()
    return result, round(time.perf_counter() - start, 3)
