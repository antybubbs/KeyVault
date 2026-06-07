import json
import time
from dataclasses import dataclass
from urllib.error import URLError
from urllib.request import Request, urlopen
from app.core.config import get_settings

CACHE_SECONDS = 6 * 60 * 60


@dataclass
class VersionCache:
    checked_at: float = 0
    latest_version: str | None = None
    release_url: str | None = None


_cache = VersionCache()


def normalize_version(version: str) -> tuple[int, ...]:
    clean = version.strip().lower().removeprefix("v")
    parts: list[int] = []
    for part in clean.split("."):
        digits = ""
        for char in part:
            if not char.isdigit():
                break
            digits += char
        if digits:
            parts.append(int(digits))
    return tuple(parts)


def latest_release() -> tuple[str | None, str | None]:
    now = time.monotonic()
    if now - _cache.checked_at < CACHE_SECONDS:
        return _cache.latest_version, _cache.release_url

    settings = get_settings()
    request = Request(
        f"https://api.github.com/repos/{settings.github_repo}/releases/latest",
        headers={"Accept": "application/vnd.github+json", "User-Agent": "KeyVault"},
    )
    try:
        with urlopen(request, timeout=3) as response:
            data = json.loads(response.read().decode("utf-8"))
    except (OSError, TimeoutError, URLError, ValueError):
        _cache.checked_at = now
        _cache.latest_version = None
        _cache.release_url = None
        return None, None

    _cache.checked_at = now
    _cache.latest_version = data.get("tag_name")
    _cache.release_url = data.get("html_url")
    return _cache.latest_version, _cache.release_url


def version_status() -> dict[str, str | bool | None]:
    settings = get_settings()
    installed = settings.app_version
    latest, release_url = latest_release()
    update_available = False
    if latest and normalize_version(latest) and normalize_version(installed):
        update_available = normalize_version(latest) > normalize_version(installed)
    return {
        "installed": installed,
        "latest": latest,
        "release_url": release_url,
        "update_available": update_available,
    }
