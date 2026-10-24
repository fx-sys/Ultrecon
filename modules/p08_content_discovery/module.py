"""Authorization-gated, low-rate content path discovery."""

from __future__ import annotations

import hashlib
import re
import time
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlsplit, urlunsplit

from core.http import normalize_url
from core.module_base import ModuleBase, ResultSet
from core.paths import resolve_path
from core.scope import Scope
from core.util import content_hash, dedupe, host_of
from modules.common import http_client, phase_settings, scoped_hosts, scoped_urls, target_url

_SAFE_WORD_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._~-]{0,79}$")
_DEFAULT_WORDS = (
    "api", "assets", "backup", "config", "docs", "health", "images", "login",
    "robots.txt", "search", "static", "status", "sitemap.xml", "uploads", "version",
)


def _bounded_int(value: Any, default: int, minimum: int, maximum: int) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError):
        number = default
    return max(minimum, min(number, maximum))


def _root(url: str, host: str) -> str | None:
    normalized = normalize_url(url)
    if not normalized or host_of(normalized) != host:
        return None
    parts = urlsplit(normalized)
    return urlunsplit((parts.scheme, parts.netloc, "/", "", ""))


def _load_words(settings: dict[str, Any], config: dict[str, Any], limit: int) -> list[str]:
    values: list[str] = []
    for key in ("wordlist", "fallback_wordlist"):
        value = settings.get(key)
        if not value:
            continue
        try:
            path = resolve_path(str(value))
            if not Path(path).is_file():
                continue
            with Path(path).open("r", encoding="utf-8", errors="replace") as handle:
                values.extend(
                    line.strip()
                    for _, line in zip(
                        range(min(limit * 4, 20000)), handle, strict=False
                    )
                )
            if values:
                break
        except OSError:
            continue
    if not values:
        values = list(_DEFAULT_WORDS)

    words: list[str] = []
    for value in values:
        word = value.strip().strip("/")
        if _SAFE_WORD_RE.fullmatch(word) and word not in {".", ".."} and word not in words:
            words.append(word)
        if len(words) >= limit:
            break
    return words


def _candidate_paths(settings: dict[str, Any], config: dict[str, Any], limit: int) -> list[str]:
    words = _load_words(settings, config, limit)
    extensions_value = settings.get("extensions", [])
    extensions: list[str] = []
    if isinstance(extensions_value, (list, tuple)):
        for value in extensions_value:
            extension = str(value).strip().lstrip(".").lower()
            if re.fullmatch(r"[a-z0-9]{1,10}", extension) and extension not in extensions:
                extensions.append(extension)
    candidates: list[str] = []
    for word in words:
        candidates.append(word)
        if "." not in word:
            candidates.extend(f"{word}.{extension}" for extension in extensions)
        if len(candidates) >= limit:
            break
    return dedupe(candidates)[:limit]


class _Pacer:
    def __init__(self, interval: float) -> None:
        self.interval = max(0.25, min(float(interval), 5.0))
        self.next_at = 0.0

    def wait(self) -> None:
        now = time.monotonic()
        if now < self.next_at:
            time.sleep(self.next_at - now)
            now = time.monotonic()
        self.next_at = now + self.interval


def _signature(response: Any) -> tuple[Any, ...]:
    body = getattr(response, "content", b"") or b""
    headers = getattr(response, "headers", {}) or {}
    return (
        getattr(response, "status_code", None),
        str(headers.get("content-type", "")).split(";", 1)[0].lower(),
        len(body),
        content_hash(body),
    )


class Module(ModuleBase):
    name = "Content discovery"
    slug = "p08_content_discovery"
    phase = 8
    description = "Probe a bounded path list using safe GET requests after authorization."
    requires_binaries: tuple[str, ...] = ()
    optional_binaries: tuple[str, ...] = ()
    is_passive = False
    active_only = True
    supports_active = True
    tables = ("endpoints",)

    def run(self, scope: Scope, config: dict[str, Any]) -> ResultSet:
        result = self.new_result()
        run = config.get("_run") or {}
        if not (bool(run.get("active")) and bool(run.get("authorized"))):
            result.note("Content discovery was skipped; it requires both active mode and confirmed authorization.")
            return result

        settings = phase_settings(config, self.phase)
        max_paths = _bounded_int(settings.get("max_paths"), 2000, 1, 5000)
        max_hosts = _bounded_int(settings.get("max_hosts"), 50, 1, 500)
        words = _candidate_paths(settings, config, max_paths)
        if not words:
            result.note("No valid content-discovery paths were available.")
            return result

        urls = scoped_urls(scope, config, tables=("http_hosts",), limit=max_hosts * 2)
        roots_by_host: dict[str, str] = {}
        for url in urls:
            host = host_of(url)
            if host and scope.allows(host):
                roots_by_host.setdefault(host, _root(url, host) or url)
        for host in scoped_hosts(scope, config, tables=("http_hosts", "subdomains"), limit=max_hosts):
            if scope.allows(host):
                roots_by_host.setdefault(host, target_url(host))
        roots = list(roots_by_host.items())[:max_hosts]
        if not roots:
            result.note("No in-scope web hosts were available for content discovery.")
            return result

        http = http_client(config)
        pace = _Pacer(settings.get("min_interval_seconds", 0.5))
        response_bytes = _bounded_int(settings.get("max_response_bytes"), 64 * 1024, 1024, 256 * 1024)
        requests_made = 0
        stopped_on_rate_limit = False
        for host, root in roots:
            if not scope.allows(host) or not scope.allows(host_of(root)):
                continue
            token = hashlib.sha256(host.encode("utf-8")).hexdigest()[:10]
            control_url = normalize_url(f"{root.rstrip('/')}/.ultrecon-missing-{token}")
            if not control_url:
                continue
            pace.wait()
            control = http.get(control_url, max_bytes=response_bytes)
            requests_made += 1
            control_signature = _signature(control) if control is not None else None

            for path in words:
                if requests_made >= max_paths + len(roots):
                    break
                candidate_url = normalize_url(f"{root.rstrip('/')}/{quote(path, safe='._~-')}")
                if not candidate_url or not scope.allows(host_of(candidate_url)):
                    continue
                pace.wait()
                response = http.get(candidate_url, max_bytes=response_bytes)
                requests_made += 1
                if response is None:
                    continue
                status = getattr(response, "status_code", None)
                if status == 429:
                    stopped_on_rate_limit = True
                    break
                if status is None or status >= 500 or status == 404:
                    continue
                if control_signature is not None and _signature(response) == control_signature:
                    continue
                headers = getattr(response, "headers", {}) or {}
                result.add(
                    "endpoints",
                    url=candidate_url,
                    host=host,
                    method="GET",
                    status_code=status,
                    content_type=headers.get("content-type", ""),
                    source_detail="authorized bounded content discovery",
                    source_tool="builtin",
                )
            if stopped_on_rate_limit:
                break

        result.note(f"Content-discovery requests made: {requests_made}.")
        if stopped_on_rate_limit:
            result.note("Content discovery stopped after the target returned HTTP 429.")
        return result
