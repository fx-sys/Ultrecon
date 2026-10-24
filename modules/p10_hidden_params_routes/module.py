"""Passive parameter extraction and strictly gated inert query probing."""

from __future__ import annotations

import re
import time
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from core.http import is_asset_url, is_js_url, normalize_url
from core.module_base import ModuleBase, ResultSet
from core.scope import Scope
from core.util import content_hash, dedupe, host_of
from modules.common import http_client, phase_settings, previous_rows

_SAFE_PARAMETER_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]{0,63}$")
_DEFAULT_PARAMETERS = (
    "page", "q", "search", "limit", "offset", "sort", "filter", "lang", "type",
    "category", "format", "view", "per_page", "start", "count", "order",
)
_FORBIDDEN_PARAMETER_RE = re.compile(
    r"(?i)(?:password|passwd|secret|token|auth|credential|cookie|session|api[_-]?key|^key$)"
)
_MUTATING_PATH_RE = re.compile(
    r"(?i)(?:^|/)(?:logout|signout|delete|remove|update|reset|execute|transfer|payment|"
    r"unsubscribe|toggle|publish|submit|login|signin|oauth|authorize)(?:/|$)"
)


def _bounded_int(value: Any, default: int, minimum: int, maximum: int) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError):
        number = default
    return max(minimum, min(number, maximum))


def _safe_url(url: str) -> str | None:
    normalized = normalize_url(url)
    if not normalized:
        return None
    parts = urlsplit(normalized)
    return urlunsplit((parts.scheme, parts.netloc, parts.path or "/", "", ""))


def _parameter_names(url: str) -> list[str]:
    try:
        pairs = parse_qsl(urlsplit(url).query, keep_blank_values=True, max_num_fields=200)
    except (ValueError, TypeError):
        return []
    names: list[str] = []
    for name, _value in pairs:
        if _SAFE_PARAMETER_RE.fullmatch(name) and name not in names:
            names.append(name)
    return names


def _safe_probe_name(value: Any) -> str | None:
    name = str(value).strip()
    if not _SAFE_PARAMETER_RE.fullmatch(name) or _FORBIDDEN_PARAMETER_RE.search(name):
        return None
    return name


def _signature(response: Any) -> tuple[Any, ...]:
    body = getattr(response, "content", b"") or b""
    headers = getattr(response, "headers", {}) or {}
    return (
        getattr(response, "status_code", None),
        str(headers.get("content-type", "")).split(";", 1)[0].lower(),
        len(body),
        content_hash(body),
    )


def _active_url(url: str) -> bool:
    path = urlsplit(url).path or "/"
    return not is_asset_url(url) and not is_js_url(url) and not _MUTATING_PATH_RE.search(path)


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


class Module(ModuleBase):
    name = "Hidden parameters & routes"
    slug = "p10_hidden_params_routes"
    phase = 10
    description = "Extract query names and optionally probe inert parameters after authorization."
    requires_binaries: tuple[str, ...] = ()
    optional_binaries: tuple[str, ...] = ()
    is_passive = False
    supports_active = True
    tables = ("parameters", "endpoints")

    def run(self, scope: Scope, config: dict[str, Any]) -> ResultSet:
        result = self.new_result()
        settings = phase_settings(config, self.phase)
        max_urls = _bounded_int(settings.get("max_urls"), 1000, 1, 5000)
        url_sources = ("endpoints", "js_files", "http_hosts")
        urls: list[str] = []
        known_names: dict[str, set[str]] = {}

        for table in url_sources:
            for row in previous_rows(config, table):
                raw_url = str(row.get("url") or "")
                normalized = normalize_url(raw_url)
                if not normalized:
                    continue
                host = host_of(normalized)
                if not host or not scope.allows(host):
                    continue
                safe = _safe_url(normalized)
                if not safe:
                    continue
                for name in _parameter_names(normalized):
                    result.add(
                        "parameters",
                        url=safe,
                        host=host,
                        name=name,
                        location="query",
                        source_tool="builtin",
                    )
                    known_names.setdefault(safe, set()).add(name.lower())
                if safe not in urls:
                    urls.append(safe)
                if len(urls) >= max_urls:
                    break
            if len(urls) >= max_urls:
                break

        for row in previous_rows(config, "parameters"):
            safe = _safe_url(str(row.get("url") or ""))
            name = _safe_probe_name(row.get("name"))
            host = host_of(safe or "")
            if safe and name and scope.allows(host):
                result.add(
                    "parameters",
                    url=safe,
                    host=host,
                    name=name,
                    location=str(row.get("location") or "query"),
                    source_tool="builtin",
                )
                known_names.setdefault(safe, set()).add(name.lower())
                if safe not in urls and len(urls) < max_urls:
                    urls.append(safe)

        run = config.get("_run") or {}
        if not (bool(run.get("active")) and bool(run.get("authorized"))):
            result.note("Active parameter probing was skipped; it requires both active mode and confirmed authorization.")
            result.note(f"In-scope URLs indexed for passive parameter extraction: {len(urls)}.")
            return result

        candidates_value = settings.get("active_parameters")
        candidate_values = list(candidates_value) if isinstance(candidates_value, (list, tuple)) else list(_DEFAULT_PARAMETERS)
        parameter_limit = _bounded_int(settings.get("max_params_per_url"), 50, 1, 50)
        active_url_limit = _bounded_int(settings.get("max_active_urls"), 25, 1, 100)
        request_limit = _bounded_int(settings.get("max_active_requests"), 250, 1, 500)
        candidates = dedupe(name for item in candidate_values if (name := _safe_probe_name(item)))[:parameter_limit]
        active_urls = [url for url in urls if scope.allows(host_of(url)) and _active_url(url)][:active_url_limit]
        if not candidates or not active_urls:
            result.note("No eligible in-scope URLs or safe query names were available for active probing.")
            return result

        http = http_client(config)
        pace = _Pacer(settings.get("min_interval_seconds", 0.5))
        max_bytes = _bounded_int(settings.get("max_response_bytes"), 64 * 1024, 1024, 256 * 1024)
        requests_made = 0
        rate_limited = False
        for url in active_urls:
            if requests_made >= request_limit:
                break
            pace.wait()
            baseline = http.get(url, max_bytes=max_bytes)
            requests_made += 1
            if baseline is None or getattr(baseline, "status_code", 0) in {401, 403, 429}:
                if baseline is not None and getattr(baseline, "status_code", None) == 429:
                    rate_limited = True
                    break
                continue
            baseline_status = getattr(baseline, "status_code", 0)
            if baseline_status >= 400:
                continue
            baseline_signature = _signature(baseline)
            tried_for_url = 0
            for name in candidates:
                if requests_made >= request_limit or tried_for_url >= parameter_limit:
                    break
                if name.lower() in known_names.get(url, set()):
                    continue
                query_url = f"{url}?{urlencode({name: 'ultrecon'})}"
                pace.wait()
                response = http.get(query_url, max_bytes=max_bytes)
                requests_made += 1
                tried_for_url += 1
                if response is None:
                    continue
                status = getattr(response, "status_code", None)
                if status == 429:
                    rate_limited = True
                    break
                if status is None or status >= 500 or status in {401, 403}:
                    continue
                if _signature(response) == baseline_signature:
                    continue
                result.add(
                    "parameters",
                    url=url,
                    host=host_of(url),
                    name=name,
                    location="query",
                    source_detail="authorized inert query-parameter probe",
                    source_tool="builtin",
                )
                known_names.setdefault(url, set()).add(name.lower())
            if rate_limited:
                break

        result.note(f"Authorized parameter-probe requests made: {requests_made}.")
        if rate_limited:
            result.note("Active parameter probing stopped after the target returned HTTP 429.")
        return result
