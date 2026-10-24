"""Passive JavaScript discovery with secret-safe output normalization."""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import parse_qsl, unquote, urlsplit, urlunsplit

from core.http import extract_js_urls, extract_urls, is_js_url, normalize_url
from core.module_base import ModuleBase, ResultSet
from core.scope import Scope
from core.util import content_hash, dedupe, host_of
from modules.common import (
    http_client,
    phase_settings,
    previous_rows,
    scoped_hosts,
    scoped_urls,
    target_url,
)

_SECRET_ASSIGNMENT_RE = re.compile(
    r"(?i)(?<![\w$])(?P<key>api[_-]?key|client[_-]?secret|access[_-]?token|auth[_-]?token|"
    r"token|secret|password|passwd|private[_-]?key)\b\s*[:=]\s*['\"`]"
    r"(?P<value>[^'\"`\s,;]{12,512})"
)
_SPECIAL_SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")),
)
_PRIVATE_KEY_RE = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")
_PLACEHOLDERS = {"changeme", "change_me", "your_api_key", "example", "placeholder", "undefined", "null", "none"}
_SENSITIVE_PATH_SEGMENTS = {
    "token", "access-token", "access_token", "secret", "api-key", "api_key", "password",
    "passwd", "reset", "reset-password", "reset_password", "auth",
}
_HIGH_ENTROPY_SEGMENT_RE = re.compile(r"^[A-Za-z0-9_-]{32,}$")
_QUERY_NAME_RE = re.compile(r"[?&]([A-Za-z0-9_.-]{1,100})=")


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
    segments = (parts.path or "/").split("/")
    clean_segments: list[str] = []
    redact_next = False
    for segment in segments:
        decoded = unquote(segment)
        if redact_next or _HIGH_ENTROPY_SEGMENT_RE.fullmatch(decoded):
            clean_segments.append("[redacted]")
            redact_next = False
            continue
        clean_segments.append(segment)
        redact_next = decoded.lower() in _SENSITIVE_PATH_SEGMENTS
    path = "/".join(clean_segments) or "/"
    return urlunsplit((parts.scheme, parts.netloc, path, "", ""))


def _query_names(url: str, text: str = "") -> list[str]:
    names = [name for name, _value in parse_qsl(urlsplit(url).query, keep_blank_values=True)]
    names.extend(match.group(1) for match in _QUERY_NAME_RE.finditer(text or ""))
    return dedupe(name for name in names if re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", name))


def _secret_types(text: str) -> dict[str, str]:
    """Return secret categories only; never return or retain matched values."""
    found: dict[str, str] = {}
    for match in _SECRET_ASSIGNMENT_RE.finditer(text or ""):
        value = match.group("value")
        normalized = value.lower().strip("._- ")
        if len(value) < 12 or normalized in _PLACEHOLDERS or len(set(value)) < 4:
            continue
        key = match.group("key").lower().replace("-", "_")
        category = "api_key" if "key" in key else "password" if "pass" in key else "secret" if "secret" in key else "token"
        found.setdefault(category, "medium")
    for category, pattern in _SPECIAL_SECRET_PATTERNS:
        if pattern.search(text or ""):
            found[category] = "high"
    if _PRIVATE_KEY_RE.search(text or ""):
        found["private_key"] = "high"
    return found


class Module(ModuleBase):
    name = "JavaScript recon"
    slug = "p09_js_recon"
    phase = 9
    description = "Discover scoped JavaScript, extract routes and record redacted secret indicators."
    requires_binaries: tuple[str, ...] = ()
    optional_binaries: tuple[str, ...] = ()
    is_passive = True
    supports_active = False
    tables = ("js_files", "endpoints", "parameters", "secrets_findings")

    def run(self, scope: Scope, config: dict[str, Any]) -> ResultSet:
        result = self.new_result()
        settings = phase_settings(config, self.phase)
        max_files = _bounded_int(settings.get("max_js_files"), 100, 1, 500)
        max_pages = _bounded_int(settings.get("max_pages"), 100, 1, 500)
        max_bytes = _bounded_int(settings.get("max_js_bytes"), 2 * 1024 * 1024, 4096, 4 * 1024 * 1024)
        max_endpoints = _bounded_int(settings.get("max_endpoints_per_file"), 500, 1, 1000)
        http = http_client(config)

        js_sources: dict[str, str] = {}
        for row in previous_rows(config, "js_files"):
            raw_url = str(row.get("url") or "")
            safe = _safe_url(raw_url)
            if safe and scope.allows(host_of(safe)) and is_js_url(safe):
                js_sources.setdefault(safe, "previously discovered JavaScript")
        for url in scoped_urls(scope, config, tables=("endpoints",), limit=max_files * 4):
            safe = _safe_url(url)
            if safe and is_js_url(safe) and scope.allows(host_of(safe)):
                js_sources.setdefault(safe, "previously discovered script endpoint")

        page_urls = scoped_urls(scope, config, tables=("http_hosts",), limit=max_pages * 2)
        if not page_urls:
            page_urls = [target_url(host) for host in scoped_hosts(
                scope, config, tables=("subdomains",), limit=max_pages
            ) if scope.allows(host)]
        for page_url in page_urls[:max_pages]:
            safe_page = _safe_url(page_url)
            if not safe_page or not scope.allows(host_of(safe_page)):
                continue
            if is_js_url(safe_page):
                js_sources.setdefault(safe_page, "script URL")
                continue
            response = http.get(safe_page, max_bytes=min(max_bytes, 512 * 1024))
            if response is None:
                continue
            page_final = normalize_url(str(getattr(response, "url", safe_page))) or safe_page
            if not scope.allows(host_of(page_final)):
                continue
            for script_url in extract_js_urls(getattr(response, "text", "") or "", page_final):
                safe_script = _safe_url(script_url)
                if safe_script and scope.allows(host_of(safe_script)):
                    js_sources.setdefault(safe_script, "script reference")
                    if len(js_sources) >= max_files:
                        break
            if len(js_sources) >= max_files:
                break

        scanned = 0
        for js_url, source_detail in list(js_sources.items())[:max_files]:
            if not scope.allows(host_of(js_url)) or not is_js_url(js_url):
                continue
            response = http.get(js_url, max_bytes=max_bytes)
            if response is None:
                continue
            status = getattr(response, "status_code", None)
            if status is None or status >= 400:
                continue
            final_url = _safe_url(str(getattr(response, "url", js_url))) or js_url
            host = host_of(final_url)
            if not scope.allows(host):
                continue
            body_bytes = getattr(response, "content", b"") or b""
            text = getattr(response, "text", "") or ""
            headers = getattr(response, "headers", {}) or {}
            result.add(
                "js_files",
                url=final_url,
                host=host,
                status_code=status,
                content_type=headers.get("content-type", ""),
                size=len(body_bytes),
                hash=content_hash(body_bytes),
                source_detail=source_detail,
                source_tool="builtin",
            )
            scanned += 1

            for name in _query_names(js_url, text)[:max_endpoints]:
                result.add(
                    "parameters",
                    url=final_url,
                    host=host,
                    name=name,
                    location="query",
                    source_tool="builtin",
                )

            for found_url in extract_urls(text, base=final_url, limit=max_endpoints):
                normalized = normalize_url(found_url)
                if not normalized or not scope.allows(host_of(normalized)):
                    continue
                for name in _query_names(normalized)[:max_endpoints]:
                    result.add(
                        "parameters",
                        url=_safe_url(normalized) or final_url,
                        host=host_of(normalized),
                        name=name,
                        location="query",
                        source_tool="builtin",
                    )
                safe_endpoint = _safe_url(normalized)
                if not safe_endpoint or is_js_url(safe_endpoint):
                    continue
                result.add(
                    "endpoints",
                    url=safe_endpoint,
                    host=host_of(safe_endpoint),
                    method="GET",
                    source_detail="route extracted from JavaScript",
                    source_tool="builtin",
                )

            if settings.get("scan_secrets", True):
                for secret_type, confidence in _secret_types(text).items():
                    result.add(
                        "secrets_findings",
                        url=final_url,
                        host=host,
                        secret_type=secret_type,
                        match_redacted="[REDACTED]",
                        confidence=confidence,
                        source_detail="secret-like value detected; value not retained",
                        source_tool="builtin",
                    )

        result.note(f"JavaScript files inspected: {scanned}; raw source and secret values were not stored.")
        return result
