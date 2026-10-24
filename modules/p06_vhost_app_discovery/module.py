"""HTTP inventory and authorization-gated virtual-host discovery."""

from __future__ import annotations

import re
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from core.http import detect_tech, extract_title, normalize_url, server_from_headers
from core.module_base import ModuleBase, ResultSet
from core.paths import resolve_path
from core.scope import Scope
from core.util import content_hash, host_of
from modules.common import http_client, phase_settings, previous_rows, scoped_hosts, target_url

_WORD_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$", re.IGNORECASE)
_DEFAULT_VHOSTS = ("www", "api", "app", "dev", "staging", "portal", "test", "cdn")


def _bounded_int(value: Any, default: int, minimum: int, maximum: int) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError):
        number = default
    return max(minimum, min(number, maximum))


def _signature(response: Any) -> tuple[Any, ...]:
    body = getattr(response, "content", b"") or b""
    headers = getattr(response, "headers", {}) or {}
    return (
        getattr(response, "status_code", None),
        str(headers.get("content-type", "")).split(";", 1)[0].lower(),
        len(body),
        content_hash(body),
    )


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


def _vhost_words(settings: dict[str, Any], config: dict[str, Any], limit: int) -> list[str]:
    values: list[str] = []
    configured = settings.get("vhost_candidates")
    if isinstance(configured, (list, tuple)):
        values.extend(str(item) for item in configured)
    else:
        wordlist = settings.get("vhost_wordlist")
        if wordlist:
            try:
                path = resolve_path(str(wordlist))
                with Path(path).open("r", encoding="utf-8", errors="replace") as handle:
                    values.extend(
                        line.strip()
                        for _, line in zip(range(limit * 4), handle, strict=False)
                    )
            except OSError:
                values = []
    if not values:
        values = list(_DEFAULT_VHOSTS)

    words: list[str] = []
    for value in values:
        word = value.strip().lower().rstrip(".")
        if _WORD_RE.fullmatch(word) and word not in words:
            words.append(word)
        if len(words) >= limit:
            break
    return words


def _root_url(url: str, host: str) -> str | None:
    normalized = normalize_url(url)
    if not normalized:
        return None
    parts = urlsplit(normalized)
    netloc = parts.netloc
    if host_of(normalized) != host:
        return None
    return urlunsplit((parts.scheme, netloc, "/", "", ""))


class Module(ModuleBase):
    name = "Virtual hosts & app discovery"
    slug = "p06_vhost_app_discovery"
    phase = 6
    description = "Inventory in-scope web applications and optionally fuzz vhosts when authorized."
    requires_binaries: tuple[str, ...] = ()
    optional_binaries: tuple[str, ...] = ()
    is_passive = False
    supports_active = True
    tables = ("http_hosts", "endpoints")

    def run(self, scope: Scope, config: dict[str, Any]) -> ResultSet:
        result = self.new_result()
        settings = phase_settings(config, self.phase)
        http = http_client(config)
        max_hosts = _bounded_int(settings.get("max_hosts"), 200, 1, 2000)
        previous = previous_rows(config, "http_hosts")
        by_host: dict[str, list[dict[str, Any]]] = {}
        for row in previous:
            host = str(row.get("host") or host_of(str(row.get("url") or ""))).lower().rstrip(".")
            if host and scope.allows(host):
                by_host.setdefault(host, []).append(row)

        hosts = [host for host in scoped_hosts(
            scope, config, tables=("http_hosts", "subdomains", "ips"), limit=max_hosts
        ) if scope.allows(host)]
        roots: dict[str, str] = {}
        baseline: dict[str, tuple[Any, ...]] = {}
        max_bytes = _bounded_int(settings.get("max_bytes"), 256 * 1024, 4096, 2 * 1024 * 1024)
        for host in hosts:
            urls = by_host.get(host) or []
            url = None
            for row in urls:
                url = _root_url(str(row.get("url") or ""), host)
                if url:
                    break
            root = url or target_url(host)
            if not scope.allows(host) or not scope.allows(host_of(root)):
                continue
            roots[host] = root
            response = http.get(root, max_bytes=max_bytes)
            if response is None:
                continue
            final_url = normalize_url(str(getattr(response, "url", root))) or root
            final_host = host_of(final_url)
            if not scope.allows(final_host):
                continue
            body = getattr(response, "text", "") or ""
            headers = dict(getattr(response, "headers", {}) or {})
            tech = detect_tech(headers, body) if settings.get("tech_signatures", True) else []
            result.add(
                "http_hosts",
                url=final_url,
                host=final_host,
                status_code=getattr(response, "status_code", None),
                title=extract_title(body),
                server=server_from_headers(headers),
                tech=", ".join(tech),
                content_length=len(getattr(response, "content", b"") or b""),
                redirect_url=final_url if final_url != root else None,
                screenshot=next((str(row.get("screenshot")) for row in urls if row.get("screenshot")), None),
                source_tool="builtin",
            )
            result.add(
                "endpoints",
                url=final_url,
                host=final_host,
                method="GET",
                status_code=getattr(response, "status_code", None),
                content_type=headers.get("content-type", ""),
                source_detail="p06 HTTP inventory",
                source_tool="builtin",
            )
            baseline[host] = _signature(response)

        if settings.get("screenshots"):
            result.note("Screenshot capture was requested, but no screenshot engine is bundled; HTTP inventory was collected instead.")

        run = config.get("_run") or {}
        active_authorized = bool(run.get("active")) and bool(run.get("authorized"))
        if not settings.get("vhost_fuzz"):
            return result
        if not active_authorized:
            result.note("Vhost fuzzing was skipped; it requires both active mode and confirmed authorization.")
            return result

        candidate_limit = _bounded_int(settings.get("max_vhosts"), 40, 1, 200)
        words = _vhost_words(settings, config, candidate_limit)
        pace = _Pacer(settings.get("min_interval_seconds", 0.5))
        attempts = 0
        for host, root in roots.items():
            if attempts >= candidate_limit or host not in baseline:
                continue
            for word in words:
                if attempts >= candidate_limit:
                    break
                candidate = f"{word}.{host}"
                if candidate == host or not scope.allows(candidate):
                    continue
                attempts += 1
                pace.wait()
                response = http.get(
                    root,
                    headers={"Host": candidate},
                    max_bytes=max_bytes,
                    allow_redirects=False,
                )
                if response is None or _signature(response) == baseline[host]:
                    continue
                headers = dict(getattr(response, "headers", {}) or {})
                body = getattr(response, "text", "") or ""
                candidate_url = normalize_url(f"{urlsplit(root).scheme}://{candidate}/")
                if not candidate_url:
                    continue
                result.add(
                    "http_hosts",
                    url=candidate_url,
                    host=candidate,
                    status_code=getattr(response, "status_code", None),
                    title=extract_title(body),
                    server=server_from_headers(headers),
                    tech=", ".join(detect_tech(headers, body)),
                    content_length=len(getattr(response, "content", b"") or b""),
                    source_tool="builtin",
                    source_detail="authorized Host-header vhost probe",
                )
                result.add(
                    "endpoints",
                    url=candidate_url,
                    host=candidate,
                    method="GET",
                    status_code=getattr(response, "status_code", None),
                    content_type=headers.get("content-type", ""),
                    source_detail="authorized vhost probe",
                    source_tool="builtin",
                )
        result.note(f"Vhost probe candidates tested: {attempts}.")
        return result
