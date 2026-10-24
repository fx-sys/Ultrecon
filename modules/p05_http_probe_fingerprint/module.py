"""Scope-checked HTTP probing and lightweight technology fingerprinting."""

from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit

from core.http import (
    detect_tech,
    extract_title,
    get_http,
    normalize_url,
    server_from_headers,
)
from core.module_base import ModuleBase, ResultSet
from core.util import host_of
from modules.common import phase_settings, scoped_hosts, seed_http_urls

_MAX_HOSTS = 2000
_MAX_PORTS = 8
_MAX_PROBES = 12000
_MAX_RESPONSE_BYTES = 1_048_576


def _bounded_int(value: Any, default: int, minimum: int, maximum: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = default
    return max(minimum, min(parsed, maximum))


def _safe_schemes(value: Any) -> list[str]:
    if not isinstance(value, (list, tuple, set)):
        value = ("https", "http")
    schemes = [str(scheme).strip().lower() for scheme in value]
    return list(dict.fromkeys(scheme for scheme in schemes if scheme in {"https", "http"}))


def _safe_ports(value: Any) -> list[int]:
    if not isinstance(value, (list, tuple, set)):
        value = (443, 80, 8443, 8080)
    ports: list[int] = []
    for item in value:
        try:
            port = int(item)
        except (TypeError, ValueError):
            continue
        if 1 <= port <= 65535 and port not in ports:
            ports.append(port)
        if len(ports) >= _MAX_PORTS:
            break
    return ports


class Module(ModuleBase):
    name = "HTTP probing & tech fingerprint"
    slug = "p05_http_probe_fingerprint"
    phase = 5
    description = "Probe scoped HTTP(S) services with bounded responses and identify technologies."
    tables = ("http_hosts",)
    is_passive = True

    def run(self, scope, config: dict[str, Any]) -> ResultSet:
        result = self.new_result()
        settings = phase_settings(config, self.phase)
        max_hosts = _bounded_int(settings.get("max_hosts", 2000), 2000, 0, _MAX_HOSTS)
        if max_hosts == 0:
            result.note("HTTP probing skipped because p05.max_hosts is zero.")
            return result

        hosts = [
            host
            for host in scoped_hosts(
                scope,
                config,
                tables=("subdomains", "ips", "http_hosts", "endpoints", "js_files"),
                limit=max_hosts,
            )
            if scope.allows(host)
        ]
        if not hosts:
            result.note("No discovered in-scope hosts are available for HTTP probing.")
            return result

        schemes = _safe_schemes(settings.get("schemes", ("https", "http")))
        ports = _safe_ports(settings.get("probe_ports", (443, 80, 8443, 8080)))
        if not schemes or not ports:
            result.note("HTTP probing skipped because no valid schemes or ports are configured.")
            return result

        safe_config = dict(config)
        safe_config["_scope"] = scope
        safe_config["p05"] = {**settings, "schemes": schemes, "probe_ports": ports}
        urls = []
        for candidate in seed_http_urls(hosts, safe_config):
            normalized = normalize_url(candidate)
            if not normalized or not scope.allows(host_of(normalized)):
                continue
            parts = urlsplit(normalized)
            effective_port = parts.port or (443 if parts.scheme == "https" else 80)
            if effective_port in ports:
                urls.append(normalized)
        expected_per_host = len(schemes) + 2 * sum(1 for port in ports if port not in (80, 443))
        default_probe_cap = max_hosts * max(1, expected_per_host)
        max_probes = _bounded_int(
            settings.get("max_probes", default_probe_cap), default_probe_cap, 0, _MAX_PROBES
        )
        if max_probes == 0:
            result.note("HTTP probing skipped because p05.max_probes is zero.")
            return result
        if len(urls) > max_probes:
            urls = urls[:max_probes]
            result.note(f"HTTP probe list capped at {max_probes} URLs.")

        http_config = config
        config["_scope"] = scope
        http = get_http(http_config)
        # A reused client must enforce this invocation's scope as well.
        if getattr(http, "scope", None) is not scope:
            http.scope = scope
        http_settings = config.get("http") or {}
        max_bytes = _bounded_int(
            http_settings.get("max_bytes", _MAX_RESPONSE_BYTES),
            _MAX_RESPONSE_BYTES,
            1024,
            _MAX_RESPONSE_BYTES,
        )
        run_settings = config.get("run") or {}
        timeout = _bounded_int(run_settings.get("timeout", 20), 20, 1, 30)
        signatures = bool(settings.get("tech_signatures", True))
        seen: set[str] = set()
        failed = 0

        for url in urls:
            requested_url = normalize_url(url)
            if not requested_url or not scope.allows(host_of(requested_url)):
                continue
            response = http.get(requested_url, timeout=timeout, max_bytes=max_bytes)
            if response is None:
                failed += 1
                continue
            final_url = normalize_url(str(getattr(response, "url", "") or requested_url))
            final_host = host_of(final_url or "")
            if not final_url or not scope.allows(final_host) or final_url in seen:
                continue
            seen.add(final_url)
            headers = dict(getattr(response, "headers", {}) or {})
            body = str(getattr(response, "text", "") or "")
            status = getattr(response, "status_code", None)
            try:
                raw_content_length = next(
                    (value for key, value in headers.items() if key.lower() == "content-length"),
                    "",
                )
                content_length = int(raw_content_length)
                if content_length < 0:
                    content_length = len(getattr(response, "content", b"") or b"")
            except (TypeError, ValueError):
                content_length = len(getattr(response, "content", b"") or b"")
            technologies = detect_tech(headers, body) if signatures else []
            result.add(
                "http_hosts",
                url=final_url,
                host=final_host,
                status_code=status,
                title=extract_title(body) or None,
                server=server_from_headers(headers),
                tech=", ".join(technologies) or None,
                content_length=content_length,
                redirect_url=final_url if final_url != requested_url else None,
                source_tool="builtin:http",
            )

        if failed:
            result.note(f"No response received for {failed} of {len(urls)} HTTP probes.")
        if len(hosts) >= max_hosts:
            result.note(f"Host list capped at {max_hosts} targets.")
        return result
