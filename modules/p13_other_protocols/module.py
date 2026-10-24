"""Passive SOAP/WSDL, gRPC and WebSocket surface indicators."""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlsplit

from core.http import normalize_url
from core.module_base import ModuleBase, ResultSet
from core.scope import Scope
from core.util import dedupe, host_of
from modules.common import http_client, phase_settings, previous_rows, scoped_hosts

_DEFAULT_SOAP_PATHS = (
    "/service.wsdl",
    "/service.asmx?wsdl",
    "/service.svc?wsdl",
    "/wsdl",
    "/soap?wsdl",
)
_WSDL_MARKER_RE = re.compile(r"<(?:\w+:)?definitions\b|<wsdl:definitions\b", re.I)
_WS_MARKER_RE = re.compile(
    r"new\s+WebSocket\s*\(|wss?://|socket\.io|sockjs|graphql-ws|subscriptions-transport-ws",
    re.I,
)


def _bounded_int(value: Any, default: int, maximum: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    return max(1, min(parsed, maximum))


def _safe_path(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    path = value.strip()
    if (
        not path.startswith("/")
        or path.startswith("//")
        or "://" in path
        or any(ord(char) < 32 for char in path)
        or any(segment == ".." for segment in path.split("/"))
    ):
        return None
    return path[:256]


def _base_urls(host: str, config: dict[str, Any], scope: Scope) -> list[str]:
    bases: list[str] = []
    for row in previous_rows(config, "http_hosts") + previous_rows(config, "endpoints"):
        url = normalize_url(str(row.get("url") or ""))
        if not url:
            continue
        parts = urlsplit(url)
        if (parts.hostname or "").lower().rstrip(".") != host or not scope.allows(host):
            continue
        base = f"{parts.scheme}://{parts.netloc}"
        if base not in bases:
            bases.append(base)
        if len(bases) >= 2:
            return bases
    if not bases and scope.allows(host):
        bases.extend((f"https://{host}", f"http://{host}"))
    return bases


def _candidate_host_url(host: str, port: Any) -> str | None:
    try:
        number = int(port)
    except (TypeError, ValueError):
        return None
    if not 1 <= number <= 65535:
        return None
    return f"grpc://{host}:{number}/"


def _wsdl_name(body: str) -> str | None:
    match = re.search(r"<(?:\w+:)?definitions\b[^>]*\bname\s*=\s*['\"]([^'\"]+)", body, re.I)
    return match.group(1)[:200] if match else None


class Module(ModuleBase):
    name = "Other protocol recon"
    slug = "p13_other_protocols"
    phase = 13
    description = "Inventory SOAP/WSDL, gRPC and WebSocket indicators without protocol handshakes."
    tables = ("api_specs", "endpoints")
    is_passive = True

    def run(self, scope: Scope, config: dict[str, Any]) -> ResultSet:
        result = self.new_result()
        settings = phase_settings(config, self.phase)
        max_hosts = _bounded_int(settings.get("max_hosts"), 500, 500)
        max_endpoints = _bounded_int(settings.get("max_endpoints"), 1000, 1000)
        hosts = scoped_hosts(scope, config, limit=max_hosts)
        raw_paths = settings.get("soap_paths", _DEFAULT_SOAP_PATHS)
        if not isinstance(raw_paths, (list, tuple)):
            raw_paths = _DEFAULT_SOAP_PATHS
        paths = dedupe(path for item in raw_paths if (path := _safe_path(item)))[:20]

        # Only lightweight GETs for WSDL metadata are issued. gRPC reflection and
        # WebSocket upgrade handshakes are deliberately not attempted.
        candidates: list[str] = []
        for host in hosts:
            if not scope.allows(host):
                continue
            for base in _base_urls(host, config, scope):
                candidates.extend(normalize_url(base + path) or "" for path in paths)
        for table in ("endpoints", "http_hosts"):
            for row in previous_rows(config, table):
                url = normalize_url(str(row.get("url") or ""))
                if not url or not scope.allows(host_of(url)):
                    continue
                path = urlsplit(url).path.lower()
                if path.endswith((".wsdl", ".asmx", ".svc")) or "wsdl" in url.lower():
                    candidates.append(url)
        candidates = [url for url in dedupe(candidates) if scope.allows(host_of(url))][:max_endpoints]

        client = http_client(config)
        max_bytes = min(_bounded_int((config.get("http") or {}).get("max_bytes"), 256_000, 512_000), 512_000)
        checked = 0
        recorded: set[tuple[str, str]] = set()
        for url in candidates:
            checked += 1
            response = client.get(url, max_bytes=max_bytes)
            if response is None or response.status_code < 200 or response.status_code >= 300:
                continue
            body = response.text[:max_bytes]
            content_type = str(response.headers.get("content-type") or "")[:200]
            if not _WSDL_MARKER_RE.search(body):
                continue
            host = host_of(url)
            title = _wsdl_name(body)
            result.add(
                "api_specs",
                url=url,
                host=host,
                spec_type="wsdl",
                title=title,
                source_detail=f"WSDL metadata response; HTTP {response.status_code}",
            )
            result.add(
                "endpoints",
                url=url,
                host=host,
                method="GET",
                status_code=int(response.status_code),
                content_type=content_type or None,
                source_detail="SOAP/WSDL metadata indicator",
            )
            recorded.add(("wsdl", url))

        # Reuse earlier endpoint and service observations; do not contact gRPC
        # listeners or send HTTP/2, reflection, or WebSocket handshakes.
        for row in previous_rows(config, "ports_services"):
            host = str(row.get("host") or "").lower().rstrip(".")
            service = " ".join(str(row.get(key) or "") for key in ("service", "version", "protocol"))
            if not host or not scope.allows(host) or not re.search(r"\bgrpc(?:-web)?\b", service, re.I):
                continue
            url = _candidate_host_url(host, row.get("port"))
            if url and ("grpc", url) not in recorded:
                result.add(
                    "api_specs",
                    url=url,
                    host=host,
                    spec_type="grpc",
                    source_detail="Previously observed service label; no gRPC request sent",
                )
                recorded.add(("grpc", url))

        for row in previous_rows(config, "endpoints"):
            url = normalize_url(str(row.get("url") or ""))
            if not url or not scope.allows(host_of(url)):
                continue
            content_type = str(row.get("content_type") or "").lower()
            detail = str(row.get("source_detail") or "").lower()
            if "application/grpc" in content_type or "grpc-web" in content_type or "grpc" in detail:
                key = ("grpc-web", url)
                if key not in recorded:
                    result.add(
                        "api_specs",
                        url=url,
                        host=host_of(url),
                        spec_type="grpc-web",
                        source_detail="Previously observed HTTP metadata; no gRPC request sent",
                    )
                    recorded.add(key)
            if re.search(r"websocket|socket\.io|sockjs|graphql-ws", url + " " + detail, re.I):
                key = ("websocket", url)
                if key not in recorded:
                    result.add(
                        "api_specs",
                        url=url,
                        host=host_of(url),
                        spec_type="websocket",
                        source_detail="Previously observed URL indicator; no upgrade handshake sent",
                    )
                    recorded.add(key)

        js_rows = previous_rows(config, "js_files")
        max_js_files = _bounded_int(settings.get("max_js_files"), 100, 200)
        for row in js_rows[:max_js_files]:
            script_url = normalize_url(str(row.get("url") or ""))
            if not script_url or not scope.allows(host_of(script_url)):
                continue
            response = client.get(script_url, max_bytes=min(max_bytes, 256_000))
            if response is None or response.status_code < 200 or response.status_code >= 300:
                continue
            script = response.text[:min(max_bytes, 256_000)]
            if not _WS_MARKER_RE.search(script):
                continue
            key = ("websocket", script_url)
            if key not in recorded:
                result.add(
                    "api_specs",
                    url=script_url,
                    host=host_of(script_url),
                    spec_type="websocket",
                    source_detail="Client script indicates WebSocket usage; no upgrade handshake sent",
                )
                recorded.add(key)

        result.note(
            f"Checked {checked} bounded WSDL candidate URL(s); gRPC and WebSocket discovery used passive indicators only."
        )
        return result
