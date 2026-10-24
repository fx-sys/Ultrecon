"""Helpers shared by phase implementations."""

from __future__ import annotations

import ipaddress
import socket
from collections.abc import Iterable
from typing import Any
from urllib.parse import urlsplit

from core.config import phase_config
from core.http import get_http, normalize_url
from core.module_base import ResultSet
from core.scope import Scope
from core.util import dedupe, host_of


def phase_settings(config: dict[str, Any], phase: int) -> dict[str, Any]:
    return phase_config(config, f"p{phase:02d}")


def previous_rows(config: dict[str, Any], table: str) -> list[dict[str, Any]]:
    store = config.get("_store")
    run = config.get("_run") or {}
    run_id = run.get("run_id")
    if store is None or not run_id:
        return []
    try:
        return store.rows(table, str(run_id))
    except Exception:
        return []


def scoped_hosts(
    scope: Scope,
    config: dict[str, Any],
    *,
    include_seeds: bool = True,
    tables: Iterable[str] = ("subdomains", "ips", "http_hosts", "endpoints", "js_files"),
    limit: int | None = None,
) -> list[str]:
    hosts: list[str] = list(scope.seed_hosts()) if include_seeds else []
    for table in tables:
        for row in previous_rows(config, table):
            candidate = str(row.get("host") or host_of(str(row.get("url") or ""))).strip()
            if candidate and scope.allows(candidate):
                hosts.append(candidate.lower().rstrip("."))
    result = dedupe(hosts)
    return result[:limit] if limit else result


def scoped_urls(
    scope: Scope,
    config: dict[str, Any],
    *,
    tables: Iterable[str] = ("http_hosts", "endpoints", "js_files"),
    limit: int | None = None,
) -> list[str]:
    urls: list[str] = []
    for table in tables:
        for row in previous_rows(config, table):
            candidate = normalize_url(str(row.get("url") or ""))
            if candidate and scope.allows(host_of(candidate)):
                urls.append(candidate)
    result = dedupe(urls)
    return result[:limit] if limit else result


def seed_http_urls(hosts: Iterable[str], config: dict[str, Any]) -> list[str]:
    phase = phase_settings(config, 5)
    schemes = phase.get("schemes", ["https", "http"])
    ports = phase.get("probe_ports", [443, 80, 8443, 8080])
    output: list[str] = []
    for host in hosts:
        for scheme in schemes:
            port = 443 if scheme == "https" else 80
            output.append(f"{scheme}://{host}" + (f":{port}" if port not in (80, 443) else ""))
        for port in ports:
            if int(port) in (80, 443):
                continue
            output.extend((f"https://{host}:{int(port)}", f"http://{host}:{int(port)}"))
    return dedupe(output)


def is_public_ip(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value.strip())
    except ValueError:
        return False
    return address.is_global


def resolve_host_addresses(
    host: str,
    config: dict[str, Any],
    *,
    limit: int = 16,
) -> list[str]:
    """Resolve a host to bounded addresses, rejecting non-global DNS by default."""
    normalized = host.strip().lower().rstrip(".")
    if not normalized or limit < 1:
        return []
    try:
        addresses = [ipaddress.ip_address(normalized)]
    except ValueError:
        try:
            records = socket.getaddrinfo(normalized, None, type=socket.SOCK_STREAM)
        except OSError:
            return []
        addresses = []
        for record in records:
            try:
                addresses.append(ipaddress.ip_address(record[4][0].split("%", 1)[0]))
            except (IndexError, ValueError):
                continue

    unique: list[str] = []
    seen: set[str] = set()
    for address in addresses:
        value = address.compressed
        if value not in seen:
            seen.add(value)
            unique.append(value)
    if not unique:
        return []
    allow_private = bool((config.get("http") or {}).get("allow_private_ips", False))
    if not allow_private and any(not ipaddress.ip_address(value).is_global for value in unique):
        return []
    return unique[:limit]


def add_endpoint(result: ResultSet, url: str, *, method: str = "GET", **fields: Any) -> None:
    normalized = normalize_url(url)
    if not normalized:
        return
    result.add("endpoints", url=normalized, host=host_of(normalized), method=method, **fields)


def add_parameter(result: ResultSet, url: str, name: str, *, location: str = "query") -> None:
    normalized = normalize_url(url)
    if not normalized or not name:
        return
    result.add(
        "parameters",
        url=normalized,
        host=host_of(normalized),
        name=name,
        location=location,
    )


def target_url(host: str, path: str = "/") -> str:
    if not path.startswith("/"):
        path = "/" + path
    return f"https://{host}{path}"


def http_client(config: dict[str, Any]):
    return get_http(config)


def is_target_url(url: str, scope: Scope) -> bool:
    try:
        parts = urlsplit(url)
    except ValueError:
        return False
    return parts.scheme in {"http", "https"} and scope.allows(parts.hostname or "")
