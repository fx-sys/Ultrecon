"""Passive GraphQL endpoint discovery with opt-in gated introspection."""

from __future__ import annotations

import json
import re
from typing import Any
from urllib.parse import urlsplit

from core.http import normalize_url
from core.module_base import ModuleBase, ResultSet
from core.scope import Scope
from core.util import dedupe, host_of
from modules.common import http_client, phase_settings, previous_rows, scoped_hosts

_DEFAULT_PATHS = ("/graphql", "/api/graphql", "/graphiql", "/v1/graphql", "/query")
_INTROSPECTION_QUERY = "query UltreconSchemaProbe { __schema { queryType { name } } }"
_GRAPHQL_PATH_RE = re.compile(r"(?:graphql|graphiql|/gql(?:/|$))", re.IGNORECASE)


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
        or "?" in path
        or "#" in path
        or "://" in path
        or any(ord(char) < 32 for char in path)
        or any(segment == ".." for segment in path.split("/"))
    ):
        return None
    return path[:256]


def _base_urls(host: str, config: dict[str, Any], scope: Scope) -> list[str]:
    bases: list[str] = []
    for table in ("http_hosts", "endpoints", "js_files"):
        for row in previous_rows(config, table):
            url = normalize_url(str(row.get("url") or ""))
            if not url:
                continue
            parts = urlsplit(url)
            if (parts.hostname or "").lower().rstrip(".") != host or not scope.allows(host):
                continue
            base = f"{parts.scheme}://{parts.netloc}"
            if base not in bases:
                bases.append(base)
            if len(bases) == 2:
                return bases
    if not bases and scope.allows(host):
        bases.extend((f"https://{host}", f"http://{host}"))
    return bases


def _is_graphql_endpoint(url: str, status: int, content_type: str, body: str) -> tuple[bool, str]:
    path = urlsplit(url).path.lower()
    blob = (body or "")[:100_000].lower()
    if any(marker in blob for marker in ("graphql", "graphiql", "__typename", "__schema")):
        return True, "GraphQL response marker"
    if "application/graphql" in content_type.lower():
        return True, "GraphQL content type"
    if "graphiql" in path and status in {200, 401, 403}:
        return True, "GraphiQL route responded"
    json_error = "application/json" in content_type.lower() and any(
        marker in blob for marker in ('"errors"', '"data"', "query is required", "must provide query")
    )
    if json_error and status in {200, 400, 401, 403, 405}:
        return True, "GraphQL-style JSON response"
    return False, ""


class Module(ModuleBase):
    name = "GraphQL recon"
    slug = "p12_graphql_recon"
    phase = 12
    description = "Discover GraphQL endpoints; schema introspection is separately gated."
    tables = ("endpoints", "graphql_findings")
    is_passive = True
    supports_active = True

    def run(self, scope: Scope, config: dict[str, Any]) -> ResultSet:
        result = self.new_result()
        settings = phase_settings(config, self.phase)
        hosts = scoped_hosts(
            scope,
            config,
            limit=_bounded_int(settings.get("max_hosts"), 500, 500),
        )
        raw_paths = settings.get("common_paths", _DEFAULT_PATHS)
        if not isinstance(raw_paths, (list, tuple)):
            raw_paths = _DEFAULT_PATHS
        paths = dedupe(path for item in raw_paths if (path := _safe_path(item)))[:30]
        max_checks = _bounded_int(settings.get("max_checks"), 1500, 3000)
        if not hosts or not paths:
            result.note("No in-scope hosts or safe GraphQL candidate paths were available.")
            return result

        candidates: list[str] = []
        for host in hosts:
            if not scope.allows(host):
                continue
            for base in _base_urls(host, config, scope):
                candidates.extend(normalize_url(base + path) or "" for path in paths)
        for row in previous_rows(config, "endpoints"):
            candidate = normalize_url(str(row.get("url") or ""))
            if not candidate:
                continue
            parts = urlsplit(candidate)
            if parts.query or parts.fragment:
                continue
            if _GRAPHQL_PATH_RE.search(parts.path) and scope.allows(host_of(candidate)):
                candidates.append(candidate)
        candidates = [url for url in dedupe(candidates) if scope.allows(host_of(url))][:max_checks]

        client = http_client(config)
        found: list[str] = []
        active_run = bool((config.get("_run") or {}).get("active"))
        authorized = bool((config.get("_run") or {}).get("authorized"))
        introspection_enabled = bool(settings.get("introspection"))
        max_bytes = min(_bounded_int((config.get("http") or {}).get("max_bytes"), 256_000, 512_000), 512_000)

        for url in candidates:
            response = client.get(url, max_bytes=max_bytes)
            if response is None:
                continue
            content_type = str(response.headers.get("content-type") or "")[:200]
            body = response.text[:max_bytes]
            detected, evidence = _is_graphql_endpoint(
                url, int(response.status_code), content_type, body
            )
            if not detected:
                continue
            found.append(url)
            host = host_of(url)
            result.add(
                "endpoints",
                url=url,
                host=host,
                method="GET",
                status_code=int(response.status_code),
                content_type=content_type or None,
                source_detail="GraphQL endpoint discovery",
            )
            result.add(
                "graphql_findings",
                url=url,
                host=host,
                finding_type="endpoint_detected",
                detail=evidence,
                severity="info",
            )

        if introspection_enabled and active_run and authorized:
            for url in found[:_bounded_int(settings.get("max_introspection_targets"), 10, 10)]:
                response = client.request(
                    "POST",
                    url,
                    json={"query": _INTROSPECTION_QUERY},
                    headers={"Accept": "application/json", "Content-Type": "application/json"},
                    timeout=5,
                    max_bytes=min(max_bytes, 128_000),
                )
                if response is None or response.status_code < 200 or response.status_code >= 300:
                    continue
                try:
                    payload = response.json()
                except (ValueError, json.JSONDecodeError):
                    continue
                data = payload.get("data") if isinstance(payload, dict) else None
                schema = data.get("__schema") if isinstance(data, dict) else None
                if isinstance(schema, dict):
                    result.add(
                        "graphql_findings",
                        url=url,
                        host=host_of(url),
                        finding_type="introspection_enabled",
                        detail="A minimal schema metadata query returned __schema.",
                        severity="low",
                    )
        elif introspection_enabled:
            result.note(
                "GraphQL introspection was requested in phase settings but skipped: both active and authorized run flags are required."
            )

        result.note(
            f"Checked {len(candidates)} in-scope GraphQL candidate URL(s); sent no query unless explicitly enabled and authorized."
        )
        return result
