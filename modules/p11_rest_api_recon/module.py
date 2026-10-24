"""Passive discovery of OpenAPI and Swagger documents."""

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

_DEFAULT_DOC_PATHS = (
    "/swagger.json",
    "/swagger/v1/swagger.json",
    "/openapi.json",
    "/api-docs",
    "/v3/api-docs",
    "/api/swagger.json",
    "/.well-known/openapi.json",
)
_HTTP_METHODS = {"get", "put", "post", "delete", "options", "head", "patch", "trace"}


def _bounded_int(value: Any, default: int, maximum: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    return max(1, min(parsed, maximum))


def _doc_path(value: Any) -> str | None:
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
    return path[:512]


def _base_urls(host: str, config: dict[str, Any], scope: Scope) -> list[str]:
    """Reuse known in-scope web origins, falling back to HTTPS then HTTP."""
    bases: list[str] = []
    for table in ("http_hosts", "endpoints", "js_files"):
        for row in previous_rows(config, table):
            candidate = normalize_url(str(row.get("url") or ""))
            if not candidate:
                continue
            parts = urlsplit(candidate)
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


def _server_bases(document: dict[str, Any], spec_url: str, scope: Scope) -> list[str]:
    source = urlsplit(spec_url)
    if not source.scheme or not source.hostname:
        return []
    origin = f"{source.scheme}://{source.netloc}"
    raw_servers = document.get("servers")
    if not isinstance(raw_servers, list) or not raw_servers:
        base_path = document.get("basePath") or ""
        raw_servers = [{"url": base_path}]

    bases: list[str] = []
    for entry in raw_servers[:10]:
        if not isinstance(entry, dict) or not isinstance(entry.get("url"), str):
            continue
        server = entry["url"].strip()
        variables = entry.get("variables")
        if isinstance(variables, dict):
            for name, spec in variables.items():
                if not isinstance(spec, dict):
                    continue
                replacement = spec.get("default")
                if replacement is None and isinstance(spec.get("enum"), list) and spec["enum"]:
                    replacement = spec["enum"][0]
                if replacement is not None:
                    server = server.replace("{" + str(name) + "}", str(replacement))
        if "{" in server or "}" in server or any(ord(char) < 32 for char in server):
            continue
        if server.startswith("/"):
            candidate = normalize_url(origin + server)
        elif "://" in server:
            candidate = normalize_url(server)
        else:
            candidate = normalize_url(origin + "/" + server.lstrip("/"))
        if not candidate:
            continue
        parts = urlsplit(candidate)
        if parts.scheme not in {"http", "https"} or not scope.allows(parts.hostname or ""):
            continue
        base = f"{parts.scheme}://{parts.netloc}{parts.path.rstrip('/') }"
        if base not in bases:
            bases.append(base)
    if not bases and scope.allows(source.hostname):
        bases.append(origin)
    return bases


def _operation_url(base: str, raw_path: Any, scope: Scope) -> str | None:
    if not isinstance(raw_path, str):
        return None
    path = raw_path.strip()
    if (
        not path
        or path.startswith("//")
        or "://" in path
        or any(ord(char) < 32 for char in path)
        or any(segment in {".", ".."} for segment in path.split("/"))
    ):
        return None
    parts = urlsplit(base)
    combined_path = "/".join((parts.path.rstrip("/"), path.lstrip("/")))
    url = normalize_url(f"{parts.scheme}://{parts.netloc}{combined_path or '/'}")
    if not url or not scope.allows(host_of(url)):
        return None
    return url


def _parse_spec(payload: str) -> tuple[dict[str, Any], str] | None:
    try:
        value = json.loads(payload)
    except (json.JSONDecodeError, TypeError, ValueError):
        return None
    if not isinstance(value, dict):
        return None
    if isinstance(value.get("openapi"), str):
        return value, "openapi"
    if isinstance(value.get("swagger"), str):
        return value, "swagger"
    return None


class Module(ModuleBase):
    name = "REST API recon"
    slug = "p11_rest_api_recon"
    phase = 11
    description = "Find OpenAPI/Swagger documents and enumerate declared operations."
    tables = ("api_specs", "endpoints")
    is_passive = True

    def run(self, scope: Scope, config: dict[str, Any]) -> ResultSet:
        result = self.new_result()
        settings = phase_settings(config, self.phase)
        hosts = scoped_hosts(
            scope,
            config,
            limit=_bounded_int(settings.get("max_hosts"), 500, 500),
        )
        raw_paths = settings.get("doc_paths", _DEFAULT_DOC_PATHS)
        if not isinstance(raw_paths, (list, tuple)):
            raw_paths = _DEFAULT_DOC_PATHS
        paths = dedupe(path for item in raw_paths if (path := _doc_path(item)))[:40]
        max_docs = _bounded_int(settings.get("max_docs"), 1500, 3000)
        max_operations = _bounded_int(settings.get("max_operations"), 2000, 5000)
        if not hosts or not paths:
            result.note("No in-scope hosts or safe API document paths were available.")
            return result

        client = http_client(config)
        candidates: list[str] = []
        for host in hosts:
            if not scope.allows(host):
                continue
            for base in _base_urls(host, config, scope):
                candidates.extend(normalize_url(base + path) or "" for path in paths)
        for row in previous_rows(config, "endpoints"):
            candidate = normalize_url(str(row.get("url") or ""))
            if candidate and re.search(r"(?:openapi|swagger|api-docs)", urlsplit(candidate).path, re.I):
                if scope.allows(host_of(candidate)):
                    candidates.append(candidate)
        candidates = [url for url in dedupe(candidates) if scope.allows(host_of(url))]

        docs_read = 0
        operations_added = 0
        seen_operations: set[tuple[str, str]] = set()
        max_bytes = min(_bounded_int((config.get("http") or {}).get("max_bytes"), 1_000_000, 1_000_000), 1_000_000)
        for url in candidates:
            if docs_read >= max_docs:
                result.note(f"Stopped after the configured document limit ({max_docs}).")
                break
            docs_read += 1
            response = client.get(url, max_bytes=max_bytes)
            if response is None or response.status_code < 200 or response.status_code >= 300:
                continue
            parsed = _parse_spec(response.text[:max_bytes])
            if not parsed:
                continue
            document, spec_type = parsed
            info = document.get("info") if isinstance(document.get("info"), dict) else {}
            title = str(info.get("title") or "")[:300] or None
            version = str(info.get("version") or "")[:120] or None
            wire_version = str(document.get("openapi") or document.get("swagger") or "")[:120] or None
            host = host_of(url)
            result.add(
                "api_specs",
                url=url,
                host=host,
                spec_type=spec_type,
                version=version,
                title=title,
                openapi_version=wire_version,
                source_detail=f"HTTP {response.status_code}; public document metadata",
            )

            paths_object = document.get("paths")
            if not isinstance(paths_object, dict):
                continue
            bases = _server_bases(document, url, scope)
            for raw_path, operations in paths_object.items():
                if operations_added >= max_operations:
                    result.note(f"Stopped after the configured operation limit ({max_operations}).")
                    break
                if not isinstance(operations, dict):
                    continue
                for method, _operation in operations.items():
                    if operations_added >= max_operations:
                        break
                    if str(method).lower() not in _HTTP_METHODS:
                        continue
                    for base in bases:
                        endpoint = _operation_url(base, raw_path, scope)
                        if not endpoint:
                            continue
                        operation_key = (endpoint, str(method).upper())
                        if operation_key not in seen_operations:
                            seen_operations.add(operation_key)
                            result.add(
                                "endpoints",
                                url=endpoint,
                                host=host_of(endpoint),
                                method=str(method).upper(),
                                source_detail=f"{spec_type.upper()} operation declared by {url}",
                            )
                            operations_added += 1
                        break
            if operations_added >= max_operations:
                break

        result.note(
            f"Checked {docs_read} candidate API document URL(s); declared operations are inventoried, not requested."
        )
        return result
