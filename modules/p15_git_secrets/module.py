"""Bounded checks for exposed VCS metadata and secrets in public JavaScript."""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from core.http import normalize_url
from core.module_base import ModuleBase, ResultSet
from core.scope import Scope
from core.util import dedupe, host_of
from modules.common import http_client, phase_settings, previous_rows, scoped_hosts

_DEFAULT_PATHS = ("/.git/HEAD", "/.git/config", "/.env", "/.env.local")
_ASSIGNMENT_RE = re.compile(
    r"(?im)(?P<key>[A-Za-z0-9_.-]*(?:api[_-]?key|secret|token|password|passwd|private[_-]?key|client[_-]?secret)[A-Za-z0-9_.-]*)"
    r"\s*[:=]\s*['\"]?(?P<value>[^\s'\"`,;]{8,})"
)
_AWS_KEY_RE = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
_GITHUB_TOKEN_RE = re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b")
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{8,}\b")
_PRIVATE_KEY_RE = re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----")
_PLACEHOLDER_RE = re.compile(
    r"^(?:example|sample|test|changeme|change[_-]?me|your[_-].*|\$\{.*\}|<.*>|none|null|undefined|todo)$",
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
        or "#" in path
        or any(ord(char) < 32 for char in path)
        or any(segment == ".." for segment in path.split("?", 1)[0].split("/"))
    ):
        return None
    return path[:256]


def _report_url(url: str) -> str:
    parts = urlsplit(url)
    return urlunsplit((parts.scheme, parts.netloc, parts.path or "/", "", ""))


def _finding_types(text: str) -> list[tuple[str, str, str]]:
    """Return type, redacted marker and confidence; never return the value."""
    findings: list[tuple[str, str, str]] = []
    for match in _ASSIGNMENT_RE.finditer(text or ""):
        key = re.sub(r"[^A-Za-z0-9_-]", "", match.group("key"))[:80]
        value = match.group("value").strip().strip("'\"")
        if len(value) < 8 or _PLACEHOLDER_RE.match(value):
            continue
        normalized = key.lower().replace("-", "_")
        if "private" in normalized:
            secret_type = "private_key_assignment"
        elif "password" in normalized or "passwd" in normalized:
            secret_type = "password_assignment"
        elif "token" in normalized:
            secret_type = "token_assignment"
        elif "secret" in normalized:
            secret_type = "secret_assignment"
        else:
            secret_type = "api_key_assignment"
        findings.append((secret_type, f"{key}=<redacted>", "medium"))
    if _AWS_KEY_RE.search(text or ""):
        findings.append(("aws_access_key_id", "AWS access key identifier=<redacted>", "high"))
    if _GITHUB_TOKEN_RE.search(text or ""):
        findings.append(("github_token", "GitHub token=<redacted>", "high"))
    if _JWT_RE.search(text or ""):
        findings.append(("jwt_token", "JWT=<redacted>", "medium"))
    if _PRIVATE_KEY_RE.search(text or ""):
        findings.append(("private_key", "Private key material=<redacted>", "high"))
    return dedupe(findings)


def _looks_like_git_head(body: str) -> bool:
    return bool(re.match(r"\s*(?:ref:\s+refs/[A-Za-z0-9_./-]+|[0-9a-f]{40})\s*$", body, re.I))


def _looks_like_git_config(body: str) -> bool:
    return bool(re.search(r"(?im)^\s*\[core\]\s*$", body) and "repositoryformatversion" in body.lower())


class Module(ModuleBase):
    name = "Git metadata and secret exposure"
    slug = "p15_git_secrets"
    phase = 15
    description = "Check bounded public VCS metadata and redact secret indicators from in-scope JavaScript."
    tables = ("secrets_findings",)
    is_passive = True

    def run(self, scope: Scope, config: dict[str, Any]) -> ResultSet:
        result = self.new_result()
        settings = phase_settings(config, self.phase)
        hosts = scoped_hosts(
            scope,
            config,
            limit=_bounded_int(settings.get("max_hosts"), 500, 500),
        )
        raw_paths = settings.get("check_paths", _DEFAULT_PATHS)
        if not isinstance(raw_paths, (list, tuple)):
            raw_paths = _DEFAULT_PATHS
        paths = dedupe(path for item in raw_paths if (path := _safe_path(item)))[:12]
        client = http_client(config)
        max_bytes = min(_bounded_int(settings.get("max_bytes_per_response"), 64_000, 64_000), 64_000)
        seen: set[tuple[str, str, str]] = set()

        bases: dict[str, list[str]] = {}
        for table in ("http_hosts", "endpoints"):
            for row in previous_rows(config, table):
                url = normalize_url(str(row.get("url") or ""))
                if not url:
                    continue
                parts = urlsplit(url)
                host = (parts.hostname or "").lower().rstrip(".")
                if host in hosts and scope.allows(host):
                    origin = f"{parts.scheme}://{parts.netloc}"
                    bases.setdefault(host, [])
                    if origin not in bases[host]:
                        bases[host].append(origin)

        for host in hosts:
            if not scope.allows(host):
                continue
            candidate_bases = bases.get(host) or [f"https://{host}", f"http://{host}"]
            for base in candidate_bases[:2]:
                for path in paths:
                    url = normalize_url(base + path)
                    if not url or not scope.allows(host_of(url)):
                        continue
                    response = client.get(url, max_bytes=max_bytes)
                    if response is None or response.status_code != 200:
                        continue
                    body = response.text[:max_bytes]
                    route = urlsplit(url).path.lower()
                    if route.endswith("/.git/head") and _looks_like_git_head(body):
                        key = (_report_url(url), "git_metadata_exposed", "Git HEAD metadata exposed")
                        if key not in seen:
                            seen.add(key)
                            result.add(
                                "secrets_findings",
                                url=key[0],
                                host=host,
                                secret_type=key[1],
                                match_redacted=key[2],
                                confidence="high",
                                source_detail="Bounded public metadata response; body not retained",
                            )
                    elif route.endswith("/.git/config") and _looks_like_git_config(body):
                        key = (_report_url(url), "git_metadata_exposed", "Git configuration metadata exposed")
                        if key not in seen:
                            seen.add(key)
                            result.add(
                                "secrets_findings",
                                url=key[0],
                                host=host,
                                secret_type=key[1],
                                match_redacted=key[2],
                                confidence="high",
                                source_detail="Bounded public metadata response; remotes and body not retained",
                            )
                    elif route.endswith(".env") or ".env." in route:
                        if "<html" not in body[:1000].lower():
                            for secret_type, marker, confidence in _finding_types(body):
                                key = (_report_url(url), secret_type, marker)
                                if key in seen:
                                    continue
                                seen.add(key)
                                result.add(
                                    "secrets_findings",
                                    url=key[0],
                                    host=host,
                                    secret_type="environment_file_exposed",
                                    match_redacted="Environment assignment=<redacted>",
                                    confidence=confidence,
                                    source_detail="Bounded public environment-file response; no values retained",
                                )

        if settings.get("scan_downloaded_js", True):
            max_js_files = _bounded_int(settings.get("max_js_files"), 100, 200)
            js_rows = previous_rows(config, "js_files")[:max_js_files]
            max_js_bytes = min(_bounded_int(settings.get("max_js_bytes"), 256_000, 512_000), 512_000)
            for row in js_rows:
                url = normalize_url(str(row.get("url") or ""))
                if not url or not scope.allows(host_of(url)):
                    continue
                response = client.get(url, max_bytes=max_js_bytes)
                if response is None or response.status_code != 200:
                    continue
                body = response.text[:max_js_bytes]
                report_url = _report_url(url)
                for secret_type, marker, confidence in _finding_types(body):
                    key = (report_url, secret_type, marker)
                    if key in seen:
                        continue
                    seen.add(key)
                    result.add(
                        "secrets_findings",
                        url=report_url,
                        host=host_of(url),
                        secret_type=secret_type,
                        match_redacted=marker,
                        confidence=confidence,
                        source_detail="Bounded public JavaScript response; no values retained",
                    )

        result.note(
            f"Inspected bounded public metadata and JavaScript responses for {len(hosts)} in-scope host(s); no repository objects or secret values were retained."
        )
        return result
