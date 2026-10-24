"""Explicitly authorized, low-impact Nuclei verification using validated templates."""

from __future__ import annotations

import ipaddress
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import yaml

from core.http import normalize_url
from core.module_base import ModuleBase, ResultSet
from core.scope import Scope
from core.toolrunner import run_json_lines
from core.util import host_of, truncate
from modules.common import phase_settings, previous_rows, resolve_host_addresses, scoped_hosts

_ALLOWED_TAGS = {"misconfig", "tech", "ssl"}
_BLOCKED_TAGS = {"bruteforce", "dos", "fuzz", "intrusive", "exploit", "rce", "ssrf", "sqli"}
_SIDE_EFFECT_PATH_TOKENS = (
    "delete", "destroy", "reset", "purge", "drop", "remove", "logout", "update",
    "create", "save", "confirm", "submit", "execute", "trigger", "reboot",
    "shutdown", "upload", "import", "restore", "write", "clear", "unsubscribe",
    "cancel", "disable", "enable", "stop", "start", "kill", "terminate", "approve",
    "revoke", "grant", "uninstall", "deactivate", "activate", "action",
)
_ALLOWED_TEMPLATE_KEYS = {"id", "info", "http"}
_ALLOWED_HTTP_KEYS = {
    "path",
    "method",
    "matchers",
    "matchers-condition",
    "stop-at-first-match",
    "max-redirects",
    "redirects",
}
_ALLOWED_MATCHER_KEYS = {"type", "part", "words", "status", "condition", "negative"}
_MAX_TEMPLATE_BYTES = 512_000
_MAX_TEMPLATE_SCAN_BYTES = 16_000_000


def _bounded_int(value: Any, default: int, minimum: int, maximum: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    return max(minimum, min(parsed, maximum))


def _safe_relative_path(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    raw = value.strip()
    if not raw or "\\" in raw or Path(raw).is_absolute():
        return None
    parts = Path(raw).parts
    if any(part in {".", ".."} for part in parts):
        return None
    return raw


def _safe_template_path(value: Any) -> bool:
    if not isinstance(value, (str, list, tuple)):
        return False
    paths = value if isinstance(value, (list, tuple)) else [value]
    if not paths or len(paths) > 10:
        return False
    for raw in paths:
        if not isinstance(raw, str):
            return False
        path = raw.strip()
        prefix = "{{BaseURL}}" if path.startswith("{{BaseURL}}") else "{{RootURL}}"
        if not path.startswith(prefix) or len(path) > 512:
            return False
        suffix = path[len(prefix) :]
        lowered_suffix = suffix.lower()
        if (
            "{{" in suffix
            or "}}" in suffix
            or "://" in suffix
            or "?" in suffix
            or "#" in suffix
            or "\\" in suffix
            or any(ord(char) < 32 for char in suffix)
            or any(segment in {".", ".."} for segment in suffix.split("/"))
            or any(token in lowered_suffix for token in _SIDE_EFFECT_PATH_TOKENS)
        ):
            return False
    return True


def _template_is_safe(document: Any, selected_ids: set[str]) -> bool:
    if not isinstance(document, dict) or set(document) - _ALLOWED_TEMPLATE_KEYS:
        return False
    template_id = document.get("id")
    if not isinstance(template_id, str) or template_id not in selected_ids:
        return False
    info = document.get("info")
    if not isinstance(info, dict):
        return False
    severity = str(info.get("severity") or "").lower()
    if severity not in {"info", "low"}:
        return False
    raw_tags = info.get("tags") or []
    tags = raw_tags.split(",") if isinstance(raw_tags, str) else raw_tags
    if not isinstance(tags, (list, tuple, set)):
        return False
    normalized_tags = {str(tag).strip().lower() for tag in tags}
    if normalized_tags & _BLOCKED_TAGS or not normalized_tags.intersection(_ALLOWED_TAGS):
        return False
    if set(info) - {"name", "author", "severity", "description", "reference", "tags", "metadata"}:
        return False

    requests = document.get("http")
    if not isinstance(requests, list) or not 1 <= len(requests) <= 10:
        return False
    for request in requests:
        if not isinstance(request, dict) or set(request) - _ALLOWED_HTTP_KEYS:
            return False
        if str(request.get("method") or "GET").upper() not in {"GET", "HEAD"}:
            return False
        if not _safe_template_path(request.get("path")):
            return False
        matchers = request.get("matchers")
        if not isinstance(matchers, list) or not matchers:
            return False
        for matcher in matchers:
            if not isinstance(matcher, dict) or set(matcher) - _ALLOWED_MATCHER_KEYS:
                return False
            if str(matcher.get("type") or "").lower() not in {"status", "word"}:
                return False
            words = matcher.get("words")
            if words is not None and (
                not isinstance(words, (str, list, tuple))
                or any(len(str(item)) > 256 for item in ([words] if isinstance(words, str) else words))
            ):
                return False
            statuses = matcher.get("status")
            if statuses is not None and not isinstance(statuses, (int, list, tuple)):
                return False
    return True


def _pinned_target(target: str, address: str) -> str | None:
    try:
        parts = urlsplit(target)
        ip = ipaddress.ip_address(address)
        port = parts.port
    except ValueError:
        return None
    host = f"[{ip.compressed}]" if ip.version == 6 else ip.compressed
    netloc = f"{host}:{port}" if port else host
    return urlunsplit((parts.scheme, netloc, parts.path or "/", "", ""))


def _same_ip(left: str, right: str) -> bool:
    try:
        return ipaddress.ip_address(left) == ipaddress.ip_address(right)
    except ValueError:
        return False


def _safe_report_url(
    value: Any,
    scope: Scope,
    fallback: str,
    *,
    expected_host: str,
    pinned_address: str,
) -> str | None:
    raw = str(value or fallback).strip()
    candidate = normalize_url(raw)
    if not candidate and "://" not in raw:
        candidate = normalize_url("https://" + raw)
    if not candidate:
        return None
    parts = urlsplit(candidate)
    candidate_host = (parts.hostname or "").lower().rstrip(".")
    if candidate_host != expected_host:
        if not _same_ip(candidate_host, pinned_address):
            return None
        fallback_parts = urlsplit(fallback)
        candidate = urlunsplit(
            (parts.scheme, fallback_parts.netloc, parts.path or "/", parts.query, "")
        )
        parts = urlsplit(candidate)
    if (parts.hostname or "").lower().rstrip(".") != expected_host:
        return None
    if not scope.allows(expected_host):
        return None
    return urlunsplit((parts.scheme, parts.netloc, parts.path or "/", "", ""))


def _host_targets(hosts: list[str], config: dict[str, Any], scope: Scope) -> list[tuple[str, str]]:
    targets: list[tuple[str, str]] = []
    for host in hosts:
        if not scope.allows(host):
            continue
        selected_url = ""
        for row in previous_rows(config, "http_hosts"):
            url = normalize_url(str(row.get("url") or ""))
            if url and host_of(url) == host:
                parts = urlsplit(url)
                selected_url = f"{parts.scheme}://{parts.netloc}/"
                break
        if not selected_url:
            selected_url = f"https://{host}/"
        if scope.allows(host_of(selected_url)):
            targets.append((host, selected_url))
    return targets


def _resolve_templates(settings: dict[str, Any], config: dict[str, Any]) -> tuple[list[Path], dict[str, dict[str, Any]]]:
    raw_ids = settings.get("template_ids")
    if not isinstance(raw_ids, (list, tuple)):
        return [], {}
    selected_ids = {str(value).strip() for value in raw_ids if isinstance(value, str) and value.strip()}
    if not selected_ids or len(selected_ids) > 10:
        return [], {}

    raw_root = settings.get("community_template_dir") or settings.get("template_dir")
    if not isinstance(raw_root, str) or not raw_root.strip():
        return [], {}
    root = Path(raw_root).expanduser()
    if not root.is_absolute():
        root = Path(str(config.get("project_root") or ".")) / root
    try:
        root = root.resolve(strict=True)
    except OSError:
        return [], {}
    if not root.is_dir():
        return [], {}

    chosen: list[Path] = []
    metadata: dict[str, dict[str, Any]] = {}
    total_bytes = 0
    examined = 0
    for path in sorted([*root.rglob("*.yaml"), *root.rglob("*.yml")]):
        examined += 1
        if examined > 2000 or total_bytes >= _MAX_TEMPLATE_SCAN_BYTES or len(chosen) >= 10:
            break
        try:
            resolved = path.resolve(strict=True)
            if not resolved.is_relative_to(root) or not resolved.is_file():
                continue
            size = resolved.stat().st_size
            if size <= 0 or size > _MAX_TEMPLATE_BYTES:
                continue
            total_bytes += size
            if total_bytes > _MAX_TEMPLATE_SCAN_BYTES:
                break
            document = yaml.safe_load(resolved.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, yaml.YAMLError):
            continue
        if not _template_is_safe(document, selected_ids):
            continue
        template_id = str(document["id"])
        if template_id in metadata:
            continue
        chosen.append(resolved)
        info = document.get("info") or {}
        metadata[template_id] = {
            "name": truncate(str(info.get("name") or template_id), 200),
            "severity": str(info.get("severity") or "info").lower(),
            "description": truncate(str(info.get("description") or ""), 500),
            "reference": info.get("reference"),
        }
    return chosen, metadata


class Module(ModuleBase):
    name = "Vulnerability verification"
    slug = "p17_vuln_verification"
    phase = 17
    description = "Run explicitly selected, validated low-impact community templates when authorized."
    tables = ("vuln_findings",)
    requires_binaries = ()
    optional_binaries = ("nuclei",)
    is_passive = False
    active_only = True

    def run(self, scope: Scope, config: dict[str, Any]) -> ResultSet:
        result = self.new_result()
        run_settings = config.get("_run") or {}
        if not bool(run_settings.get("active")) or not bool(run_settings.get("authorized")):
            result.note("Vulnerability verification skipped; both _run.active and _run.authorized must be true.")
            return result

        settings = phase_settings(config, self.phase)
        template_paths, template_metadata = _resolve_templates(settings, config)
        if not template_paths:
            result.note(
                "No safe templates selected. Configure community_template_dir and up to 10 explicit template_ids; no template update or installation is performed."
            )
            return result
        if not self.binary_available("nuclei", config):
            result.note("Nuclei is optional and not installed; no automatic installation was attempted.")
            return result

        max_hosts = _bounded_int(settings.get("max_targets"), 50, 1, 100)
        hosts = scoped_hosts(scope, config, limit=max_hosts)
        targets = _host_targets(hosts, config, scope)[:max_hosts]
        if not targets:
            result.note("No in-scope HTTP targets were available for verification.")
            return result

        rate = _bounded_int(settings.get("max_rate_per_second"), 1, 1, 1)
        template_args: list[str] = []
        for path in template_paths:
            template_args.extend(("-t", str(path)))
        seen: set[tuple[str, str]] = set()
        started = False
        scanned_addresses = 0
        skipped_hosts = 0

        for host, target in targets:
            addresses = resolve_host_addresses(host, config)
            if not addresses:
                skipped_hosts += 1
                continue
            target_parts = urlsplit(target)
            for address in addresses:
                pinned_target = _pinned_target(target, address)
                if not pinned_target:
                    continue
                if started:
                    time.sleep(1.0 / rate)
                started = True
                scanned_addresses += 1
                args = [
                    "-u",
                    pinned_target,
                    *template_args,
                    "-severity",
                    "info,low",
                    "-tags",
                    "misconfig,tech,ssl",
                    "-rl",
                    str(rate),
                    "-c",
                    "1",
                    "-bs",
                    "1",
                    "-timeout",
                    "5",
                    "-retries",
                    "0",
                    "-max-host-error",
                    "1",
                    "-disable-update-check",
                    "-disable-redirects",
                    "-no-interactsh",
                    "-jsonl",
                    "-silent",
                    "-H",
                    f"Host: {target_parts.netloc}",
                ]
                if target_parts.scheme == "https":
                    args.extend(("-sni", host))
                run = self.exec_tool("nuclei", args, config, timeout=180)
                result.record(run)
                if not run.ok:
                    continue
                for finding in run_json_lines(run.stdout):
                    template_id = str(finding.get("template-id") or finding.get("template_id") or "")
                    if template_id not in template_metadata:
                        continue
                    template = template_metadata[template_id]
                    info = finding.get("info") if isinstance(finding.get("info"), dict) else {}
                    severity = str(info.get("severity") or template["severity"]).lower()
                    if severity not in {"info", "low"}:
                        continue
                    matched = _safe_report_url(
                        finding.get("matched-at") or finding.get("matched_at") or finding.get("host"),
                        scope,
                        target,
                        expected_host=host,
                        pinned_address=address,
                    )
                    if not matched or host_of(matched) != host:
                        continue
                    key = (matched, template_id)
                    if key in seen:
                        continue
                    seen.add(key)
                    reference = info.get("reference", template.get("reference"))
                    if isinstance(reference, (list, tuple)):
                        reference = reference[0] if reference else None
                    result.add(
                        "vuln_findings",
                        url=matched,
                        host=host,
                        template_id=template_id,
                        name=truncate(str(info.get("name") or template["name"]), 200),
                        severity=severity,
                        description=truncate(str(info.get("description") or template["description"]), 500),
                        matched_at=matched,
                        reference=truncate(str(reference), 500) if reference else None,
                        source_tool="nuclei",
                    )

        if skipped_hosts:
            result.note(
                f"Skipped {skipped_hosts} host(s) without a safe DNS address; private or non-global destinations are blocked by default."
            )
        result.note(
            f"Ran validated low-impact templates against {scanned_addresses} pinned address(es) at no more than {rate} request/sec; no auto-install, template update, ZAP or Nikto scan was run."
        )
        return result
