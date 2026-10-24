"""Passive CMS and application-framework fingerprinting."""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlsplit

from core.http import detect_tech, normalize_url, parse_html
from core.module_base import ModuleBase, ResultSet
from core.scope import Scope
from core.util import dedupe, host_of
from modules.common import http_client, phase_settings, previous_rows, scoped_hosts

_DEFAULT_PROBES = ("/wp-json/", "/wp-login.php", "/administrator/", "/user/login", "/sitemap.xml")
_TECH_TO_CMS = {
    "wordpress": "WordPress",
    "drupal": "Drupal",
    "joomla": "Joomla",
    "magento": "Magento",
    "shopify": "Shopify",
    "django": "Django",
    "laravel": "Laravel",
    "ruby on rails": "Ruby on Rails",
    "spring": "Spring",
    "asp.net": "ASP.NET",
    "next.js": "Next.js",
    "nuxt": "Nuxt",
}


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
        or any(segment == ".." for segment in path.split("?", 1)[0].split("/"))
    ):
        return None
    return path[:256]


def _version_for(cms: str, body: str, headers: dict[str, str]) -> str | None:
    text = (body or "")[:200_000]
    lower = text.lower()
    patterns = {
        "WordPress": r"(?:wordpress\s+|wp-)(\d{1,2}\.\d+(?:\.\d+)?)",
        "Drupal": r"drupal\s+(\d{1,2}(?:\.\d+){0,2})",
        "Joomla": r"joomla!?\s*(\d{1,2}(?:\.\d+){0,2})",
        "Magento": r"magento(?:\s+version)?[\s:/=]+(\d{1,2}(?:\.\d+){0,2})",
        "Django": r"django[\s:/=]+(\d{1,2}(?:\.\d+){0,2})",
        "Laravel": r"laravel[\s:/=]+(\d{1,2}(?:\.\d+){0,2})",
        "Next.js": r"next\.js[\s:/=]+(\d{1,2}(?:\.\d+){0,2})",
        "Nuxt": r"nuxt(?:\.js)?[\s:/=]+(\d{1,2}(?:\.\d+){0,2})",
    }
    if cms == "WordPress":
        parser = parse_html(text)
        generator = parser.generator
        match = re.search(r"wordpress\s+([0-9.]+)", generator, re.I)
        if match:
            return match.group(1)[:40]
    pattern = patterns.get(cms)
    if pattern:
        match = re.search(pattern, lower, re.I)
        if match:
            return match.group(1)[:40]
    for key in ("x-drupal-dynamic-cache", "x-generator", "x-powered-by"):
        value = next((v for k, v in headers.items() if k.lower() == key), "")
        if value and cms.lower() in value.lower():
            match = re.search(r"\b\d{1,2}(?:\.\d+){1,2}\b", value)
            if match:
                return match.group(0)
    return None


def _fingerprints(headers: dict[str, str], body: str, path: str) -> list[tuple[str, str, str | None]]:
    normalized_headers = {str(k): str(v) for k, v in headers.items()}
    detected = {item.lower(): item for item in detect_tech(normalized_headers, body)}
    blob = ((body or "")[:200_000] + " " + " ".join(normalized_headers.values())).lower()
    path_lower = path.lower()
    candidates: dict[str, str] = {}

    for signature, cms in _TECH_TO_CMS.items():
        tech = detected.get(signature.lower())
        if tech or signature in blob:
            candidates[cms] = "technology signature"
    if path_lower.startswith("/wp-json") and any(marker in blob for marker in ("namespaces", "wp/v2", "wordpress")):
        candidates["WordPress"] = "WordPress REST metadata route"
    if path_lower.startswith("/wp-login") and ("wp-login" in blob or "wordpress" in blob or "wp-submit" in blob):
        candidates["WordPress"] = "WordPress login page marker"
    if path_lower.startswith("/administrator") and ("joomla" in blob or "com_login" in blob):
        candidates["Joomla"] = "Joomla administrator page marker"
    if path_lower.startswith("/user/login") and ("drupal" in blob or "user-login-form" in blob):
        candidates["Drupal"] = "Drupal login page marker"
    if "meta name=\"generator\" content=\"wordpress" in blob or "meta name='generator' content='wordpress" in blob:
        candidates["WordPress"] = "HTML generator metadata"

    return [
        (cms, evidence, _version_for(cms, body, normalized_headers))
        for cms, evidence in candidates.items()
    ]


def _host_bases(host: str, config: dict[str, Any], scope: Scope) -> list[str]:
    for row in previous_rows(config, "http_hosts"):
        url = normalize_url(str(row.get("url") or ""))
        if url and host_of(url) == host and scope.allows(host):
            parts = urlsplit(url)
            return [f"{parts.scheme}://{parts.netloc}"]
    return [f"https://{host}"] if scope.allows(host) else []


class Module(ModuleBase):
    name = "CMS and framework fingerprint"
    slug = "p16_cms_fingerprint"
    phase = 16
    description = "Passively fingerprint CMS and framework metadata using bounded GET requests."
    tables = ("cms_fingerprints",)
    is_passive = True

    def run(self, scope: Scope, config: dict[str, Any]) -> ResultSet:
        result = self.new_result()
        settings = phase_settings(config, self.phase)
        hosts = scoped_hosts(
            scope,
            config,
            limit=_bounded_int(settings.get("max_hosts"), 500, 500),
        )
        raw_probes = settings.get("probes", _DEFAULT_PROBES)
        if not isinstance(raw_probes, (list, tuple)):
            raw_probes = _DEFAULT_PROBES
        probes = dedupe(path for item in raw_probes if (path := _safe_path(item)))[:20]
        max_checks = _bounded_int(settings.get("max_checks"), 2000, 3000)
        max_bytes = min(_bounded_int((config.get("http") or {}).get("max_bytes"), 256_000, 512_000), 512_000)
        client = http_client(config)
        seen: set[tuple[str, str, str | None]] = set()

        # Reuse prior fingerprint metadata without making another request.
        for row in previous_rows(config, "http_hosts"):
            host = str(row.get("host") or host_of(str(row.get("url") or ""))).lower().rstrip(".")
            if not host or not scope.allows(host):
                continue
            tech = str(row.get("tech") or "")
            for value in tech.split(","):
                cms = _TECH_TO_CMS.get(value.strip().lower())
                if cms:
                    key = (host, cms, None)
                    if key not in seen:
                        seen.add(key)
                        result.add(
                            "cms_fingerprints",
                            host=host,
                            cms=cms,
                            version=None,
                            evidence="Previously observed HTTP technology signature",
                            confidence="low",
                        )

        checks = 0
        for host in hosts:
            if not scope.allows(host):
                continue
            for base in _host_bases(host, config, scope):
                paths = ["/"] + probes
                for path in dedupe(paths):
                    if checks >= max_checks:
                        result.note(f"Stopped after the configured request limit ({max_checks}).")
                        break
                    url = normalize_url(base + path)
                    if not url or not scope.allows(host_of(url)):
                        continue
                    checks += 1
                    response = client.get(url, max_bytes=max_bytes)
                    if response is None or response.status_code < 200 or response.status_code >= 400:
                        continue
                    body = response.text[:max_bytes]
                    headers = {str(k): str(v) for k, v in response.headers.items()}
                    for cms, evidence, version in _fingerprints(headers, body, path):
                        key = (host, cms, version)
                        if key in seen:
                            continue
                        seen.add(key)
                        result.add(
                            "cms_fingerprints",
                            host=host,
                            cms=cms,
                            version=version,
                            evidence=f"{evidence} at {path}"[:300],
                            confidence="high" if evidence != "technology signature" else "medium",
                        )
                if checks >= max_checks:
                    break
            if checks >= max_checks:
                break

        result.note(
            f"Made {checks} bounded passive CMS fingerprint request(s); no login or state-changing actions were sent."
        )
        return result
