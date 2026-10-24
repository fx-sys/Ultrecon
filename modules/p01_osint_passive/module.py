"""Passive OSINT collection from free public data sources."""

from __future__ import annotations

import ipaddress
from collections.abc import Callable
from typing import Any

from core.config import api_key, source_enabled
from core.http import normalize_url
from core.module_base import ModuleBase, ResultSet
from core.sources import (
    certspotter_subdomains,
    commoncrawl_urls,
    crtsh_subdomains,
    github_code_search_hosts,
    hackertarget_subdomains,
    rapiddns_subdomains,
    urlscan_subdomains,
    virustotal_subdomains,
    wayback_urls,
)
from core.util import host_of
from modules.common import http_client, phase_settings

_MAX_RESULTS = 5000
_MAX_DOMAINS = 500


def _bounded_int(value: Any, default: int, maximum: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = default
    return max(0, min(parsed, maximum))


class Module(ModuleBase):
    name = "Passive OSINT & org recon"
    slug = "p01_osint_passive"
    phase = 1
    description = "Collect in-scope hosts and archived URLs from free public sources."
    tables = ("subdomains", "ips", "endpoints")
    is_passive = True

    def run(self, scope, config: dict[str, Any]) -> ResultSet:
        result = self.new_result()
        settings = phase_settings(config, self.phase)
        max_results = _bounded_int(settings.get("max_results", 5000), 5000, _MAX_RESULTS)
        max_domains = _bounded_int(settings.get("max_domains", 100), 100, _MAX_DOMAINS)
        domains = scope.domains[:max_domains]
        if len(scope.domains) > len(domains):
            result.note(f"Domain processing capped at {max_domains} entries.")
        if not domains or max_results == 0:
            result.note("No domains or result capacity is available for passive OSINT.")
            return result

        configured = settings.get("sources")
        source_filter = (
            {str(source).strip().lower() for source in configured}
            if isinstance(configured, (list, tuple, set))
            else None
        )

        def enabled(source: str, key_name: str | None = None) -> bool:
            return (source_filter is None or source in source_filter) and source_enabled(
                config, source, needs_key=key_name
            )

        http = http_client(config)
        seen_hosts: set[str] = set()
        seen_ips: set[tuple[str, str]] = set()
        seen_urls: set[str] = set()
        optional_sources_called = 0
        allow_private = bool((config.get("http") or {}).get("allow_private_ips", False))

        def add_host(value: str, domain: str, source_tool: str) -> None:
            host = str(value or "").strip().lower().rstrip(".")
            if not host or not scope.allows(host) or host in seen_hosts:
                return
            if len(seen_hosts) >= max_results:
                return
            seen_hosts.add(host)
            result.add("subdomains", host=host, domain=domain, source_tool=source_tool)

        def add_ip(value: str, host: str, source_tool: str) -> None:
            candidate = str(value or "").strip()
            if not candidate or not scope.allows(host):
                return
            try:
                address = ipaddress.ip_address(candidate)
            except ValueError:
                return
            if not allow_private and not address.is_global:
                return
            key = (str(address), host)
            if key in seen_ips or len(seen_ips) >= max_results:
                return
            seen_ips.add(key)
            result.add("ips", ip=str(address), host=host, source_tool=source_tool)

        def add_url(value: str, source_tool: str) -> None:
            url = normalize_url(str(value or ""))
            host = host_of(url or "")
            if not url or not scope.allows(host) or url in seen_urls:
                return
            if len(seen_urls) >= max_results:
                return
            seen_urls.add(url)
            result.add(
                "endpoints",
                url=url,
                host=host,
                method="GET",
                source_detail=source_tool,
                source_tool=source_tool,
            )

        for domain in domains:
            collectors: list[tuple[str, str | None, Callable[[], Any], str]] = [
                (
                    "crtsh",
                    None,
                    lambda domain=domain: crtsh_subdomains(http, domain),
                    "crt.sh",
                ),
                (
                    "hackertarget",
                    None,
                    lambda domain=domain: hackertarget_subdomains(http, domain),
                    "HackerTarget",
                ),
                (
                    "rapiddns",
                    None,
                    lambda domain=domain: rapiddns_subdomains(http, domain),
                    "RapidDNS",
                ),
                (
                    "certspotter",
                    "certspotter",
                    lambda domain=domain: certspotter_subdomains(
                        http, domain, api_key(config, "certspotter")
                    ),
                    "CertSpotter",
                ),
                (
                    "urlscan",
                    "urlscan",
                    lambda domain=domain: urlscan_subdomains(
                        http, domain, api_key(config, "urlscan"), limit=max_results
                    ),
                    "urlscan.io",
                ),
                (
                    "virustotal",
                    "virustotal",
                    lambda domain=domain: virustotal_subdomains(
                        http, domain, api_key(config, "virustotal"), limit=max_results
                    ),
                    "VirusTotal",
                ),
                (
                    "github",
                    "github",
                    lambda domain=domain: github_code_search_hosts(
                        http, domain, api_key(config, "github"), limit=max_results
                    ),
                    "GitHub Code Search",
                ),
            ]
            for source, key_name, collector, label in collectors:
                if not enabled(source, key_name) or len(seen_hosts) >= max_results:
                    continue
                optional_sources_called += 1
                try:
                    for item in collector() or []:
                        if isinstance(item, (tuple, list)):
                            host = str(item[0] if item else "")
                            add_host(host, domain, label)
                            ip_value = item[1] if len(item) > 1 else None
                            add_ip(str(ip_value or ""), host.strip().lower().rstrip("."), label)
                        else:
                            add_host(str(item), domain, label)
                except Exception as exc:  # one public source must not stop the phase
                    result.errors.append(f"{label}: {exc}")

            archive_collectors: list[tuple[str, Callable[[int], Any], str]] = [
                (
                    "commoncrawl",
                    lambda limit, domain=domain: commoncrawl_urls(http, domain, limit=limit),
                    "Common Crawl",
                ),
                (
                    "wayback",
                    lambda limit, domain=domain: wayback_urls(http, domain, limit=limit),
                    "Wayback Machine",
                ),
            ]
            for source, collector, label in archive_collectors:
                if not enabled(source) or len(seen_urls) >= max_results:
                    continue
                optional_sources_called += 1
                remaining = max_results - len(seen_urls)
                try:
                    for url in collector(remaining) or []:
                        add_url(str(url), label)
                except Exception as exc:  # archive APIs are best-effort
                    result.errors.append(f"{label}: {exc}")

        if optional_sources_called == 0:
            result.note("No passive OSINT sources are enabled; API-key sources remain opt-in.")
        return result
