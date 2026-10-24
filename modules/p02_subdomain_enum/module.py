"""Passive-source subdomain collection and explicitly authorized DNS checks."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from core.config import api_key, source_enabled
from core.module_base import ModuleBase, ResultSet
from core.sources import (
    certspotter_subdomains,
    crtsh_subdomains,
    github_code_search_hosts,
    hackertarget_subdomains,
    is_hostname,
    rapiddns_subdomains,
    urlscan_subdomains,
    virustotal_subdomains,
)
from modules.common import http_client, phase_settings, previous_rows

_MAX_SUBDOMAINS = 5000
_MAX_DOMAINS = 500
_MAX_ACTIVE_CANDIDATES = 2000
_COMMON_LABELS = (
    "www", "api", "app", "admin", "auth", "beta", "blog", "cdn", "dev", "docs",
    "edge", "gateway", "help", "img", "internal", "login", "mail", "m", "mobile",
    "portal", "preview", "shop", "stage", "staging", "static", "status", "support",
    "test", "uat", "vpn", "web", "api-dev", "api-staging",
)
_PASSIVE_TOOLS = {
    "subfinder": ("subfinder", ("-silent", "-d")),
    "amass": ("amass", ("enum", "-passive", "-d")),
    "assetfinder": ("assetfinder", ("--subs-only",)),
}


def _bounded_int(value: Any, default: int, maximum: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = default
    return max(0, min(parsed, maximum))


def _domain_for(host: str, domains: list[str]) -> str:
    return next(
        (domain for domain in sorted(domains, key=len, reverse=True)
         if host == domain or host.endswith("." + domain)),
        "",
    )


class Module(ModuleBase):
    name = "Subdomain enumeration"
    slug = "p02_subdomain_enum"
    phase = 2
    description = "Collect passive subdomains and gate bounded DNS enumeration on authorization."
    tables = ("subdomains",)
    requires_binaries = ("subfinder", "amass", "assetfinder")
    active_binaries = ("dnsx",)
    is_passive = False
    supports_active = True

    def run(self, scope, config: dict[str, Any]) -> ResultSet:
        result = self.new_result()
        settings = phase_settings(config, self.phase)
        max_subdomains = _bounded_int(
            settings.get("max_subdomains", 5000), 5000, _MAX_SUBDOMAINS
        )
        max_domains = _bounded_int(settings.get("max_domains", 100), 100, _MAX_DOMAINS)
        domains = scope.enumeration_seeds[:max_domains]
        if len(scope.enumeration_seeds) > len(domains):
            result.note(f"Domain processing capped at {max_domains} entries.")
        if max_subdomains == 0 or not domains:
            result.note("No domains or subdomain result capacity is available.")
            return result

        configured = settings.get("passive_sources")
        source_filter = (
            {str(source).strip().lower() for source in configured}
            if isinstance(configured, (list, tuple, set))
            else {"subfinder", "amass", "assetfinder", "crtsh", "hackertarget", "rapiddns"}
        )
        http = http_client(config)
        known: set[str] = set()
        for row in previous_rows(config, "subdomains"):
            host = str(row.get("host") or "").strip().lower().rstrip(".")
            if host and scope.allows(host):
                known.add(host)

        seen: set[str] = set()

        def add_host(value: str, domain: str, source_tool: str) -> None:
            host = str(value or "").strip().lower().rstrip(".")
            if (
                not host
                or host in seen
                or not is_hostname(host)
                or not scope.allows(host)
                or not _domain_for(host, domains)
            ):
                return
            if len(seen) >= max_subdomains:
                return
            seen.add(host)
            result.add("subdomains", host=host, domain=domain, source_tool=source_tool)

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
                        http, domain, api_key(config, "urlscan"), limit=max_subdomains
                    ),
                    "urlscan.io",
                ),
                (
                    "virustotal",
                    "virustotal",
                    lambda domain=domain: virustotal_subdomains(
                        http, domain, api_key(config, "virustotal"), limit=max_subdomains
                    ),
                    "VirusTotal",
                ),
                (
                    "github",
                    "github",
                    lambda domain=domain: github_code_search_hosts(
                        http, domain, api_key(config, "github"), limit=max_subdomains
                    ),
                    "GitHub Code Search",
                ),
            ]
            for source, key_name, collector, label in collectors:
                if source not in source_filter or not source_enabled(
                    config, source, needs_key=key_name
                ):
                    continue
                if len(seen) >= max_subdomains:
                    break
                try:
                    for item in collector() or []:
                        host = item[0] if isinstance(item, (tuple, list)) and item else item
                        add_host(str(host), domain, label)
                except Exception as exc:  # public sources are best-effort
                    result.errors.append(f"{label}: {exc}")

            for source, (binary, prefix_args) in _PASSIVE_TOOLS.items():
                if source not in source_filter or len(seen) >= max_subdomains:
                    continue
                if not self.binary_available(binary, config):
                    continue
                timeout = max(1, _bounded_int(settings.get("passive_timeout", 90), 90, 180))
                run = self.exec_tool(
                    binary,
                    [*prefix_args, domain],
                    config,
                    timeout=timeout,
                )
                result.record(run)
                if not run.ok:
                    continue
                for line in run.stdout.splitlines():
                    candidate = line.strip().split(maxsplit=1)[0] if line.strip() else ""
                    add_host(candidate, domain, binary)
                    if len(seen) >= max_subdomains:
                        break

        run_flags = config.get("_run") or {}
        if run_flags.get("active") is not True or run_flags.get("authorized") is not True:
            result.note("Active DNS enumeration skipped; both active and authorized flags are required.")
            return result

        active_sources = settings.get("active_sources", ["dnsx"])
        active_sources = {
            str(source).strip().lower()
            for source in active_sources
            if str(source).strip()
        } if isinstance(active_sources, (list, tuple, set)) else set()
        if "dnsx" not in active_sources:
            result.note("Active DNS enumeration skipped; dnsx is not enabled in p02.active_sources.")
            return result
        if not self.binary_available("dnsx", config):
            result.note("Active DNS enumeration skipped; dnsx is not installed.")
            return result

        candidate_cap = _bounded_int(
            settings.get("max_active_candidates", min(max_subdomains, 1000)),
            min(max_subdomains, 1000),
            _MAX_ACTIVE_CANDIDATES,
        )
        candidates: list[str] = []
        candidate_domains: dict[str, str] = {}

        def add_candidate(host: str, domain: str) -> None:
            normalized = host.strip().lower().rstrip(".")
            if (
                candidate_cap == 0
                or len(candidates) >= candidate_cap
                or normalized in candidate_domains
                or not is_hostname(normalized)
                or not scope.allows(normalized)
            ):
                return
            candidate_domains[normalized] = domain
            candidates.append(normalized)

        for domain in domains:
            for host in sorted(known):
                if _domain_for(host, [domain]):
                    add_candidate(host, domain)
            for label in _COMMON_LABELS:
                candidate = f"{label}.{domain}"
                if scope.allows(candidate):
                    add_candidate(candidate, domain)
                if len(candidates) >= candidate_cap:
                    break
            if len(candidates) >= candidate_cap:
                break

        if not candidates:
            result.note("No in-scope DNS candidates were available for active enumeration.")
            return result

        run_cfg = config.get("run") or {}
        try:
            configured_rate = int(run_flags.get("rate_limit", run_cfg.get("rate_limit", 10)))
        except (TypeError, ValueError):
            configured_rate = 10
        rate = max(1, min(configured_rate, 10))
        timeout = _bounded_int(settings.get("active_timeout", 45), 45, 120)
        tool_run = self.exec_tool(
            "dnsx",
            ["-silent", "-rl", str(rate)],
            config,
            timeout=max(1, timeout),
            input_text="\n".join(candidates) + "\n",
        )
        result.record(tool_run)
        if not tool_run.ok:
            return result

        candidate_set = set(candidates)
        for line in tool_run.stdout.splitlines():
            output_host = line.strip().split(maxsplit=1)[0].lower().rstrip(".") if line.strip() else ""
            if output_host in candidate_set:
                add_host(output_host, candidate_domains[output_host], "dnsx")
        if len(candidates) >= candidate_cap:
            result.note(f"Active DNS candidate list capped at {candidate_cap} names.")
        return result
