"""Conservative, authorized-only Nmap port and service inventory."""

from __future__ import annotations

import xml.etree.ElementTree as ET
from typing import Any

from core.module_base import ModuleBase, ResultSet
from modules.common import phase_settings, resolve_host_addresses, scoped_hosts

_MAX_HOSTS = 1024
_MAX_TOP_PORTS = 1000
_TLS_SERVICE_NAMES = {"https", "ssl", "tls", "imaps", "pop3s", "smtps", "ftps"}


def _bounded_int(value: Any, default: int, minimum: int, maximum: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = default
    return max(minimum, min(parsed, maximum))


def _parse_nmap_xml(output: str, fallback_host: str) -> list[dict[str, Any]]:
    text = output or ""
    start = text.find("<?xml")
    if start < 0:
        start = text.find("<nmaprun")
    if start > 0:
        text = text[start:]
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return []

    rows: list[dict[str, Any]] = []
    for host_node in root.findall("host"):
        address = ""
        for address_node in host_node.findall("address"):
            if address_node.get("addrtype") in {"ipv4", "ipv6"}:
                address = address_node.get("addr", "")
                break
        for port_node in host_node.findall("./ports/port"):
            state_node = port_node.find("state")
            state = state_node.get("state", "") if state_node is not None else ""
            if state != "open":
                continue
            try:
                port = int(port_node.get("portid", ""))
            except ValueError:
                continue
            protocol = port_node.get("protocol", "tcp").lower()
            service_node = port_node.find("service")
            service = service_node.get("name", "") if service_node is not None else ""
            product = service_node.get("product", "") if service_node is not None else ""
            version = service_node.get("version", "") if service_node is not None else ""
            extra = service_node.get("extrainfo", "") if service_node is not None else ""
            tunnel = service_node.get("tunnel", "") if service_node is not None else ""
            version_text = " ".join(part for part in (product, version, extra) if part).strip()
            tls = (
                1
                if tunnel.lower() == "ssl"
                or service.lower() in _TLS_SERVICE_NAMES
                or port in {443, 465, 636, 853, 990, 993, 995, 8443}
                else (0 if service else None)
            )
            rows.append(
                {
                    "host": fallback_host,
                    "ip": address or None,
                    "port": port,
                    "protocol": protocol or "tcp",
                    "state": state,
                    "service": service or None,
                    "version": version_text or None,
                    "tls": tls,
                    "source_tool": "nmap",
                }
            )
    return rows


class Module(ModuleBase):
    name = "Ports & services"
    slug = "p04_ports_services"
    phase = 4
    description = "Run a bounded TCP top-ports scan only with active authorization."
    tables = ("ports_services",)
    requires_binaries = ("nmap",)
    is_passive = False
    active_only = True
    supports_active = True

    def run(self, scope, config: dict[str, Any]) -> ResultSet:
        result = self.new_result()
        run_flags = config.get("_run") or {}
        if run_flags.get("active") is not True or run_flags.get("authorized") is not True:
            result.note("Port scanning skipped; both active and authorized flags are required.")
            return result

        settings = phase_settings(config, self.phase)
        max_hosts = _bounded_int(settings.get("max_hosts", 1024), 1024, 1, _MAX_HOSTS)
        hosts = [
            host
            for host in scoped_hosts(
                scope,
                config,
                tables=("subdomains", "ips", "http_hosts", "endpoints"),
                limit=max_hosts,
            )
            if scope.allows(host)
        ]
        if not hosts:
            result.note("No discovered in-scope hosts are available for port scanning.")
            return result
        if not self.binary_available("nmap", config):
            result.note("Port scanning skipped; nmap is not installed.")
            return result

        top_ports = _bounded_int(settings.get("top_ports", 100), 100, 1, _MAX_TOP_PORTS)
        timing = str(settings.get("nmap_timing", "T3")).upper()
        if timing not in {"T2", "T3"}:
            timing = "T3"
        try:
            configured_rate = int(run_flags.get("rate_limit", (config.get("run") or {}).get("rate_limit", 10)))
        except (TypeError, ValueError):
            configured_rate = 10
        rate = max(1, min(configured_rate, 10))
        host_timeout = _bounded_int(settings.get("host_timeout", 60), 60, 15, 120)
        service_detection = bool(settings.get("service_detection", False))

        skipped_hosts = 0
        for host in hosts:
            if not scope.allows(host):
                continue
            addresses = resolve_host_addresses(host, config)
            if not addresses:
                skipped_hosts += 1
                continue
            for address in addresses:
                args = [
                    "-n",
                    "-Pn",
                    "-sT",
                    f"-T{timing[-1]}",
                    "--top-ports",
                    str(top_ports),
                    "--max-rate",
                    str(rate),
                    "--max-retries",
                    "1",
                    "--host-timeout",
                    f"{host_timeout}s",
                    "--open",
                    "-oX",
                    "-",
                ]
                if service_detection:
                    args.extend(("-sV", "--version-light"))
                args.append(address)
                tool_run = self.exec_tool(
                    "nmap",
                    args,
                    config,
                    timeout=min(host_timeout + 30, 150),
                )
                result.record(tool_run)
                if not tool_run.ok:
                    continue
                for row in _parse_nmap_xml(tool_run.stdout, host):
                    if scope.allows(row["host"]):
                        result.add("ports_services", row)
        if skipped_hosts:
            result.note(
                f"Skipped {skipped_hosts} host(s) without a safe DNS address; private or non-global destinations are blocked by default."
            )

        if len(hosts) >= max_hosts:
            result.note(f"Host list capped at {max_hosts} targets.")
        return result
