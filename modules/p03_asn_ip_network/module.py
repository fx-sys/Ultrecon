"""Map in-scope names to public IPs and passive ASN/prefix metadata."""

from __future__ import annotations

import ipaddress
import socket
from typing import Any

from core.config import source_enabled
from core.module_base import ModuleBase, ResultSet
from core.sources import bgpview_domain, bgpview_ip, ripestat_prefixes
from core.util import dedupe
from modules.common import http_client, is_public_ip, phase_settings, scoped_hosts

_MAX_IPS = 4096
_MAX_HOSTS = 1024
_MAX_ASN_LOOKUPS = 64
_MAX_RIPE_LOOKUPS = 32


def _bounded_int(value: Any, default: int, maximum: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = default
    return max(0, min(parsed, maximum))


def _payload_records(payload: Any) -> list[dict[str, Any]]:
    if not isinstance(payload, dict):
        return []
    data = payload.get("data") if isinstance(payload.get("data"), dict) else payload
    records: list[dict[str, Any]] = []
    for key in ("prefixes", "ipv4_prefixes", "ipv6_prefixes", "results", "asns"):
        value = data.get(key) if isinstance(data, dict) else None
        if isinstance(value, dict):
            records.append(value)
        elif isinstance(value, list):
            records.extend(item for item in value if isinstance(item, dict))
    if isinstance(data, dict) and any(
        key in data for key in ("ip", "address", "prefix", "cidr", "asn")
    ):
        records.append(data)
    return records


def _record_metadata(record: dict[str, Any]) -> dict[str, str]:
    asn_value = record.get("asn")
    asn_info = asn_value if isinstance(asn_value, dict) else {}
    asn_number = asn_info.get("asn") or (asn_value if not isinstance(asn_value, dict) else None)
    asn = str(asn_number).strip() if asn_number is not None else ""
    if asn and not asn.upper().startswith("AS"):
        asn = f"AS{asn}"
    prefix = str(record.get("prefix") or "").strip()
    if not prefix and record.get("ip") and record.get("cidr") is not None:
        try:
            prefix = f"{record['ip']}/{int(record['cidr'])}"
        except (TypeError, ValueError):
            prefix = ""
    org = str(
        asn_info.get("name")
        or asn_info.get("description")
        or record.get("organization")
        or record.get("org")
        or ""
    ).strip()
    country = str(asn_info.get("country_code") or record.get("country_code") or "").strip()
    return {"asn": asn, "org": org, "country": country, "prefix": prefix}


def _record_ip(record: dict[str, Any]) -> str:
    candidate = str(record.get("ip") or record.get("address") or "").strip()
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        return ""


def _valid_address(value: str, allow_private: bool) -> str | None:
    try:
        address = ipaddress.ip_address(value.strip())
    except ValueError:
        return None
    if not allow_private and not is_public_ip(str(address)):
        return None
    return str(address)


def _matching_metadata(ip: str, records: list[dict[str, Any]]) -> tuple[dict[str, str], list[str]]:
    address = ipaddress.ip_address(ip)
    matches: list[dict[str, Any]] = []
    prefixes: list[str] = []
    for record in records:
        record_ip = _record_ip(record)
        metadata = _record_metadata(record)
        prefix = metadata["prefix"]
        if prefix:
            try:
                network = ipaddress.ip_network(prefix, strict=False)
            except ValueError:
                network = None
            if network is not None:
                prefixes.append(str(network))
                if address.version == network.version and address in network:
                    matches.append(record)
        if record_ip == ip:
            matches.append(record)
    if not matches and len(records) == 1:
        matches = records
    combined = {"asn": "", "org": "", "country": ""}
    for record in matches:
        metadata = _record_metadata(record)
        for key in combined:
            if not combined[key] and metadata[key]:
                combined[key] = metadata[key]
    return combined, dedupe(prefixes)


class Module(ModuleBase):
    name = "ASN / IP / network mapping"
    slug = "p03_asn_ip_network"
    phase = 3
    description = "Resolve scoped hosts and enrich addresses with public ASN and prefix data."
    tables = ("ips",)
    is_passive = True

    def run(self, scope, config: dict[str, Any]) -> ResultSet:
        result = self.new_result()
        settings = phase_settings(config, self.phase)
        max_ips = _bounded_int(settings.get("max_ips", 512), 512, _MAX_IPS)
        max_hosts = _bounded_int(settings.get("max_hosts", min(max_ips, 512)), min(max_ips, 512), _MAX_HOSTS)
        if max_ips == 0 or max_hosts == 0:
            result.note("IP mapping skipped because configured caps are zero.")
            return result

        hosts = [
            host
            for host in scoped_hosts(
                scope,
                config,
                tables=("subdomains", "http_hosts", "endpoints"),
                limit=max_hosts,
            )
            if scope.allows(host)
        ]
        if not hosts:
            result.note("No discovered in-scope hosts are available for IP mapping.")
            return result

        allow_private = bool((config.get("http") or {}).get("allow_private_ips", False))
        use_bgpview = source_enabled(config, "bgpview")
        use_ripestat = source_enabled(config, "ripestat")
        http = http_client(config)
        resolved_by_host: dict[str, list[str]] = {}
        all_ips: list[str] = []
        domain_records: dict[str, list[dict[str, Any]]] = {}

        for host in hosts:
            addresses: list[str] = []
            try:
                for entry in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM):
                    sockaddr = entry[4]
                    address = _valid_address(str(sockaddr[0]), allow_private)
                    if address and address not in addresses:
                        addresses.append(address)
                    if len(addresses) >= max_ips:
                        break
            except OSError as exc:
                result.errors.append(f"DNS {host}: {exc}")

            if use_bgpview:
                try:
                    payload = bgpview_domain(http, host)
                    records = _payload_records(payload)
                    domain_records[host] = records
                    for record in records:
                        address = _valid_address(_record_ip(record), allow_private)
                        if address and address not in addresses:
                            addresses.append(address)
                except Exception as exc:
                    result.errors.append(f"BGPView {host}: {exc}")

            resolved_by_host[host] = addresses[:max_ips]
            for address in resolved_by_host[host]:
                if address not in all_ips:
                    all_ips.append(address)
                if len(all_ips) >= max_ips:
                    break
            if len(all_ips) >= max_ips:
                break

        ip_records: dict[str, list[dict[str, Any]]] = {}
        asn_lookups = 0
        if use_bgpview:
            for ip in all_ips[:_MAX_ASN_LOOKUPS]:
                host = next((h for h, values in resolved_by_host.items() if ip in values), "")
                records = list(domain_records.get(host, []))
                metadata, _ = _matching_metadata(ip, records)
                if not metadata["asn"] and asn_lookups < _MAX_ASN_LOOKUPS:
                    asn_lookups += 1
                    try:
                        records.extend(_payload_records(bgpview_ip(http, ip)))
                    except Exception as exc:
                        result.errors.append(f"BGPView {ip}: {exc}")
                ip_records[ip] = records

        prefixes_by_asn: dict[str, list[str]] = {}
        if use_ripestat:
            asns = dedupe(
                _record_metadata(record)["asn"]
                for records in ip_records.values()
                for record in records
                if _record_metadata(record)["asn"]
            )[:_MAX_RIPE_LOOKUPS]
            for asn in asns:
                try:
                    prefixes_by_asn[asn] = ripestat_prefixes(http, asn)[:256]
                except Exception as exc:
                    result.errors.append(f"RIPEstat {asn}: {exc}")

        emitted = 0
        seen_rows: set[tuple[str, str]] = set()
        for host, addresses in resolved_by_host.items():
            if not scope.allows(host):
                continue
            for ip in addresses:
                key = (ip, host)
                if key in seen_rows or emitted >= max_ips:
                    continue
                seen_rows.add(key)
                records = ip_records.get(ip, [])
                metadata, prefixes = _matching_metadata(ip, records)
                if metadata["asn"]:
                    prefixes.extend(prefixes_by_asn.get(metadata["asn"], []))
                result.add(
                    "ips",
                    ip=ip,
                    host=host,
                    asn=metadata["asn"] or None,
                    org=metadata["org"] or None,
                    country=metadata["country"] or None,
                    prefixes=dedupe(prefixes),
                    source_tool="BGPView" if records else "DNS",
                )
                emitted += 1
                if emitted >= max_ips:
                    break

        if len(all_ips) >= max_ips:
            result.note(f"IP result cap reached ({max_ips}).")
        if use_bgpview and len(all_ips) > _MAX_ASN_LOOKUPS:
            result.note(f"BGPView enrichment capped at {_MAX_ASN_LOOKUPS} IP lookups.")
        return result
