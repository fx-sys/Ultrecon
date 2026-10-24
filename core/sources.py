"""Built-in free data-source collectors (no API key required unless noted).

These functions are deliberately defensive: public endpoints change, rate
limit, and fail. A source that errors returns an empty list and logs at debug;
the phase continues with the remaining sources.
"""

from __future__ import annotations

import json
import re
from typing import Any
from urllib.parse import quote

from core.http import ReconHTTP
from core.logging_utils import get_logger
from core.util import dedupe, truncate

log = get_logger(__name__)

_HOST_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$",
    re.IGNORECASE,
)


def is_hostname(value: str) -> bool:
    return bool(_HOST_RE.match(value.strip().rstrip(".")))


def hosts_for_domain(values: list[str], domain: str) -> list[str]:
    suffix = "." + domain.lower().rstrip(".")
    out: list[str] = []
    for value in values:
        host = value.strip().lower().rstrip(".")
        if host.startswith("*."):
            host = host[2:]
        if host == domain:
            continue
        if host.endswith(suffix) and is_hostname(host):
            out.append(host)
    return dedupe(out)


def crtsh_subdomains(http: ReconHTTP, domain: str, timeout: float = 45) -> list[str]:
    """Certificate Transparency logs via crt.sh's JSON endpoint (free)."""
    url = f"https://crt.sh/?q=%25.{quote(domain)}&output=json"
    data = http.get_json(url, scope_check=False, timeout=timeout)
    if not isinstance(data, list):
        log.debug("crt.sh returned no parsable data for %s", domain)
        return []
    names: list[str] = []
    for entry in data:
        if not isinstance(entry, dict):
            continue
        for name in str(entry.get("name_value") or "").splitlines():
            names.append(name)
        for name in str(entry.get("common_name") or "").splitlines():
            names.append(name)
    return hosts_for_domain(names, domain)


def hackertarget_subdomains(http: ReconHTTP, domain: str) -> list[tuple[str, str | None]]:
    """HackerTarget hostsearch free endpoint; returns (host, ip) pairs."""
    url = f"https://api.hackertarget.com/hostsearch/?q={quote(domain)}"
    text = http.get_text(url, scope_check=False) or ""
    if "API count exceeded" in text or "<html" in text.lower():
        log.debug("HackerTarget rate limit or HTML response for %s", domain)
        return []
    pairs: list[tuple[str, str | None]] = []
    for line in text.splitlines():
        if "," not in line:
            continue
        host, _, ip = line.partition(",")
        host = host.strip().lower().rstrip(".")
        if is_hostname(host) and (host == domain or host.endswith("." + domain)):
            pairs.append((host, ip.strip() or None))
    return dedupe(pairs)


def rapiddns_subdomains(http: ReconHTTP, domain: str) -> list[str]:
    """RapidDNS free HTML subdomain listing (best-effort scraping)."""
    url = f"https://rapiddns.io/subdomain/{quote(domain)}?full=1#result"
    text = http.get_text(url, scope_check=False) or ""
    candidates = re.findall(
        r"\b([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*\."
        + re.escape(domain.rstrip("."))
        + r")\b",
        text,
        flags=re.IGNORECASE,
    )
    return hosts_for_domain(candidates, domain)


def certspotter_subdomains(http: ReconHTTP, domain: str, token: str | None = None) -> list[str]:
    url = (
        "https://api.certspotter.com/v1/issuances?"
        f"domain={quote(domain)}&include_subdomains=true&expand=dns_names"
    )
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    text = http.get_text(url, scope_check=False, headers=headers)
    if not text:
        return []
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    names: list[str] = []
    if isinstance(data, list):
        for item in data:
            if isinstance(item, dict):
                names.extend(str(n) for n in item.get("dns_names") or [])
    return hosts_for_domain(names, domain)


def virustotal_subdomains(
    http: ReconHTTP, domain: str, api_key: str, limit: int = 200
) -> list[str]:
    out: list[str] = []
    url = f"https://www.virustotal.com/api/v3/domains/{quote(domain)}/subdomains?limit=40"
    headers = {"x-apikey": api_key}
    while url and len(out) < limit:
        data = http.get_json(url, scope_check=False, headers=headers)
        if not isinstance(data, dict):
            break
        for item in (data.get("data") or []):
            try:
                out.append(item["id"])
            except (KeyError, TypeError):
                continue
        url = (data.get("links") or {}).get("next")
    return hosts_for_domain(out[:limit], domain)


def urlscan_subdomains(
    http: ReconHTTP, domain: str, api_key: str | None = None, limit: int = 200
) -> list[str]:
    url = f"https://urlscan.io/api/v1/search/?q=domain%3A{quote(domain)}&size=100"
    headers = {"api-key": api_key} if api_key else {}
    data = http.get_json(url, scope_check=False, headers=headers)
    out: list[str] = []
    if isinstance(data, dict):
        for result in data.get("results") or []:
            page = result.get("page") or {}
            if page.get("domain"):
                out.append(str(page["domain"]))
            task = result.get("task") or {}
            if task.get("domain"):
                out.append(str(task["domain"]))
    return hosts_for_domain(out[:limit], domain)


def commoncrawl_urls(
    http: ReconHTTP, domain: str, limit: int = 500
) -> list[str]:
    indexes = http.get_json("https://index.commoncrawl.org/collinfo.json", scope_check=False)
    if not isinstance(indexes, list) or not indexes:
        return []
    index_id = indexes[0].get("id") if isinstance(indexes[0], dict) else None
    if not index_id:
        return []
    url = (
        f"https://index.commoncrawl.org/{index_id}-index?"
        f"url=*.{quote(domain)}%2F*&output=json&fl=url&collapse=urlkey&limit={int(limit)}"
    )
    text = http.get_text(url, scope_check=False, timeout=60) or ""
    out: list[str] = []
    for line in text.splitlines():
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(row, dict) and row.get("url"):
            out.append(str(row["url"]))
    return dedupe(out)[:limit]


def wayback_urls(http: ReconHTTP, domain: str, limit: int = 1000) -> list[str]:
    url = (
        "https://web.archive.org/cdx/search/cdx?"
        f"url={quote(domain)}%2F*&output=json&fl=original&collapse=urlkey"
        f"&limit={int(limit)}&filter=statuscode:200"
    )
    data = http.get_json(url, scope_check=False, timeout=60)
    out: list[str] = []
    if isinstance(data, list):
        for row in data[1:]:
            if isinstance(row, list) and row:
                out.append(str(row[0]))
            elif isinstance(row, str):
                out.append(row)
    return dedupe(out)[:limit]


def github_code_search_hosts(
    http: ReconHTTP, domain: str, token: str, limit: int = 200
) -> list[str]:
    # The code-search API requires authentication; unauthenticated callers are
    # rate limited to a point where it is not worth wiring in.
    url = f"https://api.github.com/search/code?q={quote(domain)}&per_page=100"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    data = http.get_json(url, scope_check=False, headers=headers)
    out: list[str] = []
    if isinstance(data, dict):
        for item in data.get("items") or []:
            repo = item.get("repository") or {}
            for field in ("full_name", "html_url", "description"):
                value = str(repo.get(field) or "")
                out.extend(re.findall(r"[a-z0-9.-]+", value.lower()))
    return hosts_for_domain(out[:limit], domain)


def bgpview_domain(http: ReconHTTP, domain: str) -> dict[str, Any]:
    data = http.get_json(
        f"https://api.bgpview.io/search?query_term={quote(domain)}", scope_check=False
    )
    return data if isinstance(data, dict) else {}


def bgpview_ip(http: ReconHTTP, ip: str) -> dict[str, Any]:
    data = http.get_json(f"https://api.bgpview.io/ip/{quote(ip)}", scope_check=False)
    return data if isinstance(data, dict) else {}


def ripestat_prefixes(http: ReconHTTP, asn: str) -> list[str]:
    resource = asn if asn.upper().startswith("AS") else f"AS{asn}"
    data = http.get_json(
        f"https://stat.ripe.net/data/announced-prefixes/data.json?resource={quote(resource)}",
        scope_check=False,
    )
    out: list[str] = []
    if isinstance(data, dict):
        for item in (data.get("data") or {}).get("prefixes") or []:
            if isinstance(item, dict) and item.get("prefix"):
                out.append(str(item["prefix"]))
    return dedupe(out)


def extract_emails(text: str, limit: int = 200) -> list[str]:
    return dedupe(re.findall(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", text))[:limit]


def summarize_source_error(source: str, exc: Exception) -> str:
    return f"{source}: {truncate(str(exc), 200)}"
