"""Bounded in-scope web crawling and public-archive URL collection."""

from __future__ import annotations

import html
import re
from collections import deque
from typing import Any
from urllib.parse import parse_qsl, urljoin, urlsplit, urlunsplit

from core.http import (
    extract_links,
    is_asset_url,
    is_js_url,
    normalize_url,
)
from core.module_base import ModuleBase, ResultSet
from core.scope import Scope
from core.sources import commoncrawl_urls, wayback_urls
from core.util import dedupe, host_of
from modules.common import http_client, phase_settings, scoped_hosts, scoped_urls, target_url

_SITEMAP_LOC_RE = re.compile(r"<loc\b[^>]*>(.*?)</loc\s*>", re.IGNORECASE | re.DOTALL)


def _bounded_int(value: Any, default: int, minimum: int, maximum: int) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError):
        number = default
    return max(minimum, min(number, maximum))


def _clean_url(url: str) -> str | None:
    normalized = normalize_url(url)
    if not normalized:
        return None
    parts = urlsplit(normalized)
    return urlunsplit((parts.scheme, parts.netloc, parts.path or "/", "", ""))


def _sitemap_locations(text: str, base: str, scope: Scope, limit: int) -> list[str]:
    urls: list[str] = []
    for match in _SITEMAP_LOC_RE.finditer(text or ""):
        candidate = normalize_url(html.unescape(match.group(1).strip()), base)
        if candidate and scope.allows(host_of(candidate)):
            clean = _clean_url(candidate)
            if clean and clean not in urls:
                urls.append(clean)
        if len(urls) >= limit:
            break
    return urls


def _root(url: str, host: str) -> str | None:
    normalized = normalize_url(url)
    if not normalized or host_of(normalized) != host:
        return None
    parts = urlsplit(normalized)
    return urlunsplit((parts.scheme, parts.netloc, "/", "", ""))


class Module(ModuleBase):
    name = "Crawling & endpoint discovery"
    slug = "p07_crawling_endpoints"
    phase = 7
    description = "Crawl in-scope web pages and collect URLs from public archives."
    requires_binaries: tuple[str, ...] = ()
    optional_binaries: tuple[str, ...] = ()
    is_passive = True
    supports_active = False
    tables = ("endpoints", "parameters")

    def run(self, scope: Scope, config: dict[str, Any]) -> ResultSet:
        result = self.new_result()
        settings = phase_settings(config, self.phase)
        http = http_client(config)
        depth_limit = _bounded_int(settings.get("crawl_depth"), 1, 0, 3)
        per_host_limit = _bounded_int(settings.get("max_urls_per_host"), 250, 1, 2000)
        total_limit = _bounded_int(settings.get("max_total_urls"), 5000, 1, 10000)
        max_hosts = _bounded_int(settings.get("max_hosts"), 200, 1, 2000)
        request_bytes = _bounded_int(settings.get("max_page_bytes"), 512 * 1024, 4096, 2 * 1024 * 1024)

        root_rows = scoped_urls(scope, config, tables=("http_hosts",), limit=max_hosts * 2)
        roots_by_host: dict[str, str] = {}
        for url in root_rows:
            host = host_of(url)
            if host and scope.allows(host) and host not in roots_by_host:
                roots_by_host[host] = _root(url, host) or url
        for host in scoped_hosts(scope, config, tables=("http_hosts", "subdomains"), limit=max_hosts):
            if scope.allows(host) and host not in roots_by_host:
                roots_by_host[host] = target_url(host)
        roots = list(roots_by_host.items())[:max_hosts]

        emitted: set[str] = set()
        per_host_counts: dict[tuple[str, str], int] = {}

        def emit(url: str, detail: str, status_code: int | None = None, content_type: str | None = None) -> str | None:
            normalized = normalize_url(url)
            if not normalized:
                return None
            host = host_of(normalized)
            if not host or not scope.allows(host):
                return None
            parts = urlsplit(normalized)
            for name, _value in parse_qsl(parts.query, keep_blank_values=True)[:100]:
                if re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", name):
                    result.add(
                        "parameters",
                        url=_clean_url(normalized),
                        host=host,
                        name=name,
                        location="query",
                        source_tool="builtin",
                    )
            clean = _clean_url(normalized)
            if not clean:
                return None
            source_bucket = "archive" if "archive" in detail.lower() else "crawl"
            host_bucket = (host, source_bucket)
            if clean not in emitted and len(emitted) < total_limit:
                if per_host_counts.get(host_bucket, 0) < per_host_limit:
                    emitted.add(clean)
                    per_host_counts[host_bucket] = per_host_counts.get(host_bucket, 0) + 1
                    result.add(
                        "endpoints",
                        url=clean,
                        host=host,
                        method="GET",
                        status_code=status_code,
                        content_type=content_type,
                        source_detail=detail,
                        source_tool="builtin",
                    )
            return clean

        sources = settings.get("sources")
        source_names = {str(item).lower() for item in sources} if isinstance(sources, (list, tuple)) else {"builtin", "waybackurls", "commoncrawl"}
        archive_domains = _bounded_int(settings.get("max_archive_domains"), 10, 1, 50)
        wayback_limit = _bounded_int(settings.get("wayback_limit"), 1000, 1, 2000)
        commoncrawl_limit = _bounded_int(settings.get("commoncrawl_limit"), 500, 1, 1000)
        for domain in scope.domains[:archive_domains]:
            if "waybackurls" in source_names and len(emitted) < total_limit:
                try:
                    for url in wayback_urls(http, domain, limit=min(wayback_limit, total_limit)):
                        emit(url, "Wayback Machine archive")
                        if len(emitted) >= total_limit:
                            break
                except Exception:
                    result.note(f"Wayback archive lookup failed for {domain}.")
            if "commoncrawl" in source_names and len(emitted) < total_limit:
                try:
                    for url in commoncrawl_urls(http, domain, limit=min(commoncrawl_limit, total_limit)):
                        emit(url, "Common Crawl archive")
                        if len(emitted) >= total_limit:
                            break
                except Exception:
                    result.note(f"Common Crawl lookup failed for {domain}.")

        robots_enabled = bool(settings.get("robots", True))
        sitemap_enabled = bool(settings.get("sitemap", True))
        sitemap_limit = _bounded_int(settings.get("max_sitemaps_per_host"), 5, 1, 10)
        for host, root in roots:
            if len(emitted) >= total_limit:
                break
            blocked_prefixes: list[str] = []
            sitemap_urls: list[str] = []

            def is_blocked(
                candidate_url: str,
                blocked_prefixes: list[str] = blocked_prefixes,
            ) -> bool:
                candidate_path = urlsplit(candidate_url).path or "/"
                return any(candidate_path.startswith(prefix) for prefix in blocked_prefixes)

            if robots_enabled:
                robots_url = urljoin(root, "/robots.txt")
                response = http.get(robots_url, max_bytes=128 * 1024)
                if response is not None:
                    robots_final = normalize_url(str(getattr(response, "url", robots_url))) or robots_url
                    emit(robots_final, "robots.txt", getattr(response, "status_code", None), (getattr(response, "headers", {}) or {}).get("content-type"))
                    for line in (getattr(response, "text", "") or "").splitlines():
                        key, sep, value = line.partition(":")
                        if not sep:
                            continue
                        directive = key.strip().lower()
                        item = value.strip()
                        if directive == "disallow" and item.startswith("/"):
                            blocked_prefixes.append(item)
                            candidate = normalize_url(item, root)
                            if candidate:
                                emit(candidate, "robots.txt disallow path")
                        elif directive == "sitemap" and item:
                            candidate = normalize_url(item, root)
                            if candidate and scope.allows(host_of(candidate)) and not is_blocked(candidate):
                                sitemap_urls.append(candidate)

            if sitemap_enabled:
                sitemap_urls.insert(0, urljoin(root, "/sitemap.xml"))
                for sitemap_url in dedupe(sitemap_urls)[:sitemap_limit]:
                    if not scope.allows(host_of(sitemap_url)) or is_blocked(sitemap_url):
                        continue
                    response = http.get(sitemap_url, max_bytes=request_bytes)
                    if response is None:
                        continue
                    final_sitemap = normalize_url(str(getattr(response, "url", sitemap_url))) or sitemap_url
                    emit(final_sitemap, "sitemap", getattr(response, "status_code", None), (getattr(response, "headers", {}) or {}).get("content-type"))
                    sitemap_text = getattr(response, "text", "") or ""
                    for location in _sitemap_locations(sitemap_text, final_sitemap, scope, per_host_limit):
                        if not is_blocked(location):
                            emit(location, "sitemap URL")
                            sitemap_urls.append(location)

            queue: deque[tuple[str, int]] = deque([(root, 0)])
            for candidate in sitemap_urls:
                clean = _clean_url(candidate)
                if clean and clean != _clean_url(root) and scope.allows(host_of(clean)) and not is_blocked(clean):
                    queue.append((clean, 1))
            visited: set[str] = set()
            while queue and len(emitted) < total_limit and per_host_counts.get((host, "crawl"), 0) < per_host_limit:
                current, depth = queue.popleft()
                clean_current = _clean_url(current)
                if not clean_current or clean_current in visited:
                    continue
                current_host = host_of(clean_current)
                if not scope.allows(current_host):
                    continue
                current_path = urlsplit(clean_current).path or "/"
                if any(current_path.startswith(prefix) for prefix in blocked_prefixes):
                    continue
                if is_asset_url(clean_current) or is_js_url(clean_current):
                    emit(clean_current, "crawled asset reference")
                    continue
                visited.add(clean_current)
                response = http.get(clean_current, max_bytes=request_bytes)
                if response is None:
                    continue
                final_url = normalize_url(str(getattr(response, "url", clean_current))) or clean_current
                final_host = host_of(final_url)
                if not scope.allows(final_host):
                    continue
                headers = getattr(response, "headers", {}) or {}
                content_type = str(headers.get("content-type", ""))
                clean_final = emit(final_url, f"builtin crawl depth {depth}", getattr(response, "status_code", None), content_type)
                if not clean_final:
                    continue
                if depth >= depth_limit or (content_type and "html" not in content_type.lower()):
                    continue
                body = getattr(response, "text", "") or ""
                for link in extract_links(body, final_url):
                    normalized = normalize_url(link, final_url)
                    if not normalized or not scope.allows(host_of(normalized)):
                        continue
                    if is_blocked(normalized):
                        continue
                    clean_link = emit(normalized, f"link from {clean_final}")
                    if clean_link and clean_link not in visited and not is_asset_url(clean_link) and not is_js_url(clean_link):
                        queue.append((clean_link, depth + 1))

        return result
