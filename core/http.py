"""Global rate-limited HTTP client and HTML/URL parsing helpers."""

from __future__ import annotations

import ipaddress
import re
import socket
import threading
import time
from html.parser import HTMLParser
from typing import Any
from urllib.parse import parse_qsl, urljoin, urlsplit, urlunsplit

import requests
from requests.adapters import HTTPAdapter
from urllib3.util import connection as urllib3_connection
from urllib3.util.retry import Retry

from core.logging_utils import get_logger
from core.util import host_of, truncate

log = get_logger(__name__)

_ASSET_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico", ".bmp", ".tiff",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".mp3", ".mp4", ".webm", ".ogg", ".wav", ".avi", ".mov",
    ".css", ".map", ".pdf", ".zip", ".gz", ".tar", ".rar", ".7z",
}
_JS_EXTENSIONS = {".js", ".mjs", ".jsx", ".ts", ".tsx"}

_URL_RE = re.compile(
    r"""(?:"|'|`|\()((?:https?:)?//[^\s"'`<>\\)]+|/[A-Za-z0-9._~!$&*+;=:@%/-]{2,})""",
    re.IGNORECASE,
)
_ABS_URL_RE = re.compile(r"https?://[^\s\"'`<>\\)]+", re.IGNORECASE)


class RateLimiter:
    """Thread-safe token-free pacing: min interval between request starts."""

    def __init__(self, rate_per_second: float) -> None:
        self.rate = max(float(rate_per_second), 0.01)
        self._interval = 1.0 / self.rate
        self._next = 0.0
        self._lock = threading.Lock()

    def wait(self) -> None:
        with self._lock:
            now = time.monotonic()
            if now < self._next:
                delay = self._next - now
                time.sleep(delay)
                now = time.monotonic()
            self._next = now + self._interval


class _LinkParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[str] = []
        self.title = ""
        self._in_title = False
        self.generator = ""

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {k.lower(): (v or "") for k, v in attrs}
        if tag in {"a", "link", "script", "img", "iframe", "form", "source"}:
            for key in ("href", "src", "action"):
                if values.get(key):
                    self.links.append(values[key].strip())
        if tag == "title":
            self._in_title = True
        if tag == "meta" and values.get("name", "").lower() == "generator":
            self.generator = values.get("content", "")

    def handle_endtag(self, tag: str) -> None:
        if tag == "title":
            self._in_title = False

    def handle_data(self, data: str) -> None:
        if self._in_title:
            self.title += data


def normalize_url(url: str, base: str | None = None) -> str | None:
    """Normalize an HTTP(S) URL, dropping fragments and default ports."""
    url = (url or "").strip()
    if not url or url.startswith(("javascript:", "mailto:", "tel:", "data:", "#")):
        return None
    if url.startswith("//"):
        url = "https:" + url
    if base:
        url = urljoin(base, url)
    try:
        parts = urlsplit(url)
    except ValueError:
        return None
    scheme = parts.scheme.lower()
    if scheme not in {"http", "https"}:
        return None
    host = (parts.hostname or "").lower().rstrip(".")
    if not host:
        return None
    port = parts.port
    netloc = f"[{host}]" if ":" in host else host
    if port and not ((scheme == "https" and port == 443) or (scheme == "http" and port == 80)):
        netloc = f"{netloc}:{port}"
    path = parts.path or "/"
    return urlunsplit((scheme, netloc, path, parts.query, ""))


def url_host(url: str) -> str:
    return host_of(url)


def is_asset_url(url: str) -> bool:
    path = (urlsplit(url).path or "").lower()
    return any(path.endswith(ext) for ext in _ASSET_EXTENSIONS)


def is_js_url(url: str) -> bool:
    path = (urlsplit(url).path or "").lower()
    return any(path.endswith(ext) for ext in _JS_EXTENSIONS) or "javascript" in path


def extract_links(html: str, base: str) -> list[str]:
    parser = _LinkParser()
    try:
        parser.feed(html or "")
    except Exception:  # malformed HTML must never kill a phase
        pass
    out: list[str] = []
    for link in parser.links:
        normalized = normalize_url(link, base)
        if normalized and normalized not in out:
            out.append(normalized)
    return out


def parse_html(html: str) -> _LinkParser:
    parser = _LinkParser()
    try:
        parser.feed(html or "")
        parser.close()
    except Exception:
        pass
    return parser


def extract_title(html: str, limit: int = 300) -> str:
    title = re.sub(r"\s+", " ", parse_html(html).title).strip()
    return title[:limit]


def extract_js_urls(html: str, base: str) -> list[str]:
    found = [u for u in extract_links(html, base) if is_js_url(u)]
    for match in _URL_RE.finditer(html or ""):
        candidate = normalize_url(match.group(1), base)
        if candidate and is_js_url(candidate) and candidate not in found:
            found.append(candidate)
    return found


def extract_urls(text: str, base: str | None = None, *, limit: int = 2000) -> list[str]:
    """Extract absolute and root-relative HTTP(S) URLs from JS/HTML/text."""
    out: list[str] = []
    seen: set[str] = set()

    def add(candidate: str) -> None:
        if len(out) >= limit:
            return
        normalized = normalize_url(candidate, base)
        if normalized and normalized not in seen:
            seen.add(normalized)
            out.append(normalized)

    for match in _ABS_URL_RE.finditer(text or ""):
        add(match.group(0).rstrip(".,;:!?)]}\"'"))
    if base:
        for match in _URL_RE.finditer(text or ""):
            add(match.group(1).rstrip(".,;:!?)]}\"'"))
            if len(out) >= limit:
                break
    return out


def extract_parameters(url: str) -> list[tuple[str, str]]:
    try:
        return parse_qsl(urlsplit(url).query, keep_blank_values=True)
    except ValueError:
        return []


_TECH_SIGNATURES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("WordPress", ("wp-content", "wp-includes", "wp-json", "wordpress")),
    ("Drupal", ("drupal", "sites/default/files", "x-generator: drupal")),
    ("Joomla", ("joomla", "/components/com_", "content=\"joomla")),
    ("Magento", ("magento", "mage/cookies")),
    ("Shopify", ("shopify", "cdn.shopify.com")),
    ("Django", ("csrfmiddlewaretoken", "django")),
    ("Laravel", ("laravel_session", "laravel")),
    ("Ruby on Rails", ("csrf-token", "rails")),
    ("Spring", ("whitelabel error page", "spring")),
    ("ASP.NET", ("asp.net", "__viewstate", "x-aspnet-version")),
    ("Next.js", ("__next_data__", "_next/static")),
    ("Nuxt", ("__nuxt__", "_nuxt/")),
    ("React", ("react", "data-reactroot")),
    ("Angular", ("ng-version", "angular")),
    ("Vue.js", ("vue.js", "vue.min.js", "__vue__")),
    ("jQuery", ("jquery",)),
    ("Bootstrap", ("bootstrap",)),
    ("Cloudflare", ("cloudflare", "cf-ray")),
    ("Nginx", ("nginx",)),
    ("Apache", ("apache",)),
    ("IIS", ("microsoft-iis",)),
    ("Tomcat", ("tomcat", "coyote")),
    ("GraphQL", ("graphql",)),
)


def detect_tech(headers: dict[str, str] | None, body: str) -> list[str]:
    header_blob = " ".join(
        f"{k.lower()}: {v}".lower() for k, v in (headers or {}).items() if k and v
    )
    blob = header_blob + " " + (body or "")[:200_000].lower()
    tech: list[str] = []
    for name, signatures in _TECH_SIGNATURES:
        if any(sig in blob for sig in signatures):
            tech.append(name)
    generator = parse_html(body or "").generator
    if generator:
        tech.append(f"generator:{truncate(generator, 120)}")
    return sorted(set(tech))


def server_from_headers(headers: dict[str, str]) -> str | None:
    for key in ("server", "x-powered-by", "via"):
        value = headers.get(key) or headers.get(key.title())
        if value:
            return truncate(value, 200)
    return None


class _PinnedHTTPAdapter(HTTPAdapter):
    """Keep the validated DNS address fixed for each new socket connection."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.pinned_address: str | None = None
        self._connection_classes: dict[tuple[type[Any], str], type[Any]] = {}

    def _pin_pool(self, pool: Any) -> Any:
        address = self.pinned_address
        base_connection = getattr(pool, "ConnectionCls", None)
        if not address or base_connection is None:
            return pool
        key = (base_connection, address)
        connection_class = self._connection_classes.get(key)
        if connection_class is None:
            if len(self._connection_classes) >= 256:
                self._connection_classes.clear()

            class PinnedConnection(base_connection):
                def _new_conn(self):
                    return urllib3_connection.create_connection(
                        (address, self.port),
                        self.timeout,
                        source_address=self.source_address,
                        socket_options=self.socket_options,
                    )

            connection_class = PinnedConnection
            self._connection_classes[key] = connection_class
        pool.ConnectionCls = connection_class
        return pool

    def get_connection_with_tls_context(
        self,
        request: requests.PreparedRequest,
        verify: Any,
        proxies: dict[str, str] | None = None,
        cert: Any = None,
    ) -> Any:
        pool = super().get_connection_with_tls_context(
            request, verify, proxies=proxies, cert=cert
        )
        return self._pin_pool(pool)

    def get_connection(self, url: str, proxies: dict[str, str] | None = None) -> Any:
        pool = super().get_connection(url, proxies)
        return self._pin_pool(pool)


class ReconHTTP:
    """Rate-limited HTTP client with in-scope redirect enforcement."""

    def __init__(self, config: dict[str, Any], scope: Any = None) -> None:
        self.config = config
        run = config.get("run") or {}
        http_cfg = config.get("http") or {}
        self.scope = scope or config.get("_scope")
        self.rate_limiter = RateLimiter(float(run.get("rate_limit", 50)))
        self.connect_timeout = float(run.get("connect_timeout", 10))
        self.read_timeout = float(run.get("timeout", 20))
        self.max_bytes = int(http_cfg.get("max_bytes", 2 * 1024 * 1024))
        self.max_redirects = int(run.get("max_redirects", 5))
        self.verify_tls = bool(http_cfg.get("verify_tls", False))
        self.user_agent = str(run.get("user_agent") or "Ultrecon/0.1.0")
        self._local = threading.local()
        if not self.verify_tls:
            requests.packages.urllib3.disable_warnings()  # type: ignore[attr-defined]

    def _session(self) -> requests.Session:
        session = getattr(self._local, "session", None)
        if session is None:
            session = requests.Session()
            session.headers.update(
                {
                    "User-Agent": self.user_agent,
                    "Accept": "text/html,application/json,application/xml;q=0.9,*/*;q=0.8",
                    "Accept-Language": "en-US,en;q=0.8",
                }
            )
            retry = Retry(
                total=int((self.config.get("run") or {}).get("retries", 2)),
                backoff_factor=0.4,
                status_forcelist=(429, 500, 502, 503, 504),
                allowed_methods=frozenset({"GET", "HEAD", "OPTIONS"}),
                raise_on_status=False,
            )
            adapter = _PinnedHTTPAdapter(max_retries=retry, pool_connections=20, pool_maxsize=20)
            session.mount("http://", adapter)
            session.mount("https://", adapter)
            # Environment proxies resolve destinations outside our pinned socket path.
            session.trust_env = False
            self._local.session = session
        return session

    def _allowed(self, url: str) -> bool:
        if not self.scope:
            return True
        try:
            return bool(self.scope.allows(url_host(url)))
        except Exception:
            return False

    def _destination_addresses(self, url: str) -> list[str]:
        """Resolve once and return addresses safe to pin for the HTTP request."""
        try:
            parts = urlsplit(url)
            host = parts.hostname or ""
            port = parts.port or (443 if parts.scheme.lower() == "https" else 80)
        except ValueError:
            return []
        if not host:
            return []
        try:
            addresses = [ipaddress.ip_address(host)]
        except ValueError:
            try:
                resolved = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
            except OSError as exc:
                log.debug("Could not resolve HTTP destination %s: %s", host, exc)
                return []
            addresses = []
            for item in resolved:
                try:
                    addresses.append(ipaddress.ip_address(item[4][0].split("%", 1)[0]))
                except (IndexError, ValueError):
                    continue
        unique = list(dict.fromkeys(address.compressed for address in addresses))
        if not unique:
            return []
        if not bool((self.config.get("http") or {}).get("allow_private_ips", False)):
            if any(not ipaddress.ip_address(address).is_global for address in unique):
                return []
        return unique

    def _safe_destination(self, url: str) -> bool:
        """Reject private/reserved destinations unless explicitly allowed."""
        return bool(self._destination_addresses(url))

    def request(
        self,
        method: str,
        url: str,
        *,
        scope_check: bool = True,
        allow_redirects: bool = True,
        timeout: float | None = None,
        max_bytes: int | None = None,
        headers: dict[str, str] | None = None,
        data: bytes | str | None = None,
        json: Any = None,
    ) -> requests.Response | None:
        method = method.upper()
        current = normalize_url(url)
        if not current:
            return None
        if scope_check and not self._allowed(current):
            log.debug("Refusing out-of-scope request: %s", current)
            return None
        redirects = 0
        while True:
            self.rate_limiter.wait()
            addresses = self._destination_addresses(current)
            if not addresses:
                log.debug("Refusing private or non-global HTTP destination: %s", current)
                return None
            session = self._session()
            adapter = session.get_adapter(current)
            if isinstance(adapter, _PinnedHTTPAdapter):
                adapter.pinned_address = addresses[0]
            try:
                response = session.request(
                    method,
                    current,
                    timeout=(self.connect_timeout, timeout or self.read_timeout),
                    verify=self.verify_tls,
                    allow_redirects=False,
                    stream=True,
                    headers=headers,
                    data=data,
                    json=json,
                )
            except requests.RequestException as exc:
                log.debug("HTTP %s %s failed: %s", method, current, exc)
                return None
            location = response.headers.get("location")
            if (
                allow_redirects
                and response.is_redirect
                and location
                and redirects < self.max_redirects
            ):
                target = normalize_url(location, current)
                response.close()
                if not target:
                    return None
                if scope_check and not self._allowed(target):
                    log.debug("Stopping redirect outside scope: %s", target)
                    return None
                current = target
                redirects += 1
                continue
            try:
                limit = max_bytes or self.max_bytes
                chunks: list[bytes] = []
                size = 0
                if method != "HEAD":
                    for chunk in response.iter_content(chunk_size=8192):
                        if not chunk:
                            continue
                        remaining = limit - size
                        if remaining <= 0:
                            break
                        chunks.append(chunk[:remaining])
                        size += len(chunk[:remaining])
                        if size >= limit:
                            break
                response._content = b"".join(chunks)  # type: ignore[attr-defined]
                if response.encoding is None:
                    response.encoding = response.apparent_encoding or "utf-8"
                response.url = current
                return response
            except (requests.RequestException, OSError) as exc:
                log.debug("HTTP body read failed for %s: %s", current, exc)
                return None
            finally:
                response.close()

    def get(self, url: str, **kwargs: Any) -> requests.Response | None:
        return self.request("GET", url, **kwargs)

    def head(self, url: str, **kwargs: Any) -> requests.Response | None:
        kwargs.setdefault("allow_redirects", True)
        return self.request("HEAD", url, **kwargs)

    def get_text(self, url: str, **kwargs: Any) -> str | None:
        response = self.get(url, **kwargs)
        if response is None:
            return None
        try:
            return response.text
        except Exception:
            return None

    def get_json(self, url: str, **kwargs: Any) -> Any:
        import json

        text = self.get_text(url, **kwargs)
        if not text:
            return None
        try:
            return json.loads(text)
        except (json.JSONDecodeError, ValueError):
            return None


_HTTP_CLIENT_KEY = "_http_client"


def get_http(config: dict[str, Any]) -> ReconHTTP:
    client = config.get(_HTTP_CLIENT_KEY)
    if not isinstance(client, ReconHTTP):
        client = ReconHTTP(config, scope=config.get("_scope"))
        config[_HTTP_CLIENT_KEY] = client
    return client
