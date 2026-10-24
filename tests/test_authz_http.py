from __future__ import annotations

import io
import socket
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from core.authz import AUTHORIZATION_TEXT, AuthorizationError, confirm_active_testing
from core.http import ReconHTTP
from core.scope import parse_scope_lines


class TTYInput(io.StringIO):
    def isatty(self) -> bool:
        return True


def test_authorization_yes_prints_targets_and_records_confirmation() -> None:
    scope = parse_scope_lines(["example.com", "*.example.net"])
    output = io.StringIO()
    authorization = confirm_active_testing(
        scope,
        authorize_flag=True,
        assume_yes=True,
        stdout=output,
    )
    assert authorization.confirmed
    assert authorization.method == "flag+yes"
    assert authorization.targets == ["example.com", "*.example.net"]
    assert authorization.confirmed_at
    assert AUTHORIZATION_TEXT in output.getvalue()
    assert "example.com" in output.getvalue()
    assert "*.example.net (wildcard boundary)" in output.getvalue()


def test_authorization_displays_label_local_glob_exactly() -> None:
    scope = parse_scope_lines("*example*.api*.com")
    output = io.StringIO()

    confirm_active_testing(
        scope,
        authorize_flag=True,
        assume_yes=True,
        stdout=output,
    )

    assert "*example*.api*.com (label-local glob)" in output.getvalue()


def test_authorization_requires_flag() -> None:
    with pytest.raises(AuthorizationError, match="requires --authorize"):
        confirm_active_testing(parse_scope_lines("example.com"), authorize_flag=False)


def test_authorization_refuses_noninteractive_confirmation() -> None:
    with pytest.raises(AuthorizationError, match="without interactive confirmation"):
        confirm_active_testing(
            parse_scope_lines("example.com"),
            authorize_flag=True,
            stdin=io.StringIO(),
            stdout=io.StringIO(),
        )


def test_authorization_accepts_interactive_yes() -> None:
    result = confirm_active_testing(
        parse_scope_lines("example.com"),
        authorize_flag=True,
        input_fn=lambda _prompt: "yes",
        stdin=TTYInput(),
        stdout=io.StringIO(),
    )
    assert result.confirmed
    assert result.method == "interactive"


def test_http_scope_gate_uses_label_local_glob() -> None:
    client = ReconHTTP({}, scope=parse_scope_lines("*example*.api*.com"))

    assert client._allowed("https://foexamplebar.apiv1.com/path")
    assert not client._allowed("https://foexamplebar.api.com.evil/path")


def test_private_destination_denied_by_default_and_allowed_by_config() -> None:
    client = ReconHTTP({"http": {"allow_private_ips": False}})
    assert not client._safe_destination("http://127.0.0.1/")
    assert not client._safe_destination("http://[::1]/")
    permissive = ReconHTTP({"http": {"allow_private_ips": True}})
    assert permissive._safe_destination("http://127.0.0.1/")


def test_dns_destination_rejects_if_any_address_is_non_global(monkeypatch) -> None:
    def getaddrinfo(host, port, type):
        return [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.4", port)),
        ]

    monkeypatch.setattr("core.http.socket.getaddrinfo", getaddrinfo)
    client = ReconHTTP({"http": {"allow_private_ips": False}})
    assert not client._safe_destination("https://fixture.example/")


def test_dns_destination_accepts_only_global_addresses(monkeypatch) -> None:
    def getaddrinfo(host, port, type):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port))]

    monkeypatch.setattr("core.http.socket.getaddrinfo", getaddrinfo)
    client = ReconHTTP({"http": {"allow_private_ips": False}})
    assert client._safe_destination("https://fixture.example/")


def test_http_retries_wait_on_shared_rate_limiter(monkeypatch) -> None:
    class RetryHandler(BaseHTTPRequestHandler):
        request_count = 0

        def do_GET(self) -> None:
            type(self).request_count += 1
            self.send_response(503)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *_args) -> None:
            pass

    class CountingRateLimiter:
        def __init__(self) -> None:
            self.calls = 0

        def wait(self) -> None:
            self.calls += 1

    server = HTTPServer(("127.0.0.1", 0), RetryHandler)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    client = ReconHTTP(
        {
            "run": {"rate_limit": 1, "retries": 2, "connect_timeout": 1, "timeout": 1},
            "http": {"allow_private_ips": True},
        },
        scope=parse_scope_lines("retry.example"),
    )
    limiter = CountingRateLimiter()
    client.rate_limiter = limiter
    monkeypatch.setattr(client, "_destination_addresses", lambda _url: ["127.0.0.1"])
    try:
        response = client.get(f"http://retry.example:{server.server_port}/")
    finally:
        client._session().close()
        server.shutdown()
        server.server_close()
        server_thread.join(timeout=1)

    assert response is not None
    assert response.status_code == 503
    assert RetryHandler.request_count == 3
    assert limiter.calls == 3
