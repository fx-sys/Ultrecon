from __future__ import annotations

import sqlite3
from types import SimpleNamespace

from core import http as http_core
from core.datastore import DataStore
from core.scope import parse_scope_lines
from core.toolrunner import ToolRun
from modules import common
from modules.p04_ports_services import module as ports_module
from modules.p12_graphql_recon import module as graphql_module
from modules.p14_cloud_assets import module as cloud_module
from modules.p17_vuln_verification import module as vuln_module


def test_resolve_host_addresses_rejects_mixed_public_and_private_dns(monkeypatch) -> None:
    def getaddrinfo(host, port, type):
        return [
            (2, 1, 6, "", ("8.8.8.8", port)),
            (2, 1, 6, "", ("10.0.0.4", port)),
        ]

    monkeypatch.setattr(common.socket, "getaddrinfo", getaddrinfo)

    assert common.resolve_host_addresses("fixture.example", {}) == []
    assert common.resolve_host_addresses(
        "fixture.example", {"http": {"allow_private_ips": True}}
    ) == ["8.8.8.8", "10.0.0.4"]


def test_http_adapter_connects_to_the_resolved_ip(monkeypatch) -> None:
    adapter = http_core._PinnedHTTPAdapter()
    adapter.pinned_address = "93.184.216.34"
    pool = adapter.get_connection("https://fixture.example/")
    connected_to: list[tuple[str, int]] = []
    sentinel = object()

    def create_connection(address, timeout, source_address=None, socket_options=None):
        connected_to.append(address)
        return sentinel

    monkeypatch.setattr(http_core.urllib3_connection, "create_connection", create_connection)
    connection = pool.ConnectionCls(host=pool.host, port=pool.port)

    assert connection._new_conn() is sentinel
    assert connected_to == [("93.184.216.34", 443)]
    assert pool.host == "fixture.example"
    adapter.close()


def test_nmap_scans_resolved_ip_instead_of_hostname(monkeypatch) -> None:
    commands: list[list[str]] = []
    monkeypatch.setattr(ports_module, "phase_settings", lambda *_: {})
    monkeypatch.setattr(ports_module, "scoped_hosts", lambda *args, **kwargs: ["example.com"])
    monkeypatch.setattr(
        ports_module, "resolve_host_addresses", lambda *_args, **_kwargs: ["8.8.8.8"]
    )

    scanner = ports_module.Module()
    monkeypatch.setattr(scanner, "binary_available", lambda *_: True)

    def exec_tool(name, args, config, **kwargs):
        commands.append(args)
        return ToolRun(name, args, stdout="<nmaprun></nmaprun>")

    monkeypatch.setattr(scanner, "exec_tool", exec_tool)
    scanner.run(
        parse_scope_lines("example.com"),
        {"_run": {"active": True, "authorized": True}},
    )

    assert len(commands) == 1
    assert commands[0][-1] == "8.8.8.8"
    assert "example.com" not in commands[0]


def test_graphql_discovery_skips_query_bearing_prior_endpoints(monkeypatch) -> None:
    requests: list[str] = []

    class FakeHTTP:
        def get(self, url, **kwargs):
            requests.append(url)
            return SimpleNamespace(
                headers={"content-type": "text/html"},
                text="not graphql",
                status_code=404,
            )

    monkeypatch.setattr(
        graphql_module,
        "phase_settings",
        lambda *_: {"common_paths": ["/graphql"], "max_hosts": 1},
    )
    monkeypatch.setattr(
        graphql_module, "scoped_hosts", lambda *args, **kwargs: ["example.com"]
    )
    rows = {
        "http_hosts": [{"url": "https://example.com/"}],
        "endpoints": [
            {"url": "https://example.com/graphql?query=mutation%20{deleteAll}"}
        ],
    }
    monkeypatch.setattr(
        graphql_module, "previous_rows", lambda _config, table: rows.get(table, [])
    )
    monkeypatch.setattr(graphql_module, "http_client", lambda _config: FakeHTTP())

    graphql_module.Module().run(
        parse_scope_lines("example.com"),
        {"_run": {"active": False, "authorized": False}},
    )

    assert requests == ["https://example.com/graphql"]


def test_graphql_candidate_paths_reject_query_and_fragment() -> None:
    assert graphql_module._safe_path("/graphql?query={__schema}") is None
    assert graphql_module._safe_path("/graphql#fragment") is None
    assert graphql_module._safe_path("/graphql") == "/graphql"


def test_nuclei_template_rejects_destructive_and_query_paths() -> None:
    base = {
        "id": "safe-check",
        "info": {"name": "safe check", "severity": "low", "tags": ["misconfig"]},
        "http": [
            {
                "method": "GET",
                "path": ["{{BaseURL}}/robots.txt"],
                "matchers": [{"type": "status", "status": [200]}],
            }
        ],
    }
    assert vuln_module._template_is_safe(base, {"safe-check"})

    for path in (
        "{{BaseURL}}/api/delete-all",
        "{{BaseURL}}/graphql?query={__schema}",
    ):
        document = {**base, "http": [{**base["http"][0], "path": [path]}]}
        assert not vuln_module._template_is_safe(document, {"safe-check"})


def test_nuclei_pins_addresses_and_maps_findings_to_scoped_hostname() -> None:
    scope = parse_scope_lines("example.com")
    pinned = vuln_module._pinned_target(
        "https://example.com:8443/", "2001:4860:4860::8888"
    )

    assert pinned == "https://[2001:4860:4860::8888]:8443/"
    assert vuln_module._safe_report_url(
        "https://[2001:4860:4860::8888]:8443/status",
        scope,
        "https://example.com:8443/",
        expected_host="example.com",
        pinned_address="2001:4860:4860::8888",
    ) == "https://example.com:8443/status"
    assert vuln_module._safe_report_url(
        "https://other.example/status",
        scope,
        "https://example.com/",
        expected_host="example.com",
        pinned_address="8.8.8.8",
    ) is None


def test_cloud_asset_host_is_normalized_and_migrated(tmp_path, monkeypatch) -> None:
    database = tmp_path / "prior-run.sqlite3"
    connection = sqlite3.connect(database)
    connection.execute(
        """CREATE TABLE cloud_assets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id TEXT NOT NULL,
            discovered_at TEXT NOT NULL,
            source_tool TEXT NOT NULL DEFAULT 'unknown',
            extra TEXT,
            provider TEXT NOT NULL,
            asset TEXT NOT NULL,
            url TEXT,
            evidence TEXT,
            account TEXT,
            region TEXT
        )"""
    )
    connection.commit()
    connection.close()

    monkeypatch.setattr(
        cloud_module,
        "phase_settings",
        lambda *_: {
            "enabled": True,
            "own_account_context": {"aws": "123456789012"},
            "owned_assets": [
                {
                    "provider": "aws",
                    "account_id": "123456789012",
                    "asset": "example bucket",
                    "url": "https://example.com/",
                }
            ],
        },
    )
    rows = cloud_module.Module().run(
        parse_scope_lines("example.com"), {}
    ).rows["cloud_assets"]

    store = DataStore(database)
    assert store.insert_rows("cloud_assets", rows, "run-1") == 1
    stored = store.rows("cloud_assets", "run-1")[0]
    assert stored["host"] == "example.com"
    assert not stored["extra"]
    store.close()
