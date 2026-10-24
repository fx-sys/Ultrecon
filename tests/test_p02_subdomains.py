from __future__ import annotations

from core.orchestrator import collect_required_binaries
from core.scope import parse_scope_lines
from core.toolrunner import ToolRun
from modules.p02_subdomain_enum import module as p02_module


def test_passive_subdomain_tools_run_and_filter_to_scope(monkeypatch) -> None:
    outputs = {
        "subfinder": "www.example.com\noutside.invalid\n",
        "amass": "api.example.com\n",
        "assetfinder": "example.com\n",
    }
    calls: list[tuple[str, list[str]]] = []
    monkeypatch.setattr(
        p02_module, "phase_settings", lambda *_: {"passive_sources": list(outputs)}
    )
    monkeypatch.setattr(p02_module, "previous_rows", lambda *_: [])
    module = p02_module.Module()
    monkeypatch.setattr(module, "binary_available", lambda *_: True)

    def exec_tool(name, args, _config, **kwargs):
        calls.append((name, args))
        return ToolRun(name, args, stdout=outputs[name])

    monkeypatch.setattr(module, "exec_tool", exec_tool)
    result = module.run(
        parse_scope_lines("example.com"),
        {"_run": {"active": False, "authorized": False}},
    )

    assert calls == [
        ("subfinder", ["-silent", "-d", "example.com"]),
        ("amass", ["enum", "-passive", "-d", "example.com"]),
        ("assetfinder", ["--subs-only", "example.com"]),
    ]
    assert {row["host"] for row in result.rows["subdomains"]} == {
        "www.example.com",
        "api.example.com",
        "example.com",
    }
    assert len(result.tool_runs) == 3
    assert "outside.invalid" not in {row["host"] for row in result.rows["subdomains"]}


def test_generic_glob_is_never_used_as_enumeration_seed(monkeypatch) -> None:
    calls: list[tuple[str, list[str]]] = []
    module = p02_module.Module()
    monkeypatch.setattr(module, "binary_available", lambda *_: True)
    monkeypatch.setattr(
        module,
        "exec_tool",
        lambda name, args, *_args, **_kwargs: calls.append((name, args)),
    )

    result = module.run(
        parse_scope_lines("*example*.api*.com"),
        {"_run": {"active": False, "authorized": False}},
    )

    assert calls == []
    assert result.rows.get("subdomains", []) == []
    assert "No domains or subdomain result capacity is available." in result.notes


def test_dnsx_is_invoked_only_with_active_authorization(monkeypatch) -> None:
    monkeypatch.setattr(
        p02_module,
        "phase_settings",
        lambda *_: {"passive_sources": [], "active_sources": ["dnsx"]},
    )
    monkeypatch.setattr(p02_module, "previous_rows", lambda *_: [])
    module = p02_module.Module()
    monkeypatch.setattr(module, "binary_available", lambda *_: True)
    calls: list[str] = []

    def exec_tool(name, args, _config, *, input_text=None, **kwargs):
        calls.append(name)
        return ToolRun(name, args, stdout="www.example.com\n")

    monkeypatch.setattr(module, "exec_tool", exec_tool)
    scope = parse_scope_lines("example.com")

    denied = module.run(scope, {"_run": {"active": True, "authorized": False}})
    assert calls == []
    assert "dnsx" not in {row["source_tool"] for row in denied.rows.get("subdomains", [])}

    allowed = module.run(scope, {"_run": {"active": True, "authorized": True}})
    assert calls == ["dnsx"]
    assert {row["host"] for row in allowed.rows["subdomains"]} == {"www.example.com"}


def test_active_dns_binary_is_required_only_for_active_selection() -> None:
    passive = collect_required_binaries([2])
    active = collect_required_binaries([2], active=True)

    assert {"subfinder", "amass", "assetfinder"}.issubset(passive)
    assert "dnsx" not in passive
    assert "dnsx" in active
