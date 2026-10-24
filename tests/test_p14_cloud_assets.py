from __future__ import annotations

from core.config import load_config
from core.scope import parse_scope_lines
from modules.p14_cloud_assets import module as cloud_module


def test_cloud_inventory_is_disabled_by_default() -> None:
    config = load_config()

    assert config["p14"]["enabled"] is False
    result = cloud_module.Module().run(parse_scope_lines("example.com"), config)

    assert result.rows.get("cloud_assets", []) == []
    assert any("disabled by default" in note for note in result.notes)


def test_cloud_inventory_requires_matching_operator_context_and_scope(monkeypatch) -> None:
    monkeypatch.setattr(
        cloud_module,
        "phase_settings",
        lambda *_: {
            "enabled": True,
            "own_account_only": True,
            "own_account_context": {"aws": "123456789012"},
            "owned_assets": [
                {
                    "provider": "aws",
                    "account_id": "999999999999",
                    "asset": "wrong-account",
                    "host": "example.com",
                },
                {
                    "provider": "aws",
                    "account_id": "123456789012",
                    "asset": "out-of-scope",
                    "host": "outside.invalid",
                },
            ],
        },
    )

    result = cloud_module.Module().run(parse_scope_lines("example.com"), {})

    assert result.rows.get("cloud_assets", []) == []
    assert any("not independently verified" in note for note in result.notes)


def test_cloud_inventory_refuses_disabled_own_account_boundary(monkeypatch) -> None:
    monkeypatch.setattr(
        cloud_module,
        "phase_settings",
        lambda *_: {
            "enabled": True,
            "own_account_only": False,
            "own_account_context": {"aws": "123456789012"},
            "owned_assets": [
                {
                    "provider": "aws",
                    "account_id": "123456789012",
                    "asset": "example bucket",
                    "host": "example.com",
                }
            ],
        },
    )

    result = cloud_module.Module().run(parse_scope_lines("example.com"), {})

    assert result.rows.get("cloud_assets", []) == []
    assert any("own_account_only" in note for note in result.notes)
