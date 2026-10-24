from __future__ import annotations

from core.cli import main
from core.config import ConfigError, load_config


def test_non_mapping_nested_config_is_reported_as_config_error(tmp_path) -> None:
    config_path = tmp_path / "invalid.yaml"
    config_path.write_text("scope:\n  - broken\n", encoding="utf-8")

    try:
        load_config(config_path)
    except ConfigError as exc:
        assert "scope must be a mapping" in str(exc)
    else:
        raise AssertionError("invalid nested config shape was accepted")


def test_hackertarget_free_tier_source_is_off_by_default() -> None:
    config = load_config()

    assert config["optional_sources"]["hackertarget"] is False


def test_cli_returns_configuration_error_for_invalid_nested_config(tmp_path) -> None:
    target_path = tmp_path / "targets.txt"
    target_path.write_text("example.com\n", encoding="utf-8")
    config_path = tmp_path / "invalid.yaml"
    config_path.write_text("scope:\n  - broken\n", encoding="utf-8")

    assert main(["--config", str(config_path), "--list", str(target_path)]) == 2
