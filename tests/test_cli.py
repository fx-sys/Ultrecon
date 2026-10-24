from __future__ import annotations

import json

import pytest

from core.cli import build_parser, main
from core.scope import parse_scope_lines


def test_list_aliases_parse() -> None:
    for alias in ("-list", "--list", "-l"):
        args = build_parser().parse_args([alias, "targets.txt"])
        assert args.list_path == "targets.txt"


def test_check_deps_uses_only_module_required_binaries(monkeypatch, capsys) -> None:
    calls = {}

    class FakeInstaller:
        def ensure(self, names, *, install=None):
            calls["ensure"] = (names, install)
            return []

    monkeypatch.setattr(
        "core.cli.collect_required_binaries",
        lambda phases, *, active=False: ["nmap", "dnsx"] if active else ["nmap"],
    )
    monkeypatch.setattr(
        "core.cli.installer_from_config",
        lambda config, install=None: FakeInstaller(),
    )
    monkeypatch.setattr("core.cli.Installer.format_table", lambda statuses: "")

    assert main(["--all", "--active", "--authorize", "--check-deps", "--no-install"]) == 0
    assert calls["ensure"] == (["nmap", "dnsx"], False)
    capsys.readouterr()


def test_active_without_authorize_is_rejected_before_config_or_tools(tmp_path, capsys) -> None:
    target_file = tmp_path / "targets.txt"
    target_file.write_text("example.com\n", encoding="utf-8")
    with pytest.raises(SystemExit) as exc:
        main(["-list", str(target_file), "--active"])
    assert exc.value.code == 2
    assert "--active requires --authorize" in capsys.readouterr().err


def test_all_phase_modules_load_and_dry_run_is_read_only(tmp_path, capsys) -> None:
    target_file = tmp_path / "targets.txt"
    target_file.write_text("example.com\n", encoding="utf-8")
    output_dir = tmp_path / "dry-run-output"
    rc = main(["-list", str(target_file), "--all", "--dry-run", "--output", str(output_dir)])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert len(payload["phases"]) == 14
    assert all(phase["available"] for phase in payload["phases"])
    assert payload["module_load_errors"] == []
    assert not output_dir.exists()


def test_dry_run_accepts_active_plan_without_confirmation(tmp_path, capsys) -> None:
    target_file = tmp_path / "targets.txt"
    target_file.write_text("example.com\n", encoding="utf-8")
    output_dir = tmp_path / "active-dry-run"
    rc = main(
        [
            "-list",
            str(target_file),
            "--modules",
            "p04",
            "--active",
            "--authorize",
            "--dry-run",
            "--output",
            str(output_dir),
        ]
    )
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["active"] is True
    assert payload["authorized"] is False
    assert not output_dir.exists()


def test_active_p02_dry_run_includes_dnsx_dependency(tmp_path, capsys) -> None:
    target_file = tmp_path / "targets.txt"
    target_file.write_text("example.com\n", encoding="utf-8")
    output_dir = tmp_path / "active-p02-dry-run"

    assert main(
        [
            "-list",
            str(target_file),
            "--modules",
            "p02",
            "--active",
            "--authorize",
            "--dry-run",
            "--output",
            str(output_dir),
        ]
    ) == 0

    payload = json.loads(capsys.readouterr().out)
    phase = next(item for item in payload["phases"] if item["id"] == "p02")
    assert phase["active_requires"] == ["dnsx"]
    assert {tool["binary"] for tool in payload["tools"]} >= {
        "subfinder",
        "amass",
        "assetfinder",
        "dnsx",
    }
    assert not output_dir.exists()


def test_resume_dry_run_reuses_manifest_scope_without_mutation(tmp_path, capsys) -> None:
    run_dir = tmp_path / "prior-run"
    run_dir.mkdir()
    manifest_path = run_dir / "run_manifest.json"
    manifest_text = json.dumps({"resolved_scope": parse_scope_lines("example.com").to_dict()})
    manifest_path.write_text(manifest_text, encoding="utf-8")

    rc = main(["--resume", str(run_dir), "--modules", "p01", "--dry-run"])

    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["targets"] == ["example.com"]
    assert payload["output_dir"] == str(run_dir.resolve())
    assert manifest_path.read_text(encoding="utf-8") == manifest_text
    assert not (run_dir / "ultrecon.db").exists()


def test_resume_matches_normalized_glob_pattern(tmp_path, capsys) -> None:
    run_dir = tmp_path / "prior-glob-run"
    run_dir.mkdir()
    manifest_path = run_dir / "run_manifest.json"
    manifest_path.write_text(
        json.dumps({"resolved_scope": parse_scope_lines("*Example*.API*.COM").to_dict()}),
        encoding="utf-8",
    )
    target_file = tmp_path / "targets.txt"
    target_file.write_text("*example*.api*.com\n", encoding="utf-8")

    assert main(
        ["--resume", str(run_dir), "--list", str(target_file), "--modules", "p01", "--dry-run"]
    ) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["targets"] == ["*example*.api*.com"]
    assert not (run_dir / "ultrecon.db").exists()


def test_resume_rejects_different_glob_boundary(tmp_path, capsys) -> None:
    run_dir = tmp_path / "prior-glob-run"
    run_dir.mkdir()
    (run_dir / "run_manifest.json").write_text(
        json.dumps({"resolved_scope": parse_scope_lines("*example*.api*.com").to_dict()}),
        encoding="utf-8",
    )
    target_file = tmp_path / "targets.txt"
    target_file.write_text("*other*.api*.com\n", encoding="utf-8")

    assert main(
        ["--resume", str(run_dir), "--list", str(target_file), "--modules", "p01", "--dry-run"]
    ) == 2
    assert "resume scope does not match" in capsys.readouterr().err
