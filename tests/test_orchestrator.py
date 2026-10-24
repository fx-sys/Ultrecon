from __future__ import annotations

from core.orchestrator import _run_id_for_output, filter_scope, resolve_selection
from core.registry import SelectionError
from core.scope import parse_scope_lines


def test_default_selection_is_passive_quick_pass() -> None:
    selection = resolve_selection()
    assert selection.phases == [1, 2, 5, 7]
    assert not selection.active


def test_all_without_active_skips_active_only_phases() -> None:
    selection = resolve_selection(run_all=True)
    assert {4, 8, 17}.isdisjoint(selection.phases)
    assert {1, 2, 3, 5, 6, 7, 9, 10, 11, 12, 13, 14, 15, 16} == set(
        selection.phases
    )
    assert {item["phase"] for item in selection.skipped} >= {"p04", "p08", "p17"}


def test_active_selection_includes_active_only_phases() -> None:
    selection = resolve_selection(run_all=True, active_requested=True)
    assert {4, 8, 17}.issubset(selection.phases)
    assert selection.active


def test_passive_only_overrides_active_request() -> None:
    selection = resolve_selection(
        run_all=True,
        passive_only=True,
        active_requested=True,
    )
    assert not selection.active
    assert {4, 8, 17}.isdisjoint(selection.phases)
    assert any(item["phase"] == "all" for item in selection.skipped)


def test_modules_accept_phase_numbers_names_and_deduplicate() -> None:
    selection = resolve_selection(modules_arg="p02,7,p07,p11_rest_api_recon")
    assert selection.phases == [2, 7, 11]
    assert selection.mode == "modules"


def test_unknown_module_is_rejected() -> None:
    try:
        resolve_selection(modules_arg="p99")
    except SelectionError as exc:
        assert "unknown phase" in str(exc)
    else:
        raise AssertionError("unknown phase unexpectedly accepted")


def test_filter_scope_drops_hostless_and_out_of_scope_rows() -> None:
    scope = parse_scope_lines("example.com")
    rows = [
        {"host": "www.example.com"},
        {"host": "outside.invalid"},
        {"url": "https://api.example.com/v1"},
        {"source_tool": "fixture"},
    ]
    kept, dropped = filter_scope("endpoints", rows, scope)
    assert dropped == 2
    assert [row["host"] for row in kept] == ["www.example.com", "api.example.com"]


def test_filter_scope_applies_label_local_glob_to_rows() -> None:
    scope = parse_scope_lines("*example*.api*.com")
    rows = [
        {"host": "foexamplebar.apiv1.com"},
        {"host": "foexamplebar.apiv1.com.evil"},
    ]

    kept, dropped = filter_scope("endpoints", rows, scope)

    assert [row["host"] for row in kept] == ["foexamplebar.apiv1.com"]
    assert dropped == 1


def test_filter_scope_rejects_url_host_mismatch_even_if_host_matches_glob() -> None:
    scope = parse_scope_lines("*example*.api*.com")
    row = {
        "host": "foexamplebar.apiv1.com",
        "url": "https://outside.invalid/admin",
    }

    kept, dropped = filter_scope("endpoints", [row], scope)

    assert kept == []
    assert dropped == 1


def test_filter_scope_can_keep_unproven_rows_only_if_explicitly_disabled() -> None:
    scope = parse_scope_lines("example.com")
    kept, dropped = filter_scope("cloud_assets", [{"provider": "aws", "asset": "x"}], scope, enforce=False)
    assert dropped == 0
    assert len(kept) == 1


def test_custom_output_paths_with_same_basename_get_distinct_run_ids(tmp_path) -> None:
    first = tmp_path / "one" / "same-name"
    second = tmp_path / "two" / "same-name"

    first_id = _run_id_for_output(first)
    second_id = _run_id_for_output(second)

    assert first_id != second_id
    assert first_id == _run_id_for_output(first)
