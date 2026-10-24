from __future__ import annotations

import csv
import json

from core.authz import passive_authorization
from core.datastore import DataStore
from core.reporting import Reporter
from core.scope import parse_scope_lines


def test_reporters_export_requested_formats_and_stable_schema(tmp_path) -> None:
    output = tmp_path / "run"
    scope = parse_scope_lines(["example.com"])
    store = DataStore(output / "ultrecon.db")
    store.start_run(
        {
            "run_id": "run-1",
            "targets": ["example.com"],
            "phases": ["p05"],
            "active": False,
            "authorized": False,
        }
    )
    store.insert_rows(
        "http_hosts",
        [
            {
                "url": "https://example.com/",
                "host": "example.com",
                "status_code": 200,
                "tech": "Fixture",
                "source_tool": "test",
            }
        ],
        "run-1",
    )
    reporter = Reporter(
        store,
        "run-1",
        output,
        scope,
        {"run": {"rate_limit": 12}},
        passive_authorization(scope),
    )

    assert set(reporter.export("json")) == {"json"}
    payload = json.loads((output / "report.json").read_text(encoding="utf-8"))
    assert payload["schema_version"] == "1.0"
    assert payload["run"]["targets"] == ["example.com"]
    assert payload["stats"]["counts"]["http_hosts"] == 1
    assert payload["tables"]["http_hosts"][0]["tech"] == "Fixture"

    assert set(reporter.export("csv")) == {"csv"}
    with (output / "report.csv").open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    assert rows[0]["table"] == "http_hosts"
    assert rows[0]["host"] == "example.com"

    assert set(reporter.export("txt")) == {"txt"}
    assert "Run ID:       run-1" in (output / "summary.txt").read_text(encoding="utf-8")
    assert set(reporter.export("all")) == {"json", "csv", "txt"}
    store.close()
