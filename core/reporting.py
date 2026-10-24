"""JSON / CSV / text reporting for a completed run."""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any

from core import __url__, __version__
from core.authz import Authorization
from core.datastore import TABLE_NAMES, DataStore
from core.scope import Scope
from core.util import json_dumps, utc_now, write_json

SCHEMA_VERSION = "1.0"
_CSV_COLUMNS = [
    "table",
    "id",
    "run_id",
    "host",
    "url",
    "ip",
    "port",
    "protocol",
    "status_code",
    "method",
    "name",
    "title",
    "server",
    "tech",
    "service",
    "version",
    "cms",
    "severity",
    "template_id",
    "secret_type",
    "provider",
    "asset",
    "source_tool",
    "discovered_at",
]


def _decode_extra(row: dict[str, Any]) -> dict[str, Any]:
    output = dict(row)
    raw = output.get("extra")
    if isinstance(raw, str):
        try:
            output["extra"] = json.loads(raw) if raw else {}
        except json.JSONDecodeError:
            output["extra"] = {"raw": raw}
    return output


class Reporter:
    def __init__(
        self,
        store: DataStore,
        run_id: str,
        output_dir: Path,
        scope: Scope,
        config: dict[str, Any],
        authorization: Authorization,
    ) -> None:
        self.store = store
        self.run_id = run_id
        self.output_dir = Path(output_dir)
        self.scope = scope
        self.config = config
        self.authorization = authorization

    @property
    def tables(self) -> dict[str, list[dict[str, Any]]]:
        return {table: self.store.rows(table, self.run_id) for table in TABLE_NAMES}

    def report_payload(self) -> dict[str, Any]:
        run = self.store.run_record(self.run_id) or {}
        tables = {
            table: [_decode_extra(row) for row in rows]
            for table, rows in self.tables.items()
        }
        counts = {table: len(rows) for table, rows in tables.items()}
        return {
            "schema_version": SCHEMA_VERSION,
            "tool": {
                "name": "Ultrecon",
                "version": __version__,
                "url": __url__,
            },
            "generated_at": utc_now(),
            "run": {
                "run_id": self.run_id,
                "started_at": run.get("started_at"),
                "finished_at": run.get("finished_at"),
                "targets": [t.raw for t in self.scope.targets],
                "phases": _loads(run.get("phases_json"), []),
                "active": bool(run.get("active")),
                "authorized": bool(run.get("authorized")),
                "rate_limit_per_second": (self.config.get("run") or {}).get("rate_limit", 50),
            },
            "scope": self.scope.to_dict(),
            "stats": {
                "counts": counts,
                "total_findings": sum(counts.values()),
                "tool_runs": len(self.store.tool_runs(self.run_id)),
            },
            "tables": tables,
            "tool_runs": [
                _decode_extra(row) for row in self.store.tool_runs(self.run_id)
            ],
        }

    # -- exporters -------------------------------------------------------
    def write_json(self) -> Path:
        path = self.output_dir / "report.json"
        write_json(path, self.report_payload())
        return path

    def write_csv(self) -> Path:
        path = self.output_dir / "report.csv"
        path.parent.mkdir(parents=True, exist_ok=True)
        rows: list[dict[str, Any]] = []
        for table in TABLE_NAMES:
            for row in self.store.rows(table, self.run_id):
                decoded = _decode_extra(row)
                flat: dict[str, Any] = {"table": table}
                for key, value in decoded.items():
                    if isinstance(value, (dict, list)):
                        flat[key] = json_dumps(value)
                    else:
                        flat[key] = value
                rows.append(flat)
        columns = list(_CSV_COLUMNS)
        for row in rows:
            for key in row:
                if key not in columns:
                    columns.append(key)
        with path.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=columns, extrasaction="ignore")
            writer.writeheader()
            for row in rows:
                writer.writerow({k: ("" if row.get(k) is None else row.get(k)) for k in columns})
        return path

    def write_summary(self) -> Path:
        payload = self.report_payload()
        counts = payload["stats"]["counts"]
        run = payload["run"]
        tool_runs = payload["tool_runs"]
        failed = [t for t in tool_runs if (t.get("returncode") or 0) != 0]
        path = self.output_dir / "summary.txt"
        lines = [
            "Ultrecon reconnaissance summary",
            "=" * 34,
            f"Run ID:       {self.run_id}",
            f"Started:      {run.get('started_at')}",
            f"Finished:     {run.get('finished_at')}",
            f"Targets:      {', '.join(payload['run']['targets'])}",
            f"Active:       {'yes' if run.get('active') else 'no'}",
            f"Authorized:   {'yes' if run.get('authorized') else 'no'}",
            f"Rate limit:   {run.get('rate_limit_per_second')} req/s",
            f"Phases:       {', '.join(str(p.get('id', p)) if isinstance(p, dict) else str(p) for p in run.get('phases', []))}",
            "",
            "Findings by table",
            "-" * 34,
        ]
        for table in TABLE_NAMES:
            lines.append(f"{table:<24} {counts.get(table, 0):>8}")
        lines.extend(
            [
                f"{'TOTAL':<24} {payload['stats']['total_findings']:>8}",
                "",
                "Tool execution",
                "-" * 34,
                f"Tools run:    {len(tool_runs)}",
                f"Failed:       {len(failed)}",
            ]
        )
        for tool in failed[:15]:
            lines.append(
                f"  ! {tool.get('tool')}: {str(tool.get('error') or 'failed')[:120]}"
            )

        highlights = self._highlights(payload["tables"])
        if highlights:
            lines.extend(["", "Highlights", "-" * 34, *highlights])

        lines.extend(
            [
                "",
                "Reports",
                "-" * 34,
                f"Database:     {self.output_dir / 'ultrecon.db'}",
                f"JSON:         {self.output_dir / 'report.json'}",
                f"CSV:          {self.output_dir / 'report.csv'}",
                f"Manifest:     {self.output_dir / 'run_manifest.json'}",
                "",
                "Recon only. Verify findings manually and respect program scope.",
                "",
            ]
        )
        path.write_text("\n".join(lines), encoding="utf-8")
        return path

    @staticmethod
    def _highlights(tables: dict[str, list[dict[str, Any]]]) -> list[str]:
        lines: list[str] = []
        for table, limit in (("http_hosts", 10), ("vuln_findings", 10), ("secrets_findings", 10)):
            rows = tables.get(table) or []
            if not rows:
                continue
            lines.append(f"{table}:")
            for row in rows[:limit]:
                if table == "http_hosts":
                    lines.append(
                        f"  [{row.get('status_code') or '?'}] {row.get('url')} "
                        f"{('-- ' + str(row.get('title'))) if row.get('title') else ''}"
                    )
                elif table == "vuln_findings":
                    lines.append(
                        f"  [{row.get('severity') or '?'}] {row.get('template_id')} "
                        f"{row.get('url')}"
                    )
                else:
                    lines.append(
                        f"  {row.get('secret_type')} at {row.get('url')} "
                        f"({row.get('confidence') or 'unknown'})"
                    )
        return lines

    def export(self, fmt: str = "json") -> dict[str, str]:
        fmt = (fmt or "json").lower()
        if fmt not in {"json", "csv", "txt", "all"}:
            raise ValueError(f"unsupported report format: {fmt}")
        outputs: dict[str, str] = {}
        if fmt in {"json", "all"}:
            outputs["json"] = str(self.write_json())
        if fmt in {"csv", "all"}:
            outputs["csv"] = str(self.write_csv())
        if fmt in {"txt", "all"}:
            outputs["txt"] = str(self.write_summary())
        return outputs


def _loads(value: Any, default: Any) -> Any:
    if isinstance(value, str):
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return default
    return value if value is not None else default
