"""SQLite-backed normalized result store.

Every normalized row carries its ``source_tool`` and ``discovered_at``
provenance. Natural-key unique indexes make repeated runs and duplicate tool
output idempotent. Unknown extra fields are preserved in a JSON ``extra``
column so modules can evolve without a schema migration.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from core.logging_utils import get_logger
from core.util import json_dumps, utc_now, write_json

log = get_logger(__name__)

BASE_COLUMNS: tuple[tuple[str, str], ...] = (
    ("id", "INTEGER PRIMARY KEY AUTOINCREMENT"),
    ("run_id", "TEXT NOT NULL"),
    ("discovered_at", "TEXT NOT NULL"),
    ("source_tool", "TEXT NOT NULL DEFAULT 'unknown'"),
    ("extra", "TEXT"),
)


@dataclass(frozen=True)
class TableSpec:
    columns: tuple[tuple[str, str], ...]
    unique: tuple[str, ...]
    order_by: str = "id"

    @property
    def names(self) -> list[str]:
        return [name for name, _ in self.columns]


TABLE_SPECS: dict[str, TableSpec] = {
    "subdomains": TableSpec(
        (
            ("host", "TEXT NOT NULL"),
            ("domain", "TEXT"),
            ("in_scope", "INTEGER NOT NULL DEFAULT 1"),
        ),
        ("run_id", "host"),
        "host",
    ),
    "ips": TableSpec(
        (
            ("ip", "TEXT NOT NULL"),
            ("host", "TEXT"),
            ("asn", "TEXT"),
            ("org", "TEXT"),
            ("country", "TEXT"),
        ),
        ("run_id", "ip", "host"),
        "ip",
    ),
    "ports_services": TableSpec(
        (
            ("host", "TEXT NOT NULL"),
            ("ip", "TEXT"),
            ("port", "INTEGER NOT NULL"),
            ("protocol", "TEXT NOT NULL DEFAULT 'tcp'"),
            ("state", "TEXT"),
            ("service", "TEXT"),
            ("version", "TEXT"),
            ("tls", "INTEGER"),
        ),
        ("run_id", "host", "port", "protocol"),
        "host, port",
    ),
    "http_hosts": TableSpec(
        (
            ("url", "TEXT NOT NULL"),
            ("host", "TEXT NOT NULL"),
            ("status_code", "INTEGER"),
            ("title", "TEXT"),
            ("server", "TEXT"),
            ("tech", "TEXT"),
            ("content_length", "INTEGER"),
            ("redirect_url", "TEXT"),
            ("tls_issuer", "TEXT"),
            ("screenshot", "TEXT"),
        ),
        ("run_id", "url"),
        "host, url",
    ),
    "endpoints": TableSpec(
        (
            ("url", "TEXT NOT NULL"),
            ("host", "TEXT"),
            ("method", "TEXT NOT NULL DEFAULT 'GET'"),
            ("status_code", "INTEGER"),
            ("content_type", "TEXT"),
            ("source_detail", "TEXT"),
        ),
        ("run_id", "url", "method"),
        "host, url",
    ),
    "js_files": TableSpec(
        (
            ("url", "TEXT NOT NULL"),
            ("host", "TEXT"),
            ("status_code", "INTEGER"),
            ("content_type", "TEXT"),
            ("size", "INTEGER"),
            ("hash", "TEXT"),
            ("source_detail", "TEXT"),
        ),
        ("run_id", "url"),
        "host, url",
    ),
    "parameters": TableSpec(
        (
            ("host", "TEXT"),
            ("url", "TEXT NOT NULL"),
            ("name", "TEXT NOT NULL"),
            ("location", "TEXT NOT NULL DEFAULT 'query'"),
            ("value_sample", "TEXT"),
        ),
        ("run_id", "url", "name", "location"),
        "host, url, name",
    ),
    "api_specs": TableSpec(
        (
            ("url", "TEXT NOT NULL"),
            ("host", "TEXT"),
            ("spec_type", "TEXT"),
            ("version", "TEXT"),
            ("title", "TEXT"),
            ("openapi_version", "TEXT"),
            ("source_detail", "TEXT"),
        ),
        ("run_id", "url", "spec_type"),
        "host, url",
    ),
    "graphql_findings": TableSpec(
        (
            ("url", "TEXT NOT NULL"),
            ("host", "TEXT"),
            ("finding_type", "TEXT NOT NULL"),
            ("detail", "TEXT"),
            ("severity", "TEXT"),
        ),
        ("run_id", "url", "finding_type", "detail"),
        "host, url",
    ),
    "cloud_assets": TableSpec(
        (
            ("provider", "TEXT NOT NULL"),
            ("asset", "TEXT NOT NULL"),
            ("url", "TEXT"),
            ("host", "TEXT"),
            ("evidence", "TEXT"),            ("account", "TEXT"),
            ("region", "TEXT"),
        ),
        ("run_id", "provider", "asset"),
        "provider, asset",
    ),
    "secrets_findings": TableSpec(
        (
            ("url", "TEXT"),
            ("host", "TEXT"),
            ("secret_type", "TEXT NOT NULL"),
            ("match_redacted", "TEXT"),
            ("confidence", "TEXT"),
            ("source_detail", "TEXT"),
        ),
        ("run_id", "url", "secret_type", "match_redacted"),
        "host, secret_type",
    ),
    "cms_fingerprints": TableSpec(
        (
            ("host", "TEXT NOT NULL"),
            ("cms", "TEXT NOT NULL"),
            ("version", "TEXT"),
            ("evidence", "TEXT"),
            ("confidence", "TEXT"),
        ),
        ("run_id", "host", "cms", "version"),
        "host, cms",
    ),
    "vuln_findings": TableSpec(
        (
            ("url", "TEXT NOT NULL"),
            ("host", "TEXT"),
            ("template_id", "TEXT NOT NULL"),
            ("name", "TEXT"),
            ("severity", "TEXT"),
            ("description", "TEXT"),
            ("matched_at", "TEXT"),
            ("reference", "TEXT"),
        ),
        ("run_id", "url", "template_id"),
        "severity, host",
    ),
}

TABLE_NAMES: tuple[str, ...] = tuple(TABLE_SPECS)

TOOL_RUNS_SPEC = TableSpec(
    (
        ("tool", "TEXT NOT NULL"),
        ("phase", "TEXT"),
        ("command", "TEXT"),
        ("returncode", "INTEGER"),
        ("duration_seconds", "REAL"),
        ("started_at", "TEXT"),
        ("finished_at", "TEXT"),
        ("error", "TEXT"),
        ("output_path", "TEXT"),
    ),
    (),
    "id",
)

RUNS_SPEC = TableSpec(
    (
        ("run_id", "TEXT PRIMARY KEY"),
        ("started_at", "TEXT"),
        ("finished_at", "TEXT"),
        ("targets_json", "TEXT"),
        ("phases_json", "TEXT"),
        ("active", "INTEGER"),
        ("authorized", "INTEGER"),
        ("version", "TEXT"),
        ("command", "TEXT"),
        ("notes", "TEXT"),
    ),
    (),
    "started_at",
)


class DataStoreError(RuntimeError):
    pass


@dataclass
class DataStore:
    path: Path
    connection: sqlite3.Connection | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        self.path = Path(self.path)

    def connect(self) -> sqlite3.Connection:
        if self.connection is None:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.connection = sqlite3.connect(self.path)
            self.connection.row_factory = sqlite3.Row
            self.connection.execute("PRAGMA journal_mode=WAL")
            self.connection.execute("PRAGMA foreign_keys=ON")
            self.init_schema()
        return self.connection

    def close(self) -> None:
        if self.connection is not None:
            self.connection.close()
            self.connection = None

    def __enter__(self) -> DataStore:
        self.connect()
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    # -- schema ----------------------------------------------------------
    def init_schema(self) -> None:
        conn = self.connect()
        with conn:
            for table, spec in TABLE_SPECS.items():
                self._create_table(conn, table, spec)
            self._ensure_columns(conn, "cloud_assets", (("host", "TEXT"),))
            self._create_table(conn, "tool_runs", TOOL_RUNS_SPEC)
            self._create_table(conn, "runs", RUNS_SPEC, include_base=False)
        log.debug("Initialized datastore at %s", self.path)

    @staticmethod
    def _ensure_columns(
        conn: sqlite3.Connection,
        table: str,
        columns: tuple[tuple[str, str], ...],
    ) -> None:
        existing = {
            str(row["name"])
            for row in conn.execute(f'PRAGMA table_info("{table}")').fetchall()
        }
        for name, declaration in columns:
            if name not in existing:
                conn.execute(f'ALTER TABLE "{table}" ADD COLUMN "{name}" {declaration}')

    @staticmethod
    def _create_table(
        conn: sqlite3.Connection,
        table: str,
        spec: TableSpec,
        *,
        include_base: bool = True,
    ) -> None:
        columns = list(BASE_COLUMNS) + list(spec.columns) if include_base else list(spec.columns)
        definitions = ", ".join(f'"{name}" {decl}' for name, decl in columns)
        conn.execute(f'CREATE TABLE IF NOT EXISTS "{table}" ({definitions})')
        if spec.unique:
            index_name = f"ux_{table}_natural"
            cols = ", ".join(f'"{c}"' for c in spec.unique)
            conn.execute(
                f'CREATE UNIQUE INDEX IF NOT EXISTS "{index_name}" ON "{table}" ({cols})'
            )

    # -- runs ------------------------------------------------------------
    def start_run(self, record: dict[str, Any]) -> None:
        payload = {
            "run_id": record["run_id"],
            "started_at": record.get("started_at") or utc_now(),
            "finished_at": None,
            "targets_json": json_dumps(record.get("targets") or []),
            "phases_json": json_dumps(record.get("phases") or []),
            "active": int(bool(record.get("active"))),
            "authorized": int(bool(record.get("authorized"))),
            "version": record.get("version"),
            "command": record.get("command"),
            "notes": record.get("notes"),
        }
        conn = self.connect()
        with conn:
            conn.execute(
                """INSERT INTO runs
                (run_id, started_at, finished_at, targets_json, phases_json,
                 active, authorized, version, command, notes)
                VALUES (:run_id, :started_at, :finished_at, :targets_json, :phases_json,
                        :active, :authorized, :version, :command, :notes)
                ON CONFLICT(run_id) DO UPDATE SET
                  targets_json=excluded.targets_json,
                  phases_json=excluded.phases_json,
                  active=excluded.active,
                  authorized=excluded.authorized,
                  version=excluded.version,
                  command=excluded.command,
                  notes=excluded.notes""",
                payload,
            )

    def finish_run(self, run_id: str, notes: str | None = None) -> None:
        conn = self.connect()
        with conn:
            if notes is None:
                conn.execute(
                    "UPDATE runs SET finished_at=? WHERE run_id=?", (utc_now(), run_id)
                )
            else:
                conn.execute(
                    "UPDATE runs SET finished_at=?, notes=? WHERE run_id=?",
                    (utc_now(), notes, run_id),
                )

    def run_record(self, run_id: str) -> dict[str, Any] | None:
        row = self.connect().execute("SELECT * FROM runs WHERE run_id=?", (run_id,)).fetchone()
        return dict(row) if row else None

    # -- normalized rows -------------------------------------------------
    def _coerce_row(self, table: str, row: dict[str, Any]) -> dict[str, Any]:
        spec = TABLE_SPECS[table]
        allowed = set(spec.names) | {"run_id", "discovered_at", "source_tool", "extra"}
        payload: dict[str, Any] = {}
        used: set[str] = set()
        for key, value in row.items():
            if key in allowed:
                payload[key] = value
                used.add(key)
            else:
                payload.setdefault("_extra", {})[key] = value
        if "_extra" in payload:
            payload["extra"] = json_dumps(payload.pop("_extra"))
        payload.setdefault("source_tool", "unknown")
        payload.setdefault("discovered_at", utc_now())
        if "extra" in payload and not isinstance(payload["extra"], str):
            payload["extra"] = json_dumps(payload["extra"])
        return payload

    def insert_rows(self, table: str, rows: list[dict[str, Any]], run_id: str) -> int:
        if table not in TABLE_SPECS:
            raise DataStoreError(f"unknown table {table!r}")
        if not rows:
            return 0
        spec = TABLE_SPECS[table]
        conn = self.connect()
        inserted = 0
        with conn:
            for row in rows:
                payload = self._coerce_row(table, dict(row))
                payload["run_id"] = run_id
                names = [n for n in spec.names if n in payload]
                names.extend(["run_id", "discovered_at", "source_tool"])
                if "extra" in payload:
                    names.append("extra")
                names = list(dict.fromkeys(names))
                placeholders = ", ".join(f":{n}" for n in names)
                column_sql = ", ".join(f'"{n}"' for n in names)
                before = conn.total_changes
                conn.execute(
                    f'INSERT OR IGNORE INTO "{table}" ({column_sql}) VALUES ({placeholders})',
                    {n: payload.get(n) for n in names},
                )
                if conn.total_changes > before:
                    inserted += 1
        return inserted

    def insert_tool_run(self, run_id: str, phase: str, record: dict[str, Any]) -> None:
        conn = self.connect()
        payload = {
            "run_id": run_id,
            "discovered_at": utc_now(),
            "source_tool": "ultrecon",
            "extra": json_dumps({"phase": phase}),
            "tool": record.get("tool", "unknown"),
            "phase": phase,
            "command": json_dumps(record.get("command") or []),
            "returncode": record.get("returncode"),
            "duration_seconds": record.get("duration_seconds"),
            "started_at": record.get("started_at"),
            "finished_at": record.get("finished_at"),
            "error": record.get("error"),
            "output_path": record.get("output_path"),
        }
        with conn:
            conn.execute(
                """INSERT INTO tool_runs
                (run_id, discovered_at, source_tool, extra, tool, phase, command,
                 returncode, duration_seconds, started_at, finished_at, error, output_path)
                VALUES (:run_id, :discovered_at, :source_tool, :extra, :tool, :phase,
                        :command, :returncode, :duration_seconds, :started_at,
                        :finished_at, :error, :output_path)""",
                payload,
            )

    # -- queries ---------------------------------------------------------
    def rows(self, table: str, run_id: str, *, limit: int | None = None) -> list[dict[str, Any]]:
        if table not in TABLE_SPECS and table not in {"tool_runs", "runs"}:
            raise DataStoreError(f"unknown table {table!r}")
        conn = self.connect()
        sql = f'SELECT * FROM "{table}" WHERE run_id=? ORDER BY {self._order_by(table)}'
        params: list[Any] = [run_id]
        if limit:
            sql += " LIMIT ?"
            params.append(limit)
        return [dict(row) for row in conn.execute(sql, params).fetchall()]

    @staticmethod
    def _order_by(table: str) -> str:
        if table == "tool_runs":
            return "id"
        spec = TABLE_SPECS.get(table)
        return spec.order_by if spec else "id"

    def counts(self, run_id: str) -> dict[str, int]:
        result: dict[str, int] = {}
        conn = self.connect()
        for table in TABLE_SPECS:
            row = conn.execute(
                f'SELECT COUNT(*) AS n FROM "{table}" WHERE run_id=?', (run_id,)
            ).fetchone()
            result[table] = int(row["n"]) if row else 0
        return result

    def tool_runs(self, run_id: str) -> list[dict[str, Any]]:
        rows = self.connect().execute(
            "SELECT * FROM tool_runs WHERE run_id=? ORDER BY id", (run_id,)
        ).fetchall()
        return [dict(r) for r in rows]

    def export_tables(self, run_id: str, directory: Path) -> dict[str, str]:
        directory.mkdir(parents=True, exist_ok=True)
        paths: dict[str, str] = {}
        for table in TABLE_SPECS:
            rows = self.rows(table, run_id)
            path = directory / f"{table}.json"
            write_json(path, rows)
            paths[table] = str(path)
        return paths

    def summary(self, run_id: str) -> dict[str, Any]:
        counts = self.counts(run_id)
        tool_runs = self.tool_runs(run_id)
        return {
            "run_id": run_id,
            "counts": counts,
            "total_findings": sum(counts.values()),
            "tools": {
                "total": len(tool_runs),
                "failed": sum(1 for t in tool_runs if (t.get("returncode") or 0) != 0),
            },
        }
