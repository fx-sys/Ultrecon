"""Shared module interface.

Every ``modules/pNN_*/module.py`` exposes a class named ``Module`` extending
:class:`ModuleBase`. Modules return a :class:`ResultSet`; they never write to
the datastore directly, which keeps them independently testable and lets the
orchestrator enforce scope and provenance centrally.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, ClassVar

from core.scope import Scope
from core.toolrunner import ToolRun, resolve_binary, run_tool


@dataclass
class ResultSet:
    """Normalized rows produced by one phase.

    ``rows`` maps a normalized table name to a list of row dicts. The
    datastore owns validation and timestamps.
    """

    rows: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    tool_runs: list[dict[str, Any]] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def add(self, table: str, row: dict[str, Any] | None = None, **kwargs: Any) -> None:
        payload = dict(row or {})
        payload.update(kwargs)
        payload.setdefault("source_tool", "builtin")
        self.rows.setdefault(table, []).append(payload)

    def extend(self, table: str, rows: list[dict[str, Any]]) -> None:
        for row in rows:
            self.add(table, row)

    def record(self, run: ToolRun) -> None:
        self.tool_runs.append(run.as_record())
        if run.error:
            self.errors.append(f"{run.tool}: {run.error}")

    def note(self, message: str) -> None:
        self.notes.append(message)

    def count(self) -> dict[str, int]:
        return {table: len(rows) for table, rows in self.rows.items()}

    def merge(self, other: ResultSet) -> None:
        for table, rows in other.rows.items():
            self.rows.setdefault(table, []).extend(rows)
        self.tool_runs.extend(other.tool_runs)
        self.errors.extend(other.errors)
        self.notes.extend(other.notes)


class ModuleBase(ABC):
    """Base class for all recon phases."""

    name: ClassVar[str] = "unnamed"
    slug: ClassVar[str] = ""
    phase: ClassVar[int] = 0
    description: ClassVar[str] = ""
    requires_binaries: ClassVar[tuple[str, ...]] = ()
    active_binaries: ClassVar[tuple[str, ...]] = ()
    optional_binaries: ClassVar[tuple[str, ...]] = ()
    is_passive: ClassVar[bool] = True
    active_only: ClassVar[bool] = False
    supports_active: ClassVar[bool] = False
    tables: ClassVar[tuple[str, ...]] = ()

    @abstractmethod
    def run(self, scope: Scope, config: dict[str, Any]) -> ResultSet:
        """Execute the phase and return normalized rows."""

    # -- convenience helpers --------------------------------------------
    def new_result(self) -> ResultSet:
        return ResultSet()

    def binary(self, name: str, config: dict[str, Any]) -> str | None:
        return resolve_binary(name, config)

    def binary_available(self, name: str, config: dict[str, Any]) -> bool:
        return self.binary(name, config) is not None

    def exec_tool(
        self,
        name: str,
        args: list[str],
        config: dict[str, Any],
        *,
        timeout: float | None = None,
        input_text: str | None = None,
        label: str | None = None,
        cwd: str | None = None,
    ) -> ToolRun:
        """Run an external tool, capturing raw output for the run archive."""
        return run_tool(
            name,
            args,
            config,
            timeout=timeout,
            input_text=input_text,
            label=label or self.slug or self.name,
            cwd=cwd,
        )

    def active_enabled(self, config: dict[str, Any]) -> bool:
        return bool((config.get("_run") or {}).get("active", False))
