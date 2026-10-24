"""Phase selection, dynamic module loading and pipeline execution."""

from __future__ import annotations

import hashlib
import importlib.util
import traceback
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from core import __version__
from core.authz import Authorization, RunManifest, build_manifest
from core.config import load_config
from core.datastore import TABLE_SPECS, DataStore
from core.http import ReconHTTP
from core.installer import Installer, ToolsManifest, installer_from_config
from core.logging_utils import get_logger
from core.module_base import ModuleBase, ResultSet
from core.paths import (
    DATA_PROCESSED,
    DATA_RAW,
    DATA_TARGETS,
    OUTPUT_DIR,
    ensure_runtime_dirs,
)
from core.registry import (
    ACTIVE_ONLY_PHASES,
    PHASE_BY_NUMBER,
    PHASES,
    QUICK_PHASES,
    SelectionError,
    parse_modules_arg,
    phase_id,
    specs_for,
)
from core.reporting import Reporter
from core.scope import Scope
from core.util import host_of, read_json, safe_filename, target_hash, utc_now, write_json

log = get_logger(__name__)


@dataclass
class Selection:
    phases: list[int]
    active: bool
    mode: str
    skipped: list[dict[str, str]] = field(default_factory=list)

    @property
    def specs(self):
        return specs_for(self.phases)

    @property
    def active_only_count(self) -> int:
        return sum(1 for p in self.phases if p in ACTIVE_ONLY_PHASES)

    def phase_payload(self) -> list[dict[str, Any]]:
        return [
            {
                "id": spec.id,
                "slug": spec.slug,
                "title": spec.title,
                "passive": spec.passive,
                "active_only": spec.active_only,
                "mode": "active" if (self.active and not spec.passive) else "passive",
            }
            for spec in self.specs
        ]


@dataclass
class RunResult:
    run_id: str
    output_dir: Path
    counts: dict[str, int]
    modules_run: int
    modules_failed: int
    reports: dict[str, str]
    skipped: list[dict[str, str]] = field(default_factory=list)
    out_of_scope_dropped: int = 0

    @property
    def total_findings(self) -> int:
        return sum(self.counts.values())


def resolve_selection(
    *,
    run_all: bool = False,
    modules_arg: str | None = None,
    passive_only: bool = False,
    active_requested: bool = False,
) -> Selection:
    """Pure phase-selection logic (unit tested without importing modules)."""
    skipped: list[dict[str, str]] = []
    if modules_arg:
        requested = parse_modules_arg(modules_arg)
        mode = "modules"
    elif run_all:
        requested = [p.number for p in PHASES]
        mode = "all"
    else:
        requested = list(QUICK_PHASES)
        mode = "quick"

    effective_active = bool(active_requested) and not passive_only
    if active_requested and passive_only:
        skipped.append(
            {
                "phase": "all",
                "reason": "--passive-only overrides --active; active components disabled",
            }
        )

    phases: list[int] = []
    for number in requested:
        spec = PHASE_BY_NUMBER[number]
        if passive_only and spec.active_only:
            skipped.append(
                {"phase": spec.id, "reason": "active-only phase skipped by --passive-only"}
            )
            continue
        if not effective_active and spec.active_only:
            skipped.append(
                {
                    "phase": spec.id,
                    "reason": "active-only phase skipped because --active was not set",
                }
            )
            continue
        phases.append(number)

    if not phases:
        raise SelectionError(
            "no runnable phases selected. Active-only phases require --active --authorize; "
            "use --all or --modules with at least one passive/mixed phase."
        )
    return Selection(phases=sorted(phases), active=effective_active, mode=mode, skipped=skipped)


def default_output_dir(scope: Scope, timestamp: str | None = None) -> Path:
    stamp = (timestamp or utc_now()).replace(":", "").replace("-", "").replace("T", "-")
    stamp = stamp[:15]
    digest = target_hash(t.raw for t in scope.targets)
    return OUTPUT_DIR / f"{stamp}-{digest}"


def _run_id_for_output(output_dir: Path) -> str:
    """Use stable, collision-resistant IDs for custom output paths."""
    prior_manifest = read_json(output_dir / "run_manifest.json", {})
    prior_id = prior_manifest.get("run_id") if isinstance(prior_manifest, dict) else None
    if (
        isinstance(prior_id, str)
        and prior_id
        and len(prior_id) <= 200
        and prior_id not in {".", ".."}
        and "/" not in prior_id
        and "\\" not in prior_id
        and not any(ord(char) < 32 for char in prior_id)
    ):
        return prior_id

    if output_dir.parent == OUTPUT_DIR.resolve():
        return output_dir.name
    suffix = hashlib.sha256(str(output_dir).encode("utf-8")).hexdigest()[:12]
    return f"{safe_filename(output_dir.name)}-{suffix}"


def resolve_run_directory(
    *,
    scope: Scope,
    output: str | None = None,
    resume: str | None = None,
    timestamp: str | None = None,
) -> tuple[Path, bool]:
    if resume:
        candidate = Path(resume).expanduser()
        if not candidate.is_absolute() and not candidate.exists():
            candidate = OUTPUT_DIR / resume
        if not candidate.exists():
            raise FileNotFoundError(f"resume run directory not found: {candidate}")
        if not candidate.is_dir():
            raise NotADirectoryError(f"resume path is not a directory: {candidate}")
        return candidate.resolve(), True
    if output:
        return Path(output).expanduser().resolve(), False
    return default_output_dir(scope, timestamp).resolve(), False


def load_module_class(phase: int) -> type[ModuleBase]:
    spec = PHASE_BY_NUMBER.get(phase)
    if spec is None:
        raise SelectionError(f"unknown phase {phase}")
    path = spec.module_path
    if not path.exists():
        raise FileNotFoundError(f"module for {spec.id} not found at {path}")
    module_name = f"ultrecon_phase_{phase:02d}"
    import_spec = importlib.util.spec_from_file_location(module_name, path)
    if import_spec is None or import_spec.loader is None:
        raise ImportError(f"cannot load module {path}")
    module = importlib.util.module_from_spec(import_spec)
    import_spec.loader.exec_module(module)
    cls = getattr(module, "Module", None)
    if cls is None:
        raise ImportError(f"{path} does not define a Module class")
    if not issubclass(cls, ModuleBase):
        raise ImportError(f"{path}: Module must extend core.module_base.ModuleBase")
    if int(getattr(cls, "phase", 0)) != phase:
        raise ImportError(f"{path}: Module.phase does not match {spec.id}")
    return cls


def collect_required_binaries(phases: list[int], *, active: bool = False) -> list[str]:
    binaries: set[str] = set()
    for phase in phases:
        try:
            cls = load_module_class(phase)
        except Exception as exc:  # a broken module must not break selection
            log.warning("Could not inspect %s: %s", phase_id(phase), exc)
            continue
        binaries.update(cls.requires_binaries)
        if active:
            binaries.update(cls.active_binaries)
    return sorted(binaries)


def _row_host(table: str, row: dict[str, Any]) -> str:
    host = str(row.get("host") or "").strip().lower().rstrip(".")
    if host:
        return host
    url = row.get("url")
    if url:
        return host_of(str(url))
    if table == "subdomains":
        return str(row.get("host") or "")
    return ""


def filter_scope(
    table: str, rows: list[dict[str, Any]], scope: Scope, *, enforce: bool = True
) -> tuple[list[dict[str, Any]], int]:
    """Drop rows outside the declared boundary; tag every kept row in_scope."""
    kept: list[dict[str, Any]] = []
    dropped = 0
    for row in rows:
        host = _row_host(table, row)
        url = str(row.get("url") or "")
        url_host = host_of(url) if url else ""
        in_scope = scope.allows(host) if host else False
        if url and (not url_host or not host or url_host != host):
            in_scope = False
        # A hostless result cannot be proven in scope. Drop it when enforcement
        # is enabled rather than treating missing provenance as authorization.
        if enforce and (not host or not in_scope):
            dropped += 1
            continue
        if "host" not in row and host:
            row["host"] = host
        if table == "subdomains":
            row["in_scope"] = 1 if in_scope else 0
        kept.append(row)
    return kept, dropped


class Orchestrator:
    def __init__(
        self,
        *,
        scope: Scope,
        config: dict[str, Any],
        selection: Selection,
        output_dir: str | Path,
        authorization: Authorization,
        run_id: str | None = None,
        resumed: bool = False,
        command: list[str] | None = None,
        install: bool | None = None,
    ) -> None:
        self.scope = scope
        self.config = config
        self.selection = selection
        self.output_dir = Path(output_dir).resolve()
        self.run_id = run_id or _run_id_for_output(self.output_dir)
        self.authorization = authorization
        self.resumed = resumed
        self.command = command or []
        self.install = install
        self.store = DataStore(self.output_dir / "ultrecon.db")
        self.manifest: RunManifest | None = None
        self.result: RunResult | None = None
        self._module_classes: dict[int, type[ModuleBase]] = {}
        self._module_load_errors: list[dict[str, str]] = []
        self._raw_dir = DATA_RAW / self.run_id
        self._processed_dir = DATA_PROCESSED / self.run_id
        self._targets_dir = DATA_TARGETS
        self._out_of_scope = 0

    # -- preparation -----------------------------------------------------
    def prepare(self) -> None:
        ensure_runtime_dirs()
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self._raw_dir.mkdir(parents=True, exist_ok=True)
        self._processed_dir.mkdir(parents=True, exist_ok=True)
        self._targets_dir.mkdir(parents=True, exist_ok=True)
        write_json(self._targets_dir / f"{self.run_id}.json", self.scope.to_dict())
        (self._targets_dir / f"{self.run_id}.txt").write_text(
            "\n".join(t.raw for t in self.scope.targets) + "\n", encoding="utf-8"
        )
        self.config["_scope"] = self.scope
        self.config["_run"] = {
            "run_id": self.run_id,
            "output_dir": str(self.output_dir),
            "raw_dir": str(self._raw_dir),
            "processed_dir": str(self._processed_dir),
            "active": self.selection.active,
            "authorized": self.authorization.confirmed,
            "rate_limit": (self.config.get("run") or {}).get("rate_limit", 50),
            "threads": (self.config.get("run") or {}).get("threads", 10),
            "tool_timeout": (self.config.get("run") or {}).get("tool_timeout", 300),
            "keep_raw": (self.config.get("output") or {}).get("keep_raw", True),
        }
        # A single shared client enforces one global rate ceiling across phases.
        self.config["_http_client"] = ReconHTTP(self.config, scope=self.scope)
        self.store.connect()
        self.config["_store"] = self.store
        self.store.start_run(
            {
                "run_id": self.run_id,
                "started_at": utc_now(),
                "targets": [t.raw for t in self.scope.targets],
                "phases": [s.id for s in self.selection.specs],
                "active": self.selection.active,
                "authorized": self.authorization.confirmed,
                "version": __version__,
                "command": " ".join(self.command),
                "notes": "resumed" if self.resumed else None,
            }
        )
        self.manifest = build_manifest(
            run_id=self.run_id,
            scope=self.scope,
            phases=self.selection.phase_payload(),
            active=self.selection.active,
            authorization=self.authorization,
            command=self.command,
            config=self.config,
            output_dir=self.output_dir,
            resumed=self.resumed,
        )
        for item in self.selection.skipped:
            self.manifest.payload.setdefault("skipped", []).append(item)
        self.manifest.write()

    def _load_classes(self) -> None:
        failed = {item["phase"] for item in self._module_load_errors}
        for phase in self.selection.phases:
            if phase in self._module_classes or phase_id(phase) in failed:
                continue
            try:
                self._module_classes[phase] = load_module_class(phase)
            except Exception as exc:
                log.error("Could not load phase %s: %s", phase_id(phase), exc)
                error = {"phase": phase_id(phase), "error": str(exc)}
                self._module_load_errors.append(error)
                if self.manifest:
                    self.manifest.payload.setdefault("module_load_errors", []).append(error)

    def required_binaries(self) -> list[str]:
        self._load_classes()
        binaries: set[str] = set()
        for cls in self._module_classes.values():
            binaries.update(cls.requires_binaries)
            if self.selection.active:
                binaries.update(cls.active_binaries)
        return sorted(binaries)

    def dry_run(self) -> dict[str, Any]:
        """Resolve modules/tools and return a printable plan without writes or subprocesses."""
        self._load_classes()
        manifest = ToolsManifest.load()
        installer = installer_from_config(self.config, install=False)
        binaries = self.required_binaries()
        statuses = installer.detect_binaries(binaries, check_version=False)
        phases = []
        for phase in self.selection.phases:
            cls = self._module_classes.get(phase)
            if cls is None:
                error = next(
                    (item["error"] for item in self._module_load_errors if item["phase"] == phase_id(phase)),
                    "module implementation unavailable",
                )
                phases.append({"id": phase_id(phase), "available": False, "error": error})
                continue
            phases.append(
                {
                    "id": phase_id(phase),
                    "name": cls.name,
                    "available": True,
                    "active": self.selection.active and (not cls.is_passive or cls.supports_active),
                    "mode": "active" if (self.selection.active and cls.supports_active) else "passive",
                    "requires": list(cls.requires_binaries),
                    "active_requires": list(cls.active_binaries) if self.selection.active else [],
                    "optional": list(cls.optional_binaries),
                }
            )
        return {
            "run_id": self.run_id,
            "output_dir": str(self.output_dir),
            "targets": [t.raw for t in self.scope.targets],
            "active": self.selection.active,
            "authorized": self.authorization.confirmed,
            "phases": phases,
            "module_load_errors": self._module_load_errors,
            "tools": [s.to_dict() for s in statuses],
            "manifest_entries": len(manifest.tools),
            "skipped": self.selection.skipped,
        }

    # -- execution -------------------------------------------------------
    def _install_dependencies(self) -> None:
        installer: Installer = installer_from_config(self.config, install=self.install)
        binaries = self.required_binaries()
        if binaries:
            log.info("Checking %d required tool(s)", len(binaries))
            statuses = installer.ensure(binaries, install=self.install)
        else:
            statuses = []
        if self.manifest:
            self.manifest.payload["tools"] = [s.to_dict() for s in statuses]
            self.manifest.write()
        missing = [s for s in statuses if s.status in {"missing", "failed", "missing (auto-install disabled)"}]
        if missing:
            log.warning(
                "%d tool(s) unavailable; built-in fallbacks will be used where possible: %s",
                len(missing),
                ", ".join(s.binary or s.key for s in missing[:12]),
            )

    def run(self) -> RunResult:
        if self.selection.active and not self.authorization.confirmed:
            raise PermissionError("active phases selected without a confirmed authorization")
        self._load_classes()
        self.prepare()
        self._install_dependencies()
        modules_run = 0
        modules_failed = 0

        for phase in self.selection.phases:
            cls = self._module_classes.get(phase)
            if cls is None:
                modules_failed += 1
                continue
            spec = PHASE_BY_NUMBER[phase]
            mode = "active" if (self.selection.active and not cls.is_passive) else "passive"
            log.info("[%s] %s (%s)", spec.id, cls.name, mode)
            result = self._run_module(cls)
            if result is None:
                modules_failed += 1
                continue
            modules_run += 1
            self._persist_result(cls, result)
            for note in result.notes:
                log.debug("[%s] %s", spec.id, note)
            counts = result.count()
            summary = ", ".join(f"{k}={v}" for k, v in sorted(counts.items())) or "no rows"
            log.info("[%s] done: %s", spec.id, summary)
            if result.errors:
                log.debug("[%s] %d tool issue(s)", spec.id, len(result.errors))

        self.store.finish_run(self.run_id)
        self.store.export_tables(self.run_id, self._processed_dir)
        reporter = Reporter(
            self.store,
            self.run_id,
            self.output_dir,
            self.scope,
            self.config,
            self.authorization,
        )
        fmt = str((self.config.get("output") or {}).get("format", "json"))
        reports = reporter.export(fmt)
        counts = self.store.counts(self.run_id)

        if self.manifest:
            self.manifest.payload["counts"] = counts
            self.manifest.payload["out_of_scope_dropped"] = self._out_of_scope
            self.manifest.finish(status="completed" if modules_run else "failed")
        self.store.close()

        self.result = RunResult(
            run_id=self.run_id,
            output_dir=self.output_dir,
            counts=counts,
            modules_run=modules_run,
            modules_failed=modules_failed,
            reports=reports,
            skipped=self.selection.skipped,
            out_of_scope_dropped=self._out_of_scope,
        )
        return self.result

    def _run_module(self, cls: type[ModuleBase]) -> ResultSet | None:
        try:
            module = cls()
            return module.run(self.scope, self.config)
        except Exception as exc:
            log.error("[%s] module failed: %s", phase_id(cls.phase), exc)
            log.debug("%s", traceback.format_exc())
            if self.manifest:
                self.manifest.payload.setdefault("module_errors", []).append(
                    {
                        "phase": phase_id(cls.phase),
                        "error": str(exc),
                        "traceback": traceback.format_exc(limit=5),
                    }
                )
                self.manifest.write()
            return None

    def _persist_result(self, cls: type[ModuleBase], result: ResultSet) -> None:
        enforce = bool((self.config.get("scope") or {}).get("enforce", True))
        inserted: dict[str, int] = {}
        for table, rows in result.rows.items():
            if table not in TABLE_SPECS:
                log.warning("[%s] ignoring unknown table %r", phase_id(cls.phase), table)
                continue
            kept, dropped = filter_scope(table, rows, self.scope, enforce=enforce)
            self._out_of_scope += dropped
            for row in kept:
                row.setdefault("source_tool", "builtin")
            count = self.store.insert_rows(table, kept, self.run_id)
            inserted[table] = inserted.get(table, 0) + count
        for record in result.tool_runs:
            self.store.insert_tool_run(self.run_id, phase_id(cls.phase), record)
        if inserted:
            log.debug("[%s] inserted %s", phase_id(cls.phase), inserted)
        if self.manifest:
            self.manifest.payload.setdefault("phase_results", []).append(
                {
                    "phase": phase_id(cls.phase),
                    "rows": inserted,
                    "tools": len(result.tool_runs),
                    "errors": result.errors[:10],
                }
            )
            self.manifest.write()

    # -- helpers used by --check-deps / --update -------------------------
    def fake_run_for_check(self) -> list[dict[str, Any]]:
        installer = installer_from_config(self.config, install=self.install)
        statuses = installer.ensure(self.required_binaries(), install=self.install)
        return [s.to_dict() for s in statuses]


def load_config_for_run(path: str | None, *, fmt: str | None = None) -> dict[str, Any]:
    config = load_config(path)
    if fmt:
        config.setdefault("output", {})["format"] = fmt
    return config
