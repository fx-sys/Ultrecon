"""Subprocess and binary-resolution helpers for wrapped recon tools."""

from __future__ import annotations

import os
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from core.logging_utils import get_logger
from core.paths import TOOLS_BIN
from core.util import safe_filename, utc_now

log = get_logger(__name__)

_MAX_RAW_BYTES = 20 * 1024 * 1024


@dataclass
class ToolRun:
    tool: str
    command: list[str]
    returncode: int = 0
    stdout: str = ""
    stderr: str = ""
    duration: float = 0.0
    error: str | None = None
    started_at: str = field(default_factory=utc_now)
    finished_at: str = ""
    output_path: str | None = None

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.error

    def as_record(self) -> dict[str, Any]:
        return {
            "tool": self.tool,
            "command": self.command,
            "returncode": self.returncode,
            "duration_seconds": round(self.duration, 3),
            "started_at": self.started_at,
            "finished_at": self.finished_at or utc_now(),
            "error": self.error,
            "output_path": self.output_path,
        }


def _search_path(config: dict[str, Any] | None = None) -> str:
    parts = [str(TOOLS_BIN), str(Path.home() / ".local" / "bin")]
    existing = os.environ.get("PATH", "")
    if existing:
        parts.append(existing)
    if config:
        extra = (config.get("_run") or {}).get("extra_path")
        if extra:
            parts.insert(0, str(extra))
    return os.pathsep.join(parts)


def resolve_binary(name: str, config: dict[str, Any] | None = None) -> str | None:
    """Resolve a tool from tools/bin (project-local) or PATH."""
    if not name:
        return None
    candidate = Path(name).expanduser()
    if candidate.is_absolute() and candidate.is_file() and os.access(candidate, os.X_OK):
        return str(candidate)
    local = TOOLS_BIN / name
    if local.is_file() and os.access(local, os.X_OK):
        return str(local)
    found = shutil.which(name, path=_search_path(config))
    return found


def tool_env(config: dict[str, Any] | None = None) -> dict[str, str]:
    env = os.environ.copy()
    env["PATH"] = _search_path(config)
    run = (config or {}).get("_run") or {}
    if run.get("run_id"):
        env["ULTRECON_RUN_ID"] = str(run["run_id"])
    if run.get("rate_limit"):
        env["ULTRECON_RATE_LIMIT"] = str(run["rate_limit"])
    # Avoid interactive pagers / color escapes in tool output.
    env.setdefault("NO_COLOR", "1")
    env.setdefault("PAGER", "cat")
    return env


def _write_raw(config: dict[str, Any], label: str, tool: str, run: ToolRun) -> str | None:
    run_dir = Path((config.get("_run") or {}).get("raw_dir") or "")
    if not str(run_dir) or str(run_dir) == ".":
        return None
    try:
        run_dir.mkdir(parents=True, exist_ok=True)
        path = run_dir / f"{safe_filename(label)}.{safe_filename(tool)}.log"
        header = (
            f"$ {' '.join(run.command)}\n"
            f"started: {run.started_at}\n"
            f"returncode: {run.returncode}\n"
            f"duration: {run.duration:.3f}s\n"
            f"{'-' * 60}\n"
        )
        payload = (header + run.stdout + "\n--- stderr ---\n" + run.stderr)[:_MAX_RAW_BYTES]
        path.write_text(payload, encoding="utf-8", errors="replace")
        return str(path)
    except OSError as exc:
        log.debug("Could not archive output for %s: %s", tool, exc)
        return None


def run_tool(
    tool: str,
    args: list[str],
    config: dict[str, Any] | None = None,
    *,
    timeout: float | None = None,
    input_text: str | None = None,
    label: str = "tool",
    cwd: str | None = None,
) -> ToolRun:
    """Execute a tool without a shell, capturing stdout/stderr."""
    config = config or {}
    resolved = resolve_binary(tool, config)
    command = [resolved or tool, *[str(a) for a in args]]
    started = time.monotonic()
    record = ToolRun(tool=tool, command=command)
    record.started_at = utc_now()

    if not resolved:
        record.returncode = 127
        record.error = f"{tool} is not installed or not executable"
        record.finished_at = utc_now()
        log.debug("%s", record.error)
        return record

    run_cfg = config.get("run") or {}
    effective_timeout = timeout or float(run_cfg.get("tool_timeout", 300))
    log.debug("exec: %s", " ".join(command))
    try:
        proc = subprocess.run(
            command,
            input=input_text,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=effective_timeout,
            cwd=cwd,
            env=tool_env(config),
            check=False,
        )
        record.returncode = proc.returncode
        record.stdout = proc.stdout or ""
        record.stderr = proc.stderr or ""
        if proc.returncode != 0:
            tail = (record.stderr or record.stdout).strip().splitlines()
            record.error = tail[-1][:300] if tail else f"exit code {proc.returncode}"
    except subprocess.TimeoutExpired:
        record.returncode = 124
        record.error = f"timed out after {effective_timeout:.0f}s"
    except OSError as exc:
        record.returncode = 126
        record.error = str(exc)
    finally:
        record.duration = time.monotonic() - started
        record.finished_at = utc_now()
        if (config.get("_run") or {}).get("keep_raw", True):
            record.output_path = _write_raw(config, label, tool, record)

    if record.returncode != 0:
        log.debug("%s exited %s: %s", tool, record.returncode, record.error)
    return record


def run_json_lines(output: str) -> list[dict[str, Any]]:
    """Parse JSONL output, ignoring malformed lines."""
    import json

    rows: list[dict[str, Any]] = []
    for line in output.splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            rows.append(value)
    return rows
