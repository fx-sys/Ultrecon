"""Authorization gate and audit manifest.

Active phases (port scanning, brute-force content/subdomain discovery,
template-based verification) are never run silently. They require both the
``--authorize`` CLI flag and a second confirmation that reprints every target.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, TextIO

from core import __version__
from core.logging_utils import get_logger
from core.scope import Scope
from core.util import utc_now, write_json

log = get_logger(__name__)

AUTHORIZATION_TEXT = (
    "I confirm I am authorized to perform active security testing against every target "
    "listed above (owned asset, authorized pentest, or in-scope bug bounty/VDP program)."
)


class AuthorizationError(RuntimeError):
    """Raised when active testing is requested without valid authorization."""


@dataclass
class Authorization:
    required: bool
    confirmed: bool
    text: str = AUTHORIZATION_TEXT
    method: str = "not_required"
    confirmed_at: str | None = None
    targets: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "required": self.required,
            "confirmed": self.confirmed,
            "text": self.text,
            "method": self.method,
            "confirmed_at": self.confirmed_at,
            "targets": self.targets,
        }


def format_target_list(scope: Scope) -> str:
    lines = []
    for target in scope.targets:
        suffix = " (label-local glob)" if target.pattern is not None else (
            " (wildcard boundary)" if target.wildcard else ""
        )
        lines.append(f"  - {target.raw}{suffix}")
    return "\n".join(lines)


def confirm_active_testing(
    scope: Scope,
    *,
    authorize_flag: bool,
    assume_yes: bool = False,
    input_fn: Any = input,
    stdout: TextIO | None = None,
    stdin: TextIO | None = None,
) -> Authorization:
    """Validate authorization flags and obtain interactive confirmation."""
    stdout = stdout or sys.stdout
    stdin = stdin or sys.stdin
    targets = [t.raw for t in scope.targets]

    if not authorize_flag:
        raise AuthorizationError(
            "active testing requires --authorize. Re-run with "
            "--active --authorize (and --yes for unattended use) only if every target is "
            "owned by you or explicitly in scope for an authorized test."
        )

    print("\n" + "=" * 74, file=stdout)
    print("ACTIVE TESTING AUTHORIZATION", file=stdout)
    print("=" * 74, file=stdout)
    print("\nResolved target list:\n", file=stdout)
    print(format_target_list(scope), file=stdout)
    print("\n" + AUTHORIZATION_TEXT + "\n", file=stdout)

    if assume_yes:
        print("Confirmation accepted via --yes.", file=stdout)
        return Authorization(
            required=True,
            confirmed=True,
            method="flag+yes",
            confirmed_at=utc_now(),
            targets=targets,
        )

    interactive = bool(getattr(stdin, "isatty", lambda: False)())
    if not interactive:
        raise AuthorizationError(
            "refusing to run active testing without interactive confirmation. "
            "Re-run with --yes only after reading the target list above and confirming "
            "you are authorized."
        )

    try:
        answer = input_fn("Type 'yes' to confirm authorization: ")
    except (EOFError, KeyboardInterrupt) as exc:
        raise AuthorizationError("authorization confirmation aborted") from exc
    if str(answer).strip().lower() not in {"yes", "y"}:
        raise AuthorizationError("authorization was not confirmed; aborting active run")

    print("Confirmation accepted.", file=stdout)
    return Authorization(
        required=True,
        confirmed=True,
        method="interactive",
        confirmed_at=utc_now(),
        targets=targets,
    )


def passive_authorization(scope: Scope) -> Authorization:
    return Authorization(
        required=False,
        confirmed=False,
        method="not_required",
        targets=[t.raw for t in scope.targets],
    )


class RunManifest:
    """Writes output/<run>/run_manifest.json for the user's audit trail."""

    def __init__(self, path: Path, payload: dict[str, Any]) -> None:
        self.path = Path(path)
        self.payload = payload
        self.payload.setdefault("tool", "Ultrecon")
        self.payload.setdefault("version", __version__)
        self.payload.setdefault("started_at", utc_now())
        self.payload.setdefault("history", [])
        self.payload["history"].append(
            {
                "event": "started",
                "at": self.payload["started_at"],
                "active": self.payload.get("active", False),
                "authorized": bool((self.payload.get("authorization") or {}).get("confirmed")),
            }
        )

    def write(self) -> None:
        write_json(self.path, self.payload)

    def finish(self, *, status: str, error: str | None = None) -> None:
        self.payload["finished_at"] = utc_now()
        self.payload["status"] = status
        if error:
            self.payload["error"] = error
        self.payload["history"].append(
            {"event": "finished", "at": self.payload["finished_at"], "status": status}
        )
        self.write()


def build_manifest(
    *,
    run_id: str,
    scope: Scope,
    phases: list[dict[str, Any]],
    active: bool,
    authorization: Authorization,
    command: list[str],
    config: dict[str, Any],
    output_dir: Path,
    resumed: bool = False,
) -> RunManifest:
    run_cfg = config.get("run") or {}
    payload: dict[str, Any] = {
        "run_id": run_id,
        "started_at": utc_now(),
        "targets": [t.raw for t in scope.targets],
        "resolved_scope": scope.to_dict(),
        "phases": phases,
        "active": bool(active),
        "authorization": authorization.to_dict(),
        "rate_limit_per_second": run_cfg.get("rate_limit", 50),
        "threads": run_cfg.get("threads", 10),
        "command": command,
        "output_dir": str(output_dir),
        "resumed": bool(resumed),
        "config": {
            "default": (config.get("_meta") or {}).get("default_config"),
            "user": (config.get("_meta") or {}).get("user_config"),
            "api_key_envs": (config.get("_meta") or {}).get("api_key_envs", {}),
            "api_keys_present": (config.get("_meta") or {}).get("api_keys_present", []),
        },
    }
    return RunManifest(Path(output_dir) / "run_manifest.json", payload)
