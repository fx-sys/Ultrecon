"""Command-line interface for Ultrecon."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from core import __version__
from core.authz import (
    Authorization,
    AuthorizationError,
    confirm_active_testing,
    passive_authorization,
)
from core.config import load_config
from core.installer import Installer, installer_from_config
from core.logging_utils import get_logger, setup_logging
from core.orchestrator import (
    Orchestrator,
    collect_required_binaries,
    resolve_run_directory,
    resolve_selection,
)
from core.paths import OUTPUT_DIR
from core.scope import Scope, parse_scope_file
from core.util import read_json

log = get_logger(__name__)


class CLIError(ValueError):
    """Raised when the command-line request is invalid."""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ultrecon",
        description=(
            "Free, open-source web/API reconnaissance for assets you own or are "
            "explicitly authorized to test."
        ),
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "-list", "--list", "-l", dest="list_path", metavar="PATH",
        help="target file: hostname, *.domain wildcard, or label-local glob (e.g. *api*.example.test)",
    )
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--all", action="store_true", help="run all eligible phases")
    modes.add_argument("--modules", "-m", help="comma-separated phase names/numbers")
    parser.add_argument(
        "--passive-only", action="store_true", help="disable all active phase components"
    )
    parser.add_argument(
        "--active", action="store_true", help="enable active phases (requires --authorize)"
    )
    parser.add_argument(
        "--authorize", action="store_true", help="declare authorization for every listed target"
    )
    parser.add_argument(
        "--yes", action="store_true", help="confirm the printed authorization statement non-interactively"
    )
    parser.add_argument("--output", "-o", metavar="DIR", help="output directory")
    parser.add_argument(
        "--format", choices=("json", "csv", "txt", "all"), default="json",
        help="report format",
    )
    parser.add_argument("--threads", "-t", type=int, help="global concurrency hint")
    parser.add_argument("--rate-limit", type=int, help="maximum requests per second")
    parser.add_argument("--resume", metavar="RUN_ID", help="resume or extend a previous run")
    parser.add_argument("--config", metavar="PATH", help="override the default YAML config")
    parser.add_argument(
        "--check-deps", action="store_true", help="detect/install dependencies and exit"
    )
    parser.add_argument(
        "--dry-run", action="store_true", help="print the resolved plan without writing or executing"
    )
    parser.add_argument("--update", action="store_true", help="update installed tools and exit")
    install_group = parser.add_mutually_exclusive_group()
    install_group.add_argument(
        "--install", dest="install", action="store_true", help="install missing required tools"
    )
    install_group.add_argument(
        "--no-install", dest="install", action="store_false", help="skip automatic tool installation"
    )
    parser.set_defaults(install=None)
    parser.add_argument("--verbose", "-v", action="store_true", help="enable debug logging")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def _resume_scope(run_ref: str) -> tuple[Scope, Path]:
    candidate = Path(run_ref).expanduser()
    if not candidate.is_absolute() and not candidate.exists():
        candidate = OUTPUT_DIR / run_ref
    candidate = candidate.resolve()
    if not candidate.is_dir():
        raise CLIError(f"resume run directory not found: {candidate}")
    manifest = read_json(candidate / "run_manifest.json")
    scope_data = manifest.get("resolved_scope") if isinstance(manifest, dict) else None
    if not isinstance(scope_data, dict):
        raise CLIError(f"resume run has no valid resolved scope: {candidate / 'run_manifest.json'}")
    try:
        return Scope.from_dict(scope_data), candidate
    except (KeyError, TypeError, ValueError) as exc:
        raise CLIError(f"resume run contains invalid scope data: {exc}") from exc


def _scope_key(scope: Scope) -> tuple[bool, frozenset[str]]:
    return scope.include_subdomains, frozenset(target.key for target in scope.targets)


def _load_scope(args: argparse.Namespace, config: dict[str, Any]) -> tuple[Scope, Path | None]:
    include_subdomains = bool((config.get("scope") or {}).get("include_subdomains", True))
    max_targets = int((config.get("scope") or {}).get("max_targets", 10000))
    prior_scope: Scope | None = None
    prior_dir: Path | None = None
    if args.resume:
        prior_scope, prior_dir = _resume_scope(args.resume)
    if args.list_path:
        scope = parse_scope_file(
            args.list_path,
            include_subdomains=include_subdomains,
            max_targets=max_targets,
        )
        if prior_scope and _scope_key(prior_scope) != _scope_key(scope):
            raise CLIError("resume scope does not match --list; refusing to mix unrelated targets")
        return scope, prior_dir
    if prior_scope:
        return prior_scope, prior_dir
    raise CLIError("a target file is required with --list PATH (or use --resume RUN_ID)")


def _validate_args(args: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
    if args.active and not args.authorize:
        parser.error("--active requires --authorize")
    if args.yes and not (args.active and args.authorize):
        parser.error("--yes is only valid with --active --authorize")
    if args.output and args.resume:
        parser.error("--output cannot be combined with --resume")
    if args.update and (args.check_deps or args.dry_run or args.active or args.resume):
        parser.error("--update cannot be combined with --check-deps, --dry-run, --active, or --resume")
    if args.check_deps and args.dry_run:
        parser.error("--check-deps and --dry-run are separate operations")
    if args.threads is not None and args.threads < 1:
        parser.error("--threads must be at least 1")
    if args.rate_limit is not None and not 1 <= args.rate_limit <= 1000:
        parser.error("--rate-limit must be between 1 and 1000 requests/second")


def _selection(args: argparse.Namespace):
    return resolve_selection(
        run_all=args.all,
        modules_arg=args.modules,
        passive_only=args.passive_only,
        active_requested=args.active,
    )


def _check_dependencies(
    args: argparse.Namespace,
    config: dict[str, Any],
    selection: Any,
) -> int:
    binaries = collect_required_binaries(selection.phases, active=selection.active)
    installer = installer_from_config(config, install=args.install)
    statuses = installer.ensure(binaries, install=args.install)
    print(Installer.format_table(statuses))
    failed = sum(status.status in {"failed", "update-failed"} for status in statuses)
    return 1 if failed else 0


def _update_tools(config: dict[str, Any]) -> int:
    installer = installer_from_config(config)
    statuses = installer.update()
    print(Installer.format_table(statuses))
    failed = sum(status.status in {"failed", "update-failed"} for status in statuses)
    return 1 if failed else 0


def _dry_run(
    *,
    scope: Scope,
    config: dict[str, Any],
    selection: Any,
    output_dir: Path,
    authorization: Authorization,
    command: list[str],
    install: bool | None,
) -> int:
    orchestrator = Orchestrator(
        scope=scope,
        config=config,
        selection=selection,
        output_dir=output_dir,
        authorization=authorization,
        command=command,
        install=False if install is None else install,
    )
    payload = orchestrator.dry_run()
    print(json.dumps(payload, indent=2, sort_keys=True, default=str))
    return 1 if payload.get("module_load_errors") else 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    _validate_args(args, parser)
    setup_logging(args.verbose)

    try:
        config = load_config(args.config)
        if args.threads is not None:
            config.setdefault("run", {})["threads"] = args.threads
        if args.rate_limit is not None:
            config.setdefault("run", {})["rate_limit"] = args.rate_limit
        if args.format:
            config.setdefault("output", {})["format"] = args.format

        if args.update:
            return _update_tools(config)

        selection = _selection(args)
        if args.check_deps:
            return _check_dependencies(args, config, selection)

        scope, prior_dir = _load_scope(args, config)
        output_dir, resumed = resolve_run_directory(
            scope=scope,
            output=args.output,
            resume=str(prior_dir) if prior_dir else None,
        )
        if args.resume and not resumed:
            raise CLIError("could not resolve the previous run directory")

        if selection.active and not args.dry_run:
            authorization = confirm_active_testing(
                scope,
                authorize_flag=args.authorize,
                assume_yes=args.yes,
            )
        elif selection.active:
            # Dry-run displays active plan details but performs no active operation.
            authorization = Authorization(
                required=True,
                confirmed=False,
                method="dry_run",
                targets=[target.raw for target in scope.targets],
            )
        else:
            authorization = passive_authorization(scope)

        if args.dry_run:
            return _dry_run(
                scope=scope,
                config=config,
                selection=selection,
                output_dir=output_dir,
                authorization=authorization,
                command=list(argv if argv is not None else sys.argv[1:]),
                install=args.install,
            )

        orchestrator = Orchestrator(
            scope=scope,
            config=config,
            selection=selection,
            output_dir=output_dir,
            authorization=authorization,
            resumed=resumed,
            command=list(argv if argv is not None else sys.argv[1:]),
            install=args.install,
        )
        result = orchestrator.run()
        print(f"Run {result.run_id}: {result.total_findings} finding(s)")
        print(f"Output: {result.output_dir}")
        for label, path in result.reports.items():
            print(f"{label.upper()}: {path}")
        if result.modules_failed:
            log.error("%d phase(s) failed", result.modules_failed)
            return 1
        return 0
    except AuthorizationError as exc:
        log.error("%s", exc)
        return 2
    except (OSError, ValueError) as exc:
        log.error("%s", exc)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
