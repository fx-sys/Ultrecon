"""Configuration loading and validation."""

from __future__ import annotations

import copy
import os
from pathlib import Path
from typing import Any

import yaml

from core.logging_utils import get_logger
from core.paths import DEFAULT_CONFIG, PROJECT_ROOT

log = get_logger(__name__)


class ConfigError(ValueError):
    """Raised for malformed or unsafe configuration values."""


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    merged = copy.deepcopy(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = copy.deepcopy(value)
    return merged


def _read_yaml(path: Path) -> dict[str, Any]:
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except FileNotFoundError as exc:
        raise ConfigError(f"config file not found: {path}") from exc
    except OSError as exc:
        raise ConfigError(f"cannot read config file {path}: {exc}") from exc
    except yaml.YAMLError as exc:
        raise ConfigError(f"invalid YAML in {path}: {exc}") from exc
    if not isinstance(raw, dict):
        raise ConfigError(f"config root must be a mapping in {path}")
    return raw


def _env_int(name: str, minimum: int, maximum: int) -> int | None:
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return None
    try:
        value = int(raw)
    except ValueError as exc:
        raise ConfigError(f"{name} must be an integer") from exc
    if not minimum <= value <= maximum:
        raise ConfigError(f"{name} must be between {minimum} and {maximum}")
    return value


def _validate_mapping_sections(config: dict[str, Any]) -> None:
    sections = {
        "run",
        "http",
        "scope",
        "install",
        "output",
        "api_keys",
        "optional_sources",
        "_meta",
        *(f"p{phase:02d}" for phase in range(1, 18)),
    }
    for section in sections:
        if section in config and not isinstance(config[section], dict):
            raise ConfigError(f"{section} must be a mapping")


def load_config(path: str | Path | None = None) -> dict[str, Any]:
    """Load defaults, deep-merge a user file, apply safe env overrides."""
    config = _read_yaml(DEFAULT_CONFIG)
    if path:
        user_path = Path(path).expanduser()
        config = _deep_merge(config, _read_yaml(user_path))
        config["_user_config"] = str(user_path.resolve())
    _validate_mapping_sections(config)

    run = config.setdefault("run", {})
    env_rate = _env_int("ULTRECON_RATE_LIMIT", 1, 1000)
    env_threads = _env_int("ULTRECON_THREADS", 1, 200)
    if env_rate is not None:
        run["rate_limit"] = env_rate
    if env_threads is not None:
        run["threads"] = env_threads

    try:
        run["threads"] = int(run.get("threads", 10))
        run["rate_limit"] = int(run.get("rate_limit", 50))
        run["timeout"] = float(run.get("timeout", 20))
        run["retries"] = int(run.get("retries", 2))
    except (TypeError, ValueError) as exc:
        raise ConfigError("run.threads/rate_limit/timeout/retries must be numeric") from exc
    if not 1 <= run["rate_limit"] <= 1000:
        raise ConfigError("run.rate_limit must be between 1 and 1000 requests/second")
    if not 1 <= run["threads"] <= 200:
        raise ConfigError("run.threads must be between 1 and 200")
    if run["timeout"] <= 0:
        raise ConfigError("run.timeout must be positive")

    # Resolve secrets from the environment. Values never get logged or written
    # to the manifest; only the environment variable *names* live in config.
    key_names = config.get("api_keys") or {}
    secrets: dict[str, str] = {}
    for name, env_name in key_names.items():
        if not isinstance(env_name, str):
            continue
        value = os.environ.get(env_name)
        if value:
            secrets[str(name)] = value
    config["secrets"] = secrets
    config["project_root"] = str(PROJECT_ROOT)
    config.setdefault("_meta", {})
    config["_meta"].update(
        {
            "default_config": str(DEFAULT_CONFIG),
            "user_config": config.get("_user_config"),
            "api_key_envs": key_names,
            "api_keys_present": sorted(secrets),
        }
    )
    return config


def source_enabled(config: dict[str, Any], source: str, *, needs_key: str | None = None) -> bool:
    """Return whether an optional data source should run in this run."""
    enabled = bool((config.get("optional_sources") or {}).get(source, False))
    if not enabled:
        return False
    if needs_key and not (config.get("secrets") or {}).get(needs_key):
        return False
    return True


def api_key(config: dict[str, Any], name: str) -> str | None:
    return (config.get("secrets") or {}).get(name)


def run_setting(config: dict[str, Any], key: str, default: Any = None) -> Any:
    return (config.get("run") or {}).get(key, default)


def phase_config(config: dict[str, Any], phase: str, default: Any = None) -> dict[str, Any]:
    value = config.get(phase, default if default is not None else {})
    return value if isinstance(value, dict) else {}
