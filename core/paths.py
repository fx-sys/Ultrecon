"""Filesystem layout helpers.

Every path is resolvable from the repository root so the tool works from a
checkout (``python app.py``) as well as through the ``ultrecon`` entry point.
"""

from __future__ import annotations

import os
from pathlib import Path

PACKAGE_ROOT = Path(__file__).resolve().parent.parent
_CHECKOUT_ROOT = PACKAGE_ROOT if (PACKAGE_ROOT / "app.py").is_file() else None
PROJECT_ROOT = Path(
    os.environ.get("ULTRECON_HOME", _CHECKOUT_ROOT or Path.cwd())
).expanduser().resolve()
CONFIG_DIR = PACKAGE_ROOT / "config"
CORE_DIR = PACKAGE_ROOT / "core"
MODULES_DIR = PACKAGE_ROOT / "modules"
TOOLS_DIR = PROJECT_ROOT / "tools"
TOOLS_BIN = TOOLS_DIR / "bin"
TOOLS_SRC = TOOLS_DIR / "src"
WORDLISTS_DIR = PROJECT_ROOT / "wordlists"
DATA_DIR = PROJECT_ROOT / "data"
DATA_TARGETS = DATA_DIR / "targets"
DATA_RAW = DATA_DIR / "raw"
DATA_PROCESSED = DATA_DIR / "processed"
OUTPUT_DIR = PROJECT_ROOT / "output"
DOCS_DIR = PROJECT_ROOT / "docs"

DEFAULT_CONFIG = CONFIG_DIR / "config.default.yaml"
DEFAULT_MANIFEST = CORE_DIR / "tools_manifest.yaml"


def ensure_runtime_dirs() -> None:
    """Create gitignored runtime directories idempotently."""
    for path in (
        TOOLS_BIN,
        TOOLS_SRC,
        DATA_TARGETS,
        DATA_RAW,
        DATA_PROCESSED,
        OUTPUT_DIR,
    ):
        path.mkdir(parents=True, exist_ok=True)


def resolve_path(value: str | os.PathLike[str], *, base: Path | None = None) -> Path:
    """Resolve a user/config path relative to the project root."""
    path = Path(value).expanduser()
    if path.is_absolute():
        return path
    return (base or PROJECT_ROOT) / path
