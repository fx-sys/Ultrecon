"""Small dependency-free utility helpers."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable, Iterator
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, TypeVar
from urllib.parse import urlsplit

T = TypeVar("T")


def utc_now() -> str:
    """UTC timestamp in a stable, sortable ISO-8601 form."""
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def dedupe(items: Iterable[T]) -> list[T]:
    """Deduplicate while preserving first-seen order."""
    seen: set[T] = set()
    out: list[T] = []
    for item in items:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out


def chunked(items: Iterable[T], size: int) -> Iterator[list[T]]:
    batch: list[T] = []
    for item in items:
        batch.append(item)
        if len(batch) >= size:
            yield batch
            batch = []
    if batch:
        yield batch


def truncate(value: str, limit: int = 500) -> str:
    value = value.replace("\x00", "")
    return value if len(value) <= limit else value[:limit] + "..."


def redact(value: str, keep: int = 4) -> str:
    """Redact a secret-ish value for reports while retaining a fingerprint."""
    value = value.strip()
    if len(value) <= keep:
        return "*" * len(value)
    return value[:keep] + "*" * min(len(value) - keep, 24)


def target_hash(entries: Iterable[str]) -> str:
    joined = "\n".join(sorted(entries))
    return hashlib.sha256(joined.encode("utf-8")).hexdigest()[:8]


def content_hash(value: str | bytes) -> str:
    data = value.encode("utf-8", "replace") if isinstance(value, str) else value
    return hashlib.sha256(data).hexdigest()


def safe_filename(value: str, limit: int = 80) -> str:
    value = re.sub(r"[^A-Za-z0-9._-]+", "_", value).strip("._")
    return (value or "item")[:limit]


def host_of(url: str) -> str:
    if "://" not in url:
        url = "//" + url
    try:
        return (urlsplit(url).hostname or "").lower().rstrip(".")
    except ValueError:
        return ""


def json_dumps(value: Any, *, pretty: bool = False) -> str:
    return json.dumps(
        value,
        indent=2 if pretty else None,
        sort_keys=True,
        default=str,
        ensure_ascii=False,
    )


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json_dumps(value, pretty=True) + "\n", encoding="utf-8")
    tmp.replace(path)


def read_json(path: Path, default: Any = None) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return default


def as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        return list(value)
    return [value]
