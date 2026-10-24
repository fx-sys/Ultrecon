"""Target list parsing, validation and scope-boundary checks.

The target file contains one hostname or wildcard hostname per line. Blank
lines and comments are ignored. Wildcards are *scope boundaries*: they are not
expanded into a seed list here. The subdomain enumeration phase uses the base
of a legacy ``*.example.com`` entry as a seed and applies the wildcard as a
boundary to results. Label-local globs constrain already-known hosts and are
never used as probe seeds.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

from core.util import dedupe

_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_GLOB_LABEL_RE = re.compile(r"^[a-z0-9*-]+$")
_MAX_HOSTNAME_LEN = 253
_MAX_FILE_BYTES = 4 * 1024 * 1024
_MAX_GLOB_STARS = 16


class ScopeError(ValueError):
    """Raised when the target list is missing, empty or invalid."""


@dataclass(frozen=True)
class Target:
    raw: str
    domain: str | None
    wildcard: bool = False
    pattern: str | None = None

    @property
    def key(self) -> str:
        """Return the canonical scope entry, independent of input casing."""
        if self.pattern is not None:
            return self.pattern
        if self.domain is None:
            return ""
        return f"*.{self.domain}" if self.wildcard else self.domain

    def to_dict(self) -> dict[str, object]:
        value: dict[str, object] = {"raw": self.raw, "wildcard": self.wildcard}
        if self.pattern is not None:
            value["pattern"] = self.pattern
        else:
            value["domain"] = self.domain
        return value


def _normalize_label(label: str) -> str:
    try:
        ascii_label = label.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ScopeError(f"invalid internationalized label {label!r}") from exc
    if not _LABEL_RE.fullmatch(ascii_label):
        raise ScopeError(f"invalid hostname label {label!r}")
    return ascii_label


def _normalize_glob_pattern(candidate: str) -> str:
    if candidate.count("*") > _MAX_GLOB_STARS:
        raise ScopeError(f"hostname patterns may contain at most {_MAX_GLOB_STARS} wildcards")
    labels = candidate.split(".")
    if len(labels) < 2 or any(not label for label in labels):
        raise ScopeError("hostname pattern must contain at least two non-empty labels")
    if "*" in labels[-1]:
        raise ScopeError("the final hostname label must be literal")

    normalized_labels: list[str] = []
    for label in labels:
        if "*" not in label:
            normalized_labels.append(_normalize_label(label))
            continue
        if not label.isascii():
            raise ScopeError("wildcard-bearing labels must use ASCII characters")
        if "**" in label:
            raise ScopeError("adjacent wildcards are not supported")
        if not _GLOB_LABEL_RE.fullmatch(label):
            raise ScopeError(f"invalid hostname pattern label {label!r}")
        if not any(char in "abcdefghijklmnopqrstuvwxyz0123456789" for char in label):
            raise ScopeError("wildcard-bearing labels must contain a literal letter or digit")
        if len(label) > 63:
            raise ScopeError("hostname pattern label exceeds 63 characters")
        normalized_labels.append(label)

    normalized = ".".join(normalized_labels)
    if len(normalized) > _MAX_HOSTNAME_LEN:
        raise ScopeError("hostname pattern exceeds 253 characters")
    return normalized


def normalize_hostname(entry: str, *, allow_wildcard: bool = False) -> tuple[str, bool]:
    """Return the normalized hostname/pattern and legacy wildcard flag.

    A single leading ``*.`` retains its suffix-boundary semantics. Other
    asterisks use label-local glob matching and are returned in the normalized
    hostname pattern with ``wildcard`` set to false.
    """
    original = entry.strip()
    if not original:
        raise ScopeError("empty entry")
    if any(ch.isspace() for ch in original):
        raise ScopeError(f"whitespace inside entry {original!r}")
    if "://" in original or "/" in original or "?" in original or "#" in original:
        raise ScopeError("URLs/paths are not allowed; provide a bare hostname")
    if ":" in original:
        raise ScopeError("ports and IPv6 addresses are not allowed in the target list")

    candidate = original.lower()
    if candidate.endswith("."):
        candidate = candidate[:-1]
    legacy_wildcard = candidate.startswith("*.") and candidate.count("*") == 1
    if "*" in candidate:
        if not allow_wildcard:
            raise ScopeError("wildcard entries are not allowed here")
        if not legacy_wildcard:
            return _normalize_glob_pattern(candidate), False
        candidate = candidate[2:]
    if not candidate:
        raise ScopeError("missing domain after wildcard")
    if candidate.startswith(".") or candidate.endswith(".") or ".." in candidate:
        raise ScopeError("invalid empty label")

    # Reject raw IPs: this is a domain-scope tool, not a CIDR/IP scanner.
    try:
        ipaddress.ip_address(candidate)
    except ValueError:
        pass
    else:
        raise ScopeError("IP addresses are not allowed; add the domain instead")

    labels = candidate.split(".")
    if len(labels) < 2:
        raise ScopeError("target must be a fully qualified domain name (at least two labels)")
    normalized = ".".join(_normalize_label(label) for label in labels)
    if len(normalized) > _MAX_HOSTNAME_LEN:
        raise ScopeError("hostname exceeds 253 characters")
    return normalized, legacy_wildcard


def _target_from_entry(entry: str) -> Target:
    raw = entry.strip()
    normalized, wildcard = normalize_hostname(raw, allow_wildcard=True)
    if not wildcard and "*" in normalized:
        return Target(raw=raw, domain=None, pattern=normalized)
    return Target(raw=raw, domain=normalized, wildcard=wildcard)


def _normalize_candidate_host(host: str) -> str | None:
    candidate = str(host).strip().lower()
    if candidate.endswith("."):
        candidate = candidate[:-1]
    if (
        not candidate
        or "*" in candidate
        or any(ch.isspace() for ch in candidate)
        or any(char in candidate for char in ":/?#")
        or candidate.startswith(".")
        or candidate.endswith(".")
        or ".." in candidate
    ):
        return None
    try:
        ipaddress.ip_address(candidate)
    except ValueError:
        pass
    else:
        return None
    labels = candidate.split(".")
    if len(labels) < 2:
        return None
    try:
        normalized = ".".join(_normalize_label(label) for label in labels)
    except ScopeError:
        return None
    if len(normalized) > _MAX_HOSTNAME_LEN:
        return None
    return normalized


@lru_cache(maxsize=1024)
def _compiled_glob_label(pattern: str) -> re.Pattern[str]:
    return re.compile(re.escape(pattern).replace(r"\*", ".*"))


def _matches_glob(pattern: str, host: str) -> bool:
    pattern_labels = pattern.split(".")
    host_labels = host.split(".")
    if len(pattern_labels) != len(host_labels):
        return False
    return all(
        _compiled_glob_label(pattern_label).fullmatch(host_label) is not None
        for pattern_label, host_label in zip(pattern_labels, host_labels, strict=True)
    )


@dataclass
class Scope:
    """Resolved target scope for a run."""

    targets: list[Target]
    source: Path | None = None
    include_subdomains: bool = True
    metadata: dict[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.targets:
            raise ScopeError("scope contains no targets")
        deduped: list[Target] = []
        seen: set[str] = set()
        for target in self.targets:
            if target.key not in seen:
                seen.add(target.key)
                deduped.append(target)
        self.targets = deduped

    # -- core properties -------------------------------------------------
    @property
    def domains(self) -> list[str]:
        """Concrete base domains, excluding label-local glob constraints."""
        return dedupe(t.domain for t in self.targets if t.domain)

    @property
    def wildcard_domains(self) -> list[str]:
        return dedupe(t.domain for t in self.targets if t.wildcard and t.domain)

    @property
    def bare_domains(self) -> list[str]:
        return dedupe(t.domain for t in self.targets if not t.wildcard and t.pattern is None and t.domain)

    @property
    def enumeration_seeds(self) -> list[str]:
        """Concrete names used by p02, never pre-generated wildcard targets."""
        return self.domains

    def allows(self, host: str) -> bool:
        """Check whether a concrete hostname falls inside a scope boundary.

        A bare ``example.com`` entry permits the apex and (by default) its
        subdomains. A ``*.example.com`` entry permits subdomains only; add the
        bare apex separately if the apex is in scope. Other wildcard patterns
        match whole hostnames with ``*`` limited to a single DNS label.
        """
        normalized_host = _normalize_candidate_host(host)
        if not normalized_host:
            return False
        for target in self.targets:
            if target.pattern is not None:
                if _matches_glob(target.pattern, normalized_host):
                    return True
                continue
            if target.domain is None:
                continue
            if normalized_host == target.domain:
                if target.wildcard:
                    continue
                return True
            if normalized_host.endswith("." + target.domain):
                if target.wildcard:
                    return True
                if self.include_subdomains:
                    return True
        return False

    def allows_url(self, url: str) -> bool:
        from core.util import host_of

        return self.allows(host_of(url))

    def seed_hosts(self) -> list[str]:
        """Hosts to probe in phases before p02 has produced anything."""
        return self.domains

    # -- serialization ---------------------------------------------------
    def to_dict(self) -> dict[str, object]:
        return {
            "source": str(self.source) if self.source else None,
            "include_subdomains": self.include_subdomains,
            "targets": [t.to_dict() for t in self.targets],
            "domains": self.domains,
            "wildcards": self.wildcard_domains,
            "enumeration_seeds": self.enumeration_seeds,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, value: dict[str, object]) -> Scope:
        if not isinstance(value, dict):
            raise ScopeError("invalid scope payload: expected an object")
        raw_targets = value.get("targets") or []
        if not isinstance(raw_targets, list):
            raise ScopeError("invalid scope payload: targets must be a list")
        targets: list[Target] = []
        for item in raw_targets:
            if not isinstance(item, dict):
                raise ScopeError("invalid scope payload: each target must be an object")
            raw = item.get("raw")
            pattern = item.get("pattern")
            if pattern is not None:
                if not isinstance(pattern, str):
                    raise ScopeError("invalid scope payload: pattern must be a string")
                canonical, wildcard = normalize_hostname(pattern, allow_wildcard=True)
                if wildcard or "*" not in canonical:
                    raise ScopeError("invalid scope payload: pattern is not a label-local glob")
                entry = raw if isinstance(raw, str) else pattern
                target = _target_from_entry(entry)
                if target.pattern != canonical:
                    raise ScopeError("invalid scope payload: raw target does not match pattern")
                targets.append(target)
                continue

            domain = item.get("domain")
            wildcard = item.get("wildcard", False)
            if not isinstance(domain, str) or not domain or not isinstance(wildcard, bool):
                raise ScopeError("invalid scope payload: domain and wildcard fields are required")
            entry = raw if isinstance(raw, str) and raw else (f"*.{domain}" if wildcard else domain)
            target = _target_from_entry(entry)
            if (
                target.pattern is not None
                or target.domain != domain.lower().rstrip(".")
                or target.wildcard != wildcard
            ):
                raise ScopeError("invalid scope payload: target fields are inconsistent")
            targets.append(target)

        include_subdomains = value.get("include_subdomains", True)
        if not isinstance(include_subdomains, bool):
            raise ScopeError("invalid scope payload: include_subdomains must be a boolean")
        metadata = value.get("metadata") or {}
        if not isinstance(metadata, dict):
            raise ScopeError("invalid scope payload: metadata must be an object")
        return cls(
            targets=targets,
            source=Path(value["source"]) if value.get("source") else None,
            include_subdomains=include_subdomains,
            metadata=dict(metadata),
        )

    def __len__(self) -> int:
        return len(self.targets)

    def __str__(self) -> str:
        return ", ".join(t.raw for t in self.targets)


def parse_scope_lines(
    lines: list[str] | tuple[str, ...] | str,
    *,
    include_subdomains: bool = True,
    source: Path | None = None,
    max_targets: int = 10000,
) -> Scope:
    """Parse already-loaded lines into a validated Scope."""
    if isinstance(lines, str):
        lines = lines.splitlines()
    targets: list[Target] = []
    errors: list[str] = []
    seen: set[str] = set()
    for line_no, raw_line in enumerate(lines, start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            target = _target_from_entry(line)
        except ScopeError as exc:
            errors.append(f"line {line_no}: {line!r}: {exc}")
            continue
        if target.key in seen:
            continue
        seen.add(target.key)
        targets.append(target)
        if len(targets) > max_targets:
            raise ScopeError(
                f"too many targets ({len(targets)}); limit is {max_targets}. "
                "Raise scope.max_targets only if this is intentional."
            )
    if errors:
        preview = "\n  ".join(errors[:25])
        extra = f"\n  ... and {len(errors) - 25} more" if len(errors) > 25 else ""
        raise ScopeError(f"invalid target file:\n  {preview}{extra}")
    if not targets:
        raise ScopeError("target file contains no targets (blank or comments only)")
    return Scope(targets=targets, source=source, include_subdomains=include_subdomains)


def parse_scope_file(
    path: str | Path,
    *,
    include_subdomains: bool = True,
    max_targets: int = 10000,
) -> Scope:
    file_path = Path(path).expanduser()
    try:
        if not file_path.exists():
            raise ScopeError(f"target file not found: {file_path}")
        if not file_path.is_file():
            raise ScopeError(f"target path is not a file: {file_path}")
        size = file_path.stat().st_size
        if size > _MAX_FILE_BYTES:
            raise ScopeError(f"target file is too large ({size} bytes)")
        text = file_path.read_text(encoding="utf-8-sig")
    except ScopeError:
        raise
    except OSError as exc:
        raise ScopeError(f"cannot read target file {file_path}: {exc}") from exc
    return parse_scope_lines(
        text,
        include_subdomains=include_subdomains,
        source=file_path.resolve(),
        max_targets=max_targets,
    )
