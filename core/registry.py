"""Static phase registry used for CLI selection and documentation.

The executable module in ``modules/pNN_.../module.py`` owns the actual tool
wiring. This registry is deliberately dependency-free so selection logic can
be unit tested without importing every module or touching the network.
"""

from __future__ import annotations

from dataclasses import dataclass

from core.paths import MODULES_DIR


class SelectionError(ValueError):
    """Raised for an unknown phase or invalid module selection."""


@dataclass(frozen=True)
class PhaseSpec:
    number: int
    slug: str
    title: str
    purpose: str
    passive: bool
    active_only: bool = False
    quick: bool = False

    @property
    def id(self) -> str:
        return f"p{self.number:02d}"

    @property
    def module_path(self):
        return MODULES_DIR / self.slug / "module.py"


PHASES: tuple[PhaseSpec, ...] = (
    PhaseSpec(
        1,
        "p01_osint_passive",
        "Passive OSINT & org recon",
        "Certificate transparency, public DNS archives and org metadata.",
        passive=True,
        quick=True,
    ),
    PhaseSpec(
        2,
        "p02_subdomain_enum",
        "Subdomain enumeration",
        "Passive providers plus gated brute-force, permutation and takeover checks.",
        passive=False,
        quick=True,
    ),
    PhaseSpec(
        3,
        "p03_asn_ip_network",
        "ASN / IP / network mapping",
        "Map domains to ASNs, prefixes and reverse-DNS hostnames.",
        passive=True,
    ),
    PhaseSpec(
        4,
        "p04_ports_services",
        "Ports & services",
        "Rate-limited port and service discovery (active only).",
        passive=False,
        active_only=True,
    ),
    PhaseSpec(
        5,
        "p05_http_probe_fingerprint",
        "HTTP probing & tech fingerprint",
        "Probe live web hosts, status, titles, servers and technologies.",
        passive=True,
        quick=True,
    ),
    PhaseSpec(
        6,
        "p06_vhost_app_discovery",
        "Virtual hosts & app discovery",
        "Screenshots and gated vhost fuzzing for discovered web hosts.",
        passive=False,
    ),
    PhaseSpec(
        7,
        "p07_crawling_endpoints",
        "Crawling & endpoint discovery",
        "Crawl sites and public URL archives into normalized endpoints.",
        passive=True,
        quick=True,
    ),
    PhaseSpec(
        8,
        "p08_content_discovery",
        "Content discovery",
        "Wordlist-based path discovery (active only).",
        passive=False,
        active_only=True,
    ),
    PhaseSpec(
        9,
        "p09_js_recon",
        "JavaScript recon",
        "Enumerate JS, mine routes and flag secret-like strings.",
        passive=True,
    ),
    PhaseSpec(
        10,
        "p10_hidden_params_routes",
        "Hidden parameters & routes",
        "Extract parameters and discover hidden routes, with gated fuzzing.",
        passive=False,
    ),
    PhaseSpec(
        11,
        "p11_rest_api_recon",
        "REST API recon",
        "Find OpenAPI/Swagger specs and enumerate API operations.",
        passive=False,
    ),
    PhaseSpec(
        12,
        "p12_graphql_recon",
        "GraphQL recon",
        "Detect GraphQL endpoints and (with authorization) introspect.",
        passive=False,
    ),
    PhaseSpec(
        13,
        "p13_other_protocols",
        "gRPC / SOAP / WebSocket recon",
        "Inventory non-REST API surface across other web protocols.",
        passive=False,
    ),
    PhaseSpec(
        14,
        "p14_cloud_assets",
        "Cloud assets",
        "Import explicit in-scope inventory for an operator-designated account; no cloud API or asset probes are made.",
        passive=True,
    ),
    PhaseSpec(
        15,
        "p15_git_secrets",
        "Git & secret exposure",
        "Check for exposed VCS metadata and scan client code for secrets.",
        passive=True,
    ),
    PhaseSpec(
        16,
        "p16_cms_fingerprint",
        "CMS & framework fingerprint",
        "Identify CMS/framework versions and known metadata endpoints.",
        passive=False,
    ),
    PhaseSpec(
        17,
        "p17_vuln_verification",
        "Vulnerability verification",
        "Template-based verification with free tools (active only).",
        passive=False,
        active_only=True,
    ),
)

PHASE_BY_NUMBER: dict[int, PhaseSpec] = {p.number: p for p in PHASES}
QUICK_PHASES: tuple[int, ...] = tuple(p.number for p in PHASES if p.quick)
ACTIVE_ONLY_PHASES: frozenset[int] = frozenset(p.number for p in PHASES if p.active_only)
MIXED_PHASES: frozenset[int] = frozenset(
    p.number for p in PHASES if not p.passive and not p.active_only
)


def _token_lookup() -> dict[str, int]:
    lookup: dict[str, int] = {}
    for spec in PHASES:
        lookup[spec.id] = spec.number
        lookup[str(spec.number)] = spec.number
        lookup[f"p{spec.number}"] = spec.number
        lookup[spec.slug] = spec.number
        lookup[spec.slug.split("_", 1)[1]] = spec.number
        lookup[spec.title.lower()] = spec.number
    return lookup


_TOKENS = _token_lookup()


def phase_id(number: int) -> str:
    return f"p{number:02d}"


def parse_phase_token(token: str) -> int:
    normalized = token.strip().lower().replace("-", "_").replace(" ", "_")
    if normalized in _TOKENS:
        return _TOKENS[normalized]
    raise SelectionError(
        f"unknown phase {token!r}; use p01..p17, 1..17, or a phase slug "
        "such as p02_subdomain_enum"
    )


def parse_modules_arg(value: str) -> list[int]:
    if not value or not value.strip():
        raise SelectionError("--modules was empty")
    numbers: list[int] = []
    for token in value.replace(" ", ",").split(","):
        token = token.strip()
        if not token:
            continue
        number = parse_phase_token(token)
        if number not in numbers:
            numbers.append(number)
    if not numbers:
        raise SelectionError("--modules did not contain any phases")
    return sorted(numbers)


def all_phase_numbers() -> list[int]:
    return [p.number for p in PHASES]


def specs_for(numbers: list[int] | tuple[int, ...]) -> list[PhaseSpec]:
    return [PHASE_BY_NUMBER[n] for n in numbers if n in PHASE_BY_NUMBER]
