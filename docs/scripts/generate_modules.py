"""Generate docs/MODULES.md from the tool manifest."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.installer import ToolsManifest  # noqa: E402
from core.registry import PHASES  # noqa: E402


def _cell(value: object) -> str:
    return str(value or "—").replace("|", r"\|").replace("\n", " ")


def render() -> str:
    manifest = ToolsManifest.load(ROOT / "core" / "tools_manifest.yaml")
    phase_titles = {phase.number: phase.title for phase in PHASES}
    lines = [
        "# Module and Tool Catalog",
        "",
        "This catalog is generated from [`core/tools_manifest.yaml`](../core/tools_manifest.yaml). "
        "Run `python docs/scripts/generate_modules.py` after editing the manifest, or add "
        "`--check` in CI to verify it is current.",
        "",
        "Ultrecon is a reconnaissance and inventory tool, not an exploitation framework. Active "
        "components require `--active --authorize` and a separate confirmation. Optional free-tier "
        "sources remain off unless explicitly enabled and configured with their own API key.",
        "",
    ]
    for phase in PHASES:
        entries = sorted(
            (tool for tool in manifest.tools.values() if tool.phase == phase.number),
            key=lambda tool: (tool.kind, tool.name.lower()),
        )
        lines.extend(
            [
                f"## {phase.id.upper()} — {phase_titles[phase.number]}",
                "",
                phase.purpose,
                "",
                "| Tool / source | Type | Access | Install | Binary / check | Source | Notes |",
                "|---|---|---|---|---|---|---|",
            ]
        )
        for tool in entries:
            state = ""
            if not tool.default_enabled:
                state = "Off by default. "
            if tool.active:
                state = "Active; authorization required. " + state
            if tool.api_key_env:
                state += f"Key: `{tool.api_key_env}`. "
            if tool.notes:
                state += tool.notes
            binary_check = "—"
            if tool.binary:
                binary_check = f"`{tool.binary}`"
                if tool.check_cmd:
                    binary_check += f" · `{tool.check_cmd}`"
            lines.append(
                "| "
                + " | ".join(
                    _cell(value)
                    for value in (
                        f"**{tool.name}** (`{tool.key}`)",
                        tool.kind,
                        tool.access,
                        tool.install_method,
                        binary_check,
                        f"[{tool.repo_url}]({tool.repo_url})" if tool.repo_url else "—",
                        state,
                    )
                )
                + " |"
            )
        if not entries:
            lines.append("| — | — | — | — | — | — | No tools declared. |")
        lines.append("")

    lines.extend(
        [
            "## Stable report schema",
            "",
            "JSON reports use schema version `1.0`. The top-level object contains `schema_version`, "
            "`tool`, `generated_at`, `run`, `scope`, `stats`, `tables`, and `tool_runs`. `stats` "
            "contains per-table `counts`, `total_findings`, and `tool_runs`. `tables` is keyed by "
            "the normalized tables below; row-level `extra` values are decoded as JSON when possible.",
            "",
            "| Table | Purpose |",
            "|---|---|",
            "| `subdomains` | Discovered in-scope hostnames and provenance. |",
            "| `ips` | IP addresses and network/ASN metadata. |",
            "| `ports_services` | Port and service observations. |",
            "| `http_hosts` | HTTP status, title, server, technologies, and URLs. |",
            "| `endpoints` | Discovered web/API paths and endpoint metadata. |",
            "| `js_files` | JavaScript resources and extracted analysis metadata. |",
            "| `parameters` | Query and route parameter names. |",
            "| `api_specs` | OpenAPI/Swagger documents and parsed operations. |",
            "| `graphql_findings` | GraphQL endpoint and safe schema observations. |",
            "| `cloud_assets` | Cloud assets constrained to explicitly configured own-account inventory. |",
            "| `secrets_findings` | Redacted secret-like values and their source locations. |",
            "| `cms_fingerprints` | CMS/framework identification and version hints. |",
            "| `vuln_findings` | Non-destructive template-verification observations. |",
            "",
            "Every normalized finding carries `source_tool` and `discovered_at`; the report also "
            "includes run scope, selected phases, authorization state, aggregate counts, and tool "
            "execution records. Consumers should use `schema_version` when validating compatibility.",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="fail if the generated file is stale")
    args = parser.parse_args()
    output = ROOT / "docs" / "MODULES.md"
    generated = render()
    if args.check:
        if not output.is_file() or output.read_text(encoding="utf-8") != generated:
            print(f"{output.relative_to(ROOT)} is out of date", file=sys.stderr)
            return 1
        print(f"{output.relative_to(ROOT)} is current")
        return 0
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(generated, encoding="utf-8")
    print(f"Wrote {output.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
