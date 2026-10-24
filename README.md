Ultrecon or ultimate reconnaissance is a tool that made to be free , inspired from everysingle tool of recon on github by mixing them all up on this repo

# Ultrecon

Free and open-source reconnaissance automation for authorized web and API bug-bounty and vulnerability-disclosure work.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE) [![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/) [![Build](https://github.com/fx-sys/Ultrecon/actions/workflows/ci.yml/badge.svg)](https://github.com/fx-sys/Ultrecon/actions/workflows/ci.yml)

Ultrecon accepts a list of authorized hostnames and scope patterns, runs a modular reconnaissance pipeline—from passive OSINT and subdomain discovery through network and HTTP inventory, crawling, API discovery, and non-destructive vulnerability-template verification—and normalizes observations into JSON, CSV, text, and a local SQLite database. The CLI keeps active components behind an explicit authorization gate.

## Legal & Ethics

Use Ultrecon only on assets you own or are explicitly authorized to test. A bug-bounty listing, wildcard, or `--authorize` flag is not proof of authorization: verify every hostname, resolved address, third-party service, exclusion, testing window, and permitted technique against the asset owner's current rules before running a phase.

Start with `--dry-run`, use conservative limits, and stop if the owner asks you to stop. Some passive-discovery phases still send ordinary, rate-limited HTTP requests to in-scope hosts. Active phases can generate substantially more traffic and require both `--active` and `--authorize`, followed by interactive confirmation or explicit `--yes` confirmation. Do not use the tool to disrupt services, exhaust resources, bypass rate limits, access another person's data, or test outside the written scope.

Ultrecon is for reconnaissance and inventory. Its modules do not perform credential brute-forcing, exploitation, destructive testing, or data exfiltration. Treat reports and discovered client-side material as sensitive; secret-like indicators are redacted where supported. Do not publish target data, credentials, or findings without permission.

## Installation

Requirements: Python 3.10 or newer. Git is needed to clone the repository and initialize the optional SecLists wordlist submodule. Linux is the recommended environment for the bundled external-tool installers.

```bash
git clone https://github.com/fx-sys/Ultrecon.git
cd Ultrecon
git submodule update --init --recursive
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

For development dependencies and the installed `ultrecon` command:

```bash
python -m pip install -e '.[dev]'
```

Run `python app.py ...` from the checkout or `ultrecon ...` after installing the console entry point. Missing eligible tools may be installed automatically by default; use `--no-install` to prevent installation and review the dependency plan before allowing tool changes.

## Quickstart

Create `web.txt` with only assets expressly listed in the engagement scope. These reserved names are examples, not permission to test them:

```text
example.test
*.example.test
*api*.example.test
```

Preview first. A dry run resolves modules and dependencies but does not contact targets, install tools, or create run data:

```bash
python app.py --help
python app.py -list web.txt --all --dry-run
```

After verifying authorization and the program's rules, the basic invocation from the CLI specification is:

```bash
python app.py -list web.txt --all
```

`--all` without `--active` runs eligible passive phases and passive portions of mixed phases; it skips active-only phases. It is not a zero-traffic mode: passive modules can make rate-limited requests. To avoid automatic tool installation and reduce request/concurrency limits, use a conservative invocation such as:

```bash
python app.py --list web.txt --all --no-install --rate-limit 5 --threads 2
```

### Scope pattern behavior

- A bare hostname such as `example.test` includes its apex and, by default, its subdomains. Set `scope.include_subdomains: false` in a custom config for apex-only matching.
- The legacy `*.example.test` form matches subdomains, including nested subdomains, but does not include the apex. Add the apex separately if authorized.
- Other `*` patterns are label-local globs. For example, `*api*.example.test` can match `my-api.example.test`; `*` never crosses a dot, and the entire hostname must match with the same number of labels.
- A generic glob's final label must be literal. Wildcard-bearing labels must be ASCII, include at least one literal letter or digit, and cannot contain adjacent `**`. Generic globs are scope constraints, not probe seeds: include concrete authorized hostnames when a phase needs starting hosts.
- Patterns do not confer authorization and do not automatically expand into targets. Discovered hosts and results are checked against the resolved scope.

## Passive and active modes

Without `--all` or `--modules`, the quick pass selects p01, passive p02, p05, and p07. `--all` selects every eligible passive phase. Mixed phases keep their active components disabled unless active mode is explicitly requested. See the phase table below and `python app.py --help` for current details.

Only use active components when the target owner explicitly permits the selected techniques. The CLI prints the resolved target list and requires confirmation before execution:

```bash
python app.py --list web.txt --modules p02,p04,p08,p10,p17 --active --authorize
```

For unattended use, `--yes` supplies that confirmation explicitly; inspect the printed/resolved scope before opting in:

```bash
python app.py --list web.txt --modules p02,p04,p08,p10,p17 --active --authorize --yes
```

`--active` without `--authorize` is rejected before dependency installation or phase execution. `--passive-only` disables active components even when `--active` is present. Do not use `--yes` to bypass scope review.

## Results and run management

A run prints its ID and output directory. The directory contains a run manifest, a SQLite database, and the selected reports. JSON is the default; choose `csv`, `txt`, or `all` to export other formats:

```bash
python app.py --list web.txt --all --format json --output ./output/example-run
python app.py --list web.txt --all --format all --output ./output/example-run
```

Review scope, provenance, tool records, errors, dropped out-of-scope rows, and report contents before acting on observations. Run directories may contain sensitive target data. Runtime data and `output/` are local and git-ignored; do not add scan results, databases, raw tool output, credentials, or reports to a source-code commit.

Resume a previous output directory to extend the same resolved scope. If `--list` is omitted, the saved scope is reused; if supplied, the new scope must match the saved scope:

```bash
python app.py --resume ./output/example-run --modules p07,p09
```

## Command reference

Run `python app.py --help` for the current help text.

| Option | Alias | Purpose |
|---|---|---|
| `--list PATH` | `-list`, `-l` | Read hostnames, legacy wildcards, and label-local glob patterns from a file. |
| `--all` | — | Select all eligible phases; active-only work remains disabled unless active mode is requested. |
| `--modules LIST` | `-m` | Select comma-separated phase IDs, numbers, or names, e.g. `p02,p07,p11`. |
| `--passive-only` | — | Disable active components. |
| `--active` | — | Request active components; requires `--authorize` and confirmation. |
| `--authorize` | — | Declare authorization for every listed target; required with `--active`. |
| `--yes` | — | Confirm the displayed target list non-interactively; valid only with `--active --authorize`. |
| `--output DIR` | `-o` | Set the run output directory. |
| `--format {json,csv,txt,all}` | — | Select report format; default is JSON. |
| `--threads N` | `-t` | Set the global concurrency hint. |
| `--rate-limit N` | — | Set the maximum request rate (1–1000 requests/second); follow the program's lower limits where required. |
| `--resume RUN_ID` | — | Resume a prior run directory and its saved scope. |
| `--config PATH` | — | Load a configuration file instead of the default. |
| `--check-deps` | — | Check dependencies for selected phases; add `--no-install` to prevent installation. |
| `--dry-run` | — | Print the resolved plan without target requests, installations, or run-data writes. |
| `--update` | — | Update installed tools and exit. |
| `--install` / `--no-install` | — | Enable or disable automatic installation of eligible dependencies. |
| `--verbose` | `-v` | Enable debug logging. |
| `--version` | — | Print the installed version. |
| `--help` | `-h` | Show CLI help. |

## Architecture

```text
Ultrecon/
├── app.py                  # CLI entry point
├── core/                   # scope, authorization, orchestration, HTTP, storage, reports
├── modules/                # p01–p17 phase implementations
├── config/                 # conservative defaults and scope schema
├── wordlists/              # optional data submodules
├── docs/MODULES.md         # generated tool catalog and report schema
├── tests/                  # offline unit and safety regression tests
└── output/<run>/           # local, git-ignored run data and reports
```

## Phases

| Phase | Purpose |
|---|---|
| p01 | Passive OSINT, certificate transparency, and organization metadata. |
| p02 | Passive subdomain discovery; gated active DNS enumeration components. |
| p03 | ASN, IP, prefix, and reverse-DNS mapping. |
| p04 | Rate-limited port and service discovery (active only). |
| p05 | HTTP probing and technology fingerprinting. |
| p06 | Web application discovery and optional gated virtual-host checks. |
| p07 | Crawling and endpoint discovery, including public URL archives. |
| p08 | Wordlist-based path discovery (active only). |
| p09 | JavaScript inventory, route extraction, and redacted secret-like indicators. |
| p10 | Parameter and route discovery; active probes are gated. |
| p11 | REST API/OpenAPI specification discovery and operation inventory. |
| p12 | GraphQL endpoint discovery and authorization-gated schema inspection. |
| p13 | gRPC, SOAP, and WebSocket surface discovery. |
| p14 | Opt-in import of explicit, in-scope cloud inventory; no cloud APIs or asset probes. |
| p15 | Exposed Git metadata and client-side secret indicators. |
| p16 | CMS and framework fingerprinting. |
| p17 | Non-destructive vulnerability-template verification (active only). |

See [`docs/MODULES.md`](docs/MODULES.md) for the manifest-backed tool catalog, per-tool installation/access notes, and stable JSON report schema.

## Configuration and dependencies

The conservative default configuration is [`config/config.default.yaml`](config/config.default.yaml). Copy it and pass `--config PATH` to customize request limits, optional sources, output behavior, and phase settings. API-key **values** must not go in YAML or logs; configure the named environment variables instead. Optional API-backed sources are off by default unless enabled and configured.

Check dependencies without installing anything:

```bash
python app.py --all --check-deps --no-install
```

`--update` updates installed tools and may make network or package-manager changes; review the selected tools and environment before using it.

### p14 cloud inventory

p14 is disabled by default and imports explicit inventory records only. It does not call cloud-provider APIs, probe buckets, or invoke CloudList/cloud_enum. To opt in, set `p14.enabled: true`, keep `p14.own_account_only: true`, and provide an operator-designated `own_account_context` and `owned_assets` list in the config. Account IDs are operator assertions and are **not independently verified** by the importer. Only records with a matching configured account context and an in-scope host are recorded. Do not put credentials in the config.

## Development and tests

Tests are offline and mock HTTP and subprocess/tool interactions. They must not scan live third-party hosts. Install development dependencies and run:

```bash
python -m pip install -e '.[dev]'
python -m pytest -q
ruff check .
python docs/scripts/generate_modules.py --check
```

Regenerate the module catalog after manifest edits:

```bash
python docs/scripts/generate_modules.py
```

Modules return normalized `ResultSet` rows. The orchestrator applies scope enforcement, records provenance, and persists each run in SQLite. JSON report schema version `1.0` is documented in the module catalog.

## Contributing

Contributions should preserve the authorization gate, scope enforcement, conservative rate limits, and the no-exploitation/no-brute-force/no-exfiltration constraints. Add or update offline tests for behavior changes, mock all network and subprocess activity, and keep `docs/MODULES.md` generated from `core/tools_manifest.yaml`. Do not submit real target data, credentials, scan output, or reports. Please include the intended scope and testing approach in an issue or pull request.

## License

Ultrecon is released under the MIT License. See [`LICENSE`](LICENSE).

## Roadmap

The build milestones organize the project's planned capabilities:

- **M0 — CLI foundation:** command-line entry point, phase selection, and dry-run planning.
- **M1 — Passive MVP:** passive OSINT, subdomain discovery, HTTP probing, crawling, and normalized reports.
- **M2 — Passive coverage:** network mapping, application/JavaScript discovery, cloud inventory import, Git indicators, and CMS fingerprinting.
- **M3 — Authorized active components:** gated DNS, port, content, parameter, and non-destructive template checks.
- **M4 — API and protocol discovery:** REST/OpenAPI, GraphQL, gRPC, SOAP, and WebSocket inventory.
- **M5 — Polish:** resume/update workflows, report formats, offline tests, documentation, and CI.

Potential follow-up work should remain within authorized reconnaissance and should not introduce exploitation, credential attacks, destructive testing, or collection of out-of-scope data.
