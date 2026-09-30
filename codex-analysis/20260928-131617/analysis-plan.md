# Project Analysis Plan
_Generated: 2026-09-28 13:16:17 +0300_

## Stack Summary
- Python 3.10-3.14 package built with setuptools, exposing the `xferry` console script.
- Synchronous custom HTTP/WebSocket server with a bundled classic-JavaScript UI and no frontend build step.
- Runtime dependencies: ACME, cryptography, defusedxml, josepy and their transitive dependencies.
- Distribution/deployment assets: wheel/sdist verification, Docker, Compose, Linux systemd setup, PEX eager SCIE, managed release/update/rollback code, and GitHub Actions.
- Quality toolchain: pytest, Hypothesis, pytest-cov, benchmark tests, Ruff, strict mypy, Bandit, pip-audit, MkDocs Material, browser smoke tests, and generated-document contracts.

## Product Target Confirmed by the User
- Portable CLI on Windows, macOS, and Linux; PyPI plus `pipx` is the primary native journey.
- Managed production support on Ubuntu 22.04/24.04/26.04 and Debian 12/13 with systemd, on x86_64 and arm64.
- Multi-architecture GHCR image for `linux/amd64` and `linux/arm64`.
- Published PyPI, GHCR, and GitHub Release artifacts, triggered by `vX.Y.Z` tags and protected by a manual GitHub Environment approval.
- Explicit `xferry update` for managed Linux installations, retaining verified activation, health checking, and rollback.
- One canonical English documentation set.
- Risk-first sequencing: green quality gates, safe publication and platform coverage, then evidence-backed modular refactoring.

## Project Structure Overview
- `xferry/`: runtime package and public import namespace.
- `xferry/http/`, `handlers/`, `security/`, `smuggle/`: protocol, feature, and security domains.
- `xferry/management/`: Linux managed setup, service control, release lifecycle, and platform detection.
- `xferry/data/static/ui/`: no-build browser application.
- `tests/`: 3,171 collected cases after parametrization, including property, security, artifact, deployment, browser, and management coverage.
- `.github/workflows/`, `Dockerfile`, `deploy/`, `packaging/`, and `tools/`: build, deployment, release, installer, verification, and documentation automation.
- `README.md`, root public contracts, `docs/`, `mkdocs.yml`, and ADRs: user and contributor documentation.

## Reconnaissance Coverage
- Read project metadata, install and operations documentation, architecture and release ADRs, Docker/systemd/SCIE assets, CI/release/security/docs workflows, management entry points, platform models, release manifest code, documentation generators, and representative boundary tests.
- Mapped tracked files, package modules, internal imports, large modules/functions, test names, release-related references, and platform-specific operations.
- Inspected GitHub Releases and recent Actions state read-only; no public releases exist and the remote main branch predates 29 local commits.
- Excluded ignored build/cache/output directories, minified third-party JavaScript, binaries, and all secret-heavy paths.

## Verification Baseline
- Isolated full suite: 3,171 passed; total coverage 87.73%, above the configured 85% threshold.
- Pinned Ruff check and format check: passed.
- Documentation render/sync/staleness checks and `mkdocs build --strict`: passed.
- Pinned `mypy==1.20.1 --strict`: failed at `xferry/handlers/notepad.py:285` because `Any` is returned as `NotepadService`.
- The full functional suite runs on Ubuntu; the existing Windows/macOS job runs only a small portable subset on Python 3.12.

## Context7 Documentation Checks
- **Python Packaging User Guide** - checked PyPI Trusted Publishing and isolated CLI installation; impact: supports OIDC publication and `pipx` as the primary native application installer.
- **PEX** `2.99.0` - checked eager SCIE and target-platform behavior; impact: SCIE includes Python but remains a platform-specific artifact requiring per-platform builds.
- **Docker** - checked Buildx multi-platform publication, SBOM, and provenance; impact: supports `linux/amd64,linux/arm64` publishing and attested images.
- **MkDocs** `1.6.1` - checked maximal link/nav/anchor validation; impact: current strict build should be evaluated for explicit `validation` warnings.
- **GitHub Actions** - checked protected environments, PyPI OIDC, GHCR permissions, immutable action pins, and artifact attestations; impact: defines the publication security baseline.

## Observed Problems & Risks
- ADR-006, documentation guards, release workflows, and public prose deliberately enforce source-only distribution, directly conflicting with the confirmed target.
- Release verification produces no public artifacts, has read-only permissions, and is not tag-triggered.
- SCIE builders, installer parsing, managed-state validation, and updater platform IDs hard-code `linux-x86_64`.
- Managed host support omits arm64 and Debian 13; user-facing preflight text still says x86_64 only.
- Remote update logic exists but is disabled and omitted from the public CLI.
- Cross-platform CI does not test the complete portable runtime, built-wheel installation, first-run server lifecycle, or the Python-version endpoints on Windows/macOS.
- The current local branch has not run remote CI; strict typing is already red locally.
- Public quick-start commands are Unix-shell-centric despite an OS-independent package classifier.
- Documentation synchronization is strong, but current semantic guards encode the obsolete source-only decision and MkDocs maximal validation is not configured explicitly.
- Several runtime and UI modules are large and contain high-branch functions; their actual cohesion and change risk require evidence-based review before refactoring.

## Selected Agents

### Must Run
- **devops-engineer** - distribution channels, release workflow, Docker/SCIE/systemd portability, and operational lifecycle.
- **architect-reviewer** - module boundaries, coupling, complexity, public API stability, and maintainability.
- **documentation-engineer** - install/operation truth, information architecture, generated contracts, and freshness automation.
- **qa-expert** - platform/test matrix, packaged artifact acceptance, and release gates.
- **security-auditor** - publication/updater/installer supply-chain and least-privilege review.

### High Value
- **dx-optimizer** - minimize install-to-first-success and update/uninstall friction across the confirmed platform matrix.

## Execution Strategy
- Parallel batch 1: `devops-engineer`, `architect-reviewer`, `documentation-engineer`.
- Parallel batch 2 after batch 1: `qa-expert`, `security-auditor`, `dx-optimizer`. Each receives the complete relevant batch-1 reports and must validate or challenge their recommendations.
- Root synthesis: read all reports in full, retry failed or generic reports at most twice after correcting scope, deduplicate findings, and produce the final evidence-backed remediation roadmap.

## Focus Areas Per Agent

### devops-engineer
- Relevant paths: `pyproject.toml`, `Dockerfile`, `.github/workflows/`, `packaging/`, `deploy/`, `tools/build_scie_release.py`, `xferry/management/`.
- Questions: exact release topology; safe tag-to-approval flow; PyPI/GHCR/Release artifact promotion; x86_64/arm64 build and smoke strategy; distro support; install/update/rollback/uninstall contracts.
- Known risks: source-only policy coupling, hard-coded platform identifiers, untested published-artifact path, and release job permission expansion.

### architect-reviewer
- Relevant paths: `xferry/server.py`, settings/configuration modules, handlers, management modules, `xferry/data/static/ui/`, import-boundary tests, architecture docs and ADRs.
- Questions: which large units truly mix responsibilities; where stable seams already exist; what refactors are necessary for release/platform work; how to preserve public imports and protocol behavior.
- Known risks: central server dependency fan-out, large parsing/handler functions, duplicated platform/release validation, and large browser modules.

### documentation-engineer
- Relevant paths: `README.md`, `CONTRIBUTING.md`, `API.md`, `docs/`, `mkdocs.yml`, documentation render/sync/staleness tools and tests.
- Questions: decision-tree installation journeys; OS-specific commands; upgrade/recovery/uninstall coverage; support matrix; canonical/generated ownership; link and command validation.
- Known risks: accurate but obsolete source-only guidance, Unix-only quick start, semantic guards that prevent the new policy, and absent published-artifact examples.

### qa-expert
- Relevant paths: `tests/`, `pyproject.toml`, `.github/workflows/`, artifact verification and browser/Docker smoke tools.
- Questions: smallest sufficient OS/Python/architecture matrix; portable versus Linux-only suites; wheel/PyPI/GHCR/SCIE acceptance; update rollback fault cases; release non-publication guarantees on PRs.
- Known risks: green Linux suite masking platform failures, editable installs instead of consumer artifacts, and no end-to-end publication rehearsal.

### security-auditor
- Relevant paths: release workflows, action permissions, installer template, manifest/updater/managed-state code, Dockerfile/Compose, SECURITY and distribution ADRs.
- Questions: OIDC and environment protection; artifact identity/provenance; checksum trust root; redirect and manifest safety; rollback integrity; registry permissions; secret exposure; safe curl/install guidance.
- Known risks: widening workflow permissions, mutable/replaced release assets, multi-platform manifest ambiguity, and enabling dormant remote update behavior.

### dx-optimizer
- Relevant paths: README/quick start/operations, CLI help/i18n, management setup/service/release commands, Docker/Compose examples, error and diagnostics paths.
- Questions: command count and prerequisites to first success; consistent install/start/doctor/update/uninstall journeys; actionable errors; platform-specific friction; whether alternatives remain discoverable without overwhelming users.
- Known risks: source checkout and virtualenv ceremony, Linux commands presented as universal, fragmented lifecycle guidance, and distinct installation methods with inconsistent UX.
