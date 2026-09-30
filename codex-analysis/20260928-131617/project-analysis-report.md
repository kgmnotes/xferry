# Project Analysis Report
_Generated: 2026-09-28 13:46:44 MSK_
_Agents used: 6_
_Output directory: `/home/user/PycharmProjects/xferry/codex-analysis/20260928-131617`_

## Executive Summary

XFerry's runtime core is in substantially better condition than its current installation story suggests. The isolated baseline passed 3,171 tests with 87.73% branch-aware coverage, Ruff and documentation gates passed, request/runtime boundaries are meaningful, the Docker runtime is hardened, and the managed updater already has careful size/hash checks, health-gated activation, locking, and rollback behavior.

The project is not yet ready for the confirmed public-distribution target. This is intentional rather than accidental: ADR-006, documentation, semantic guards, tests, and the release workflow all enforce a source-only model. The current workflow verifies artifacts and then discards them; it does not promote immutable build outputs or publish to PyPI, GHCR, or GitHub Releases. Managed artifacts and state are hard-coded to `linux-x86_64`, Debian 13 is absent, and the public CLI omits `xferry update`.

The most important security finding is that the future root-run updater cannot safely trust only a SHA-256 value supplied by a manifest downloaded from the same GitHub Release trust domain as the executable. Before `xferry update` becomes public, the client needs an independent trust root. The recommended launch design is a canonical, signed multi-platform manifest verified against embedded Ed25519 public keys, while workflow attestations, SBOMs, and provenance remain publication/audit controls.

No CRITICAL issues were found. Six deduplicated HIGH launch blockers were identified. Broad runtime refactoring is not one of them: `xferry/server.py` should remain the composition root for this work, and release/platform contracts should be centralized narrowly.

## Scope & Coverage

- Repository snapshot: `main` at `7f8e2c56e7eefe25a2270d37bece97ddf374a738`, 29 commits ahead of `origin/main`, 0 behind when audited.
- Product scope: portable PyPI/pipx CLI on Windows/macOS/Linux; managed systemd deployment on Ubuntu 22.04/24.04/26.04 and Debian 12/13 on x86_64/arm64; GHCR `linux/amd64` and `linux/arm64`; PyPI/GHCR/GitHub Release publication from `vX.Y.Z` tags with protected-environment approval; explicit verified update and rollback.
- Analyzed: package metadata, runtime/module boundaries, CLI and management code, installer/SCIE/update paths, Docker/Compose/systemd assets, GitHub workflows, documentation/ADRs/guards, representative and release-focused tests.
- Root verification:
  - 3,171 tests passed in 154.92 seconds.
  - Coverage 87.73%, above the configured 85% floor.
  - Ruff 0.15.5 check and format check passed.
  - Documentation render/sync/staleness checks and `mkdocs build --strict` passed.
  - Mypy 1.20.1 failed at `xferry/handlers/notepad.py:285` because an `Any` is returned as `NotepadService`.
  - 85 deployment/release-focused tests passed.
  - Bandit reported no medium/high findings.
  - Pip-audit identified `mkdocs-material==9.7.6` (`PYSEC-2026-3864`, fixed in 9.7.7) and `pip==26.1.2` (`PYSEC-2026-3721`, fixed in 26.2).
- External-state checks: PyPI `xferry` returned 404; no GitHub tags, Releases, or GHCR package were found; the only visible GitHub Environment was `github-pages`. Current credentials had read access only, so branch protection, environment protection, and organization-level Actions policy could not be proven.
- Context7 was available and used for PyPA Trusted Publishing/pipx, PEX SCIE behavior, Docker Buildx multi-platform publication, MkDocs validation, systemd operator guidance, and GitHub Actions environments/OIDC/attestations.
- Safety: secret-heavy paths and generated/dependency directories were excluded. No source, test, configuration, infrastructure, or project documentation file was changed; only audit/planning artifacts were written.

## Agents Used

| Agent | Role | Report | Status |
|---|---|---|---|
| architect-reviewer | Runtime boundaries, coupling, and release-contract architecture | `agent-reports/architect-reviewer.md` | completed |
| devops-engineer | CI/CD, artifact promotion, deployment, and release topology | `agent-reports/devops-engineer.md` | completed |
| documentation-engineer | Installation/operation truth, docs guards, and freshness | `agent-reports/documentation-engineer.md` | completed |
| qa-expert | Platform matrices, consumer artifact acceptance, and release gates | `agent-reports/qa-expert.md` | completed |
| security-auditor | Supply-chain trust, updater/installer verification, and least privilege | `agent-reports/security-auditor.md` | completed |
| dx-optimizer | Install-to-first-success and day-2 operator journeys | `agent-reports/dx-optimizer.md` | completed |

## Critical & High Issues

No CRITICAL issues were found.

| # | Severity | Issue | Source Agent(s) | File / Area | Recommended Fix |
|---|---|---|---|---|---|
| 1 | HIGH | Accepted policy and automated guards deliberately block the confirmed public-distribution target | devops-engineer, documentation-engineer, qa-expert, security-auditor, architect-reviewer | `docs/ADR/ADR-006-release-artifacts.md`, `tools/check_stale_docs.py`, `tests/test_check_stale_docs.py`, `tests/test_deployment_artifacts.py` | Supersede ADR-006 and replace negative source-only assertions with positive publication-safety invariants before enabling publishers. |
| 2 | HIGH | No immutable build-once, verify-once, protected promotion chain exists | devops-engineer, qa-expert, security-auditor | `.github/workflows/release.yml` | Preserve exact wheel/sdist, SCIE, installer, manifest, checksums, SBOM, and provenance outputs; publish only downloaded promoted artifacts from job-scoped, protected jobs. |
| 3 | HIGH | A public root-run updater would trust a mutable manifest and executable from one release domain | security-auditor, devops-engineer, documentation-engineer, dx-optimizer | `xferry/management/releases.py`, `tools/build_scie_release.py`, `packaging/install.sh.in` | Add a signed canonical manifest and embedded client trust keys before exposing `xferry update`; initially require `--to VERSION`. |
| 4 | HIGH | Managed platform identity and support are hard-coded to Linux x86_64 and omit Debian 13 | devops-engineer, qa-expert, security-auditor, dx-optimizer, documentation-engineer, architect-reviewer | `xferry/management/model.py`, `releases.py`, `managed_state.py`, `tools/build_scie_release.py`, `packaging/install.sh.in` | Centralize platform/artifact contracts and add `linux-x86_64` plus `linux-aarch64` across all target distros, builders, state, tests, and docs. |
| 5 | HIGH | Portable consumer acceptance does not prove wheel/pipx behavior across Windows, macOS, and Python boundaries | qa-expert, dx-optimizer | `.github/workflows/ci.yml`, `tools/verify_python_artifacts.py` | Test built-wheel and pipx-style installs outside the checkout on Windows/macOS/Linux for Python 3.10, 3.12, and 3.14. |
| 6 | HIGH | The default onboarding and lifecycle UX do not implement the three target journeys | dx-optimizer, documentation-engineer, qa-expert | `README.md`, `docs/quick-start.md`, `docs/operations.md`, `xferry/management/cli.py`, Docker examples | Make pipx the portable default, clearly separate managed Linux commands, publish immutable GHCR examples, and expose update only after its trust/release dependencies are complete. |

## Architecture & Design

The runtime architecture does not justify a broad refactor. `xferry/server.py:108` is a legitimate composition root. Lifecycle and WebSocket responsibilities already live in `xferry/lifecycle.py` and `xferry/websocket_runtime.py`; request ordering is centralized in `xferry/request_pipeline.py`; method policy comes from `xferry/features.py`; and plugin services are intentionally narrow in `xferry/extensions.py`. Focused tests enforce those boundaries.

The architectural weakness relevant to the requested outcome is release-contract duplication. Platform IDs, executable naming, manifest expectations, installer checks, updater selection, and managed-state parsing are maintained independently. The safe intervention is one release/platform model used by builder, parser, updater, managed state, tests, and generated installer/docs data. Portable pipx usage and managed Linux lifecycle must remain separate product contracts.

The private-hook protocol between `RequestPipeline` and the server remains a LOW change hotspot, but it is unrelated to the release goal and should stay in backlog unless a concrete protocol/security change needs it.

## Security & Compliance

Existing strengths include SHA-pinned Actions, `persist-credentials: false` in release checkouts, digest-pinned Docker bases, a non-root image user, hardened Compose settings, strict manifest parsing, HTTPS/redirect validation, size and SHA-256 checks, update locking, config checks, health checks, and automatic restore.

The missing boundary is publisher identity at the client. Hashing an executable against a manifest from the same mutable Release is integrity against transport corruption, not authenticity against a compromised publisher. Recommended minimum launch control:

1. Canonical manifest v2 covers version, tag, platform, executable name/size/SHA-256, source commit, workflow run, and complete artifact digests.
2. Publish a detached Ed25519 signature with a key ID; the client embeds a small trusted public-key ring and rejects unknown, revoked, malformed, expired, downgraded, or mismatched metadata.
3. Keep GitHub artifact attestations, SBOMs, and provenance for producer-side auditability; client-side Sigstore verification and TUF-style threshold/expiry metadata can follow later.
4. Never document `curl | sudo sh`. Download installer, signature/manifest, verify, then execute explicitly.
5. Give each publish job only the permissions it needs. Use PyPI Trusted Publishing/OIDC, `packages: write` only for GHCR, and `contents: write` only for GitHub Release creation.

The two vulnerable CI/docs tool pins are not direct runtime vulnerabilities, but release automation executes them and the existing strict dependency audit will block a safe release. Patch and re-audit them before release work.

## Performance & Reliability

No material runtime performance regression or scalability defect was established in this release-focused audit. Existing tests cover high-risk parser, WebSocket, auth, storage, and update paths.

Reliability is strongest inside the current single-platform updater: failed config, restart, or health checks restore the prior release. The main reliability gap is matrix evidence. SCIE/systemd behavior must be proven for every supported distro/architecture, and GHCR images must be pulled and smoked on both target architectures. Real arm64 runners are preferred for managed-host acceptance if QEMU is too slow or cannot exercise systemd faithfully.

## Code Quality & Maintainability

- Strict typing is currently red at `xferry/handlers/notepad.py:285`. This is a narrow type-narrowing defect rather than a demonstrated runtime failure and should be fixed first.
- Coverage and test volume are strong, and release/update failure paths are unusually well represented.
- Centralizing the release/platform model is the only significant refactor required for this outcome.
- Avoid broad changes to the server composition root or browser modules during distribution work; they add risk without unblocking installation.
- Root CLI affordances (`xferry --version`, clear unknown-command errors, grouped help) and stable `next_actions` in diagnostics are small, bounded improvements.

## DevOps & Infrastructure

The current release workflow is a useful verification prototype: it builds and validates Python artifacts, a Docker image, and a SCIE bundle. It is intentionally manual/read-only and loses all outputs after the run.

The target topology should be:

`vX.Y.Z tag -> quality/preflight gates -> build exact candidates -> verify candidates -> store workflow artifacts -> protected release-production approval -> publish the same bytes/images -> post-publish consumer smoke`

Required invariants:

- tag, `xferry.config.__version__`, changelog entry, manifest version, and filenames match;
- PRs and ordinary branch pushes can never publish;
- all third-party actions remain commit-SHA pinned;
- publish jobs do not rebuild candidates;
- PyPI uses Trusted Publishing and no static API token;
- GHCR publishes `linux/amd64,linux/arm64`, SBOM, provenance, immutable `vX.Y.Z` tags and recorded digest;
- GitHub Releases contain signed manifests, signatures, SCIE assets per architecture, installers, checksums, SBOMs, and source/workflow metadata;
- production jobs use a protected `release-production` environment with required reviewers and job-scoped permissions;
- no mutable `latest` dependency is used for the first public release line.

## Frontend & UX

The browser UI itself was not a primary audit target and no frontend defect was found. Installation UX has three distinct journeys that should be reflected consistently in help, docs, tests, and release artifacts:

| Journey | Default path | Lifecycle owner |
|---|---|---|
| Portable CLI | `pipx install xferry` then `xferry run --preset local --open` | `pipx upgrade/uninstall`; works on Windows/macOS/Linux |
| Managed Linux | verified installer, `sudo xferry setup/status/doctor/update/rollback/uninstall` | XFerry managed release state and systemd |
| Container | immutable `ghcr.io/kgmnotes/xferry:vX.Y.Z` or digest | Docker/Compose and registry digest |

Top-level help should label Linux-only commands instead of making portable users infer applicability. `doctor --json` should remain telemetry-free and secret-redacted while adding detected platform/state and local `next_actions`.

## Data & ML

Not applicable. The project has no database, data pipeline, or ML subsystem relevant to this audit.

## Product & Growth

The biggest adoption improvement is reducing the portable first-run path from a six-command source checkout to two commands when pipx is already installed. Public artifacts are not merely a marketing surface: they are the prerequisite for a credible cross-platform CLI journey.

The launch should favor immutable, explainable behavior over convenience aliases. For v1, publish version tags/digests only and make managed updates explicit with `xferry update --to X.Y.Z`. A signed latest-channel metadata design may be added after the first release line is stable.

## Documentation & Process

Documentation tooling is healthy but enforces the old decision. ADR-006 must be marked superseded, not silently rewritten. Documentation guards should then assert currency and safety: supported journeys, exact platform matrix, immutable references, protected environment, no static publisher tokens, and verified installer/update steps.

The canonical English docs should be organized around the three journeys. Source checkout belongs in contributor documentation. Add explicit MkDocs validation for omitted nav files, absolute/unrecognized links, and anchors; generate or verify the platform matrix and CLI reference from canonical code contracts; reconcile the PR template's `[Unreleased]` expectation with `CHANGELOG.md`.

## Quick Wins Backlog

| Priority | Task | Source Agent(s) | Area | Estimated Effort |
|---|---|---|---|---|
| 1 | Fix Notepad service type narrowing and restore `mypy xferry` | architect-reviewer, devops-engineer, qa-expert | Quality gate | < 0.5 day |
| 2 | Upgrade `mkdocs-material` to at least 9.7.7 and `pip` to at least 26.2; regenerate/validate constraints | security-auditor | Supply chain | 0.5 day |
| 3 | Add release preflight for tag/version/changelog/filename consistency | devops-engineer, qa-expert, security-auditor | Release | 0.5-1 day |
| 4 | Add `verify_docker_image.py` to release image verification | qa-expert | Container QA | < 0.5 day |
| 5 | Add root `xferry --version` and actionable unknown-command output | dx-optimizer | CLI UX | 0.5 day |
| 6 | Add explicit MkDocs validation settings | documentation-engineer | Docs | < 0.5 day |
| 7 | Reconcile `[Unreleased]` PR-template/changelog policy | documentation-engineer | Process | < 0.5 day |

## Deeper Improvements Roadmap

1. **Release policy and trust contract** — supersede ADR-006, add supply-chain boundaries to the threat model, define immutable version rules, key ownership/rotation, platform identifiers, and the three user journeys.
2. **Canonical release model** — implement a single multi-platform manifest/artifact model and compatible state migration before adding arm64 or public update.
3. **Consumer evidence** — prove built-wheel/pipx behavior on portable operating systems and managed lifecycle behavior across the complete Linux matrix.
4. **Build-once promotion** — preserve exact verified candidates and attach SBOM/provenance/attestations before any public publisher is enabled.
5. **Protected publishers** — add PyPI Trusted Publishing, multi-arch GHCR, and GitHub Release assets behind one protected production approval and least-privilege jobs.
6. **Signed managed lifecycle** — verify signed manifests/installers client-side, then expose explicit update, health, rollback, and recovery journeys.
7. **Journey-first documentation** — publish canonical English quick starts and operations docs only when their acceptance tests pass against real artifacts.

## Full Recommended Action Plan

### Immediate

1. Restore a clean baseline: fix the mypy error; patch the two vulnerable tool pins; rerun mypy, Ruff, full pytest/coverage, docs checks, Bandit, and pip-audit.
2. Write and approve a new controlled-publication ADR that supersedes ADR-006. Record the target platform matrix, artifact namespaces, immutable-tag policy, protected environment, signing/key-rotation model, update rules, and the portable/managed/container journey boundaries.
3. Replace source-only semantic tests with positive release safety tests, but keep all public publishers disabled.

### Short Term

4. Introduce the canonical platform/release manifest model and backwards-compatible managed-state handling.
5. Add Linux aarch64 and Debian 13 build/installer/update support with normal, failure, and recovery tests.
6. Add Ed25519-signed manifest generation and client verification, including unknown-key, tamper, wrong-platform, downgrade, rollback, and key-rotation cases.
7. Upgrade cross-platform CI to install built wheels outside the checkout on Windows/macOS/Linux for Python 3.10, 3.12, and 3.14; retain the full Linux 3.10-3.14 suite.
8. Improve root help/version/errors and actionable, redacted diagnostics without changing runtime protocol behavior.

### Medium Term

9. Convert release verification into build-once/promote-exactly workflow artifacts; add tag/version/changelog gates, checksums, SBOMs, provenance, and artifact attestations. Do not publish yet.
10. Add a staging rehearsal: TestPyPI exact-version pipx smoke, candidate multi-arch registry image smoke, and GitHub draft-release asset verification.
11. Add protected production jobs for PyPI, GHCR, and GitHub Releases, all consuming promoted candidates. Configure the external Trusted Publisher, GHCR visibility, and required-reviewer environment.
12. Expose managed `xferry update --to VERSION [--dry-run] [--json]` only after the signed release assets exist and the complete managed matrix passes.
13. Replace source-first user docs with canonical pipx, managed Linux, and immutable-GHCR journeys; generate/validate CLI and support-matrix content.

### Long Term

14. Run a complete release rehearsal and first tagged release with post-publication pipx, pull-by-digest, installer, update, health, rollback, and uninstall checks.
15. Add signed latest-channel metadata only if desired; do not make mutable GitHub/GHCR `latest` the trust anchor.
16. Evaluate client-side Sigstore verification or TUF-style expiry, threshold signatures, rollback protection, and key revocation after the simpler signed-manifest launch is stable.
17. Add release incident runbooks for PyPI yanking, GHCR deprecation, GitHub Release withdrawal, signing-key revocation, and managed rollback communication.

## Open Questions for the Team

The confirmed product decisions answer the platform/channel questions: all specified managed distros and both architectures are launch targets; Windows/macOS are portable CLI targets rather than managed-systemd targets; PyPI, GHCR, and GitHub Releases are required.

Remaining external or ownership decisions:

- Confirm that public namespaces will be PyPI `xferry`, GHCR `ghcr.io/kgmnotes/xferry`, and GitHub `kgmnotes/xferry`; reserve/configure them before publisher activation.
- Name the owners/reviewers for the `release-production` GitHub Environment and PyPI Trusted Publisher.
- Generate and custody the Ed25519 signing key, publish its key ID/public key, and approve rotation/revocation procedure. The private key must not enter the repository.
- Decide whether managed setup documentation should default to private mode or public sslip mode. Risk-first recommendation: private/local first, explicit opt-in for public exposure.
- Decide whether Russian CLI localization is user-facing documentation scope. Canonical documentation remains English either way.

## Appendix: Source Reports

- `/home/user/PycharmProjects/xferry/codex-analysis/20260928-131617/agent-reports/architect-reviewer.md`
- `/home/user/PycharmProjects/xferry/codex-analysis/20260928-131617/agent-reports/devops-engineer.md`
- `/home/user/PycharmProjects/xferry/codex-analysis/20260928-131617/agent-reports/documentation-engineer.md`
- `/home/user/PycharmProjects/xferry/codex-analysis/20260928-131617/agent-reports/qa-expert.md`
- `/home/user/PycharmProjects/xferry/codex-analysis/20260928-131617/agent-reports/security-auditor.md`
- `/home/user/PycharmProjects/xferry/codex-analysis/20260928-131617/agent-reports/dx-optimizer.md`
