# STAGE-014 - Publish canonical journey documentation

## Status
PARTIALLY_CLOSED

## Priority
MEDIUM

## Source findings
- `codex-analysis/20260928-131617/project-analysis-report.md` - F-006, F-013, F-014, F-015, and F-017: docs are internally strong but source/POSIX-first and encode the obsolete policy.
- `agent-reports/documentation-engineer.md` - docs, guards, ADR nav, examples, and tests must move together.
- `agent-reports/dx-optimizer.md` - structure around portable, managed Linux, and container first-success journeys.

## Goal
Prepare a canonical English documentation set, validated against staged artifacts and real CLI help, that gives short, accurate portable, managed, and container journeys without publishing it ahead of production activation.

## Non-goals
- Translate canonical docs into other languages.
- Document mutable `latest`, pipe-to-shell install, or unsupported operating systems.
- Remove contributor source-install workflows.
- Deploy the release branch/docs to production before STAGE-015.

## Scope
### Likely files to inspect
- `README.md`, `docs/index.md`, `docs/quick-start.md`, `docs/operations.md`, `docs/public-direct.md`, `docs/scenarios.md`.
- `CONTRIBUTING.md`, `SECURITY.md`, `CHANGELOG.md`, `.github/PULL_REQUEST_TEMPLATE.md`.
- `examples/README.md`, Docker/Compose examples, systemd assets.
- `mkdocs.yml`, docs render/sync/staleness tools/tests.
- Real `xferry help` and per-command help under forced English locale.

### Likely files to change
- User/operator/contributor/security docs and release runbook references.
- Docker/Compose examples to use immutable GHCR version/digest for public journeys while retaining source examples under contributor scope.
- `mkdocs.yml` explicit validation.
- Generated CLI reference/support matrix source and output, sync/stale guards, and docs/deployment tests.
- Changelog/PR-template policy.

### Files that must not be changed
- Release/runtime behavior merely to make prose easier.
- Canonical docs deployment on the public branch before STAGE-015 approval.
- Secret values, real credentials, or private signing material.

## Dependencies
- Depends on: STAGE-010, STAGE-011, STAGE-012, STAGE-013
- Blocks: STAGE-015

## Implementation steps
1. Make pipx the first portable path with separate Windows and Unix/macOS bootstrap commands, then the two-command first success.
2. Document managed Linux prerequisites/support matrix, verified installer flow, setup mode, status/doctor/logs, exact-version update, rollback, and uninstall.
3. Document immutable GHCR version/digest run and Compose usage, health inspection, data/secrets, and arm64/amd64 support.
4. Move source checkout and local Docker builds to contributor/developer paths rather than deleting them.
5. Generate or check CLI reference in English and generate/validate the support matrix from the canonical code contract.
6. Add explicit MkDocs nav/link/anchor validation, replace obsolete semantic bans with currency/safety checks, and reconcile `[Unreleased]` policy.
7. Validate every command/link against staged artifacts; keep the docs change on the release branch until STAGE-015.

## Acceptance criteria
- [ ] A new user can identify the correct portable, managed, or container path without reading source-install instructions first.
- [ ] Pipx path has correct Windows and Unix/macOS commands and a two-command first success when pipx is present.
- [ ] Managed docs list exactly the ten supported distro/arch pairs and never use `curl | sudo sh`.
- [ ] Container docs use immutable `vX.Y.Z` and optional digest; no required `latest` reference exists.
- [ ] CLI reference and support matrix are generated/validated from canonical sources under English locale.
- [ ] MkDocs explicitly warns/fails on omitted nav files, bad absolute/unrecognized links, and bad anchors under strict build.
- [ ] Docs guards, examples, security docs, ADR navigation, changelog, and PR template are mutually consistent.
- [ ] Public docs are not deployed before STAGE-015 activates the corresponding artifacts.

## Verification plan
| Check | Command or method | Expected result |
|---|---|---|
| Targeted tests | `python -m pytest -q tests/test_check_stale_docs.py tests/test_docker_first_docs.py tests/test_deployment_artifacts.py tests/test_management_cli.py` | All pass |
| Generated docs | `python tools/render_settings.py --check && python tools/render_contracts.py --check && python tools/sync_docs.py --check && python tools/check_stale_docs.py` | No drift |
| Docs build | `mkdocs build --strict` | Clean with explicit validation settings |
| Journey smoke | Execute copied pipx, managed, and GHCR commands against staging artifacts | Commands work as written |

## Suggested subagents
- `documentation-engineer` - canonical/generated docs and information architecture.
- `dx-optimizer` - first-success and recovery journey review.
- `qa-expert` - executable command/link acceptance.
- `security-auditor` - installer/update guidance review.

## Risks and rollback
- Risk: docs advertise channels before activation or contain commands valid only in the checkout.
- Rollback: keep changes on the release branch, preserve current public source-only docs until go-live, and deploy docs only with STAGE-015.

## Completion notes
- Follow-up 2026-10-14 00:20:31 +0300: documentation implementation and both feature lines are now included in main `0230ea9` through PR #45; PR #42 is closed as superseded. Generated contracts, mirror sync, strict MkDocs, packaged OS journeys and browser checks passed on the combined source. Pages run `38468423923` built strictly and skipped deployment as designed; full stage closure still requires the missing TestPyPI portable receipt.
- Attempt: 2026-10-13 21:52:58 +0300; result PARTIALLY_CLOSED. Report: `stage-reports/STAGE-014-20261013-215258.md`.
- Documentation implementation is present in PR #42 at `fa06558008f1eed558fb171fb729e274fe947de3` and remains open/unmerged so public docs are not deployed before production activation.
- Independent review by `gkumurzhi` explicitly covered STAGE-014 documentation implementation at the exact head, with the condition that PR #42 is not merged into a public deployment path before STAGE-010 closes and STAGE-015 go/no-go is granted.
- Local verification on the documentation branch passed 304 targeted docs/policy tests, generated settings/contracts checks, docs mirror sync, stale-doc policy, and strict MkDocs.
- Staging substitution evidence is recorded in `stage-reports/STAGE-014-20261013-staging-evidence.json`. Managed, container, and draft Release substitutions have hosted receipts; Pages deployment is intentionally deferred to STAGE-015.
- Remaining blocker: the portable PyPI/pipx staged receipt is impossible until STAGE-010's TestPyPI pending publisher mapping exists. A fresh browser attempt could not reach the TestPyPI form because Playwright received `407 Proxy Authentication Required`; no secrets or private browser storage were read.
