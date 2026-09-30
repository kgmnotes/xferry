# STAGE-005 - Add complete managed host support matrix

## Status
CLOSED

## Priority
HIGH

## Source findings
- `codex-analysis/20260928-131617/project-analysis-report.md` - F-004: Debian 13 and arm64 are absent from host support and diagnostics.
- `agent-reports/qa-expert.md` - required matrix is five distro versions by two architectures; Python fanout is not needed for SCIE.
- `agent-reports/dx-optimizer.md` - platform errors should report detected OS/arch/systemd and next actions.

## Goal
Make managed host detection, planning, preflight, and diagnostics correctly accept all ten confirmed distro/architecture combinations and reject unsupported hosts with actionable, redacted output.

## Non-goals
- Build or publish SCIE artifacts (STAGE-006).
- Expose remote update (STAGE-013).
- Promise support for non-systemd distributions, Windows, or macOS managed services.

## Scope
### Likely files to inspect
- `xferry/management/model.py` - supported OS/architecture rules.
- `xferry/management/planning.py` and `setup.py` - preflight and failure messages.
- `xferry/management/service.py` and `i18n.py` - status/doctor representations.
- `tests/test_management_planning.py`, `tests/test_management_setup.py`, `tests/test_management_service.py` - host and diagnostics coverage.

### Likely files to change
- Management host-detection/planning/setup/diagnostic modules above.
- Tests covering Ubuntu 22.04/24.04/26.04 and Debian 12/13 on x86_64/aarch64.
- Canonical release contract only if a missing host alias is discovered.

### Files that must not be changed
- `tools/build_scie_release.py` and `packaging/install.sh.in` - artifact/installer work is STAGE-006.
- `.github/workflows/release.yml` - no publication.
- Runtime server/handlers/UI.

## Dependencies
- Depends on: STAGE-004
- Blocks: STAGE-006, STAGE-013

## Implementation steps
1. Normalize `x86_64`/`amd64` and `aarch64`/`arm64` host identities through the canonical contract.
2. Add Debian 13 and both architectures to managed support while preserving systemd and privilege requirements.
3. Parameterize positive tests for all ten target pairs and negative tests for unsupported distro/version/arch/systemd states.
4. Improve text and JSON diagnostics with detected values, supported matrix, safe `next_actions`, and no secrets/telemetry.
5. Verify existing x86_64 behavior and exit codes remain compatible.

## Acceptance criteria
- [x] All ten required distro/architecture pairs are accepted when systemd and other prerequisites are present.
- [x] Unsupported OS, version, architecture, or missing systemd fails before mutation.
- [x] Errors include detected OS/version/architecture/systemd and a concrete next action.
- [x] JSON diagnostics use stable `code`, `message`, `detail`, and `next_actions` fields without secrets.
- [x] Windows/macOS clearly report that managed commands are Linux/systemd-only and point portable users to pipx lifecycle commands.

## Verification plan
| Check | Command or method | Expected result |
|---|---|---|
| Targeted tests | `python -m pytest -q tests/test_management_planning.py tests/test_management_setup.py tests/test_management_service.py` | Full matrix and failure cases pass |
| Type/lint/build | `mypy xferry && ruff check xferry/management tests/test_management_planning.py tests/test_management_setup.py tests/test_management_service.py` | Clean |
| Manual/static review | Inspect representative text/JSON outputs | Actionable, stable, and secret-redacted |

## Suggested subagents
- `python-pro` - host normalization and typed result changes.
- `qa-expert` - matrix reduction/coverage and negative cases.
- `dx-optimizer` - actionable diagnostics and OS-specific lifecycle language.
- `reviewer` - ensure preflight remains mutation-free.

## Risks and rollback
- Risk: accepting a host before matching executable support exists.
- Rollback: keep the new detection tests but feature-gate acceptance until STAGE-006 closes; do not publish managed support prematurely.

## Completion notes
- Closed on 2026-09-29 after adding Debian 13 and canonical x86_64/aarch64 acceptance across the five supported distro releases.
- Unsupported host dimensions retain exit code 4 and stop before the setup lock or managed writes; text and JSON output now carry bounded detected facts, the supported matrix, and local next actions.
- Doctor and non-Linux command diagnostics expose stable `code`, `message`, `detail`, and `next_actions` fields without credentials, paths, telemetry, or backend imports; Windows/macOS point to pipx install/upgrade/uninstall.
- Verification passed 309 stage-targeted tests, 381 expanded management/CLI tests, strict mypy for all 69 source files, scoped Ruff lint/format, all 3,265 repository tests, direct representative-output review, and independent subagent review.
- Native arm64/systemd execution remains the optional STAGE-006 artifact smoke concern; injected host/preflight coverage proves this stage's host contract without publishing or building installers.
- Report: `stage-reports/STAGE-005-20260929-144237.md`.
