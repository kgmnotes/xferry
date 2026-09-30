# STAGE-013 - Expose safe managed update lifecycle

## Status
OPEN

## Priority
HIGH

## Source findings
- `codex-analysis/20260928-131617/project-analysis-report.md` - F-003, F-007, and F-014: defensive internal updater exists, but public command/trust/UX do not.
- `agent-reports/qa-expert.md` - CLI acceptance must cover help, JSON, dry run, non-Linux rejection, exact version, and recovery.
- `agent-reports/dx-optimizer.md` - portable pipx upgrades and managed Linux updates must be clearly separated.

## Goal
Expose an explicit managed-Linux-only `xferry update --to VERSION` command that verifies signed immutable release metadata, supports dry-run/JSON, health-gates activation, and automatically restores the prior release on failure.

## Non-goals
- Default to mutable/latest-channel updates.
- Make `xferry update` manage pipx installations on Windows/macOS/Linux.
- Replace local `xferry rollback` or weaken root/lock/config/health protections.
- Activate a production release trigger.

## Scope
### Likely files to inspect
- `xferry/management/cli.py`, `i18n.py` - command parsing/help/result output.
- `xferry/management/releases.py`, `managed_state.py` - verified update/rollback behavior.
- `xferry/management/service.py` - status/doctor/health and JSON redaction.
- `tests/test_management_cli.py`, `tests/test_management_releases.py`, `tests/test_management_service.py`, `tests/test_scie_release.py`.

### Likely files to change
- Management CLI/i18n/release/service modules above.
- CLI, release, managed-state, service, and SCIE integration tests.
- Generated CLI contract data if the project maintains it.

### Files that must not be changed
- Portable `pipx upgrade/uninstall` ownership semantics.
- Signature bypass/default-off switches for production code.
- Runtime server request protocol and handler behavior.
- Public user docs until STAGE-014.

## Dependencies
- Depends on: STAGE-005, STAGE-007, STAGE-012
- Blocks: STAGE-014, STAGE-015

## Implementation steps
1. Add `update` parsing/help with required `--to X.Y.Z`, optional `--dry-run` and `--json`, and explicit managed-Linux/root scope.
2. Enable remote release access only through this command after managed-install detection; portable installs receive a pipx next action.
3. Fetch versioned manifest/signature/assets, verify publisher signature and all existing constraints, then plan changes without mutation for dry-run.
4. Preserve lock, config validation, service-state capture, restart, health gate, restore, release retention, and rollback eligibility.
5. Return stable text/JSON results with `code`, `message`, `detail`, before/target/active versions, rollback result, and redacted `next_actions`.
6. Test normal, no-op, non-root, non-managed, wrong OS/arch, signature/hash/size error, timeout, config failure, restart failure, unhealthy candidate, restore failure, and concurrent update.

## Acceptance criteria
- [ ] `xferry update --help` clearly states managed Linux only and requires explicit `--to VERSION`.
- [ ] `--dry-run` performs no filesystem/service mutation and reports the complete plan.
- [ ] Portable installations are directed to `pipx upgrade xferry`; they never mutate managed paths.
- [ ] Unsigned, untrusted, wrong-version/platform, downgraded, corrupt, or redirected-unsafe releases fail before activation.
- [ ] Successful update health-checks the exact target and preserves a rollback candidate.
- [ ] Failed config/start/health restores the previous release and reports the recovery outcome.
- [ ] JSON output is stable, actionable, telemetry-free, and secret-redacted.

## Verification plan
| Check | Command or method | Expected result |
|---|---|---|
| Targeted tests | `python -m pytest -q tests/test_management_cli.py tests/test_management_releases.py tests/test_management_service.py tests/test_scie_release.py` | Normal/failure/recovery cases pass |
| Type/lint/build | `mypy xferry && ruff check xferry/management tests/test_management_cli.py tests/test_management_releases.py` | Clean |
| Staging integration | Install previous SCIE, update to exact signed rehearsal version, verify health, then rollback/uninstall on both architectures | Lifecycle succeeds and state remains valid |
| Manual/static review | Trace command-to-manager enablement and pre-mutation checks | No bypass or portable-path mutation |

## Suggested subagents
- `cli-developer` - command/JSON/help contract.
- `python-pro` - release-manager integration.
- `qa-expert` - lifecycle failure/recovery matrix.
- `security-auditor` - signature and privilege/pre-mutation review.

## Risks and rollback
- Risk: a root-run command installs untrusted code, corrupts managed state, or cannot restore service.
- Rollback: keep production caller inactive, use the existing local rollback path, restore the prior symlink/state/service, and remove the public command if trust invariants cannot be met.

## Completion notes
Filled by `close-plan-stage`.
