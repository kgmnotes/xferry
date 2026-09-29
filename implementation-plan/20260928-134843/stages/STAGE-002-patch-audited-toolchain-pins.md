# STAGE-002 - Patch audited CI toolchain pins

## Status
CLOSED

## Priority
MEDIUM

## Source findings
- `codex-analysis/20260928-131617/project-analysis-report.md` - F-009: two known advisories affect pinned CI/docs tooling.
- `agent-reports/security-auditor.md` - `mkdocs-material==9.7.6` and `pip==26.1.2` run in CI/release contexts and have fixed versions available.

## Goal
Refresh the pinned toolchain so strict dependency audit, documentation, and existing quality gates pass with `mkdocs-material>=9.7.7` and `pip>=26.2`.

## Non-goals
- Upgrade unrelated runtime dependencies merely because newer versions exist.
- Relax `pip-audit --strict` or remove deterministic pins.
- Change documentation content or release behavior.

## Scope
### Likely files to inspect
- `constraints/ci.txt` - exact dependency graph.
- `pyproject.toml` - declared docs/tooling ranges.
- `tools/check_dependency_constraints.py` and `tools/check_toolchain_pins.py` - pin invariants.
- `.github/workflows/security.yml` and `.github/workflows/ci.yml` - consuming jobs.

### Likely files to change
- `constraints/ci.txt` - audited direct and any required transitive pin refresh.
- Dependency constraint tests or metadata only if the refreshed graph requires it.

### Files that must not be changed
- `xferry/**` - no runtime feature change is required.
- `.github/workflows/security.yml` - do not bypass the audit.
- `pyproject.toml` - unless a declared lower bound is demonstrably incompatible with the secure resolved graph.

## Dependencies
- Depends on: `None`
- Blocks: STAGE-003, STAGE-009

## Implementation steps
1. Re-resolve the constrained toolchain in a clean environment, changing only pins required for fixed versions and compatibility.
2. Review the full constraint diff for unexpected runtime or build-system movement.
3. Run dependency completeness, toolchain pin, pip-audit, and documentation gates.
4. Record the advisory IDs and fixed versions in the stage completion report.

## Acceptance criteria
- [ ] `mkdocs-material` is pinned to 9.7.7 or newer and `pip` to 26.2 or newer.
- [ ] Strict pip-audit reports no known vulnerabilities for the constrained graph.
- [ ] Constraint completeness and toolchain pin contracts pass.
- [ ] Documentation render/sync/staleness and strict MkDocs build remain green.
- [ ] Unrelated runtime pins are unchanged unless justified in completion notes.

## Verification plan
| Check | Command or method | Expected result |
|---|---|---|
| Targeted tests | `python tools/check_dependency_constraints.py --constraints constraints/ci.txt && python tools/check_toolchain_pins.py` | Both pass |
| Type/lint/build | `python -m pip_audit --strict --no-deps -r constraints/ci.txt` | No vulnerabilities, nonzero failures absent |
| Docs regression | `python tools/render_settings.py --check && python tools/render_contracts.py --check && python tools/sync_docs.py --check && python tools/check_stale_docs.py && mkdocs build --strict` | All pass |
| Manual/static review | Review `git diff -- constraints/ci.txt` | Only necessary, compatible pin changes |

## Suggested subagents
- `dependency-manager` - resolve and explain the minimal secure pin update.
- `security-auditor` - confirm advisories are remediated without audit suppression.
- `reviewer` - inspect constraint graph drift.

## Risks and rollback
- Risk: transitive pin changes break Python 3.10-3.14 or docs rendering.
- Rollback: revert the constraint refresh, then resolve a narrower compatible fixed graph; never restore the vulnerable graph for release use.

## Completion notes
- Closed: 2026-09-29 13:13:40 +0300.
- Updated only `constraints/ci.txt`: `mkdocs-material==9.7.6` to `9.7.7` and `pip==26.1.2` to `26.2`. No runtime or transitive pin changed.
- Remediated `PYSEC-2026-3864` (fixed in `mkdocs-material 9.7.7`) and `PYSEC-2026-3721` (fixed in `pip 26.2`); the vulnerable graph was reproduced before the change as the negative control.
- A clean Python 3.12 constrained environment resolved the project toolchain without conflict. The new package metadata covers the declared Python 3.10-3.14 range, while the retained CI matrix supplies cross-version execution.
- Strict pip-audit, dependency completeness, toolchain pin invariants, all render/sync/staleness checks, strict MkDocs, scoped Ruff, and the full 3,171-test suite passed.
- Read-only dependency and security subagents independently confirmed the minimal diff, unchanged audit/workflow strictness, and closure readiness with no blocking findings.
- Report: `../stage-reports/STAGE-002-20260929-125932.md`.
