# Implementation Plan
_Generated: 2026-09-28 13:48:43 MSK_

## Source analysis

- `codex-analysis/20260928-131617/project-analysis-report.md`
- `codex-analysis/20260928-131617/agent-reports/*.md`

## Strategy

The plan is risk-first and journey-oriented. It restores green gates before changing release policy, establishes one platform and trust contract before adding architectures, proves consumer artifacts before enabling publishers, and keeps all production publication unreachable until the final activation stage. Portable CLI, managed Linux, and container journeys share release identity but remain separate lifecycle contracts.

STAGE-010, STAGE-011, and STAGE-012 are parallelizable after STAGE-009. All other dependencies are explicit below.

## Stage overview

| Stage | Priority | Status | Title | Depends on | Main verification | Expected files |
|---|---|---|---|---|---|---|
| STAGE-001 | MEDIUM | CLOSED | Restore strict typing baseline | None | `mypy xferry`; focused handler tests | `xferry/handlers/notepad.py`, tests if needed |
| STAGE-002 | MEDIUM | CLOSED | Patch audited CI toolchain pins | None | pip-audit, docs build, toolchain checks | `constraints/ci.txt`, dependency metadata/tests |
| STAGE-003 | HIGH | CLOSED | Adopt controlled distribution policy and guards | 001, 002 | ADR/docs guard/deployment policy tests | ADR, SECURITY/threat model, guard tools/tests |
| STAGE-004 | HIGH | CLOSED | Centralize release platform and manifest contracts | 003 | model/parser/state compatibility tests | management release modules, builder contract, tests |
| STAGE-005 | HIGH | CLOSED | Add complete managed host support matrix | 004 | planning/setup tests for 10 distro/arch pairs | platform/planning/setup/diagnostics/tests |
| STAGE-006 | HIGH | CLOSED | Build and verify multi-arch SCIE installers | 004, 005 | x86_64/aarch64 bundle and base-image smoke | SCIE builder, installer template, CI/tests |
| STAGE-007 | HIGH | CLOSED | Establish signed release metadata trust | 004, 006 | signature/tamper/key-rotation/update tests | signing/verifier code, manifest builder, threat model/tests |
| STAGE-008 | HIGH | CLOSED | Prove portable packaged CLI journeys | 003 | built-wheel/pipx-style OS/Python matrix | CLI, artifact verifier, CI/tests |
| STAGE-009 | HIGH | CLOSED | Create build-once candidate promotion pipeline | 006, 007, 008 | preflight, promoted artifact identity, no-publish guards | release workflow/tools/tests |
| STAGE-010 | HIGH | PARTIALLY_CLOSED | Add PyPI Trusted Publishing path | 008, 009 | TestPyPI/pipx exact-version smoke | release workflow, package metadata/tests |
| STAGE-011 | HIGH | CLOSED | Add multi-arch GHCR publication path | 009 | exact OCI promotion; native amd64+arm64 pull/smoke; registry/SBOM/SLSA verification | GHCR workflow, candidate identity, promotion/verification tooling/tests |
| STAGE-012 | HIGH | CLOSED | Publish signed GitHub Release assets | 007, 009 | exact draft asset set; protected signing; downloaded signature/tamper verification | release workflow, release tools/tests |
| STAGE-013 | HIGH | CLOSED | Expose safe managed update lifecycle | 005, 007, 012 | CLI normal/failure/recovery tests | management CLI/releases/service/i18n/tests |
| STAGE-014 | MEDIUM | OPEN | Publish canonical journey documentation | 010, 011, 012, 013 | docs guards, generated contracts, strict MkDocs | README/docs/examples/MkDocs/guards/tests |
| STAGE-015 | HIGH | OPEN | Activate and rehearse production release | 010, 011, 012, 013, 014 | protected tag release and post-publish matrix | release orchestration, runbooks, changelog |

## How to close a stage

Use:

```text
$close-plan-stage STAGE-001
$close-plan-stage next
$close-plan-stage STAGE-003 --no-subagents
```

## Definition of closed

A stage is CLOSED only when all acceptance criteria are met, verification is completed, and `stage-status.md` plus a stage report are updated. Production publication is not authorized until STAGE-015.
