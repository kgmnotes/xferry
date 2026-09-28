# STAGE-006 - Build and verify multi-arch SCIE installers

## Status
OPEN

## Priority
HIGH

## Source findings
- `codex-analysis/20260928-131617/project-analysis-report.md` - F-004 and F-012: current bundle/installer is x86_64-only and installer authenticity must be designed before public use.
- `agent-reports/devops-engineer.md` - current deterministic SCIE and base-image smoke provide a strong starting point.
- `agent-reports/qa-expert.md` - managed acceptance must cover both architectures and every target distro.

## Goal
Produce deterministic, correctly named SCIE candidates and installer assets for `linux-x86_64` and `linux-aarch64`, with complete non-public verification across the target distro matrix.

## Non-goals
- Publish assets or add GitHub write permissions.
- Add signing private keys or enable root-run remote update.
- Build Windows/macOS SCIE artifacts; portable users use PyPI/pipx.

## Scope
### Likely files to inspect
- `tools/build_scie_release.py` - current PEX/SCIE build and manifest generation.
- `packaging/install.sh.in` - OS/arch validation and download/install behavior.
- `.github/workflows/ci.yml` and `.github/workflows/release.yml` - existing SCIE lanes.
- `tests/test_scie_release.py`, `tests/test_deployment_artifacts.py` - bundle/installer contracts.
- `xferry/management/data/xferry.service` - installed executable assumptions.

### Likely files to change
- `tools/build_scie_release.py` - explicit canonical platform target and deterministic per-platform output.
- `packaging/install.sh.in` - generated multi-arch selection/validation and safe staged execution.
- CI/release verification lanes with no external publication.
- SCIE, installer, and deployment tests.

### Files that must not be changed
- PyPI/GHCR publisher configuration - later stages.
- Public quick-start docs - artifacts are not public yet.
- Runtime server/handler modules.

## Dependencies
- Depends on: STAGE-004, STAGE-005
- Blocks: STAGE-007, STAGE-009

## Implementation steps
1. Add an explicit canonical platform argument/matrix to the SCIE builder and generate deterministic `xferry-{version}-{platform}` assets.
2. Render installers from canonical release data so architecture/distro messages and artifact selection cannot drift.
3. Verify executable size/SHA-256, manifest v2, canonical CLI, and no-host-Python execution for both platforms.
4. Add base-image smoke for Ubuntu 22.04/24.04/26.04 and Debian 12/13; use native arm64 for final evidence when emulation cannot faithfully test the target.
5. Exercise install/setup/status/doctor/rollback/uninstall in isolated managed roots, with wrong-platform and corrupt-payload rejection.

## Acceptance criteria
- [ ] Builder emits exactly one valid candidate per requested platform with deterministic names and manifest metadata.
- [ ] Installer selects only the host-matching artifact and rejects unsupported/mismatched platforms before mutation.
- [ ] Both candidates run `run --version`, `--help`, and `run --check-config` without host Python.
- [ ] Every target distro/architecture combination has automated smoke evidence; emulated versus native coverage is explicitly recorded.
- [ ] Corrupt, truncated, wrong-name, wrong-platform, and unsupported-schema artifacts fail closed.
- [ ] No asset is uploaded to a public registry or Release in this stage.

## Verification plan
| Check | Command or method | Expected result |
|---|---|---|
| Targeted tests | `python -m pytest -q tests/test_scie_release.py tests/test_deployment_artifacts.py tests/test_management_planning.py` | All pass |
| Build | `python tools/build_scie_release.py --platform linux-x86_64 --output-dir dist/scie-x86_64` and corresponding `linux-aarch64` command | Deterministic valid bundles |
| Type/lint/build | `ruff check tools/build_scie_release.py tests/test_scie_release.py && ruff format --check tools/build_scie_release.py tests/test_scie_release.py` | Clean |
| Integration | CI matrix runs bundle on all required base images/architectures | All supported pairs pass; unsupported pairs fail early |

## Suggested subagents
- `build-engineer` - deterministic dual-architecture SCIE production.
- `devops-engineer` - CI matrix and artifact handling.
- `qa-expert` - normal/failure/recovery matrix design.
- `security-auditor` - installer pre-mutation and unsafe-input review.

## Risks and rollback
- Risk: cross-building succeeds but produces an executable that fails on native arm64 or a target libc/base.
- Rollback: keep publication disabled and remove the unsupported candidate; do not claim support until native evidence passes.

## Completion notes
Filled by `close-plan-stage`.
