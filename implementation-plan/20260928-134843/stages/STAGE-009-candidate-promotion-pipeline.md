# STAGE-009 - Create build-once candidate promotion pipeline

## Status
OPEN

## Priority
HIGH

## Source findings
- `codex-analysis/20260928-131617/project-analysis-report.md` - F-002 and F-010: release outputs are discarded and release identity is incomplete.
- `agent-reports/devops-engineer.md` - publishers must consume exact promoted artifacts and never rebuild.
- `agent-reports/qa-expert.md` and `security-auditor.md` - tag/version/changelog, action pin, permission, and no-branch-publication invariants are release blocking.

## Goal
Turn release verification into a non-publishing candidate pipeline that checks release identity, builds each candidate once, verifies it, and preserves an immutable digest-indexed artifact set for downstream protected publishers.

## Non-goals
- Write to PyPI, GHCR, or GitHub Releases.
- Activate a `v*` production trigger.
- Add production write permissions or signing private-key access.

## Scope
### Likely files to inspect
- `.github/workflows/release.yml` - current verification lanes.
- `.github/workflows/ci.yml` and `security.yml` - required quality gates.
- `tools/verify_python_artifacts.py`, `verify_docker_image.py`, `docker_image_smoke.py`, `build_scie_release.py` - candidate verification.
- `xferry/config.py`, `CHANGELOG.md` - release identity.
- Deployment/toolchain policy tests.

### Likely files to change
- `.github/workflows/release.yml` and/or a non-public reusable candidate workflow.
- `tools/check_release_preflight.py` (new or equivalent) plus tests.
- `tests/test_deployment_artifacts.py`, toolchain pin checks, and release fixtures.

### Files that must not be changed
- Production PyPI/GHCR/GitHub Release publisher jobs - STAGE-010/011/012.
- Production tag trigger - STAGE-015.
- User quick-start documentation.

## Dependencies
- Depends on: STAGE-006, STAGE-007, STAGE-008
- Blocks: STAGE-010, STAGE-011, STAGE-012

## Implementation steps
1. Add a release preflight that requires exact `vX.Y.Z` syntax and equality among requested tag, source version, changelog entry, manifest version, and artifact filenames.
2. Run all required quality/security/docs gates before candidate construction.
3. Build wheel/sdist, both SCIE bundles/installers, canonical unsigned manifest bytes, checksums, dependency SBOMs, and multi-arch OCI candidate layout once.
4. Verify each candidate, create a machine-readable digest inventory, then upload exact outputs with SHA-pinned artifact actions.
5. Add downstream download-and-verify tests proving byte/digest identity and absence of rebuild commands.
6. Keep the workflow manual/reusable and externally non-publishing until STAGE-015.

## Acceptance criteria
- [ ] Preflight rejects malformed/mismatched tag, version, changelog, manifest, or filename data.
- [ ] Candidate jobs run only after normal CI/security/docs gates pass.
- [ ] One digest inventory covers every promoted file and OCI manifest/platform image.
- [ ] Downloaded workflow artifacts match producer digests byte-for-byte.
- [ ] No downstream/publisher job rebuilds candidates.
- [ ] Workflow/actions are commit-SHA pinned, checkout credentials are not persisted, and default permissions remain read-only.
- [ ] No external package, registry, or Release write occurs in this stage.

## Verification plan
| Check | Command or method | Expected result |
|---|---|---|
| Targeted tests | `python -m pytest -q tests/test_deployment_artifacts.py tests/test_scie_release.py tests/test_docker_image_smoke.py` plus preflight tests | All pass |
| Preflight | Run the new checker against matching and intentionally mismatched `vX.Y.Z` fixtures | Match passes; every mismatch fails |
| Workflow evidence | Manual candidate run; download artifacts and verify digest inventory | Exact identity; no external publication |
| Type/lint/build | `ruff check tools .github/workflows tests && python tools/check_toolchain_pins.py` where supported by existing tooling | Clean/pinned |

## Suggested subagents
- `devops-engineer` - candidate workflow and artifact graph.
- `build-engineer` - deterministic artifact and OCI layout production.
- `security-auditor` - permission/action/no-rebuild review.
- `qa-expert` - identity and negative preflight tests.

## Risks and rollback
- Risk: workflow artifacts are incomplete, mutable within the run, or too large; OCI promotion may accidentally rebuild.
- Rollback: retain the existing verification-only workflow and keep all publisher stages disabled until digest identity is proven.

## Completion notes
Filled by `close-plan-stage`.
