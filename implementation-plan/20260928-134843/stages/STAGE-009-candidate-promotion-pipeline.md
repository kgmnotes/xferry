# STAGE-009 - Create build-once candidate promotion pipeline

## Status
CLOSED

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
- [x] Preflight rejects malformed/mismatched tag, version, changelog, manifest, or filename data.
- [x] Candidate jobs run only after normal CI/security/docs gates pass.
- [x] One digest inventory covers every promoted file and OCI manifest/platform image.
- [x] Downloaded workflow artifacts match producer digests byte-for-byte.
- [x] No downstream/publisher job rebuilds candidates.
- [x] Workflow/actions are commit-SHA pinned, checkout credentials are not persisted, and default permissions remain read-only.
- [x] No external package, registry, or Release write occurs in this stage.

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
- Implemented strict source/changelog preflight; reusable source/security/docs gates; once-built wheel/sdist; exact-wheel native SCIE builders and image Dockerfile; OCI SBOM/provenance export; safe producer archive transfer by immutable artifact ID and SHA256; complete canonical file/platform digest inventory and downstream revalidation.
- Local verification covers adversarial release/archive/OCI metadata fixtures, 458 focused and 3,476 full repository tests, real wheel/sdist offline installs, exact-wheel native x86_64 SCIE and all five Linux base probes, native OCI export/load/hardened lifecycle, and byte/mode equality for 26 real native candidate files. See the report for final command counts and independent review.
- Hosted failure remediation normalizes only BuildKit's empty `oci/ingest` staging directory and rejects files, non-empty/nested directories, direct links, and symlinked candidate/OCI parents before deletion. The final remediation passed 180 focused and all 3,485 repository tests plus strict mypy, repository Ruff, actionlint, compile, collection, and toolchain guards.
- Manual run `36712344792` on public-tree SHA `40ac9bc031aa28b9adc2765857a8926f522e4005` passed source/security/docs gates, all five Python quality jobs, both native SCIE jobs, all nine Ubuntu/macOS/Windows portable consumers, one multiarch OCI producer, both native OCI consumers, the collector, and the final download verifier.
- Final artifact `11095067140` was downloaded independently through the Artifact API. Its 254,412,956-byte ZIP matched API SHA256 `97cad6b7fc6ca848de441930162d842f05d004659f14a5fd40e2b89995c7e878`; inner archive SHA256 `c3746592f16699fafe062e5bf245853f5058a8bdff70193ddf1c112e84ac8517` and inventory SHA256 `b6e86089660bff44daf856c2dc18ac4a310b79c40dde949f3aa9817894a99189` verified exact tag, source SHA, run ID, bytes, modes, and OCI platform graph.
- The feature PR still intentionally trips the unchanged public-surface policy on tracked internal plan/analysis inputs. The public rehearsal tree excludes those inputs and passed the same guard; no guard was weakened. No package-index, registry, or GitHub Release publication/write occurred, and no production Environment or private key was accessed.
- Result: CLOSED. Report: `stage-reports/STAGE-009-20260930-152200.md`.
