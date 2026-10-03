# STAGE-010 - Add PyPI Trusted Publishing path

## Status
PARTIALLY_CLOSED

## Priority
HIGH

## Source findings
- `codex-analysis/20260928-131617/project-analysis-report.md` - F-002, F-005, and F-006: package metadata exists but no safe publisher or consumer path does.
- `agent-reports/devops-engineer.md` and `qa-expert.md` - use OIDC Trusted Publishing and exact promoted artifacts, followed by pipx smoke.
- Context7/PyPA check - standalone CLI installation should use pipx and production publication should be environment-gated.

## Goal
Implement an initially non-production-activated PyPI publisher that uses Trusted Publishing to upload the exact promoted wheel/sdist and proves exact-version pipx installation through TestPyPI/staging.

## Non-goals
- Store a PyPI API token.
- Rebuild wheel/sdist in the publish job.
- Activate production tag publication before STAGE-015.
- Publish managed SCIE or container assets to PyPI.

## Scope
### Likely files to inspect
- Candidate workflow/artifacts from STAGE-009.
- `pyproject.toml` - name, metadata, version, URLs, classifiers.
- `tools/verify_python_artifacts.py` - consumer checks.
- Release/deployment policy tests and docs guards.

### Likely files to change
- A reusable/protected PyPI publish job in `.github/workflows/`.
- Package metadata only where TestPyPI/PyPI validation identifies a real issue.
- Deployment policy tests and post-publish pipx smoke workflow.

### Files that must not be changed
- Any tracked/static PyPI token or credential.
- Candidate artifact bytes after STAGE-009 verification.
- Production `v*` trigger - STAGE-015.

## Dependencies
- Depends on: STAGE-008, STAGE-009
- Blocks: STAGE-014, STAGE-015

## Implementation steps
1. Document the exact publisher identity and obtain owner configuration/confirmation for TestPyPI only. Production PyPI configuration/publication is not authorized by this invocation.
2. Add a job that downloads and verifies promoted wheel/sdist, grants only `id-token: write` plus required read access, and invokes a SHA-pinned official publisher.
3. Keep production job unreachable from ordinary/manual branch events until STAGE-015; use a separate explicit staging rehearsal path.
4. Publish the preserved STAGE-009 `xferry==0.1.0` wheel/sdist to TestPyPI without rebuilding or relabeling. Download and verify both accepted files from TestPyPI, then install the verified local wheel with actual pipx on Windows/macOS/Linux, using PyPI only for dependencies. A conflicting existing version requires an owner decision, not a new identity.
5. Verify metadata, console entry point, imports, help/version/config, and no source-tree dependency.

## Acceptance criteria
- [x] No static PyPI credential exists in repository or workflow configuration.
- [x] Publish job has job-scoped `id-token: write`, consumes downloaded candidates, and contains no build command.
- [ ] Trusted Publisher mapping is documented and independently confirmed by the owner.
- [ ] Exact promoted wheel/sdist digests match the files accepted by TestPyPI.
- [ ] Exact-version pipx install and portable smoke pass on Windows, macOS, and Linux.
- [x] Production PyPI publication remains inactive until STAGE-015.

## Verification plan
| Check | Command or method | Expected result |
|---|---|---|
| Targeted tests | `python -m pytest -q tests/test_deployment_artifacts.py tests/test_cli.py tests/test_public_surface.py` | Policy and CLI contracts pass |
| Artifact identity | Compare candidate digest inventory with files submitted to TestPyPI | Exact match |
| Consumer integration | `python tools/testpypi_publish.py smoke --download-dir <fresh-absolute-download-dir> --fresh-root <fresh-absolute-pipx-root>` on three OSes | Install and smoke succeed |
| Security/static review | Inspect job permissions, environment, action SHA, and absence of token secrets | Least privilege/OIDC only |

## Suggested subagents
- `devops-engineer` - Trusted Publishing workflow.
- `dependency-manager` - package metadata/index resolution review.
- `qa-expert` - TestPyPI and cross-platform pipx acceptance.
- `security-auditor` - OIDC mapping and permission review.

## Risks and rollback
- Risk: TestPyPI uploads are immutable; the fixed 0.1.0 candidate cannot be renamed to avoid a conflict. Mixed-index resolution could install another project artifact, so the verified local XFerry wheel is installed with PyPI-only dependencies.
- Rollback: keep production inactive; stop on namespace/file conflicts or expired candidate artifacts. Any deletion/yanking or candidate replacement needs separate owner authorization; do not rebuild/relabel this candidate.

## Completion notes
- Attempt: 2026-09-30 16:13:00 +0300; result PARTIALLY_CLOSED. Report: `stage-reports/STAGE-010-20260930-125252.md`; operator instructions: `stage-reports/STAGE-010-20260930-125252-operator.md`.
- Added separate manual `testpypi.yml`, fixed candidate identity manifest, authenticated wheel/sdist preparation, TestPyPI accepted-byte verification, three-OS actual pipx smoke, and staging-specific policy regressions. `release.yml` and STAGE-009 candidate bytes were preserved.
- Final verification: 501 focused tests and all 3,533 repository tests passed, together with strict mypy, Ruff lint/format (176 files), compile, actionlint, package-content validation, release preflight, stale-doc guard, and two independent reviews. The second review exposed a missing-top-level-permissions guard gap; it was reproduced and fixed test-first. Actual local Linux pipx smoke passed against the preserved candidate wheel; this does not establish TestPyPI or hosted OS acceptance.
- External evidence: the protected `testpypi` Environment now exists with no secrets, exact branch policy `codex/stage-010-testpypi-rehearsal`, reviewers `kgmnotes` and `gkumurzhi`, self-review prevention, and administrator bypass disabled. TestPyPI `xferry/0.1.0` still returns 404; publisher mapping has no owner confirmation, the workflow is not registered on the default branch, and no upload or hosted OS run occurred.
- Production custody prerequisite: `gkumurzhi` accepted explicit repository `write` access and is now an eligible `production-release` reviewer alongside `kgmnotes`; self-review remains prevented and administrator bypass disabled. Deployment refs remain unrestricted, so STAGE-012 must not consume that environment until its exact reviewed rehearsal ref is selected and allowlisted.
- No production PyPI/tag/public Release/docs activation or STAGE-015 work occurred; no signing secret was read or exposed.
- Attempt: 2026-10-03 12:20:24 +0300; result PARTIALLY_CLOSED. Fresh run `37111932008` at `f1361d07442e8e5228c2442162a865ca713d2d38` proved workflow registration, exact OIDC claims, and a valid protected `testpypi` approval by `gkumurzhi`.
- The authenticated handoff artifact `11269958516` has digest `sha256:69a2b778d8ad3c9c84c6f7dcd32ef87f04fe6b70e1a4ae19f78fb5a1a2e3da25` and expires `2026-10-04T09:06:43Z`; the original candidate artifact `11095067140` remains valid through `2026-10-14T12:11:38Z`.
- TestPyPI rejected the otherwise valid OIDC token with `invalid-publisher: valid token, but no corresponding publisher`. The exact missing pending publisher mapping is project `xferry`, owner `kgmnotes`, repository `xferry`, workflow `testpypi.yml`, environment `testpypi`. TestPyPI remains 404, no distribution was uploaded, and the three OS pipx jobs correctly skipped.
- After an authorized TestPyPI account owner creates that mapping, rerun the failed jobs before the handoff artifact expires, obtain a fresh independent environment approval, then verify the accepted wheel/sdist bytes and all three OS receipts. Report: `stage-reports/STAGE-010-20261003-122024.md`.
