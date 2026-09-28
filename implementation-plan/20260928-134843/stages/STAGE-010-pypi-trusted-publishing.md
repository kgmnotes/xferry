# STAGE-010 - Add PyPI Trusted Publishing path

## Status
OPEN

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
1. Reserve/configure the TestPyPI and PyPI project/publisher identities using the agreed namespace and exact GitHub repository/workflow/environment mapping.
2. Add a job that downloads and verifies promoted wheel/sdist, grants only `id-token: write` plus required read access, and invokes a SHA-pinned official publisher.
3. Keep production job unreachable from ordinary/manual branch events until STAGE-015; use a separate explicit staging rehearsal path.
4. Publish a unique TestPyPI rehearsal version, then install that exact version with pipx on Windows/macOS/Linux, using production PyPI only for dependencies if needed.
5. Verify metadata, console entry point, imports, help/version/config, and no source-tree dependency.

## Acceptance criteria
- [ ] No static PyPI credential exists in repository or workflow configuration.
- [ ] Publish job has job-scoped `id-token: write`, consumes downloaded candidates, and contains no build command.
- [ ] Trusted Publisher mapping is documented and independently confirmed by the owner.
- [ ] Exact promoted wheel/sdist digests match the files accepted by TestPyPI.
- [ ] Exact-version pipx install and portable smoke pass on Windows, macOS, and Linux.
- [ ] Production PyPI publication remains inactive until STAGE-015.

## Verification plan
| Check | Command or method | Expected result |
|---|---|---|
| Targeted tests | `python -m pytest -q tests/test_deployment_artifacts.py tests/test_cli.py tests/test_public_surface.py` | Policy and CLI contracts pass |
| Artifact identity | Compare candidate digest inventory with files submitted to TestPyPI | Exact match |
| Consumer integration | `pipx install --index-url https://test.pypi.org/simple/ --pip-args='--extra-index-url https://pypi.org/simple' 'xferry==X.Y.Z...'` on three OSes | Install and smoke succeed |
| Security/static review | Inspect job permissions, environment, action SHA, and absence of token secrets | Least privilege/OIDC only |

## Suggested subagents
- `devops-engineer` - Trusted Publishing workflow.
- `dependency-manager` - package metadata/index resolution review.
- `qa-expert` - TestPyPI and cross-platform pipx acceptance.
- `security-auditor` - OIDC mapping and permission review.

## Risks and rollback
- Risk: publishing an incorrect version is irreversible; TestPyPI dependency resolution may differ from production.
- Rollback: use unique rehearsal versions, never reuse a version, keep production inactive, and discard/yank only the staging artifact if needed.

## Completion notes
Filled by `close-plan-stage`.
