# STAGE-012 - Publish signed GitHub Release assets

## Status
OPEN

## Priority
HIGH

## Source findings
- `codex-analysis/20260928-131617/project-analysis-report.md` - F-002, F-003, F-010, and F-012: exact promoted assets and client-verifiable metadata are absent.
- `agent-reports/security-auditor.md` - GitHub Release must carry signed manifests and must not be the sole unverified trust domain.
- `agent-reports/devops-engineer.md` - publish SCIE/installers/manifests/checksums/SBOMs and source/workflow identity from downloaded candidates.

## Goal
Implement an initially non-production-activated GitHub Release publisher that signs the already-built canonical manifest, uploads the complete exact asset set to a draft/staging Release, and proves client verification without rebuilding.

## Non-goals
- Expose managed update to end users (STAGE-013).
- Use `releases/latest` as the v1 update trust anchor.
- Commit or log private signing material.
- Activate the production tag caller before STAGE-015.

## Scope
### Likely files to inspect
- Candidate digest inventory and signing tooling from STAGE-007/009.
- `.github/workflows/release.yml` and deployment policy tests.
- `xferry/management/releases.py` expected URL/asset layout.
- Release/changelog metadata and SBOM outputs.

### Likely files to change
- A protected GitHub Release publish job under `.github/workflows/`.
- Release asset assembly/verification tooling and tests.
- SECURITY/release operator notes for signing-key handling if not already complete.

### Files that must not be changed
- Tracked private key material or real secret fixtures.
- Candidate wheel/SCIE/installer bytes.
- Production tag trigger - STAGE-015.

## Dependencies
- Depends on: STAGE-007, STAGE-009
- Blocks: STAGE-013, STAGE-014, STAGE-015

## Implementation steps
1. Define the complete Release asset inventory: both SCIE binaries, per-platform installers if used, canonical manifest, detached signature, checksums, SBOMs, digest inventory, provenance/attestation references, and release metadata.
2. Add a protected job with `contents: write` only where required; download and re-verify candidate artifacts.
3. Load signing material only inside the protected job, sign the exact canonical manifest bytes, record key ID, and scrub temporary material.
4. Create a draft or non-production rehearsal Release for an immutable rehearsal tag and upload exact assets without overwriting/rebuilding.
5. Download assets through the same URL patterns clients will use and verify signature, size/hash, platform selection, and source/workflow metadata.

## Acceptance criteria
- [ ] Rehearsal Release contains the complete, uniquely named asset inventory and no unexpected files.
- [ ] All unsigned candidate files match the STAGE-009 digest inventory exactly.
- [ ] Manifest signature verifies with the shipped client key ring and fails after any mutation.
- [ ] Publish job performs no source build and has only job-scoped required permissions.
- [ ] Signing private material is absent from repository, uploaded artifacts, normal logs, and caches.
- [ ] Asset URLs are immutable/versioned and do not require `latest`.
- [ ] Production publication remains inactive until STAGE-015.

## Verification plan
| Check | Command or method | Expected result |
|---|---|---|
| Targeted tests | `python -m pytest -q tests/test_deployment_artifacts.py tests/test_management_releases.py tests/test_scie_release.py` | All pass |
| Asset inventory | Download rehearsal Release assets and compare names/digests to expected inventory | Exact match |
| Signature | Run the repository verifier on downloaded manifest/signature, then on a tampered copy | Valid passes; tampered fails |
| Security/static review | Inspect permissions, secret references, action SHAs, temp cleanup, and logs | Least privilege; no key disclosure |

## Suggested subagents
- `devops-engineer` - Release job and asset orchestration.
- `security-engineer` - protected signing operation and secret lifetime.
- `qa-expert` - downloaded-asset acceptance.
- `security-auditor` - independent trust-chain review.

## Risks and rollback
- Risk: signing the wrong manifest, leaking the key, overwriting assets, or producing client URLs that differ from rehearsal.
- Rollback: delete the draft/rehearsal Release, revoke/rotate exposed candidate keys if necessary, keep production caller disabled, and rebuild no artifact under the same version.

## Completion notes
Filled by `close-plan-stage`.
