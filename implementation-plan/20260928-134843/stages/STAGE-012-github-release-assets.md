# STAGE-012 - Publish signed GitHub Release assets

## Status
CLOSED

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
- [x] Rehearsal Release contains the complete, uniquely named asset inventory and no unexpected files.
- [x] All unsigned candidate files match the STAGE-009 digest inventory exactly.
- [x] Manifest signature verifies with the shipped client key ring and fails after any mutation.
- [x] Publish job performs no source build and has only job-scoped required permissions.
- [x] Signing private material is absent from repository, uploaded artifacts, normal logs, and caches.
- [x] Asset URLs are immutable/versioned and do not require `latest`.
- [x] Production publication remains inactive until STAGE-015.

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
- Closed 2026-10-01 01:41:45 +0300. Initial implementation was merged through PR #38 (`55805f9`); the draft-aware correction is reviewed at PR #41, commit `19ce00f7e0e97efe8221d3a594bab0e2ce439e36`.
- PR #41 received `gkumurzhi` approval, an independent no-findings code review, and all 23 GitHub checks. It intentionally remains unmerged because every `main` push automatically deploys public Pages, which is prohibited before STAGE-015.
- Exact branch `codex/stage-012-draft-release-rehearsal-v2` is protected and locked. Lightweight tag `xferry-stage-012-rehearsal-v0.1.0-36712344792-v2` points directly to `19ce00f`.
- Both `production-release` and `github-release-staging` allowlist only that exact v2 branch; required reviewers, self-review prevention, and disabled administrator bypass were preserved.
- Run [`36785117025`](https://github.com/kgmnotes/xferry/actions/runs/36785117025) passed all four jobs. `gkumurzhi` independently approved protected signing and draft publication.
- Draft prerelease `400481506` contains exactly 18 uniquely named assets. Hosted and independent local downloads passed exact inventory, signature, shipped-key-ring, platform, source/workflow identity, and tamper-rejection verification.
- The failed v1 draft `400465201` was deleted only after v2 verification. Its protected branch and lightweight tag remain at `a0b1de8` as immutable audit evidence.
- The production tag, public/non-draft Release, production PyPI, and public documentation deployment remain inactive. Anonymous public Release delivery is deferred to STAGE-015.
- Full evidence: `stage-reports/STAGE-012-20261001-014145.md`.
