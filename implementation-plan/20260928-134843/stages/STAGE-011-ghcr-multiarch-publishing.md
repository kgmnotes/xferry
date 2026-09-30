# STAGE-011 - Add multi-arch GHCR publication path

## Status
CLOSED

## Priority
HIGH

## Source findings
- `codex-analysis/20260928-131617/project-analysis-report.md` - F-011 and F-015: no GHCR/multi-arch path exists and examples are source-build only.
- `agent-reports/qa-expert.md` - release verification is weaker than CI because it omits `verify_docker_image.py` and arm64 runtime evidence.
- `agent-reports/security-auditor.md` - use least privilege, immutable tags/digests, SBOM, and provenance.

## Goal
Implement an initially non-production-activated GHCR publisher that promotes the exact verified OCI candidate as `linux/amd64` and `linux/arm64`, records its digest, and proves both platform images by pull/run.

## Non-goals
- Publish or depend on a mutable `latest` tag.
- Rebuild the image after candidate verification.
- Activate production tag publication before STAGE-015.
- Change application runtime behavior or weaken Docker hardening.

## Scope
### Likely files to inspect
- `Dockerfile`, `.dockerignore`, Docker verification/smoke tools.
- Candidate OCI layout/digest inventory from STAGE-009.
- `.github/workflows/release.yml` and deployment policy tests.
- Existing Compose examples for later compatibility, without documenting the public path yet.

### Likely files to change
- A reusable/protected GHCR publish job under `.github/workflows/`.
- OCI promotion/registry verification tooling if needed.
- Deployment, image, and policy tests.

### Files that must not be changed
- Application runtime source unless a real cross-architecture bug is demonstrated.
- Public Docker/Compose docs - STAGE-014.
- Production `v*` trigger - STAGE-015.

## Dependencies
- Depends on: STAGE-009
- Blocks: STAGE-014, STAGE-015

## Implementation steps
1. Confirm GHCR namespace/visibility and protected-environment access for `ghcr.io/kgmnotes/xferry`.
2. Add a job with only `contents: read`, `packages: write`, `id-token: write`, and `attestations: write` as actually required.
3. Download/verify the promoted OCI candidate and push the same platform manifests without a source rebuild.
4. Apply immutable `vX.Y.Z` tagging, record the multi-arch digest, publish SBOM/provenance/attestation, and omit `latest`.
5. Pull by digest/version on amd64 and arm64, run image-surface verification, dependency imports, version/config, health, and browser-first-run smoke.
6. Keep the production caller disabled until STAGE-015.

## Acceptance criteria
- [x] GHCR manifest contains exactly `linux/amd64` and `linux/arm64` for the target version.
- [x] Registry digests correspond to the promoted OCI candidate inventory; no publish-job build occurs.
- [x] Each architecture passes `verify_docker_image.py` and `docker_image_smoke.py` after pulling from GHCR.
- [x] Version tag and digest are immutable release identities; no `latest` dependency is created.
- [x] SBOM, provenance, and attestation are attached and verifiable.
- [x] Publisher permissions are job-scoped and production activation remains disabled.

## Verification plan
| Check | Command or method | Expected result |
|---|---|---|
| Targeted/static tests | Corrected branch: 160 focused tests, Ruff lint/format, compile, Actionlint and policy checks | All passed before PR #40 merged |
| Registry manifest | Run `36779670844`; receipt/index independently downloaded and hashed | Exact digest `sha256:38fa2dbd7e14edd7ad305620d4d8ee80cea1eb8857f500c757263dcdb88d3622`; exactly two target platforms plus their attestations |
| Runtime integration | Native `pull-smoke` jobs pulled `ghcr.io/kgmnotes/xferry@sha256:38fa2d...` on amd64 and arm64 | Image verification, runtime lifecycle, browser first-run, persistence and cleanup passed on both architectures |
| Security/static review | Protected workflow, exact candidate receipt, registry verifier, and independent review | Least privilege, no rebuild, SPDX/SLSA identity, and publication-time absence of `latest` verified |

## Suggested subagents
- `docker-expert` - OCI promotion and multi-platform correctness.
- `devops-engineer` - GHCR permissions/workflow.
- `qa-expert` - dual-architecture pull/run acceptance.
- `security-auditor` - provenance, attestation, and least-privilege review.

## Risks and rollback
- Risk: OCI promotion changes digests, emulated arm64 smoke hides a native failure, or registry visibility is wrong.
- Rollback: delete/deprecate only rehearsal tags, keep production caller disabled, and require native arm64 evidence before STAGE-015.

## Completion notes
- Implementation merged through PR #37 as `4a0deec`; the deterministic registry-verifier destination fix merged through PR #40 as `54a1713`.
- Successful hosted evidence: [run `36779670844`](https://github.com/kgmnotes/xferry/actions/runs/36779670844), exact protected head `f0da2711b7bb111071bad926752bd31be065dc13`.
- Published identity: `ghcr.io/kgmnotes/xferry:v0.1.0` at `sha256:38fa2dbd7e14edd7ad305620d4d8ee80cea1eb8857f500c757263dcdb88d3622`; no `latest` tag existed at the publication gate.
- All five jobs passed: immutable candidate identity/preparation, protected publish, registry graph verification, native amd64 pull/runtime/browser smoke, and native arm64 pull/runtime/browser smoke. The registry graph preserved the exact STAGE-009 platform, SPDX SBOM and SLSA provenance descriptors.
- Production caller remains disabled; STAGE-015 owns activation. Canonical public container documentation remains STAGE-014 scope.
- Closure report: `stage-reports/STAGE-011-20261001-004320.md`.
