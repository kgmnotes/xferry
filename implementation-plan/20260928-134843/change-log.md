# Change Log

## 2026-09-28 14:43:22 +0300 — STAGE-001
- Status: CLOSED
- Files changed: `xferry/handlers/notepad.py`, `plan.md`, `stage-status.md`, `stages/STAGE-001-restore-strict-typing-baseline.md`, and the stage report.
- Verification: pinned strict mypy passed; 130 focused tests passed; scoped Ruff lint/format passed; optional full suite passed all 3,171 tests; independent read-only review passed.
- Report: `stage-reports/STAGE-001-20260928-143829.md`

## 2026-09-29 13:13:40 +0300 — STAGE-002
- Status: CLOSED
- Files changed: `constraints/ci.txt`, `plan.md`, `stage-status.md`, `stages/STAGE-002-patch-audited-toolchain-pins.md`, `change-log.md`, and the stage report.
- Verification: clean constrained resolution, package consistency, dependency/toolchain contracts, strict pip-audit, docs render/sync/staleness, scoped Ruff, strict MkDocs, and all 3,171 tests passed; independent dependency and security reviews passed.
- Report: `stage-reports/STAGE-002-20260929-125932.md`

## 2026-09-29 14:00:12 +0300 — STAGE-003
- Status: CLOSED
- Files changed: ADR-006/ADR-011 and ADR navigation, `SECURITY.md` plus its generated mirror, `docs/threat-model.md`, `mkdocs.yml`, the staged documentation/workflow guard and tests, and this active plan's status, stage, change log, and report artifacts.
- Verification: 133 targeted tests, scoped Ruff lint/format, documentation sync and semantic guard, strict MkDocs, action-pin validation, all 3,212 repository tests, and final architecture/security reviews passed; `.github/workflows/release.yml` remained unchanged and non-publishing.
- Report: `stage-reports/STAGE-003-20260929-132815.md`

## 2026-09-29 14:40:45 +0300 — STAGE-004
- Status: CLOSED
- Files changed: canonical release contract; release, managed-state, host, builder, and installer consumers; focused contract tests; and this active plan's status, stage, change log, and report artifacts.
- Verification: 274 focused contract tests, 206 managed setup tests, all 3,245 repository tests, mypy, scoped Ruff lint/format, shell syntax, canonical-literal audit, package/archive validation, and final subagent re-review passed.
- Report: `stage-reports/STAGE-004-20260929-140255.md`

## 2026-09-29 15:48:34 +0300 — STAGE-005
- Status: CLOSED
- Files changed: managed host model, setup planning/result mapping, doctor and CLI diagnostics, i18n action rendering, four focused test modules, and this active plan's overview, status, stage, change log, and report artifacts.
- Verification: all 309 stage-targeted and 381 expanded management/CLI tests, strict mypy for 69 source files, scoped Ruff lint/format, all 3,265 repository tests, representative Windows/macOS JSON review, and independent QA/final reviews passed.
- Report: `stage-reports/STAGE-005-20260929-144237.md`

## 2026-09-29 18:58:35 +0300 — STAGE-006
- Status: CLOSED
- Files changed: native multi-platform SCIE builder, generated installer validation, CI/manual release verification matrices, canonical managed-state platform preflight, focused builder/installer/workflow/lifecycle tests, and this active plan's overview, status, stage, change log, and report artifacts.
- Verification: 177 stage-targeted and 458 expanded tests, strict mypy, repository-wide Ruff lint/format, shell/YAML/actionlint checks, real native x86_64 and aarch64 builds and no-host-Python CLI probes, all ten native target images, all 3,291 repository tests, and independent final re-review passed. Native evidence: GitHub Actions run `36593256300`, SHA `ca8c83631437d07a4bbce67933a5dbd309f36a4e`.
- Report: `stage-reports/STAGE-006-20260929-155138.md`

## 2026-09-29 19:53:24 +0300 — STAGE-007
- Status: PARTIALLY_CLOSED
- Files changed: canonical release contract and version ordering; release trust, update, and rollback handling; signing/offline verification tools; SCIE builder and installer metadata; security/threat-model documentation; focused tests; and this active plan's overview, status, stage, change log, and report artifacts.
- Verification: 265 stage-targeted and all 3,308 repository tests, strict mypy for 70 source files, scoped Ruff lint/format, installer shell syntax, documentation sync, diff validation, bounded private-key/logging review, and independent security review passed. Production release workflow remained unchanged.
- Remaining blocker: no owner-approved production Ed25519 public key, key ID, custody model, or rotation/revocation owner is available to enroll; the default key ring remains empty and remote update remains disabled and fail-closed.
- Report: `stage-reports/STAGE-007-20260929-190303.md`

## 2026-09-30 10:19:54 +0300 — STAGE-007
- Status: CLOSED
- Files changed: enrolled production public trust root and proof; protected signing-custody/runbook documentation; under-lock downgrade recheck and regression test; resolved active-plan status, matrix, risks, change log, and closure report.
- External configuration: private key stored only as `XFERRY_RELEASE_ED25519_PRIVATE_KEY_PEM` in required-reviewer GitHub Environment `production-release`; key ID stored as non-secret environment variable; owner `kgmnotes`; admin bypass disabled.
- Verification: 266 stage-targeted and all 3,309 repository tests, strict mypy for 70 source files, scoped Ruff lint/format, installer shell syntax, documentation sync, diff validation, bounded private-key/logging review, offline production-key interoperability, and independent security/custody/acceptance reviews passed.
- Residual: bind or reverify the installer's persisted manifest signature before public activation; tracked for STAGE-012/013 and fail-closed today.
- Report: `stage-reports/STAGE-007-20260930-101954.md`

## 2026-09-30 11:06:22 +0300 — STAGE-008
- Status: PARTIALLY_CLOSED
- Files changed: root CLI/i18n; Python artifact verifier; CI wheel identity/transfer and nine-job consumer matrix; focused CLI, workflow, portable artifact, HTTP fixture, and Python-version schema tests; this active plan's overview, status, stage, change log, and report.
- Verification: 343 targeted tests, the exact built wheel and 312 copied portable tests on each Linux Python 3.10/3.12/3.14, external offline wheel/sdist installs, strict mypy, repository Ruff lint/format, actionlint, all 3,330 tests with coverage on each Linux Python 3.10/3.11/3.12/3.13/3.14, and final read-only QA review passed.
- Post-review verification: fixed one Minor known-command diagnostic regression test-first; 6 focused cases, all 3,332 Python 3.12 tests, Ruff lint/format, actionlint, diff integrity, and an independent candidate review passed with no Critical or Important findings. The rebuilt exact wheel (`fce1ba554e5949a7f0d1ab822d8fa8f502d48631ea58f913c8f6ee7f0ef39918`) passed the full 312-test portable journey on Linux Python 3.10/3.12/3.14.
- Remaining evidence: run and record all nine native OS/Python consumer jobs and producer wheel identity after the authorized wrapper pushes the candidate; no commit, push, or hosted dispatch was performed in this invocation.
- Report: `stage-reports/STAGE-008-20260930-102812.md`

## 2026-09-30 12:00:21 +0300 — STAGE-008 hosted remediation
- Status: PARTIALLY_CLOSED
- Hosted evidence: run `36690775333` passed the exact-wheel producer and six of nine portable consumers; macOS 3.10 exposed a relative constraints path, while Windows 3.10/3.14 exposed a transient post-exit listener race.
- Files changed: `.github/workflows/ci.yml`, `tools/verify_python_artifacts.py`, the two focused regression modules, the stage file, this change log, and the existing stage report.
- Verification: 54 focused tests, all 3,335 Python 3.12 tests, strict mypy, repository Ruff lint/format, actionlint, pytest collection policy, a real external-wheel lifecycle plus 312 portable tests, diff integrity, and independent review passed.
- Remaining evidence: fresh hosted producer identity and all nine green portable consumers.
- Report: `stage-reports/STAGE-008-20260930-102812.md`

## 2026-09-30 12:07:05 +0300 — STAGE-008
- Status: CLOSED
- Hosted evidence: run `36693644399`, SHA `bcf2430262de016369829896f52c71c8fc1ef2c0`; producer wheel SHA256 `86f2bb19c4a5e9de0d4820d6a0d09a7de646f782e7e81c6f473597ba02a20d5d`; all nine Ubuntu/macOS/Windows × Python 3.10/3.12/3.14 consumers passed.
- Verification: the hosted producer and nine portable consumers, 54 focused tests, all 3,335 Python 3.12 tests, strict mypy, repository Ruff lint/format, actionlint, pytest collection policy, real external-wheel acceptance, diff integrity, and independent review passed.
- Known unrelated gate: the aggregate CI conclusion remains red only at the documented pre-existing public-tree policy before the full Linux jobs; shipping artifact validation and all STAGE-008 jobs are green.
- Report: `stage-reports/STAGE-008-20260930-102812.md`

## 2026-09-30 12:50:07 +0300 — STAGE-009
- Status: PARTIALLY_CLOSED
- Files changed: `.github/workflows/ci.yml`, `security.yml`, `release.yml`, `candidate-scie.yml`; `packaging/Dockerfile.candidate`; `tools/check_release_preflight.py`, `candidate_inventory.py`, `build_scie_release.py`; `tests/test_candidate_promotion.py`, `test_deployment_artifacts.py`, `test_scie_release.py`, `test_browser_smoke_modes.py`; selected stage, plan overview/status/matrix, this log, and closure report.
- Implementation: manual strict-version candidate orchestration, source/docs/security gates before construction, exact-wheel native SCIE/image builds, OCI SBOM/provenance closure, SHA-pinned immutable artifact-ID transfers, canonical per-file/platform digest inventory, and fail-closed downstream byte verification without rebuild.
- Verification: 458 focused and all 3,476 final repository tests passed; strict mypy, compile, Ruff lint/format (174 files), actionlint, generated/strict docs, tooling/dependency policies, real wheel/sdist/offline/312-test portable journeys, native SCIE across five bases, native OCI export/load lifecycle, 26-file authenticated byte/mode equality and independent final review passed. Reproduced and fixed the SLSA junk-predicate gap test-first.
- Remaining evidence: successful complete hosted candidate run and exact downloaded-artifact digest verification after wrapper commit/push. Unchanged HEAD reproduces the existing public shipping-tree policy failure; its gate was preserved.
- Boundary: no commit/push, production publication/tag activation, production Environment, or private-key access; later publishers remain staging/draft/rehearsal until STAGE-015.
- Report: `stage-reports/STAGE-009-20260930-121326.md`

## 2026-09-30 15:22:00 +0300 — STAGE-009 hosted closure
- Status: CLOSED
- Hosted evidence: run `36712344792`, public-tree SHA `40ac9bc031aa28b9adc2765857a8926f522e4005`; every quality/security/docs, Python candidate, nine portable, two native SCIE, multiarch OCI, two native image, collector, and final download job passed.
- Remediation: BuildKit's optional empty `oci/ingest` staging state is removed before packing; malformed/non-empty/link shapes and symlinked parents fail closed. Independent review exposed the parent-symlink deletion boundary, fixed test-first.
- Verification: 180 focused and all 3,485 repository tests, strict mypy, Ruff lint/format, compile, actionlint, collection/toolchain policies, public-tree preflight/surface checks, and final hosted run passed.
- Downloaded evidence: artifact `11095067140`; API/ZIP SHA256 `97cad6b7fc6ca848de441930162d842f05d004659f14a5fd40e2b89995c7e878`; archive SHA256 `c3746592f16699fafe062e5bf245853f5058a8bdff70193ddf1c112e84ac8517`; inventory SHA256 `b6e86089660bff44daf856c2dc18ac4a310b79c40dde949f3aa9817894a99189`; exact `v0.1.0`/source/run identity reverified locally.
- Boundary: no PyPI, GHCR, or GitHub Release publication/write and no production Environment, signing-secret, or private-key access. The feature PR's unchanged internal-plan public-surface failure remains separate from the passing public rehearsal tree.
- Report: `stage-reports/STAGE-009-20260930-152200.md`

## 2026-09-30 16:13:00 +0300 — STAGE-010
- Status: PARTIALLY_CLOSED.
- Files changed: `.github/workflows/testpypi.yml`, `packaging/testpypi-candidate.json`, `tools/testpypi_publish.py`, `tools/check_stale_docs.py`, `tests/test_testpypi_publish.py`; selected stage, active plan overview/status/matrix, this log, closure report, external snapshot, and operator instructions.
- Implementation: TestPyPI-only SHA-pinned OIDC publisher of the preserved STAGE-009 0.1.0 distributions; authenticated artifact/run/archive/inventory identity; no rebuild; remote accepted-file byte verification; actual pipx consumer workflow on Linux/macOS/Windows; separate staging-policy guards.
- Verification: 500 final focused tests, mypy, Ruff lint/format, compile, actionlint, stale-doc/release preflight, exact original candidate preparation, package validation, real isolated local Linux pipx lifecycle, and independent review passed. Reviewer-found pipx constraint-path and five policy-guard gaps were fixed.
- Remaining: owner-confirmed TestPyPI mapping, staging environment/workflow availability, actual accepted TestPyPI wheel/sdist bytes, and hosted three-OS pipx evidence. TestPyPI version endpoint returns 404. No commit/push or external write was performed.
- Prerequisite only: production-release needs restricted refs and an independent eligible reviewer before STAGE-012; no repository permissions were granted and no signing secret was accessed. STAGE-015 untouched.
- Report: `stage-reports/STAGE-010-20260930-125252.md`; instructions: `stage-reports/STAGE-010-20260930-125252-operator.md`.

## 2026-09-30 16:42:58 +0300 — STAGE-010 operator update
- Status: PARTIALLY_CLOSED; production remains inactive.
- Access boundary: `gkumurzhi` accepted explicit repository `write` access and joined `kgmnotes` as a required `production-release` reviewer. Self-review prevention and disabled administrator bypass were preserved; the signing secret value was not read. Exact deployment-ref restriction is still required before STAGE-012 consumes the Environment.
- Staging boundary: created secret-free `testpypi`, limited it to branch `codex/stage-010-testpypi-rehearsal`, configured both eligible reviewers, prevented self-review, and disabled administrator bypass.
- Independent review found that deleting the top-level workflow permissions block escaped the policy guard. A failing regression reproduced it; the guard now requires exactly `contents: read` and `actions: read`.
- Verification: the new regression passed, all 3,533 repository tests passed, and strict mypy, Ruff lint/format, compile, actionlint v1.7.7, stale-doc guard, release preflight, and diff integrity were clean.
- Remaining: owner-confirmed TestPyPI Trusted Publisher mapping, workflow registration on the default branch, actual immutable `0.1.0` upload, accepted-byte verification, and hosted Ubuntu/macOS/Windows receipts.

## 2026-10-01 00:43:20 +0300 — STAGE-011 hosted closure
- Status: CLOSED.
- Integration: PR #37 merged the GHCR rehearsal as `4a0deec`; PR #40 merged the registry-verifier destination fix as `54a1713`. Both rehearsal branches were retained and protected; `ghcr-staging` allowlists only the corrected v2 branch.
- Hosted evidence: run `36779670844`, protected head `f0da2711b7bb111071bad926752bd31be065dc13`; all five jobs passed.
- Published identity: `ghcr.io/kgmnotes/xferry:v0.1.0`, digest `sha256:38fa2dbd7e14edd7ad305620d4d8ee80cea1eb8857f500c757263dcdb88d3622`; publication refused a mutable `latest` tag before registry write.
- Acceptance: exact STAGE-009 OCI graph promoted without rebuild; registry identity, both platform manifests, SPDX/SLSA descriptors, native amd64/arm64 image/runtime/browser lifecycles, named-volume persistence, and cleanup verified.
- Boundary: production activation remains disabled until STAGE-015; public container documentation remains STAGE-014 scope.
- Report: `stage-reports/STAGE-011-20261001-004320.md`.

## 2026-10-01 01:41:45 +0300 — STAGE-012 hosted closure
- Status: CLOSED.
- Reviewed implementation: PR #41, protected and locked head `19ce00f7e0e97efe8221d3a594bab0e2ce439e36`, received `gkumurzhi` approval, all 23 required checks, and an independent no-findings review. It remains unmerged to avoid the automatic public Pages deployment attached to every `main` push.
- Hosted evidence: run `36785117025`; identity, protected signing, secret-free draft publication/download, and read-only verification all passed after independent approvals by `gkumurzhi`.
- Release identity: draft prerelease `400481506`, lightweight tag `xferry-stage-012-rehearsal-v0.1.0-36712344792-v2`, exactly 18 versioned assets, no `latest`, overwrite, edit, or rebuild path.
- Verification: 250 focused tests; all 3,608 tests at 87.73% coverage; stale-doc, Node syntax, Ruff lint/format, actionlint and diff checks; independent code review; hosted signature/tamper verification; and a separate authenticated local download and verification all passed.
- Rollback: failed v1 draft `400465201` was deleted after v2 success. The v1 protected branch and tag remain at `a0b1de8`; the v2 draft remains unpublished.
- Boundary: no production `v0.1.0` tag, non-draft public Release, production PyPI publication, or public documentation deployment occurred. Anonymous public delivery remains STAGE-015 scope.
- Report: `stage-reports/STAGE-012-20261001-014145.md`.

## 2026-10-03 12:20:24 +0300 — STAGE-010 hosted follow-up
- Status: PARTIALLY_CLOSED; production remains inactive.
- Hosted evidence: run `37111932008` at `f1361d0` passed identity and received a valid independent `testpypi` Environment approval from `gkumurzhi`; authenticated handoff artifact `11269958516` has digest `sha256:69a2b778d8ad3c9c84c6f7dcd32ef87f04fe6b70e1a4ae19f78fb5a1a2e3da25` and expires `2026-10-04T09:06:43Z`.
- Exact blocker: TestPyPI rejected the valid OIDC token with `invalid-publisher` because the pending publisher mapping for `xferry` / `kgmnotes/xferry` / `testpypi.yml` / `testpypi` does not exist. No upload occurred; the three OS consumers skipped and TestPyPI remains 404.
- Remaining: authenticated TestPyPI owner creates the mapping, failed jobs are rerun with fresh protected approval, and accepted wheel/sdist bytes plus Windows/macOS/Linux pipx receipts are verified.
- Rerun attempt 2 received a new protected approval from `gkumurzhi` and failed at the same TestPyPI exchange with the same exact claims and `invalid-publisher`; this rules out stale approval/first-attempt state and leaves the account-level mapping as the sole upload blocker.
- Report: `stage-reports/STAGE-010-20261003-122024.md`.

## 2026-10-03 12:19:45 +0300 — STAGE-013 hosted closure
- Status: CLOSED.
- Implementation: PR #42, exact head `fa06558008f1eed558fb171fb729e274fe947de3`, exposes the explicit signed managed-Linux update lifecycle with dry-run/JSON, portable pipx separation, exact-target health, rollback retention, and automatic recovery.
- Hosted evidence: run `36876624959` passed full managed install/update/health/rollback/uninstall on native x86_64 and arm64; run `36876631449` passed all 29 candidate jobs across Python 3.10-3.14, portable Windows/macOS/Linux, dual-arch SCIE/OCI, docs, risk, and security.
- Verification: fresh 3,723-test full suite, Ruff, strict MyPy for 71 files, generated settings/contracts/docs checks, stale-doc guard, and strict MkDocs passed. Independent correctness and security reviews had no material findings; `gkumurzhi` approved the exact head.
- Boundary: PR #42 remains open and unmerged; STAGE-014/Public Pages and every production action remain gated by STAGE-010 and separate STAGE-015 authorization.
- Report: `stage-reports/STAGE-013-20261003-121945.md`.
