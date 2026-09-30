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
