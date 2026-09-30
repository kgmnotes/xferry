# Stage Status

| Stage | Status | Priority | Title | Last attempt | Result | Report |
|---|---|---|---|---|---|---|
| STAGE-001 | CLOSED | MEDIUM | Restore strict typing baseline | 2026-09-28 14:43:22 +0300 | Pinned mypy, 130 focused tests, Ruff, and the 3,171-test full suite passed after a behavior-preserving local annotation. | `stage-reports/STAGE-001-20260928-143829.md` |
| STAGE-002 | CLOSED | MEDIUM | Patch audited CI toolchain pins | 2026-09-29 13:13:40 +0300 | Refreshed the two vulnerable toolchain pins; strict audit, constraint/toolchain checks, docs gates, and all 3,171 tests passed. | `stage-reports/STAGE-002-20260929-125932.md` |
| STAGE-003 | CLOSED | HIGH | Adopt controlled distribution policy and guards | 2026-09-29 14:00:12 +0300 | Accepted ADR-011, added release trust boundaries and staged publisher guards, and passed 133 targeted plus all 3,212 repository tests. | `stage-reports/STAGE-003-20260929-132815.md` |
| STAGE-004 | CLOSED | HIGH | Centralize release platform and manifest contracts | 2026-09-29 14:40:45 +0300 | Added one strict v1/v2 release contract, migrated its consumers and builder/installer data, and passed 274 focused plus all 3,245 repository tests. | `stage-reports/STAGE-004-20260929-140255.md` |
| STAGE-005 | CLOSED | HIGH | Add complete managed host support matrix | 2026-09-29 15:48:34 +0300 | Added the complete ten-host matrix, pre-mutation rejection, and actionable redacted diagnostics; 309 focused and all 3,265 repository tests passed. | `stage-reports/STAGE-005-20260929-144237.md` |
| STAGE-006 | CLOSED | HIGH | Build and verify multi-arch SCIE installers | 2026-09-29 18:58:35 +0300 | Added fail-closed dual-architecture SCIE bundles and native ten-image verification; both native jobs and all 3,291 repository tests passed. | `stage-reports/STAGE-006-20260929-155138.md` |
| STAGE-007 | CLOSED | HIGH | Establish signed release metadata trust | 2026-09-30 10:19:54 +0300 | Enrolled the protected production Ed25519 trust root, closed the concurrent-downgrade race, and passed 266 focused plus all 3,309 repository tests. | `stage-reports/STAGE-007-20260930-101954.md` |
| STAGE-008 | CLOSED | HIGH | Prove portable packaged CLI journeys | 2026-09-30 12:07:05 +0300 | Exact wheel `86f2bb19...20d5d` passed all nine Ubuntu/macOS/Windows × Python 3.10/3.12/3.14 jobs in run `36693644399`; 54 focused, 3,335 full-suite, static/workflow, real external-wheel, and independent-review gates also passed. | `stage-reports/STAGE-008-20260930-102812.md` |
| STAGE-009 | OPEN | HIGH | Create build-once candidate promotion pipeline | - | - | - |
| STAGE-010 | OPEN | HIGH | Add PyPI Trusted Publishing path | - | - | - |
| STAGE-011 | OPEN | HIGH | Add multi-arch GHCR publication path | - | - | - |
| STAGE-012 | OPEN | HIGH | Publish signed GitHub Release assets | - | - | - |
| STAGE-013 | OPEN | HIGH | Expose safe managed update lifecycle | - | - | - |
| STAGE-014 | OPEN | MEDIUM | Publish canonical journey documentation | - | - | - |
| STAGE-015 | OPEN | HIGH | Activate and rehearse production release | - | - | - |
