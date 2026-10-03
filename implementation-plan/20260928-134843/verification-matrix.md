# Verification Matrix

| Stage | Required checks | Optional checks | Known blockers | Baseline needed? |
|---|---|---|---|---|
| STAGE-001 | strict mypy; handler-context/notepad tests; Ruff | full suite | None | Mypy currently has one known error |
| STAGE-002 | strict pip-audit; dependency/toolchain checks; strict docs build | clean-environment lock refresh diff review | Network/package-index availability | Two known advisories |
| STAGE-003 | ADR index; stale-doc and deployment policy tests; security docs sync | architecture review | None | Existing source-only guards pass |
| STAGE-004 | platform/manifest/model/state unit and property tests; mypy | v1 fixture fuzzing | Existing managed-state compatibility | Current schema/platform fixtures |
| STAGE-005 | all target distro/arch detection and diagnostic tests | native host preflight | Native arm64 availability | Current x86_64/Debian 12 behavior |
| STAGE-006 | two SCIE bundles; checksum/manifest/install tests; distro base smoke | native arm64/systemd smoke | arm64 runner/QEMU fidelity | Existing x86_64 SCIE smoke |
| STAGE-007 | canonicalization/signature/tamper/key rotation/downgrade tests | offline verifier interoperability | None; enrollment and protected custody confirmed | Existing checksum/rollback cases |
| STAGE-008 | built-wheel install matrix; pipx-style commands; portable subset; CLI contracts | actual TestPyPI install deferred to 010 | Hosted OS runner availability | Existing editable 3.12 matrix |
| STAGE-009 | tag/version/changelog preflight; exact artifact digest equality; no external writes | independent Artifact API download | None; run `36712344792` and downloaded artifact `11095067140` passed exact identity verification | Current verification workflow |
| STAGE-010 | TestPyPI Trusted Publishing; accepted wheel/sdist bytes; actual exact-version pipx smoke on three OSes | manual metadata review | Missing pending publisher mapping for `xferry` / `kgmnotes/xferry` / `testpypi.yml` / `testpypi`; run `37111932008` reached TestPyPI with a valid OIDC token but failed `invalid-publisher`, so upload and hosted OS receipts did not run | Stage 008 wheel matrix and exact Stage 009 artifact |
| STAGE-011 | exact STAGE-009 OCI promotion without rebuild; native amd64+arm64 image/runtime/browser smokes; registry digest equality; SBOM/SLSA verification; publication-time absence of latest | additional consumer rehearsal | None; all five jobs passed in run `36779670844` at `f0da271`; production activation deferred to STAGE-015 | Exact Stage 009 artifact and published digest `sha256:38fa2dbd7e14edd7ad305620d4d8ee80cea1eb8857f500c757263dcdb88d3622` |
| STAGE-012 | complete draft Release assets; exact STAGE-009 identity; protected signature; downloaded inventory/signature/tamper verification; no rebuild | anonymous public URL check deferred to activation | None for draft scope: run `36785117025` passed all four jobs on protected `19ce00f`; release `400481506` is draft+prerelease with exactly 18 assets. Public anonymous delivery remains a STAGE-015 activation check | Exact Stage 009 artifact `11095067140` and its recorded digests |
| STAGE-013 | CLI normal/failure/recovery; signed exact-version update; health/rollback/uninstall | native systemd E2E | None; run `36876624959` passed the complete managed lifecycle on native x86_64 and arm64, and run `36876631449` passed all 29 candidate jobs | Existing internal updater tests |
| STAGE-014 | generated docs/CLI/support matrix; all docs guards; strict MkDocs | link checker against staged URLs | Public/staging URLs | Existing docs gate baseline |
| STAGE-015 | full gates; protected approval; production tag; post-publish portable/container/managed smokes | incident tabletop | Owner approval and public namespaces | All prior stage reports |
