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
| STAGE-010 | TestPyPI Trusted Publishing; exact-version pipx smoke on three OSes | manual metadata review | Namespace/publisher ownership | Stage 008 wheel matrix |
| STAGE-011 | Buildx amd64+arm64; image verifier; pull/run by digest; SBOM/provenance | native arm64 smoke | GHCR permissions/visibility | Existing local Docker smoke |
| STAGE-012 | complete draft/staging Release assets; signature verification; no rebuild | GitHub attestation verify | Signing key and contents permission | Stage 009 candidate digests |
| STAGE-013 | CLI normal/failure/recovery; signed exact-version update; health/rollback/uninstall | native systemd E2E | Published staging assets | Existing internal updater tests |
| STAGE-014 | generated docs/CLI/support matrix; all docs guards; strict MkDocs | link checker against staged URLs | Public/staging URLs | Existing docs gate baseline |
| STAGE-015 | full gates; protected approval; production tag; post-publish portable/container/managed smokes | incident tabletop | Owner approval and public namespaces | All prior stage reports |
