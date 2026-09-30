# STAGE-007 - Establish signed release metadata trust

## Status
CLOSED

## Priority
HIGH

## Source findings
- `codex-analysis/20260928-131617/project-analysis-report.md` - F-003 and F-012: checksum-only verification lacks an independent publisher trust root.
- `agent-reports/security-auditor.md` - workflow attestations do not protect a client unless the client verifies them; signed manifest is the minimum launch control.
- `agent-reports/devops-engineer.md` - current health/rollback mechanics should be preserved.

## Goal
Require cryptographic publisher authentication for remote managed artifacts through deterministic Ed25519-signed manifest v2 metadata and an embedded, rotation-capable public-key ring.

## Non-goals
- Store a private signing key in the repository.
- Implement TUF, threshold signing, or client-side Sigstore verification at launch.
- Expose `xferry update` publicly before GitHub Release assets exist.
- Replace existing size/hash, HTTPS, config, health, or rollback checks.

## Scope
### Likely files to inspect
- `xferry/management/releases.py` - manifest download/parse/verify/activation order.
- Canonical release contract from STAGE-004.
- `tools/build_scie_release.py` and installer template - canonical metadata/assets.
- `SECURITY.md`, `docs/threat-model.md` - key/trust requirements.
- `tests/test_management_releases.py`, `tests/test_scie_release.py` - adversarial and recovery fixtures.

### Likely files to change
- `xferry/management/release_trust.py` (new or equivalent) - canonical bytes, key ring, Ed25519 verification, key IDs.
- `xferry/management/releases.py` - verify signature before candidate write/activation.
- Signing helper under `tools/` that accepts external private-key input without logging it.
- Manifest/bundle generation, installer verification assets, security docs, and tests.

### Files that must not be changed
- Any tracked private key, seed, token, certificate private material, or real secret fixture.
- `.github/workflows/release.yml` production publishers - STAGE-012/015.
- Runtime server protocol/handlers.

## Dependencies
- Depends on: STAGE-004, STAGE-006
- Blocks: STAGE-009, STAGE-012, STAGE-013

## Implementation steps
1. Specify deterministic canonical manifest serialization and detached signature format, including `key_id`, source commit, workflow run, platform artifact, and complete digest set.
2. Add an embedded trusted public-key ring with explicit IDs and overlap support for rotation; use test-only keys in fixtures.
3. Add a signing tool that reads private material from a protected path/descriptor, never commits or logs it, and signs already-built manifest bytes without rebuilding artifacts.
4. Require signature verification before remote executable download/installation; then retain size/hash/platform/version/config/health checks as defense in depth.
5. Add installer verification guidance/assets that support download → signature verification with a trusted public key → explicit `sudo` execution; prohibit pipe-to-shell.
6. Cover tampering, unknown/revoked key ID, wrong key, non-canonical encoding, mismatched digest set, platform swap, downgrade, and rotation overlap.

## Acceptance criteria
- [x] Valid manifest v2 signatures verify offline using only shipped public keys and existing runtime dependencies. Owner-approved key `xferry-release-2026-09` is embedded; an enrollment proof and an ephemeral canonical manifest signed before private-key cleanup both verified through the shipped ring.
- [x] Any metadata/artifact-reference mutation invalidates the signature before filesystem/service mutation.
- [x] Unsigned remote manifests and unknown/revoked keys fail closed with stable, actionable error codes.
- [x] Two-key rotation overlap is tested; removal/revocation behavior is documented.
- [x] No private key or real secret appears in tracked files, logs, fixtures, or artifacts.
- [x] Existing SHA-256, size, HTTPS/redirect, config, health, and automatic rollback checks remain required.
- [x] Installer instructions/assets do not require `curl | sudo sh`.

## Verification plan
| Check | Command or method | Expected result |
|---|---|---|
| Targeted tests | `python -m pytest -q tests/test_management_releases.py tests/test_scie_release.py` | Valid, tamper, rotation, downgrade, and recovery cases pass |
| Type/lint/build | `mypy xferry && ruff check xferry/management tools tests/test_management_releases.py tests/test_scie_release.py` | Clean |
| Secret/static review | `git diff --check` plus bounded search for test/private-key markers and logging paths | No real private material or key output |
| Manual cryptographic review | Verify exact signed byte contract and pre-mutation ordering | Unambiguous canonicalization and independent trust root |

## Suggested subagents
- `security-engineer` - Ed25519 key-ring and verification implementation.
- `security-auditor` - adversarial review of canonicalization, key handling, and trust ordering.
- `python-pro` - typed integration with release parsing.
- `test-automator` - tamper/rotation/downgrade property cases.

## Risks and rollback
- Risk: ambiguous canonicalization, leaked key material, or an unverifiable rotation can brick updates or authorize malicious content.
- Rollback: keep public update disabled, revoke the candidate key ID, retain current local rollback, and revert verifier/signing changes before any signed release is declared supported.

## Completion notes
- Added a strict canonical schema-v2 `ed25519` manifest contract, domain-separated detached signature envelopes, and an immutable active/revoked public-key ring. Owner-approved production key `xferry-release-2026-09` is enrolled; its private material exists only in the required-reviewer GitHub Environment `production-release`, and `kgmnotes` owns rotation/revocation.
- Remote update now authenticates the canonical manifest and declared key ID before deriving or downloading an artifact. Signed metadata and its signature are persisted and reverified for managed release eligibility; version downgrades and equal-precedence identity changes are rejected.
- Added external-path/file-descriptor signing, offline manifest/installer verification, signed installer metadata handling, actionable English/Russian failure messages, rotation/revocation guidance, threat-model updates, and adversarial coverage for tampering, noncanonical encodings, platform swaps, wrong/unknown/revoked keys, overlap, downgrade, and pre-mutation rejection.
- Verification passed: 266 focused tests, all 3,309 repository tests, strict mypy for 70 source files, scoped Ruff lint/format, shell syntax, documentation synchronization, diff validation, bounded private-key/logging checks, protected-environment metadata review, and offline production-key interoperability.
- An independent final security review found a stale-current race that could replace a concurrent newer release. The version policy is now rechecked under the managed lock before candidate execution, with a RED-to-GREEN regression test.
- The signed installer still re-downloads the manifest signature after operator verification; substitution can only make installed state fail closed and lose rollback eligibility, not authorize different code. This publication-path hardening is recorded for STAGE-012/013 before activation.
- Report: `stage-reports/STAGE-007-20260930-101954.md`.
