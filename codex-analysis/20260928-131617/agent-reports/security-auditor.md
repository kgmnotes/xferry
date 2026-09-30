# security-auditor Report
_Generated: 2026-09-28 13:42:56 MSK_
_Source plan: /home/user/PycharmProjects/xferry/codex-analysis/20260928-131617/analysis-plan.md_

## Summary

Scope analyzed: release workflows, action pins/permissions, installer template, SCIE builder, release manifest/downloader/updater/managed-state code, Docker/Compose, security docs/threat model/ADR-006, and relevant release/update tests.

No repository files were modified. I validated the batch-1 conclusion that the repo is deliberately source-only today. I would sharpen the updater conclusion: the local update mechanics are fairly defensive, but the public trust root is missing. For a root-run `xferry update`, workflow attestations alone are not enough unless the client enforces them; the minimum launch control should be a client-verified signed manifest or equivalent client-side provenance check.

No CRITICAL findings. The highest-risk launch blockers are:

- no protected tag-to-publication chain exists;
- current tests/docs forbid the permissions and actions needed for safe publication;
- updater/installer trust would collapse to mutable GitHub Release assets unless signed or otherwise independently verified client-side.

## Documentation Checks

Read in full first, per instruction:

- `codex-analysis/20260928-131617/analysis-plan.md`
- `agent-reports/devops-engineer.md`
- `agent-reports/architect-reviewer.md`
- `agent-reports/documentation-engineer.md`

Context7 was available and used for current platform guidance:

- GitHub Actions docs: granular `GITHUB_TOKEN` permissions, protected environments, OIDC, and artifact attestation permissions. Current guidance supports scoped permissions such as `contents: read`, `packages: write`, `id-token: write`, and `attestations: write`.
- Python Packaging User Guide: PyPI Trusted Publishing should use a tagged publish job, environment `pypi`, and `id-token: write`; production PyPI should require manual approval.
- Docker build-push action docs: GHCR multi-arch release should use Buildx inputs such as `platforms: linux/amd64,linux/arm64`, `push: true`, immutable tags/digests, `sbom`, and `provenance`; GHCR push needs `packages: write`.

Repository documentation checked:

- `SECURITY.md:10-11` and `docs/security.md:12-13` still say only source checkout is supported and automation does not publish packages/binaries/images.
- `docs/threat-model.md:5-8` scopes runtime/network/storage but does not yet include release/update supply-chain boundaries.
- `docs/ADR/ADR-006-release-artifacts.md:13-15` explicitly forbids PyPI, GHCR, GitHub Releases, and release downloads.
- `README.md:21-25` documents source-only install.
- `tools/check_stale_docs.py:164-190` rejects `xferry update`, PyPI/GHCR/release URLs, publisher actions, write permissions, and secrets-backed publication.
- `tools/check_stale_docs.py:593-610` requires ADR-006 to remain accepted.

## Detailed Findings

Current trust chain state:

- Desired chain is `vX.Y.Z tag -> protected workflow -> exact built artifacts -> approved promotion -> PyPI/GHCR/GitHub Release -> installer/update client`.
- Current `.github/workflows/release.yml` stops after local verification. It is `workflow_dispatch` only at `release.yml:3-4`, has `contents: read` at `release.yml:6-7`, builds/verifies wheel/Docker/SCIE at `release.yml:54-97`, `release.yml:120-129`, and `release.yml:157-199`, then only echoes “without publication” at `release.yml:201-210`.
- Actions are commit-SHA pinned, and release checkout uses `persist-credentials: false` at `release.yml:24-26`, `106-108`, and `138-140`. The repo also enforces SHA action refs in `tools/check_toolchain_pins.py:208-232`.

Updater safety already present:

- HTTPS downloader rejects non-HTTPS/userinfo/fragments and unsafe final URLs in `xferry/management/releases.py:65-113` and `900-918`.
- Manifest parsing rejects duplicate keys, loose schemas, unsafe basenames, invalid versions, and invalid SHA-256 in `releases.py:116-196`.
- Candidate download checks size and SHA-256 before chmod/install in `releases.py:453-470`.
- Activation is root-gated, locked, config-checked, service-state checked, health-gated, and restores previous release on failure in `releases.py:283-326`, `488-590`.
- Tests cover normal update at `tests/test_management_releases.py:1014-1066`, corruption rejection at `795-815`, redirect rejection at `882-907`, health rollback at `1235-1256`, and bootstrap rollback eligibility at `tests/test_scie_release.py:780-846`.

Main gap: the checksum trust root is the manifest itself.

- `ReleaseManager` defaults to GitHub Releases at `releases.py:255`.
- Latest update downloads `.../latest/download/xferry-release.json` at `releases.py:434-438`, then downloads the executable from `.../download/{manifest.tag}/{manifest.executable_name}` at `releases.py:453-455`.
- The manifest schema has no signature, certificate identity, workflow run, artifact digest set, or attestation reference at `releases.py:125-216`.
- Therefore SHA-256 prevents transfer corruption, but not malicious replacement of both manifest and executable by a compromised release publisher or overly broad workflow token.

Installer state:

- `tools/build_scie_release.py:164-195` embeds size/hash and renders `install.sh`.
- `packaging/install.sh.in:227-239` downloads with `curl -fsSL --retry 3` and verifies size/SHA-256 before install.
- That protects the binary only if the installer script itself is authentic. A future “curl install.sh | sudo sh” path would need a signed installer or a documented download-verify-execute flow.

Docker/GHCR state:

- `Dockerfile:7` and `Dockerfile:29` use digest-pinned Python bases; runtime drops to non-root at `Dockerfile:56`.
- Compose applies useful runtime hardening: read-only rootfs, caps dropped, no-new-privileges, limits, secrets at `deploy/docker/docker-compose.public-direct.yml:11-33`.
- No GHCR release path exists; the release workflow only does local `docker build --tag xferry:release-smoke .` at `release.yml:120-121`.

## Issues Found

- [HIGH] Public release trust chain is absent and current tests forbid required launch controls
  - File/area: `.github/workflows/release.yml`, `tests/test_deployment_artifacts.py`, ADR/docs guards.
  - Evidence: Release is manual-only and read-only at `.github/workflows/release.yml:3-7`; release gate only confirms local verification at `release.yml:201-210`; tests forbid `actions/upload-artifact`, `actions/download-artifact`, `actions/attest`, `packages: write`, `contents: write`, `id-token: write`, `attestations: write`, GHCR, and PyPI at `tests/test_deployment_artifacts.py:454-473`; ADR-006 forbids publication at `docs/ADR/ADR-006-release-artifacts.md:13-15`.
  - Detail: The repo has good local verification primitives, but no tag-triggered protected publish environment, artifact promotion boundary, PyPI OIDC, GHCR permission, GitHub Release upload, attestation, or immutable artifact handoff.
  - Impact: A naive publication change would either fail the repo's own guards or bypass them, risking rebuilt/unattested artifacts, broad credentials, mutable release assets, and no auditable approval boundary.
  - Confidence: High.

- [HIGH] Public `xferry update` would trust mutable release assets without client-side publisher verification
  - File/area: `xferry/management/releases.py`, SCIE manifest schema, GitHub Release asset model.
  - Evidence: Default release origin is GitHub Releases at `releases.py:255`; latest manifest URL is `latest/download/xferry-release.json` at `releases.py:434-438`; executable URL is derived from manifest tag/name at `releases.py:453-455`; candidate verification checks only manifest-provided size/SHA-256 at `releases.py:461-470`; manifest schema has only version/tag/platform/name/size/sha256 at `releases.py:125-216`.
  - Detail: The updater safely verifies bytes against the downloaded manifest, but the manifest and executable come from the same mutable trust domain. Workflow attestations/SBOMs are useful detective controls, but they do not protect update clients unless the client verifies them or verifies a signed manifest.
  - Impact: If a release asset writer, release workflow token, or maintainer account is compromised, an attacker can publish a matching malicious manifest and executable. A managed host running update as root would install and restart attacker-controlled code.
  - Confidence: High.

- [MEDIUM] Installer trust would be unsafe if launched with pipe-to-shell curl guidance
  - File/area: `packaging/install.sh.in`, `tools/build_scie_release.py`, future install docs.
  - Evidence: Builder embeds executable size/hash into the installer at `tools/build_scie_release.py:58-66`; installer downloads the executable and verifies those embedded values at `packaging/install.sh.in:227-239`; no installer signature or detached verification is present in the template.
  - Detail: The binary hash check is valuable, but only after trusting the installer script. If docs publish `curl .../install.sh | sudo sh`, replacement of the installer asset replaces the trust root and the embedded hash.
  - Impact: A compromised or mutable installer asset becomes direct root code execution on managed hosts.
  - Confidence: High for launch risk; not exploitable today because public installer distribution is intentionally disabled.

- [MEDIUM] Managed release platform identity is duplicated and single-platform, creating unsafe expansion risk
  - File/area: SCIE builder, installer, updater, managed-state parser, host support model.
  - Evidence: SCIE name is hard-coded `linux-x86_64` at `tools/build_scie_release.py:115`; manifest platform is hard-coded at `build_scie_release.py:170`; installer rejects non-`x86_64` at `packaging/install.sh.in:19-21`; updater `_PLATFORM` is `linux-x86_64` at `releases.py:42`; managed-state parser requires `linux-x86_64` at `xferry/management/managed_state.py:333-345`; host support excludes Debian 13 and aarch64 at `xferry/management/model.py:55-65`.
  - Detail: Batch-1 was right that this is not a one-file change. Adding arm64/Debian 13 without one shared platform model can produce artifacts that one component publishes and another refuses, or rollback state that later becomes “unsupported.”
  - Impact: Public multi-arch release/update can fail closed on supported hosts, strand rollback inventory, or push operators toward manual unsafe recovery.
  - Confidence: High.

- [LOW] Known vulnerable pinned toolchain components remain in CI/docs constraints
  - File/area: `constraints/ci.txt`; supplied baseline pip-audit result.
  - Evidence: Supplied baseline says `pip-audit` found `mkdocs-material 9.7.6` with fix `9.7.7` and `pip 26.1.2` with fix `26.2`; pins are at `constraints/ci.txt:40` and `constraints/ci.txt:50`.
  - Detail: These are build/docs/tooling pins rather than direct runtime server dependencies, but they run in CI/release environments.
  - Impact: Avoidable supply-chain exposure in release automation and docs builds.
  - Confidence: Medium because I did not rerun `pip-audit` in this read-only pass; evidence relies on the provided verified baseline plus current pins.

## Concrete Recommendations

1. Supersede ADR-006 before enabling publication. Replace the source-only guards in `tools/check_stale_docs.py` and `tests/test_deployment_artifacts.py` with publication-safety guards requiring:
   - `on.push.tags: ["v*"]` or equivalent tag gate;
   - protected environments for PyPI, GHCR, and GitHub Release promotion;
   - no static publisher secrets for PyPI;
   - job-scoped permissions only.

2. Convert `.github/workflows/release.yml` into build-once/promote-exactly:
   - build wheel/sdist, SCIE assets, installer, manifest, checksums, SBOMs once;
   - upload them as workflow artifacts;
   - publish jobs download those exact artifacts and do not rebuild;
   - PyPI job: `environment: pypi`, `id-token: write`, Trusted Publishing;
   - GHCR job: `packages: write`, `id-token: write`, `attestations: write`, Buildx `platforms: linux/amd64,linux/arm64`, `sbom`, `provenance`;
   - GitHub Release job: protected environment, `contents: write`, upload exact assets and signatures.

3. Add a client-side release trust root before exposing `xferry update`.
   - Minimal launch version: signed release manifest, verified by an embedded public key in `xferry/management/releases.py`, covering version, tag, platform, executable name, size, SHA-256, source commit, workflow run, and artifact digests.
   - Keep GitHub artifact attestations/SBOMs as workflow-side provenance and incident response evidence.
   - Treat client-side Sigstore/GitHub attestation verification as a deeper improvement unless the team is ready to support that complexity at launch.

4. Make install docs verify before root execution.
   - Avoid `curl | sudo sh`.
   - Prefer: download `install.sh`, `install.sh.sig` or signed manifest, verify signature/checksum, then run `sudo sh install.sh`.
   - Keep the existing embedded binary hash check as a second layer.

5. Centralize release platform identity.
   - Replace hard-coded `linux-x86_64` in `tools/build_scie_release.py`, `packaging/install.sh.in`, `xferry/management/releases.py`, `xferry/management/managed_state.py`, and `xferry/management/model.py` with one shared platform matrix that covers `linux-x86_64` and `linux-aarch64`, plus Debian 13.

## Quick Wins

- Update `constraints/ci.txt` for `mkdocs-material` and `pip`, then rerun the existing security/docs gates.
- Add a release preflight that fails unless `vX.Y.Z == xferry.config.__version__`, changelog has that version, and artifact names use that version.
- Add tests that require action SHA pins to remain in publish workflows, extending `tools/check_toolchain_pins.py`.
- Add SECURITY/threat-model text for release/update trust boundaries before changing release YAML.
- Initially require `xferry update --to VERSION`; defer unsigned `latest` behavior until signed metadata is in place.

## Deeper Improvements

- Client-side verification of GitHub/Sigstore artifact attestations, not just signed manifests.
- TUF-style metadata with key rotation, expiry, threshold signatures, and rollback protection.
- Separate TestPyPI/staging and production release environments.
- Publish GHCR only by immutable version tags and digests; delay or tightly control `latest`.
- Add real arm64 managed-host smoke coverage, not only QEMU container build checks.
- Include release incident playbooks: yanking PyPI, deprecating GHCR tags, revoking signatures, and communicating rollback.

## Open Questions

- Who owns PyPI Trusted Publishing setup and protected GitHub environment approval?
- Is the public namespace definitely `kgmnotes/xferry` for PyPI, GHCR, and GitHub Releases?
- Should first public `xferry update` require explicit `--to VERSION`, or may signed `latest` launch immediately?
- Where should manifest signing keys live, and what is the rotation/revocation process?
- Are client-side Sigstore/GitHub attestation checks required at launch, or is signed manifest plus protected workflow acceptable?
- Is Debian 13/aarch64 mandatory for the first managed-release launch or staged after x86_64 parity?
