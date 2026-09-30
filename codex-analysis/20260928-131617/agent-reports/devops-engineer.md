# devops-engineer Report
_Generated: 2026-09-28 13:33:04 MSK_
_Source plan: /home/user/PycharmProjects/xferry/codex-analysis/20260928-131617/analysis-plan.md_

## Summary

Read-only DevOps audit of `/home/user/PycharmProjects/xferry` at commit `7f8e2c56e7eefe25a2270d37bece97ddf374a738`. Branch is `main`, ahead of `origin/main` by 29 commits. I did not modify files; the existing untracked `codex-analysis/` directory was left untouched.

Operational boundary analyzed: public release and managed deployment path for `xferry` — GitHub Actions control plane, Python package artifacts, Docker/GHCR image path, SCIE/systemd installer path, managed update/rollback path, and release documentation/tests.

Overall: the repository is intentionally source-only today. It has strong local verification primitives, but it is not yet safe or configured to publish PyPI packages, GHCR images, GitHub Release assets, or public remote updates. The smallest safe move is not “add publish steps”; it is to replace the source-only release policy with a protected, artifact-promoting release topology first.

No CRITICAL findings.

## Documentation Checks

Repository documentation/policy checked:

- [README.md](/home/user/PycharmProjects/xferry/README.md:21) says supported distribution is source checkout only.
- [ADR-006](/home/user/PycharmProjects/xferry/docs/ADR/ADR-006-release-artifacts.md:13) explicitly forbids PyPI, GHCR, GitHub Releases, and artifact uploads.
- [operations docs](/home/user/PycharmProjects/xferry/docs/operations.md:3) say remote updates are not public.
- [SECURITY.md](/home/user/PycharmProjects/xferry/SECURITY.md:10) says automation does not publish packages, binaries, or registry images.
- [tests/test_deployment_artifacts.py](/home/user/PycharmProjects/xferry/tests/test_deployment_artifacts.py:413) locks that policy in tests.

Context7 checks performed:

- GitHub Actions `/websites/github_en_actions`: artifact attestations require `attestations: write`, `contents: read`, `id-token: write`; container publishing also needs package write access; protected environments gate publish jobs with approvals. Sources included GitHub artifact attestation and protected environment docs.
- Docker Build Push Action `/docker/build-push-action`: confirmed release-relevant inputs: `platforms`, `push`, `tags`, `cache-from`, `cache-to`, `sbom`, and `provenance`.
- Python Packaging User Guide `/websites/packaging_python_en`: confirmed PyPI Trusted Publishing via GitHub Actions is the recommended path and requires `id-token: write`; `pipx` is the expected install path for standalone CLI apps.

## Detailed Findings

Control plane:

- Current release workflow is manual, read-only, and non-publishing: [release.yml](/home/user/PycharmProjects/xferry/.github/workflows/release.yml:3), [release.yml](/home/user/PycharmProjects/xferry/.github/workflows/release.yml:6), [release.yml](/home/user/PycharmProjects/xferry/.github/workflows/release.yml:201).
- Docs Pages already demonstrates a separate deployed environment with OIDC-like permissions: [docs-pages.yml](/home/user/PycharmProjects/xferry/.github/workflows/docs-pages.yml:8), [docs-pages.yml](/home/user/PycharmProjects/xferry/.github/workflows/docs-pages.yml:21). Release should use a separate protected environment, not reuse docs deployment.

Artifact/data plane:

- Python artifacts are built and offline-smoked: [release.yml](/home/user/PycharmProjects/xferry/.github/workflows/release.yml:54), [verify_python_artifacts.py](/home/user/PycharmProjects/xferry/tools/verify_python_artifacts.py:393).
- Docker image is built only locally: [release.yml](/home/user/PycharmProjects/xferry/.github/workflows/release.yml:120).
- SCIE bundle is built only for `linux-x86_64`: [build_scie_release.py](/home/user/PycharmProjects/xferry/tools/build_scie_release.py:115), [build_scie_release.py](/home/user/PycharmProjects/xferry/tools/build_scie_release.py:170).

Runtime/update path:

- Installer/systemd/update design has useful rollback controls, but only for the currently supported `linux-x86_64` release shape.
- Public CLI exposes rollback/uninstall, not update: [cli.py](/home/user/PycharmProjects/xferry/xferry/management/cli.py:34), [cli.py](/home/user/PycharmProjects/xferry/xferry/management/cli.py:158), [cli.py](/home/user/PycharmProjects/xferry/xferry/management/cli.py:333).
- Update is internally disabled by default before network/filesystem boundaries: [releases.py](/home/user/PycharmProjects/xferry/xferry/management/releases.py:262), [releases.py](/home/user/PycharmProjects/xferry/xferry/management/releases.py:283).

Validation observed from repository/tests:

- Normal path covered: Python artifact build/offline smoke, Docker local lifecycle smoke, SCIE build/checksum/systemd-base smoke.
- Failure path covered: remote update disabled, corrupt payload rejection, platform mismatch rejection, candidate config/health failure.
- Recovery path covered: rollback, failed update restore, uninstall preserve/purge behavior.

Live verification still required: GitHub protected environments, PyPI Trusted Publishing project mapping, GHCR package permissions/visibility, actual multi-arch Docker build, arm64 runner/QEMU behavior, and SCIE smoke on real target hosts.

## Issues Found

- [HIGH] Release publication is intentionally blocked by policy, workflow, docs, and tests
  - File/area: GitHub Actions release workflow, ADR/docs, release policy tests.
  - Evidence: [release.yml](/home/user/PycharmProjects/xferry/.github/workflows/release.yml:4) is manual-only; [release.yml](/home/user/PycharmProjects/xferry/.github/workflows/release.yml:6) has only `contents: read`; [release.yml](/home/user/PycharmProjects/xferry/.github/workflows/release.yml:210) confirms verification “without publication”; [ADR-006](/home/user/PycharmProjects/xferry/docs/ADR/ADR-006-release-artifacts.md:13) forbids PyPI/GHCR/GitHub Releases; [tests/test_deployment_artifacts.py](/home/user/PycharmProjects/xferry/tests/test_deployment_artifacts.py:454) forbids the exact publish/attestation permissions and actions needed.
  - Detail: Publishing is not merely missing YAML; the repository deliberately encodes source-only distribution as an architecture boundary.
  - Impact: Any direct PyPI/GHCR/GitHub Release enablement would either fail tests or bypass documented release safety.
  - Confidence: High.

- [HIGH] Target platform support is hard-coded to `linux-x86_64`
  - File/area: SCIE builder, installer, managed release/update model.
  - Evidence: [build_scie_release.py](/home/user/PycharmProjects/xferry/tools/build_scie_release.py:115) emits `xferry-{version}-linux-x86_64`; [install.sh.in](/home/user/PycharmProjects/xferry/packaging/install.sh.in:19) rejects non-`x86_64`; [releases.py](/home/user/PycharmProjects/xferry/xferry/management/releases.py:42) defines `_PLATFORM = "linux-x86_64"`; [model.py](/home/user/PycharmProjects/xferry/xferry/management/model.py:55) supports Ubuntu 22.04/24.04/26.04 and Debian 12 only; [tests/test_management_planning.py](/home/user/PycharmProjects/xferry/tests/test_management_planning.py:113) asserts `aarch64` is unsupported.
  - Detail: Multi-platform publication would need changes across artifact names, manifest schema expectations, installer OS/arch detection, tests, and update selection.
  - Impact: Debian 13 and arm64/aarch64 public release targets cannot install or update safely through the current SCIE path.
  - Confidence: High.

- [HIGH] No immutable artifact promotion or provenance path exists
  - File/area: `.github/workflows/release.yml`, artifact verification/publishing boundary.
  - Evidence: Python, Docker, and SCIE jobs build and verify local outputs, but the release gate only echoes completion: [release.yml](/home/user/PycharmProjects/xferry/.github/workflows/release.yml:54), [release.yml](/home/user/PycharmProjects/xferry/.github/workflows/release.yml:120), [release.yml](/home/user/PycharmProjects/xferry/.github/workflows/release.yml:157), [release.yml](/home/user/PycharmProjects/xferry/.github/workflows/release.yml:201). Tests currently forbid `actions/upload-artifact`, `actions/download-artifact`, and `actions/attest`: [tests/test_deployment_artifacts.py](/home/user/PycharmProjects/xferry/tests/test_deployment_artifacts.py:454).
  - Detail: A safe release pipeline should build once, preserve exact artifacts, verify those artifacts, then publish the same bytes from a protected job. Current jobs discard their outputs.
  - Impact: If publication is added naively, publish jobs may rebuild different artifacts or publish unverifiable outputs.
  - Confidence: High.

- [MEDIUM] PyPI/pipx release path is absent despite package readiness
  - File/area: Python packaging and release workflow.
  - Evidence: Package metadata and console script exist: [pyproject.toml](/home/user/PycharmProjects/xferry/pyproject.toml:5), [pyproject.toml](/home/user/PycharmProjects/xferry/pyproject.toml:56). Offline artifact smoke is already present: [verify_python_artifacts.py](/home/user/PycharmProjects/xferry/tools/verify_python_artifacts.py:393). But release tests forbid `gh-action-pypi-publish` and `pypi.org`: [tests/test_deployment_artifacts.py](/home/user/PycharmProjects/xferry/tests/test_deployment_artifacts.py:461).
  - Detail: Context7/PyPA docs recommend Trusted Publishing with `id-token: write`, tag gating, and a PyPI environment.
  - Impact: Users cannot install `xferry` through PyPI/pipx; ad-hoc publishing would risk static token leakage or unapproved releases.
  - Confidence: High.

- [MEDIUM] GHCR/multi-arch Docker release path is absent
  - File/area: Dockerfile, Docker compose, release workflow.
  - Evidence: Dockerfile uses a digest-pinned base: [Dockerfile](/home/user/PycharmProjects/xferry/Dockerfile:7). Release workflow only runs `docker build --tag xferry:release-smoke .`: [release.yml](/home/user/PycharmProjects/xferry/.github/workflows/release.yml:120). Public-direct compose builds locally as `xferry:public-direct-local`: [docker-compose.public-direct.yml](/home/user/PycharmProjects/xferry/deploy/docker/docker-compose.public-direct.yml:5). Tests assert no GHCR image reference: [tests/test_deployment_artifacts.py](/home/user/PycharmProjects/xferry/tests/test_deployment_artifacts.py:468).
  - Detail: Context7/Docker docs indicate Buildx should own `platforms`, `push`, `tags`, `sbom`, and `provenance`.
  - Impact: No supported `docker pull ghcr.io/...` path; no multi-arch manifest; no registry provenance or digest for rollback/promotion.
  - Confidence: High.

- [MEDIUM] Public update command cannot be enabled safely until release manifests/assets are redesigned
  - File/area: Management CLI and release manager.
  - Evidence: CLI command set excludes `update`: [cli.py](/home/user/PycharmProjects/xferry/xferry/management/cli.py:24), [cli.py](/home/user/PycharmProjects/xferry/xferry/management/cli.py:34). Tests assert update is not public: [tests/test_management_cli.py](/home/user/PycharmProjects/xferry/tests/test_management_cli.py:186). Remote update defaults disabled before boundaries: [releases.py](/home/user/PycharmProjects/xferry/xferry/management/releases.py:283), [tests/test_management_releases.py](/home/user/PycharmProjects/xferry/tests/test_management_releases.py:297). Manifest download verifies HTTPS plus size/hash: [releases.py](/home/user/PycharmProjects/xferry/xferry/management/releases.py:434), [releases.py](/home/user/PycharmProjects/xferry/xferry/management/releases.py:453).
  - Detail: The updater has good local rollback mechanics, but it currently depends on a single-platform manifest and does not verify a release signature/attestation client-side.
  - Impact: Prematurely exposing `xferry update` could make hosts depend on an incomplete public artifact topology.
  - Confidence: High.

- [MEDIUM] Release tag/version/changelog invariants are incomplete for public publishing
  - File/area: Release workflow, version source, changelog.
  - Evidence: Release workflow checks only that source version is a supported release line: [release.yml](/home/user/PycharmProjects/xferry/.github/workflows/release.yml:43). It is `workflow_dispatch` only: [release.yml](/home/user/PycharmProjects/xferry/.github/workflows/release.yml:4). Source version is `0.1.0`: [config.py](/home/user/PycharmProjects/xferry/xferry/config.py:6). Changelog has only `0.1.0`: [CHANGELOG.md](/home/user/PycharmProjects/xferry/CHANGELOG.md:5).
  - Detail: There is no repository-level release gate proving `refs/tags/vX.Y.Z` matches `xferry.config.__version__`, changelog entry, artifact names, and release notes.
  - Impact: A public release could publish a tag/source/version mismatch.
  - Confidence: High.

- [MEDIUM] Current CI appears blocked by supplied mypy baseline
  - File/area: CI type-check lane and notepad handler.
  - Evidence: CI runs `mypy xferry`: [ci.yml](/home/user/PycharmProjects/xferry/.github/workflows/ci.yml:68). Mypy is strict: [pyproject.toml](/home/user/PycharmProjects/xferry/pyproject.toml:147). Pinned mypy is `1.20.1`: [constraints/ci.txt](/home/user/PycharmProjects/xferry/constraints/ci.txt:43). Supplied baseline says failure is at [notepad.py](/home/user/PycharmProjects/xferry/xferry/handlers/notepad.py:285).
  - Detail: I did not rerun mypy to avoid cache/output writes; this finding depends on the provided baseline.
  - Impact: A protected release job should not publish while normal CI is red.
  - Confidence: Medium.

## Concrete Recommendations

Smallest safe recommendation: implement a controlled release boundary before any public publication.

Preferred sequence:

1. Replace ADR-006/source-only policy with a reviewed release ADR covering PyPI, GHCR, GitHub Releases, SCIE assets, update/rollback, and immutable-version rules.
2. Update the policy tests that currently forbid publication, but keep them strict: require protected environments, minimal permissions, SHA-pinned actions, artifact promotion, and no static publisher secrets.
3. Make `vX.Y.Z` the release authority. Gate release jobs on tag/source/changelog consistency: `vX.Y.Z == xferry.config.__version__`, changelog entry exists, artifact names match.
4. Build once, verify once, and publish exact promoted artifacts:
   - Upload wheel/sdist, SCIE bundle(s), installer(s), SBOMs, checksums, and manifest(s) as workflow artifacts.
   - Download those artifacts in publish jobs.
   - Do not rebuild inside publish jobs.
5. Add protected publish jobs:
   - PyPI: protected `pypi` environment, `id-token: write`, pinned `pypa/gh-action-pypi-publish`, publish wheel/sdist only from downloaded artifacts.
   - GHCR: protected environment, `packages: write`, `contents: read`, `attestations: write`, `id-token: write`, pinned Docker actions, Buildx `platforms: linux/amd64,linux/arm64`, `sbom: true`, `provenance: true`.
   - GitHub Release: protected release environment, `contents: write`, upload exact SCIE assets, installers, manifests, checksums, SBOMs, and digest/provenance references.
6. Only after that, expose `xferry update` with `--dry-run`, `--to VERSION`, and `--json`, wired to a manager that explicitly opts into remote updates for that command path.

Validation expectations:

- Normal path: tag build → artifact verification → protected approval → PyPI/GHCR/GitHub Release publish → pipx/docker/installer smoke.
- Failure path: block publish on CI/mypy failure, artifact mismatch, missing attestation, PyPI/GHCR auth failure, Docker multi-arch smoke failure, or SCIE health failure.
- Recovery path: never reuse PyPI versions; avoid mutable `latest` initially; use immutable GHCR version tags/digests; keep previous SCIE release retained for `xferry rollback`; yank/deprecate bad releases rather than overwriting artifacts.

## Quick Wins

- Fix the supplied mypy blocker before release work.
- Add a release preflight script that checks tag/version/changelog consistency.
- Draft the replacement ADR for controlled publication.
- Convert `release.yml` from “verify and discard” to “verify and upload workflow artifacts,” still without external publication at first.
- Add a protected `release-production` environment name to future publish jobs and document required approvers.
- Add Debian 13 and aarch64 support tests before changing installer/update behavior.

## Deeper Improvements

- Redesign release manifests for multiple platforms and possibly multiple artifact kinds.
- Add native or QEMU-backed arm64 Docker and SCIE smoke tests.
- Add client-side release signature/attestation verification if the threat model requires protection beyond HTTPS plus manifest SHA-256.
- Add release observability: published artifact digests, workflow run ID, source commit, package URLs, GHCR manifest digest, and rollback instructions in every release note.
- Separate candidate, staging/TestPyPI, and production release environments if releases become frequent or operator approval needs audit trails.

## Open Questions

- Is the intended public namespace definitely `kgmnotes/xferry` for PyPI, GHCR, and GitHub Releases?
- Should Debian 13 be a required supported host immediately, or staged after Debian 12 parity?
- Is arm64/aarch64 required for both Docker and SCIE/systemd installer, or Docker first?
- Should `latest` ever be published, or only immutable version tags?
- Who owns PyPI Trusted Publishing setup and GitHub protected-environment approval?
- Is GitHub Release + manifest SHA-256 sufficient for updates, or should the client verify Sigstore/GitHub attestations before switching `/opt/xferry/current`?
- Should public `xferry update` default to latest, or require `--to VERSION` for the first public release line?
