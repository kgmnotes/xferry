# qa-expert Report
_Generated: 2026-09-28 13:41:37 MSK_
_Source plan: /home/user/PycharmProjects/xferry/codex-analysis/20260928-131617/analysis-plan.md_

## Summary

Scope analyzed: `tests/`, `pyproject.toml`, `.github/workflows/`, `tools/verify_python_artifacts.py`, `tools/verify_docker_image.py`, `tools/docker_image_smoke.py`, `tools/build_scie_release.py`, `packaging/install.sh.in`, and `xferry/management/*`.

I validate the batch-1 findings: the repo still encodes source-only distribution, `linux-x86_64` managed artifacts, no public `xferry update`, and no PyPI/GHCR/GitHub Release publication path. I slightly refine the CI finding: there is a cross-platform job, but it is Python 3.12 only, uses editable install, and does not prove PyPI/pipx or wheel behavior on Windows/macOS.

No files were modified. I did not rerun the full test suite; this is read-only evidence review plus Context7 checks.

## Documentation Checks

Context7 used:

- GitHub Actions `/websites/github_en_actions`: confirms environment-gated publish jobs, `id-token: write` for OIDC, artifact promotion with upload/download, and `attestations: write`/`packages: write` where applicable.
- Python Packaging User Guide `/websites/packaging_python_en`: confirms Trusted Publishing, protected PyPI/TestPyPI environments, tag-gated PyPI publication, and `pipx install PACKAGE` as the standalone CLI install route.
- Docker Build Push Action `/docker/build-push-action`: confirms Buildx `platforms`, `push`, `tags`, `sbom`, and `provenance` inputs for multi-platform image publication.

Batch-1 doc/process findings are supported by repo evidence: `tools/check_stale_docs.py:164-190`, `tests/test_check_stale_docs.py:54-74`, and `tests/test_deployment_artifacts.py:413-473` actively forbid the new publication/update routes.

## Detailed Findings

Current portable coverage:

- `pyproject.toml:11` declares Python `>=3.10,<3.15`, and classifiers cover 3.10 through 3.14 at `pyproject.toml:35-40`.
- Full tests run only on Ubuntu for Python 3.10-3.14 in `.github/workflows/ci.yml:20-71`.
- Cross-platform smoke exists for `ubuntu-latest`, `macos-15`, and `windows-latest`, but only Python 3.12, editable install, and a small subset: `.github/workflows/ci.yml:233-273`.
- Wheel/sdist validation is strong on Linux via `tools/verify_python_artifacts.py:173-223` and offline install smoke at `tools/verify_python_artifacts.py:393-455`, but there is no equivalent Windows/macOS wheel or pipx consumer smoke.

Current Linux-only coverage:

- Management update/rollback internals are well covered: disabled update boundary at `tests/test_management_releases.py:297`, corruption at `:799`, platform mismatch at `:817`, successful update at `:1014`, restart failure at `:1208`, unhealthy candidate restore at `:1235`, and rollback target selection at `:1494`.
- Public CLI still excludes `update`: command tables omit it at `xferry/management/cli.py:21-40`, release dispatch only handles rollback/uninstall at `xferry/management/cli.py:329-342`, and tests assert absence at `tests/test_management_cli.py:182-195`.
- Managed platform support rejects arm64/Debian 13 today: `xferry/management/model.py:55-65`, `packaging/install.sh.in:19-40`, `tools/build_scie_release.py:115`, and `tests/test_management_planning.py:105-132`.

Smallest sufficient matrices:

- Portable CLI/PyPI/pipx: keep full Linux Python 3.10-3.14; add packaged wheel/pipx smoke on Windows, macOS, Linux for Python 3.10, 3.12, and 3.14. This covers floor, common stable, and ceiling without a 15-job full suite.
- Managed Linux: Ubuntu 22.04/24.04/26.04 and Debian 12/13 across `x86_64` and `arm64`. No Python fanout is needed for SCIE because it embeds CPython; the product risk is distro/arch/systemd.
- GHCR: `linux/amd64` and `linux/arm64` only, with pulled-image smoke by digest/tag on both architectures.

## Issues Found

- [HIGH] Release tests currently prove non-publication, not safe publication
  - File/area: `.github/workflows/release.yml`, `tests/test_deployment_artifacts.py`, `tools/check_stale_docs.py`
  - Evidence: release is `workflow_dispatch` only with `contents: read` at `.github/workflows/release.yml:3-7`; publish permissions/actions are forbidden at `tests/test_deployment_artifacts.py:454-473`; public install/update routes are forbidden at `tools/check_stale_docs.py:164-190`.
  - Detail: These guards must become positive safety assertions: tag-only publish, protected environment, artifact promotion, OIDC, attestations, no static secrets, and no PR/branch publication.
  - Impact: Public release work will either fail tests or bypass the current quality contract.
  - Confidence: High

- [HIGH] Portable consumer install coverage is missing for Windows/macOS and Python boundaries
  - File/area: `.github/workflows/ci.yml`, `tools/verify_python_artifacts.py`
  - Evidence: full Python matrix is Ubuntu-only at `.github/workflows/ci.yml:20-71`; cross-platform is Python 3.12 editable install at `.github/workflows/ci.yml:233-273`; artifact smoke is Linux workflow-bound at `.github/workflows/ci.yml:110-142` and `.github/workflows/release.yml:54-83`.
  - Detail: No CI lane installs the built wheel or a PyPI/TestPyPI package through `pipx` on Windows/macOS.
  - Impact: A PyPI release can pass Linux artifact checks while failing the confirmed portable CLI path.
  - Confidence: High

- [HIGH] Managed Linux matrix is currently unsupported beyond `linux-x86_64` and Debian 12
  - File/area: SCIE builder, installer, platform model, release tests
  - Evidence: builder emits `xferry-{version}-linux-x86_64` at `tools/build_scie_release.py:115`; installer rejects non-`x86_64` at `packaging/install.sh.in:19-21`; supported OS excludes Debian 13 and arm64 at `xferry/management/model.py:55-65`; tests assert aarch64 unsupported at `tests/test_management_planning.py:105-132`.
  - Detail: Multi-arch/distro support needs source changes plus tests before release lanes can be meaningful.
  - Impact: The target managed production matrix cannot be truthfully released or verified today.
  - Confidence: High

- [MEDIUM] GHCR multi-arch release acceptance is absent and release image verification is weaker than CI
  - File/area: `.github/workflows/release.yml`, `.github/workflows/ci.yml`, `tools/verify_docker_image.py`
  - Evidence: release only runs `docker build --tag xferry:release-smoke .` at `.github/workflows/release.yml:120-129`; CI runs `tools/verify_docker_image.py` before image smoke at `.github/workflows/ci.yml:473-480`; no release Buildx/GHCR/SBOM/provenance path exists.
  - Detail: Context7 Docker docs support Buildx `platforms`, `push`, `sbom`, and `provenance` for the target.
  - Impact: A release image could skip the internal-file surface scan and never prove arm64 runtime behavior.
  - Confidence: High

- [MEDIUM] Public `xferry update` acceptance does not exist at the CLI boundary
  - File/area: `xferry/management/cli.py`, `tests/test_management_cli.py`, `tests/test_management_releases.py`
  - Evidence: CLI command set omits update at `xferry/management/cli.py:21-40`; tests assert update is not public at `tests/test_management_cli.py:182-195`; internal manager defaults remote updates off at `xferry/management/releases.py:281-286`.
  - Detail: Internal update/rollback tests are strong, but they do not validate the future public command, help text, JSON output, non-Linux rejection, or exact-version/latest user flows.
  - Impact: Exposing update later could miss user-visible parser, permission, dry-run, and recovery failures.
  - Confidence: High

- [MEDIUM] Release-blocking tag/version/changelog and environment readiness are not encoded
  - File/area: `.github/workflows/release.yml`, version/docs guards
  - Evidence: release checks only supported source line at `.github/workflows/release.yml:43-52`; no `vX.Y.Z` trigger, protected release environment, artifact upload/download, PyPI/GHCR/GitHub Release publish, or tag/source/changelog consistency gate exists.
  - Detail: Context7/PyPA/GitHub docs support publishing from downloaded build artifacts in protected OIDC jobs.
  - Impact: A future publish workflow could rebuild different bytes, publish from the wrong tag, or ship without manual approval.
  - Confidence: High

## Concrete Recommendations

1. Replace source-only guards with publication safety guards before enabling publish jobs. Require `vX.Y.Z` tag, protected `release-production`/`pypi`/`ghcr` environments, exact artifact promotion, SHA-pinned actions, OIDC, attestations, no static publisher secrets, and explicit no-publish behavior on PRs/branches.

2. Add portable packaged acceptance:
   - Build wheel/sdist once.
   - Install the wheel outside the checkout on Windows/macOS/Linux for Python 3.10, 3.12, 3.14.
   - Run `pip check`, `xferry --help`, `xferry run --version`, `python -m xferry run --check-config`, and the portable unit subset.
   - Add `pipx install` smoke from TestPyPI/PyPI for the exact version before production PyPI.

3. Add managed Linux release acceptance:
   - Build SCIE assets for `linux-x86_64` and `linux-aarch64`.
   - Run installer/setup/status/doctor/update/rollback/uninstall on Ubuntu 22.04/24.04/26.04 and Debian 12/13 for both arches.
   - Include failure cases: bad checksum, wrong platform manifest, candidate config failure, unhealthy candidate, failed restore, non-root update, and ambiguous prior state.

4. Add GHCR acceptance:
   - Build/push with Buildx for `linux/amd64,linux/arm64`.
   - Pull by immutable digest/version tag.
   - Run `verify_docker_image.py` and `docker_image_smoke.py` on both architectures.
   - Publish SBOM/provenance and block release if either arch fails.

5. Define release-blocking go/no-go:
   - mypy, Ruff, full tests, docs strict build, docs guards, Bandit, pip-audit pass.
   - No medium/high dependency audit findings.
   - Tag/version/changelog/artifact names match.
   - PyPI, GHCR, GitHub Release assets are published from promoted artifacts only.
   - Post-publish pipx, docker pull, SCIE install, update, health check, and rollback smokes pass.

## Quick Wins

- Fix the known mypy blocker at `xferry/handlers/notepad.py:285`.
- Add `python tools/verify_docker_image.py --image xferry:release-smoke` to release image verification.
- Add Debian 13 and aarch64 tests that initially document current rejection, then flip when implementation lands.
- Add a release preflight test for `vX.Y.Z == xferry.config.__version__` and changelog presence.
- Expand cross-platform smoke from editable install to built-wheel install for Python 3.10 and 3.14.

## Deeper Improvements

- Introduce one shared platform/release artifact model used by builder, installer, release manager, managed-state parser, tests, and docs.
- Split portable CLI acceptance from Linux managed/systemd acceptance in CI naming and docs.
- Add a one-time TestPyPI rehearsal lane before first production PyPI release.
- Add real arm64 runner coverage if QEMU proves too slow or flaky for SCIE/systemd and Docker smokes.
- Add release notes generated from artifact digests, workflow run ID, source commit, GHCR digest, PyPI version, and rollback instructions.

## Open Questions

- Should the first public release include all managed distro/arch targets, or can arm64/Debian 13 be staged behind explicit docs?
- Will GHCR publish only immutable `vX.Y.Z` tags/digests, or also `latest`?
- Should `xferry update` default to latest, or require `--to VERSION` for the first public line?
- Who owns GitHub protected environment approvals and PyPI/TestPyPI Trusted Publisher setup?
- Is HTTPS plus manifest SHA-256 sufficient for update trust, or is client-side Sigstore/attestation verification required before activation?
