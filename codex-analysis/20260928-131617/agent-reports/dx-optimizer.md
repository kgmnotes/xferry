# dx-optimizer Report
_Generated: 2026-09-28 13:44:16 MSK_
_Source plan: /home/user/PycharmProjects/xferry/codex-analysis/20260928-131617/analysis-plan.md_

## Summary

Read-only DX audit completed. No repository files were modified.

Workflow/tool boundary analyzed: install-to-first-success and day-2 lifecycle for three user journeys: portable PyPI/pipx CLI on Windows/macOS/Linux, managed Linux systemd install/update/rollback/uninstall, and Docker/GHCR container use.

Primary friction source: the repo is internally consistent around the old source-only, Linux x86_64 model, while the confirmed product target is public pipx/PyPI, GHCR, GitHub Releases, and managed Linux update. That old model is encoded in docs, CLI help, release code, and tests, so the batch-1 conclusion is correct: this is not a one-page docs fix.

DX-specific challenge to batch-1: the release/publishing work should be sequenced around user journeys, not artifact taxonomy. The smallest safe intervention is to define and test the three default journeys and keep portable CLI UX separate from managed-Linux lifecycle UX.

Validations performed:

- Normal path: inspected `xferry run --help` and `xferry run --version`; the portable `run` help is strong and journey-oriented.
- Failure path: inspected `xferry update --help`, `xferry status`, `xferry doctor`, and rollback dry-run behavior; public update is absent and several errors are stable but not yet actionable.
- Integration edge: inspected docs/tests/release/Compose/systemd/update paths against current PyPA, Docker, and systemd guidance via Context7.

## Documentation Checks

Repository docs and contracts checked:

- `README.md`, `docs/index.md`, `docs/quick-start.md`, `docs/operations.md`, `docs/scenarios.md`, `docs/public-direct.md`
- `CONTRIBUTING.md`, `SECURITY.md`, `docs/security.md`, `docs/ADR/ADR-006-release-artifacts.md`
- `deploy/docker/docker-compose.public-direct.yml`, `examples/docker/docker-compose.yml`, `Dockerfile`
- `deploy/systemd/install-systemd.sh`, `xferry/management/data/xferry.service`, `packaging/install.sh.in`
- `xferry/management/cli.py`, `xferry/cli.py`, `xferry/management/i18n.py`, `xferry/management/service.py`, `xferry/management/setup.py`, `xferry/management/releases.py`
- Representative tests: `tests/test_management_cli.py`, `tests/test_management_releases.py`, `tests/test_management_planning.py`, `tests/test_docker_first_docs.py`, `tests/test_deployment_artifacts.py`, `tests/test_check_stale_docs.py`

Context7 checks:

- Python Packaging User Guide `/websites/packaging_python_en`: confirmed pipx guidance for standalone Python CLI apps, including Unix/macOS `python3 -m pip install --user pipx`, Windows `py -m pip install --user pipx`, `pipx ensurepath`, and `pipx install PACKAGE`. Direct `pipx` library resolution was unavailable; Context7 resolved `pipx` oddly to `uv`, so PyPA packaging docs were used.
- Docker `/docker/docs`: confirmed Docker image references support `IMAGE[:TAG][@DIGEST]`, tags default to `latest`, health state can be inspected, and amd64 emulation on Apple Silicon is best-effort. Impact: public docs should prefer immutable version tags/digests and real multi-arch images.
- systemd `/systemd/systemd`: confirmed failed starts point operators to `systemctl status` and the journal, and `Restart=on-failure` is recommended for long-running services. Current unit already uses `Restart=on-failure`.

## Detailed Findings

Current documented source journey:

| Journey | Current prerequisites | Current commands to first success | Ambiguity |
| --- | --- | ---: | --- |
| Source/POSIX quick start | Git, Python 3.10-3.14, venv/pip, POSIX shell | 6: clone, cd, venv, activate, install, run | Accurate today, but wrong default for pipx/Windows/macOS target |
| pipx target, pipx already installed | Python, pipx on PATH | 2: `pipx install xferry`, `xferry run --preset local --open` | Blocked because PyPI artifact does not exist and docs forbid package install |
| pipx target, bootstrap needed | Python, pip, shell restart/PATH | 4 + terminal restart: install pipx, ensurepath, install xferry, run | Needs OS-specific Windows `py` vs Unix/macOS `python3` wording |
| Managed Linux target | Ubuntu/Debian + systemd + root/sudo + release asset + network mode decision | Ideally 3-4: install, setup, status/doctor, optional logs | Current code/docs support only linux x86_64 and no public update |
| Docker/GHCR target | Docker | Ideally 1: `docker run ghcr.io/...:vX.Y.Z`, or 1 compose up using `image:` | Current examples build local images from source checkout |

Batch-1 conclusions validated:

- Source-only policy is real: `README.md:21-35`, `docs/quick-start.md:3-21`, `docs/index.md:20-22`, `ADR-006:13-15`, `SECURITY.md:10-11`.
- Docs/tests actively block new public install docs: `tests/test_check_stale_docs.py:54-60` flags `xferry update`, GHCR, and publisher routes; `tests/test_deployment_artifacts.py:454-473` forbids upload/download artifacts, GHCR, PyPI, write permissions, and publisher actions.
- Public update is absent: `xferry/management/cli.py:21-40` lists commands and has only `rollback` as maintenance; `tests/test_management_cli.py:182-195` asserts update is not public; `xferry/management/releases.py:283-286` disables update by default.
- Managed platform target is not implemented: `xferry/management/model.py:55-65` supports Ubuntu 22.04/24.04/26.04 and Debian 12 on x86_64 only; `packaging/install.sh.in:19-39` rejects non-x86_64 and Debian 13; `tests/test_management_planning.py:105-114` asserts aarch64 unsupported.
- Docker publication is absent: `examples/docker/docker-compose.yml:1-13` and `deploy/docker/docker-compose.public-direct.yml:5-8` build local images; release workflow only builds `xferry:release-smoke` at `.github/workflows/release.yml:120-129`.

User-simplicity additions:

- `xferry run --help` is the best current UX artifact: it gives local, local-secure, and public-direct launch journeys in `xferry/cli.py:160-176`.
- Top-level help is management-heavy: `xferry/management/i18n.py:23-31` examples mix `xferry run` with `sudo xferry setup/status`, and `_LINUX_MANAGEMENT_COMMANDS` gates most commands to Linux in `xferry/management/cli.py:40` and `515-517`.
- Diagnostics are telemetry-free and JSON-capable, but terse. `ServiceStatus.to_json()` avoids secrets at `xferry/management/service.py:58-68`; `DoctorReport.to_json()` does the same at `service.py:94-103`. However, non-root status returns only unknown fields, and non-root doctor only says root is required.

## Issues Found

- [HIGH] Public onboarding is still source/POSIX-first instead of pipx-first
  - File/area: README, quick start, docs index, docs tests.
  - Evidence: `README.md:21-35` and `docs/quick-start.md:3-21` require source checkout, venv, POSIX activation, and local install. `docs/index.md:13-22` routes users to “Install from source.” `pyproject.toml:34` says OS Independent and `pyproject.toml:56-57` exposes the `xferry` console script.
  - Detail: The package is shaped like a portable CLI, but the default user path is contributor-style source setup.
  - Impact: Windows/macOS/Linux pipx users do not have a short, supported first-success path.
  - Confidence: High.

- [HIGH] Managed update is implemented internally but intentionally undiscoverable
  - File/area: Management CLI, release manager, tests, operations docs.
  - Evidence: `xferry/management/releases.py:283-326` has update logic with manifest/download/health gates, but `remote_updates_enabled` defaults false at `releases.py:262` and returns `remote_updates_disabled` at `releases.py:285-286`. CLI command lists omit `update` at `xferry/management/cli.py:21-40`; tests assert that at `tests/test_management_cli.py:182-195`; operations docs say remote updates are not exposed at `docs/operations.md:3-6`.
  - Detail: The safety mechanics exist, but the public UX contract and release artifact trust root do not.
  - Impact: The confirmed `xferry update` target cannot be documented or used without changing CLI/tests/release topology together.
  - Confidence: High.

- [HIGH] Managed platform wording and enforcement do not match the target matrix
  - File/area: Managed platform model, installer, release manifest platform, tests.
  - Evidence: `xferry/management/model.py:55-65` requires x86_64 and omits Debian 13; `packaging/install.sh.in:19-39` says Linux x86_64 and Ubuntu/Debian 12 only; `xferry/management/releases.py:42` hard-codes `linux-x86_64`; `tests/test_management_planning.py:113` asserts aarch64 unsupported.
  - Detail: This affects installer acceptance, setup preflight, release selection, rollback metadata, and docs.
  - Impact: arm64 and Debian 13 users will fail before first success, often with generic platform wording.
  - Confidence: High.

- [MEDIUM] Portable CLI UX and managed-Linux lifecycle UX are blended at the top level
  - File/area: Root help, examples, Linux command gate.
  - Evidence: Root help says “Manage an installed XFerry service or run the server,” then lists `setup/status/logs/start/stop/restart/doctor/credentials/uninstall` beside `run`; examples include `sudo xferry setup/status` from `xferry/management/i18n.py:27-45`. Non-Linux management commands fail through `xferry/management/cli.py:515-517`.
  - Detail: This is sensible for operators, but confusing for pipx users on Windows/macOS whose normal update/uninstall path should be `pipx upgrade/uninstall`, not `sudo xferry update/uninstall`.
  - Impact: Users must infer which commands apply to their install type.
  - Confidence: High.

- [MEDIUM] Managed diagnostics are stable but not sufficiently actionable
  - File/area: `status`, `doctor`, setup preflight, release result text.
  - Evidence: Non-root status returns unknown fields with exit 3; doctor says `managed diagnostics require root`. Preflight collapses platform, port, and firewall failures to short messages at `xferry/management/setup.py:703-723`. Platform failure text in `planning.py:149-154` says supported OS, x86_64, and systemd without reporting detected OS/arch/systemd.
  - Detail: The commands avoid leaking secrets, which is good, but they do not consistently tell the operator the next command to run.
  - Impact: Common install failures cause context switching to docs or systemd rather than self-service recovery.
  - Confidence: High.

- [MEDIUM] Docker first success is still a source-build path, not a GHCR path
  - File/area: Docker examples, release workflow, docs tests.
  - Evidence: `examples/docker/docker-compose.yml:1-13` builds `xferry:local`; `deploy/docker/docker-compose.public-direct.yml:5-8` builds `xferry:public-direct-local`; release workflow builds only `xferry:release-smoke` at `.github/workflows/release.yml:120-129`; tests require source-build labels at `tests/test_docker_first_docs.py:63-73`.
  - Detail: The Dockerfile itself is strong: non-root runtime, healthcheck, and sane default command at `Dockerfile:56-67`.
  - Impact: Container users cannot copy a GHCR pull/run command or compose file for public artifacts.
  - Confidence: High.

- [LOW] Root command lacks small conventional affordances for package users
  - File/area: Root CLI.
  - Evidence: `xferry run --version` works through `xferry/cli.py:201`, but `python -m xferry --version` returns a generic usage error. Unknown commands, including `update`, show root help plus `usage error` rather than “unknown command.”
  - Detail: This is minor but visible immediately after pipx install.
  - Impact: First-run verification is less natural than `xferry --version`.
  - Confidence: Medium.

## Concrete Recommendations

Smallest coherent intervention: create a journey contract before changing publication mechanics.

1. Supersede the source-only ADR and tests with a user-journey release contract.
   - Keep source checkout as “Contributor from source.”
   - Add public user journeys: “Portable CLI with pipx,” “Managed Linux service,” and “Container with GHCR.”
   - Tradeoff: more docs/test changes up front, but prevents piecemeal publication drift.

2. Separate portable and managed UX explicitly.
   - Portable: `pipx install xferry`, `xferry run --preset local --open`, `xferry run --check-config`, `pipx upgrade xferry`, `pipx uninstall xferry`.
   - Managed Linux: installer, `sudo xferry setup`, `sudo xferry status`, `sudo xferry doctor --deep`, `sudo xferry update`, `sudo xferry rollback`, `sudo xferry uninstall`.
   - Tradeoff: top-level help may need a compact decision tree, but it lowers cognitive load.

3. Define command acceptance criteria.
   - `xferry --version` works after pipx install.
   - `xferry help` groups commands by install type: portable, managed Linux, maintenance.
   - `xferry update --help` exists only when the release topology is ready, and says “managed Linux only.”
   - All managed commands support `--json` where useful and return stable `code`, `message`, `detail`, and `next_actions`.

4. Define docs acceptance criteria.
   - Quick start opens with pipx tabs/blocks for Windows, macOS, and Linux.
   - Managed install docs show supported distro/arch matrix, root expectations, systemd requirement, setup modes, first health check, update/rollback/uninstall.
   - Docker docs show immutable GHCR version tag and optional digest, plus Compose using `image: ghcr.io/...`.
   - Source checkout moves to contributor docs.

5. Improve telemetry-free diagnostics.
   - Add no network telemetry. Instead, make `xferry doctor --json` the support artifact.
   - Include detected OS, version, arch, systemd presence, current release, service state, config state, endpoint state, and suggested local commands.
   - Keep secrets redacted, matching current JSON design.

## Quick Wins

- Add `xferry --version` at the management root.
- Improve unknown command errors: `unknown command 'update'; run 'xferry help'`.
- Add `--lang en` or `XFERRY_LANG=en` to any future generated CLI docs so canonical docs remain English.
- Extend `doctor`/`status` non-root output with “rerun with sudo” in text and `next_actions` in JSON.
- Update managed platform error wording to include detected OS/arch/systemd and the supported matrix.
- Add a docs decision tree stub before publication, even if public artifact sections remain marked “planned.”

## Deeper Improvements

- Replace duplicated platform literals with one platform/support matrix used by installer, release manifest, setup preflight, tests, and docs.
- Introduce public `xferry update --dry-run --json` only after protected release artifacts exist.
- Add GHCR examples with version tags/digests and healthcheck inspection.
- Add packaged-artifact first-run CI: pipx-style wheel install on Windows/macOS/Linux, GHCR pull/run, and managed installer smoke on x86_64 + arm64 targets.
- Generate a CLI reference from real help output and assert it stays synchronized.
- Preserve current source/checkout Docker examples under contributor docs so existing productive workflows do not break.

## Open Questions

- What exact public namespace should docs use for PyPI, GHCR, and GitHub Releases?
- Should managed `setup` default to public sslip mode, or should docs steer first-time operators to `--private` unless they explicitly choose public exposure?
- Should `xferry update` default to latest, or require `--to VERSION` for the first public release line?
- Will public docs mention Russian CLI localization, or keep localization undocumented while canonical docs remain English?
- Should `latest` ever be published for GHCR, or should v1 start with immutable tags/digests only?
