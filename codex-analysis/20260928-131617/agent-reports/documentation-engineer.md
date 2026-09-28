# documentation-engineer Report
_Generated: 2026-09-28 13:31:06 MSK_
_Source plan: /home/user/PycharmProjects/xferry/codex-analysis/20260928-131617/analysis-plan.md_

## Summary

Read-only documentation audit completed for `/home/user/PycharmProjects/xferry`. No repository files were modified; `git status --short` still shows only pre-existing `?? codex-analysis/`.

Primary result: the current documentation, ADRs, docs guards, CLI, release workflow, and platform code are consistently source-only. Enabling public publication/update workflows is not a docs-only change; ADR-006, stale-doc guards, tests, release automation, platform constants, and operator docs must change together.

## Documentation Checks

Analyzed boundary:

- User docs: `README.md`, `docs/index.md`, `docs/quick-start.md`, `docs/scenarios.md`
- Operator docs: `docs/operations.md`, `docs/public-direct.md`, `deploy/docker/*`, `deploy/systemd/*`, `packaging/install.sh.in`
- Developer docs: `CONTRIBUTING.md`, `docs/architecture.md`, `docs/frontend-contract.md`, `docs/ADR/*`
- API docs: root `API.md` canonical; `docs/api.md` generated mirror
- Security docs: root `SECURITY.md` canonical; `docs/security.md` generated mirror; `docs/threat-model.md`
- Guards/generated regions: `tools/check_stale_docs.py`, `tools/sync_docs.py`, `tools/render_settings.py`, `tools/render_contracts.py`, related tests and CI hooks

Validated:

- `python tools/check_public_surface.py`
- `python tools/check_stale_docs.py`
- `python tools/render_settings.py --check`
- `python tools/render_contracts.py --check`
- `python tools/sync_docs.py --check`
- `python -m xferry help`
- Failure-path check: `python -m xferry update --help` exits `2`
- Context7 checked MkDocs validation guidance for MkDocs 1.6 strict/link/nav validation.

## Detailed Findings

Current docs are internally consistent, but consistent around the old source-only decision. `ADR-006` is accepted and says distribution is only from reviewed source checkouts. The stale-doc checker enforces that same policy and actively rejects `xferry update`, `pip install xferry`, GHCR image references, release URLs, publisher actions, and secrets-backed publication workflows.

The main friction point is therefore policy/tooling drift against the desired future publication workflow. If publication is enabled before superseding ADR-006 and updating guards, new docs will either fail checks or describe behavior the CLI/release system does not provide.

MkDocs docs tooling is mostly healthy, but `mkdocs.yml` lacks an explicit `validation:` block. Context7's MkDocs docs show that validation warnings for omitted nav files, anchors, unrecognized links, and absolute links can be promoted to strict-build failures by `mkdocs build --strict`.

## Issues Found

- [HIGH] Publication docs are blocked by accepted ADR-006 and stale-doc guards
  - File/area: `[docs/ADR/ADR-006-release-artifacts.md](/home/user/PycharmProjects/xferry/docs/ADR/ADR-006-release-artifacts.md:1)`, `[README.md](/home/user/PycharmProjects/xferry/README.md:21)`, `[docs/quick-start.md](/home/user/PycharmProjects/xferry/docs/quick-start.md:3)`, `[tools/check_stale_docs.py](/home/user/PycharmProjects/xferry/tools/check_stale_docs.py:164)`
  - Evidence: ADR-006 is “accepted” and “Source-only distribution”; README and quick start say workflows do not publish packages, binaries, releases, or registry images; stale-doc guards reject update/publish/public-install routes.
  - Detail: `tools/check_stale_docs.py` lines 164–190 ban `xferry update`, publisher actions, GHCR, releases/latest, and `pip install xferry`; lines 385–440 require source-checkout install wording; lines 593–610 require ADR-006 to remain accepted.
  - Impact: Public PyPI/GHCR/GitHub Release/update docs cannot be added safely without changing the governing ADR and tests first.
  - Confidence: High

- [HIGH] `xferry update` is not a public CLI command
  - File/area: `[xferry/management/cli.py](/home/user/PycharmProjects/xferry/xferry/management/cli.py:21)`, `[xferry/management/releases.py](/home/user/PycharmProjects/xferry/xferry/management/releases.py:262)`
  - Evidence: Public commands list includes `rollback` but not `update`; `python -m xferry update --help` exits `2`; release manager defaults `remote_updates_enabled=False`.
  - Detail: CLI routing handles rollback/uninstall only at `xferry/management/cli.py:329–342`.
  - Impact: Any operator docs for `xferry update` would currently be false.
  - Confidence: High

- [MEDIUM] Managed platform support does not match the target publication matrix
  - File/area: `[xferry/management/model.py](/home/user/PycharmProjects/xferry/xferry/management/model.py:55)`, `[packaging/install.sh.in](/home/user/PycharmProjects/xferry/packaging/install.sh.in:19)`, `[xferry/management/releases.py](/home/user/PycharmProjects/xferry/xferry/management/releases.py:42)`
  - Evidence: Supported OS list is Ubuntu 22.04/24.04/26.04 and Debian 12 only; host support requires `x86_64`; installer says Linux x86_64 only; release platform is `linux-x86_64`.
  - Detail: Debian 13 and aarch64 are absent from code and installer validation.
  - Impact: Docs cannot promise Debian 13 or aarch64 managed installs/updates until code, packaging, CI, and docs share one platform matrix.
  - Confidence: High

- [MEDIUM] Quick start is source/POSIX-only and does not cover future pipx/Windows/macOS install paths
  - File/area: `[docs/quick-start.md](/home/user/PycharmProjects/xferry/docs/quick-start.md:3)`, `[README.md](/home/user/PycharmProjects/xferry/README.md:21)`
  - Evidence: Quick start says no PyPI/GitHub Release/GHCR, then uses `git clone`, `python3 -m venv`, POSIX activation, and shell/curl examples.
  - Detail: This is accurate today, but it will not support a native published CLI journey across Linux/macOS/Windows.
  - Impact: Future users would lack the shortest safe install path and platform-specific recovery commands.
  - Confidence: High

- [MEDIUM] MkDocs strict mode is missing explicit validation hardening
  - File/area: `[mkdocs.yml](/home/user/PycharmProjects/xferry/mkdocs.yml:1)`
  - Evidence: Current config has site/theme/extensions/nav only; no `validation:` block appears through line 56.
  - Detail: Context7 MkDocs guidance confirms MkDocs 1.6 supports validation settings for omitted nav files, absolute links, unrecognized links, and anchors; warning-level diagnostics fail under `mkdocs build --strict`.
  - Impact: Link, anchor, and nav drift can be missed even when strict build runs.
  - Confidence: High

- [MEDIUM] Operator docs still center source checkout while managed install assets exist
  - File/area: `[docs/operations.md](/home/user/PycharmProjects/xferry/docs/operations.md:3)`, `[docs/public-direct.md](/home/user/PycharmProjects/xferry/docs/public-direct.md:18)`, `[deploy/systemd/install-systemd.sh](/home/user/PycharmProjects/xferry/deploy/systemd/install-systemd.sh:4)`
  - Evidence: Operations says source-only and remote updates not exposed; public deployment assumes `/opt/xferry-source`; systemd installer delegates to `/opt/xferry/current/xferry setup`.
  - Detail: There are two operator models: source venv docs and managed `/opt/xferry/current` lifecycle assets.
  - Impact: Publication/installer docs need a clear operator boundary for setup, status, logs, doctor, rollback, uninstall, and update once enabled.
  - Confidence: High

- [LOW] PR template changelog instruction drifts from current changelog shape
  - File/area: `[.github/PULL_REQUEST_TEMPLATE.md](/home/user/PycharmProjects/xferry/.github/PULL_REQUEST_TEMPLATE.md:27)`, `[CHANGELOG.md](/home/user/PycharmProjects/xferry/CHANGELOG.md:5)`
  - Evidence: PR template asks for `[Unreleased]`; changelog currently starts at `[0.1.0]`.
  - Detail: This is small, but it creates contributor uncertainty.
  - Impact: Minor contributor friction and inconsistent release-note expectations.
  - Confidence: High

## Concrete Recommendations

Smallest safe intervention:

1. Supersede ADR-006 before changing install/update docs.
   - Add a new ADR defining publication channels, supported platform matrix, artifact names, verification guarantees, rollback/update behavior, and ownership boundaries.
   - Mark ADR-006 superseded instead of silently editing its meaning.

2. Update guards in the same PR as the ADR.
   - Replace source-only checks in `tools/check_stale_docs.py` with publication-currency checks.
   - Update tests that currently forbid `pip install xferry`, GHCR, releases/latest, publisher actions, and `xferry update`.
   - Keep secret-safety checks; only allow publication credentials in narrowly scoped workflows if intentionally designed.

3. Generate or validate the release/install docs from canonical sources.
   - Single platform matrix shared by host support, installer, release manifest, CI matrix, and docs.
   - CLI help snapshot or generated `docs/cli-reference.md`.
   - Release asset names/checksums derived from release/build metadata, not duplicated prose.

Key tradeoff: this is larger than a text-only docs update, but it avoids publishing docs that CI rejects or that operators cannot run.

## Quick Wins

- Add MkDocs validation to `mkdocs.yml`:

```yaml
validation:
  nav:
    omitted_files: warn
    absolute_links: warn
  links:
    absolute_links: relative_to_docs
    unrecognized_links: warn
    anchors: warn
```

- Fix the changelog checkbox mismatch: either add `[Unreleased]` to `CHANGELOG.md` or update the PR template wording.
- Add a short docs note that `xferry update` is not currently public, if users are already asking for it.
- Add a troubleshooting pointer to `xferry doctor --help` / `xferry doctor --json` in operator docs.

## Deeper Improvements

- Create a generated CLI reference from `python -m xferry help` and per-command help.
- Replace duplicated platform prose with a generated support matrix.
- Split operator docs into:
  - source checkout operation,
  - managed installation lifecycle,
  - public-direct exposure,
  - rollback/update recovery.
- When publication is enabled, update these together:
  - `docs/ADR/README.md`
  - `docs/ADR/ADR-006-release-artifacts.md`
  - `mkdocs.yml` ADR nav label
  - `README.md`
  - `docs/index.md`
  - `docs/quick-start.md`
  - `docs/operations.md`
  - `docs/public-direct.md`
  - `CONTRIBUTING.md`
  - `SECURITY.md`
  - `CHANGELOG.md`
  - `examples/README.md`
  - `examples/docker/docker-compose.yml`
  - `deploy/docker/docker-compose.public-direct.yml`
  - `tools/check_stale_docs.py`
  - `tests/test_check_stale_docs.py`
  - `tests/test_deployment_artifacts.py`
  - `tests/test_docker_first_docs.py`
  - `tests/test_management_cli.py`
  - `.github/workflows/release.yml`

## Open Questions

- Which publication channels are intended for v1: PyPI, pipx, GHCR, GitHub Releases, SCIE installer, or all of them?
- Should `xferry update` become public, or should updates remain installer-managed only?
- Is Debian 13/aarch64 support required at launch, or should docs explicitly defer it?
- What is the canonical support boundary for Windows/macOS: local `xferry run` only, or managed install/update too?
- Who owns release publication credentials and rollback incident procedure after ADR-006 is superseded?
