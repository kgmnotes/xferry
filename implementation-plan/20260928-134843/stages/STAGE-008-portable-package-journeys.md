# STAGE-008 - Prove portable packaged CLI journeys

## Status
OPEN

## Priority
HIGH

## Source findings
- `codex-analysis/20260928-131617/project-analysis-report.md` - F-005, F-006, F-014, and F-018: editable Python 3.12 smoke does not prove the target consumer journey.
- `agent-reports/qa-expert.md` - recommended packaged matrix is Windows/macOS/Linux at Python 3.10, 3.12, and 3.14.
- `agent-reports/dx-optimizer.md` - root version/help should distinguish portable and managed lifecycles.

## Goal
Prove that a built wheel works outside the source checkout through a pipx-style isolated install on all portable operating systems and supported Python boundaries, with conventional first-run CLI behavior.

## Non-goals
- Publish to production PyPI (STAGE-010).
- Implement managed Linux setup/update on Windows or macOS.
- Run the entire 3,171-test suite on every hosted OS/Python pair.

## Scope
### Likely files to inspect
- `pyproject.toml` - package metadata, console script, Python range.
- `xferry/management/cli.py`, `xferry/management/i18n.py`, `xferry/__main__.py`, `xferry/cli.py` - root/portable UX.
- `.github/workflows/ci.yml` - full and cross-platform matrices.
- `tools/verify_python_artifacts.py` - artifact validation/offline smoke.
- `tests/test_cli.py`, `tests/test_management_cli.py` - command contracts.

### Likely files to change
- Root CLI/i18n modules for `--version`, grouped help, and actionable unknown/platform errors.
- Cross-platform CI and artifact verification tooling.
- CLI, packaging, and workflow-policy tests.

### Files that must not be changed
- Managed updater release enablement - STAGE-013.
- Runtime HTTP/WebSocket protocol behavior.
- PyPI credentials or production publisher configuration.

## Dependencies
- Depends on: STAGE-003
- Blocks: STAGE-009, STAGE-010

## Implementation steps
1. Build wheel/sdist once on Linux and transfer the exact wheel to portable acceptance jobs.
2. On Windows, macOS, and Linux with Python 3.10/3.12/3.14, install the wheel outside the checkout into a pipx-created or equivalent isolated application environment.
3. Run `pip check`, import completeness, `xferry --version`, `python -m xferry --version`, help, config check, a short start/health/stop smoke, and the portable test subset.
4. Group top-level help into portable versus managed Linux commands and improve unknown-command/platform guidance without changing stable exit semantics unintentionally.
5. Keep the full Ubuntu Python 3.10-3.14 suite as the exhaustive logic gate.

## Acceptance criteria
- [ ] The same built wheel installs and runs on Windows, macOS, and Linux at Python 3.10, 3.12, and 3.14.
- [ ] Acceptance runs outside the checkout and cannot import source-tree code accidentally.
- [ ] `xferry --version`, `python -m xferry --version`, `xferry --help`, `xferry run --check-config`, and a bounded server lifecycle smoke succeed.
- [ ] Help labels managed Linux commands and points portable upgrade/uninstall to pipx.
- [ ] Unknown commands name the offending command and point to `xferry help`.
- [ ] The existing full Linux Python 3.10-3.14 suite remains green.

## Verification plan
| Check | Command or method | Expected result |
|---|---|---|
| Targeted tests | `python -m pytest -q tests/test_cli.py tests/test_management_cli.py tests/test_public_surface.py` | All pass |
| Artifact build | `python -m build --sdist --wheel --outdir dist && python tools/verify_python_artifacts.py validate --workspace "$PWD" --wheel 'dist/xferry-*.whl' --sdist 'dist/xferry-*.tar.gz'` | Valid artifacts |
| Hosted matrix | CI jobs for three OSes × Python 3.10/3.12/3.14 install exact wheel and run portable smoke | Nine jobs pass |
| Type/lint/build | `mypy xferry && ruff check xferry tests tools/verify_python_artifacts.py` | Clean |

## Suggested subagents
- `cli-developer` - root help/version/error behavior.
- `qa-expert` - consumer matrix and no-source-import guarantees.
- `build-engineer` - exact wheel transfer and hosted-runner workflow.
- `reviewer` - public CLI compatibility review.

## Risks and rollback
- Risk: hosted matrix cost/flakiness or shell syntax leaks across Windows/POSIX.
- Rollback: retain built-wheel smoke at 3.12 while fixing runner-specific orchestration; do not fall back to editable installs as release evidence.

## Completion notes
Filled by `close-plan-stage`.
