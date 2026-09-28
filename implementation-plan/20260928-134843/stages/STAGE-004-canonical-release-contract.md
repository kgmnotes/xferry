# STAGE-004 - Centralize release platform and manifest contracts

## Status
OPEN

## Priority
HIGH

## Source findings
- `codex-analysis/20260928-131617/project-analysis-report.md` - F-004: platform/artifact rules are duplicated across builder, installer, updater, and state.
- `agent-reports/architect-reviewer.md` - centralize the release model; do not broadly refactor the server.
- `agent-reports/security-auditor.md` - expansion without one model can strand supported hosts and rollback inventory.

## Goal
Create one typed release/platform contract that defines platform IDs, artifact names, manifest v2 fields, and compatibility parsing for every builder/consumer.

## Non-goals
- Enable arm64 hosts or public publication in this stage.
- Add signing private keys or a public update command.
- Refactor unrelated runtime/configuration code.

## Scope
### Likely files to inspect
- `xferry/management/releases.py` - manifest parser, platform constant, download selection.
- `xferry/management/managed_state.py` - installed release validation.
- `xferry/management/model.py` - host identity/support.
- `tools/build_scie_release.py` - artifact naming and manifest output.
- `packaging/install.sh.in` - generated platform/executable assumptions.
- `tests/test_management_releases.py`, `tests/test_scie_release.py`, `tests/test_management_planning.py` - current contract fixtures.

### Likely files to change
- `xferry/management/release_contract.py` (new or equivalent) - typed platform, artifact, and manifest v2 model.
- `xferry/management/releases.py` and `managed_state.py` - consume the canonical parser/model.
- `tools/build_scie_release.py` - generate names/metadata from the same contract.
- Tests and fixtures for v1 compatibility and v2 strictness.

### Files that must not be changed
- `xferry/server.py`, handler modules, and browser UI - unrelated.
- `.github/workflows/release.yml` - workflow promotion belongs to STAGE-009.
- Public docs - support is not expanded yet.

## Dependencies
- Depends on: STAGE-003
- Blocks: STAGE-005, STAGE-006, STAGE-007

## Implementation steps
1. Define canonical IDs `linux-x86_64` and `linux-aarch64`, normalized host aliases, deterministic artifact naming, and strict filename/basename rules.
2. Define manifest v2 fields for schema/version/tag/platform/artifact size+digest/source commit/workflow run/artifact digest set/signing key metadata, leaving signature production to STAGE-007.
3. Make builder, updater parser, and managed-state validation consume this model rather than independent literals.
4. Preserve safe read compatibility for existing schema-v1 state/releases; write v2 for new artifacts only.
5. Add duplicate-key, unknown-field, path, platform, version, size, digest, downgrade, and v1 migration fixtures.

## Acceptance criteria
- [ ] A single Python module owns supported platform IDs, aliases, artifact naming, and manifest validation.
- [ ] Searches find no independent `linux-x86_64` validation logic outside the canonical model, generated shell data, tests, or documentation fixtures.
- [ ] Existing valid v1 managed state remains readable for rollback/migration.
- [ ] New artifacts/state use strict manifest v2 and deterministic names.
- [ ] Unknown platforms, unsafe names, duplicate keys, loose schemas, and inconsistent tag/version metadata fail closed.
- [ ] Public imports and runtime protocol behavior remain unchanged.

## Verification plan
| Check | Command or method | Expected result |
|---|---|---|
| Targeted tests | `python -m pytest -q tests/test_management_releases.py tests/test_scie_release.py tests/test_management_planning.py` | All contract and compatibility cases pass |
| Type/lint/build | `mypy xferry && ruff check xferry/management tools/build_scie_release.py tests/test_management_releases.py tests/test_scie_release.py` | Clean |
| Manual/static review | `rg -n 'linux-x86_64|linux-aarch64' xferry tools packaging tests` | Remaining literals are canonical, generated, or explicit fixtures only |

## Suggested subagents
- `api-designer` - review manifest v2 as a compatibility-sensitive contract.
- `python-pro` - implement typed parsing/model boundaries.
- `security-auditor` - review strict parsing and downgrade/path behavior.
- `reviewer` - verify scope stays within release contracts.

## Risks and rollback
- Risk: parser/state migration makes existing installations unreadable or weakens strict rejection.
- Rollback: retain v1 fixture tests and revert consumers to the previous parser while keeping no v2 artifacts published.

## Completion notes
Filled by `close-plan-stage`.
