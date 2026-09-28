# STAGE-003 - Adopt controlled distribution policy and guards

## Status
OPEN

## Priority
HIGH

## Source findings
- `codex-analysis/20260928-131617/project-analysis-report.md` - F-001: accepted policy and automated guards conflict with the confirmed target.
- `agent-reports/documentation-engineer.md` - ADR-006 and stale-doc guards must change together.
- `agent-reports/security-auditor.md` and `qa-expert.md` - negative non-publication tests must become positive safety invariants.

## Goal
Supersede the source-only architecture decision with an approved, staged controlled-publication contract while keeping all external publishers disabled in this stage.

## Non-goals
- Publish to PyPI, GHCR, or GitHub Releases.
- Add write permissions, OIDC, registry login, release upload, or public update behavior yet.
- Rewrite runtime architecture or public install docs ahead of working artifacts.

## Scope
### Likely files to inspect
- `docs/ADR/ADR-006-release-artifacts.md` and `docs/ADR/README.md` - current decision/status.
- `SECURITY.md`, `docs/security.md`, `docs/threat-model.md` - release/update trust scope.
- `tools/check_stale_docs.py` - source-only semantic rules.
- `tests/test_check_stale_docs.py`, `tests/test_deployment_artifacts.py`, `tests/test_docker_first_docs.py` - policy tests.
- `.github/workflows/release.yml` - current safe verification-only state.

### Likely files to change
- `docs/ADR/ADR-006-release-artifacts.md` - mark superseded without rewriting history.
- `docs/ADR/ADR-007-controlled-distribution.md` (or next available number) and `docs/ADR/README.md` - new governing contract.
- `SECURITY.md`, `docs/threat-model.md`, generated `docs/security.md` through the normal sync path.
- `tools/check_stale_docs.py` and relevant tests - staged safety rules.

### Files that must not be changed
- `.github/workflows/release.yml` - no publisher permissions/actions in this stage.
- `xferry/management/releases.py` - update trust is implemented later.
- `README.md` and `docs/quick-start.md` - do not advertise unavailable channels.

## Dependencies
- Depends on: STAGE-001, STAGE-002
- Blocks: STAGE-004, STAGE-008, STAGE-009

## Implementation steps
1. Write the controlled-publication ADR: three user journeys, required channels/matrix, immutable version authority, exact artifact promotion, protected approval, signing/trust, rollback, and documentation ownership.
2. Mark ADR-006 superseded and update the ADR index/navigation.
3. Extend the threat model and security contract with tag, workflow, artifact, registry, signing-key, installer, and update-client trust boundaries.
4. Replace unconditional string bans with staged policy validation: the current no-publish workflow remains valid; unsafe publisher fixtures fail; safe future publisher fixtures can be expressed.
5. Preserve source-only wording in user docs until public channels pass their later acceptance stages.

## Acceptance criteria
- [ ] A new accepted ADR explicitly supersedes ADR-006 and records all confirmed product targets and launch invariants.
- [ ] Security/threat-model docs cover release/update supply-chain boundaries and key ownership requirements.
- [ ] Current verification-only workflow still has no externally reachable publication path.
- [ ] Tests reject branch/PR publication, static PyPI tokens, unpinned actions, broad permissions, rebuilding in publish jobs, and unprotected production jobs.
- [ ] Semantic guards no longer permanently forbid safe future PyPI/GHCR/GitHub Release/update references.
- [ ] User-facing docs still describe only behavior that exists at this stage.

## Verification plan
| Check | Command or method | Expected result |
|---|---|---|
| Targeted tests | `python -m pytest -q tests/test_check_stale_docs.py tests/test_deployment_artifacts.py tests/test_docker_first_docs.py` | All pass, including unsafe fixture rejection |
| Type/lint/build | `ruff check tools/check_stale_docs.py tests/test_check_stale_docs.py tests/test_deployment_artifacts.py` | Clean |
| Documentation | `python tools/sync_docs.py --check && python tools/check_stale_docs.py && mkdocs build --strict` | Synced and strict-clean |
| Manual/static review | Trace ADR status and workflow permissions | No public publisher is enabled |

## Suggested subagents
- `architect-reviewer` - review the decision boundary and compatibility with existing architecture.
- `security-auditor` - review trust/permission/key language and negative controls.
- `documentation-engineer` - keep canonical/generated documents and guards coherent.
- `reviewer` - confirm the stage does not accidentally authorize publication.

## Risks and rollback
- Risk: relaxing the old bans without equivalent positive checks creates an unsafe gap.
- Rollback: revert the new guard logic and ADR status together; never leave policy and enforcement on different decisions.

## Completion notes
Filled by `close-plan-stage`.
