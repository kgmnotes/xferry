# STAGE-015 - Activate and rehearse production release

## Status
OPEN

## Priority
HIGH

## Source findings
- `codex-analysis/20260928-131617/project-analysis-report.md` - the final target requires `vX.Y.Z`, protected approval, all three channels, and post-publish consumer evidence.
- `agent-reports/devops-engineer.md`, `qa-expert.md`, and `security-auditor.md` - release must fail closed on quality, identity, permission, provenance, platform, or health errors.
- `risks-and-blockers.md` - external namespace, environment, key, and native-arm64 evidence must be resolved before activation.

## Goal
Activate the production tag-triggered release path only after a full rehearsal, perform one approved release from exact candidates, and prove portable, container, managed-update, rollback, and incident-response outcomes.

## Non-goals
- Bypass a failed gate to meet a release date.
- Reuse/overwrite a published PyPI version or mutable Release asset.
- Add `latest` as an update trust anchor.
- Expand runtime features during release activation.

## Scope
### Likely files to inspect
- All stage reports and `stage-status.md` - closure evidence.
- `.github/workflows/release.yml` and reusable candidate/publisher jobs.
- `CHANGELOG.md`, release notes, SECURITY/threat model, operator/release runbooks.
- GitHub Environment, PyPI Trusted Publisher, GHCR package settings (external state).

### Likely files to change
- Production release orchestrator/tag trigger and final policy tests.
- `CHANGELOG.md`/release notes and `docs/release-runbook.md` (new or equivalent).
- Incident/yank/deprecate/revoke/rollback procedures.
- Planning status/report artifacts after successful closure.

### Files that must not be changed
- Candidate artifact bytes after verification.
- Historical published artifacts under an existing version.
- Quality/security thresholds to make the release pass.

## Dependencies
- Depends on: STAGE-010, STAGE-011, STAGE-012, STAGE-013, STAGE-014
- Blocks: `None`

## Implementation steps
1. Audit every prior stage as CLOSED and resolve every external blocker: namespaces, Trusted Publisher, protected reviewers, job policies, signing-key custody, and native arm64 evidence.
2. Run a no-production rehearsal through candidate build, protected approval, staging channels, signed asset download, pipx/GHCR/managed update, rollback, and uninstall.
3. Add/enable only `vX.Y.Z` production triggering; prove PRs, branches, forks, manual arbitrary refs, and mismatched tags cannot publish.
4. Enforce one `release-production` approval boundary and job-scoped permissions; publish the exact candidate set in a documented partial-failure-aware order.
5. Run full preflight, approve the environment, publish PyPI/GHCR/GitHub Release artifacts, and record digests, workflow run, commit, key ID, and URLs in release notes.
6. Run post-publish portable pipx, image pull-by-digest on two architectures, verified managed install/update/health/rollback/uninstall on the complete host matrix.
7. Exercise the incident tabletop: PyPI yank, GHCR deprecation, Release withdrawal notice, signing-key revocation, and operator rollback communication without deleting evidence.

## Acceptance criteria
- [ ] All prior stages are CLOSED with passing reports; no open release blocker remains.
- [ ] GitHub `release-production` has required reviewers, no self-bypass as agreed, and only production publisher jobs reference it.
- [ ] `vX.Y.Z` is the only production trigger and matches source version, changelog, manifests, filenames, and release notes.
- [ ] Full tests/coverage, mypy, Ruff, docs, Bandit, pip-audit, artifact, platform, and policy gates pass before approval.
- [ ] PyPI, GHCR, and GitHub Release consume exact promoted candidates and expose consistent version/source/digest identity.
- [ ] Post-publish pipx succeeds on Windows/macOS/Linux; GHCR succeeds on amd64/arm64; managed install/update/health/rollback/uninstall succeeds on all ten required host pairs.
- [ ] Release notes record immutable identities and recovery instructions; no `latest` trust dependency exists.
- [ ] Partial-release and key-compromise runbooks are reviewed and executable.

## Verification plan
| Check | Command or method | Expected result |
|---|---|---|
| Repository gates | Run the complete CI, security, docs, candidate, and release-policy workflow set on the release commit | All green before approval |
| External controls | Inspect GitHub Environment/reviewer rules, PyPI Trusted Publisher mapping, GHCR visibility/permissions | Match approved contract |
| Production consumers | `pipx install xferry==X.Y.Z`; inspect/pull GHCR by digest; download/verify Release assets; managed lifecycle matrix | Every target succeeds |
| Identity reconciliation | Compare tag, commit, version, changelog, PyPI files, GHCR digest, Release digests/signature/workflow run | One coherent immutable release |
| Recovery/tabletop | Execute documented non-destructive rehearsal of yank/deprecate/revoke/rollback communication | Owners can respond without overwriting artifacts |

## Suggested subagents
- `deployment-engineer` - orchestrate rehearsal and activation evidence.
- `qa-expert` - independent go/no-go and post-publish matrix.
- `security-auditor` - final permission/trust/key review.
- `documentation-engineer` - release notes/runbook accuracy.
- `reviewer` - final cross-channel identity review.

## Risks and rollback
- Risk: partial public release, immutable wrong PyPI version, compromised signing key, or a platform-specific outage.
- Rollback: never overwrite a version; stop remaining publishers, yank the PyPI release when justified, deprecate/deny the GHCR tag while preserving digest evidence, mark the GitHub Release withdrawn, revoke the signing key, and direct managed operators to the retained previous release via `xferry rollback`.

## Completion notes
Filled by `close-plan-stage`.
