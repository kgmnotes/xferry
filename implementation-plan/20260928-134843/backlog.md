# Backlog and Needs-Investigation Items

| Item | Source | Why not staged now | Suggested next step |
|---|---|---|---|
| Replace private RequestPipeline server hooks with a smaller explicit runtime interface | F-016, architect-reviewer | No current defect; unrelated to distribution outcome | Revisit only when a concrete protocol/security change crosses the hook boundary |
| Client-side Sigstore/GitHub attestation verification | security-auditor | Signed manifest is a smaller sufficient launch control | Evaluate after first release; measure dependency and offline-verification cost |
| TUF-style expiry, threshold signatures, delegated roles, and rollback protection | security-auditor | Substantial operational/key-management complexity | Threat-model after signed-manifest operations are stable |
| Signed latest-channel metadata | DevOps, QA, Security, DX | V1 deliberately requires explicit immutable version | Design a separate channel schema with expiry and rollback counters |
| Mutable GHCR `latest` tag | DevOps, QA, DX | Adds ambiguity without helping the first safe release | Consider only as a convenience alias; never use as update/rollback identity |
| Russian documentation for localized CLI | dx-optimizer | Canonical docs are explicitly English; user-facing scope is undecided | Decide localization policy after English journey docs stabilize |
| Separate candidate/staging/production GitHub Environments | DevOps, Security | One protected production environment satisfies current release frequency/target | Add if release frequency or approval roles justify it |
| Broader browser/UI modularization | Architecture | No release blocker or concrete regression established | Use a separate UI-focused audit before refactoring |
| Performance/scalability audit | Synthesis | No material performance issue found; current task is distribution | Run separately when load/SLO targets exist |
| Default managed setup exposure (`--private` versus public sslip) | DX open question | Requires product/operator risk decision | Prefer private in examples until the owner explicitly approves public-first setup |
