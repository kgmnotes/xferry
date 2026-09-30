# Planning Decisions

| Decision | Rationale | Alternatives rejected |
|---|---|---|
| Treat Windows/macOS/Linux pipx use as the portable contract; managed service lifecycle remains Linux/systemd-only | Matches the confirmed target and avoids implying Windows/macOS service management | One universal lifecycle command set on every OS |
| Support Ubuntu 22.04/24.04/26.04 and Debian 12/13 on x86_64 and arm64 before the first managed release | The user confirmed the complete matrix as the target | Shipping arm64 or Debian 13 as undocumented/best-effort follow-ups |
| Keep `xferry/server.py` as the composition root | Architecture review found real boundaries and strong tests; broad refactoring does not unblock release work | General server/module rewrite before packaging |
| Use one canonical Python release/platform model and generate shell/docs literals from it | Prevents builder/installer/updater/state drift | Maintaining platform strings independently |
| Use build-once, verify-once, promote-exactly semantics | Prevents publish jobs from rebuilding different bytes | Independent rebuild inside each publisher |
| Use one protected `release-production` GitHub Environment with required reviewers and job-scoped permissions | Matches the requested single manual approval while preserving least privilege | Static publisher tokens or repository-wide write permissions |
| Use PyPI Trusted Publishing/OIDC | Current PyPA guidance and no long-lived API token | Stored PyPI API token |
| Publish only immutable `vX.Y.Z` tags/digests for v1; do not depend on mutable `latest` | Risk-first release and rollback semantics | `latest` as the initial install/update trust anchor |
| Require `xferry update --to VERSION` at launch | Explicit operator intent and immutable metadata reduce rollback/downgrade ambiguity | Unsigned or implicit latest-channel updates |
| Sign canonical manifest v2 with Ed25519 and verify via an embedded key ring | `cryptography` is already a runtime dependency; simple client verification provides an independent trust root | Workflow attestations that clients do not enforce; immediate TUF/Sigstore client complexity |
| Keep SBOMs, provenance, and GitHub attestations in addition to client signatures | They provide producer-side audit and incident evidence | Treating a signed manifest as the only supply-chain record |
| Avoid `curl | sudo sh` | The installer itself is part of the root trust chain | Pipe-to-shell convenience path |
| Keep English as the canonical documentation language | Confirmed product requirement | Parallel canonical language trees |
| Organize docs around portable, managed, and container journeys | Minimizes install-to-first-success and distinguishes lifecycle ownership | Artifact-by-artifact or source-first navigation |
| Assume PyPI `xferry`, GHCR `ghcr.io/kgmnotes/xferry`, and GitHub `kgmnotes/xferry` pending owner confirmation | Derived from package and repository metadata; PyPI name appeared unclaimed during audit | Inventing a different public namespace |
