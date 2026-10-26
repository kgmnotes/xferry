# Changelog

This project follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- Production release and release-incident runbooks covering exact-version
  go/no-go, publish order, partial-release recovery, signing-key custody, and
  operator rollback communication.

### Changed

- Refresh runtime dependencies and contributor tooling together, keeping CI,
  pre-commit hooks, and release verification dependency pins aligned.
- Production drafts are resolved through authenticated paginated listings and
  bound numeric Release IDs; public pipx and anonymous native image checks run
  before the signed GitHub Release becomes visible.
- Main pushes validate documentation; Pages publication now requires successful
  production and signed public-channel evidence for the documented source.
- Signed platform manifests also authenticate the Python distributions,
  candidate inventory, and archive containing the complete OCI graph.

- Release security documentation separates `production-release` signing-key
  custody and its single release authorization from the secret-free
  `release-production` automatic publication boundary.

## [0.2.1] - 2026-10-27

Public two-version managed update and rollback acceptance is established by
successful production lifecycle checks after publication.

### Changed

- Use one `production-release` approval after candidate, quality, security, and
  native readiness checks. Signed draft creation, PyPI, GHCR, GitHub Release,
  and public consumer checks then proceed in the enforced dependency order
  without additional publisher approvals.
- Align release, signing-key, threat-model, and incident-response documentation
  with the single authorization while retaining separate publisher permissions,
  immutable artifacts, and the final managed lifecycle and Pages gates.

### Fixed

- Reject missing release dependencies, bypass conditions, and error suppression
  in the signer, publisher, and blocking consumer jobs through executable policy
  checks and mutation regressions.
- Clarify that managed rollback requires trusted current state and a still-trusted
  target; signing-key compromise can require reviewed trust-root recovery instead.

## [0.2.0] - 2026-10-01

### Added

- Portable pipx, signed managed Linux, and immutable container installation
  journeys with generated CLI and managed-host references.
- Exact-version managed update, health-gated activation, rollback, and
  conservative uninstall documentation.

## [0.1.0] - 2026-08-20

### Added

- The xferry HTTP server, browser UI, and contributor source workflow.
- Basic file upload, browsing, download, deletion, and inspection APIs.
- Standard, custom, Advanced Session, NOTE, WebSocket, and SMUGGLE workflows.
- Explicit `none`, XOR, and AES-256-GCM payload modes.
- Local, local-secure, and public-direct launch presets.
- TLS, Basic Auth, browser-origin checks, request limits, storage quotas, path
  containment, and redacted diagnostics.
- Opt-in resumable client-encrypted streaming transfers up to 2 GiB, with
  browser-side download and confirmed one-shot server decryption.
