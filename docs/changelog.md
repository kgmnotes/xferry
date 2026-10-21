<!-- Generated from ../CHANGELOG.md by tools/sync_docs.py. Edit CHANGELOG.md and rerun the sync tool. -->

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

- Release security documentation now separates `production-release` signing-key
  custody from the secret-free `release-production` publication approval
  boundary.

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
