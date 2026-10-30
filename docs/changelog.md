<!-- Generated from ../CHANGELOG.md by tools/sync_docs.py. Edit CHANGELOG.md and rerun the sync tool. -->

# Changelog

This project follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- Stop Requests batches after the current logical check, retaining partial
  reports and attempt history, with a complete checking/reporting guide.
- Offline encrypted-storage validation and explicit directory rebind, a cold
  backup/restore runbook and a synthetic HTTP restore rehearsal.
- Authenticated TLS transfer measurements with bounded-memory acceptance,
  restart recovery and advisory weekly performance comparisons.
- Firefox and WebKit base-workflow checks alongside the full Chromium suite,
  with explicit Large files capability checks and browser support documentation.

## [0.3.2] - 2026-10-28

Includes the setup, configuration, migration, and file-transfer features from
`0.3.1`.

### Fixed

- Use a compatible toolchain for public pipx installation checks, preventing
  the bootstrap's shared pip upgrade from conflicting with CI tool constraints.

## [0.3.1] - 2026-10-28

PyPI-only partial publication: the wheel and source distribution were published
with verified hashes. Public pipx checks then stopped on a bootstrap dependency
conflict. No GHCR image or public GitHub Release was published for this version.

### Added

- Install on the server host with `xferry setup` for native Linux or Docker,
  signed release verification, HTTPS, generated 12-character Basic Auth
  credentials, and a checked connection URL.
- An interactive `xferry config` editor and complete setting explanations,
  defaults, examples, constraints, and effective values for scripts.
- Direct `files_dir` selection with stable platform defaults and separate
  private state for notes, certificates, and encrypted-transfer recovery.
- Automatic renewal of built-in ACME certificates without interrupting active
  transfers.

- Production release and release-incident runbooks covering exact-version
  go/no-go, publish order, partial-release recovery, signing-key custody, and
  operator rollback communication.

### Changed

- **Breaking:** simplify access, HTTPS, and logging to `access`, `https_mode`,
  `log_level`, and `log_format`. Retired INI keys, environment variables, and
  CLI options are rejected; use the migration guide for existing profiles.
- **Breaking:** remove public `install`, `configure`, and `examples` commands;
  use `setup`, `config`, and the concise command help. Configuration selection
  consistently uses `--config FILE`.
- Configuration changes apply to running installations with health verification
  and rollback. Stopped servers stay stopped; ordinary Docker edits retain the
  pinned image.
- Native upgrades from the old settings format stage configuration and service
  unit conversion together. Failed activation restores the previous deployment;
  the new portable CLI can also roll back to the matching retained old format.
- Unify native and Docker lifecycle commands, including start, stop, status,
  logs, update, rollback, uninstall, and reinstallation with retained data.
- Use protected authentication files and the credentials action instead of
  inline passwords. Opening a browser remains a launch-only option.
- Shorten onboarding and operations documentation while keeping full settings,
  API, recovery, and migration references separate.

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

### Fixed

- Align release candidate containers with the standard Docker runtime: use
  canonical launch options, keep private state under writable `/data`, and use
  the same pinned base image.
- Validate managed diagnostics against the installed CLI contract, including
  the files-folder check in the new CLI.
- Preserve service-owned Basic Auth files through deployment checkpoints,
  update, and rollback while keeping control files and checkpoints root-owned.
- Preserve passwords, file paths, notes, certificates, and encrypted state
  during supported migration and retained-data reinstallation.
- Honor the saved foreground profile and explicit setup options, use the same
  CLI during privilege handoff, and reject secret-bearing retired options
  without echoing their values.
- Generate unique HTTP demo files without pre-deleting existing user files,
  remove unused upload-comparison code, and clarify the scope of clear-all.

## [0.3.0] - 2026-10-28

Unpublished candidate. Release preparation stopped before signing and
publication when the candidate container failed its startup check. No packages
or container images were published. Its changes are included in `0.3.1`.

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
