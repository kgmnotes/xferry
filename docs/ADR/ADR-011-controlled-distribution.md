# ADR-011: Controlled distribution and staged activation

- **Status:** accepted
- **Supersedes:** ADR-006

## Context

XFerry has three distinct release journeys: a portable Python CLI, a
multi-architecture container, and a managed Linux installation with signed
updates. ADR-006 kept every journey source-only while build verification was
established. Permanent source-only distribution no longer matches the product
target, but accepting a channel design is not permission to publish unfinished
or unverified artifacts.

Distribution crosses repository, workflow, runner, artifact, registry,
signing, installer, and update-client trust boundaries. A release must keep one
version identity and the exact verified bytes across those boundaries.

## Decision

### Availability remains stage-owned

This decision approves the architecture, not immediate publication. Until the
acceptance stage for a channel is closed, the supported distribution remains a
reviewed source checkout and user documentation must not advertise that
channel. In this stage, `.github/workflows/release.yml` remains manual,
read-only, verification-only, and unable to reach an external publisher.

Later stages activate channels independently only after their required
consumer journey, trust, and rollback checks pass. A partially implemented
channel is not a supported channel.

### One immutable release identity

- The version authority is a protected tag in the exact form `vX.Y.Z`.
- The tag, `xferry.config.__version__`, package metadata, release manifest, and
  changelog version must agree before a candidate is built.
- A candidate is built once from the tagged commit. Every publisher consumes
  the previously verified candidate and promotes the same bytes or OCI digests;
  publisher jobs must not rebuild.
- Published versions and digests are immutable. A failed release is revoked,
  yanked, or superseded; its version and artifact names are never reused.
- Mutable convenience labels such as `latest` are never an install, update, or
  rollback authority.

### Required journeys and channels

| Journey | Controlled channel | Required release proof |
| --- | --- | --- |
| Portable CLI | PyPI wheel and source distribution | Exact-version install and `pipx`-style smoke on the supported OS/Python matrix |
| Container | GHCR OCI image for `linux/amd64` and `linux/arm64` | Pull and run by digest, multi-architecture manifest inspection, SBOM, and provenance |
| Managed Linux | Signed SCIE executables, installer metadata, checksums, and update metadata attached to a GitHub Release | Supported distro/architecture install, health, update, rollback, and uninstall journeys with signature verification |

All channels carry the same version identity. GitHub Release metadata is the
discovery boundary for managed artifacts, but signed metadata and artifact
digests, not the release page or a mutable URL, are the update authority.

### Trigger, approval, and permission controls

- Production publishers run only for protected version-tag refs. Branch and
  pull-request events cannot reach a production publisher.
- Each production publisher targets the protected `production` environment.
  Repository administrators configure required reviewers and restrict that
  environment to protected release tags.
- Workflow permissions default to read-only. Write scopes exist only on the job
  that needs them: `id-token: write` for PyPI trusted publishing,
  `packages: write` for GHCR, and `contents: write` for GitHub Release assets.
- PyPI uses OIDC trusted publishing; a long-lived PyPI token is forbidden.
  Other channel credentials must be short-lived and job-scoped where the
  service supports federation.
- External workflow actions are pinned to lowercase full commit SHAs. Checkout
  credentials are not persisted into build or publisher steps.
- Publisher jobs depend on verified build jobs, download or otherwise resolve
  the exact candidate by immutable identity, and verify recorded digests before
  any external write.

### Signing and key ownership

Designated release maintainers own the release-signing identity and its
rotation and revocation procedure. Private signing material must not be stored
in the repository, build products, logs, or general workflow configuration; it
is exposed only to the protected signing/publisher boundary. Approval of that
boundary must be independent from untrusted pull-request execution.

Verifier trust roots, key identifiers, validity windows, and rotation metadata
are reviewed repository content. Update clients and installers fail closed on
an unknown key, invalid signature, digest mismatch, version mismatch,
downgrade, or revoked release. ADR and implementation work in the signed
metadata stage must define the concrete signing mechanism before managed
publication is enabled.

### Rollback and incident response

Rollback selects a previously verified, still-trusted exact version or digest;
it never rebuilds an old tag or silently falls back to an unsigned artifact.
Channel owners retain the evidence needed to map a version to its source commit,
candidate digests, signatures, SBOM, and provenance. On compromise they stop
promotion, revoke or yank affected channel entries where possible, publish an
advisory, rotate affected identities, and update signed revocation metadata
before resuming releases.

### Documentation ownership

Release maintainers own workflow and channel procedures; security maintainers
own signing, key-custody, and incident-response contracts; documentation
maintainers own user journeys. User-facing installation or update instructions
change only in the stage that proves the corresponding public artifact. Root
canonical documents are updated before generated mirrors, and documentation
guards enforce the current availability state.

## Consequences

- ADR-006 remains historical evidence, while this ADR governs future channel
  work.
- Safe publisher definitions can be reviewed and tested before activation
  without making a public channel reachable.
- Later stages must supply hosted-service configuration evidence that static
  repository checks cannot prove, including tag rules and required environment
  reviewers.
- More release metadata and retention are required, but a consumer can trace
  every supported installation and rollback target to one reviewed candidate.
