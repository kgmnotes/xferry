# Threat model

## Scope

The system boundary includes the TCP/TLS listener, HTTP parser,
authentication, browser-origin policy, handlers, WebSocket notes, storage,
bundled UI, and the accepted release and update contract. Clients, reverse
proxies, tunnel providers, DNS and ACME services, the host filesystem, backups,
GitHub-hosted runners, protected repository environments, PyPI, GHCR, GitHub
Releases, signing services, installers, update clients, and the operator are
external.

## Assets

- Basic Auth credentials, ACME account keys, and certificate private keys
- uploaded files, note ciphertext and metadata, and the client-held note key
- runtime and configuration integrity
- worker, memory, disk, socket, and file-descriptor capacity
- log, metric, and diagnostic privacy
- protected release tags and workflow definitions
- publisher identities, environment approvals, and signing keys
- candidate artifacts, OCI digests, manifests, checksums, SBOMs, provenance,
  registry records, installer metadata, and update metadata
- installer and update-client trust roots, version state, and rollback state

## Threats and controls

| Threat | Primary controls |
| --- | --- |
| Credential interception or guessing | Verified TLS, file-backed credentials, authentication rate limiting, proxy throttling |
| Path traversal or symlink escape | Shared descendant resolver and uploads-only access boundary |
| Cross-origin browser mutation | Same-origin checks and exact allowed origins; wildcard CORS is read-only |
| DNS rebinding or untrusted authority | Earliest Host admission against listener/certificate policy; CORS cannot widen authorities |
| Ambiguous security headers | Duplicate/folded protected fields rejected before auth, routing, CORS, Advanced sessions, or WebSocket handling |
| Ambiguous HTTP framing | Header and body caps, rejected transfer encoding, rejected conflicting content lengths; identical duplicate values remain accepted for Content-Length |
| Memory or storage exhaustion | Body admission budget, per-request caps, quotas, free-space reserve, SMUGGLE retention |
| Worker exhaustion | Finite thread pool, request timeouts, and WebSocket admission limit |
| Secret disclosure | Redacted configuration, bounded diagnostics, low-cardinality metrics, and file-backed auth |
| Advanced token abuse | High-entropy bearer token, auth or direct-loopback ownership, prefix match, expiry, idle timeout, revocation |
| Lost Notepad key | Explicit non-recovery contract; the server stores no durable client key |
| Abandoned one-shot artifacts | Age, count, and byte retention plus startup cleanup |
| Branch or pull-request publication | Production publishers accept protected version-tag refs only and require protected-environment approval |
| Workflow or third-party action compromise | Reviewed workflow changes, full commit-SHA action pins, non-persisted checkout credentials, and least-privilege job permissions |
| Candidate substitution or publish-job rebuild | Build-once candidate handoff, recorded digests, publisher dependency on verified jobs, and pre-publication digest verification |
| Static publisher credential theft | PyPI OIDC trusted publishing and short-lived, environment-scoped identities for other channels where supported |
| Registry tag drift or artifact replacement | Immutable versions and digests; mutable labels are not install, update, or rollback authorities |
| Signing-key compromise | Restricted maintainer ownership, protected signing boundary, two-key overlap, local revocation state, and reviewed verifier trust roots |
| Installer or update metadata tampering | Canonical Ed25519 signature before artifact-reference use, separately signed installer bytes, digest, version, key, revocation, and downgrade checks that fail closed |

## Trust boundaries

TLS protects a direct network connection, but a tunnel or reverse proxy may
terminate TLS before xferry. The runtime trusts the direct accepted-socket peer
for peer identity; forwarding headers do not change it.

Request authority is admitted independently from browser CORS policy. The
effective server TLS scheme plus canonical Host and effective port define
same-origin. A gateway must forward one allowed Host; duplicated or folded
security fields are rejected rather than interpreted first- or last-value.

The operator controls filesystem permissions, other writers, backups, and hard
quotas. Application-level scans and quotas cannot provide a strong storage
boundary when another process can mutate the same directory without
coordination.

Advanced Session tokens select routing and parser context. They do not replace
Basic Auth. With Basic Auth disabled, Advanced control and data operations are
limited to a direct loopback peer.

A protected version tag is the release identity boundary. Repository and tag
rules admit a candidate into trusted build jobs; they do not by themselves
authorize an external write. Exact candidate artifacts and recorded digests
cross from build jobs into separate publisher jobs. Those jobs cross the
protected `production` environment and receive only the write scope for their
one channel. Pull-request code and branch-triggered jobs remain outside that
boundary.

PyPI, GHCR, and GitHub Releases are separate distribution boundaries. Their
availability metadata is not sufficient proof of artifact identity. Consumers
anchor trust in an exact version or digest plus signed metadata. The signing
service is a separate boundary from the build runner: designated release
maintainers own its identity, while reviewed repository content owns verifier
trust roots and rotation metadata.

Installers and update clients cross from public channel metadata into a local
managed host. They must verify signatures, digests, release identity, trusted
keys, revocation state, and downgrade policy before changing the installation.
Rollback crosses the same boundary and may select only a previously verified,
still-trusted exact release.

The concrete launch contract signs the exact canonical schema-v2 manifest
bytes with Ed25519 and carries the signature in a strict detached envelope that
binds its payload type and key ID. The manifest authenticates source commit,
workflow run, exact platform artifact, size, SHA-256, and the complete declared
digest set before the client derives the artifact URL. Installer bytes use a
separate signature domain and must be verified before explicit `sudo`
execution. HTTPS, hash/size, configuration, health, and rollback checks remain
defense in depth rather than substitutes for publisher authentication.

The reviewed client key ring can carry the old and new active public keys
during rotation. A manifest selects one key; an unknown or locally revoked key
fails closed. The old key is revoked or removed only after supported artifacts
have moved to the new signer. Production key `xferry-release-2026-09` is held
by the required-reviewer `production-release` GitHub Environment and its public
trust root is shipped in the client. This enrollment authenticates a publisher;
it does not make the managed channel public before the release-assets and final
activation stages close.

## Out of scope

- multi-tenant isolation
- safe exposure to arbitrary internet clients without operator controls
- durable recovery of a Secure Notepad key
- confidentiality from XOR or a generated SMUGGLE artifact
- protection from a host administrator, TLS-terminating provider, or
  compromised browser
- availability or internal integrity of third-party distribution services
- recovery of a compromised release without maintainer revocation, credential
  rotation, and a newly reviewed release

Review this model when authentication, storage boundaries, proxy trust,
cryptography, distribution policy, or the always-on method surface changes.
