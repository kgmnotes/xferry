# Threat model

## Scope

The system boundary includes the TCP/TLS listener, HTTP parser,
authentication, browser-origin policy, handlers, WebSocket notes, storage, and
bundled UI. Clients, reverse proxies, tunnel providers, DNS and ACME services,
the host filesystem, backups, and the operator are external.

## Assets

- Basic Auth credentials, ACME account keys, and certificate private keys
- uploaded files, note ciphertext and metadata, and the client-held note key
- runtime and configuration integrity
- worker, memory, disk, socket, and file-descriptor capacity
- log, metric, and diagnostic privacy

## Threats and controls

| Threat | Primary controls |
| --- | --- |
| Credential interception or guessing | Verified TLS, file-backed credentials, authentication rate limiting, proxy throttling |
| Path traversal or symlink escape | Shared descendant resolver and uploads-only access boundary |
| Cross-origin browser mutation | Same-origin checks and exact allowed origins; wildcard CORS is read-only |
| Ambiguous HTTP framing | Header and body caps, rejected transfer encoding, rejected conflicting content lengths; identical duplicate values are accepted |
| Memory or storage exhaustion | Body admission budget, per-request caps, quotas, free-space reserve, SMUGGLE retention |
| Worker exhaustion | Finite thread pool, request timeouts, and WebSocket admission limit |
| Secret disclosure | Redacted configuration, bounded diagnostics, low-cardinality metrics, and file-backed auth |
| Advanced token abuse | High-entropy bearer token, auth or direct-loopback ownership, prefix match, expiry, idle timeout, revocation |
| Lost Notepad key | Explicit non-recovery contract; the server stores no durable client key |
| Abandoned one-shot artifacts | Age, count, and byte retention plus startup cleanup |

## Trust boundaries

TLS protects a direct network connection, but a tunnel or reverse proxy may
terminate TLS before xferry. The runtime trusts the direct accepted-socket peer
for peer identity; forwarding headers do not change it.

The operator controls filesystem permissions, other writers, backups, and hard
quotas. Application-level scans and quotas cannot provide a strong storage
boundary when another process can mutate the same directory without
coordination.

Advanced Session tokens select routing and parser context. They do not replace
Basic Auth. With Basic Auth disabled, Advanced control and data operations are
limited to a direct loopback peer.

## Out of scope

- multi-tenant isolation
- safe exposure to arbitrary internet clients without operator controls
- durable recovery of a Secure Notepad key
- confidentiality from XOR or a generated SMUGGLE artifact
- protection from a host administrator, TLS-terminating provider, or
  compromised browser

Review this model when authentication, storage boundaries, proxy trust,
cryptography, release artifacts, or the always-on method surface changes.
