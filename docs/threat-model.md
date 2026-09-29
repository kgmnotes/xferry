# Threat model

## Scope

The system boundary includes the TCP/TLS listener, HTTP parser,
authentication, browser-origin policy, handlers, WebSocket notes, storage, and
bundled UI. Clients, reverse proxies, tunnel providers, DNS and ACME services,
the host filesystem, backups, and the operator are external.

## Assets

- Basic Auth credentials, ACME account keys, and certificate private keys
- uploaded files, client-encrypted file ciphertext and metadata, note
  ciphertext and metadata, and client-held content, resume, and note keys
- runtime and configuration integrity
- worker, memory, disk, socket, and file-descriptor capacity
- log, metric, and diagnostic privacy

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
| Lost encrypted-transfer password | Explicit non-recovery contract; the server does not know the password or content key by default |
| Mixed-file or forged resume | Authenticated metadata plus per-chunk `K_resume` HMACs recomputed from the reselected local file |
| Encrypted-file tampering | Per-chunk AES-GCM tags, position/length AAD, fail-closed download, and aborted partial output |
| Malicious or compromised xferry host | Browser-side decryption by default; no password or key upload; ciphertext alone does not reveal plaintext |
| One-shot server decryption exposure | Separate confirmation, exact `content_key` body, TLS or a direct loopback peer, no key logging/persistence, no plaintext artifact |
| Abandoned one-shot artifacts | Age, count, and byte retention plus startup cleanup |

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

For encrypted transfers, the browser-to-server API boundary contains only
ciphertext, public manifest values, and resume MACs. The server does not know
the password or content key by default. Browser-side decryption therefore
protects against disclosure by an honest-but-curious storage service, a stolen
ciphertext backup, or a malicious or compromised xferry host that did not
obtain the browser runtime or password. It does not hide sizes, timing, file
IDs, chunk completion, or creation/update times.

The one-shot server decryption path deliberately crosses that boundary. After explicit
confirmation, `K_content` and plaintext are trusted to the server process for
one response. The route is restricted to effective TLS or a direct loopback
peer; a TLS-terminating reverse proxy remains able to observe plaintext and the
key. Basic Auth and same-origin checks remain mandatory controls rather than
cryptographic substitutes.

## Out of scope

- multi-tenant isolation
- safe exposure to arbitrary internet clients without operator controls
- durable recovery of a Secure Notepad key
- recovery of a forgotten encrypted-transfer password or content key
- confidentiality from XOR or a generated SMUGGLE artifact
- protection from a host administrator, TLS-terminating provider, or
  compromised browser

Review this model when authentication, storage boundaries, proxy trust,
cryptography, distribution policy, or the always-on method surface changes.
