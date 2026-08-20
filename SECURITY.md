# Security Policy

## Scope

`xferry` is a controlled security-testing tool, not a hardened multi-tenant
service. Use it only with explicit authorization and test data. Binding to a
public address, enabling TLS, or adding Basic Auth does not by itself make an
internet-facing deployment safe.

Version `0.1.0` is available as source. No GitHub Release, PyPI package, or
GHCR image has been published.

## Report a vulnerability

Do not open a public issue. Create a
[private GitHub Security Advisory](https://github.com/kgmnotes/xferry/security/advisories/new)
with the affected version, configuration, reproduction steps, and expected
impact. Do not include live credentials or user data.

Reports are handled on a best-effort basis. We usually acknowledge a report
within three working days and provide an initial assessment within seven.

## External exposure baseline

Before exposing xferry outside a trusted network, provide all of the following:

1. TLS with a hostname clients verify.
2. Strong Basic Auth read from a permission-restricted file.
3. A firewall or reverse proxy with finite connection, header, body, and
   timeout limits.
4. Finite upload, note, and temporary-artifact quotas, plus a free-space
   reserve or external hard quota.
5. Exact allowed browser origins. Wildcard CORS permits read-only requests and
   does not authorize mutations.
6. Proxy-side per-client throttling when the direct TCP peer is a proxy.
7. Process or container resource limits, logs, and monitoring.
8. Backups and a tested recovery procedure for operator-owned state.
9. Test data or data the operator is explicitly permitted to handle.

The [public deployment guide](docs/public-direct.md) turns this baseline into a
configuration procedure.

## Security boundaries

- `local` and `local-secure` are intended for loopback or trusted-local use.
- `public-direct` enables strict configuration validation, but presets do not
  add or remove HTTP methods.
- Basic Auth credentials travel with every request and require TLS on an
  untrusted network.
- The runtime identifies the direct accepted-socket peer. Forwarding headers do
  not establish client identity or a loopback boundary.
- Each active WebSocket occupies one worker.
- Request-body admission limits are not a process memory ceiling.
- Filesystem quotas assume the operator controls other writers to the data
  directory.
- A generated SMUGGLE URL is one-shot. A scanner, preloader, or `HEAD` request
  can consume it first.
- ACME account keys and certificate private keys are secrets.

## Payloads and notes

Advanced upload and SMUGGLE support `none`, XOR, and AES payload modes. XOR is
compatibility obfuscation, not confidentiality. AES uses the documented
AES-256-GCM format and fails closed; it never falls back to XOR. Use TLS for
transport confidentiality.

Secure Notepad stores ciphertext and metadata, but the server does not retain
the client-derived AES key. Losing the client session key makes an existing
note unrecoverable even when the server data directory survives.

See the [threat model](docs/threat-model.md) for assets, trust boundaries, and
out-of-scope threats.
