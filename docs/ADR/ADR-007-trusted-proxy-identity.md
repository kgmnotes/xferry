# ADR-007: Trusted proxy identity

- **Status:** accepted

## Context

Forwarded client-IP headers are supplied by the request path and can be forged
unless a known proxy strips and rewrites them. The application currently has
no trusted-proxy allowlist or validated forwarding chain.

## Decision

Use the direct accepted-socket peer for authentication throttling, request
identity, and the no-auth Advanced Session loopback boundary. Do not treat
`Forwarded`, `X-Forwarded-For`, `X-Real-IP`, or similar headers as client
identity.

A reverse proxy must enforce per-client throttling before forwarding requests.
A remotely reachable loopback proxy is not a valid no-auth Advanced Session
deployment; enable Basic Auth at xferry.

## Consequences

- Direct deployments have a clear, non-spoofable peer source.
- Proxied logs and rate limits refer to the proxy connection unless the proxy
  supplies its own controls.
- Adding trusted forwarded identity requires a separate explicit trust model
  and implementation.
