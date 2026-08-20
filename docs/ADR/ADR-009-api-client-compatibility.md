# ADR-009: API and client compatibility

- **Status:** accepted

## Context

The bundled UI, curl, examples, and operator scripts consume the same HTTP and
WebSocket implementation. Separate browser or SDK response formats would
multiply compatibility paths that the project does not maintain.

## Decision

Publish one unversioned API for the current `0.x` line. The browser UI, curl,
and other clients use the same routes, request shapes, success objects, and
four-field error envelope.

Clients discover active core methods from `PING.supported_methods`, treat
method lists as sets, and ignore unknown additive response fields. Human error
messages, JSON key order, generated IDs, and exact metric names are not client
branching contracts.

Document complete curl journeys for Basic operations and Advanced Session
create, use, inspect, and revoke. There is no official SDK and no global
idempotency key.

## Consequences

- API examples can be exercised directly with curl.
- UI-only endpoints and compatibility parsers are not required.
- Mutating clients must use stable resource identifiers where supported and
  confirm state after an unknown outcome.
