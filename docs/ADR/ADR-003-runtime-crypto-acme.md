# ADR-003: Runtime cryptography and ACME dependencies

- **Status:** accepted

## Context

AES-GCM payloads, Secure Notepad ECDH, X.509 handling, self-signed
certificates, and built-in HTTP-01 issuance are runtime features. Treating
their libraries as optional would make installed behavior depend on an extra
chosen outside the runtime contract.

## Decision

Declare `cryptography`, `acme`, and `josepy` as runtime dependencies.
`cryptography` provides AES-GCM, ECDH, X.509 parsing, and certificate helpers.
`acme` and `josepy` provide HTTP-01 issuance.

Do not substitute weaker crypto when an operation is unavailable or fails.
The affected request or startup path fails closed.

## Consequences

- A normal source installation includes the libraries required by documented
  crypto and ACME features.
- Import paths that do not need ACME avoid eager ACME initialization.
- Dependency updates require compatibility and security testing across all
  supported Python versions.
