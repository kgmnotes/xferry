# ADR-008: Notepad recovery

- **Status:** accepted

## Context

Secure Notepad encrypts note content with client-derived key material. A
server-held recovery key would change the confidentiality boundary and add a
new high-value secret.

## Decision

Store encrypted note blobs and plaintext metadata under `<root>/notes/`. Do
not persist the client-derived AES key or other durable recovery material on
the server.

Treat a lost client session key as permanent loss of access to the existing
note. Preserving or backing up server storage does not change that result.

## Consequences

- Server compromise does not reveal a durable client recovery key because no
  such key exists.
- Operators and users must understand that persistence is not recoverability.
- A future recovery feature would require an explicit key custody and threat
  model decision.
