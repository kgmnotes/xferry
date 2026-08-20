# ADR-002: Payload protection

- **Status:** accepted

## Context

Advanced uploads and generated SMUGGLE artifacts need an explicit wire choice
for unchanged, compatibility-obfuscated, and authenticated encrypted payloads.
Guessing the cipher from content or falling back after a decryption error would
make results ambiguous.

## Decision

Expose exactly three payload modes:

- `none` leaves payload bytes unchanged and forbids key and HMAC metadata where
  the Advanced contract requires that restriction.
- `xor` applies repeating-key XOR. It is compatibility obfuscation, not
  confidentiality.
- `aes` uses the canonical password-based AES-256-GCM wire format.

Advanced upload requires explicit encryption metadata. AES and XOR require a
nonempty key. Optional HMAC-SHA256 is verified over decoded bytes before
decryption. A request selected as AES never falls back to XOR, and XOR never
falls back to AES.

## Consequences

- Clients can reproduce one documented transformation.
- Invalid keys, tags, metadata, and payloads fail closed before publication.
- TLS remains necessary for transport confidentiality.
