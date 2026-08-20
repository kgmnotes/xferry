# Architecture Decision Records

These records describe the active architecture. All ten decisions are
accepted and match the current implementation.

| ID | Decision |
| --- | --- |
| [ADR-001](ADR-001-handler-registry.md) | Handler registry |
| [ADR-002](ADR-002-payload-protection.md) | Payload protection: `none`, XOR, and AES |
| [ADR-003](ADR-003-runtime-crypto-acme.md) | Runtime cryptography and ACME dependencies |
| [ADR-004](ADR-004-upload-containment.md) | Upload containment |
| [ADR-005](ADR-005-thread-pool.md) | Thread pool concurrency |
| [ADR-006](ADR-006-release-artifacts.md) | Release artifacts |
| [ADR-007](ADR-007-trusted-proxy-identity.md) | Trusted proxy identity |
| [ADR-008](ADR-008-notepad-recovery.md) | Notepad recovery |
| [ADR-009](ADR-009-api-client-compatibility.md) | API and client compatibility, including curl |
| [ADR-010](ADR-010-methods-and-presets.md) | Always-on methods and launch presets |

A new decision should state its context, choice, and consequences. Change the
active set when implementation changes; use Git history for earlier text.
