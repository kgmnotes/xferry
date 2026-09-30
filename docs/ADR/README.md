# Architecture Decision Records

These records describe accepted architecture and retain superseded decisions
as historical context. Ten decisions are active and accepted; ADR-006 is
superseded by ADR-011.

| ID | Status | Decision |
| --- | --- | --- |
| [ADR-001](ADR-001-handler-registry.md) | Accepted | Handler registry |
| [ADR-002](ADR-002-payload-protection.md) | Accepted | Payload protection: `none`, XOR, and AES |
| [ADR-003](ADR-003-runtime-crypto-acme.md) | Accepted | Runtime cryptography and ACME dependencies |
| [ADR-004](ADR-004-upload-containment.md) | Accepted | Upload containment |
| [ADR-005](ADR-005-thread-pool.md) | Accepted | Thread pool concurrency |
| [ADR-006](ADR-006-release-artifacts.md) | Superseded by ADR-011 | Source-only distribution |
| [ADR-007](ADR-007-trusted-proxy-identity.md) | Accepted | Trusted proxy identity |
| [ADR-008](ADR-008-notepad-recovery.md) | Accepted | Notepad recovery |
| [ADR-009](ADR-009-api-client-compatibility.md) | Accepted | API and client compatibility, including curl |
| [ADR-010](ADR-010-methods-and-presets.md) | Accepted | Always-on methods and launch presets |
| [ADR-011](ADR-011-controlled-distribution.md) | Accepted | Controlled distribution and staged activation |

A new decision should state its context, choice, and consequences. Change the
active set when implementation changes; use Git history for earlier text.
