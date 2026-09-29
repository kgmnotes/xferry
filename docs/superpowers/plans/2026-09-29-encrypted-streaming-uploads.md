# Encrypted Streaming Uploads v1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add opt-in, resumable, client-encrypted 2 GiB transfers with bounded memory and browser or one-shot server decryption.

**Architecture:** A versioned EUF v1 codec protects independent 8 MiB chunks. A crash-safe hidden store exposes a reserved HTTP namespace, while two focused browser modules provide streaming upload/resume/download.

**Tech Stack:** Python 3.10+, `cryptography`, standard-library filesystem/threading, browser Web Crypto, File System Access API, vanilla JavaScript.

**Spec:** `docs/superpowers/specs/2026-09-29-encrypted-streaming-uploads-design.md`

## Global Constraints

- Feature disabled by default and available in the general distribution.
- Maximum default plaintext size is 2048 MiB; chunk size is exactly 8 MiB.
- Server stores no plaintext and no key unless a caller supplies `K_content` for one response.
- Existing Basic and Advanced upload contracts remain backward compatible.
- Development is TDD; no production behavior is added before its failing test.

## Review Focus

- Nonce uniqueness and exact JS/Python wire interoperability.
- Quota accounting and crash recovery for pre-sized partial files.
- Duplicate/conflicting chunk retries and mixed-file resume prevention.
- Secret redaction in errors, logs, URLs, manifests, and persistent state.
- Bounded request/response memory and cleanup on interrupted streams.

---

### Task 1: EUF v1 codec, settings, and capability contract

**Files:**
- Create: `xferry/encrypted_transfer.py`
- Modify: `xferry/settings.py`, `xferry/settings_schema.py`, `xferry/server_config.py`, `xferry/runtime_posture.py`, `xferry/handlers/info.py`
- Test: `tests/test_encrypted_transfer.py`, relevant settings/PING tests

- [x] Write failing independent-vector tests for ID/base64 validation, AAD, PBKDF2/HKDF, metadata, chunks, resume HMAC, and tamper failure.
- [x] Implement immutable manifest types and Python codec helpers.
- [x] Write failing settings/PING tests, then add the opt-in flag and limits with the approved defaults.
- [x] Run focused tests and static checks; commit the task.

### Task 2: Crash-safe encrypted storage

**Files:**
- Create: `xferry/encrypted_storage.py`
- Modify: `xferry/storage.py`, `xferry/handlers/context.py`, `xferry/server.py`
- Test: `tests/test_encrypted_storage.py`

- [x] Write failing tests for create, durable chunk write, idempotent retry, conflict, quota, completion, delete, expiry, and restart reconciliation.
- [x] Implement the hidden data store, atomic sidecars, locks, state machine, and startup/TTL reconciliation.
- [x] Prove hidden data is accounted but inaccessible to ordinary file operations.
- [x] Run focused tests and static checks; commit the task.

### Task 3: Reserved API and transformed response streaming

**Files:**
- Create: `xferry/handlers/encrypted_files.py`
- Modify: handler composition/routing, `xferry/http/response.py`, `xferry/server.py`, `xferry/request_pipeline.py`
- Test: `tests/test_encrypted_api.py`, HTTP response/pipeline/live tests

- [ ] Write failing contract tests for every route, status, stable error, auth/origin rule, and disabled 404 behavior.
- [ ] Add handlers and strict schemas, including idempotent create/chunk/complete and final deletion.
- [ ] Write failing iterator-response tests, then add bounded transformed streaming for one-shot decrypt.
- [ ] Add route-specific chunk size/admission checks before large body allocation.
- [ ] Run focused and neighboring server suites; commit the task.

### Task 4: Browser crypto and large-file workflow

**Files:**
- Create: `xferry/data/static/ui/encrypted-transfer-crypto.js`, `xferry/data/static/ui/encrypted-transfer.js`
- Modify: `xferry/data/index.html`, upload UI styles/bootstrap assets
- Test: Node-backed static UI tests and browser smoke coverage

- [ ] Write failing JS/Python interoperability tests using independent literals.
- [ ] Implement Web Crypto derivation, AAD, chunk encryption/decryption, and resume MAC without whole-file buffering.
- [ ] Write failing UI workflow tests, then add capability-gated upload, pause, resume, cancel, list, unlock, client download, and confirmed server decrypt.
- [ ] Persist only non-secret progress in IndexedDB and abort partial downloads on failure.
- [ ] Run UI syntax, Node, accessibility, and browser smoke checks; commit the task.

### Task 5: Documentation, integration, and resource verification

**Files:**
- Modify: `API.md`, generated `docs/api.md`, config/operations/frontend/threat-model/ADR/changelog documentation
- Test: docs freshness, full suite, build/static checks, resource smoke

- [ ] Document the exact v1 schema, error contract, trust boundary, configuration, and recovery behavior.
- [ ] Add a 64 MiB automated round-trip and an opt-in 2 GiB resource smoke that records peak memory.
- [ ] Run `ruff check`, `ruff format --check`, `mypy`, static asset checks, docs freshness, and full `pytest`.
- [ ] Perform a fresh whole-branch security/correctness review and fix Important findings via RED->GREEN.
