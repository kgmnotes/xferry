# architect-reviewer Report
_Generated: 2026-09-28_
_Source plan: `/home/user/PycharmProjects/xferry/codex-analysis/20260928-131617/analysis-plan.md`_

## Summary

Scope analyzed: runtime request path, server composition, handler/plugin boundaries, settings/schema, management release/update flow, installer/build scripts, docs/ADRs/security docs, and related tests.

No CRITICAL or HIGH architecture defects were evident from the read-only review. The runtime boundaries are mostly real, documented, and covered by focused tests. The main risk is distribution architecture: the repo currently encodes a source-only, Linux x86_64 managed-release model, while future publication/portable release goals would cross accepted architecture and release-trust boundaries.

No files were modified or created. The agent did not rerun tests.

## Documentation Checks

Context7 was not used because the recommendations are repo-internal architecture/release-contract findings, not current external framework/API guidance.

Checked documentation and policy alignment:

- `docs/architecture.md:6` documents the request path.
- `docs/architecture.md:20` documents method policy ownership.
- `docs/architecture.md:64` documents config/plugin boundaries.
- `docs/ADR/ADR-006-release-artifacts.md:13` explicitly chooses source-only distribution.
- `docs/security.md:12` repeats that automation does not publish packages, release binaries, or registry images.
- `.github/workflows/release.yml:3` is manual-only and `.github/workflows/release.yml:6` has read-only permissions.

## Detailed Findings

The runtime architecture is healthier than the file sizes suggest. `xferry/server.py:108` acts as a composition root, constructing lifecycle, WebSocket, auth, metrics, storage, handler context, and plugins. The extracted runtime boundaries are meaningful: `xferry/lifecycle.py:48` owns startup/admission/cleanup, and `xferry/websocket_runtime.py:30` owns WebSocket capacity and frame lifecycle.

Request sequencing is centralized in `xferry/request_pipeline.py:153`, with admission before auth/dispatch and explicit short-circuit paths. Tests cover failure isolation and ordering, including malformed/admission failures before side effects at `tests/test_request_pipeline.py:257`, auth failure before dispatch at `tests/test_request_pipeline.py:507`, and direct peer identity at `tests/test_request_pipeline.py:458`.

The core method registry is a strong boundary. `xferry/features.py:18` defines method metadata, and tests assert the registry, CORS/mutation derivations, handler binding, plugin separation, and UI alignment at `tests/test_core_method_policy.py:92` and `tests/test_core_method_policy.py:178`.

The plugin API is intentionally narrow. `xferry/extensions.py:17` exposes only `PluginServices(upload_dir, upload_storage)`, and handler context tests enforce documented dependencies and no server escape hatch at `tests/test_handler_context.py:19` and `tests/test_handler_context.py:210`.

## Issues Found

- [MEDIUM] Publication goal conflicts with accepted source-only release architecture
  - File/area: `docs/ADR/ADR-006-release-artifacts.md:13`, `docs/security.md:12`, `.github/workflows/release.yml:1`
  - Evidence: ADR-006 says automated jobs do not publish to PyPI, GHCR, or GitHub Releases; the security docs repeat no package/binary/image publication; release workflow permissions are read-only and the gate only confirms verification at `.github/workflows/release.yml:201`.
  - Detail: Adding PyPI/GHCR/GitHub Releases or portable CLI artifacts is not just a CI change; it changes the repository's release trust model.
  - Impact: Publishing without a new ADR/operator model risks unsigned or under-specified artifact provenance, confusing rollback/update semantics, and docs that contradict actual distribution.
  - Confidence: High.

- [MEDIUM] Release platform/manifest contract is duplicated across build, installer, updater, and managed-state validation
  - File/area: `tools/build_scie_release.py:115`, `packaging/install.sh.in:19`, `xferry/management/releases.py:42`, `xferry/management/managed_state.py:338`
  - Evidence: Builder emits `linux-x86_64`; installer only accepts Linux x86_64/systemd; updater has `_PLATFORM = "linux-x86_64"`; managed-state parser hardcodes platform and executable naming.
  - Detail: The same artifact schema and platform rules are hand-maintained in several places.
  - Impact: Adding Linux aarch64 or Windows/macOS portable artifacts risks drift where one component builds an artifact another component rejects or mishandles.
  - Confidence: High.

- [LOW] Strict typing gate is fragile at the lazy Notepad service boundary
  - File/area: `xferry/handlers/notepad.py:281`, `.github/workflows/ci.yml:67`, `pyproject.toml:147`
  - Evidence: CI runs `mypy xferry`; mypy is strict; `_get_notepad_service()` lazily reads and returns `_notepad_service` via `getattr` at `xferry/handlers/notepad.py:283`. Runtime concurrency behavior is tested at `tests/test_handler_context.py:123`.
  - Detail: This looks like a type-confidence issue, not a proven runtime defect.
  - Impact: CI/type confidence is reduced even though runtime behavior appears covered.
  - Confidence: Medium.

- [LOW] RequestPipeline-to-server private-hook coupling remains a change hotspot
  - File/area: `xferry/request_pipeline.py:71`, `xferry/server.py:23`
  - Evidence: `RequestPipelineServer` depends on many private `_server` hooks, while `server.py` composes many subsystems.
  - Detail: This is acceptable today because sequencing tests are strong, but cross-cutting changes can accidentally break admission/auth/session/WebSocket ordering.
  - Impact: Future security or protocol changes may require touching several private hook contracts at once.
  - Confidence: Medium.

## Concrete Recommendations

1. Before adding publication channels, write a new release ADR covering artifact provenance, signing/checksums/SBOMs, supported platforms, rollback semantics, and operator docs. Expected gain: prevents release-trust drift. Cost: small design step before implementation.
2. Introduce one shared Python release artifact/platform model for builder, updater, managed-state parser, and tests. Keep the shell installer generated from that model or from per-platform generated literals. Expected gain: safer multi-platform expansion. Cost: modest refactor around release metadata.
3. Fix the Notepad lazy-service typing locally, without changing runtime behavior. A helper or explicit typed local after the lock should be enough. Expected gain: restore strict mypy confidence. Cost: very small.
4. Do not refactor `server.py` broadly for current distribution work. Treat it as a composition root. Only extract new adapters when changing a specific behavior such as auth runtime, operator output, admission, or session control.

## Quick Wins

- Add/adjust the Notepad type narrowing so `mypy xferry` passes.
- Add one release-contract test that enumerates supported platform IDs from a single source of truth.
- Add a short publication-policy reminder to any issue or plan about PyPI/GHCR/GitHub Releases until ADR-006 is superseded.

## Deeper Improvements

- Replace duplicated release manifest/platform parsing with a shared `ReleaseArtifact`/`PlatformId` model.
- Split managed Linux installer concerns from portable CLI artifact concerns; they have different OS, privilege, systemd, and update assumptions.
- If request-pipeline behavior expands, consider replacing private server hooks with a smaller explicit runtime interface object rather than a broad server protocol.

## Open Questions

- Are PyPI/GHCR/GitHub Releases now an intended product goal, or should ADR-006 remain authoritative? Answered by user: publication is the target and ADR-006 must be superseded.
- Which targets are required? Answered by user: portable Windows/macOS/Linux CLI; managed Ubuntu/Debian x86_64+aarch64; multi-arch container.
- Should remote updates remain disabled? Answered by user: expose an explicit managed `xferry update` workflow.
