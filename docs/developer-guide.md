# Developer guide

Use this page to find the code and checks for a change. Paths below are relative
to the repository root. Start with [development setup](contributing.md#development-setup)
for the Python environment; [architecture](architecture.md) explains the runtime
contracts, and [ADRs](ADR/README.md) record why those contracts were chosen.

## Repository map

The application has two main parts: the HTTP server and the management layer
that configures, installs and controls it. Both ship in the `xferry` package.

| Area | Source locations | Responsibility and reference |
| --- | --- | --- |
| Management | `xferry/management/` | CLI dispatch, configuration, setup, systemd/Docker lifecycle, signed updates and rollback. See [operations](operations.md) and [CLI reference](cli-reference.md). |
| Server composition and lifecycle | `xferry/server.py`, `xferry/server_config.py`, `xferry/lifecycle.py`, `xferry/websocket_runtime.py` | Wire services, accept connections, own workers and clean up resources. See [architecture](architecture.md). |
| HTTP and dispatch | `xferry/http/`, `xferry/request_admission.py`, `xferry/request_pipeline.py`, `xferry/handlers/`, `xferry/features.py` | Parse bounded requests, enforce admission, dispatch methods and produce responses. See [API reference](api.md). |
| Security | `xferry/security/`, `xferry/runtime_posture.py` | Authentication, cryptography, TLS issuance/renewal and deployment validation. See [threat model](threat-model.md). |
| Data services | `xferry/storage.py`, `xferry/paths.py`, `xferry/encrypted_storage.py`, `xferry/encrypted_transfer.py`, `xferry/notepad_service.py`, `xferry/advanced_sessions.py`, `xferry/smuggle/` | File publication, quotas, encrypted transfers, notes, Advanced Sessions and generated artifacts. See [settings](settings.md), [encrypted transfers](encrypted-transfers.md) and the API reference. |
| Browser UI | `xferry/data/index.html`, `xferry/data/static/ui/` | Packaged HTML, CSS and JavaScript, organized by workflow. See [frontend contract](frontend-contract.md). |
| Tests and tools | `tests/`, `tools/` | Unit, integration, property and browser checks; documentation generators and release tooling. See [contributor checks](contributing.md#checks). |
| Deployment and distribution | `deploy/`, `examples/`, `packaging/`, `.github/workflows/`, `pyproject.toml`, `constraints/ci.txt` | Deployment templates, contributor examples, artifact builds, CI and pinned tooling. See [release runbook](release-runbook.md). |

## Follow execution

### Starting the server

```text
xferry / python -m xferry
  -> xferry.management.cli.main
  -> run command: xferry.cli.run_main
  -> settings.resolve_settings -> ServerSettings.to_server_config
  -> XFerryServer(ServerConfig)
  -> server.start -> ServerLifecycle
```

The console entry point is declared in `pyproject.toml`; `xferry/__main__.py`
uses the same dispatcher. `xferry/management/cli.py` selects commands such as
`setup`, `config` and `run`. `xferry/cli.py` owns foreground server arguments
and startup; its `main` function delegates back to the common dispatcher.

Setting definitions live in `xferry/settings_schema.py`; resolution lives in
`xferry/settings.py`. `xferry/server_config.py` defines the immutable runtime
configuration. Consult [value sources](settings.md#value-sources) before changing
precedence or defaults.

### Handling a request

1. `ServerLifecycle` in `xferry/lifecycle.py` accepts a connection, reserves
   capacity and submits work to the connection worker pool.
2. `XFerryServer` in `xferry/server.py` handles TLS when enabled and delegates
   bounded request reception to `xferry/http/io.py`.
3. `RequestPipeline.process` in `xferry/request_pipeline.py` constructs an
   `HTTPRequest`, attaches the direct peer and applies the policy from
   `xferry/request_admission.py`. Authentication and route-specific checks run
   before handler dispatch; WebSocket upgrades take their own runtime path.
4. `HandlerMixin._dispatch_handler` in `xferry/handlers/__init__.py` resolves
   control routes, Advanced Sessions and registered methods. Built-in method
   metadata comes from `xferry/features.py`; handlers use scoped services from
   `xferry/handlers/context.py`.
5. Handlers call data services, return an `HTTPResponse`, and the pipeline sends
   it through the server response helpers and records metrics. Rejected requests
   can return before dispatch. `xferry/http/response.py` owns response encoding.

For browser changes, start at `xferry/data/index.html` and follow the script
sequence in the [frontend load order](frontend-contract.md#load-order).
`window.XferryApp` connects shared services and workflow modules. The browser
uses the same HTTP/WebSocket contracts as other clients.

## Choose a change route

Run these focused checks from the repository root in the development environment.
They are starting points for the affected behavior; the full quality checks
remain in [Contributing](contributing.md#checks).

### HTTP methods and dispatch

Start with `xferry/features.py`, `xferry/handlers/` and
`xferry/request_pipeline.py`. Follow [adding an HTTP method](contributing.md#adding-an-http-method)
and update the canonical root `API.md` when the wire contract changes.

```bash
python -m pytest -q tests/test_core_method_policy.py tests/test_handler_registry.py tests/test_request_pipeline.py tests/test_server_methods.py
```

### CLI and settings

Use `xferry/management/cli.py` for command routing, `xferry/cli.py` for `run`,
`xferry/settings_schema.py` and `xferry/settings.py` for runtime settings, and
`xferry/management/configuration.py` for persisted configuration workflows.
Keep the [settings reference](settings.md) and generated CLI help current.

```bash
python -m pytest -q tests/test_cli.py tests/test_management_cli.py tests/test_settings.py tests/test_settings_schema.py tests/test_configuration_workflow.py
```

### Ordinary files and quotas

Start with `xferry/handlers/files.py` and `xferry/storage.py`. Shared descendant
resolution lives in `xferry/http/utils.py`; `xferry/paths.py` selects default
data and configuration locations.
`files_dir` is the actual public file directory; the HTTP prefix `/uploads/`
does not imply a nested directory. Review [storage boundaries](architecture.md#storage-boundaries)
and [ADR-004](ADR/ADR-004-upload-containment.md) before changing path handling.

```bash
python -m pytest -q tests/test_handlers/test_files.py tests/test_files_directory.py tests/test_handlers/test_path_traversal.py tests/test_http/test_path_traversal_prefix.py
```

### Encrypted transfers and recovery

Start with `xferry/encrypted_transfer.py`, `xferry/encrypted_storage.py` and
`xferry/handlers/encrypted_files.py`; client modules are the
`encrypted-transfer*.js` files under `xferry/data/static/ui/`. Read the
[transfer operations](encrypted-transfers.md), [frontend contract](frontend-contract.md#encrypted-transfer-workflow)
and [ADR-012](ADR/ADR-012-encrypted-streaming-transfers.md).

```bash
python -m pytest -q tests/test_encrypted_transfer.py tests/test_encrypted_storage.py tests/test_encrypted_api.py tests/test_encrypted_recovery.py
python tools/browser_smoke.py --mode encrypted-transfer
```

### Browser interface

Edit the relevant workflow in `xferry/data/static/ui/` and its markup in
`xferry/data/index.html`. Preserve the [frontend public surface](frontend-contract.md#public-surface)
and shared service boundaries. Run the UI contracts and the affected journey;
the example below selects file management.

```bash
python -m pytest -q tests/test_static_ui_assets.py
python tools/browser_smoke.py --mode ui-contracts
python tools/browser_smoke.py --mode files
```

### Installation and updates

Start with `planning.py`, `setup.py`, `service.py`, `releases.py`,
`release_contract.py` and `release_trust.py` under `xferry/management/`.
Check behavior against [managed lifecycle](operations.md#managed-linux-lifecycle).

```bash
python -m pytest -q tests/test_management_planning.py tests/test_management_setup.py tests/test_management_service.py tests/test_management_releases.py
```

The publication pipeline is a separate concern: `tools/candidate_inventory.py`,
`tools/production_release.py` and the release workflows under `.github/workflows/`.
Its focused tests are `tests/test_candidate_promotion.py`,
`tests/test_production_release.py` and `tests/test_release_production.py`.
Follow the [release runbook](release-runbook.md) for publication procedures.

## Testing and documentation conventions

- `tests/conftest.py` isolates operator data paths and blocks direct privileged
  host commands through `subprocess.run`. Management tests inject process runners,
  layouts and downloaders; use the existing fake implementations as examples.
- `tests/server_factory.py` provides test-only `make_server_config` and
  `make_server` adapters. Production code constructs `XFerryServer(ServerConfig(...))`.
- `make_request` in `tests/conftest.py` supplies a default Host and test admission
  context. Calling a handler with it does not exercise the complete authentication
  and request pipeline; use pipeline or live-server tests for that behavior.
- Some pytest UI checks invoke Node.js. Browser smoke also requires Chromium and
  the pinned Playwright CLI; browser CI uses Node 22. This tooling is for tests;
  the application itself has no frontend build step. Install the CI browser with:

  ```bash
  npx --yes --package @playwright/cli@0.1.9 playwright-cli install-browser chromium --with-deps
  ```

- `python tools/browser_smoke.py --help` lists current journeys. Without an
  external target, `--mode full` runs all journeys against temporary servers.
  With `--target-url`, `full` covers only the cross-tool scenario and modifies
  the target's data; see [browser checks](contributing.md#checks).
- `--browser chromium|firefox|webkit` selects an engine; Chromium remains the
  default. The base browser matrix runs `first-run`, `basic-upload-profiles`,
  `request-matrix`, `files`, `notepad` and `encrypted-compatibility`. The full
  suite and positive encrypted-transfer journey require Chromium. Install and
  run a second engine with:

  ```bash
  npx --yes --package @playwright/cli@0.1.9 playwright-cli install-browser firefox --with-deps
  python tools/browser_smoke.py --browser firefox --mode request-matrix
  python tools/browser_smoke.py --browser firefox --mode encrypted-compatibility
  ```

  Substitute `webkit` for the other matrix job. Non-default engines use
  `output/playwright/browser-smoke/<browser>/<mode>` unless `--artifacts-dir`
  supplies an explicit directory. Receipts record `browserName`; CI preserves
  each engine's results and failure diagnostics independently. Refer to the
  [browser support contract](frontend-contract.md#browser-support-and-acceptance)
  for the Large files capability boundary. Temporary local servers bypass
  inherited proxies; package downloads keep their proxy settings. Explicit
  `--target-url` runs retain the caller's proxy configuration.
- Do not add whole-package coverage to a focused test selection: the configured
  85% threshold belongs to the full suite. Use the full coverage command from
  Contributing when checking that threshold.
- Update canonical documents and regenerate their derived regions and mirrors
  using the [documentation workflow](contributing.md#documentation). Settings
  examples, contract tables and CLI help derive from code; architectural prose
  still needs a manual comparison with the implementation.
