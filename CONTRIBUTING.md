# Contributing

Focused fixes, tests, and documentation improvements are welcome. Open an
issue before a large behavior or protocol change so the contract can be agreed
before implementation.

## Development setup

```bash
git clone https://github.com/kgmnotes/xferry.git
cd xferry
python3 -m venv .venv
. .venv/bin/activate
PIP_CONSTRAINT=constraints/ci.txt python -m pip install -e '.[dev,lint,test,docs]'
pre-commit install
```

The project supports Python 3.10 through 3.14. `constraints/ci.txt` pins the
toolchain used by CI, documentation, security checks, and container builds.

On Windows PowerShell:

```powershell
$env:PIP_CONSTRAINT = "constraints/ci.txt"
python -m pip install -e ".[dev,lint,test,docs]"
Remove-Item Env:PIP_CONSTRAINT
```

## Branches and commits

Create a short-lived branch from `main`. Use Conventional Commit summaries,
for example `fix(upload): reject an invalid filename` or
`docs(api): clarify Advanced Session ownership`.

Do not merge into `main` without review and passing CI.

## Checks

Run the checks relevant to your change. The complete local set is:

```bash
python -m pip check
python tools/check_dependency_constraints.py --constraints constraints/ci.txt
ruff check xferry tests tools
ruff format --check xferry tests tools
mypy xferry
pytest --cov=xferry --cov-report=term-missing
python tools/render_settings.py --check
python tools/render_contracts.py --check
python tools/sync_docs.py --check
python tools/check_stale_docs.py
python tools/check_public_surface.py
mkdocs build --strict
```

Browser changes also require the affected browser smoke mode. Available modes
include `first-run`, `ui-contracts`, `request-matrix`, `advanced`, `files`,
`notepad`, `mobile`, and `full`.

## Documentation

The root files `API.md`, `CHANGELOG.md`, `CONTRIBUTING.md`, and `SECURITY.md`
are canonical. Their `docs/` copies are generated. The marked settings regions
in the Docker and systemd INI examples come from the operator settings schema;
the marked method and capability tables in `API.md` come from the runtime
contract registries. Regenerate all derived files in this order:

`docs/cli-reference.md` is the generated CLI reference captured from the real
English dispatcher. `docs/managed-hosts.md` is the generated managed support
matrix sourced from the runtime host contract.

```bash
python tools/render_settings.py --write
python tools/render_contracts.py --write
python tools/sync_docs.py --write
python tools/render_settings.py --check
python tools/render_contracts.py --check
python tools/sync_docs.py --check
```

Keep API examples synchronized with actual handlers and tests. Architectural
decisions live in `docs/ADR/`. Update an active ADR only when the decision
itself still holds; otherwise replace the decision set deliberately.

## Code conventions

- Use Python 3.10-compatible syntax and type public production code.
- Use `pathlib.Path` for paths and the shared descendant resolver for
  user-supplied path components. See
  [ADR-004](docs/ADR/ADR-004-upload-containment.md).
- Use `secrets` for security-sensitive randomness.
- Keep response errors in the documented four-field JSON envelope.
- Keep user-facing logs, CLI help, responses, and documentation in English.
- Never log credentials, Advanced Session tokens, payload keys, note keys, or
  plaintext content.

## Adding an HTTP method

1. Add or extend the scoped handler in `xferry/handlers/`.
2. Add one `CoreMethodSpec` in `xferry/features.py`.
3. Add unit and integration coverage for dispatch, CORS, browser mutation
   policy, and `PING` discovery where applicable.
4. Document the wire contract in `API.md`.
5. Add an ADR only when the change makes a durable architectural decision.

## Writing a plugin method

Plugins are loaded only through an explicit operator allowlist. A
`PluginMethodSpec` handler has the signature
`(HTTPRequest, HandlerContext) -> HTTPResponse`. The frozen, slotted public
boundary is exactly `PluginServices(upload_dir, upload_storage)` inside
`HandlerContext(services, plugin_name)`: handlers may read
`context.plugin_name`, `context.services.upload_dir`, and
`context.services.upload_storage`.

The former `context.server` reference is removed without a property, alias,
`__getattr__`, or compatibility shim. No authentication controller, request
pipeline, TLS or lifecycle state, metrics collector, Notepad service, Advanced
Session store, or SMUGGLE coordinator is part of the supported plugin API.
Publish bytes with the quota-aware
`context.services.upload_storage.publish_bytes(file_path, data)` service;
`file_path` must be a direct child of `context.services.upload_dir`. Do not
write directly into the upload directory when publishing a plugin result.

Plugin publication does not grant SMUGGLE provenance. An ordinary XHTML file,
including one with a SMUGGLE-like name, remains an ordinary upload and is sent
as an attachment; only artifacts registered by the core SMUGGLE coordinator
retain the runnable, one-shot contract. Request admission and authentication
complete before plugin dispatch. Core override and public-direct plugin use
each require explicit operator opt-in.

## Distribution verification

The source checkout is the contributor workflow; it is not the first user
installation path. Public user documentation separates portable pipx, managed
Linux, and immutable container lifecycles. Release automation must promote one
verified candidate without rebuilding, and production publication remains
behind protected approvals. Do not deploy release-branch documentation before
the corresponding artifacts are activated. Local Compose examples may build
the checkout only when they are clearly labelled as contributor examples.

## Security reports

Do not report vulnerabilities in a public issue. Follow the private process in
[SECURITY.md](SECURITY.md).
