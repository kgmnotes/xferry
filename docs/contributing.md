<!-- Generated from ../CONTRIBUTING.md by tools/sync_docs.py. Edit CONTRIBUTING.md and rerun the sync tool. -->

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
are canonical. Their `docs/` copies are generated:

```bash
python tools/sync_docs.py --write
python tools/sync_docs.py --check
```

Keep API examples synchronized with actual handlers and tests. Architectural
decisions live in `docs/ADR/`. Update an active ADR only when the decision
itself still holds; otherwise replace the decision set deliberately.

## Code conventions

- Use Python 3.10-compatible syntax and type public production code.
- Use `pathlib.Path` for paths and the shared descendant resolver for
  user-supplied path components. See
  [ADR-004](ADR/ADR-004-upload-containment.md).
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

## Release workflow

The repository contains a release workflow for Python distributions, a
container image, and SCIE installer assets. Publication requires a version tag
and all verification lanes to pass. A manual workflow run verifies artifacts
but does not publish them. No release artifact is currently public, so user
documentation must keep source installation first.

## Security reports

Do not report vulnerabilities in a public issue. Follow the private process in
[SECURITY.md](security.md).
