# Testing on your VPS before a stable release

The protected `testing` branch publishes opt-in builds for manual VPS checks.
`main` and the normal PyPI package remain the stable channel. A successful
preview build does not authorize a production release or deploy to any server.

## Development and publication

Create feature branches from `testing` and open PRs into `testing`. The required
`CI gate` combines the relevant checks for the exact commit. Documentation-only
changes run documentation checks; runtime, dependency, workflow, build-tool and
unknown paths run the full checks. A documentation-only push does not publish
another package. Manual Testing Builds dispatch on `testing` can rebuild a
commit with a new identity.

`packaging/channels.toml` selects the next stable target, initially `0.5.1`.
CI creates a temporary source tree and stamps a unique PEP 440 version such as
`0.5.1.devN`, source SHA and `run.attempt` build ID. It does not commit generated
preview version changes back to the branch.

Every preview contains the same identity in:

- the wheel and sdist on **TestPyPI**;
- signed native executables for Linux x86_64 and aarch64 in the public
  `testing-vVERSION` GitHub prerelease;
- the multiarch image in **ghcr.io/kgmnotes/xferry-testing**, addressed by digest.

Testing manifests use a separate signing key. A signed `testing-images.json`
selects the Docker digest. Setup and update require the CLI and runtime to have
exactly the same version, source SHA and build ID. Install the wheel belonging
to the selected build first. Missing artifacts or an identity/signature mismatch
stop the operation; they never select a stable artifact as a fallback.

The Testing Builds workflow verifies published bytes, TestPyPI hashes and
anonymous access to both image architectures, then attaches
`testing-ready.json` to the prerelease. Use only a build with that report and a
successful workflow. A partially published build is not ready.

## Install and update

Open the selected [testing prerelease](https://github.com/kgmnotes/xferry/releases)
and download its `testing-ready.json`. It records the exact version, source,
build ID, image digest and copyable commands. Use `commands.pipx` to install a
separate `xferry-preview` command. Its hash-pinned wheel URL comes from TestPyPI;
dependencies use the normal PyPI index. A venv user can use `commands.pip`
instead. Do not combine TestPyPI and PyPI with `--extra-index-url`.

On a clean Debian/Ubuntu VPS, install prerequisites before the report's pipx
command:

```bash
sudo apt update
sudo apt install pipx
pipx ensurepath
```

Start a new shell if pipx is not yet on PATH. Choose one backend and use the
report's `commands.native` or `commands.docker`. The setup wizard asks for the
remaining settings. The native service uses the signed standalone executable;
Docker uses the signed catalog's immutable digest. Neither needs a Git checkout.

For an existing deployment, install the new preview wheel and run the report's
`commands.update`, adding `--instance ID` if needed. The first stable-to-testing
switch must explicitly specify `--channel testing`. Later updates retain the
recorded channel if the flag is omitted. Check identity and health:

```bash
xferry-preview status --json
xferry-preview doctor --deep --json
```

The report's installation commands use `/srv/share` as the files directory;
select the directory you actually intend to share. Keep the preview controller
installed separately from an existing stable controller.

## Rollback and manual checks

Before switching an existing stable deployment to testing, take a normal
[backup](backup-restore.md). XFerry separately retains the last stable runtime
and its compatible profile, compiled configuration and service definition.
Further preview updates do not rotate this stable snapshot out of history.
Current credentials and user data remain current during rollback.

```bash
xferry-preview rollback --channel stable --dry-run
xferry-preview rollback --channel stable
xferry-preview doctor --deep --json
```

Add `--instance ID` when selecting a Docker bundle or one of several instances.
A fresh preview installation has no previous stable snapshot. Use a disposable
deployment for clean-install checks and a separate existing stable deployment
for update/rollback checks. Remove the disposable deployment after testing.
Rollback between previews requires installing the target preview's CLI wheel
and selecting that exact retained version with `--to VERSION`.

On your VPS, check clean installation, the interactive setup/configurator,
authenticated health, upload/download, restart and data persistence, then the
stable-to-preview update and stable rollback. Repeat the relevant checks for
the backend and architecture you use. CI uses container and disposable runner
fixtures; access to your servers remains manual.

## Accept and prepare stable

After the owner explicitly accepts the exact tested build, record its version,
source SHA and build ID with **Testing Acceptance**. The workflow is dispatched
from protected `main` once the workflow has reached that branch; set
`confirm_vps_checks` only after the manual checks above. It attaches an immutable
`testing-acceptance.json` receipt. Neither this workflow nor a `testing` push
creates a production tag.

Merge the accepted `testing` history into `main` without squashing its source
ancestry, then add a final release commit. Its allowed
changes are version markers, changelog/generated version metadata and the exact
`[promotion]` selection in `packaging/channels.toml`:

```toml
[promotion]
version = "THE_ACCEPTED_PREVIEW_VERSION"
source_commit = "THE_ACCEPTED_SOURCE_SHA"
build_id = "THE_ACCEPTED_RUN.ATTEMPT"
```

The production preflight verifies the accepted preview's signatures, receipt
and restricted source diff. Functional changes require another preview and VPS
acceptance. The final stable package is rebuilt and tested with its final
version; its bytes differ from the `.dev` package. Continue with the
[production release runbook](release-runbook.md), including the existing single
production signing approval.

## Maintainer configuration

Protect `testing` with the required `CI gate`, PR review policy and no forced
pushes. Keep existing `main` checks until the new gate exists on `main`; then
migrate its protection deliberately. The `testing-signing` environment permits
only the protected `testing` branch, with no repeated production approval. It
contains `XFERRY_TESTING_SIGNING_KEY_PEM` and
`XFERRY_TESTING_SIGNING_KEY_ID=xferry-testing-2026-11`. The public key is
`6086c4feb99d9ef9b059c9df6d11fcbbfdb7a89ed82b43782b387b0b78c7cf4f`.

The existing TestPyPI trusted-publisher mapping continues to use `testpypi.yml`
and environment `testpypi`; allow `testing` there without a reviewer gate.
Production workflows still use their own environments, approval and signing key.
Set the separate `xferry-testing` GHCR package public so clean VPS installs need
no registry login. Ready verification fails while anonymous pulls are blocked.
