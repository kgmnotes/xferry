# Quick start

This page describes the unpublished **0.5.0 source candidate**. Published older
packages keep their version's CLI. For candidate validation before release,
install a [source checkout](contributing.md) with its matching artifacts.

Run these commands on the machine where files will be served. For a VPS, connect
to its terminal first. The current configuration format is version 1 and the
deployment manifest is version 2. Older state is rejected without modification;
read [upgrade notes](migration.md) before replacing an existing installation.

## Install the CLI

xferry supports Python 3.10–3.14. Install pipx once if needed:

| System | Commands |
| --- | --- |
| Debian / Ubuntu | `sudo apt install pipx`, then `pipx ensurepath` |
| macOS with Homebrew | `brew install pipx`, then `pipx ensurepath` |
| Windows PowerShell | `py -m pip install --user pipx`, then `py -m pipx ensurepath` |

Open a new terminal after `ensurepath`, then install:

```console
pipx install xferry
```

`xferry` opens the interactive menu. The commands below give the same choices
explicitly. Use a release that includes this interface; a source checkout uses
its own matching artifacts as described in [Contributing](contributing.md).

## Run once

```console
xferry run --open
```

To select a specific shared folder:

```console
xferry run --files-dir ~/Shared --open
xferry run --files-dir .
```

The default address is <http://127.0.0.1:8080>. The selected folder is served
directly: existing files can be downloaded and uploads are saved there. Choose a
folder whose entire contents you intend to share and modify. Without
`--files-dir`, xferry uses a stable per-user folder outside the current directory.

Press `Ctrl+C` to stop. Save a foreground profile with
`xferry config --config ~/xferry.ini`; run it again with
`xferry run --config ~/xferry.ini`. Explicit launch options override that profile.
Notes, credentials and certificates stay outside the public folder.

## Persistent Linux service

Use a [supported Linux host](managed-hosts.md) with systemd:

```console
xferry setup --backend native --files-dir /srv/share
```

The CLI requests sudo, asks for access, previews the resources it will create,
then installs a verified signed runtime and starts the service. A newly created
shared folder defaults to `/var/lib/xferry/files`. Existing files keep their
owner; xferry grants the runtime access using the deployment's recorded policy.

Public setup uses trusted HTTPS on **443** and a generated 12-character Basic
Auth password designed for typing. Choose an automatic address (requires public
IPv4) or enter your domain after pointing DNS at the host. Allow inbound TCP
**80 and 443**. Port 80 remains necessary for certificate renewal. Setup prints
the URL, credentials and deployment ID. Save the password when it is displayed.
The [public deployment guide](public-direct.md) explains HTTPS and network requirements.

For a scripted setup with a domain:

```console
xferry setup --backend native --access public --domain files.example.com --files-dir /srv/share
```

Private access is an explicit alternative for a loopback-only server:

```console
xferry setup --backend native --access private --files-dir /srv/share
```

## Container through setup

Docker Engine and the Compose plugin must already work for your user:

```console
xferry setup --backend docker --files-dir /srv/share
```

The wizard asks the same access questions and starts the deployment. Public
HTTPS is exposed on host **443**; internal container ports are managed by the
backend. Your INI describes host paths and public ports. A separate runtime
profile maps these into the container. The image is pinned by digest.

Use a dedicated shared folder for each persistent instance; choose a different
folder when creating another deployment. Keep the generated manifest, operator
INI and secret files. The manifest records
the deployment identity, ownership and image. Select this deployment using its
printed ID when more than one exists:

```console
xferry status --instance ID
xferry stop --instance ID
xferry start --instance ID
xferry doctor --instance ID --deep
```

Ordinary configuration keeps the pinned image. Updates use
`xferry update --to VERSION --instance ID`. [Operations](operations.md) covers
advanced installation, manual Compose and recovery.

## Send a first file

1. Open the URL printed by setup and enter the printed username and password.
2. In **Upload**, choose a small test file and press **Send**. Protocol controls
   are available under **Advanced options**.
3. Open **Download**, download the file and verify its contents. Delete it when
   it is no longer needed.

For the loopback foreground server, the same transfer works with curl:

```bash
printf 'authorized test\n' > sample.txt
curl --fail-with-body -H 'X-File-Name: sample.txt' \
  --data-binary @sample.txt http://127.0.0.1:8080/uploads
curl --fail-with-body http://127.0.0.1:8080/uploads/sample.txt
```

For public access, use the printed HTTPS URL and add `--user USER`; curl prompts
for the password. Do not disable certificate verification.

## Stop, reinstall and remove

Use `Ctrl+C` for a foreground run. Both persistent backends use the same commands:

```console
xferry stop --instance ID
xferry start --instance ID
xferry uninstall --instance ID
```

Uninstall removes the runtime and retains configuration, credentials, files,
notes and certificate state. The menu offers reinstall with the retained data;
you can also run `xferry setup --backend native --instance ID` or choose `docker`
for the corresponding deployment.

To delete xferry-owned resources too, review its plan first:

```console
xferry uninstall --instance ID --purge --dry-run
xferry uninstall --instance ID --purge --yes
```

Without `--yes`, an interactive terminal shows the plan and asks for confirmation;
answering No cancels the operation. Scripts must pass `--yes`. A dry-run does not
require confirmation and does not remove resources.

Purge uses recorded ownership. The shared folder and its files remain, including
the native default `/var/lib/xferry/files`. Changed or unowned resources are
reported and preserved. The deployment manifest and registry entry are removed.
The service account is removed only when retained folders or files no longer
need its identity. The separate CLI installed by pipx remains available:

```console
pipx uninstall xferry
```

Removing the CLI does not remove a running service or container. Stop and
uninstall the selected deployment first. A CLI installed in your own virtual
environment is removed with that environment's package manager.
