# Quick start

Run these commands on the host where the server will operate. The same setup
works on your computer or on a VPS; connect to the VPS terminal first.

These commands require **xferry 0.3.0 or newer**. Use matching artifacts from
the [versioned release](https://github.com/kgmnotes/xferry/releases/tag/v0.3.0)
or a [source checkout](contributing.md). Existing `0.2.x` installations should
follow the [migration guide](migration.md); the
[v0.2.0 commands](archive/0.2.0-installation.md) remain archived.

## Install the CLI

xferry supports Python 3.10–3.14. Install pipx once if needed:

| System | Commands |
| --- | --- |
| Debian / Ubuntu | `sudo apt install pipx`, then `pipx ensurepath` |
| macOS with Homebrew | `brew install pipx`, then `pipx ensurepath` |
| Windows PowerShell | `py -m pip install --user pipx`, then `py -m pipx ensurepath` |

Open a new terminal after `ensurepath`:

```console
pipx install xferry
xferry
```

## Portable

For a foreground process, select **Run once** in the menu or run:

```console
xferry run --open
```

Open <http://127.0.0.1:8080>. Press `Ctrl+C` to stop. Configure a saved profile
with `xferry config`; later `xferry run` reads it automatically. Explicit launch
options override saved values:

```console
xferry run --files-dir .
xferry run --port 9090
xferry run --config /path/to/xferry.ini
```

The first command serves the current directory directly. Choose a directory
whose entire contents you intend to share and allow xferry to modify. Without
`--files-dir`, files live in the stable user data directory described in
[Settings](settings.md#files-and-private-state).

## Managed Linux

```console
xferry setup
```

Select the Linux service, access mode, and files folder. Setup checks the
[supported host requirements](managed-hosts.md) and requests sudo before asking
configuration questions. It verifies the selected signed release and installs
the service, prepares credentials and HTTPS as needed, then prints the working
URL. The default files folder is `/var/lib/xferry/files`.

For public HTTPS with a domain, point its DNS record at this host first. For an
automatic address, the host needs a public IPv4 address. In both cases, allow
inbound TCP 80 for certificate issuance and renewal, and the chosen HTTPS port.
See [Public deployment](public-direct.md).

A repeatable private setup can use explicit options:

```console
xferry setup --access private --files-dir /srv/share
```

## Container

Docker Engine and the Compose plugin must already work for your user:

```console
xferry setup --docker
```

The wizard starts the deployment and uses the selected host folder directly as
a bind mount. Keep the generated deployment files: they identify the instance
and pin its image. Later CLI operations discover the deployment; `--config`
selects it explicitly if there is more than one instance:

```console
xferry status --config /path/to/deployment/xferry.ini
xferry stop --config /path/to/deployment/xferry.ini
xferry start --config /path/to/deployment/xferry.ini
```

Ordinary configuration keeps the pinned image. Image updates require `xferry update --to VERSION`. For manually maintained containers, use an immutable
version or digest; [Operations](operations.md#container-lifecycle) explains ownership.

## Send a first file

1. Open **Upload**, choose a small test file and send it.
2. Check the HTTP result and the saved file path.
3. Open **Download**, download the file, then delete it if no longer needed.

The equivalent loopback API example:

```bash
printf 'authorized test\n' > sample.txt
curl --fail-with-body -H 'X-File-Name: sample.txt' \
  --data-binary @sample.txt http://127.0.0.1:8080/uploads
curl --fail-with-body --request INFO http://127.0.0.1:8080/uploads/
curl --fail-with-body http://127.0.0.1:8080/uploads/sample.txt
```

For public access, use the printed HTTPS URL and `--user USER`; curl prompts for
the password. See [Scenarios](scenarios.md) for the other tabs.

## Stop and protect data

Use `Ctrl+C` for a foreground run or `xferry stop` for a service/container.
`xferry uninstall` preserves data by default, and setup can reuse the preserved
installation. `xferry uninstall --purge-data` also deletes retained application
data. Review the selected files folder before choosing this destructive action.
