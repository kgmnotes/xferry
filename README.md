# xferry

[![CI](https://github.com/kgmnotes/xferry/actions/workflows/ci.yml/badge.svg)](https://github.com/kgmnotes/xferry/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/Python-3.10--3.14-blue.svg)](https://www.python.org/)
![Source version](https://img.shields.io/badge/version-0.5.0-orange.svg)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

xferry is an HTTP toolkit for testing Secure Web Gateways on systems you are
authorized to test. Its web UI provides **Upload**, **Download**, **Requests**,
**Advanced**, and **Notepad** tabs.

This checkout documents the **unpublished 0.5.0 candidate**. The commands below
apply to that version; published older packages use their own release documentation.
To try the candidate before publication, use a [source checkout](CONTRIBUTING.md).

## Choose a way to run

Install the CLI on the machine where files will be served:

```console
pipx install xferry
```

**Run once** as a portable foreground process on your computer. Open the printed
URL and stop with `Ctrl+C`:

```console
xferry run --open
```

Choose another shared folder explicitly:

```console
xferry run --files-dir ~/Shared --open
```

**Persistent Linux service** on a [supported host](docs/managed-hosts.md) or VPS:

```console
xferry setup --backend native --files-dir /srv/share
```

**Container** on a host with Docker Engine and its Compose plugin:

```console
xferry setup --backend docker --files-dir /srv/share
```

Setup previews the installation, checks the selected folder, starts the server,
and prints its deployment ID, URL and generated Basic Auth password. Public
setup uses browser-trusted TLS on port **443**. Choose an automatic address or
your own domain; inbound TCP 80 must also be reachable for certificates.

Run `xferry` for an interactive menu. The menu distinguishes running, stopped,
incomplete and retained installations, and offers the matching next action.
See the [quick start](docs/quick-start.md) for all three journeys, a first transfer
and removal. A [source checkout](CONTRIBUTING.md) and manual Compose are operator
workflows. Existing deployments must follow the [upgrade notes](docs/migration.md);
the current interface does not convert legacy configuration or deployment state.

## Choose where files live

```console
xferry run --files-dir /srv/share
xferry run --files-dir .
```

The selected directory is used directly: existing files can be downloaded, new
uploads are saved there, and deletion actions affect its contents. With no
folder specified, foreground runs use your user data directory; a new Linux
service uses `/var/lib/xferry/files`. These defaults do not depend on the current
directory. Notes, passwords and certificate state are kept separately. Use a separate
shared folder for each persistent instance.

## Change settings and manage the server

```console
xferry config
xferry config explain files_dir
xferry status
xferry logs
xferry stop
xferry start
```

Configuration changes automatically apply to a running installed server. A
stopped server stays stopped. Use `--instance ID` to select a persistent
deployment, or `config --config FILE` for a foreground profile.
[All settings](docs/settings.md) includes defaults, units and examples;
`xferry --help` shows common commands and `xferry run --help-all` shows all launch
options.

`xferry uninstall` removes the selected runtime and retains configuration,
credentials, private state and the shared folder for reinstall. `xferry uninstall
--purge --yes` removes resources recorded as owned by xferry; the shared folder
and its files remain, including the default files folder. Both commands print
the resources they retain. Purge requires an explicit confirmation; declining
the prompt cancels it, and scripts must pass `--yes`.
The separately installed pipx CLI is removed with `pipx uninstall xferry`.

## Try a transfer

```bash
printf 'authorized test\n' > sample.txt
curl --fail-with-body -H 'X-File-Name: sample.txt' \
  --data-binary @sample.txt http://127.0.0.1:8080/uploads
curl --fail-with-body http://127.0.0.1:8080/uploads/sample.txt
```

For authenticated HTTPS, add `--user USER` and use the URL printed by setup.

- [Common scenarios](docs/scenarios.md): methods, files, notes and transport artifacts
- [API reference](API.md): Advanced Sessions, custom HTTP methods such as `SYNCDATA`, and payload protection (`none`, XOR, AES-256-GCM)
- [Operations](docs/operations.md), [public deployment](docs/public-direct.md), [managed hosts](docs/managed-hosts.md)
- [CLI reference](docs/cli-reference.md), [migration](docs/migration.md), [security](SECURITY.md)

Documentation: <https://xferry.kgmnotes.ru/> · License: MIT
