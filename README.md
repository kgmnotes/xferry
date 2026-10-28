# xferry

[![CI](https://github.com/kgmnotes/xferry/actions/workflows/ci.yml/badge.svg)](https://github.com/kgmnotes/xferry/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/Python-3.10--3.14-blue.svg)](https://www.python.org/)
![Source version](https://img.shields.io/badge/version-0.3.1-orange.svg)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

xferry is an HTTP toolkit for testing Secure Web Gateways on systems you are
authorized to test. Its web UI provides **Upload**, **Download**, **Requests**,
**Advanced**, and **Notepad** tabs.

These commands require **xferry 0.3.1 or newer**. Existing `0.2.x` installations
use the [migration guide](docs/migration.md); [v0.2.0 instructions](docs/archive/0.2.0-installation.md)
remain archived. Obtain matching native/container artifacts from the
[versioned release](https://github.com/kgmnotes/xferry/releases/tag/v0.3.1).
Contributors can use a [source checkout](CONTRIBUTING.md).

## Start here

Install the CLI on the host where the server will run:

```console
pipx install xferry
xferry
```

The menu offers a foreground run, server setup, and configuration. For a quick
foreground run on <http://127.0.0.1:8080>:

```console
xferry run --open
```

For a persistent Linux service or Docker deployment:

```console
xferry setup
```

Setup checks prerequisites, asks for access and a files folder, starts the
server, and prints its URL. Public access configures HTTPS and generates a
12-character Basic Auth password. You can use a domain or an automatic address.
See the [quick start](docs/quick-start.md) for requirements and examples.

## Choose where files live

```console
xferry run --files-dir /srv/share
xferry run --files-dir .
```

The selected directory is used directly: existing files can be downloaded, new
uploads are saved there, and deletion actions affect its contents. With no
folder specified, foreground runs use your user data directory; a new Linux
service uses `/var/lib/xferry/files`. These defaults do not depend on the current
directory. Notes, passwords and certificate state are kept separately.

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
stopped server stays stopped. Use `--config FILE` to select another profile.
[All settings](docs/settings.md) includes defaults, units and examples;
`xferry --help` shows common commands and `xferry run --help-all` shows all launch
options.

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
