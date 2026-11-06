# xferry

[![CI](https://github.com/kgmnotes/xferry/actions/workflows/ci.yml/badge.svg)](https://github.com/kgmnotes/xferry/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/Python-3.10--3.14-blue.svg)](https://www.python.org/)
![Version](https://img.shields.io/badge/version-0.5.0-orange.svg)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

xferry is an HTTP toolkit for testing Secure Web Gateways on systems you are
authorized to test. Run it on a VPS, then use its web UI from a computer behind
the gateway to upload and download files, try custom HTTP methods, and exchange
encrypted notes.

## Run on a VPS

Connect to your VPS over SSH. You need a [supported Linux host](docs/managed-hosts.md)
with systemd, Python 3.10–3.14, sudo or root access, and a public IPv4 address.
Allow inbound TCP **80 and 443**; both ports must be available to xferry.
Port 80 is also needed later for certificate renewal.

Install pipx if needed (Ubuntu / Debian):

```console
sudo apt install pipx
pipx ensurepath
```

Reconnect your SSH session so the updated PATH takes effect, then install xferry:

```console
pipx install xferry
```

Choose a dedicated folder for uploads and downloads, replacing `/srv/share` below
with your path. Existing files in that folder will be available for downloading;
new uploads will be saved there. Deleting files in the web UI affects this folder.

```console
xferry setup --backend native --access public --files-dir /srv/share
```

Review the installation plan and confirm it; setup requests sudo when needed.
It installs a persistent service, obtains a browser-trusted TLS certificate for
an automatic sslip.io address, enables Basic Auth, and starts HTTPS on port **443**.
No domain of your own is required. Setup prints the URL, username, generated
password, and deployment ID. Save those details. The service keeps running after
you disconnect from SSH.

To use your own domain, see [Public deployment](docs/public-direct.md).

## Send your first file

1. On your computer, open the HTTPS URL printed by setup and sign in with the
   printed username and password.
2. In **Upload**, choose a small test file and press **Send**.
3. Open **Download**, download the file and check its contents. It is stored in
   the folder you selected on the VPS.

To exercise your gateway, open xferry from the computer and network path that
passes through it. See [Common scenarios](docs/scenarios.md) for request tests,
reports, encrypted notes and transport experiments.

## Other ways to run

- **Locally:** after installing with pipx, run `xferry run --open`. This opens a
  foreground server at <http://127.0.0.1:8080>; stop it with `Ctrl+C`.
- **Docker:** follow [Container through setup](docs/quick-start.md#container-through-setup).
- **From source:** see [Contributing](CONTRIBUTING.md).

## Documentation

- [Quick start](docs/quick-start.md): installation alternatives and curl examples
- [Operations](docs/operations.md): status, logs, stop/start, updates and removal
- [Settings](docs/settings.md) and [CLI reference](docs/cli-reference.md)
- [API reference](API.md): HTTP methods, Advanced Sessions and payload protection
- [Upgrade notes](docs/migration.md): read before updating an existing deployment
- [Security policy](SECURITY.md)

Documentation: <https://xferry.kgmnotes.ru/> · License: MIT
