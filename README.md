# xferry

![Python 3.10-3.14](https://img.shields.io/badge/Python-3.10--3.14-blue.svg)
![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)
![Version](https://img.shields.io/badge/version-0.1.0-orange.svg)
[![CI](https://github.com/kgmnotes/xferry/actions/workflows/ci.yml/badge.svg)](https://github.com/kgmnotes/xferry/actions/workflows/ci.yml)
[![Security](https://github.com/kgmnotes/xferry/actions/workflows/security.yml/badge.svg)](https://github.com/kgmnotes/xferry/actions/workflows/security.yml)

`xferry` is a controlled HTTP toolkit for testing Secure Web Gateways. It
serves and uploads files, sends standard and custom HTTP methods, provides a
Secure Notepad, and builds test artifacts for transport experiments.

Documentation: <https://xferry.kgmnotes.ru/>

> [!WARNING]
> Use xferry only on systems and data you own or are authorized to test. Do not
> expose it to arbitrary internet clients. External deployments need TLS,
> authentication, finite quotas, network controls, and monitoring. See
> [Security](SECURITY.md).

## Install from source

Version `0.1.0` is the current public source version. No GitHub Release, PyPI
package, or GHCR image has been published, so install from a checkout:

```bash
git clone https://github.com/kgmnotes/xferry.git
cd xferry
python3 -m venv .venv
. .venv/bin/activate
python -m pip install .
xferry run --preset local --open
```

The local preset listens on `127.0.0.1:8080`. The web UI provides Send,
Requests, Files, Advanced, and Secure Notepad workflows.

## Use curl

Upload a test file with the basic API:

```bash
printf 'authorized test\n' > sample.txt
curl --fail-with-body \
  --request POST \
  --header 'X-File-Name: sample.txt' \
  --data-binary @sample.txt \
  http://127.0.0.1:8080/uploads
```

The API also exposes `GET`, `HEAD`, `PUT`, `PATCH`, `DELETE`, `OPTIONS`,
`FETCH`, `INFO`, `PING`, `NONE`, `NOTE`, and `SMUGGLE`. An authorized
Advanced Session can route `POST`, `PUT`, `PATCH`, `NONE`, or a syntactically
valid unregistered method such as `SYNCDATA` to an Advanced upload. Advanced
payload protection is explicit: `none`, XOR obfuscation, or AES-256-GCM. There
is no cipher fallback.

See the [API reference](API.md) for complete request shapes and a curl journey.

## Documentation

- [Quick start](docs/quick-start.md)
- [Scenarios](docs/scenarios.md)
- [Operations](docs/operations.md)
- [Disposable SSH tunnel](docs/disposable-ssh-tunnel.md)
- [Public deployment](docs/public-direct.md)
- [Security policy](SECURITY.md) and [threat model](docs/threat-model.md)
- [Architecture](docs/architecture.md) and [ADRs](docs/ADR/README.md)
- [Contributing](CONTRIBUTING.md)

License: MIT.
