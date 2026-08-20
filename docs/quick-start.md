# Quick start

The current version is installed from source. No GitHub Release, PyPI package,
or GHCR image exists for `0.1.0`.

## Install

Python 3.10 through 3.14 is supported.

```bash
git clone https://github.com/kgmnotes/xferry.git
cd xferry
python3 -m venv .venv
. .venv/bin/activate
python -m pip install .
```

Start the loopback server and open its web UI:

```bash
xferry run --preset local --open
```

The server listens on <http://127.0.0.1:8080>. If a browser does not open,
visit that address manually.

## Send a first file

In the UI:

1. Open **Send**.
2. Select a small test file.
3. Send it and confirm the returned path and size.
4. Open **Files**, download the file, and delete it.

The same flow works with curl:

```bash
printf 'authorized test\n' > sample.txt
curl --fail-with-body \
  --request POST \
  --header 'X-File-Name: sample.txt' \
  --data-binary @sample.txt \
  http://127.0.0.1:8080/uploads

curl --fail-with-body \
  --request INFO \
  http://127.0.0.1:8080/uploads/

curl --fail-with-body \
  http://127.0.0.1:8080/uploads/sample.txt
```

## Try a custom method

The **Requests** panel lists the methods returned by `PING`. The built-in
surface includes standard methods plus `FETCH`, `INFO`, `PING`, `NONE`, `NOTE`,
and `SMUGGLE`.

Arbitrary unregistered methods are accepted only as Advanced uploads under an
authorized Advanced Session. The [API reference](api.md#advanced-sessions-upload)
contains the create, use, inspect, and revoke curl journey.

## Stop and protect data

Press `Ctrl+C` in the server terminal. Files remain under `./uploads/` and note
state remains under `./notes/` because the default root is the current
directory. Use `--dir PATH` to select an operator-owned data root.

Do not bind to a public address as a shortcut. For trusted-local protection,
use `xferry run --preset local-secure`. For external service configuration,
follow [Public deployment](public-direct.md). See [Operations](operations.md)
for data paths, persistence, capacity, and container cleanup.
