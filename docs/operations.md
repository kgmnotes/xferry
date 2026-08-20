# Operations

Choose the data root and its lifetime before the first upload. The current
public distribution is source-only, so release update and rollback commands do
not provide a published artifact to install.

## Source process

By default, `xferry run` uses the current directory as its root. Set an
explicit operator-owned directory for repeatable use:

```bash
install -d -m 0700 "$PWD/xferry-data"
xferry run --preset local --dir "$PWD/xferry-data"
```

Press `Ctrl+C` to stop the process. Restarting with the same `--dir` preserves
uploads and encrypted note state.

## Data layout

Inside the configured root:

- `uploads/` contains user files and generated SMUGGLE artifacts.
- `notes/` contains encrypted note blobs and plaintext note metadata. It does
  not contain a durable client recovery key.

ACME state is stored under `~/.xferry/acme/` for the runtime user. Protect its
account keys, domain private keys, and certificate chain files as secrets.
Temporary self-signed certificate files are removed when the process exits.

Backing up `notes/` does not make a note recoverable after the client-derived
key is lost.

## Docker from the checkout

The example Compose file builds `xferry:local` from source. It is a contributor
workflow, not a published image installation:

```bash
docker compose -f examples/docker/docker-compose.yml up --build xferry
docker compose -f examples/docker/docker-compose.yml down
```

The service publishes only `127.0.0.1:8080` and uses named volumes. `down`
removes containers and the project network but keeps data. This command also
deletes the named volumes and is destructive:

```bash
docker compose -f examples/docker/docker-compose.yml down --volumes
```

## Capacity

`--body-memory-budget` limits admitted in-flight request bodies. It is not an
RSS ceiling: decoded payloads, parser objects, TLS buffers, worker stacks, and
WebSocket state use additional memory.

Persistent capacity has two layers:

1. A filesystem, volume, or platform quota controlled by the operator.
2. Application limits such as `--upload-storage-limit`,
   `--upload-file-limit`, `--upload-reserve-free`, note limits, and SMUGGLE
   retention limits.

Each active WebSocket occupies one worker. Tune workers, WebSocket admission,
per-request size, body budget, storage quotas, and process memory together.

## Health and diagnostics

Use `PING /` for health, method discovery, and a metrics snapshot:

```bash
curl --fail-with-body --request PING http://127.0.0.1:8080/
```

`PING` and `GET /metrics` perform exact storage scans. For a large data root,
probe less frequently or use a TCP liveness check when only process liveness is
required.

Run with `--json-log` for structured logs. Keep credentials, Advanced Session
tokens, payload keys, and note keys out of command arguments and log systems.

## Public services

Use a service manager with a dedicated runtime user, an explicit data root,
file-backed credentials, finite resource limits, and restart policy. Validate
the generated public configuration before starting it:

```bash
xferry run --write-sample-config ./xferry.ini
xferry run --config ./xferry.ini --check-config
xferry run --config ./xferry.ini --print-config
```

See [Public deployment](public-direct.md) for the required configuration and
external controls.
