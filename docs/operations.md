# Operations

Choose one lifecycle owner and one durable data location before the first
upload. Portable, managed Linux, and container installations share runtime
behavior but intentionally use different upgrade and removal commands.

## Portable lifecycle

Pipx owns portable installation state on Windows, macOS, and Linux:

```console
pipx upgrade xferry
pipx uninstall xferry
```

Run with an explicit operator-owned directory when data must survive process
restarts:

```console
install -d -m 0700 "$PWD/xferry-data"
xferry run --preset local --dir "$PWD/xferry-data"
```

Press `Ctrl+C` to stop. Restarting with the same `--dir` preserves uploads and
encrypted note state. Do not use managed `update`, `rollback`, or `uninstall`
commands for a pipx installation.

## Managed Linux lifecycle

The managed service is limited to the [generated host matrix](managed-hosts.md).
Use the fixed unit name and root-gated commands:

```console
sudo xferry status
sudo xferry doctor --deep
sudo xferry logs --lines 200
sudo xferry restart
```

Updates require an exact immutable version. A dry-run verifies signed metadata
and reports the plan without changing managed files or service state:

```console
sudo xferry update --to 0.1.0 --dry-run --json
sudo xferry update --to 0.1.0 --json
```

Successful activation must report exact-version health and retain the prior
verified release. Recovery never downloads a mutable channel:

```console
sudo xferry rollback
sudo xferry rollback --to 0.1.0
```

Normal uninstall removes the runtime, unit, and CLI link while preserving
configuration, credentials, uploads, notes, and ACME state. Purge is explicit
and destructive:

```console
sudo xferry uninstall --dry-run
sudo xferry uninstall
sudo xferry uninstall --purge-data --yes
```

## Container lifecycle

The released image supports `linux/amd64` and `linux/arm64`. Pull and run an
immutable version tag, or prefer the digest recorded in the release inventory:

```console
docker pull ghcr.io/kgmnotes/xferry:v0.1.0
docker pull ghcr.io/kgmnotes/xferry@sha256:${XFERRY_DIGEST}
docker run --rm --publish 127.0.0.1:8080:8080 \
  --volume xferry-data:/data \
  ghcr.io/kgmnotes/xferry:v0.1.0
```

For the public-direct Compose contract, set the health hostname to the
configured TLS hostname and admitted request authority on every invocation:

```console
XFERRY_HEALTH_HOST=files.example.com \
  docker compose -f deploy/docker/docker-compose.public-direct.yml up -d
XFERRY_HEALTH_HOST=files.example.com \
  docker compose -f deploy/docker/docker-compose.public-direct.yml down
```

`down` removes containers and the project network but keeps named volumes.
Adding `--volumes` also deletes uploads, notes, and ACME state and is
destructive.

```console
XFERRY_HEALTH_HOST=files.example.com \
  docker compose -f deploy/docker/docker-compose.public-direct.yml down --volumes
```

The contributor Compose file under `examples/docker/` deliberately builds the
current checkout; it is not the public container journey.

## Data layout

Inside a portable or container data root:

- `uploads/` contains user files and generated SMUGGLE artifacts.
- `notes/` contains encrypted note blobs and plaintext note metadata. It does
  not contain a durable client recovery key.

Managed Linux stores configuration under `/etc/xferry`, releases under
`/opt/xferry`, and durable data under `/var/lib/xferry`. ACME state is secret
operator state. Backing up `notes/` does not recover a note after the
client-derived key is lost.

## Capacity

`--body-memory-budget` limits admitted in-flight request bodies. It is not an
RSS ceiling: decoded payloads, parser objects, TLS buffers, worker stacks, and
WebSocket state use additional memory.

Persistent capacity combines an operator-controlled filesystem or volume quota
with application limits such as `--upload-storage-limit`, `--upload-file-limit`,
`--upload-reserve-free`, note limits, and SMUGGLE retention limits. Tune those
limits with workers, WebSocket admission, process memory, and free-space alerts.

## Health and diagnostics

Use `PING /` for health, version, method discovery, and a metrics snapshot:

```console
curl --fail-with-body --request PING http://127.0.0.1:8080/
```

`PING` and `GET /metrics` perform exact storage scans. Probe less often for a
large data root. Keep credentials, Advanced Session tokens, payload keys, and
note keys out of command arguments and logs.

## Public services

Use a dedicated runtime identity, explicit data root, file-backed credentials,
finite limits, restart policy, and immutable release identity. Validate public
configuration before starting it:

```console
xferry run --write-sample-config ./xferry.ini
xferry run --config ./xferry.ini --check-config
xferry run --config ./xferry.ini --print-config
```

See [Public deployment](public-direct.md) for the required network, TLS,
authentication, storage, and monitoring controls.
