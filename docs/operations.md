# Operations

Choose the data root and its lifetime before the first upload. Supported
distribution is source-only from a reviewed checkout. Remote updates are not
exposed by the public CLI; `xferry rollback` can only select a verified release
already retained in a managed installation and never fetches one.

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
- `uploads/.xferry-encrypted/` contains hidden encrypted-transfer `.part` and
  `.xfr` ciphertext files. Ordinary file APIs cannot list, download, delete,
  or clear this directory.
- `notes/` contains encrypted note blobs and plaintext note metadata. It does
  not contain a durable client recovery key.
- `.xferry/encrypted-uploads/` contains mode-0600 encrypted-transfer state
  sidecars beneath a mode-0700 service directory.

ACME state is stored under `~/.xferry/acme/` for the runtime user. Protect its
account keys, domain private keys, and certificate chain files as secrets.
Temporary self-signed certificate files are removed when the process exits.

Backing up `notes/` does not make a note recoverable after the client-derived
key is lost.

## Encrypted transfer operations

Large client-encrypted transfers are disabled by default. Enable them only for
an operator-controlled data root:

```ini
[server]
encrypted_uploads = true

[limits]
encrypted_upload_max_size_mb = 0
upload_storage_limit_mb = 24576
upload_reserve_free_mb = 4096
upload_file_limit = 4096
encrypted_upload_incomplete_ttl_seconds = 604800
```

This is the private-service resource profile in `examples/large-files.ini`:
24 GiB shared upload quota, 4 GiB free-space reserve, 4096 ordinary plus encrypted
files (including partials), and seven days of incomplete retention. Merge its
settings into the existing deployment config without replacing TLS, auth,
root directory or existing data. Library/local defaults do not silently enable
these aggregate limits.

The equivalent feature flag is `--encrypted-uploads`. A zero
`encrypted_upload_max_size_mb` (the default) means automatic capacity admission;
an explicit positive value sets a lower operator ceiling. The v1 recovery
implementation supports at most 4096 chunks / 32 GiB plaintext per file so even
the worst-case journal fits the 1 MiB sidecar limit. This is a recovery safety
boundary, not a claim that a 32 GiB real-browser round trip has been verified.
The advertised maximum is recalculated from remaining quota and disk headroom,
subtracting tag overhead. The maximum is a plaintext limit; stored ciphertext
adds one 16-byte AES-GCM tag per 8 MiB
chunk. Partial reservations count their complete declared ciphertext length
against the ordinary upload byte and file quotas, including the free-space
reserve. Plan filesystem capacity for the largest concurrent partial files,
completed ciphertext, backups, and temporary operational headroom.
Sparse partials on filesystems without preallocation also reserve their not-yet-
allocated bytes when checking free space. The browser checks the entire selected
queue before deriving keys or uploading data; capacity snapshots are advisory,
and server reservations recheck atomically. A competing upload can still cause
a later file to be refused, without deleting already completed files.

`GET /_xferry/encrypted-uploads` includes a non-secret `storage` snapshot with
`available_bytes`, `remaining_files` and `max_plaintext_size`. Limits concern
the shared storage root, not individual accounts sharing Basic Auth. Reducing
the new-upload ceiling does not hide or invalidate existing encrypted files.

Encrypted uploads require at least two workers and a body admission budget for
two maximum ciphertext chunks (`16 MiB + 32 bytes`). When the budget is
omitted, XFerry derives at least that floor. When it is configured through the
whole-MiB CLI or settings option, use at least `17` MiB. The encrypted route
caps are independent of the smaller ordinary `--max-size` limit.

State advances `partial -> committing -> complete`. A chunk is acknowledged
only after its ciphertext and atomic sidecar state are durable. Startup
reconciles an interrupted commit without exposing the hidden files through
ordinary uploads. Incomplete records older than
`encrypted_upload_incomplete_ttl_seconds` are removed during startup and
lazily on encrypted-store access, listing, or new-upload quota admission;
completed files remain until their encrypted-file DELETE route is called.
Back up the ciphertext and `.xferry/encrypted-uploads/` sidecars together.

The project default for incomplete retention remains 86400 seconds (24 hours).
For seven days without durable upload activity, configure
`encrypted_upload_incomplete_ttl_seconds = 604800`. The partial-list API reports
the actual policy as `incomplete_ttl_seconds` beside `encrypted_uploads`, so the
client can display the configured retention. Server cleanup does not require
the user's browser to be open, but is lazy: with no server access and no restart,
an expired partial can remain until the next cleanup trigger. Completed files
are removed only by explicit deletion.

Upload recovery also requires the original browser's IndexedDB nonce journal.
Before each content chunk's first encryption the browser durably records its
plaintext HMAC, including chunks not yet acknowledged by the server. Reusing a
content key and nonce for changed bytes is unsafe; losing that journal, or
resuming an incomplete upload created by an older client without a journal,
requires a new session with new ID and keys. Existing partial uploads are not
automatically deleted when the client refuses unsafe recovery.

Browser download recovery stores only authenticated encrypted chunks in OPFS,
the Origin Private File System. It requires desktop Chrome/Edge with OPFS and
the File System Access API, and roughly one extra file's size of browser storage.
On a reload the user re-enters the password and selects the destination again;
the browser verifies cached chunks, fetches only missing chunks, and reconstructs
the plaintext output locally. Passwords, keys, plaintext names and plaintext
file bytes are not persisted in this recovery cache. The per-chunk ciphertext
API is `GET /_xferry/encrypted-files/{id}/chunks/{index}`; completed EUF v1 files
and the existing concatenated ciphertext route remain compatible.

After successful output closure the client deletes that download's cache.
Manual cache clearing is available; otherwise inactive entries older than
seven days are cleaned at the next application open. No background deletion
is guaranteed while the site or browser is closed. Browser storage eviction
can remove cached ciphertext earlier and then those chunks must be fetched
again. These client cache rules do not delete files on the server.

The server cannot recover a forgotten browser password and does not store
plaintext, `K_content`, or `K_resume`. Browser-side download is the default
trust boundary. The optional server-decrypt action sends `K_content` after a
separate confirmation and is available only over TLS or direct loopback; it
streams one response and does not create a plaintext artifact.

Run the checked 64 MiB round-trip and inspect its JSON memory record with:

```bash
python tools/encrypted_transfer_resource_smoke.py --size-mib 64 --json
```

The output includes `peak_rss_bytes`, `peak_rss_delta_bytes`, byte counts, and
source/round-trip SHA-256 values. The 2 GiB smoke is deliberately opt-in
because it reserves and writes roughly 2 GiB of local storage:

```bash
XFERRY_RUN_2GIB_SMOKE=1 \
  pytest -q -s tests/test_encrypted_resource_smoke.py::test_2_gib_encrypted_streaming_resource_smoke_records_peak_memory
```

Run it on the same filesystem and under the same memory limits intended for
production. A passing smoke demonstrates bounded application buffers for this
path; it is not a substitute for host disk quotas or process-level limits.

## Docker from the checkout

The example Compose file builds `xferry:local` from source. It is a local
checkout workflow, not a registry-image installation:

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
