# Operations

## Portable lifecycle

`xferry run` reads the saved foreground profile. Explicit launch options override
it. Stop with `Ctrl+C`. Use pipx to maintain the CLI itself:

```console
pipx upgrade xferry
pipx uninstall xferry
```

The stable files and private-state directories survive removing the pipx package.
A running foreground process needs a restart after changing its configuration.
Use `xferry config --config FILE` to edit another foreground profile.

## Managed Linux lifecycle

The [supported hosts](managed-hosts.md) use the same commands as generated Docker
deployments. When necessary, the CLI hands off to sudo before configuration:

```console
xferry status
xferry logs --lines 100
xferry stop
xferry start
xferry restart
xferry doctor --deep
```

`xferry config` opens the settings wizard. Scripted changes validate the entire
result and apply automatically if the server is running:

```console
xferry config set max_size_mb=200 --dry-run
xferry config set max_size_mb=200
xferry config check
```

An unsuccessful health check restores the previous configuration. A stopped
server stays stopped. Changing the files folder does not move existing files;
encrypted payloads and their private sidecars must remain consistent.

When crossing from the old CLI/settings to this workflow, use the
[one-time native migration](migration.md#native-linux-service-from-the-old-release) first.
Choose an exact published version for ordinary updates; replace `VERSION` below:

```console
xferry update --to VERSION --dry-run
xferry update --to VERSION
xferry rollback
```

Managed updates verify signed release metadata and exact-version health. The
previous verified release remains available for rollback. See the
[release runbook](release-runbook.md) for release acceptance and recovery details.

`xferry uninstall` removes the installation and retains its configuration,
password, files, notes and certificates. Running setup again can reuse retained
data. The separate `--purge-data` option is destructive; check the displayed plan
and selected folder before confirming. An external files folder is not silently
removed with the runtime. Saved-data purge remains available after uninstall.

## Container lifecycle

These lifecycle commands require `0.3.2` or newer. Existing `0.2.x`
installations use the previous interface; see [migration](migration.md).

For a deployment created by `xferry setup --docker`, use the same lifecycle and
configuration commands. Add `--config /path/to/deployment/xferry.ini` to select it.
Keep the deployment directory, protected auth file and persistent volumes.
Configuration edits preserve the pinned image; only an explicit update changes
it. Rollback uses the retained image/configuration.

If you maintain containers manually, manage that deployment with Docker instead.
Pin an immutable image version or digest such as
`ghcr.io/kgmnotes/xferry@sha256:${XFERRY_DIGEST}`. Published v0.2.0 uses the
[archived image instructions](archive/0.2.0-installation.md).

The manual public sample pins the compatible `v0.3.2` image; you can replace its
tag with the recorded digest. Images from 0.2.x require their archived
configuration. The health hostname must match an admitted TLS hostname:

```console
XFERRY_HEALTH_HOST=files.example.com docker compose -f deploy/docker/docker-compose.public-direct.yml up -d
XFERRY_HEALTH_HOST=files.example.com docker compose -f deploy/docker/docker-compose.public-direct.yml down
```

`down` keeps named volumes. Adding `--volumes` deletes them and is destructive.
The Compose files under `examples/docker/` build a source checkout for development.

## Data layout

`files_dir` is the exact folder exposed through `/uploads/`. Existing files and
new uploads share that folder. Hidden `.xferry-encrypted/` payloads are managed
through the encrypted-transfer API, not ordinary file listing or clear-all.

Private state holds `notes/`, `.xferry/encrypted-uploads/` sidecars and TLS state.
It is selected automatically outside the public folder. Native installation
keeps configuration in `/etc/xferry`, releases in `/opt/xferry`, and durable state
in `/var/lib/xferry`; Docker keeps separate state/ACME volumes. See
[Settings](settings.md#files-and-private-state) for platform defaults.

Back up configuration, protected auth files, files, private state and ACME
material together. Restore these consistently before starting the server.
Notepad ciphertext does not include the browser's recovery key.

Encrypted uploads are disabled by default. Enable them with `xferry config set
encrypted_uploads=true` or the wizard. See [Encrypted transfer operations](encrypted-transfers.md)
for retention, browser recovery, consistent backups and the optional resource smoke.

## Capacity

`max_size_mb` bounds one request. `body_memory_budget_mb` is an admission budget
for concurrent request bodies, not an RSS ceiling. Its automatic value is workers
multiplied by the request limit. Large encrypted transfers stream chunks; their
plaintext limit is configured separately.

The upload byte quota, file-count quota and free-space reserve apply to the
selected files folder. Temporary SMUGGLE artifacts and notes have separate
limits. Public mode requires finite upload capacity or an explicit declaration
that external quotas enforce it. Read [the setting descriptions](settings.md)
for units, zero/automatic behavior and dependencies.

## Health and diagnostics

`xferry status` reports the selected installation. `xferry doctor --deep` adds
configuration and authenticated health checks. An authenticated `PING /` must
return HTTP 200 and `"health":"ready"`. Check a small upload/download/delete
cycle after an update or restore. `xferry config show --all` reports resolved
settings and their sources; it does not print passwords.

## Public services

Use `access=public`, file-backed Basic Auth and browser-trusted HTTPS. Setup
prepares these together. See [Public deployment](public-direct.md) for ports,
Host admission, proxy behavior and external controls.

Built-in ACME certificates renew in the running process without interrupting
active transfers. Keep inbound HTTP-01 port 80 reachable. Failed renewals retain
the active certificate and retry with backoff. For externally managed PEM
certificates, restart after replacing their files.
