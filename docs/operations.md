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

Existing installations follow the [upgrade notes](migration.md); unsupported
configuration and deployment schemas are rejected without changing their state.
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
data. Use `--purge --dry-run` to review owned resources before confirming
`--purge --yes`. The shared folder and its files remain, including the native
default `/var/lib/xferry/files`; changed or unowned resources also remain.
The manifest and registry entry are removed. The service account remains while
retained folders or files need its identity. Saved-data purge remains available
after uninstall. Without `--yes`, an interactive terminal asks for confirmation;
declining cancels the operation. Noninteractive purge requires `--yes`, while
`--dry-run` does not require confirmation.
The separate pipx/virtual-environment controller remains; remove a pipx-installed
CLI with `pipx uninstall xferry` after uninstalling the deployment.

## Container lifecycle

For a deployment created by `xferry setup --backend docker`, use the same lifecycle and
configuration commands. Add `--instance ID` to select it.
Keep the deployment directory, protected auth file and persistent volumes.
Configuration edits preserve the pinned image; only an explicit update changes
it. Rollback uses the retained image/configuration.

For a reviewed image built outside the public release registry, select its
immutable digest explicitly with `xferry setup --backend docker --image
REPOSITORY@sha256:DIGEST`. This is an operator option for matching source or
candidate builds; it cannot be combined with `--to`. Setup verifies the image's
actual repository digest before creating the deployment.

Use `xferry setup --backend docker --output /absolute/path/to/bundle` when creating
another deployment for the same user. The output directory is an explicit
creation destination; later operations select the recorded `--instance ID`.

### Advanced Compose access

`xferry setup --backend docker` prepares the protected authentication file,
operator profile, runtime mapping and Compose bundle together. Its image is
pinned as `ghcr.io/kgmnotes/xferry@sha256:DIGEST`. The generated bundle is the
single deployment definition and contains the same project name used by the
management CLI. Use that file directly so manual commands manage the existing
containers and volumes.

For direct Compose access, replace
`/srv/xferry/deployment` below with the bundle location printed by setup:

```console
docker compose -f /srv/xferry/deployment/compose.yaml up -d
docker compose -f /srv/xferry/deployment/compose.yaml down
```

The file belongs to the existing setup bundle. Health checks use the generated
TLS hostname and read
the mounted authentication secret. Keep using `xferry config --instance ID` to
change settings so the operator profile, compiled runtime and ownership receipt
stay consistent. Independent edits are detected and preserved for review.

`down` keeps named volumes. Adding `--volumes` deletes them and is destructive.
The Compose files under `examples/docker/` build a source checkout for development.

## Data layout

Use a dedicated shared folder for each persistent instance. Two deployments
cannot share the same folder, overlapping trees or another path to the same
directory. A retained installation keeps its folder claim for reinstall. To
reuse an external folder with another deployment, purge the old installation's
owned resources first; its external shared files remain. Manual container
sharing outside this management model is an operator-owned workflow.

`files_dir` is the exact folder exposed through `/uploads/`. Existing files and
new uploads share that folder. Hidden `.xferry-encrypted/` payloads are managed
through the encrypted-transfer API, not ordinary file listing or clear-all.

Private state holds `notes/`, `.xferry/encrypted-uploads/` sidecars and TLS state.
It is selected automatically outside the public folder. Native installation
keeps configuration in `/etc/xferry`, releases in `/opt/xferry`, and durable state
in `/var/lib/xferry`. Docker keeps notes, encrypted sidecars and ACME state in
one named data volume mounted at `/data`, plus a separate derived secrets volume.
The operator INI does not invent a host `state_dir`. `xferry status --instance ID
--json` reports the actual backup volume in `details.state_storage.name`; config
inspection displays `Docker volume NAME` and runtime root `/data`. See
[Settings](settings.md#files-and-private-state) for platform defaults.

Back up configuration, protected auth files, files, private state and ACME
material together. Restore these consistently before starting the server.
Notepad ciphertext does not include the browser's recovery key.
Follow the [cold backup and restore procedure](backup-restore.md), including
offline validation before starting encrypted storage on a replacement disk.

Encrypted uploads are disabled by default. Enable them with `xferry config set
encrypted_uploads=true` or the wizard. See [Encrypted transfer operations](encrypted-transfers.md)
for retention, browser recovery, consistent backups and the optional resource smoke.

## Capacity

`max_size_mb` bounds one request. `body_memory_budget_mb` is a separate admission
budget for buffered request bodies. Its automatic value is one eighth of the
available RAM/cgroup memory limit, bounded to **32–128 MiB**. It is not an RSS
ceiling. Large encrypted transfers stream chunks; their plaintext limit is
configured separately.

Runtime capacities are independent. The defaults admit **32 TCP connections**,
**2 TLS handshakes**, **4 short computations** (`workers`), **4 transfers** and
**8 WebSocket connections**. Authentication admits **16 total checks**, including **2 active verifications**;
the others wait for an active slot. Increasing `workers` changes short-computation
capacity; it does not increase all connection or authentication limits. Idle
keep-alive connections expire after **5 seconds**.

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

`--json` suppresses credentials in both stdout and stderr. Automation reads the
protected authentication file; a human setup or credential reset without
`--json` displays the generated password once after successful health verification.

## Public services

Use `access=public`, file-backed Basic Auth and browser-trusted HTTPS. Setup
prepares these together. See [Public deployment](public-direct.md) for ports,
Host admission, proxy behavior and external controls.

Built-in ACME certificates renew in the running process without interrupting
active transfers. Keep inbound HTTP-01 port 80 reachable. Failed renewals retain
the active certificate and retry with backoff. For externally managed PEM
certificates, restart after replacing their files.
