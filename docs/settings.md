# Settings and files folder

Run `xferry config` for the wizard. It groups settings by topic and offers search
for less common options. Use `--config FILE` to select a particular foreground,
native or Docker profile.

```console
xferry config show --all
xferry config explain files_dir
xferry config explain body_memory_budget_mb
xferry config set max_size_mb=200 --dry-run
xferry config set max_size_mb=200
xferry config check
```

`explain` works without an existing configuration. `set` validates the whole
configuration and automatically applies changes to a running installed server;
failed health checks restore the previous configuration. A stopped instance
stays stopped. Restart a foreground process yourself to load saved changes.

## Files and private state

`files_dir` is the exact directory for existing downloadable files and new
uploads. `/srv/share` saves `example.txt` as `/srv/share/example.txt`. Upload,
download and deletion use this same folder, including manually placed files.
The HTTP prefix stays `/uploads/`, regardless of the folder's name.

```console
xferry run --files-dir /srv/share
xferry run --files-dir .
```

The second command explicitly selects the current directory. Defaults are
stable and independent of the launch directory:

| Installation | Default files folder |
| --- | --- |
| Linux foreground | `$XDG_DATA_HOME/xferry/files`, otherwise `~/.local/share/xferry/files` |
| macOS foreground | `~/Library/Application Support/xferry/files` |
| Windows foreground | `%LOCALAPPDATA%\xferry\files` |
| New native Linux service | `/var/lib/xferry/files` |
| Docker setup | The host folder shown and saved by its wizard, mounted directly into the container |

The wizard saves absolute paths and checks access without changing ownership
of an existing shared folder. Selecting another folder does not copy old files.
Private notes, encrypted-transfer sidecars and TLS material live separately in
automatically selected state. `config show --all` includes effective automatic
paths and limits. Preserve this state with its file payloads when backing up or
migrating encrypted transfers. Hidden encrypted payloads inside the files folder
are handled by their own API and excluded from ordinary file actions.

Old installations keep their existing storage through a
[one-time migration](migration.md); no file move is implied by changing the CLI.

## Choose a mode

- `access=private`: loopback access by default. HTTPS and authentication can be added.
- `access=public`: strict external-service requirements, including HTTPS, file-backed authentication and bounded resources.
- `access=lab`: explicit test mode for intentional HTTP experiments; review the listener before using it.

`https_mode` selects `off`, `auto`, `domain`, `files`, or `self-signed`.
`log_level` selects `warning`, `info`, or `debug`; `log_format` selects `text` or
`json`. Passwords belong in a protected auth file. The credentials action creates
or resets them; `--open` is a launch-only option.

## Value sources

Precedence is built-in defaults, access-mode defaults, explicit INI, environment,
then explicit launch options. A plain `xferry run` loads the saved foreground
profile. Use `xferry run --config FILE` for another one. `config show` identifies
sources and redacts secrets. Service configuration inspection does not inherit
your interactive shell's environment; external service/container overrides must
be managed by their owner.

All runtime changes take effect in a new process. The wizard and `config set`
handle installed-server restarts and health checks automatically. `--dry-run`
previews changes. Setup owns instance paths, secrets and container mounts;
changing an application setting does not update the CLI package or image.

## Complete reference

The following entries are generated from the CLI's setting metadata. A blank or
`null` default means automatic/unset as described in that entry. Installation
profiles write their own explicit paths, HTTPS and resource defaults. MiB is
1,048,576 bytes; KiB is 1,024 bytes.

<!-- BEGIN GENERATED: xferry-contracts/settings-reference -->
### server

#### `access`

Who can reach the server. Public mode always enforces verified HTTPS, file-backed access and finite limits.

Default: `"private"`. private, public, lab

Public mode defaults to automatic HTTPS; private binds loopback.

Applies to: all. Change: restart.

```ini
[server]
access = public
```

Environment: `XFERRY_ACCESS`; launch: `--access`.

#### `log_level`

How much diagnostic information the server records.

Default: `"info"`. warning, info, debug

Applies to: all. Change: restart.

```ini
[server]
log_level = info
```

Environment: `XFERRY_LOG_LEVEL`; launch: `--log-level`.

#### `log_format`

Whether logs are readable text or structured JSON.

Default: `"text"`. text, json

Applies to: all. Change: restart.

```ini
[server]
log_format = text
```

Environment: `XFERRY_LOG_FORMAT`; launch: `--log-format`.

#### `host`

Address the server listens on. Private mode accepts only loopback; public defaults to all interfaces.

Default: `"127.0.0.1"`. An IP address or hostname; private requires localhost or a loopback IP

Default: 127.0.0.1 for private/lab, 0.0.0.0 for public.

Applies to: all. Change: restart.

```ini
[server]
host = 127.0.0.1
```

Environment: `XFERRY_HOST`; launch: `-H`, `--host`.

#### `port`

Listen port

Default: `8080`. Minimum 1; maximum 65535

Default: 8080 for private/lab, 8443 for public. Open this port in the host firewall when sharing.

Applies to: all. Change: restart.

```ini
[server]
port = 8080
```

Environment: `XFERRY_PORT`; launch: `-p`, `--port`.

#### `files_dir`

Exact folder for downloadable files and new uploads. Existing files in this folder are available too.

Default: platform user data folder (see the table above). A readable and writable directory

If omitted, uses the stable per-user xferry/files folder. Relative paths resolve from the launch directory. Private state and configuration must be outside it.

Applies to: all; installation-owned mappings use the files-folder action. Change: files-folder workflow; updates the service or container mapping.

```ini
[server]
files_dir = /srv/share
```

Environment: `XFERRY_FILES_DIR`; launch: `--files-dir`.

#### `encrypted_uploads`

Enable resumable browser-encrypted large-file transfers

Default: `false`. true or false

Encrypted transfers require at least two workers and a body budget for two encrypted chunks.

Applies to: advanced. Change: restart.

```ini
[server]
encrypted_uploads = true
```

Environment: `XFERRY_ENCRYPTED_UPLOADS`; launch: `--encrypted-uploads`.

#### `workers`

Number of worker threads

Default: `10`. Minimum 1

Encrypted uploads require at least 2. Automatic memory and WebSocket limits depend on this value.

Applies to: advanced. Change: restart.

```ini
[server]
workers = 4
```

Environment: `XFERRY_WORKERS`; launch: `-w`, `--workers`.

### tls

#### `https_mode`

How the server obtains HTTPS certificates. Automatic uses a public IPv4 hostname; domain uses your DNS name.

Default: `"off for private/lab; auto for public"`. off, auto, domain, files, self-signed

domain requires domain; files requires cert_file and key_file; self-signed is private/lab only.

Applies to: all; file certificates in Docker require explicit mounts. Change: HTTPS workflow; validates certificates and verifies the restarted server.

```ini
[tls]
https_mode = auto
```

Environment: `XFERRY_HTTPS_MODE`; launch: `--https`.

#### `cert_file`

Path to certificate file (PEM)

Default: `"not set"`. A readable PEM certificate or certificate-chain file

Requires https_mode = files and key_file. Public wildcard binds also require allowed_hosts.

Applies to: advanced. Change: HTTPS workflow; validates certificates and verifies the restarted server.

```ini
[tls]
cert_file = /etc/xferry/server.pem
```

Environment: `XFERRY_CERT_FILE`; launch: `--cert`.

#### `key_file`

Path to private key file (PEM)

Default: `"not set"`. A readable PEM private-key file matching cert_file

Requires https_mode = files and cert_file. Protect this file from other users.

Applies to: advanced. Change: HTTPS workflow; validates certificates and verifies the restarted server.

```ini
[tls]
key_file = /etc/xferry/server.key
```

Environment: `XFERRY_KEY_FILE`; launch: `--key`.

#### `domain`

DNS hostname used for an automatically issued domain certificate.

Default: `"not set"`. A DNS hostname without URL or port

Requires https_mode = domain, DNS pointing to this host, and public HTTP port 80 reaching the challenge listener.

Applies to: all. Change: HTTPS workflow; validates certificates and verifies the restarted server.

```ini
[tls]
domain = files.example.com
```

Environment: `XFERRY_DOMAIN`; launch: `--domain`.

#### `email`

Email for Let's Encrypt notifications (optional)

Default: `"not set"`. An email address, or empty to omit contact details

Used only with https_mode = auto or domain for certificate-account contact details.

Applies to: advanced. Change: HTTPS workflow; validates certificates and verifies the restarted server.

```ini
[tls]
email = admin@example.com
```

Environment: `XFERRY_EMAIL`; launch: `--email`.

#### `public_ip`

Public IPv4 address used to form an automatic sslip.io certificate hostname.

Default: `"not set"`. A public IPv4 address; empty means automatic detection

Requires https_mode = auto. Use when automatic public-IP detection selects the wrong address.

Applies to: advanced. Change: HTTPS workflow; validates certificates and verifies the restarted server.

```ini
[tls]
public_ip = 203.0.113.10
```

Environment: `XFERRY_PUBLIC_IP`; launch: `--public-ip`.

#### `acme_server`

ACME directory URL or staging for test certificates.

Default: `"not set"`. HTTPS directory URL or staging

Requires https_mode = auto or domain. Empty selects the production service; staging issues certificates browsers will not trust.

Applies to: advanced. Change: HTTPS workflow; validates certificates and verifies the restarted server.

```ini
[tls]
acme_server = staging
```

Environment: `XFERRY_ACME_SERVER`; launch: `--acme-server`.

#### `acme_http_address`

Bind address for HTTP-01 challenge server

Default: `""`. An IP address; empty listens on all interfaces

Requires https_mode = auto or domain. Public HTTP port 80 must reach this HTTP-01 listener.

Applies to: advanced. Change: HTTPS workflow; validates certificates and verifies the restarted server.

```ini
[tls]
acme_http_address = 0.0.0.0
```

Environment: `XFERRY_ACME_HTTP_ADDRESS`; launch: `--acme-http-address`.

#### `acme_http_port`

Bind port for HTTP-01 challenge server

Default: `80`. Minimum 1; maximum 65535

Requires https_mode = auto or domain. Default 80; use another internal port only when public port 80 is forwarded to it.

Applies to: advanced. Change: HTTPS workflow; validates certificates and verifies the restarted server.

```ini
[tls]
acme_http_port = 80
```

Environment: `XFERRY_ACME_HTTP_PORT`; launch: `--acme-http-port`.

### limits

#### `max_size_mb`

Maximum HTTP request body in MiB, including multipart overhead; this is not a per-file size guarantee.

Default: `100`; unit: MiB. Integer at least 1 MiB

Applies to: all. Change: restart.

```ini
[limits]
max_size_mb = 100
```

Environment: `XFERRY_MAX_SIZE_MB`; launch: `-m`, `--max-size`.

#### `encrypted_upload_max_size_mb`

Max encrypted-upload plaintext size in MiB; 0 = automatic

Default: `0`; unit: MiB. Integer from 0 to 32768 MiB; 0 selects the available quota/free-space limit

Used only when encrypted_uploads is true; max_size_mb still limits each encrypted chunk request.

Applies to: advanced. Change: restart.

```ini
[limits]
encrypted_upload_max_size_mb = 0
```

Environment: `XFERRY_ENCRYPTED_UPLOAD_MAX_SIZE_MB`; launch: `--encrypted-upload-max-size`.

#### `encrypted_upload_incomplete_ttl_seconds`

Expiry for inactive encrypted uploads in seconds

Default: `86400`; unit: seconds. Minimum 1

Used only when encrypted_uploads is true; inactive partial uploads are cleaned up after this time.

Applies to: advanced. Change: restart.

```ini
[limits]
encrypted_upload_incomplete_ttl_seconds = 604800
```

Environment: `XFERRY_ENCRYPTED_UPLOAD_INCOMPLETE_TTL_SECONDS`; launch: `--encrypted-upload-incomplete-ttl`.

#### `upload_storage_limit_mb`

Aggregate files folder storage quota in MiB; 0 disables

Default: `0`; unit: MiB. Minimum 0

Public defaults to 4096 MiB. At least one disk control must remain enabled unless upload_quota_externally_managed is true.

Applies to: advanced. Change: restart.

```ini
[limits]
upload_storage_limit_mb = 4096
```

Environment: `XFERRY_UPLOAD_STORAGE_LIMIT_MB`; launch: `--upload-storage-limit`.

#### `upload_file_limit`

Aggregate files folder file count quota; 0 disables

Default: `0`. Minimum 0

Public defaults to 4096 files. Existing files in files_dir count toward the limit.

Applies to: advanced. Change: restart.

```ini
[limits]
upload_file_limit = 4096
```

Environment: `XFERRY_UPLOAD_FILE_LIMIT`; launch: `--upload-file-limit`.

#### `upload_reserve_free_mb`

Free disk space to preserve when committing uploads, in MiB; 0 disables this reserve.

Default: `0`; unit: MiB. Minimum 0

Public defaults to 1024 MiB. Applies to the filesystem containing files_dir.

Applies to: advanced. Change: restart.

```ini
[limits]
upload_reserve_free_mb = 1024
```

Environment: `XFERRY_UPLOAD_RESERVE_FREE_MB`; launch: `--upload-reserve-free`.

#### `upload_quota_externally_managed`

Confirm that storage is limited outside xferry, for example by a filesystem quota.

Default: `false`. true or false

Public access permits all three upload disk controls to be zero only when this is true.

Applies to: advanced. Change: restart.

```ini
[limits]
upload_quota_externally_managed = false
```

Environment: `XFERRY_UPLOAD_QUOTA_EXTERNALLY_MANAGED`; launch: `--upload-quota-externally-managed`.

#### `note_storage_limit_mb`

Total encrypted-note storage quota in MiB; 0 disables the quota.

Default: `256`; unit: MiB. Minimum 0

Notes are stored in private state, outside files_dir.

Applies to: advanced. Change: restart.

```ini
[limits]
note_storage_limit_mb = 256
```

Environment: `XFERRY_NOTE_STORAGE_LIMIT_MB`; launch: `--note-storage-limit`.

#### `note_count_limit`

Aggregate encrypted note count quota; 0 disables

Default: `1000`. Minimum 0

Limits encrypted notes in private state, independently of upload_file_limit.

Applies to: advanced. Change: restart.

```ini
[limits]
note_count_limit = 1000
```

Environment: `XFERRY_NOTE_COUNT_LIMIT`; launch: `--note-count-limit`.

#### `smuggle_temp_age`

Max age for retained SMUGGLE temp pages in seconds; 0 disables

Default: `3600`; unit: seconds. Minimum 0

Applies only to retained SMUGGLE pages in the files folder; 0 disables age-based cleanup.

Applies to: advanced. Change: restart.

```ini
[limits]
smuggle_temp_age = 3600
```

Environment: `XFERRY_SMUGGLE_TEMP_AGE`; launch: `--smuggle-temp-age`.

#### `smuggle_temp_file_limit`

Max retained SMUGGLE temp page count; 0 disables

Default: `32`. Minimum 0

Applies only to retained SMUGGLE pages; 0 disables the count limit.

Applies to: advanced. Change: restart.

```ini
[limits]
smuggle_temp_file_limit = 32
```

Environment: `XFERRY_SMUGGLE_TEMP_FILE_LIMIT`; launch: `--smuggle-temp-file-limit`.

#### `smuggle_temp_storage_limit_mb`

Max retained SMUGGLE temp page bytes in MiB; 0 disables

Default: `128`; unit: MiB. Minimum 0

Applies only to retained SMUGGLE pages; 0 disables the storage limit.

Applies to: advanced. Change: restart.

```ini
[limits]
smuggle_temp_storage_limit_mb = 128
```

Environment: `XFERRY_SMUGGLE_TEMP_STORAGE_LIMIT_MB`; launch: `--smuggle-temp-storage-limit`.

#### `max_header_size_kb`

Max HTTP request header size in KiB

Default: `64`; unit: KiB. Minimum 1

Rejects oversized HTTP headers before request bodies are read.

Applies to: advanced. Change: restart.

```ini
[limits]
max_header_size_kb = 64
```

Environment: `XFERRY_MAX_HEADER_SIZE_KB`; launch: `--max-header-size`.

#### `body_memory_budget_mb`

Admission budget for aggregate in-flight request bodies in MiB, not an RSS ceiling

Default: `"automatic from request size and worker count"`; unit: MiB. Empty means automatic; otherwise an integer at least 1 MiB

Automatic is max_size_mb × workers, raised for encrypted chunks when needed. Public defaults to 512 MiB.

Applies to: advanced. Change: restart.

```ini
[limits]
body_memory_budget_mb = 256
```

Environment: `XFERRY_BODY_MEMORY_BUDGET_MB`; launch: `--body-memory-budget`.

#### `body_idle_timeout`

Max idle seconds between request body chunks; 0 disables

Default: `5.0`; unit: seconds. Minimum 0

Public access requires a positive value.

Applies to: advanced. Change: restart.

```ini
[limits]
body_idle_timeout = 5
```

Environment: `XFERRY_BODY_IDLE_TIMEOUT`; launch: `--body-idle-timeout`.

#### `body_timeout`

Max seconds to receive a request body after headers; 0 disables

Default: `300.0`; unit: seconds. Minimum 0

Public access requires a positive value.

Applies to: advanced. Change: restart.

```ini
[limits]
body_timeout = 300
```

Environment: `XFERRY_BODY_TIMEOUT`; launch: `--body-timeout`.

#### `body_min_rate`

Minimum average request body read rate in bytes/s; 0 disables

Default: `0.0`; unit: bytes/s. Minimum 0

Measured across body reads; 0 disables the minimum rate without disabling timeouts.

Applies to: advanced. Change: restart.

```ini
[limits]
body_min_rate = 1024
```

Environment: `XFERRY_BODY_MIN_RATE`; launch: `--body-min-rate`.

#### `stream_send_idle_timeout`

Max seconds a streamed response send may block per chunk

Default: `5.0`; unit: seconds. Minimum 0.001

Must stay positive in every access mode.

Applies to: advanced. Change: restart.

```ini
[limits]
stream_send_idle_timeout = 5
```

Environment: `XFERRY_STREAM_SEND_IDLE_TIMEOUT`; launch: `--stream-send-idle-timeout`.

#### `stream_send_timeout`

Max total seconds for a streamed response transfer; 0 disables

Default: `300.0`; unit: seconds. Minimum 0

Public access requires a positive value.

Applies to: advanced. Change: restart.

```ini
[limits]
stream_send_timeout = 300
```

Environment: `XFERRY_STREAM_SEND_TIMEOUT`; launch: `--stream-send-timeout`.

#### `max_websocket_connections`

Max active WebSocket connections; each occupies a worker and 0 rejects all

Default: `"automatic: half of the worker count"`. Empty means automatic; otherwise an integer at least 0

Automatic reserves half the workers for WebSockets (workers // 2). Each active connection occupies one worker; 0 rejects all.

Applies to: advanced. Change: restart.

```ini
[limits]
max_websocket_connections = 5
```

Environment: `XFERRY_MAX_WEBSOCKET_CONNECTIONS`; launch: `--max-websocket-connections`.

#### `websocket_frame_idle_timeout`

Max idle seconds while waiting for the rest of an incomplete WebSocket frame

Default: `5.0`; unit: seconds. Minimum 0.001

Applies while reading an incomplete WebSocket frame; it does not close an otherwise idle connection.

Applies to: advanced. Change: restart.

```ini
[limits]
websocket_frame_idle_timeout = 5
```

Environment: `XFERRY_WEBSOCKET_FRAME_IDLE_TIMEOUT`; launch: `--websocket-frame-idle-timeout`.

### security

#### `auth_file`

Protected file containing one username:password line. Generate or change it through the credentials action.

Default: `"not set"`. A readable protected file with one nonempty username:password line

Required for public access; optional for private/lab. Use xferry credentials to generate or reset it.

Applies to: all; installation-owned paths are managed automatically. Change: credentials workflow; use Password or credentials reset.

```ini
[security]
auth_file = /etc/xferry/auth
```

Environment: `XFERRY_AUTH_FILE`; launch: `--auth-file`.

#### `allowed_hosts`

HTTP Host names/IP addresses admitted by the server. Empty means automatic listener/certificate names.

Default: `[]`. Whitespace-separated names/IPs without URLs, ports, CIDRs or wildcards

Empty derives allowed hosts from the listener/certificate. Public wildcard binds with file certificates require an explicit list containing the certificate hostname.

Applies to: advanced. Change: restart.

```ini
[security]
allowed_hosts = files.example.com localhost
```

Environment: `XFERRY_ALLOWED_HOSTS`; launch: `--allowed-host`.

### cors

#### `cors_origin`

Browser origin allowed to read responses from a separate web application. Empty disables cross-origin access.

Default: `""`. An exact origin; empty disables

Public access rejects *. Set an exact origin only when using a separate browser application.

Applies to: advanced. Change: restart.

```ini
[cors]
cors_origin = https://portal.example.com
```

Environment: `XFERRY_CORS_ORIGIN`; launch: `--cors-origin`.

### plugins

#### `plugin_allowlist`

Explicit extension modules allowed to load.

Default: `[]`. Comma-separated module entry points

Installed plugins only; public access also requires plugins_allow_public_direct = true.

Applies to: advanced. Change: restart.

```ini
[plugins]
plugin_allowlist = example.module:plugin
```

Environment: `XFERRY_PLUGIN_ALLOWLIST`.

#### `plugins_allow_public_direct`

Permit allowlisted extensions in public mode.

Default: `false`. true or false

Only matters with access = public and a nonempty plugin_allowlist.

Applies to: advanced. Change: restart.

```ini
[plugins]
plugins_allow_public_direct = false
```

Environment: `XFERRY_PLUGINS_ALLOW_PUBLIC_DIRECT`.

#### `plugins_override_core`

Permit extensions to replace built-in HTTP method handlers.

Default: `false`. true or false

Only matters with plugin_allowlist; allows a plugin to replace a built-in HTTP method.

Applies to: advanced. Change: restart.

```ini
[plugins]
plugins_override_core = false
```

Environment: `XFERRY_PLUGINS_OVERRIDE_CORE`.
<!-- END GENERATED: xferry-contracts/settings-reference -->
