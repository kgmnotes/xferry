# CLI reference

This page is generated from the real English command dispatcher. Run
`python tools/render_contracts.py --write` after changing CLI help.

<!-- BEGIN GENERATED: xferry-contracts/cli-reference -->
## `xferry --help`

```text
usage: xferry [--lang LANG] COMMAND [OPTIONS]

Run xferry for a short menu, setup to install, or run to start once.

  run           Run the XFerry server.
  setup         Install and configure a Linux service or Docker server on this host.
  config        Open settings, or show/explain/check/set a setting.
  status        Show the installed server status.
  logs          Show installed server logs.
  start         Start the installed server.
  stop          Stop the installed server.
  restart       Restart the installed server.
  doctor        Check the selected service or container deployment.
  credentials   Manage service credentials.
  uninstall     Remove the managed installation safely.
  update        Update the installed server to an exact release version.
  rollback      Restore a verified release on a long-lived installation.

Root options: --help, --version, --lang LANG, --plain (text interface).

Examples:
  xferry run --files-dir ~/Shared
  xferry setup --backend native
  xferry status
  xferry config explain files_dir
```

## `xferry run --help`

```text
usage: xferry run [-h] [-V] [--help-all] [--config FILE] [--open] [--access {private,public,lab}]
       [-H HOST] [-p PORT] [--files-dir DIR] [--https {off,auto,domain,files,self-signed}]
       [--auth-file FILE] [--allowed-host HOST]

Run the file server on this host.

By default it listens at http://127.0.0.1:8080 and uses your saved configuration.
Use xferry setup for an installed service, or xferry config to change settings.
Use --help-all for every limit, certificate and protocol option.

options:
  -h, --help            show this help message and exit
  -V, --version         show program's version number and exit
  --help-all            Show every configuration, limit, TLS and protocol
                        option

Configuration:
  --config FILE         Read settings from an INI configuration file
  --open                Open the server in your browser after it starts

Basic:
  --access {private,public,lab}
                        Server access: private loopback, public HTTPS, or
                        explicit lab testing
  -H HOST, --host HOST  Bind host (default: 127.0.0.1)
  -p PORT, --port PORT  Listen port (default: 8080)
  --files-dir DIR       Folder for uploads and downloads (default: per-user
                        xferry/files)

TLS:
  --https {off,auto,domain,files,self-signed}
                        HTTPS mode; default: off for private/lab, automatic
                        address for public

Authentication:
  --auth-file FILE      Read Basic Auth credentials from one user:pass line in
                        FILE
  --allowed-host HOST   Admit this Host/IP (repeatable; replaces file/env
                        list)

Examples:
  xferry run --open
  xferry run --files-dir ./shared
  xferry run --access public --auth-file /path/to/auth
  xferry run --config ./xferry.ini

INI settings are overridden by XFERRY_* environment variables, then explicit
command options. Use xferry config show --all to see effective values and sources.
```

## `xferry setup --help`

```text
usage: xferry setup [-h] [--help-all] [--channel {stable,testing}] [--instance ID] [--backend
       {native,docker}] [--access {private,public}] [--domain DOMAIN] [--files-dir DIR] [--public-ip
       IP] [--email EMAIL] [--firewall {allow,deny}] [--to VERSION | --image
       REPOSITORY@sha256:DIGEST] [--dry-run] [--json]

Install and configure a Linux service or Docker server on this host.

options:
  -h, --help            Show this help and exit.
  --help-all            Show all command options.
  --channel {stable,testing}
                        Select stable or opt into an exact testing build; updates keep the recorded
                        channel.
  --instance ID         Select a persistent deployment by ID.
  --backend {native,docker}
                        Install a Linux service or Docker Compose deployment (default: native).
  --access {private,public}
                        Private access or public HTTPS (default: public).
  --domain DOMAIN       Use your domain for public HTTPS.
  --files-dir DIR       Host folder for uploads and downloads.
  --public-ip IP        Public IPv4 for the automatic HTTPS address.
  --email EMAIL         Optional certificate contact address.
  --firewall {allow,deny}
                        Allow or decline required UFW rules.
  --to VERSION          Signed release version to install (default: 0.5.1).
  --image REPOSITORY@sha256:DIGEST
                        Use an explicit immutable Docker image instead of a release version.
  --dry-run             Validate and preview changes.
  --json                Print machine-readable results.

Example: xferry setup --backend native
```

## `xferry config --help`

```text
usage: xferry config [-h] [--help-all] [--instance ID | --config FILE] [--all] [--group GROUP]
       [--search TEXT] [--dry-run] [--json] [{show,explain,check,set}] [KEY[=VALUE] ...]

Open settings, or show/explain/check/set a setting.

positional arguments:
  {show,explain,check,set}
                        Omit to open the settings wizard.
  KEY[=VALUE]

options:
  -h, --help            Show this help and exit.
  --help-all            Show all command options.
  --instance ID         Select a persistent deployment by ID.
  --config FILE         Edit an explicit foreground configuration profile.
  --all                 Show every setting.
  --group GROUP         Show one settings group.
  --search TEXT         Find settings by name or description.
  --dry-run             Validate and preview changes.
  --json                Print machine-readable results.

Example: xferry config explain files_dir
```

## `xferry status --help`

```text
usage: xferry status [-h] [--help-all] [--instance ID] [--json]

Show the installed server status.

options:
  -h, --help     Show this help and exit.
  --help-all     Show all command options.
  --instance ID  Select a persistent deployment by ID.
  --json         Print machine-readable results.

Example: xferry status
```

## `xferry logs --help`

```text
usage: xferry logs [-h] [--help-all] [--instance ID] [--lines COUNT] [--since WHEN] [--follow]

Show installed server logs.

options:
  -h, --help     Show this help and exit.
  --help-all     Show all command options.
  --instance ID  Select a persistent deployment by ID.
  --lines COUNT  Number of recent log lines (default: 100).
  --since WHEN   Show logs since this time.
  --follow       Stream new log lines.

Example: xferry logs --follow
```

## `xferry start --help`

```text
usage: xferry start [-h] [--help-all] [--instance ID] [--json]

Start the installed server.

options:
  -h, --help     Show this help and exit.
  --help-all     Show all command options.
  --instance ID  Select a persistent deployment by ID.
  --json         Print machine-readable results.

Example: xferry start
```

## `xferry stop --help`

```text
usage: xferry stop [-h] [--help-all] [--instance ID] [--json]

Stop the installed server.

options:
  -h, --help     Show this help and exit.
  --help-all     Show all command options.
  --instance ID  Select a persistent deployment by ID.
  --json         Print machine-readable results.

Example: xferry stop
```

## `xferry restart --help`

```text
usage: xferry restart [-h] [--help-all] [--instance ID] [--json]

Restart the installed server.

options:
  -h, --help     Show this help and exit.
  --help-all     Show all command options.
  --instance ID  Select a persistent deployment by ID.
  --json         Print machine-readable results.

Example: xferry restart
```

## `xferry doctor --help`

```text
usage: xferry doctor [-h] [--help-all] [--instance ID] [--deep] [--skip-network] [--json]

Check the selected service or container deployment.

options:
  -h, --help      Show this help and exit.
  --help-all      Show all command options.
  --instance ID   Select a persistent deployment by ID.
  --deep          Include external connectivity checks.
  --skip-network  Check local state only.
  --json          Print machine-readable results.

Example: xferry doctor
```

## `xferry credentials --help`

```text
usage: xferry credentials [-h] [--help-all] [--instance ID | --config FILE] [--json] {reset}

Manage service credentials.

positional arguments:
  {reset}        Generate a new 12-character password.

options:
  -h, --help     Show this help and exit.
  --help-all     Show all command options.
  --instance ID  Select a persistent deployment by ID.
  --config FILE  Edit an explicit foreground configuration profile.
  --json         Print machine-readable results.

Example: xferry credentials reset
```

## `xferry update --help`

```text
usage: xferry update [-h] [--help-all] [--channel {stable,testing}] [--instance ID] --to VERSION
       [--dry-run] [--json]

Update the installed server to an exact release version.

options:
  -h, --help            Show this help and exit.
  --help-all            Show all command options.
  --channel {stable,testing}
                        Select stable or opt into an exact testing build; updates keep the recorded
                        channel.
  --instance ID         Select a persistent deployment by ID.
  --to VERSION          Exact release version.
  --dry-run             Validate and preview changes.
  --json                Print machine-readable results.

Example: xferry update --to 0.5.1
```

## `xferry rollback --help`

```text
usage: xferry rollback [-h] [--help-all] [--channel {stable,testing}] [--instance ID] [--to VERSION]
       [--dry-run] [--json]

Restore a verified release on a long-lived installation.

options:
  -h, --help            Show this help and exit.
  --help-all            Show all command options.
  --channel {stable,testing}
                        Select stable or opt into an exact testing build; updates keep the recorded
                        channel.
  --instance ID         Select a persistent deployment by ID.
  --to VERSION          Exact release version.
  --dry-run             Validate and preview changes.
  --json                Print machine-readable results.

Example: xferry rollback
```

## `xferry uninstall --help`

```text
usage: xferry uninstall [-h] [--help-all] [--instance ID] [--purge] [--yes] [--dry-run] [--json]

Remove the managed installation safely.

options:
  -h, --help     Show this help and exit.
  --help-all     Show all command options.
  --instance ID  Select a persistent deployment by ID.
  --purge        Delete owned configuration, credentials and private state; keep external files.
  --yes          Confirm deletion without a prompt.
  --dry-run      Validate and preview changes.
  --json         Print machine-readable results.

Example: xferry uninstall
```
<!-- END GENERATED: xferry-contracts/cli-reference -->
