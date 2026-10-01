# CLI reference

This page is generated from the real English command dispatcher. Run
`python tools/render_contracts.py --write` after changing CLI help.

<!-- BEGIN GENERATED: xferry-contracts/cli-reference -->
## `xferry --help`

```text
usage: xferry [--lang LANG] COMMAND [OPTIONS]

Manage an installed XFerry service or run the server with xferry run.

Portable commands (Windows, macOS, Linux):
  run
  examples
  help

Managed Linux/systemd commands:
  setup
  status
  logs
  start
  stop
  restart
  doctor
  credentials
  uninstall

Optional maintenance:
  update
  rollback

Portable lifecycle: pipx upgrade xferry; pipx uninstall xferry.
Managed commands and optional maintenance require a supported Linux/systemd host.
Root options: --help, --version, --lang LANG.

Examples:
  xferry run --preset local
  sudo xferry setup
  sudo xferry status
  xferry examples
```

## `xferry run --help`

```text
usage: xferry run [-h] [-V] [--help-all]
                  [--preset {local,local-secure,public-direct}]
                  [--config FILE] [--check-config] [--print-config]
                  [--write-sample-config FILE] [-H HOST] [-p PORT] [-d DIR]
                  [--open] [--tls | --no-tls] [--auth CREDS]
                  [--auth-file FILE] [--allowed-host HOST]

HTTP server with custom methods, TLS, Auth, and uploads-only file access.

Choose a launch journey:
  local          Loopback HTTP for first-run and demos.
                 xferry run --preset local --open
  local-secure   Loopback self-signed TLS plus generated auth in an interactive TTY.
                 Service form: xferry run --preset local-secure --auth-file FILE
  public-direct  Advanced public path. Start from the generated INI; real TLS,
                 file-backed auth, finite quotas, and strict validation are required.
                 xferry run --write-sample-config ./xferry.ini
                 xferry run --config ./xferry.ini --check-config

Capacity model:
  Body memory is an admission budget for in-flight request bodies, not an RSS ceiling; decoded, parsed, TLS, and Python overhead can coexist.
  Each active WebSocket occupies one worker while connected.

Use --help-all for every tuning and protocol option.

options:
  -h, --help            show this help message and exit
  -V, --version         show program's version number and exit
  --help-all            Show every configuration, limit, TLS and protocol
                        option

Configuration:
  --preset {local,local-secure,public-direct}
                        Select journey defaults below every explicit
                        file/env/CLI value
  --config FILE         Read settings from an INI configuration file
  --check-config        Validate the resolved configuration and exit without
                        starting
  --print-config        Print the resolved configuration as redacted JSON and
                        exit
  --write-sample-config FILE
                        Write a public-direct sample INI configuration and
                        exit

Basic:
  -H HOST, --host HOST  Bind host (default: 127.0.0.1)
  -p PORT, --port PORT  Listen port (default: 8080)
  -d DIR, --dir DIR     Root directory (default: current)

Modes:
  --open                Open browser after start

TLS:
  --tls, --no-tls       Enable HTTPS with a generated self-signed certificate

Authentication:
  --auth CREDS          Basic Auth: 'user:pass', 'random', or 'user' (random
                        password)
  --auth-file FILE      Read Basic Auth credentials from one user:pass line in
                        FILE
  --allowed-host HOST   Admit this Host/IP (repeatable; replaces file/env
                        list)

The named journeys select defaults only; every explicit INI, XFERRY_* or CLI
value remains authoritative. Use --help-all for the exhaustive option list.
```

## `xferry setup --help`

```text
usage: xferry setup [-h] [--domain DOMAIN | --private] [--public-ip IP] [--email EMAIL]
                    [--body-budget-mib MIB] [--max-upload-mib MIB] [--workers COUNT]
                    [--reserve-mib MIB] [--upload-storage-mib MIB] [--firewall {allow,deny}]
                    [--dry-run] [--json]

Install and configure the managed XFerry service.

options:
  -h, --help            Show this help and exit.
  --domain DOMAIN
  --private
  --public-ip IP
  --email EMAIL
  --body-budget-mib MIB
  --max-upload-mib MIB
  --workers COUNT
  --reserve-mib MIB
  --upload-storage-mib MIB
  --firewall {allow,deny}
  --dry-run
  --json

Example: sudo xferry setup
```

## `xferry status --help`

```text
usage: xferry status [-h] [--json]

Show the managed service status.

options:
  -h, --help  Show this help and exit.
  --json

Example: sudo xferry status
```

## `xferry logs --help`

```text
usage: xferry logs [-h] [--lines COUNT] [--since WHEN] [--follow]

Show managed service logs.

options:
  -h, --help     Show this help and exit.
  --lines COUNT
  --since WHEN
  --follow

Example: xferry logs
```

## `xferry start --help`

```text
usage: xferry start [-h]

Start the managed service.

options:
  -h, --help  Show this help and exit.

Example: sudo xferry start
```

## `xferry stop --help`

```text
usage: xferry stop [-h]

Stop the managed service.

options:
  -h, --help  Show this help and exit.

Example: sudo xferry stop
```

## `xferry restart --help`

```text
usage: xferry restart [-h]

Restart the managed service.

options:
  -h, --help  Show this help and exit.

Example: sudo xferry restart
```

## `xferry doctor --help`

```text
usage: xferry doctor [-h] [--deep] [--skip-network] [--json]

Check the managed installation.

options:
  -h, --help      Show this help and exit.
  --deep
  --skip-network
  --json

Example: sudo xferry doctor
```

## `xferry credentials --help`

```text
usage: xferry credentials [-h] [--json] {reset}

Manage service credentials.

positional arguments:
  {reset}

options:
  -h, --help  Show this help and exit.
  --json

Example: sudo xferry credentials reset
```

## `xferry examples --help`

```text
usage: xferry examples [-h]

Print copy-paste management command examples.

options:
  -h, --help  Show this help and exit.

Example: xferry examples
```

## `xferry update --help`

```text
usage: xferry update [-h] --to VERSION [--dry-run] [--json]

Update a managed Linux/systemd installation as root to an exact signed version. Portable
installations use `pipx upgrade xferry`.

options:
  -h, --help    Show this help and exit.
  --to VERSION  Exact immutable release version to verify and install.
  --dry-run     Verify signed metadata and report the apply plan without host mutation.
  --json

Example: sudo xferry update --to 0.1.0
```

## `xferry rollback --help`

```text
usage: xferry rollback [-h] [--to VERSION] [--dry-run] [--json]

Restore a verified release on a long-lived installation.

options:
  -h, --help    Show this help and exit.
  --to VERSION
  --dry-run
  --json

Example: sudo xferry rollback --to 0.1.0
```

## `xferry uninstall --help`

```text
usage: xferry uninstall [-h] [--purge-data] [--yes] [--dry-run] [--json]

Remove the managed installation safely.

options:
  -h, --help    Show this help and exit.
  --purge-data
  --yes
  --dry-run
  --json

Example: sudo xferry uninstall
```
<!-- END GENERATED: xferry-contracts/cli-reference -->
