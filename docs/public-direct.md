# Public deployment

Run `xferry setup` on the server host, select **Public**, then choose a domain or
an automatic address. Use `xferry setup --docker` for a generated Docker
deployment. Setup generates a 12-character Basic Auth password, configures HTTPS,
starts the server and prints the URL. Later changes use `xferry config`.

These commands require **xferry 0.3.2 or newer**. Existing `0.2.x` installations
use [migration](migration.md); the [v0.2.0 guide](archive/0.2.0-installation.md)
remains archived. Review the
[external exposure baseline](security.md#external-exposure-baseline) before
allowing untrusted clients.

## HTTPS requirements

| Mode | What you provide |
| --- | --- |
| `auto` | A public IPv4 address; setup uses an sslip.io hostname. Auto-detection can be overridden with `public_ip`. |
| `domain` | A DNS hostname pointing to this host. Set `domain`; `email` is optional. |
| `files` | A PEM certificate and matching key, plus admitted hostnames in `allowed_hosts`. Renew them with your certificate manager. |

For `auto` and `domain`, inbound TCP 80 must reach the ACME challenge listener for
issuance and renewal. The chosen HTTPS port must also be reachable. An occupied
port or NAT mapping needs to be resolved before setup can complete. The
`acme_http_port` setting changes the internal listener; ACME still connects to
public port 80. `acme_server=staging` is for tests and produces certificates that
browsers do not trust. `self-signed` is suitable for lab/private use.

A scripted domain setup:

```console
xferry setup --access public --domain files.example.com --files-dir /srv/share
```

## Review configuration

```console
xferry config check
xferry config show --all
xferry config explain allowed_hosts
```

Public mode requires trusted HTTPS, protected file-backed authentication,
working request-authority admission, finite upload capacity and enabled body and
stream timeouts. It rejects wildcard browser CORS. Use the generated defaults,
then adjust only limits needed for the workload. All settings and examples are
listed in [the reference](settings.md).

`allowed_hosts` admits HTTP Host names/IPs, independently of CORS origins.
INI/environment values use whitespace; CLI `--allowed-host` can be repeated.
Each source replaces the lower-precedence list. Empty means automatic admission
from listener/certificate names. Explicit lists must include the ACME hostname.
With supplied certificates on a wildcard listener, set the list explicitly.
URLs, ports, CIDRs and wildcards are not host entries.

## Network and verification

Limit access with a firewall or reverse proxy. Set connection/time limits and
hard disk/process quotas appropriate to the host; monitor free space and health.
The application uses the direct TCP peer for authentication throttling and
loopback checks. `Forwarded`, `X-Forwarded-For`, and `X-Real-IP` do not grant a
trusted client identity.

For manually managed containers, pin a release version or
`ghcr.io/kgmnotes/xferry@sha256:${XFERRY_DIGEST}` and retain configuration and
volumes. The generated deployment already pins its image.

Probe from another network with normal certificate verification:

```console
curl --fail-with-body --user USER --request PING https://files.example.com/
```

Require HTTP 200 and `"health":"ready"`, then perform a small file lifecycle
check. Store the password securely. Use the credentials action in `xferry config`
to replace it; no inline password setting is needed.

For recovery, preserve data and use `xferry rollback` or the previous tested
manual image digest/configuration. Restore traffic after authenticated health
and file operations pass. See [Operations](operations.md).
