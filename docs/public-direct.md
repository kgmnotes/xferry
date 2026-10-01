# Public deployment

`public-direct` is the strict configuration path for a service reachable from
an untrusted network. It validates application settings, but the operator must
still provide the network, storage, monitoring, and recovery boundaries in the
[security policy](security.md#external-exposure-baseline).

!!! danger "Experienced operators only"
    Do not treat this as a continuation of the loopback quick start. Test the
    complete deployment on data and infrastructure approved for the
    engagement.

## Prepare the host

Use the immutable `ghcr.io/kgmnotes/xferry:v0.2.0` image or the exact
`ghcr.io/kgmnotes/xferry@sha256:${XFERRY_DIGEST}` recorded by the release. The
released image supports `linux/amd64` and `linux/arm64`. The Compose file at
`deploy/docker/docker-compose.public-direct.yml` pins the
versioned image and applies a read-only filesystem and finite resource limits.

Prepare permission-restricted configuration and secret paths. The examples
below assume:

- runtime data is stored in a named volume;
- `/etc/xferry/auth` contains exactly one strong `user:password` line;
- DNS points to the host and TCP 80/443 are controlled by the firewall;
- a supervisor applies process limits and restarts.

Do not place credentials in the command line, repository, or environment.

## Generate and edit the configuration

```bash
xferry run --write-sample-config /etc/xferry/xferry.ini
```

The sample enables `public-direct`, file-backed authentication, bounded
workers and body memory, finite upload quotas, body and stream timeouts, and
JSON logs. Review every path and limit.

For a real domain, replace the sample `sslip = true` setting with:

```ini
[tls]
letsencrypt = true
domain = files.example.com

[security]
auth_file = /etc/xferry/auth
allowed_hosts = files.example.com
```

Alternatively, configure both `cert_file` and `key_file` for certificates
managed outside xferry. A wildcard bind with file certificates must set an
explicit `allowed_hosts` list because XFerry cannot infer the certificate
names from files. INI and `XFERRY_ALLOWED_HOSTS` values use ASCII whitespace
between host/IP entries; the CLI uses repeatable `--allowed-host`. A layer
replaces the whole lower-precedence list, an empty value selects auto-mode,
and entries cannot be URLs, ports, CIDRs, wildcards, or comma lists.

Auto-mode on a wildcard bind admits loopback authorities and adds the final
ACME/sslip certificate hostname after TLS setup, before the listener binds.
An explicit ACME domain must also appear in the explicit allowlist. CORS
origins are a separate browser policy and never add request authorities.

Public-direct rejects self-signed-only TLS, missing file-backed authentication,
disabled body or stream timeouts, wildcard CORS, an unbounded upload capacity
declaration, and an unresolved request-authority policy.

Validate without starting the listener:

```bash
xferry run --config /etc/xferry/xferry.ini --check-config
xferry run --config /etc/xferry/xferry.ini --print-config
```

The printed posture is redacted. Inspect the effective URL, data root, TLS and
authentication modes, workers, body budget, WebSocket admission, and storage
limits. Confirm the printed request-authority mode/list matches the certificate
and gateway health-check `Host` value.

## Add external controls

Before routing traffic, configure:

- firewall rules limited to required ports and source networks where possible;
- reverse-proxy connection, request-header, request-body, and timeout caps;
- proxy-side per-client throttling;
- a hard disk or volume quota and free-space alerts;
- process memory, CPU, PID, and file-descriptor limits;
- exact allowed browser origins when a separate frontend origin is required;
- exact allowed request authorities for every certificate/gateway hostname;
- off-host monitoring with normal certificate verification;
- backups of data and ACME state, plus a tested restore procedure.

The application uses the direct TCP peer for authentication throttling and
no-auth Advanced Session loopback checks. `Forwarded`, `X-Forwarded-For`, and
`X-Real-IP` are not trusted client identity.

## Start and verify

After placing the reviewed config at `deploy/docker/xferry.ini` and credentials
at `deploy/docker/secrets/xferry_auth`, start the immutable Compose service:

```console
XFERRY_HEALTH_HOST=files.example.com \
  docker compose -f deploy/docker/docker-compose.public-direct.yml up -d
```

Replace `files.example.com` with the configured TLS hostname and admitted
request authority. Compose requires this value before parsing its healthcheck.

Then probe it from another network using a protected curl config:

```bash
curl --config /run/secrets/xferry-curl.conf \
  --fail --silent --show-error \
  --request PING \
  https://files.example.com/
```

Require HTTP 200 and JSON with `"health":"ready"`. Also test a small upload,
download, and deletion with approved data. Monitor TLS failures, non-200
responses, authentication throttling, quota denials, storage-scan latency,
worker saturation, and free space.

## Recovery

Keep the exact image digest, configuration, and backup used for each
deployment. To recover:

1. Stop new traffic at the firewall or proxy.
2. Preserve the current data and ACME state.
3. Restore the last tested immutable image digest and configuration.
4. Validate the configuration before starting.
5. Restore traffic only after authenticated HTTPS `PING` and a file lifecycle
   check pass.

Never substitute `latest` during recovery. A retained version tag is useful for
people; the recorded digest is the rollback identity enforced by the registry.
