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

Create a dedicated runtime user and permission-restricted paths. The examples
below assume:

- the source checkout and virtual environment are installed under
  `/opt/xferry-source`;
- runtime data is owned by the service user at `/var/lib/xferry`;
- `/etc/xferry/auth` contains exactly one strong `user:password` line;
- DNS points to the host and TCP 80/443 are controlled by the firewall;
- a supervisor applies process limits and restarts.

Do not place credentials in the command line, repository, or environment.

## Generate and edit the configuration

```bash
cd /opt/xferry-source
. .venv/bin/activate
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
```

Alternatively, configure both `cert_file` and `key_file` for certificates
managed outside xferry. Public-direct rejects self-signed-only TLS, missing
file-backed authentication, disabled body or stream timeouts, wildcard CORS,
and an unbounded upload capacity declaration.

Validate without starting the listener:

```bash
xferry run --config /etc/xferry/xferry.ini --check-config
xferry run --config /etc/xferry/xferry.ini --print-config
```

The printed posture is redacted. Inspect the effective URL, data root, TLS and
authentication modes, workers, body budget, WebSocket admission, and storage
limits.

## Add external controls

Before routing traffic, configure:

- firewall rules limited to required ports and source networks where possible;
- reverse-proxy connection, request-header, request-body, and timeout caps;
- proxy-side per-client throttling;
- a hard disk or volume quota and free-space alerts;
- process memory, CPU, PID, and file-descriptor limits;
- exact allowed browser origins when a separate frontend origin is required;
- off-host monitoring with normal certificate verification;
- backups of data and ACME state, plus a tested restore procedure.

The application uses the direct TCP peer for authentication throttling and
no-auth Advanced Session loopback checks. `Forwarded`, `X-Forwarded-For`, and
`X-Real-IP` are not trusted client identity.

## Start and verify

Start xferry through the configured supervisor, then probe it from another
network using a protected curl config:

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

Keep the source revision, dependency constraints, configuration, and backup
used for each deployment. To recover:

1. Stop new traffic at the firewall or proxy.
2. Preserve the current data and ACME state.
3. Restore the last tested source environment and configuration.
4. Validate the configuration before starting.
5. Restore traffic only after authenticated HTTPS `PING` and a file lifecycle
   check pass.

There is no published binary or container image to use as a rollback target at
this time.
