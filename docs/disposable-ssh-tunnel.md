# Disposable SSH tunnel

This procedure publishes a loopback xferry process through a temporary reverse
SSH tunnel. Use it only for an authorized, short-lived test. The tunnel
provider terminates public TLS and may observe credentials and transferred
content.

!!! warning "Use test data"
    Create unique file-backed credentials, set finite quotas, and stop both
    processes after the test. A tunnel does not provide the complete
    [external exposure baseline](security.md#external-exposure-baseline).

## Prepare the local process

Run from the checkout after installing xferry:

```bash
XFERRY_TUNNEL_DIR=/tmp/xferry-tunnel-demo
test ! -e "$XFERRY_TUNNEL_DIR"
install -d -m 0700 "$XFERRY_TUNNEL_DIR" "$XFERRY_TUNNEL_DIR/data"

umask 0077
python -c 'import secrets; print("xferry:" + secrets.token_urlsafe(24))' \
  > "$XFERRY_TUNNEL_DIR/auth"

xferry run \
  --preset local \
  --host 127.0.0.1 \
  --port 8080 \
  --dir "$XFERRY_TUNNEL_DIR/data" \
  --auth-file "$XFERRY_TUNNEL_DIR/auth" \
  --max-size 32 \
  --upload-storage-limit 256 \
  --upload-file-limit 128 \
  --upload-reserve-free 512 \
  --note-storage-limit 64 \
  --note-count-limit 256 \
  --workers 4 \
  --max-websocket-connections 2 \
  --body-memory-budget 64
```

Leave the terminal open.

## Start the tunnel

In a second terminal, use a provider approved for the engagement. This example
uses Optimistix Tunnel:

```bash
XFERRY_TUNNEL_DIR=/tmp/xferry-tunnel-demo

ssh -F /dev/null -tt -p 1122 \
  -R 80:127.0.0.1:8080 \
  -o ExitOnForwardFailure=yes \
  -o ConnectTimeout=10 \
  -o ServerAliveInterval=15 \
  -o ServerAliveCountMax=3 \
  -o UserKnownHostsFile="$XFERRY_TUNNEL_DIR/known_hosts" \
  -o GlobalKnownHostsFile=/dev/null \
  -o StrictHostKeyChecking=accept-new \
  user@ssh.optimistixtunnel.com
```

Record the returned HTTPS URL. Browser mutations require that exact origin.
Stop only xferry, then restart it with the original arguments plus:

```bash
--cors-origin 'https://assigned-name.otnl.link'
```

Do not use a wildcard origin. It permits read-only CORS but does not authorize
uploads, deletion, NOTE, SMUGGLE, Advanced requests, or WebSocket notes.

## Stop and remove

Stop SSH first, then xferry. After copying any required test evidence, remove
the dedicated directory:

```bash
XFERRY_TUNNEL_DIR=/tmp/xferry-tunnel-demo
test "$XFERRY_TUNNEL_DIR" = /tmp/xferry-tunnel-demo
find "$XFERRY_TUNNEL_DIR" -depth -delete
```

This deletes the generated credentials, uploads, notes, and temporary
artifacts. Do not terminate unrelated processes by a broad process name.
