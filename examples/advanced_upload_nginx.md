# Advanced Sessions upload behind nginx

This example runs XFerry behind nginx while keeping Advanced routing and
parsing scoped to an explicit session token. User file access remains limited
to `<root>/uploads/`.

## 1. Start the server

```bash
xferry run \
  --host 127.0.0.1 \
  --port 18080 \
  --dir /srv/xferry \
  --auth-file /run/secrets/xferry_auth \
  --quiet
```

Uploaded files are written to `/srv/xferry/uploads/`.

## 2. nginx configuration

```nginx
server {
    listen 443 ssl http2;
    server_name files.example.com;

    ssl_certificate     /etc/letsencrypt/live/files.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/files.example.com/privkey.pem;

    location / {
        proxy_pass         http://127.0.0.1:18080;
        proxy_set_header   Host              $host;
        proxy_set_header   X-Real-IP         $remote_addr;
        proxy_set_header   X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto https;

        # Preserve custom HTTP methods used by an authorized Advanced Session.
        proxy_method       $request_method;

        client_max_body_size 200m;
        proxy_read_timeout   300s;
        proxy_send_timeout   300s;
    }
}
```

nginx preserves custom methods, but the session token, not the proxy, selects
the Advanced routing/parser context.

## 3. Create, use, inspect, and revoke a session

The control contract is `POST /_xferry/advanced-sessions`, optional
`GET /_xferry/advanced-sessions/current`, and
`DELETE /_xferry/advanced-sessions/current`. With Basic Auth configured, all
control and data requests require the same verified username. Store Basic Auth
in `/run/secrets/xferry_curl.conf` with mode `0600`, for example as
`user = "operator:<strong-password>"`. The commands read credentials from that
file and request-specific token headers from curl config on standard input, so
neither secret is expanded into process arguments. Never place the token in a
URL, cookie, path, body, `Authorization`, or forwarding header.

The create JSON is exactly
`{"prefix":"/advanced","decoder":"auto","diagnostic_headers":true}`.
The data request JSON is exactly
`{"data":"aGVsbG8=","encoding":"base64","encryption":"none","name":"hello.txt"}`.

```bash
base_url='https://files.example.com'

session_json="$(
  curl --silent --show-error --fail-with-body \
    --config /run/secrets/xferry_curl.conf --config - <<EOF
header = "Content-Type: application/json"
data = "{\"prefix\":\"/advanced\",\"decoder\":\"auto\",\"diagnostic_headers\":true}"
url = "$base_url/_xferry/advanced-sessions"
EOF
)"

advanced_token="$(printf '%s' "$session_json" | jq -r '.advanced_session.token')"
[[ "$advanced_token" =~ ^[A-Za-z0-9_-]{43}$ ]]

curl --silent --show-error --fail-with-body \
  --config /run/secrets/xferry_curl.conf --config - <<EOF
request = "SYNCDATA"
header = "X-XFerry-Advanced-Session: $advanced_token"
header = "Content-Type: application/json"
data = "{\"data\":\"aGVsbG8=\",\"encoding\":\"base64\",\"encryption\":\"none\",\"name\":\"hello.txt\"}"
url = "$base_url/advanced/upload"
EOF

# Optional inspection; its response omits the token.
curl --silent --show-error --fail-with-body \
  --config /run/secrets/xferry_curl.conf --config - <<EOF
header = "X-XFerry-Advanced-Session: $advanced_token"
url = "$base_url/_xferry/advanced-sessions/current"
EOF

curl --silent --show-error --fail-with-body \
  --config /run/secrets/xferry_curl.conf --config - <<EOF
request = "DELETE"
header = "X-XFerry-Advanced-Session: $advanced_token"
url = "$base_url/_xferry/advanced-sessions/current"
EOF
```

Create succeeds with `201`. Its `Cache-Control: no-store` response contains
`advanced_session.token` exactly once; the token is 43 unpadded ASCII
base64url characters. Revoke succeeds with
`{"advanced_session":{"revoked":true}}`. A revoked token cannot be reused;
invalid, expired, or revoked tokens return `404 advanced_session_not_found`.

## Routing and authorization rules

The `X-XFerry-Advanced-Session` token selects routing/parser context and never
replaces Basic Auth. The request path must match the immutable session prefix
case-sensitively and on a segment boundary. With Basic Auth, create, use,
inspect, and revoke require the same verified username. With Basic Auth
disabled, control and data requests are permitted only when the direct accepted
socket peer is loopback; forwarded headers do not establish that boundary.

An authorized matching session makes `POST`, `PUT`, `PATCH`, and `NONE`
Advanced uploads. Without the header, they keep Basic behavior. An authorized
matching session may also carry a syntactically valid unregistered custom
method such as `SYNCDATA`; without one, an unregistered custom method returns
`405 method_not_allowed`. Registered non-upload methods are never intercepted
and return `409 advanced_method_conflict` when combined with a matching session.

Sessions are per-server, in-memory, and vanish on restart. They have a
60-minute absolute lifetime, a 15-minute idle lifetime, and a capacity of 64.
Tokens must not leak through logs or any query, cookie, path, body,
`Authorization`, or forwarding header.

## Canonical carriers and fields

Every Advanced request has exactly one carrier: a declared body;
`X-XFerry-Data` or contiguous `X-XFerry-Data-0` through
`X-XFerry-Data-255` with canonical `X-XFerry-*` metadata headers; canonical
query fields; exact `xferry_*` cookie names; or
`<session-prefix>/_payload/<percent-encoded-name>/<base64url-data>`.

The only logical fields are `data`, `encryption`, `key`, `key_is_base64`,
`name`, `hmac`, `encoding`, and `method_override`. Aliases, duplicate or
unknown structured fields, ambiguous carriers, and noncanonical headers fail.

## Encryption and integrity

`encryption` is required and exactly `none|xor|aes` (`none`, `xor`, or `aes`).
`none` is explicit canonical metadata and forbids key, base64-key, and HMAC
metadata. `xor` is explicit compatibility/obfuscation, not confidentiality,
and requires a nonempty key. `aes` is AES-256-GCM and requires a nonempty key.
Optional HMAC is checked before AES/XOR decryption.
There is no AES-to-XOR or XOR-to-AES fallback.

## Caveats

- Always layer TLS and Basic Auth on externally reachable deployments.
- Prefer JSON body transport for sensitive data; headers and URLs are more
  likely to appear in proxy logs.
- `diagnostic_headers` defaults off. When enabled it emits only
  `X-XFerry-Handler: advanced`; it never exposes token, key, HMAC, or payload.
- `client_max_body_size` is only the proxy cap. XFerry still enforces its own
  request, carrier, decoded-size, and storage limits.
- nginx terminates the shown HTTP/2 connection and proxies HTTP/1.1 upstream.
  Protocol-specific HTTP/2/HTTP/3 behavior and resumable `Content-Range`
  uploads are outside XFerry's upload contract.
