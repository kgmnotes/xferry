# Architecture

xferry is a synchronous Python HTTP server with a bundled no-build web UI. The
`xferry` package is the runtime and public import namespace.

## Request path

1. The accept loop admits a TCP connection and applies TLS when configured.
2. The receive layer parses bounded HTTP framing.
3. The request pipeline applies Basic Auth, browser-origin policy, payload
   limits, and WebSocket upgrade checks.
4. The handler registry selects a core or explicitly registered plugin method.
5. The handler uses scoped storage and metrics services.
6. The pipeline records metrics and writes the response.

The server runs accepted connections in a `ThreadPoolExecutor`. A keep-alive
connection occupies its worker while active, and each WebSocket occupies one
worker until it closes. See [ADR-005](ADR/ADR-005-thread-pool.md).

## Method policy

`xferry.features.CoreMethodSpec` owns the name, handler binding, mutation flag,
CORS eligibility, UI group, and exposure note for each built-in method.
Handler registration, browser mutation checks, CORS, `PING`, and UI grouping
derive from that registry.

`PING.supported_methods` is the availability contract. `method_groups` is
presentation metadata. Launch presets select configuration defaults and
validation posture; they do not enable or disable methods.

## Storage boundaries

The operator supplies a root directory. User-visible file operations resolve
under `<root>/uploads/`; Secure Notepad state is stored separately under
`<root>/notes/`. The shared descendant resolver resolves paths and rejects
escapes, including symlink escapes.

`UploadStorageService` applies upload quotas and publication rules. Generated
SMUGGLE artifacts share the upload volume and have additional retention and
one-shot rules. Note storage applies separate encrypted-blob and count limits.

## Advanced Sessions

Advanced routing is selected only by `X-XFerry-Advanced-Session`. A session is
immutable and stored in a per-server in-memory store. It binds a prefix,
decoder, diagnostics flag, and owner. Sessions have a 60-minute absolute
lifetime, 15-minute idle timeout, and server capacity of 64.

Authentication, direct-peer, browser-origin, token, prefix, and method checks
run before Advanced parsing. The canonical carriers are body, header, query,
cookie, and path. A matching session accepts the four upload methods and a
syntactically valid unregistered method; a registered non-upload method
returns a conflict.

## Cryptography

`cryptography` provides AES-GCM, ECDH, X.509 parsing, and self-signed
certificate generation. `acme` and `josepy` provide built-in HTTP-01 issuance.
These are runtime dependencies. Unsupported crypto operations fail closed.

Secure Notepad performs ECDH in the client flow and stores encrypted blobs on
the server. The server does not store durable client recovery material.

## Configuration and extensions

`ServerSettings` resolves built-in defaults, preset defaults, INI values,
`XFERRY_*` environment variables, and CLI flags. Explicit values override
presets. `RuntimePosture` produces the redacted configuration and validates
public-direct requirements.

Plugins are loaded only when explicitly configured. Core methods are reserved
unless the operator enables core override, and public-direct rejects plugins
unless they are explicitly allowed. Advanced Session creation also rejects a
plugin conflict with `POST`, `PUT`, `PATCH`, or `NONE`.

## Browser UI

The bundled UI uses classic same-origin JavaScript without a build step.
`window.XferryApp` is its only intentional application global. The UI consumes
the same HTTP and WebSocket API as curl and other clients. See the
[frontend contract](frontend-contract.md).
