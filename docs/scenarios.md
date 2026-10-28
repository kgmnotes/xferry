# Scenarios

## Transfer files

Use **Upload** to send files and **Download** to browse, inspect, download or
delete them. The files folder includes both uploads and files placed there by
other means. **Clear files folder** deletes all its files and subfolders,
including manually added files; hidden service files are preserved.

Upload supports Multipart, Raw URL, Raw Header, and No filename profiles,
with selectable method, path and MIME. No filename sends raw bytes to `/` and
lets the server generate a name. Each send can create a file and trigger gateway
inspection. See the [API](api.md) for exact request shapes.

## Exercise HTTP methods

**Requests** runs prepared method scenarios and displays the status, headers and
body. It lists methods advertised by `PING.supported_methods`.

- `GET`, `HEAD`, and `INFO` use the path field.
- `POST`, `PUT`, `PATCH`, and `NONE` send a small generated text file with a unique name.
- `DELETE` first creates a demo file, then deletes that new file.
- `FETCH` and `SMUGGLE` prepare a new demo file for their scenario.
- `PING` and `OPTIONS` target `/`; `NOTE` targets `/notes/key`.

The path field is not an arbitrary request-body editor. For custom bodies,
headers and automation, use curl or another HTTP client with the [API reference](api.md).
Demo preparation does not delete pre-existing files. Successful upload responses
provide the actual saved path, including any server-side collision rename.

## Test Advanced routing

**Advanced** creates an Advanced Session with an immutable path prefix, decoder,
and optional diagnostics. Its bearer token can route a documented carrier or
an unregistered method such as `SYNCDATA` to an upload. Payload protection is
explicit: `none`, XOR, or AES-256-GCM. See [Advanced Sessions](api.md#advanced-sessions-upload).

## Exchange an encrypted note

**Notepad** encrypts content in the browser and stores ciphertext on the server.
The server does not retain the client-derived key. Losing the browser session
key means the old note cannot be recovered from server storage.

## Generate a transport artifact

`SMUGGLE` wraps an uploaded file in a temporary same-origin HTML, SVG, or XML
artifact. Its URL is one-shot and can be consumed by a scanner, preloader, or
`HEAD` request before the intended user opens it.

## Provide temporary access

Use a loopback server behind a [disposable SSH tunnel](disposable-ssh-tunnel.md)
for a short demonstration, or follow [Public deployment](public-direct.md) for
a persistent server on an untrusted network.
