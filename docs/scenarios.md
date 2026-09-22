# Scenarios

## Transfer a file

Use **Upload** for basic uploads and **Files** to browse, inspect, download, or
delete them. Upload can build Multipart, Raw URL, Raw Header, and No filename
requests and can declare the file-part or raw-body MIME. No filename sends raw
bytes to `/` so the server generates the name; it never sends raw bytes to
`/uploads`.

**Compare profiles** sends one confirmed upload for each of the four request
profiles. **Compare methods** reuses the active request profile with POST,
NONE, PUT, and PATCH. Both comparisons create files on the server and may
trigger gateway inspection; they are mutating tests, not previews or dry runs.

Start here when checking whether a gateway permits ordinary file transfer.

## Exercise HTTP methods

Use **Requests** to send a method and inspect the status, headers, and body.
The server advertises its active core methods through `PING.supported_methods`.

## Test Advanced routing

An Advanced Session binds an immutable path prefix, decoder, and optional
diagnostics to a bearer token. It accepts the documented payload carriers and
can route an unregistered method such as `SYNCDATA` to an upload. Payload mode
is explicit: `none`, XOR, or AES. See [Advanced Sessions](api.md#advanced-sessions-upload).

## Exchange an encrypted note

**Secure Notepad** encrypts content in the browser and stores ciphertext on
the server. The server does not retain the client-derived key. If the browser
session key is lost, the old note cannot be recovered from the data directory.

## Generate a transport artifact

`SMUGGLE` creates a temporary same-origin HTML, SVG, or XML artifact around an
uploaded test file. Its URL is one-shot and may be consumed by a scanner,
preloader, or `HEAD` request before the intended user opens it.

## Provide temporary access

For a short authorized demonstration, use a loopback server behind the
[disposable SSH tunnel](disposable-ssh-tunnel.md). For a service reachable from
an untrusted network, use the [public-direct procedure](public-direct.md).
