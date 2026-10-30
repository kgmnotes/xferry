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

### Complete a gateway check and share the result

For example, check how your gateway handles a small text file and the HTTP
methods exposed by xferry:

1. Use a dedicated test files folder. In **Upload**, send a small, non-sensitive
   text file, note the returned path, and download it once to verify its contents.
2. Open xferry from the client and network path that passes through the gateway
   under test. In **Requests**, enter the saved file path and run `GET` or `HEAD`
   to inspect that resource.
3. Open **Technical requests** and select **Run all**. This uses prepared paths
   for the method matrix, rather than applying the path field to every method.
   Some checks create unique demonstration files; `DELETE` deletes only its
   newly prepared demo file.
4. Inspect the expected and actual status and the response body. A matching
   status confirms the HTTP scenario's expectation, not compliance with your
   gateway policy. A network failure alone does not prove the gateway blocked
   the request. Record your intended policy outcome separately.
5. To shorten a run, select **Stop after current check**. The current scenario,
   including any preparation and primary request, finishes before the run stops.
   A slow request may still wait for its timeout. Completed actions are not
   undone; unstarted methods are listed as not run, not as failures.
6. Select **Only issues** to inspect completed failures. **Rerun issues** retries
   those rows and retains their attempt history; it can also be stopped after
   the current check. Unretried rows keep their previous results. A new **Run
   all** starts a fresh matrix.
7. Select **Export JSON** after completion or stopping. A partial report retains
   completed results, identifies unrun methods, and records the progress of the
   last full run or issue rerun. Copy or download the relevant HTTP details from
   the request/response inspector when supporting evidence is useful. Review
   paths and response content before sharing them.
8. Download reports before reloading the page: the matrix and attempt history
   are held in this page's memory. In **Download**, remove only the demo files
   you no longer need; **Clear files folder** also removes unrelated shared files.

To compare direct access with access through the gateway, repeat the check from
each network path and give the two exported reports descriptive filenames. The
interface does not automatically compare separate runs or save reusable scenarios.

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
