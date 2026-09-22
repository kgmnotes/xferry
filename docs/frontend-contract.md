# Frontend contract

The bundled UI is a no-build vanilla JavaScript application. Its only
intentional application global is `window.XferryApp`, created by
`static/ui/bootstrap.js`. Workflow files use private closures and register
commands and redacted state through that namespace.

## Load order

1. `bootstrap.js` creates the namespace, event bus, DOM contract, and
   registries.
2. `core.js`, `notifications.js`, `dialogs.js`, and `inspector.js` register shared services.
3. `upload.js`, `requests.js`, `files.js`, `opsec.js`, and `notepad.js`
   register workflows.
4. `app.js` initializes discovery and shortcuts, then emits `app.ready`.

No Node.js runtime, package manager, bundler, or generated frontend artifact
is required.

## Public surface

`XferryApp.describe()` lists registered services, workflow commands, events,
and semantic DOM keys. The supported namespace methods are `service`,
`invoke`, `getState`, `on`, `emit`, `element`, `describe`, and
`unexpectedGlobals`.

Workflow groups are `upload`, `requests`, `files`, `advanced`, and `notepad`.
Production workflows use the shared `http.request` service. Its test-only
adapter controls allow deterministic browser regression tests without adding
writable globals.

The Upload workflow keeps `compare` as the profile-comparison command and
registers `compare-methods` for method comparison. Both commands are
mutating, confirmed workflows: they send the selected file sequentially and
create one server-side file per comparison case. They are not dry runs.

The Advanced workflow uses the public session endpoints and the
`X-XFerry-Advanced-Session` header. The token remains in closure memory and
transient request headers. There is no UI-only Advanced API.

## Events and DOM

The closed event set is `locale.changed`, `server.methods.changed`,
`workspace.changed`, and `app.ready`. Unknown events, duplicate registrations,
and unknown commands fail explicitly.

Cross-module code resolves elements through semantic keys in `XferryApp.dom`.
Workflow-local selectors may stay private. A new cross-workflow selector needs
a semantic key and a static contract test.

## Upload feedback

The Upload tab keeps **Technical details** at the bottom of the main content
flow. It remains discoverable before a file is selected and updates the raw
request preview as the method, request profile, declared MIME, or file changes.
Bounded body samples do not replace the file's full size in `Content-Length`
or omitted-byte reporting, and Multipart previews use the effective MIME that
the browser serializes for the file part.
On desktop it may open once for the first ready request without moving focus or
scroll position; mobile starts collapsed, and a user's explicit open/closed
choice wins over later live updates.

After one successful upload, the existing inline status shows the HTTP status,
canonical saved server path, and response-reported size. A multi-file result
shows aggregate success/error counts and clears the single-file metadata. The
status stays beside the Technical details entry point; there is no standalone
result card or corner notification.

## Rendering and privacy

- Build user-controlled file and note lists with DOM APIs and `textContent`.
- Pass technical request and response output through inspector redaction before
  storing, copying, or downloading it.
- Expose only status and counts in workflow snapshots. In particular, Upload
  status metadata may be rendered locally but filenames and saved paths must
  not be returned by `getState()`.
- Keep session IDs, derived keys, note bodies, filenames, and note titles out
  of diagnostic state.
- Never place Advanced tokens, payload keys, HMAC values, plaintext, or
  ciphertext in logs, DOM attributes, storage, cookies, or URLs.
- Keep sequence guards on asynchronous list and load operations so stale
  responses cannot replace newer state.
