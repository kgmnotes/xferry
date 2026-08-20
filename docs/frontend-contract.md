# Frontend contract

The bundled UI is a no-build vanilla JavaScript application. Its only
intentional application global is `window.XferryApp`, created by
`static/ui/bootstrap.js`. Workflow files use private closures and register
commands and redacted state through that namespace.

## Load order

1. `bootstrap.js` creates the namespace, event bus, DOM contract, and
   registries.
2. `core.js`, `dialogs.js`, and `inspector.js` register shared services.
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

## Rendering and privacy

- Build user-controlled file and note lists with DOM APIs and `textContent`.
- Pass technical request and response output through inspector redaction before
  storing, copying, or downloading it.
- Expose only status and counts in workflow snapshots.
- Keep session IDs, derived keys, note bodies, filenames, and note titles out
  of diagnostic state.
- Never place Advanced tokens, payload keys, HMAC values, plaintext, or
  ciphertext in logs, DOM attributes, storage, cookies, or URLs.
- Keep sequence guards on asynchronous list and load operations so stale
  responses cannot replace newer state.
