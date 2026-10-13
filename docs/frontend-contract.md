# Frontend contract

The bundled UI is a no-build vanilla JavaScript application. Its only
intentional application global is `window.XferryApp`, created by
`static/ui/bootstrap.js`. Workflow files use private closures and register
commands and redacted state through that namespace.

## Load order

1. `bootstrap.js` creates the namespace, event bus, DOM contract, and
   registries.
2. `core.js`, `notifications.js`, `dialogs.js`, and `inspector.js` register shared services.
3. `upload.js` and `requests.js` register the ordinary request workflows.
   `encrypted-transfer-crypto.js` then registers EUF v1 primitives,
   `encrypted-transfer-persistence.js` and `encrypted-transfer-network.js`
   register recovery storage and bounded retry transport, and
   `encrypted-transfer.js` registers the capability-gated large-file workflow.
   `files.js`, `opsec.js`, and `notepad.js` register the remaining workflows.
4. `app.js` initializes discovery and shortcuts, then emits `app.ready`.

No Node.js runtime, package manager, bundler, or generated frontend artifact
is required.

## Public surface

`XferryApp.describe()` lists registered services, workflow commands, events,
and semantic DOM keys. The supported namespace methods are `service`,
`invoke`, `getState`, `on`, `emit`, `element`, `describe`, and
`unexpectedGlobals`.

Workflow groups are `upload`, `requests`, `encrypted-transfer`, `files`,
`advanced`, and `notepad`.
Ordinary production workflows use the shared `http.request` service. Its
test-only adapter controls allow deterministic browser regression tests without
adding writable globals. Encrypted transfers use their own bounded, cancellable
retry transport to report byte progress and recover from interrupted requests.

The Upload workflow keeps `compare` as the profile-comparison command and
registers `compare-methods` for method comparison. Both commands are
mutating, confirmed workflows: they send the selected file sequentially and
create one server-side file per comparison case. They are not dry runs.

The Advanced workflow uses the public session endpoints and the
`X-XFerry-Advanced-Session` header. The token remains in closure memory and
transient request headers. There is no UI-only Advanced API.

## Encrypted transfer workflow

The Large files tab remains hidden until `PING.encrypted_uploads` has the exact
supported v1 capability shape. Missing, disabled, unavailable, or additive
unknown capability data fails closed. Uploads read only 8 MiB `File.slice()`
regions and run at most two chunks concurrently; a whole-file `arrayBuffer()`
is outside the contract.

The partial-list response may add `storage` capacity metadata without changing
the strict PING capability shape. Render available ciphertext storage, remaining
file slots and the effective plaintext file limit. Before queue key derivation,
refresh capacity and check aggregate ciphertext bytes (16 tag bytes per chunk)
and file count. Older servers without `storage` retain their advertised per-file
limit and server-side admission. Snapshots are advisory; atomic server admission
is authoritative and quota errors have localized explanations.
Collection responses are bounded at 32 MiB to accommodate 4096 records with
maximum-size encrypted metadata under the private-service 24 GiB quota;
individual JSON responses retain the 16 MiB bound. Much larger operator quotas
or record counts need a paginated API rather than removing response bounds.

The Web Crypto module derives `K_content` and `K_resume` in its private
closure. Workflow state exposes only phase, IDs, counts, progress, and
decrypted presentation metadata after an explicit unlock. IndexedDB may retain
the original encrypted manifest, public EUF values (including salts, nonce
prefixes, encrypted metadata and MACs), chunk indexes, non-secret status and
timestamps. It never stores passwords, keys, plaintext filenames or plaintext
file bytes. Before first encrypting a chunk it commits that chunk's plaintext
HMAC to a durable nonce journal and waits for transaction completion. A reload
requires the original file and password again; the workflow authenticates
metadata and every journaled and acknowledged resume MAC before reusing a
nonce. If a journal is missing, including a legacy incomplete upload, it offers
a new ID and keys and retains the old partial until deletion or expiry.

Each upload/download has its own phase and progress. Uploads read at most
two chunks concurrently and the queue runs files sequentially. Transient
network/408/429/5xx failures use capped, jittered exponential retry with
`Retry-After`; 30 seconds without network progress triggers recovery. Pause and
cancel wait for pending requests to settle. A cancellation that cannot reach
the server remains visibly pending deletion. A per-session cross-tab lock
prevents simultaneous transfer writes.

Client download fetches the ciphertext chunk API and authenticates one chunk at a
time, retains only verified ciphertext in Origin Private File System (OPFS)
storage, and writes plaintext through the File System Access API. Recovery after
reload re-enters the password and chooses an output location, verifies cached
chunks and fetches missing chunks. Network or filesystem failure aborts the
writable stream while retaining verified ciphertext for retry. A tag failure
does not publish an output file or retain the rejected chunk. `K_content` stays
in memory and does not enter inspector state, URLs, headers, browser storage,
or the server.

The interface shows transfer phase, percentage, bytes, speed and estimated time,
with separate network, verification, writing and final saving states. Success
requires the output stream to close. Download cache requires roughly one
additional file's size of local storage; quota failure is a recoverable pause.
Delete the cache after successful output closure or explicit manual clearing.
Remove inactive entries older than seven days on next application open; cleanup
while the site is closed is not guaranteed. Cache cleanup never deletes the
server's completed file. Desktop Chrome/Edge with the necessary file APIs is
the supported browser environment; unavailable APIs receive an actionable
compatibility explanation.

The separately confirmed server-decrypt action is the only exception: after
the user selects an output file it POSTs exactly one `content_key` JSON field,
then streams the plaintext response to that writable. The inspector treats
`content_key` as a secret. Refreshing the encrypted-file list clears unlocked
keys from the workflow closure.

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

The visible file queue is the selection summary; the duplicate selected-file
count remains screen-reader-only. On desktop the Send button is placed beside
the file drop zone at the same height, while narrow screens stack a compact
button below it. Profile and method comparison controls remain implemented but
are hidden from the default Upload interface.

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
- Never place Advanced tokens, payload keys, plaintext, or ciphertext in logs,
  DOM attributes, cookies, or URLs. Encrypted-transfer journals and ciphertext
  caches use only the explicitly permitted browser storage described above;
  they never retain passwords, keys, plaintext names or plaintext bytes.
- Keep sequence guards on asynchronous list and load operations so stale
  responses cannot replace newer state.
