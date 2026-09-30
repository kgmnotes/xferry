# ADR-011: Client-encrypted streaming transfers

- **Status:** accepted

## Context

Browser users need to transfer large files without whole-file buffers or
making plaintext storage the server default. Interrupted uploads must resume
without trusting a same-sized replacement file, filenames must remain private,
and existing Basic and Advanced upload behavior must not change.

One authenticated encryption operation over a complete file cannot meet the
browser memory and resumability requirements. Keeping a password-derived key
on the server would make recovery convenient, but would also make server or
backup compromise sufficient to decrypt every retained file.

## Decision

Adopt the versioned EUF v1 format with independent AES-256-GCM content chunks,
an encrypted metadata record, and a password-derived resume key. Use fixed
8 MiB plaintext chunks and browser upload parallelism of two. Bind file ID,
size, chunk geometry, index, and plaintext length into authenticated data, and
use keyed resume MACs to compare previously encrypted chunks with a reselected
local file. Before first encrypting a content chunk, durably commit its
plaintext HMAC to an IndexedDB nonce journal. This covers a lost acknowledgement:
the server may have received ciphertext even when the browser did not record
success. Preserve the original encrypted manifest and validate every journaled
and acknowledged chunk before reuse. A missing journal, including a legacy
incomplete session without one, requires a new ID and keys; retain the old
partial until explicit deletion or configured expiry.

Keep the feature disabled by default behind `encrypted_uploads`. Store
ciphertext in a hidden, quota-accounted upload directory and crash-recoverable
state in a permission-restricted runtime directory. Ordinary file APIs do not
cross this boundary. Persist only non-secret progress in the browser; require
the file and password again after reload.

Use remaining shared quota and disk headroom as the default upload limit,
including ciphertext tags and promised space for sparse partials. An operator
can configure a lower per-file ceiling; zero selects automatic admission.
Bound v1 recovery to 4096 chunks / 32 GiB so per-file journals remain safely
within the existing 1 MiB sidecar read limit. Keep the seven-field PING capability
shape and v1 cryptographic bytes unchanged; expose capacity as an additive
`storage` object on the partial-list envelope. A snapshot is not a reservation.

Browser-side streaming decryption is the default download path. Add a completed
file's ciphertext-chunk GET route while retaining concatenated EUF v1 downloads.
Authenticate ciphertext chunks before placing them in private OPFS storage;
persist no password, key, plaintext metadata or file bytes. After reopening,
require the password and destination again, verify cached chunks, fetch missing
chunks, and reconstruct the plaintext output locally. Delete recovery cache
after successful output closure or manual clearing; remove inactive caches
older than seven days at the next application open. A closed site cannot
guarantee background cleanup. Server partial retention is independent and
configured by the operator; completed files require explicit deletion.

Offer optional
one-shot server-side decryption only after explicit confirmation and only over
effective TLS or direct loopback. That request carries `K_content`, never the
password or `K_resume`; the server streams the response and neither persists
the key nor creates a plaintext file.

## Consequences

- Password loss is permanent; the server cannot provide recovery.
- File size, timing, IDs, and chunk progress remain visible to the server even
  though filename, content type, modification time, and file bytes are private.
- Each stored content chunk costs a 16-byte tag; hidden partial reservations
  count against shared upload quotas before data arrives.
- Resume verifies every previously encrypted local chunk, including lost
  acknowledgements, before sending new data and may reread a large prefix
  after reload. Loss of the durable journal forbids reusing the old session.
- Resumable downloads need approximately one extra file's size of browser
  storage. Storage eviction can require fetching previously cached chunks;
  authenticated ciphertext may remain while the site is closed.
- A browser compromise can read passwords and plaintext. Confirmed server-side
  decryption intentionally extends trust to the server and TLS path for one
  response.
- Protocol changes require a new version rather than reinterpretation of EUF
  v1 bytes.
