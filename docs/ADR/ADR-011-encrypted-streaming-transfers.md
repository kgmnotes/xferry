# ADR-011: Client-encrypted streaming transfers

- **Status:** accepted

## Context

Browser users need to transfer files up to 2 GiB without whole-file buffers or
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
use keyed resume MACs to compare acknowledged chunks with a reselected local
file.

Keep the feature disabled by default behind `encrypted_uploads`. Store
ciphertext in a hidden, quota-accounted upload directory and crash-recoverable
state in a permission-restricted runtime directory. Ordinary file APIs do not
cross this boundary. Persist only non-secret progress in the browser; require
the file and password again after reload.

Browser-side streaming decryption is the default download path. Offer optional
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
- Resume verifies every acknowledged local chunk before sending new data and
  may reread a large prefix after reload.
- A browser compromise can read passwords and plaintext. Confirmed server-side
  decryption intentionally extends trust to the server and TLS path for one
  response.
- Protocol changes require a new version rather than reinterpretation of EUF
  v1 bytes.
