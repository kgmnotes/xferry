# Encrypted Streaming Uploads v1 Design

## Goal

XFerry can upload and download files up to 2048 MiB from Chrome/Edge with
bounded memory, resumable encrypted chunks, encrypted filenames, and no
server-side key knowledge by default. The feature is part of the general
distribution, is disabled by default, and does not change Basic or Advanced
upload contracts.

## Browser protocol

- The browser generates a 16-byte file ID, rendered as 32 lowercase hex, a
  16-byte PBKDF2 salt, and an 8-byte AES-GCM nonce prefix.
- Passwords contain at least 14 Unicode code points and at most 1024 UTF-8
  bytes. They are encoded exactly as entered, without trimming or Unicode
  normalization.
- PBKDF2-HMAC-SHA256 with 600,000 iterations derives a 32-byte master key.
  HKDF-SHA256, salted with the file ID bytes, derives `K_content` with info
  `xferry-euf-v1/content` and `K_resume` with info
  `xferry-euf-v1/resume`.
- File data is split into fixed 8 MiB plaintext chunks. AES-256-GCM uses the
  8-byte nonce prefix followed by the big-endian 32-bit chunk index. Index
  `0xffffffff` is reserved for metadata.
- Metadata is exact JSON containing `name`, `content_type`, and
  `last_modified_ms`; its UTF-8 representation is capped at 4096 bytes.
- Metadata AAD is `XFERRY-EUF1-META\0`, file ID bytes, plaintext size (u64),
  chunk size (u32), and chunk count (u32), all integers big-endian.
- Chunk AAD is `XFERRY-EUF1-CHUNK\0`, file ID bytes, plaintext size (u64),
  chunk size (u32), chunk count (u32), chunk index (u32), and chunk plaintext
  length (u32), all integers big-endian.
- Each chunk resume token is HMAC-SHA256 over
  `XFERRY-EUF1-RESUME\0 || file_id || index || length || plaintext`, using
  `K_resume`. Binary values in JSON and headers use unpadded base64url.
- At most two chunks from one file are uploaded concurrently. No whole-file
  `arrayBuffer()` is permitted.

## HTTP surface

The reserved same-origin namespace is `/_xferry/encrypted-*`:

- `GET /_xferry/encrypted-uploads`
- `PUT|GET|DELETE /_xferry/encrypted-uploads/{id}`
- `PUT /_xferry/encrypted-uploads/{id}/chunks/{index}`
- `POST /_xferry/encrypted-uploads/{id}/complete`
- `GET /_xferry/encrypted-files`
- `GET|DELETE /_xferry/encrypted-files/{id}`
- `GET /_xferry/encrypted-files/{id}/data`
- `POST /_xferry/encrypted-files/{id}/decrypt`

Create requests carry version, sizes, PBKDF2 salt, nonce prefix, and encrypted
metadata. Chunk requests have a raw octet-stream body and one
`X-XFerry-Chunk-MAC` header. Identical create/chunk/complete retries are
idempotent; conflicting bytes or metadata return 409.

The decrypt endpoint accepts a 32-byte base64url `K_content` in a JSON body,
validates encrypted metadata before sending headers, and streams plaintext
without creating a plaintext file. It is allowed only for effective HTTPS or
direct loopback and never persists or logs the key.

When enabled, `PING.encrypted_uploads` reports version 1, effective maximum
size, the fixed chunk size, parallelism 2, and the browser/server decryption
capabilities. When disabled, the UI is hidden and all reserved routes return
the ordinary 404 envelope.

## Persistence and safety

Ciphertext lives under `uploads/.xferry-encrypted/` as `{id}.part` and
`{id}.xfr`; state sidecars live in a permission-restricted directory beneath
the runtime root. Partial data counts toward the ordinary upload byte/file
quota. Creation reserves the declared ciphertext length. A chunk is
acknowledged only after data and atomic state updates are durable.

State transitions are `partial -> committing -> complete`. Startup reconciles
interrupted commits. Partial uploads expire after 86,400 seconds of inactivity;
completed files remain until explicitly deleted. Ordinary upload listing,
download, deletion, and clear operations cannot expose or remove the hidden
encrypted store.

## UI and compatibility

The existing upload screen gains a separate large-encrypted mode gated by the
PING capability. IndexedDB stores only non-secret IDs and progress. Resuming
requires reselecting the file and re-entering the password, then recomputing
resume HMACs for acknowledged chunks.

Chrome/Edge download decrypts one chunk at a time and writes through the File
System Access API. Integrity or network failure aborts the writable stream.
The optional server-decrypt action has a confirmation and sends only
`K_content`. Existing Basic upload, Advanced/OpSec, file, and note behavior is
unchanged.

## Configuration defaults

- `[server] encrypted_uploads = false` / `--encrypted-uploads`
- `[limits] encrypted_upload_max_size_mb = 2048`
- `[limits] encrypted_upload_incomplete_ttl_seconds = 86400`
- Fixed chunk size: 8 MiB
- Fixed browser parallelism: 2 chunks
