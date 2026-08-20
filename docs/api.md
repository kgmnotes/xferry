<!-- Generated from ../API.md by tools/sync_docs.py. Edit API.md and rerun the sync tool. -->

# API Reference

All responses include standard headers: `Server`, `Date`, `Connection`, and
`X-Content-Type-Options: nosniff` (`close` by default, `keep-alive` when the
server keeps the socket open).
CORS headers are only emitted when CORS is explicitly enabled.
XFerry exposes one unversioned HTTP API shipped by the current 0.x line.
Browsers and curl use the same routes, request shapes, success objects, and
error envelope; there is no version prefix, compatibility parser, or alternate
browser response format.

## Contract Stability

The surface described in this document is the HTTP/WebSocket contract shipped
by XFerry 0.x. The server does not implement `/api/v1` endpoints or another
versioned API prefix; clients discover the active method surface with `PING`.

The compatibility promise is intentionally narrow:

- Documented method names, route shapes, filesystem scopes, and stable `PING`
  discovery fields should not be removed or renamed without a release note and
  compatibility guidance.
- `PING` fields `supported_methods`, `plugin_methods`, `access_scope`, and
  `metrics` are the stable discovery mechanism for clients. Treat
  `supported_methods` and `plugin_methods` as sets. The additive
  `method_groups` object is presentation metadata and must not be treated as
  independent capability negotiation.
- Response examples may gain additive JSON fields. Clients should ignore fields
  they do not understand unless this document marks the field as required.
- Application errors use the one error envelope documented below. Exact
  human-readable messages, JSON formatting, and object key order are not a
  compatibility mechanism.
- Generated temporary names, generated request IDs, precise timing values, and
  low-level counter names are operational diagnostics, not a stable client API.
  They may change as long as `PING` discovery remains available.
- Advanced Sessions uploads, `SMUGGLE`, `NOTE`, and WebSocket notes are part of
  the single full method surface.

The built-in browser UI, bundled examples, and operator-owned scripts are
reference consumers of this unversioned surface, not an official SDK or a public
client support program with broader compatibility guarantees.

There is no global idempotency key in the unversioned XFerry 0.x API. Read-only methods (`GET`, `HEAD`,
`FETCH`, `INFO`, `PING`, and `OPTIONS`) are the safest retry targets. Mutating
methods can create, replace, delete, or clear state before a client observes a
timeout. Retrying a mutating request should use a stable filename or note ID
when the endpoint supports one, then confirm final state with `INFO`, `FETCH`,
`NOTE /notes?action=list`, or `NOTE /notes/{id}?action=load`.
`X-Request-Id` is correlation-only, whether supplied by the client or generated
by the server; it is never an idempotency key.

NOTE IDs are exactly 32 lowercase hexadecimal characters. For an idempotent
NOTE create/retry, send a stable `id` with `create_if_missing: true` in either
the HTTP save body or WebSocket save `input`. WebSocket `request_id` correlates
one request and response but is not stored, replayed, or used for deduplication.

Transport-layer failures are distinct from handler responses. Some
receive-layer framing failures close the TCP connection before an HTTP response
exists, and WebSocket protocol failures after a successful upgrade use
WebSocket close frames instead of HTTP JSON bodies. The response-body tables
below apply only when the server emits an HTTP response or an application-level
WebSocket JSON frame.

## Error Response Bodies

Every application error response has exactly this JSON body:

```json
{"error":{"code":"...","message":"...","field":null,"details":{}}}
```

`code` is a stable lowercase snake_case token; `field` is `null` or a string;
and `details` is always an object. The HTTP status appears only on the status
line, never as a JSON field. This envelope applies to browser-origin failures,
uploads, DELETE, INFO, FETCH, PING, SMUGGLE, NOTE HTTP, auth, request guards,
and Advanced session control and data errors. `HEAD` selects the corresponding GET
status and representation headers but sends no body.
The stable shared/global `internal_error` code documents handler failures that return HTTP 500.

Some receive/framing failures occur before an HTTP response exists, including
unsupported `Transfer-Encoding`, conflicting or invalid `Content-Length`, a
declared length over the configured cap, receive timeouts, and a receive hard
cap breach. Those cases may close the connection. After a successful WebSocket
upgrade, protocol failures use WebSocket close frames and the intentional NOTE
WebSocket message shapes remain documented in their separate section.

---

## Full Method Surface

XFerry has one always-on core method surface. The handler registry, exact-origin
CORS preflight, browser UI affordances, and WebSocket notes all use this full
surface by default. Core methods are:

`GET`, `HEAD`, `POST`, `PUT`, `PATCH`, `DELETE`, `OPTIONS`, `FETCH`, `INFO`,
`PING`, `NONE`, `NOTE`, `SMUGGLE`, plus syntactically valid unregistered
methods when an authorized Advanced Session selects the upload route.

Wildcard CORS remains read-only and lists only read methods; exact CORS origins
can receive the full method list and can echo a requested unknown advanced
upload method when the method token is valid.

---

## Request Framing and Caps

The receive layer enforces protocol framing before handler dispatch:

- Request headers are capped by `--max-header-size KB` (`64` KiB by default)
  before the terminating blank line.
- Request bodies are capped by `--max-size MB` (`100` MiB by default) using the
  declared `Content-Length` and the bytes actually read.
- Concurrent in-flight request bodies are reserved against
  `--body-memory-budget MB`. The default budget is `--workers * --max-size`.
  Aggregate budget exhaustion returns `503` before the remaining body bytes are
  read.
- Active WebSocket upgrades are capped by `--max-websocket-connections N`.
  The default is `--workers // 2`; `0` rejects all WebSocket admissions with
  `503`.
- Incomplete WebSocket frames are capped by
  `--websocket-frame-idle-timeout SECONDS` (`5` seconds by default). Timeout
  failures close the WebSocket with protocol close code `1002`.
- Aggregate disk usage under `uploads/` is controlled separately with optional
  `--upload-storage-limit MB`, `--upload-file-limit N`, and
  `--upload-reserve-free MB` limits. A value of `0` disables each aggregate
  limit.
- Encrypted Notepad blobs under `notes/` are capped by
  `--note-storage-limit MB` and `--note-count-limit N` (`256` MiB and `1000`
  notes by default). A value of `0` disables each aggregate Notepad limit.
- Generated one-shot SMUGGLE pages are retained under `uploads/` only within
  `--smuggle-temp-age SECONDS`, `--smuggle-temp-file-limit N`, and
  `--smuggle-temp-storage-limit MB` (`3600` seconds, `32` files, and `128` MiB
  by default). A value of `0` disables the corresponding retention limit.
- `Transfer-Encoding` is unsupported and rejected at the receive layer because
  the server does not decode chunked request bodies.
- Invalid, negative, or conflicting duplicate `Content-Length` values are
  rejected. Duplicate identical `Content-Length` values are accepted.
- Receive-layer framing failures may close the connection before an HTTP error
  response is built, except aggregate body-memory budget exhaustion, which
  returns a JSON `503`. Rejections are counted under `metrics.receive`.

---

## GET

Serve the bundled web UI, bundled static assets, and user files from `uploads/`.

**Request:**
```
GET /uploads/path/to/file HTTP/1.1
```

`GET /` and `GET /index.html` serve the built-in UI. `GET /static/...` serves
the built-in UI assets. Other file paths are resolved inside `uploads/`;
`/file.txt` and `/uploads/file.txt` both target `<root>/uploads/file.txt`.

**Response:** File contents with appropriate `Content-Type`. Bundled HTML files
include `Content-Security-Policy`; uploaded HTML/SVG files are forced to
download as attachments.

The bundled UI CSP currently includes `default-src 'self'`, `script-src
'self'`, `style-src 'self' 'unsafe-inline'`, `img-src 'self' data:`,
`connect-src 'self' ws: wss:`, `base-uri 'self'`, `object-src 'none'`,
`frame-ancestors 'none'`, and `form-action 'self'`. Inline scripts are blocked.
The remaining inline style allowance is limited to current UI progress widgets.

**Status codes:** `200` OK, `304` Not Modified (if ETag matches), `404` Not Found

---

## HEAD

Returns the same headers as GET but with no response body. Useful for checking file existence and metadata without transferring content.

**Request:**
```
HEAD /uploads/path/to/file HTTP/1.1
```

**Response:** Same status code and headers as GET (200 or 404), empty body.

**Status codes:** `200` OK, `304` Not Modified (if ETag matches), `404` Not Found

---

## Basic Upload: POST / PUT / PATCH / NONE

All four methods use the same Basic handler unless an authorized matching
`X-XFerry-Advanced-Session` selects Advanced dispatch. Basic has three exact
wire profiles:

| Profile | Request target | Body/headers | Filename source |
|---------|----------------|--------------|-----------------|
| **Multipart (default)** | `/uploads` | The browser UI sends one `FormData` file part using field `file`; the server accepts any non-empty file-part field name. The browser owns the multipart boundary and `Content-Length`. | `X-File-Name`, then part `filename`, then URL, then generated |
| **Raw URL** | `/uploads/<encoded-name>` | Original file bytes, no `X-File-Name` | URL |
| **Raw Header** | `/uploads` | Original bytes, `Content-Type: application/octet-stream`, URL-encoded `X-File-Name` | header |

Example Raw Header request:

```http
POST /uploads HTTP/1.1
Content-Type: application/octet-stream
X-File-Name: myfile.txt
Content-Length: 1234

<file bytes>
```

Filename precedence is `X-File-Name` > multipart file-part `filename` > URL
path > generated timestamp name. The `/uploads` collection special case
applies only to multipart: a raw request to `/uploads` without
`X-File-Name` saves a literal filename `uploads`. `X-File-Name` values are
URL-decoded and sanitized before publication. A multipart part `filename` is
parsed and sanitized but is not URL-decoded by XFerry. Collisions receive a
safe suffix.

For Basic multipart, scalar form fields are ignored. The request must contain
exactly one top-level file part with a non-empty payload. Zero or multiple file
parts, an empty file payload, nested multipart parts, malformed boundaries or
part headers, and duplicate singleton MIME part headers (`Content-Disposition`,
`Content-Type`, or `Content-Transfer-Encoding`) are rejected with `400`.
`Content-Transfer-Encoding` may be absent or use `binary` / `8bit`
case-insensitively. Unsupported encodings are rejected and are never decoded.

**Response (201):**
```json
{
  "file": {
    "name": "myfile.txt",
    "path": "/uploads/myfile.txt",
    "size_bytes": 1234,
    "size_human": "1.2 KB",
    "content_type": "text/plain",
    "uploaded_at": "2026-08-14T00:00:00+00:00",
    "sha256": "<64 lowercase hex>"
  },
  "upload": {
    "kind": "basic",
    "profile": "raw_header",
    "carrier": "body",
    "filename_source": "header",
    "normalized_name": "myfile.txt",
    "collision_renamed": false,
    "request_body_size": 1234,
    "payload_size": 1234
  }
}
```

The `file` and `upload` objects are the canonical response. The SHA-256 digest
is over final payload bytes, not a multipart envelope. Clients consume this
JSON; dispatch, routing source/revision, carrier/profile mirrors, and hashes
are not top-level response fields or optional response mirrors.

**Status codes:** `201` Created, `400` No data, `413` Payload too large, `500` Server error

---

## DELETE

Delete a file from `uploads/`. Only files inside `uploads/` can be deleted.
To clear the upload workspace, use the explicit clear flag; plain
`DELETE /uploads` still rejects directory deletion.

**Request:**
```
DELETE /uploads/filename.txt HTTP/1.1
```

**Response (200):**
```json
{
  "deleted_file": {
    "name": "filename.txt",
    "path": "/uploads/filename.txt"
  }
}
```

**Clear uploads request:**
```
DELETE /uploads?clear=true HTTP/1.1
```

**Clear uploads response (200):**
```json
{
  "cleared_uploads": {
    "path": "/uploads",
    "deleted_files": 3,
    "deleted_dirs": 1,
    "preserved": [".gitkeep"]
  }
}
```

Hidden service files such as `.gitkeep` are preserved. Current notepad storage
lives in the separate top-level `notes/` directory; `uploads/notes/` is treated
as ordinary upload content.

**Status codes:** `200` OK, `403` Outside uploads/, `404` Not Found, `400` Cannot delete directory

---

## FETCH

Download a file with `Content-Disposition: attachment`.

**Request:**
```
FETCH /uploads/file.txt HTTP/1.1
```

**Response:** File contents with download headers.

**Headers:** `Content-Disposition`

**Status codes:** `200` OK, `404` Not Found

---

## INFO

Directory listing as JSON. Supports pagination via query parameters. Paths are
always resolved inside `uploads/`; `/` and `/uploads/` both describe the upload
workspace.

**Request:**
```
INFO /uploads/?offset=0&limit=100 HTTP/1.1
```

**Query parameters:**
- `offset` (default: 0): skip the first N items.
- `limit` (default: 100, max: 1000): return at most this many items.
- `inspect=true`: opt in to bounded content inspection metadata.
- `inspect=false`: preserve the default response shape without
  content inspection. Omitting `inspect` has the same effect; other values are
  rejected.

**Response (200):**
```json
{
  "entry": {
    "exists": true,
    "path": "/uploads",
    "name": "uploads",
    "kind": "directory",
    "size_bytes": 4096,
    "size_human": "4.0 KB",
    "content_type": "unknown",
    "created_at": "2026-08-14T00:00:00+00:00",
    "modified_at": "2026-08-14T00:00:00+00:00",
    "extension": "",
    "access_scope": "uploads",
    "inspection": null
  },
  "page": {
    "offset": 0,
    "limit": 100,
    "total_items": 42,
    "returned_items": 1
  },
  "contents": [
    {
      "name": "file.txt",
      "kind": "file",
      "inspection": null
    }
  ]
}
```

Every INFO response has an `entry`; directory responses additionally have
`page` and `contents`. Each `contents` item has `name`, `kind`, and
`inspection`; request INFO for a specific child path for its complete entry.

### Optional content inspection

Request inspection explicitly, for example:

```http
INFO /uploads/report.pdf?inspect=true HTTP/1.1
```

The response then gains this additive `inspection` object for an individual
file (or for eligible file entries in a directory listing):

```json
{
  "inspection": {
    "mime_type": "application/pdf",
    "mime_source": "signature",
    "content_state": "recognized",
    "warning": null,
    "reasons": []
  }
}
```

`mime_source` is one of `signature`, `text`, `extension`, or `unknown`.
`content_state` is `recognized`, `opaque`, or `unknown`. `warning` is `null`,
`possible_encrypted_or_packed`, or `extension_mismatch`. `reasons` may contain
`encrypted_suffix`, `extension_mismatch`, `unrecognized_binary`,
`insufficient_data`, or `unavailable`.

Inspection is heuristic metadata, not a security verdict: no numeric
probability or entropy score is reported, and an opaque file never proves XOR
encryption. A `.enc` or `.xor` suffix is only a reason. Password-protected
ZIP-family or other container files are identified only by their outer format,
not as proof of their contents or encryption.

The server reads at most 65,536 bytes from the file head. For ZIP-family,
PE/SFX, or otherwise opaque candidates it may use a separately bounded,
65,557-byte ZIP-tail sample solely to confirm the outer ZIP format. For a directory
request, it sorts and paginates first, then inspects only regular, non-symlink files
in the visible page; directories and entries outside that page are not inspected.

**Status codes:** `200` OK, `400` Invalid path, `404` Not Found

---

## PING

Health check endpoint.

**Request:**
```
PING / HTTP/1.1
```

**Response (200):**
```json
{
  "health": "ready",
  "server": "XFerry/0.1.0",
  "timestamp": "2026-08-14T00:00:00+00:00",
  "supported_methods": ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "FETCH", "INFO", "PING", "NONE", "NOTE", "SMUGGLE"],
  "method_groups": {
    "request": ["GET", "HEAD", "OPTIONS", "INFO", "PING"],
    "upload": ["POST", "PUT", "PATCH", "NONE"],
    "files": ["DELETE", "FETCH", "SMUGGLE"],
    "notepad": ["NOTE"]
  },
  "plugin_methods": [],
  "access_scope": "uploads",
  "metrics": {
    "uptime_seconds": 3600.5,
    "requests": {
      "total": 150,
      "client_errors": 4,
      "server_errors": 2,
      "status_counts": {"200": 144, "404": 4, "500": 2},
      "latency_ms": {"count": 150, "total": 2450.75, "avg": 16.338, "max": 180.25}
    },
    "connections": {
      "active": 3,
      "accepted": 150,
      "closed": 147
    },
    "receive": {
      "bytes": 1048576,
      "rejections": 2,
      "rejection_reasons": {
        "header_too_large": 1,
        "body_too_large": 1
      }
    },
    "timeouts": {
      "websocket_incomplete_frame": 1
    },
    "request_admission": {
      "active": 2,
      "accepted": 150,
      "rejected": 1
    },
    "response": {
      "bytes": 524288,
      "stream_aborts": 0,
      "stream_abort_reasons": {}
    },
    "websocket": {
      "active": 0,
      "rejected_admissions": 1,
      "closed": 4,
      "protocol_errors": 0,
      "message_too_big": 0,
      "incomplete_frame_timeouts": 1,
      "idle_pings": 3,
      "errors": 0
    },
    "worker": {
      "exceptions": 0,
      "exception_sources": {},
      "last_exception_type": null
    },
    "storage": {
      "usage": {
        "notes": {"bytes": 4096, "items": 2},
        "smuggle_temp": {"bytes": 8192, "items": 1},
        "uploads": {"bytes": 532480, "items": 6}
      },
      "quota_denials": {
        "notes": {"bytes": 0, "notes": 0},
        "smuggle_temp": {"bytes": 0, "files": 0},
        "uploads": {
          "bytes": 1,
          "disk_full": 0,
          "files": 0,
          "free_space": 0
        }
      },
      "scans": {
        "info": {
          "count": 3,
          "items": 18,
          "total_ms": 1.2,
          "avg_ms": 0.4,
          "max_ms": 0.6
        },
        "notepad_listing": {
          "count": 1,
          "items": 2,
          "total_ms": 0.3,
          "avg_ms": 0.3,
          "max_ms": 0.3
        },
        "notepad_usage": {
          "count": 2,
          "items": 3,
          "total_ms": 0.4,
          "avg_ms": 0.2,
          "max_ms": 0.25
        },
        "storage_snapshot": {
          "count": 3,
          "items": 9,
          "total_ms": 0.9,
          "avg_ms": 0.3,
          "max_ms": 0.5
        },
        "upload_quota": {
          "count": 4,
          "items": 20,
          "total_ms": 2.4,
          "avg_ms": 0.6,
          "max_ms": 0.8
        }
      }
    },
    "advanced_upload": {
      "decode_rejections": {
        "crypto_unavailable": 0,
        "decoded_too_large": 1,
        "decrypt_failed": 0,
        "encoded_too_large": 0,
        "hmac_mismatch": 0,
        "invalid_encoding": 1,
        "invalid_key": 0
      }
    }
  }
}
```

`supported_methods` is the availability source of truth for built-in core
methods. `method_groups` is derived presentation metadata for organizing those
methods in clients; it does not enable or disable a feature independently.
Clients should treat `supported_methods` and `plugin_methods` as sets and
ignore unknown additive fields. Plugin methods remain separate and are not
inserted into core groups. Legacy discovery fields `profile`, `capabilities`,
and `advanced_upload` are no longer emitted.

When the core `SMUGGLE` implementation is active, `PING` also includes mandatory
schema-v1 `smuggle_capabilities` for bundled UI clients. Missing, malformed, or
unsupported capability data disables the bundled builder before it prepares demo
uploads or emits SMUGGLE requests. The object is still advisory discovery data,
not an authorization decision; the server enforces the request contract on every
SMUGGLE request. It includes `schema_version=1`, `source_max_bytes`,
`field_limits`, `defaults`, `mode_fields`, `extensions`, `mime_presets`,
`mime_by_extension`, `presets`, `locales`, constructor enum lists,
`trigger_events`, `custom_trigger_methods`, `temp_policy`, and boolean `caps`.
Current defaults, limits, and built-ins are:

- default builder values: `mode=simple`, `preset=direct`, `locale=ru`,
  `encryption=none`, `payload_encoding=base64`, `trigger_method=svg`,
  `trigger_event=onload`, `output_format=html`,
  `download_variant=blob-anchor`, `page_template=default`,
  `mime_type=application/octet-stream`, `delay_ms=0`, `null_byte=false`, and
  `show_notice=true`
- field limits: `download_name` 120 characters, `download_ext` 32 characters,
  `title` 120 characters, `message` 280 characters, `cta_label` 80 characters,
  `delay_ms` `0..10000`, `mime_type` 120 characters, and `trigger_event` 64
  characters
- modes: `simple`, `constructor` (`mode=simple|constructor`)
- mode applicability: `preset`, `cta_label`, and `delay_ms` are simple-only;
  `payload_encoding`, `trigger_method`, `trigger_event`, `output_format`,
  `download_variant`, `page_template`, `mime_type`, and `null_byte` are
  constructor-only
- encryption modes: `none`, `xor`, `aes` (`encryption=none|xor|aes`).
  `none` leaves bytes unchanged and carries no password. `xor` is explicit
  compatibility obfuscation with a password gate, not confidentiality.
  `aes` is password-based AES-256-GCM using the canonical XFerry wire format.
  There is no AES-to-XOR or XOR-to-AES fallback.
- locales: `ru`, `en`
- suggested extracted-file extensions: `txt`, `bin`, `dat`, `zip`, `pdf`;
  `extensions` is a UI suggestion list, not an allowlist or a content-safety
  boundary
- constructor MIME presets cover generic/text (`application/octet-stream`,
  `text/plain`, `text/html`, `text/css`, `text/csv`, `text/javascript`,
  `application/json`, `application/xml`, `application/pdf`), archives
  (`application/zip`, `application/gzip`, `application/x-tar`,
  `application/x-7z-compressed`, `application/vnd.rar`), images/media
  (`image/png`, `image/jpeg`, `image/gif`, `image/webp`, `image/svg+xml`,
  `audio/mpeg`, `video/mp4`), legacy and OOXML Office types
  (`application/msword`, `application/vnd.openxmlformats-officedocument.wordprocessingml.document`,
  `application/vnd.ms-excel`,
  `application/vnd.openxmlformats-officedocument.spreadsheetml.sheet`,
  `application/vnd.ms-powerpoint`,
  `application/vnd.openxmlformats-officedocument.presentationml.presentation`),
  packages/binaries (`application/java-archive`,
  `application/vnd.android.package-archive`, `application/wasm`,
  `application/vnd.microsoft.portable-executable`, `application/x-msi`), and
  scripts (`text/x-python`, `application/x-powershell`, `application/x-sh`)
- `mime_by_extension` supplies matching suggestions for `bin`, `dat`, `txt`,
  `log`, `md`, `csv`, `html`, `htm`, `css`, `js`, `mjs`, `json`, `xml`, `pdf`,
  `zip`, `gz`, `tgz`, compound `tar.gz`, `tar`, `7z`, `rar`, `png`, `jpg`,
  `jpeg`, `gif`, `webp`, `svg`, `mp3`, `mp4`, `doc`, `docx`, `xls`, `xlsx`,
  `ppt`, `pptx`, `jar`, `apk`, `wasm`, `exe`, `dll`, `scr`, `msi`, `py`, `pyw`,
  `ps1`, `psm1`, `psd1`, `sh`, `bash`, and `zsh`
- simple presets: `direct`, `card_manual`, `card_auto`
- payload encodings: `base64`, `base64url`, `base32`, `percent`, `reverse`,
  `xor`, `hex`, `split`, `attrs`, `charcode`
- outer artifact formats: `html`, `htm`, `shtml`, `shtm`, `xhtml`, `xht`,
  `xhtm`, `xml`, `svg` (this expansion adds no output formats)
- page templates: `default`, `minimal`, `corporate`, `drive`,
  `npf-zip-archive-help`
- download variants: `blob-anchor`, `data-uri`, `iframe-blob`, `filereader`,
  `fetch-blob`, `window-open`, `loc-assign`, `form-post`, `timeout-blob`,
  `promise-blob`, `raf-blob`, `microtask-blob`, `observer-blob`,
  `response-blob`, `readable-stream`, `message-channel-blob`,
  `idle-callback-blob`
- trigger map: `svg:onload`; `body:onload,onpageshow`;
  `img:onerror,onload`; `audio:onerror,onloadstart`;
  `video:onerror,onloadstart`; `source:onerror`;
  `input:onfocus,oninput,onchange,onkeydown`;
  `select:onfocus,onchange`;
  `button:onfocus,onclick,onpointerdown,onkeydown`;
  `textarea:onfocus,oninput,onchange,onkeydown`;
  `details:ontoggle,onclick`; `iframe:srcdoc,onload`;
  `animate:onbegin,onend,onrepeat`; `animmotion:onbegin,onend,onrepeat`;
  `set:onbegin,onend`;
  `cssanim:onanimationstart,onanimationend,onanimationiteration`;
  `csstransition:ontransitionrun,ontransitionstart,ontransitionend`;
  `link:onerror,onload`; `script:onerror`; `form:onsubmit`;
  `custom:onfocus`; `focusin:onfocusin`;
  `contentvis:oncontentvisibilityautostatechange`.
  Clients should still prefer the exact `trigger_events` map returned by the
  running server over a hard-coded copy.
- custom trigger eligibility: `custom_trigger_methods` lists the canonical,
  registered element-method tokens that may accept a validated custom event:
  `svg`, `body`, `img`, `audio`, `video`, `source`, `input`, `select`, `button`,
  `textarea`, `details`, `iframe`, `animate`, `animmotion`, `set`, `cssanim`,
  `csstransition`, `link`, `script`, `form`, `custom`, `focusin`, and
  `contentvis`
- capability flags: `one_shot`, `constructor`, `xor_obfuscation`,
  `aes_gcm`, `source_cap_enforced`, `custom_extension`, `custom_mime_type`,
  `custom_trigger_event`, and `searchable_options` are boolean; the current
  built-in implementation reports all nine as `true`

The server owns built-in method name, handler binding, mutation, CORS, UI group,
and exposure metadata in one typed `CoreMethodSpec` registry. Handler
registration, CORS projections, `PING`, and the bundled UI are derived from
that policy to prevent method drift.

`GET /metrics` returns `{"metrics": <same snapshot>}` and sends
`Cache-Control: no-store`. The `PING.metrics` object is that same snapshot.
`requests` contains totals, status/error counts, and `latency_ms`; `receive`
contains request bytes and rejected framing; `response` contains response bytes
and streamed-response aborts. `connections`, `timeouts`, `request_admission`,
`websocket`, and `worker` are independent canonical groups. Worker failures
are counted in `worker`, and accepted WebSocket upgrades are counted in
`websocket`, not in request-response aliases.

`storage.usage` is refreshed with exact filesystem scans when `PING` or
`GET /metrics` builds its snapshot. `uploads` is aggregate regular-file usage
under `uploads/`, including generated SMUGGLE artifacts because they consume
the same volume; `smuggle_temp` is the generated-artifact subset. `notes`
counts encrypted `.enc` blobs and their bytes, not metadata sidecars.

`storage.quota_denials` uses only closed labels: upload byte/file/free-space/
disk-full denials, note byte/count denials, and SMUGGLE temporary byte/file
denials. `advanced_upload.decode_rejections` similarly uses the fixed reasons
shown above. Paths, filenames, note titles, session IDs, methods, encodings,
and exception messages never become metric labels.

`storage.scans` contains cumulative `count`, examined `items`, `total_ms`,
`avg_ms`, and `max_ms` for five fixed scopes: `info`, `upload_quota`,
`notepad_usage`, `notepad_listing`, and `storage_snapshot`. `items` is
cumulative work, not current cardinality. INFO pagination preserves exact
totals and therefore sorts/scans the directory in `O(n)` before slicing the
response. Aggregate upload quota checks and exact usage snapshots are also
`O(n)`; no cache or storage index is maintained. Consequently `PING` and
`GET /metrics` are operational snapshots rather than constant-time probes.
Increase the probe interval, or use a TCP-only liveness probe when process
liveness is sufficient, if storage grows too large for frequent exact scans.

---

## SMUGGLE

Create a temporary same-origin HTML/SVG/XML artifact for a file in `uploads/`.
The SMUGGLE request returns JSON with a temporary URL; clients then open or
download that URL to receive the generated artifact. The source file,
one-shot artifact, and extracted file are three separate things: changing the
download-facing extension or MIME metadata does not convert or validate the
embedded bytes.

**Request:**
```
SMUGGLE /uploads/file.txt HTTP/1.1
```

Encode each path segment before adding SMUGGLE query parameters. A raw `?` or
`#` in an upload filename changes the request path unless the filename segment
is percent-encoded first. For display and follow-up automation, use
`download.name` from the response rather than reimplementing filename
normalization in the client.

**With explicit encryption:**
```
SMUGGLE /uploads/file.txt?mode=simple&encryption=aes HTTP/1.1
```

`encryption=none|xor|aes` is the complete public encryption selector. `none`
stores the original bytes in the generated artifact and carries no password.
`xor` stores an XOR-obfuscated payload and shows a server-generated password
CAPTCHA; this is compatibility obfuscation and a manual password gate, not
confidentiality. `aes` stores the canonical password-based AES-256-GCM wire
payload and the generated page decrypts it with Web Crypto. There is no
AES-to-XOR or XOR-to-AES fallback.

SMUGGLE accepts a bounded safe-builder layer for neutral internal test
artifacts. Use `locale=ru` or `locale=en` to select localized artifact copy
where the renderer provides localized text. Omit `locale` to use the default
`ru`; unsupported locale values return a `400` SMUGGLE error with
`code=invalid_smuggle_locale` and `field=locale`.

**Safe builder query parameters:**

- `download_name`: optional download-facing basename.
- `download_ext`: optional validated extracted-file suffix, at most 32
  characters. `txt`, `bin`, `dat`, `zip`, and `pdf` are suggestions rather
  than an allowlist; a safe custom suffix, including a compound suffix such as
  `tar.gz`, is accepted. Each ASCII segment starts with a letter or digit; its
  remaining characters may also contain `_`, `+`, or `-`. Segments are
  separated by single dots, and one optional leading dot is normalized away.
  The suffix changes only the normalized extracted filename, not the embedded
  bytes, outer artifact format, or MIME metadata.
- `mode`: optional renderer selector; exactly `simple` or `constructor`.
  Constructor-only parameters require `mode=constructor`. Simple-only
  parameters require `mode=simple`; the server never infers a mode from another
  field and never discards incompatible fields silently.
- `encryption`: optional artifact encryption selector; exactly `none`, `xor`,
  or `aes`.
- `preset`: simple-only fixed shell preset; one of `direct`, `card_manual`, or
  `card_auto`.
- `title`: optional bounded title text rendered inside the generated page.
- `message`: optional bounded explanatory copy rendered inside the generated
  page.
- `cta_label`: simple-only bounded button label for card presets.
- `delay_ms`: simple-only auto-start delay in milliseconds for `card_auto`
  (bounded to `0..10000`).
- `show_notice`: `1` or `0` to keep or hide the visible experimental/test-artifact
  notice.
- `payload_encoding`: constructor-only payload encoding; one of `base64`,
  `base64url`, `base32`, `percent`, `reverse`, `xor`, `hex`, `split`, `attrs`,
  or `charcode`. The default is `payload_encoding=base64`.
- `trigger_method` and `trigger_event`: constructor trigger pair. Valid events
  come from `PING.smuggle_capabilities`; for example `body:onpageshow` and
  `svg:onload` are distinct supported pairs. Built-in event sets are closed,
  but a custom `trigger_event` is accepted when it is a bounded safe event token
  and `trigger_method` is one of the registered canonical element tokens in
  `custom_trigger_methods`. A custom event only attaches the handler to that
  generated element: the server does not synthesize or dispatch the event and
  does not accept raw HTML or JavaScript, so the event may never fire unless
  normal browser or user behavior produces it. Custom input must use the
  normalized `on...` form. After that prefix the token starts with an ASCII
  letter and contains only lowercase ASCII letters, digits, `_`, or `-`, with a
  total normalized limit of 64 characters.
- `output_format`: constructor-only outer artifact format; one of `html`,
  `htm`, `shtml`, `shtm`, `xhtml`, `xht`, `xhtm`, `xml`, or `svg`.
- `download_variant`: constructor-only download implementation; one of
  `blob-anchor`, `data-uri`, `iframe-blob`, `filereader`, `fetch-blob`,
  `window-open`, `loc-assign`, `form-post`, `timeout-blob`, `promise-blob`,
  `raf-blob`, `microtask-blob`, `observer-blob`, `response-blob`,
  `readable-stream`, `message-channel-blob`, or `idle-callback-blob`.
- `page_template`: constructor-only page shell; one of `default`, `minimal`,
  `corporate`, `drive`, or `npf-zip-archive-help`.
- `mime_type`: constructor-only extracted-file Blob/data URI MIME metadata.
  Clients may use a value from `mime_presets`/`mime_by_extension` or submit a
  validated custom MIME type. It does not inspect, validate, or convert source
  bytes, and it is not a simple-mode option.
- `null_byte`: `1` or `0` to prepend a leading NUL byte before the generated
  outer artifact bytes.

`loc-assign` applies the selected `mime_type` to its `data:` URL, but it cannot
force the normalized download name because no `download` attribute participates
in that navigation. For this variant the browser chooses any saved filename and
the response reports `download.name_applied=false`; other current variants
report `true`.

The safe builder remains server-authoritative: it renders only fixed neutral
test-artifact shells, keeps the normal one-shot temp-file lifecycle, and does
not allow arbitrary HTML, CSS, JavaScript, external redirects, or custom
assets. XOR in the constructor payload-encoding list is only obfuscation of the
embedded payload representation; it is separate from `encryption=xor`. The
`title`, `message`, `cta_label`, and `show_notice` values affect the generated
shell where the selected mode/template supports them. Archive-themed page
templates are neutral instructions copy; they do not imply archive conversion
or content checks.

**With safe builder parameters:**
```
SMUGGLE /uploads/report.bin?mode=simple&encryption=none&download_name=Quarterly-Report&download_ext=pdf&preset=card_auto&title=Quarterly%20Report&message=Internal%20controlled%20test%20file&cta_label=Download%20test%20artifact&delay_ms=1200&show_notice=1 HTTP/1.1
```

**Response (200):**
```json
{
  "artifact": {
    "url": "/uploads/smuggle_0123abcd4567ef89.html",
    "name": "smuggle_0123abcd4567ef89.html",
    "size_bytes": 8192,
    "content_type": "text/html; charset=utf-8",
    "one_shot": true,
    "expires_at": null
  },
  "source": {"name": "report.bin", "path": "/uploads/report.bin", "size_bytes": 1234},
  "download": {"name": "Quarterly-Report.pdf", "name_applied": true, "mime_type": "application/octet-stream"},
  "builder": {
    "schema_version": 1,
    "mode": "simple",
    "preset": "card_auto",
    "locale": "ru",
    "encryption": "none",
    "payload_encoding": "base64",
    "output_format": "html",
    "trigger_method": "svg",
    "trigger_event": "onload",
    "trigger_event_custom": false,
    "download_variant": "blob-anchor",
    "page_template": "default",
    "notice_shown": true,
    "null_byte": false
  }
}
```

`builder.trigger_event_custom` is `true` only when constructor mode accepted a custom
event token rather than one of the selected method's built-in events. It is
`false` for built-in events and non-constructor responses.

**Headers:** `Content-Type: application/json`

`artifact.url` contains the relative path for a follow-up request that
returns the one-shot artifact with the file data
embedded in the selected payload format. The first `GET`, `HEAD`, or matching
conditional request consumes and deletes the temporary artifact; browser
preloads, link scanners, or manual `HEAD` checks can therefore consume it before
the intended user opens it. Regenerating creates another independent one-shot
URL and does not invalidate any older URL that has not yet been consumed,
expired, or pruned. The server also prunes retained temporary artifacts by age,
count, and generated artifact bytes before admitting a new SMUGGLE artifact;
leftover temporary artifacts are cleaned up when the server starts.

SMUGGLE source files are capped before HTML generation. The effective cap is
the lower of the SMUGGLE source cap (10 MiB by default) and the configured
upload limit. Generated-page retention failures return `507` JSON errors and do
not publish a temporary URL.

**Too large response (413):**
```json
{
  "error": {
    "code": "smuggle_source_too_large",
    "message": "SMUGGLE source too large. Max size: 10.0 MB",
    "field": "source",
    "details": {
      "scope": "uploads",
      "resource": "upload",
      "actual_bytes": 10485761,
      "limit_bytes": 10485760
    }
  }
}
```

Invalid safe-builder parameters, unsafe/overlong custom suffixes or events, and
mode-applicability conflicts return `400` JSON errors such as
`{"error":{"code":"invalid_smuggle_extension","message":"Invalid SMUGGLE builder extension","field":"download_ext","details":{}}}`.
Current SMUGGLE code tokens are `invalid_smuggle_locale`,
`invalid_smuggle_extension`, `invalid_smuggle_preset`,
`invalid_smuggle_payload_encoding`, `invalid_smuggle_trigger_method`,
`invalid_smuggle_trigger_event`, `invalid_smuggle_output_format`,
`invalid_smuggle_download_variant`, `invalid_smuggle_page_template`,
`invalid_smuggle_delay`, `invalid_smuggle_show_notice`,
`invalid_smuggle_null_byte`, `invalid_smuggle_mime_type`,
`invalid_smuggle_configuration`, `unknown_smuggle_parameter`,
`smuggle_field_too_long`, `smuggle_source_not_found`,
`smuggle_source_too_large`, `smuggle_temp_quota_exceeded`,
`invalid_smuggle_mode`, `invalid_smuggle_encryption`,
`invalid_smuggle_query`, `duplicate_smuggle_parameter`,
`invalid_smuggle_policy`, `invalid_smuggle_download_name`,
`invalid_smuggle_title`, `invalid_smuggle_message`, and
`invalid_smuggle_cta_label`. Clients should render `error.message` for
operators.

**Status codes:** `200` OK, `400` Invalid builder params, `404` File not found, `413` Source too large, `500` Artifact creation failed, `507` Temp storage budget exhausted

---

## NOTE

Secure Notepad uses client-side encrypted note blobs. Clients derive an
AES-256-GCM key through ECDH, and the server stores only opaque encrypted data
plus note metadata. The feature uses the runtime `cryptography` dependency and
fails closed with `501 feature_unavailable` if that backend is unavailable.
Notes live in the separate top-level `notes/` directory as `<id>.enc` and
`<id>.meta.json` pairs, alongside `uploads/` rather than inside it.

The `data` field is encrypted client-side and stored as an opaque base64 blob.
IDs, titles, timestamps, sizes, and the optional audit session marker are
plaintext metadata visible to the server and to operators who can read
`notes/*.meta.json`.

Every server-generated or client-supplied note ID must match exactly:

```text
[0-9a-f]{32}
```

Short IDs, uppercase IDs, path aliases, and decoded values outside this grammar
return `400 invalid_field` with `field: "id"`.

Current note keys are session-bound, not durably recoverable. The browser UI and `examples/notepad_client.py` keep the derived AES key only in process memory. Reloading the page, restarting the client, server restart, idle session expiry, or LRU session eviction can leave previously saved note bodies undecryptable by that client. The server does not persist note encryption keys and exposes no API to decrypt or re-key stored note blobs.

ADR-008 treats this as an intentional product/security boundary: stored
ciphertext plus metadata are not sufficient for durable recovery, and the
current HTTP/WebSocket Notepad flow is not a backup or multi-device sync
system.

The Notepad-specific encrypted blob limit requires a title containing 1 through
200 Unicode scalar values after trimming. `data` must decode to 28 through
1,048,576 bytes: a 12-byte nonce, ciphertext, and a 16-byte GCM tag. Aggregate
encrypted blobs are capped by
`--note-storage-limit MB` and `--note-count-limit N` before any note temp files
are created. These limits apply to `NOTE /notes?action=save` and WebSocket
`save`, independently of HTTP `--max-size` and the WebSocket message limit.
Per-note over-limit saves return `413 payload_too_large`; aggregate quota
failures return `507 storage_quota_exceeded`. Failures leave existing note
files unchanged and do not publish partial note state.

### Exact HTTP routes and request IDs

The accepted NOTE routes are exactly:

- `NOTE /notes/key`
- `NOTE /notes/exchange`
- `NOTE /notes?action=list`
- `NOTE /notes?action=save`
- `NOTE /notes?action=clear`
- `NOTE /notes/{id}?action=load`
- `NOTE /notes/{id}?action=delete`

`NOTE /notes` without a query returns `400 missing_field` with
`field: "action"`. Unknown or duplicate query keys, unknown action values,
query strings on key/exchange, trailing-slash aliases, bare query names,
substring matches, and the removed `?list`, `?delete`, and `?clear=1` forms are
rejected. Mutating JSON objects reject unknown fields; camelCase request aliases
are not accepted.

HTTP clients may supply `X-Request-Id` using this recommended and validated
grammar:

```text
[A-Za-z0-9._:-]{1,128}
```

An invalid supplied value returns `400 invalid_field` with
`field: "X-Request-Id"` before the NOTE operation runs. Normally dispatched
responses return `X-Request-Id`. It is only a log/response correlation value;
use a stable note `id` plus `create_if_missing: true`, not a request ID, when a
save must be safely retried after an unknown outcome.

### NOTE /notes/key

Get the server's ECDH public key.

**Request:**
```
NOTE /notes/key HTTP/1.1
```

**Response (200):**
```json
{
  "key": {
    "available": true,
    "algorithm": "ecdh_p256_hkdf_sha256_aes_256_gcm",
    "public_key": "<base64 of 65-byte uncompressed P-256 point>",
    "public_key_encoding": "x9_62_uncompressed_base64"
  }
}
```

If the crypto backend is unavailable, NOTE HTTP returns the shared `501`
error envelope:

```json
{
  "error": {
    "code": "feature_unavailable",
    "message": "Secure Notepad crypto is unavailable",
    "field": null,
    "details": {"feature": "note", "dependency": "cryptography"}
  }
}
```

In that mode, exchange and all note operations are unavailable.

---

### NOTE /notes/exchange

Exchange ECDH keys to establish a session. The client sends its ephemeral P-256
public key; the server returns a short-lived `session.id` and
`server_public_key`. Both sides independently derive the same AES-256-GCM
session key via HKDF-SHA256.

Exact derivation contract:

| Parameter | Value |
|---|---|
| Curve | ECDH P-256 (`secp256r1`) |
| Public key encoding | 65-byte uncompressed X9.62 point, base64 encoded on the wire |
| HKDF hash | SHA-256 |
| HKDF output length | 32 bytes |
| HKDF salt | 32 zero bytes (`00` repeated 32 times) |
| HKDF info | UTF-8 bytes for `notepad-e2e-key` |
| Content cipher | AES-256-GCM |
| Encrypted blob format | `nonce(12) + ciphertext + tag(16)`, then base64 encoded as `data` |

**Request:**
```
NOTE /notes/exchange HTTP/1.1
Content-Type: application/json

{"client_public_key": "<base64 of 65-byte uncompressed P-256 point>"}
```

**Response (200):**
```json
{
  "session": {"id": "<32 lowercase hex>", "ttl_seconds": 3600},
  "server_public_key": "<base64 of 65-byte uncompressed P-256 point>"
}
```

`session.id` is audit-only server state. If an active ID is later supplied as
the save body field `session_id`, the server records that the write followed a
recent ECDH exchange. It is not an authorization token for reads or writes.
A syntactically valid unknown or expired `session_id` is accepted and ignored;
it is never echoed by save. A syntactically invalid value returns
`400 invalid_field`.

The complete session ID is returned only as part of this protocol response and
may be sent back by the client. Debug lifecycle messages use a stable
`sidfp:<12-hex>` SHA-256 fingerprint instead of the complete identifier, and
unknown-session exceptions use generic text. Operators can correlate lifecycle
events without turning logs or error bodies into a source of reusable
ephemeral session identifiers.

The request object has exactly one key. Missing `client_public_key` returns
`400 missing_field`; an invalid point encoding or an extra/legacy field returns
`400 invalid_field`.

**Status codes:** `200` OK, `400` Missing/invalid key, `501` ECDH unavailable

---

### NOTE /notes?action=list: list notes

**Request:**
```
NOTE /notes?action=list HTTP/1.1
X-Request-Id: note-list-1
```

**Response (200):**
```json
{
  "notes": [
    {
      "id": "<32 lowercase hex>",
      "title": "My Note",
      "created_at": "2026-08-14T00:00:00+00:00",
      "updated_at": "2026-08-14T00:00:00+00:00",
      "size_bytes": 256
    }
  ],
  "page": {"limit": 1000, "returned_items": 1, "truncated": false}
}
```

Listing work is bounded by the configured list limit, which follows
`--note-count-limit` by default and falls back to `1000` when note count quota is
disabled.

---

### NOTE /notes?action=save: save note

Send a JSON object to create or update a note. `title` and `data` are required.
Omit `id` for a server-generated ID. With `id`, an existing note is updated;
when the note is missing, `create_if_missing: true` creates it and makes a retry
at the same identity safe. Without that flag, a missing supplied ID returns
`404 resource_not_found`. The encrypted blob is the source of truth, so
malformed metadata sidecars are ignored or rebuilt as needed.

**Request:**
```
NOTE /notes?action=save HTTP/1.1
Content-Type: application/json
X-Request-Id: note-save-1

{
  "title": "My Note",
  "data": "<base64-encoded encrypted blob>",
  "id": "0123456789abcdef0123456789abcdef",
  "create_if_missing": true,
  "session_id": "fedcba9876543210fedcba9876543210"
}
```

**Response (201 for new, 200 for update):**
```json
{
  "note": {
    "id": "0123456789abcdef0123456789abcdef",
    "title": "My Note",
    "created_at": "2026-08-14T00:00:00+00:00",
    "updated_at": "2026-08-14T00:00:00+00:00",
    "size_bytes": 256
  },
  "created": true
}
```

`id`, `create_if_missing`, and `session_id` are optional. No header carries the
session ID. Missing/unknown fields, invalid JSON/object types, invalid booleans,
out-of-grammar IDs/sessions, invalid titles, and invalid base64 all use the
canonical error envelope.

**Status codes:** `201` Created, `200` Updated, `400` Invalid request, `404`
Note not found for update, `413` Encrypted note data too large, `507` Notepad
aggregate quota exceeded, `501` Secure Notepad unavailable

---

### NOTE /notes/{id}?action=load: load note

**Request:**
```
NOTE /notes/0123456789abcdef0123456789abcdef?action=load HTTP/1.1
```

**Response (200):**
```json
{
  "note": {
    "id": "0123456789abcdef0123456789abcdef",
    "title": "My Note",
    "created_at": "2026-08-14T00:00:00+00:00",
    "updated_at": "2026-08-14T00:00:00+00:00",
    "size_bytes": 256
  },
  "data": "<base64-encoded encrypted blob>"
}
```

**Status codes:** `200` OK, `404` Not Found, `501` Secure Notepad crypto backend unavailable

---

### NOTE /notes/{id}?action=delete: delete note

**Request:**
```
NOTE /notes/0123456789abcdef0123456789abcdef?action=delete HTTP/1.1
```

**Response (200):**
```json
{
  "deleted_note": {"id": "0123456789abcdef0123456789abcdef"}
}
```

**Status codes:** `200` OK, `404` Not Found, `501` Secure Notepad crypto backend unavailable

---

### NOTE /notes?action=clear: clear all notes

Deletes all user-visible entries from the separate `notes/` directory. Files in
`uploads/` are not touched.

**Request:**
```
NOTE /notes?action=clear HTTP/1.1
```

**Response (200):**
```json
{
  "cleared_notes": {
    "path": "/notes",
    "deleted_files": 4,
    "deleted_dirs": 0,
    "preserved": []
  }
}
```

Hidden files inside `notes/` are preserved.

**Status codes:** `200` OK, `500` Clear failed, `501` Secure Notepad crypto backend unavailable

---

### Browser and curl HTTP examples

The browser UI and command-line clients use the same HTTP routes and bodies.
For a same-origin browser call (with `encryptedData` produced by the ECDH/AES
flow above):

```js
const requestId = "browser-note-save-1";
const response = await fetch("/notes?action=save", {
  method: "NOTE",
  headers: {
    "Content-Type": "application/json",
    "X-Request-Id": requestId,
  },
  body: JSON.stringify({
    title: "My Note",
    data: encryptedData,
    id: "0123456789abcdef0123456789abcdef",
    create_if_missing: true,
    session_id: "fedcba9876543210fedcba9876543210",
  }),
});
const body = await response.json();
if (!response.ok) {
  throw new Error(`${body.error.code}: ${body.error.message}`);
}
console.log(body.note.id, body.created);
```

Equivalent curl requests use the same custom method and query grammar:

```bash
base_url=http://127.0.0.1:8080

curl --fail-with-body --silent --show-error \
  --request NOTE \
  --header 'X-Request-Id: curl-note-list-1' \
  "${base_url}/notes?action=list"

curl --fail-with-body --silent --show-error \
  --request NOTE \
  --header 'Content-Type: application/json' \
  --header 'X-Request-Id: curl-note-save-1' \
  --data '{"title":"My Note","data":"<base64 nonce+ciphertext+tag>","id":"0123456789abcdef0123456789abcdef","create_if_missing":true,"session_id":"fedcba9876543210fedcba9876543210"}' \
  "${base_url}/notes?action=save"

curl --fail-with-body --silent --show-error \
  --request NOTE \
  "${base_url}/notes/0123456789abcdef0123456789abcdef?action=load"
```

For cross-origin browser calls, the origin must be an exact configured CORS
origin allowed to perform mutations. Wildcard CORS remains read-only.

---

## WebSocket /notes/ws

Notepad transport over WebSocket (RFC 6455) is not a durable workspace-sync
protocol: the server provides no revision checks, replay, resume token,
collaborative merge, or request-ID deduplication.

Only exact `GET /notes/ws` may upgrade. A query-bearing target,
`/notes/ws/child`, or any other prefix/path is handled as an ordinary HTTP
request and never reaches WebSocket handshake processing. Before upgrade,
Basic Auth, same-origin/exact-origin policy, crypto availability, handshake
validation, and connection-capacity admission all apply. Failures use the
canonical HTTP error envelope when a response can be built and carry
`X-Request-Id` when the request pipeline has generated one.

Upgrade validation requires `GET`, `Host`, `Upgrade: websocket`,
`Connection: Upgrade`, a valid base64 16-byte `Sec-WebSocket-Key`, and
`Sec-WebSocket-Version: 13`. The connection uses a 60-second idle timeout; the
server sends ping frames while idle. Active connections are limited by
`--max-websocket-connections` (`--workers // 2` by default), and incomplete
frames must finish within `--websocket-frame-idle-timeout` (`5` seconds by
default). Missing crypto rejects admission with `501 feature_unavailable`.

**Upgrade request:**
```
GET /notes/ws HTTP/1.1
Host: <server-host>
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: <base64-nonce>
Sec-WebSocket-Version: 13
```

**Response:**
```
HTTP/1.1 101 Switching Protocols
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Accept: <computed accept key>
```

All application messages are UTF-8 JSON text frames. Clients send masked
frames, as RFC 6455 requires; the server sends unmasked frames. Protocol
processing completes before NOTE action dispatch.

Same-origin upgrades are allowed by default. Cross-origin upgrades require the
`Origin` to match an exact configured `--cors-origin` value. Wildcard
`--cors-origin *` is read-only CORS and does not authorize WebSocket upgrades.

### WebSocket request grammar

Every application request is a JSON object with exactly three top-level keys:

```json
{
  "action": "save",
  "request_id": "client-123",
  "input": {
    "title": "My Note",
    "data": "<base64 nonce+ciphertext+tag>",
    "id": "0123456789abcdef0123456789abcdef",
    "create_if_missing": true,
    "session_id": "fedcba9876543210fedcba9876543210"
  }
}
```

`request_id` is required on every application request and must match:

```text
[A-Za-z0-9._:-]{1,128}
```

Allowed actions and their exact `input` objects are:

| `action` | `input` | Domain operation |
|---|---|---|
| `list` | `{}` | Same operation as `NOTE /notes?action=list` |
| `save` | `title`, `data`, optional `id`, optional `create_if_missing`, optional `session_id` | Same operation as `NOTE /notes?action=save` |
| `load` | `{"id":"<32 lowercase hex>"}` | Same operation as `?action=load` |
| `delete` | `{"id":"<32 lowercase hex>"}` | Same operation as `?action=delete` |
| `clear` | `{}` | Same operation as `NOTE /notes?action=clear` |

`input` must be an object. Unknown top-level keys, unknown input keys,
top-level domain fields, unknown actions, invalid request IDs, and legacy
`type`, `opId`, `noteId`, `createIfMissing`, and `sessionId` fields are
rejected. There is no compatibility parser.

### WebSocket success grammar and HTTP parity

A success frame echoes the exact action and request ID and places the exact
corresponding HTTP success object under `result`:

```json
{
  "action": "save",
  "request_id": "client-123",
  "result": {
    "note": {
      "id": "0123456789abcdef0123456789abcdef",
      "title": "My Note",
      "created_at": "2026-08-14T00:00:00+00:00",
      "updated_at": "2026-08-14T00:00:00+00:00",
      "size_bytes": 256
    },
    "created": true
  }
}
```

`list`, `load`, `delete`, and `clear` wrap the unchanged HTTP domain result in
the same way. There is no `success`, operation-shaped response type, flat note
metadata, count alias, or numeric JSON status.

### WebSocket application errors

An application error retains correlation at the top level and uses the same
four-field error object as HTTP:

```json
{
  "action": "load",
  "request_id": "client-123",
  "error": {
    "code": "resource_not_found",
    "message": "Note not found",
    "field": "id",
    "details": {"resource": "note"}
  }
}
```

If `action` is missing or invalid, the response has `"action": null`. If
`request_id` is missing or invalid, it has `"request_id": null`. The nested
`error` remains identical to the HTTP error object; correlation fields are not
copied into `error.details`, and no numeric status is added. Malformed JSON,
non-object JSON, invalid input, and ordinary domain failures are application
errors rather than success-like frames.

Common NOTE errors include `malformed_json`, `invalid_json_type`,
`missing_field`, `invalid_field`, `empty_payload`, `invalid_encoding`,
`resource_not_found`, `payload_too_large`, `storage_quota_exceeded`,
`clear_failed`, and `feature_unavailable`. Clients branch on `error.code` and
may display `error.message`.

### Browser WebSocket example

```js
const socket = new WebSocket(`${location.protocol === "https:" ? "wss" : "ws"}://${location.host}/notes/ws`);
socket.addEventListener("open", () => {
  socket.send(JSON.stringify({
    action: "load",
    request_id: "browser-load-1",
    input: {id: "0123456789abcdef0123456789abcdef"},
  }));
});
socket.addEventListener("message", ({data}) => {
  const frame = JSON.parse(data);
  if (frame.error) throw new Error(`${frame.error.code}: ${frame.error.message}`);
  console.log(frame.action, frame.request_id, frame.result);
});
```

For a save whose acknowledgement is lost, retry with the same stable note
`id` and `create_if_missing: true`; reusing `request_id` alone provides no
idempotency. Repeated writes to the same ID are last-write-wins at the encrypted
blob level. After any unknown delete or clear outcome, confirm final state.

### WebSocket close grammar

Application errors above are JSON frames and normally leave the connection
open. Protocol/transport failures use RFC 6455 close frames:

| Close code | Condition |
|---|---|
| `1000` | Orderly normal shutdown |
| `1002` | Invalid frame structure, unmasked client frame, fragmented frame, invalid close payload, or incomplete-frame timeout |
| `1003` | Binary application frame |
| `1009` | Message exceeds the configured limit |
| `1011` | Unexpected internal failure or inability to send an application response |

After a `1011` or transport loss, clients must treat any in-flight mutation as
having an unknown outcome and verify server state before deciding how to retry.

---

## OPTIONS

CORS preflight handler. Returns allowed methods when CORS is enabled.

**Response (204):** No body. If CORS is disabled, no
`Access-Control-Allow-*` headers are emitted. If CORS is enabled,
`Access-Control-Allow-Methods` lists the full core method surface for exact
origins. For wildcard `--cors-origin *`, preflight stays read-only and lists
only read methods. Basic/default requests may use `Authorization`,
`Content-Type`, `If-None-Match`, `X-File-Name`, `X-Request-Id`, and
`X-XFerry-No-Gzip`.

Only an exact configured non-wildcard data origin may request Advanced data
headers: `X-XFerry-Advanced-Session`, `X-XFerry-Data`,
`X-XFerry-Data-0` through `X-XFerry-Data-255`,
`X-XFerry-Encryption`, `X-XFerry-Key`, `X-XFerry-Key-Is-Base64`,
`X-XFerry-Name`, `X-XFerry-HMAC`, `X-XFerry-Encoding`, and
`X-XFerry-Method-Override`. Wildcard CORS is read-only: it neither authorizes
nor advertises session-bearing Advanced data headers. Advanced control
endpoints are never CORS-enabled.

---

## Advanced Sessions upload

Advanced upload is a public, session-scoped API for the bundled UI, `curl`,
scripts, and other clients. Only the
`X-XFerry-Advanced-Session` header selects Advanced routing and parsing. A
request without that header follows the normal XFerry API; a request with it
never silently falls back when its token, authorization, prefix, method, or
payload is invalid. Advanced writes remain limited to `uploads/`.

### Advanced session API

The following are the only Advanced control endpoints. They all send
`Cache-Control: no-store`.

| Operation | Method and path | Success | Token behavior |
| --- | --- | ---: | --- |
| Create session | `POST /_xferry/advanced-sessions` | `201` | The response contains the token exactly once. |
| Inspect current session | `GET /_xferry/advanced-sessions/current` | `200` | Requires the session header; the response omits the token. |
| Revoke current session | `DELETE /_xferry/advanced-sessions/current` | `200` | Requires the session header. |

Create a session with a closed JSON object:

```http
POST /_xferry/advanced-sessions HTTP/1.1
Content-Type: application/json

{"prefix":"/advanced","decoder":"auto","diagnostic_headers":true}
```

```json
{
  "advanced_session": {
    "token": "<43-character base64url token without padding>",
    "prefix": "/advanced",
    "decoder": "auto",
    "diagnostic_headers": true,
    "created_at": "2026-08-13T18:30:00Z",
    "expires_at": "2026-08-13T19:30:00Z",
    "idle_timeout_seconds": 900
  }
}
```

Inspect and revoke use the same singleton header:

```http
GET /_xferry/advanced-sessions/current HTTP/1.1
X-XFerry-Advanced-Session: <token>
```

The `200` inspection representation omits `token`:

```json
{
  "advanced_session": {
    "prefix": "/advanced",
    "decoder": "auto",
    "diagnostic_headers": true,
    "created_at": "2026-08-13T18:30:00Z",
    "expires_at": "2026-08-13T19:30:00Z",
    "idle_timeout_seconds": 900
  }
}
```

Revoke uses the same header:

```http
DELETE /_xferry/advanced-sessions/current HTTP/1.1
X-XFerry-Advanced-Session: <token>
```

A successful revoke returns:

```json
{"advanced_session":{"revoked":true}}
```

The header value is exactly 43 ASCII base64url characters from
`[A-Za-z0-9_-]`. It has no padding, whitespace, folded form, duplicate value,
or comma-combined value. A malformed header returns `400 invalid_field` with
field `X-XFerry-Advanced-Session`; a missing header on a current-session
operation returns `400 missing_field`. Tokens are never accepted from a query
parameter, cookie, path, request body, `Authorization`, or forwarding header.
Unknown, expired, revoked, wrong-owner, and wrong-auth-mode tokens all return
`404 advanced_session_not_found`.

### Authentication, peer, and origin

Basic Auth is evaluated before peer, origin, or token lookup. With Basic Auth
configured, create, use, inspect, and revoke require valid credentials and the
same exact, case-sensitive verified username that created the session; the
source IP may change. The session token selects a parser/routing context: it
does not replace Basic Auth.

With Basic Auth disabled, each control or data operation requires its direct
accepted-socket peer to be loopback. `Forwarded`, `X-Forwarded-For`,
`X-Real-IP`, `X-Forwarded-Proto`, and similar headers have no authority for
loopback, ownership, origin, routing, or audit identity. A remotely reachable
loopback proxy is not a supported no-auth Advanced Sessions deployment; enable
Basic Auth at XFerry instead.

Control endpoints are strict same-origin for browser requests. A configured
CORS origin does not grant control access. Advanced browser data requests are
same-origin or from an exact configured non-wildcard CORS origin only; wildcard
CORS does not authorize session-bearing Advanced data requests.

Sessions are immutable, live only in a lock-protected per-server in-memory
store, and vanish on restart. They have a 60-minute absolute lifetime and a
15-minute inactivity timeout; successful create, Advanced use, and inspection
refresh inactivity only. Rejected requests never refresh activity. At most 64
live sessions exist per server; expired sessions are removed before capacity is
checked, and exhaustion returns `503 advanced_session_capacity_exhausted`.
Create a replacement session to change its prefix, decoder, or diagnostics,
then revoke the old session.

### Advanced data requests

`POST`, `PUT`, `PATCH`, and `NONE` are Advanced uploads only with an authorized
session header and a path matching the immutable session prefix. Without the
header, those methods retain Basic upload behavior. A syntactically valid,
unregistered custom method is an Advanced upload only with an authorized,
matching session; without one it returns `405 method_not_allowed`. A registered
core or plugin non-upload method with an authorized matching session returns
`409 advanced_method_conflict` rather than being shadowed. `method_override`
is diagnostic metadata only and never changes routing, authentication, origin
checks, method conflict detection, or authorization.

For example, an unregistered method can upload canonical JSON data:

```http
SYNCDATA /advanced/upload HTTP/1.1
X-XFerry-Advanced-Session: <token>
Content-Type: application/json

{"data":"aGVsbG8=","encoding":"base64","encryption":"none","name":"hello.txt"}
```

Success is `201` and returns the standard upload representation:

```json
{
  "file": {
    "name": "hello.txt",
    "path": "/uploads/hello.txt",
    "size_bytes": 5,
    "size_human": "5.0 B",
    "content_type": "application/octet-stream",
    "uploaded_at": "2026-08-14T00:00:00+00:00",
    "sha256": "<64 lowercase hex>"
  },
  "upload": {
    "kind": "advanced",
    "profile": "json",
    "carrier": "body",
    "filename_source": "body",
    "normalized_name": "hello.txt",
    "collision_renamed": false,
    "request_body_size": 78,
    "payload_size": 5,
    "encoding": "base64",
    "encryption": "none",
    "method_override": null
  }
}
```

The optional diagnostics setting can mirror only shared non-sensitive
diagnostic response headers. Responses never return session tokens, token
hashes, keys, HMAC values, plaintext, ciphertext, owner names, or raw peer
headers.

### Canonical carriers

Every Advanced request supplies exactly one payload carrier and uses only these
canonical logical fields:

| Field | Required/type | Meaning |
| --- | --- | --- |
| `data` | Required string for encoded carriers | Encoded file bytes |
| `encryption` | Required string | Exactly `none`, `xor`, or `aes` |
| `key` | String | Required and nonempty for `xor`/`aes` or when `hmac` is supplied; otherwise forbidden |
| `key_is_base64` | Boolean | Optional, default `false`; when true, `key` is strict standard base64 of nonempty UTF-8 text |
| `name` | String | Optional suggested filename; an omitted name is generated |
| `hmac` | String | Optional lowercase 64-character HMAC-SHA256 hex over decoded bytes before decryption |
| `encoding` | Required string for encoded carriers | Exactly `raw`, `base64`, `base64url`, `hex`, `percent`, `gzip-base64`, or `gzip-base64url` |
| `method_override` | String | Optional diagnostic HTTP token with no routing or security authority |

The one carrier is one of:

- a nonempty JSON, form, XML, multipart, raw, or text body selected by the
  session decoder and declared `Content-Type`;
- `X-XFerry-Data` or contiguous `X-XFerry-Data-0` through
  `X-XFerry-Data-255`, with the corresponding canonical metadata headers;
- canonical query fields such as `data`, `encoding`, `encryption`, and `name`;
- exact cookie names `xferry_data`, `xferry_encryption`, `xferry_key`,
  `xferry_key_is_base64`, `xferry_name`, `xferry_hmac`, `xferry_encoding`, and
  `xferry_method_override`; or
- `<session-prefix>/_payload/<percent-encoded-name>/<base64url-data>`, with
  crypto metadata only in its query string.

JSON, form, multipart-encoded, query, and header carriers may use `data_0`
through `data_255` instead of `data`. Chunks start at zero, are contiguous and
unique, use canonical decimal indexes without leading zeroes except `0`, and
cannot be mixed with direct `data`. Header chunks use `X-XFerry-Data-0` through
`X-XFerry-Data-255`. XML, cookies, and the path carrier do not support chunks.

Raw and text body carriers omit `data` and `encoding` because the body is the
payload, but still require encryption metadata. An unencrypted raw/text
request therefore includes:

```http
X-XFerry-Encryption: none
```

The decoder maps a body only from its declared media type. `auto` recognizes
JSON, form, multipart, XML, text, and raw media types; a missing, malformed,
or unsupported body media type returns `415 unsupported_media_type` and never
causes body sniffing. Structured carriers are closed: aliases, unknown fields,
duplicates, and ambiguous carrier combinations fail rather than being ignored.

### Encryption and integrity

`encryption=none` does not encrypt bytes, but it remains explicit canonical
metadata in every carrier. When it is selected, `key`, `key_is_base64=true`,
and HMAC metadata are forbidden. `encryption=xor` is explicit compatibility
obfuscation, not confidentiality, and requires a nonempty `key`.
`encryption=aes` is AES-256-GCM and also requires a nonempty `key`. Its wire
format is version byte `0x01`, a 16-byte salt, a 12-byte nonce, and ciphertext
including the GCM tag; PBKDF2-SHA256 with 600000 iterations derives the
AES-256-GCM key. HMAC, if present, is verified over decoded bytes before AES or
XOR decryption. There is no AES-to-XOR or XOR-to-AES fallback.

Advanced payloads decode to at least one byte. The decoded upload cap remains
16 MiB and is also bounded by the server request/upload limit. Header and
cookie encoded data are limited to 64 KiB; query and path encoded data are
limited to 16 KiB. Gzip expansion is bounded while decoding, and all size,
crypto, integrity, and filename failures occur before publication.

### Advanced errors

All Advanced failures use the shared XFerry 0.x error envelope:

```json
{"error":{"code":"advanced_session_not_found","message":"Advanced session not found","field":"X-XFerry-Advanced-Session","details":{}}}
```

| Situation | Status | Code | Field | Details |
| --- | ---: | --- | --- | --- |
| Missing session header for current control | 400 | `missing_field` | `X-XFerry-Advanced-Session` | `{}` |
| Malformed or duplicate session header | 400 | `invalid_field` | `X-XFerry-Advanced-Session` | `{}` |
| Unknown, expired, revoked, wrong-owner, or wrong-mode token | 404 | `advanced_session_not_found` | `X-XFerry-Advanced-Session` | `{}` |
| No-auth non-loopback direct peer | 403 | `forbidden_peer` | `null` | `{}` |
| Browser control origin or fetch metadata forbidden | 403 | `forbidden_origin` | `Origin` or `Sec-Fetch-Site` | `{}` |
| Valid session outside prefix | 409 | `advanced_route_mismatch` | `prefix` | `{"prefix":"/advanced"}` |
| Plugin conflict at create | 409 | `advanced_method_conflict` | `null` | `{"methods":["PATCH","POST"]}` sorted |
| Registered non-upload method with a session | 409 | `advanced_method_conflict` | `null` | `{"method":"GET"}` |
| Session capacity exhausted | 503 | `advanced_session_capacity_exhausted` | `null` | `{"limit":64}` |
| Unregistered method without a session | 405 | `method_not_allowed` | `null` | `{"method":"CUSTOM"}` and canonical `Allow` |

Security-sensitive values are never echoed in an error, diagnostic, log, or
metric label.

### Public curl journey

With Basic Auth enabled, create a session, use it, inspect it if desired, and
revoke it. Keep the token in a shell variable and avoid writing it to logs:

```bash
base_url='https://example.test'
credentials='operator:password'

session_json="$(
  curl --silent --show-error --fail-with-body \
    --user "$credentials" \
    --header 'Content-Type: application/json' \
    --data '{"prefix":"/advanced","decoder":"auto","diagnostic_headers":true}' \
    "$base_url/_xferry/advanced-sessions"
)"

# jq is used only to keep the example readable; it is not an API dependency.
advanced_token="$(printf '%s' "$session_json" | jq -r '.advanced_session.token')"

curl --silent --show-error --fail-with-body \
  --user "$credentials" \
  --header "X-XFerry-Advanced-Session: $advanced_token" \
  --header 'Content-Type: application/json' \
  --data '{"data":"aGVsbG8=","encoding":"base64","encryption":"none","name":"hello.txt"}' \
  "$base_url/advanced/upload"

# A valid unregistered method uses the same active session and payload contract.
curl --silent --show-error --fail-with-body \
  --user "$credentials" \
  --request SYNCDATA \
  --header "X-XFerry-Advanced-Session: $advanced_token" \
  --header 'Content-Type: application/json' \
  --data '{"data":"Y3VzdG9t","encoding":"base64","encryption":"none","name":"custom.txt"}' \
  "$base_url/advanced/upload"

curl --silent --show-error --fail-with-body \
  --user "$credentials" \
  --header "X-XFerry-Advanced-Session: $advanced_token" \
  "$base_url/_xferry/advanced-sessions/current"

curl --silent --show-error --fail-with-body \
  --user "$credentials" \
  --request DELETE \
  --header "X-XFerry-Advanced-Session: $advanced_token" \
  "$base_url/_xferry/advanced-sessions/current"
```

Use `--user` on create, inspect, data use, and revoke whenever Basic Auth is
configured. The same journey works without `--user` only when Basic Auth is
disabled and `curl` is the direct loopback peer, for example at
`http://127.0.0.1:<port>/`. `POST`, `PUT`, `PATCH`, and `NONE` may replace the
data request method without changing its payload contract. The custom-method
example above runs before revocation, while its session remains active.

---

## Authentication

When `--auth` is enabled, all requests require HTTP Basic Auth:

```
Authorization: Basic <base64(user:pass)>
```

Failed auth returns `401` with `WWW-Authenticate` header. Rate limiting applies after 5 failures (30s cooldown, `429` response).

The limiter keys on the direct TCP peer IP from the accepted socket. In
proxied deployments, `401`/`429` semantics therefore reflect the proxy
connection unless the proxy enforces per-client throttling first. `Forwarded`,
`X-Forwarded-For`, and similar headers are not trusted as client identity; see
[`docs/ADR/ADR-007-trusted-proxy-identity.md`](ADR/ADR-007-trusted-proxy-identity.md).

---

## Browser-Origin Mutation Guard

State-changing HTTP requests from browsers are accepted only when they are
same-origin or explicitly allowed by `--cors-origin`. Protected methods are
`POST`, `PUT`, `PATCH`, `DELETE`, `NONE`, `NOTE`, `SMUGGLE`, plus unknown
methods that carry advanced-upload data.

Requests with an `Origin` header must match the request host/scheme or a
configured CORS origin. `Sec-Fetch-Site: cross-site` and `same-site` requests
without `Origin` are rejected; with `Origin`, they require a configured CORS
origin. Non-browser API clients that omit both `Origin` and `Sec-Fetch-Site`
keep the existing behavior. Wildcard `--cors-origin *` still emits read CORS
headers, but does not authorize browser mutations from arbitrary origins.

Rejected browser-origin mutations return `403` JSON:

```json
{"error":{"code":"forbidden","message":"Forbidden cross-origin browser mutation","field":null,"details":{}}}
```

---

## Common Headers

| Header | Description |
|--------|-------------|
| `X-Request-Id` | Unique request correlation ID on normally dispatched HTTP responses; direct guard or upgrade errors may be sent before this decoration |
| `Content-Disposition` | Canonical download filename and attachment metadata on FETCH responses |
| `X-XFerry-Handler` | Sole optional diagnostics-gated Advanced dispatch header; its only possible value is `advanced`, and it is not a result mirror |
| `X-XFerry-No-Gzip` | Request opt-out for HTTP response gzip compression (`1`); the canonical client header |
| `X-Exphttp-No-Gzip` | Legacy request alias for `X-XFerry-No-Gzip` |
