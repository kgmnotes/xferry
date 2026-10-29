# ADR-004: Upload containment

- **Status:** accepted

## Context

User-controlled paths can include traversal components, absolute paths,
encoded separators, or symlinks. File operations must not escape the upload
workspace or reach bundled application assets.

## Decision

Resolve user file paths through the shared descendant resolver. Resolve both
the configured base and candidate, then require the candidate to be relative
to the base with `Path.relative_to`. Reject traversal, symlink escape, hidden
service files, and paths outside the configured public files directory.

The base is `files_dir` itself, not an `uploads/` subdirectory beneath it. The
HTTP prefix remains `/uploads/`. When a server is constructed without
`files_dir`, the base falls back to `<root>/uploads/`; normal CLI launches
resolve a files directory from settings and platform defaults. This clarifies
the current directory selection without changing the containment decision.

Serve the bundled UI and static assets from read-only package resources, not
from the operator upload directory. Keep Secure Notepad state in the separate
`<root>/notes/` directory under the private state root. Encrypted-transfer
sidecars and TLS state also belong to private state; hidden encrypted payloads
in the public files directory are accessible only through their dedicated API.
See [files and private state](../settings.md#files-and-private-state).

## Consequences

- GET, upload, INFO, FETCH, DELETE, and SMUGGLE share the same containment
  boundary.
- A filename can be normalized or rejected without changing the configured
  file boundary.
- Operators must still protect the files directory and private state from
  uncoordinated external writers.
