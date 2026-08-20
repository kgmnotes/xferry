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
service files, and paths outside `<root>/uploads/`.

Serve the bundled UI and static assets from read-only package resources, not
from the operator upload directory. Keep Secure Notepad state in the separate
`<root>/notes/` directory.

## Consequences

- GET, upload, INFO, FETCH, DELETE, and SMUGGLE share the same containment
  boundary.
- A filename can be normalized or rejected without changing the configured
  root.
- Operators must still protect the root from uncoordinated external writers.
