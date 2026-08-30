# ADR-006: Source-only distribution

- **Status:** accepted

## Context

The repository can build Python distributions, a container image, and SCIE
installer assets. Build verification and supported distribution are separate
security boundaries.

## Decision

Support distribution only from a reviewed source checkout. Automated jobs do
not publish to PyPI, GHCR, or GitHub Releases and do not expose build products
as release downloads.

CI and the manual Release Verification workflow verify three ephemeral build
lanes:

1. wheel and source distribution;
2. the tested container image;
3. the SCIE executable, installer, manifest, checksums, and SBOM.

The manual workflow has read-only repository permissions, no tag trigger, no
artifact upload, no publisher credentials, and no publication jobs. Its shared
gate records only that all verification lanes completed.

## Consequences

- Documentation and examples use source checkout installation only.
- A build output is not a supported release or distribution artifact.
- Managed rollback may use only a previously verified release already retained
  on that host; it does not create or fetch rollback material.
- Adding any publication channel requires a new reviewed architecture decision
  and explicit operator documentation.
