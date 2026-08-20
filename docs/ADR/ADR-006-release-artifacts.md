# ADR-006: Release artifacts

- **Status:** accepted

## Context

The repository can build Python distributions, a container image, and SCIE
installer assets. Users need to distinguish source availability from artifacts
that have passed the release workflow and actually been published.

## Decision

Keep source installation as the current user path. Version `0.1.0` has no
GitHub Release, PyPI publication, or GHCR image.

The release workflow verifies three artifact lanes before publication:

1. wheel and source distribution;
2. the tested container image;
3. the SCIE executable, installer, manifest, checksums, and SBOM.

Manual workflow runs verify artifacts only. Tag-triggered publication is
eligible only after the shared release gate succeeds. Published container use
must resolve to an immutable digest rather than a floating tag.

## Consequences

- Documentation cannot advertise download URLs before publication exists.
- A build output is not a release merely because it was produced locally.
- Rollback material must come from a previously verified and retained
  artifact, not a rebuilt approximation.
