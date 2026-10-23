# Production Release Runbook

This runbook prepares a production release. It is not permission to publish.
Create a production tag only after the owner records a separate exact
go/no-go for one version in the form `vX.Y.Z`.

## Audience and Scope

Release maintainers use this document to promote one verified candidate across
the portable, container, and managed Linux channels. Operators use the
post-publish and rollback sections to verify or recover deployments.

The runbook assumes two production GitHub Environments:

- `production-release` is the signing-key custody boundary. Only the signer job
  may read the private key.
- `release-production` is the secret-free production publication approval
  boundary. The current production workflow uses it directly on the four
  writer/publisher jobs: draft GitHub Release creation, PyPI publication, GHCR
  publication, and public GitHub Release activation. Those jobs must not
  receive signing secrets.

Do not use a generic production environment or an unreviewed replacement name.

## Prerequisites

All items in this list are blocking. Stop on the first missing item.

- The reviewed release code is merged into protected `main` before creating
  the production tag. A `main` push builds and validates documentation;
  public Pages deployment requires a separate dispatch with successful
  production and public-channel evidence.
- STAGE-010, STAGE-011, STAGE-012, STAGE-013, and STAGE-014 are `CLOSED` in
  the operator's release evidence log, with passing staging receipts.
- The version is one exact tag, `vX.Y.Z`, and matches source version,
  changelog entry, package metadata, release manifests, filenames, and release
  notes.
- The TestPyPI rehearsal mapping uses workflow `testpypi.yml` and GitHub
  Environment `testpypi`; its passing receipt is staging evidence only.
- The production PyPI mapping uses workflow `release-production.yml` and GitHub
  Environment `release-production`. Both mappings use repository owner
  `kgmnotes` and repository `xferry`, but TestPyPI and PyPI have separate
  registries and require separate account-owner confirmation.
- The GHCR package is visible to the expected audience and accepts only the
  release publisher job for writes.
- The `production-release` GitHub Environment requires reviewers `kgmnotes`
  and `gkumurzhi`, prevents self-review, disables admin bypass, restricts
  deployment refs to authorized release refs, and is referenced only by the
  signer job.
- `production-release` contains secret
  `XFERRY_RELEASE_ED25519_PRIVATE_KEY_PEM` and variable
  `XFERRY_RELEASE_SIGNING_KEY_ID=xferry-release-2026-09`.
- The `release-production` GitHub Environment requires reviewers `kgmnotes`
  and `gkumurzhi`, prevents self-review, disables admin bypass, restricts
  deployment refs to authorized release refs, contains no signing secret, and
  is referenced only by production publisher jobs.
- The public trust root for `xferry-release-2026-09` is present in
  `xferry/management/release_trust.py`, `SECURITY.md`, and
  `docs/security.md`.
- The candidate artifact retention window covers the full release operation
  and post-publish checks.
- No production PyPI package, GHCR tag, GitHub Release, or Pages deployment
  already exists for the target version.

## Go/No-Go Checklist

Record the answer and evidence link for every item before creating the tag.

| Check | Required answer |
| --- | --- |
| Target version | Exact `vX.Y.Z`; no pre-release or build metadata |
| Release commit | One reviewed commit SHA; no dirty or unpushed state |
| Prior stages | STAGE-010 through STAGE-014 are `CLOSED` |
| CI and security gates | Full tests, coverage, mypy, Ruff, docs, Bandit, pip-audit, artifact, platform, and policy gates pass |
| Candidate identity | Candidate archive, inventory, source commit, workflow run, and digests agree |
| TestPyPI/PyPI | Trusted publisher mapping is confirmed by an account owner |
| GHCR | Version tag and digest publication path is ready; no mutable alias is required |
| GitHub Release | Draft release path creates once and never overwrites assets |
| Signing key | `production-release` approval is required before any signing secret is available |
| Publication approval | `release-production` approval is required before any public publisher writes |
| Reviewer independence | The approver is not the actor who requested the deployment |
| Rollback target | Previous exact version or digest remains available and trusted |
| Communications | Release notes, operator notice, and withdrawal notice template are ready |

Any `No`, `Unknown`, or expired evidence is a no-go.

## Native Systemd Fixture Rehearsal

After the reviewed implementation is merged into protected `main`, dispatch
`Native Systemd Fixture Matrix` (`managed-systemd-matrix.yml`) on `main`.
It builds signed, nonproduction 0.1.1 and 0.1.2 fixtures separately on native
x86_64 and aarch64 runners. Each runner exercises Ubuntu 22.04, 24.04 and
26.04 plus Debian 12 and 13 with actual systemd as PID 1, a private cgroup
namespace and no host runtime mounts or external container network.
The fixture containers keep `/tmp` non-executable and give the signed installer
a separate container-only `/var/tmp` tmpfs (`exec,nosuid,nodev`, sticky mode
1777) via standard `TMPDIR`, also used when applying the version-changing
update. Readiness verifies these mount boundaries before
the app probe; signature, TLS, checksum and size checks remain mandatory.

Every pair must pass install, private setup, deep doctor, dry-run update,
version-changing update, authenticated exact-version health, rollback and
conservative uninstall. Configuration, authentication and sentinel data must
be preserved. The final job requires both architectures and all ten passing
receipts, bound to source commit, run, attempt and the checked-out verifier
hashes; a missing, failed or duplicate pair fails the matrix.

Only sanitized JSON receipts are uploaded. Raw command output, generated
credentials, private loopback TLS material and authentication/configuration
hashes must not be uploaded. Ephemeral signing keys remain in memory; the
production signing Environment is not used.

The receipt explicitly records `publicReleaseEvidence: false`. This rehearsal
does not replace staging publication receipts or post-publish acceptance,
and does not unlock the production-readiness gate. Actual public update and
rollback acceptance requires two distinct public managed versions; a
first-release install or same-version update cannot prove that lifecycle.

## Release Order

Use this order so a partial release has a clear recovery point.

1. Verify the candidate.
   Run the release verification workflow for `vX.Y.Z`. Confirm the produced
   archive SHA-256, inventory SHA-256, source commit, workflow run, Python
   wheel/sdist hashes, OCI digest, SCIE executable hashes, SBOM, provenance,
   and managed metadata signatures.

2. Cross the `production-release` signing-key custody boundary.
   Only the protected signing job may read
   `XFERRY_RELEASE_ED25519_PRIVATE_KEY_PEM`. It signs already-built managed
   manifests and installers, uploads signed artifacts for downstream jobs, and
   does not publish to PyPI, GHCR, GitHub Releases, or Pages.
   `release-production` publisher jobs receive only signed artifacts, recorded
   digests, and the approval dependency; they must not receive or export the
   private key.

3. Create the signed draft GitHub Release.
   Under the secret-free `release-production` publication boundary, create a
   draft Release for `vX.Y.Z` from the signed candidate assets. Keep it draft
   while PyPI and GHCR are verified. Download the draft assets and verify
   signatures, hashes, inventory identity, and tamper rejection.

4. Publish PyPI.
   Under `release-production`, publish the exact wheel and sdist through OIDC
   trusted publishing. Do not use a static API token, skip-existing, or a
   rebuild. Verify the accepted file hashes against the candidate inventory.
   Run exact-version pipx smoke on Windows, macOS, and Linux.

5. Publish GHCR.
   Under `release-production`, copy the exact OCI candidate to the version tag
   and record the resulting digest. Pull by digest on `linux/amd64` and
   `linux/arm64`, inspect the multi-architecture manifest, and run the
   container smoke with the recorded digest.

6. Make the GitHub Release public.
   Still under `release-production`, publish the GitHub Release without
   replacing assets only after PyPI and GHCR checks pass. Release notes must
   record the tag, commit, workflow run, candidate archive SHA-256, inventory
   SHA-256, PyPI file hashes, GHCR digest, signed asset hashes, signing key ID,
   and rollback instructions.

7. Run post-publish managed checks.
   On every supported managed host pair, verify install, setup, status, doctor,
   exact-version update, health, rollback, and conservative uninstall. Keep
   host, architecture, version, digest, and log receipt links with the release.

8. Prepare separate Pages publication.
   The current production workflow does not deploy Pages. Publish public
   documentation only after all public artifacts exist and the post-publish
   checks pass. Dispatch `Documentation Pages` on `main` with `production_run`
   set to that completed Production Release run ID. Its read-only gate checks
   the successful run and all consumer jobs, signed public assets, exact PyPI
   bytes, and anonymous GHCR access before the protected `github-pages`
   deployment job receives its Pages permissions. The release source must
   match `main`, or differ only by documentation changes. Remove the staged
   availability notices only after these public checks pass. No signing secret
   is used by the documentation workflow.

## Post-Publish Evidence

Attach or link these receipts to the release notes or release report:

- GitHub Actions run URL and attempt.
- Release commit SHA and tag object or protected tag evidence.
- Candidate archive SHA-256 and inventory SHA-256.
- PyPI wheel and sdist filenames, sizes, and SHA-256 hashes.
- GHCR version tag, digest, platform manifest, SBOM, and provenance evidence.
- GitHub Release URL, asset names, sizes, SHA-256 hashes, signatures, and
  `--latest=false` or equivalent evidence.
- Managed host matrix results for install, update, rollback, and uninstall.
- Pages deployment URL and commit SHA, when a separate docs publication has
  run.

## Rollback

Rollback uses a previously verified exact version or digest. It never rebuilds
an old tag and never switches to a mutable alias.

- Portable: notify users to install the previous exact version with pipx after
  the current version is yanked or withdrawn according to the incident matrix.
- Container: notify operators to pin the previous recorded digest.
- Managed Linux: use `sudo xferry rollback` or
  `sudo xferry rollback --to X.Y.Z` after confirming the target remains trusted.
- Documentation: mark the affected version withdrawn, keep evidence public, and
  point operators to the retained recovery version.

## No-Go Outcomes

When a gate fails before any external publication, stop the workflow, preserve
logs and artifacts, and do not create the production tag again until the
underlying failure has a new reviewed fix. When a gate fails after one channel
is public, follow [Incident response](incident-response.md).
