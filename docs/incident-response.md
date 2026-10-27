# Release Incident Response

This document is for non-destructive production tabletop and recovery. It
preserves evidence, stops further promotion, and communicates exact operator
actions. It does not authorize deleting release evidence or copying private
signing material out of `production-release`.

## First Response

1. Cancel the release run and stop remaining jobs promptly. Reject any pending
   `production-release` signer approval. After signing is approved, publication
   continues automatically; there are no `release-production` approvals to hold.
2. Preserve workflow logs, candidate artifacts, release inventories, PyPI file
   metadata, GHCR digests, GitHub Release assets, Pages deployment records, and
   operator reports.
3. Identify the affected version, source commit, workflow run, channels, and
   signing key ID.
4. Decide whether the incident is channel-specific, multi-channel, or
   signing-key related.
5. Publish an operator notice with the exact affected version or digest and the
   safe rollback target.

## Partial Release Recovery Matrix

| State | Stop next | Recovery action | Operator message |
| --- | --- | --- | --- |
| Candidate verified, nothing public | Reject the `production-release` signer approval, or cancel the run if already approved | Fix the candidate or workflow, then start a new release from a new reviewed commit | No public action required |
| Signed assets exist, no channel public | Cancel the run before automatic publishers continue | Revoke the draft signing attempt if needed, keep artifacts as internal evidence, and rerun only after review | No public action required |
| PyPI public, GHCR and Release still private | Cancel remaining GHCR and Release jobs | Yank the PyPI files if the package is unsafe; otherwise leave them and finish only after go/no-go review | Portable users pin the previous exact version until notice clears |
| GHCR public, PyPI or Release incomplete | Cancel remaining publication jobs | Mark the affected digest withdrawn in release notes and operator notices; do not delete digest evidence | Container operators pin the previous recorded digest |
| Draft GitHub Release exists, not public | Cancel its activation job and keep it draft | Edit the draft notes to mark it withdrawn or delete only an unpublished draft when evidence is already preserved elsewhere | No public action required |
| Public GitHub Release exists | Stop Pages deployment | Edit the Release notes and title to state withdrawn, keep assets for evidence unless legal or platform policy requires removal | Managed operators roll back to the previous trusted version |
| Pages deployed with bad instructions | Stop further Pages deployments | Publish a corrected page that points to withdrawn status and safe rollback | Operators follow the corrected rollback notice |
| Signing key suspected compromised | Stop every publisher and signer | Disable secret use, mark the public key `REVOKED`, create a new reviewed key, and ship a new trust root before releasing again | Managed operators reject affected signed metadata; roll back only while current state and the target remain trusted, otherwise halt for reviewed trust-root recovery |

## Non-Destructive Tabletop

Run this tabletop without changing public artifacts:

1. Select a hypothetical version `vX.Y.Z` and one previous safe version.
2. Walk through the matrix row that matches the simulated failure.
3. Draft the PyPI yank reason, GHCR withdrawal notice, GitHub Release notice,
   signing-key revocation note, and operator rollback message.
4. Confirm every message includes the affected exact version or digest, the
   previous safe version or digest, and the evidence owner.
5. Confirm no step requires reading, printing, exporting, or copying
   `XFERRY_RELEASE_ED25519_PRIVATE_KEY_PEM`.
6. Confirm no step requires deleting package, registry, release, or workflow
   evidence.

Record the tabletop date, participants, simulated state, selected actions, and
open follow-up items in the release report.

## Channel Procedures

### PyPI Yank

Use yanking when the version is public but should no longer be selected by
ordinary installers. Do not upload replacement files under the same version.
Record the yanked filenames, hashes, reason, account owner, timestamp, and
post-yank JSON metadata. If the problem is only another channel, leave PyPI
untouched and document why.

### GHCR Withdrawal Without Deletion

GHCR digests are evidence. Do not delete a digest as the first response. Stop
advertising the affected digest, update release notes and operator notices to
mark it withdrawn, and direct operators to the previous recorded digest. If the
registry later supports an explicit deprecation state that preserves digest
evidence, prefer that over deletion.

### GitHub Release Withdrawal

For a draft Release, keep it draft and mark the notes withdrawn while evidence
is collected. For a public Release, edit the title and notes to say withdrawn,
list affected assets and hashes, and point to the rollback target. Do not
replace assets under the same version. Deleting a public Release is a last
resort for legal or credential-exposure reasons and requires separate owner
approval.

### Signing-Key Revocation and Rotation

Suspected private-key compromise is not a normal rotation. Stop all release
jobs, disable the existing environment secret, mark
`xferry-release-2026-09` as `REVOKED` in the reviewed public key ring, and
publish an advisory. Generate a new Ed25519 key only through the protected
custody process: private key goes directly to the `production-release`
Environment Secret, public key and fingerprint go to the repository, and
`kgmnotes` remains the rotation and revocation owner unless a new owner is
explicitly approved.

Planned rotation may temporarily ship two active public keys. Compromise
recovery must not rely on two active keys for the compromised identity.

Managed rollback authenticates both the current installed manifest and the
target against the selected local key ring. If the current signing key is
revoked, rollback fails closed before switching releases. An earlier release
signed by the same revoked key is not an independently trusted recovery target.
Halt deployment changes and obtain reviewed trust-root recovery when either
current state or the target cannot be authenticated. Do not re-enable a revoked
key, replace signed metadata, or bypass signature checks to force rollback.

### Operator Rollback Communication

Every operator notice must include:

- affected exact version or digest;
- whether portable, container, managed Linux, or docs are affected;
- previous safe exact version or digest; when no trusted target exists, say so
  instead of naming an unverified target;
- rollback command or deployment change;
- evidence link and contact owner;
- statement that no mutable alias is an approved recovery target.

Successful managed rollback requires trusted current state and an independently
still-trusted target. If that condition is not met, the operator notice must
state that rollback is blocked and direct operators to reviewed trust-root
recovery.

## Recovery Exit Criteria

Close an incident only after affected channels are marked yanked, withdrawn, or
revoked as appropriate; the previous safe version is verified; operator
communications are published; the key state is reviewed; and a new release
go/no-go is recorded for any replacement version.
