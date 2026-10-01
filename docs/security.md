<!-- Generated from ../SECURITY.md by tools/sync_docs.py. Edit SECURITY.md and rerun the sync tool. -->

# Security Policy

## Scope

`xferry` is a controlled security-testing tool, not a hardened multi-tenant
service. Use it only with explicit authorization and test data. Binding to a
public address, enabling TLS, or adding Basic Auth does not by itself make an
internet-facing deployment safe.

The supported user journeys are portable pipx, managed Linux, and immutable
container distribution. Select an exact version or digest, keep lifecycle
ownership with that channel, and use a reviewed source checkout only for
contributor work.

## Report a vulnerability

Do not open a public issue. Create a
[private GitHub Security Advisory](https://github.com/kgmnotes/xferry/security/advisories/new)
with the affected version, configuration, reproduction steps, and expected
impact. Do not include live credentials or user data.

Reports are handled on a best-effort basis. We usually acknowledge a report
within three working days and provide an initial assessment within seven.

## External exposure baseline

Before exposing xferry outside a trusted network, provide all of the following:

1. TLS with a hostname clients verify.
2. Strong Basic Auth read from a permission-restricted file.
3. A firewall or reverse proxy with finite connection, header, body, and
   timeout limits.
4. Finite upload, note, and temporary-artifact quotas, plus a free-space
   reserve or external hard quota.
5. An explicit request-Host allowlist matching every certificate and gateway
   authority. Do not treat CORS origins as request authorities.
6. Exact allowed browser origins. Wildcard CORS permits read-only requests and
   does not authorize mutations.
7. Proxy-side per-client throttling when the direct TCP peer is a proxy.
8. Process or container resource limits, logs, and monitoring.
9. Backups and a tested recovery procedure for operator-owned state.
10. Test data or data the operator is explicitly permitted to handle.

The [public deployment guide](public-direct.md) turns this baseline into a
configuration procedure.

## Security boundaries

- `local` and `local-secure` are intended for loopback or trusted-local use.
- `public-direct` enables strict configuration validation, but presets do not
  add or remove HTTP methods.
- Basic Auth credentials travel with every request and require TLS on an
  untrusted network.
- The runtime identifies the direct accepted-socket peer. Forwarding headers do
  not establish client identity or a loopback boundary.
- Every HTTP/1.1 request must carry one valid admitted `Host`; HTTP/1.0 may omit
  it. Duplicate or folded security fields fail before authentication, routing,
  CORS, or WebSocket handling. A valid but unapproved authority receives 421.
- Configure request authorities with `[security] allowed_hosts`,
  `XFERRY_ALLOWED_HOSTS`, or repeatable `--allowed-host`. CORS is independent
  and never expands this allowlist.
- Each active WebSocket occupies one worker.
- Request-body admission limits are not a process memory ceiling.
- Filesystem quotas assume the operator controls other writers to the data
  directory.
- A generated SMUGGLE URL is one-shot. A scanner, preloader, or `HEAD` request
  can consume it first.
- ACME account keys and certificate private keys are secrets.

## Release and update supply chain

ADR-011 defines a controlled-distribution architecture. Public artifacts are
promoted from one verified candidate, never rebuilt by a publisher, and remain
unadvertised until the protected production activation completes.

Release tags, workflow definitions, publisher identities, candidate artifacts,
digests, manifests, checksums, SBOMs, provenance, signing identities, registry
records, installer metadata, and update metadata are security-sensitive assets.
The release boundary also includes GitHub-hosted runners, protected repository
environments, PyPI, GHCR, GitHub Releases, the signing service, installers, and
update clients.

The following controls govern every future publisher:

1. Only a protected `vX.Y.Z` tag may authorize production publication. Branch
   and pull-request workflows cannot reach a production publisher.
2. The tagged version must match the source, package, changelog, and manifest
   versions. Build jobs create one candidate; publisher jobs promote those exact
   verified bytes or OCI digests and never rebuild them.
3. External actions use full commit-SHA pins. Workflow permissions default to
   read-only, with channel-specific write scopes granted only to a publisher job
   behind the protected `production` environment and required review.
4. PyPI uses OIDC trusted publishing and never a static API token. Registry,
   release, attestation, and signing credentials are short-lived and scoped to
   the one job and environment that need them wherever the service supports it.
5. Published versions are immutable. Installation, update, and rollback select
   an exact version or digest rather than a mutable convenience label.
6. Installers and update clients verify the signed metadata, artifact digest,
   release identity, trusted key, and downgrade policy before replacing a
   working installation. Verification fails closed.

Designated release maintainers own signing-key custody, rotation, revocation,
and recovery. Private signing material must stay outside the repository,
ordinary build jobs, artifacts, and logs. Reviewed verifier trust roots and key
rotation metadata belong in the repository; an independent protected-environment
approval gates access to the signing identity. A compromise stops promotion,
revokes or yanks affected releases where supported, rotates identities, and
publishes updated trust or revocation metadata before release work resumes.

### Signed release metadata contract

Remote managed releases use platform-specific manifest schema v2 plus detached
`xferry-release-linux-ARCH.json.sig` envelopes. Installed metadata retains the
local names `xferry-release.json` and `xferry-release.json.sig`. Signed bytes are
exactly the UTF-8 bytes
emitted by `ReleaseManifest.to_bytes()`: fixed field order, two-space JSON
indentation, lexically sorted artifact digests, and one trailing newline. A
signed manifest declares `ed25519` and exactly one lowercase key ID. The
detached envelope fixes its schema, algorithm, payload type, key ID, and base64
signature; signature input is domain-separated and binds both the payload type
and key ID. Semantically equivalent but non-canonical JSON is rejected.

The signed fields include the exact version and tag, platform-specific artifact
name, byte size, SHA-256 digest, source commit, workflow run, and complete
declared artifact-digest map. The client authenticates those fields before it
derives or downloads an executable URL. HTTPS and redirect policy, byte size,
SHA-256, platform/version admission, downgrade prevention, config validation,
health checks, and automatic rollback remain additional mandatory controls.

The embedded public-key ring supports two active keys during a planned
rotation. Each manifest still selects one signer: artifacts signed by either
active key verify during the overlap. After cutover, mark the old key
`REVOKED`; its signatures then fail with `release_signing_key_revoked`. Removing
an ID makes it unknown and fails with `release_signing_key_unknown`. Do not
remove or revoke the old key until every still-supported artifact has been
re-signed or retired. A revoked release is never an eligible signed rollback
target.

The initial production key is enrolled with the following reviewed record:

- key ID: `xferry-release-2026-09`;
- raw public key (hex):
  `4fe9ccd46e154ff6d866957995395993a584f50c80e3384d5db4068791684efc`;
- raw-public-key SHA-256 fingerprint:
  `e5e2e0f8bc8e051c540edea2ff5e0570c22876485c3f1cb6c3fd668a02b54859`;
- private-key custody: GitHub Environment `production-release`, secret
  `XFERRY_RELEASE_ED25519_PRIVATE_KEY_PEM`;
- environment protection: required reviewer `kgmnotes`, admin bypass disabled;
- rotation and revocation owner: `kgmnotes`.

The matching environment variable `XFERRY_RELEASE_SIGNING_KEY_ID` carries the
non-secret key ID. Test suites generate separate disposable keys in memory;
test keys must never enter the production ring.

`production-release` is the private signing-key boundary. It is deliberately
separate from the `production` publisher-approval environment required by
ADR-011. Later release jobs may pass only signed artifacts and recorded digests
between those boundaries; they must never pass or export private key material.
Before any workflow is allowed to consume the signing secret, its environment
ref policy must be restricted to the reviewed release workflow and authorized
release refs.

If the signing identity may be compromised, stop every release and promotion
job, preserve the workflow and artifact evidence, and disable use of the
environment secret. Mark the affected public key `REVOKED` in the shipped ring,
publish an advisory and withdraw or deprecate affected artifacts without
deleting evidence, then create a new protected identity and ship its reviewed
public key before release work resumes. Planned rotation may use a two-active-key
overlap; suspected compromise must not. Loss of the environment secret is
recovered by rotation, never by copying private material into the repository or
logs.

The signing helper reads an Ed25519 private key only from a permission-restricted
path or an already-protected file descriptor. It signs already-built canonical
manifest or installer bytes, never rebuilds artifacts, and never prints private
material. Release automation must sign both `xferry-release.json` and
`install.sh` at the protected signing boundary.

### Privileged installer verification order

The required shape is download, offline verification with the shipped
public-key ring, and only then explicit privileged execution. For x86_64, use:

```console
curl --proto '=https' --proto-redir '=https' --fail --silent --show-error \
  --remote-name "$release_url/xferry-release-linux-x86_64.json"
curl --proto '=https' --proto-redir '=https' --fail --silent --show-error \
  --remote-name "$release_url/xferry-release-linux-x86_64.json.sig"
curl --proto '=https' --proto-redir '=https' --fail --silent --show-error \
  --remote-name "$release_url/install-linux-x86_64.sh"
curl --proto '=https' --proto-redir '=https' --fail --silent --show-error \
  --remote-name "$release_url/install-linux-x86_64.sh.sig"
python tools/verify_release_signature.py \
  --manifest xferry-release-linux-x86_64.json \
  --signature xferry-release-linux-x86_64.json.sig
python tools/verify_release_signature.py \
  --installer install-linux-x86_64.sh \
  --signature install-linux-x86_64.sh.sig
sudo sh ./install-linux-x86_64.sh
```

Run the verifier from a reviewed checkout. Never stream a network response into
a shell, and never use
`curl | sudo sh`: the installer is itself part of the root trust chain.

## Payloads and notes

Advanced upload and SMUGGLE support `none`, XOR, and AES payload modes. XOR is
compatibility obfuscation, not confidentiality. AES uses the documented
AES-256-GCM format and fails closed; it never falls back to XOR. Use TLS for
transport confidentiality.

Secure Notepad stores ciphertext and metadata, but the server does not retain
the client-derived AES key. Losing the client session key makes an existing
note unrecoverable even when the server data directory survives.

See the [threat model](threat-model.md) for assets, trust boundaries, and
out-of-scope threats.
