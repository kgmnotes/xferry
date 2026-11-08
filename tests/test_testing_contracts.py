"""Testing builds never inherit production origins, identities or signing policy."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from dataclasses import replace

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from xferry.management import channels, versions
from xferry.management.release_contract import ReleaseManifest, artifact_name, require_build_id
from xferry.management.release_trust import (
    DEFAULT_RELEASE_KEY_RING,
    DEFAULT_TESTING_KEY_RING,
    MANIFEST_SIGNATURE_TYPE,
    TESTING_MANIFEST_SIGNATURE_TYPE,
    TESTING_SIGNING_KEY_ID,
    ReleaseKeyRing,
    ReleaseTrustError,
    TrustedReleaseKey,
    create_detached_signature,
    parse_signed_manifest,
    verify_manifest_signature,
    verify_signed_manifest,
)


@pytest.fixture
def signing():
    signer = Ed25519PrivateKey.generate()
    ring = ReleaseKeyRing(
        [
            TrustedReleaseKey(
                key_id="testing-unit",
                public_key=signer.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw),
            )
        ]
    )
    return signer, ring


def _testing_manifest(**overrides) -> ReleaseManifest:
    options = {
        "version": "0.5.1.dev123001",
        "platform": "linux-x86_64",
        "executable_size": 12,
        "executable_sha256": "a" * 64,
        "source_commit": "b" * 40,
        "workflow_run": "123",
        "build_id": "123.1",
        "artifact_digests": {
            "xferry-0.5.1.dev123001-linux-x86_64": "a" * 64,
            "install-linux-x86_64.sh": "c" * 64,
        },
        "signing_key_ids": ["testing-unit"],
    }
    options.update(overrides)
    return ReleaseManifest.create_v3(**options)


def signed_testing(signing):
    signer, ring = signing
    manifest = _testing_manifest()
    payload = manifest.to_bytes()
    signature = create_detached_signature(
        payload,
        payload_type=TESTING_MANIFEST_SIGNATURE_TYPE,
        key_id="testing-unit",
        signer=signer,
    )
    return manifest, payload, signature, ring


@pytest.mark.parametrize("version", ["0.5.1.dev0", "0.5.1.dev1", "0.5.1.dev123001"])
def test_canonical_testing_versions_are_explicitly_separate(version):
    assert versions.is_testing_version(version)
    assert versions.is_package_version(version)
    assert not versions.is_canonical_release_version(version)
    assert not versions.is_supported_release_version(version)
    assert channels.validate_version_for_channel(version, "testing") == version
    with pytest.raises(ValueError, match="stable version"):
        channels.validate_version_for_channel(version)


@pytest.mark.parametrize(
    "version",
    [
        None,
        [],
        True,
        "",
        "0.5.dev1",
        "0.05.1.dev1",
        "0.5.1.dev01",
        "0.5.1.dev",
        "0.5.1rc1",
        "0.5.1.dev1+local",
    ],
)
def test_malformed_or_noncanonical_testing_versions_are_rejected(version):
    assert not versions.is_testing_version(version)
    with pytest.raises(ValueError):
        channels.validate_version_for_channel(version, "testing")


@pytest.mark.parametrize(
    ("older", "newer"),
    [
        ("0.5.0", "0.5.1.dev1"),
        ("0.5.1.dev9", "0.5.1.dev10"),
        ("0.5.1.dev123001", "0.5.1.dev123002"),
        ("0.5.1.dev1000", "0.5.1-rc.1"),
        ("0.5.1.dev1000", "0.5.1"),
        ("0.5.1.dev1", "0.6.0.dev1"),
    ],
)
def test_testing_version_order_can_identify_real_upgrades_and_downgrades(older, newer):
    assert versions.compare_release_versions(older, newer) == -1
    assert versions.compare_release_versions(newer, older) == 1
    assert versions.compare_release_versions(older, older) == 0


def test_packaged_dev_version_can_start_the_actual_management_cli():
    code = """
import importlib
from xferry import config
from xferry.management import versions
config.__version__ = '0.5.1.dev123001'
importlib.reload(versions)
from xferry.management.cli import main
raise SystemExit(main(['--version']))
"""
    result = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, check=False
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "xferry 0.5.1.dev123001"


@pytest.mark.parametrize("value", [None, [], {}, True, "preview", "Testing", ""])
def test_unknown_channel_cannot_choose_a_download_origin(value):
    with pytest.raises(ValueError, match="stable or testing"):
        channels.normalize_channel(value)


def test_channel_origins_never_fall_back_to_production():
    version = "0.5.1.dev123001"
    assert channels.release_tag(version, "testing") == f"testing-v{version}"
    assert channels.manifest_url(version, "linux-aarch64", "testing") == (
        f"https://github.com/kgmnotes/xferry/releases/download/testing-v{version}/"
        "xferry-release-linux-aarch64.json"
    )
    assert channels.image_reference(version, "testing") == (
        f"ghcr.io/kgmnotes/xferry-testing:v{version}"
    )
    assert channels.release_tag("0.5.0") == "v0.5.0"
    assert channels.image_reference("0.5.0") == "ghcr.io/kgmnotes/xferry:v0.5.0"
    with pytest.raises(ValueError):
        channels.release_tag(version)
    with pytest.raises(ValueError):
        channels.image_reference("0.5.0", "testing")
    with pytest.raises(ValueError):
        channels.manifest_url(version, "windows-x86_64", "testing")


@pytest.mark.parametrize(
    "url",
    ["http://example.test", "https://example.test/?secret=value", "https://example.test/#fragment"],
)
def test_manifest_sources_do_not_accept_insecure_or_ambiguous_urls(url):
    with pytest.raises(ValueError, match="HTTPS base"):
        channels.manifest_url("0.5.0", "linux-x86_64", base_url=url)


def test_v3_identity_survives_canonical_serialization_and_artifact_naming():
    manifest = _testing_manifest()
    payload = manifest.to_bytes()
    assert ReleaseManifest.parse(payload) == manifest
    assert ReleaseManifest.parse_new(payload) == manifest
    assert manifest.channel == "testing"
    assert manifest.build_id == "123.1"
    assert manifest.tag == f"testing-v{manifest.version}"
    assert artifact_name(manifest.version, manifest.platform) == manifest.executable_name
    assert list(json.loads(payload))[-2:] == ["channel", "build_id"]


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("channel", "stable"),
        ("channel", "preview"),
        ("build_id", "123"),
        ("build_id", "124.1"),
        ("build_id", "123.0"),
        ("build_id", "0123.1"),
        ("tag", "v0.5.1.dev123001"),
        ("schema_version", 4),
    ],
)
def test_testing_metadata_rejects_cross_channel_or_unbound_identity(field, value):
    document = json.loads(_testing_manifest().to_bytes())
    document[field] = value
    with pytest.raises(ValueError, match="invalid release manifest"):
        ReleaseManifest.parse(json.dumps(document).encode())


def test_stable_v2_remains_unchanged_and_cannot_smuggle_testing_metadata():
    manifest = ReleaseManifest.create_v2(
        version="0.5.0",
        platform="linux-x86_64",
        executable_size=12,
        executable_sha256="a" * 64,
        source_commit="b" * 40,
        workflow_run="123",
    )
    assert manifest.channel == "stable" and manifest.build_id is None
    document = json.loads(manifest.to_bytes())
    assert "channel" not in document and "build_id" not in document
    assert ReleaseManifest.parse(manifest.to_bytes()) == manifest
    document["channel"] = "testing"
    with pytest.raises(ValueError):
        ReleaseManifest.parse(json.dumps(document).encode())
    with pytest.raises(ValueError):
        ReleaseManifest.create_v2(
            version="0.5.1.dev1",
            platform="linux-x86_64",
            executable_size=12,
            executable_sha256="a" * 64,
            source_commit="b" * 40,
            workflow_run="123",
        )


def test_signed_testing_manifest_requires_explicit_opt_in(signing):
    manifest, payload, signature, ring = signed_testing(signing)
    assert verify_signed_manifest(payload, signature, key_ring=ring, channel="testing") == manifest
    with pytest.raises(ReleaseTrustError, match="release_channel_mismatch"):
        verify_signed_manifest(payload, signature, key_ring=ring)
    with pytest.raises(ReleaseTrustError, match="release_channel_mismatch"):
        parse_signed_manifest(payload)
    with pytest.raises(ReleaseTrustError, match="release_channel_mismatch"):
        verify_manifest_signature(payload, manifest, signature, key_ring=ring)


def test_production_manifest_cannot_enter_testing_with_a_production_signature(signing):
    signer, ring = signing
    manifest = ReleaseManifest.create_v2(
        version="0.5.0",
        platform="linux-x86_64",
        executable_size=12,
        executable_sha256="a" * 64,
        source_commit="b" * 40,
        workflow_run="123",
        signing_key_ids=["testing-unit"],
    )
    payload = manifest.to_bytes()
    signature = create_detached_signature(
        payload, payload_type=MANIFEST_SIGNATURE_TYPE, key_id="testing-unit", signer=signer
    )
    assert verify_signed_manifest(payload, signature, key_ring=ring) == manifest
    with pytest.raises(ReleaseTrustError, match="release_channel_mismatch"):
        verify_signed_manifest(payload, signature, key_ring=ring, channel="testing")


def test_signatures_bind_channel_domain_source_and_actual_public_key(signing):
    manifest, payload, signature, ring = signed_testing(signing)
    changed = replace(manifest, source_commit="d" * 40).to_bytes()
    with pytest.raises(ReleaseTrustError, match="release_signature_invalid"):
        verify_signed_manifest(changed, signature, key_ring=ring, channel="testing")
    other = Ed25519PrivateKey.generate()
    wrong_ring = ReleaseKeyRing(
        [
            TrustedReleaseKey(
                "testing-unit", other.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
            )
        ]
    )
    with pytest.raises(ReleaseTrustError, match="release_signature_invalid"):
        verify_signed_manifest(payload, signature, key_ring=wrong_ring, channel="testing")
    wrong_domain = create_detached_signature(
        payload, payload_type=MANIFEST_SIGNATURE_TYPE, key_id="testing-unit", signer=signing[0]
    )
    with pytest.raises(ReleaseTrustError, match="release_signature_invalid"):
        verify_signed_manifest(payload, wrong_domain, key_ring=ring, channel="testing")


def test_default_channel_trust_roots_are_separate(signing):
    assert channels.key_ring_for_channel() is DEFAULT_RELEASE_KEY_RING
    assert channels.key_ring_for_channel("testing") is DEFAULT_TESTING_KEY_RING
    assert DEFAULT_RELEASE_KEY_RING.get(TESTING_SIGNING_KEY_ID) is None
    assert DEFAULT_TESTING_KEY_RING.get("xferry-release-2026-09") is None
    _manifest, payload, signature, _ring = signed_testing(signing)
    with pytest.raises(ReleaseTrustError, match="release_signing_key_unknown"):
        verify_signed_manifest(payload, signature, channel="testing")


@pytest.mark.parametrize("build_id", ["0.1", "1.0", "01.1", "1.01", "1.1.extra", "local", None])
def test_invalid_build_identity_cannot_be_written_to_manifest(build_id):
    with pytest.raises(ValueError, match="invalid testing build identity"):
        require_build_id(build_id)


def test_unsigned_testing_artifacts_are_not_accepted_as_downloads():
    payload = _testing_manifest(signing_key_ids=[]).to_bytes()
    with pytest.raises(ReleaseTrustError, match="release_manifest_unsigned"):
        parse_signed_manifest(payload, channel="testing")


def _image_catalog(**overrides):
    document = {
        "schema": 1,
        "channel": "testing",
        "version": "0.5.1.dev123001",
        "source_commit": "b" * 40,
        "build_id": "123.1",
        "image": "ghcr.io/kgmnotes/xferry-testing@sha256:" + "d" * 64,
    }
    document.update(overrides)
    return (json.dumps(document, indent=2) + "\n").encode()


def _manifest_for_catalog(payload):
    manifest = _testing_manifest()
    digests = dict(manifest.artifact_digests)
    digests[channels.TESTING_IMAGES_NAME] = hashlib.sha256(payload).hexdigest()
    return replace(manifest, artifact_digests=tuple(sorted(digests.items())))


def test_docker_catalog_returns_only_the_image_authenticated_by_the_build_manifest():
    payload = _image_catalog()
    manifest = _manifest_for_catalog(payload)
    assert channels.parse_testing_images(payload, manifest) == (
        "ghcr.io/kgmnotes/xferry-testing@sha256:" + "d" * 64
    )
    with pytest.raises(ValueError, match="invalid testing image catalog"):
        channels.parse_testing_images(payload.replace(b"dddd", b"eeee", 1), manifest)
    with pytest.raises(ValueError, match="invalid testing image catalog"):
        channels.parse_testing_images(payload, _testing_manifest())
    with pytest.raises(ValueError, match="invalid testing image catalog"):
        channels.parse_testing_images(payload, replace(manifest, channel="stable"))


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("schema", True),
        ("schema", 2),
        ("channel", "stable"),
        ("version", "0.5.1.dev123002"),
        ("source_commit", "e" * 40),
        ("build_id", "123.2"),
        ("image", "ghcr.io/kgmnotes/xferry@sha256:" + "d" * 64),
        ("image", "ghcr.io/kgmnotes/xferry-testing:v0.5.1.dev123001"),
        ("image", "ghcr.io/other/xferry-testing@sha256:" + "d" * 64),
        ("image", "ghcr.io/kgmnotes/xferry-testing@sha256:" + "D" * 64),
        ("image", None),
        ("extra", "ignored metadata must be rejected"),
    ],
)
def test_signed_catalog_cannot_claim_another_source_build_or_repository(field, value):
    payload = _image_catalog(**{field: value})
    with pytest.raises(ValueError, match="invalid testing image catalog"):
        channels.parse_testing_images(payload, _manifest_for_catalog(payload))


@pytest.mark.parametrize(
    "kind", ["duplicate", "noncanonical", "missing", "invalid-utf8", "oversize"]
)
def test_catalog_encoding_is_unambiguous_and_bounded(kind):
    payload = _image_catalog()
    if kind == "duplicate":
        payload = payload.replace(b'"schema": 1,', b'"schema": 1, "schema": 1,')
    elif kind == "noncanonical":
        payload = payload.rstrip()
    elif kind == "missing":
        document = json.loads(payload)
        document.pop("source_commit")
        payload = json.dumps(document).encode()
    elif kind == "invalid-utf8":
        payload = b"\xff"
    else:
        payload = b" " * (channels.MAX_TESTING_IMAGES_BYTES + 1)
    with pytest.raises(ValueError, match="invalid testing image catalog"):
        channels.parse_testing_images(payload, _manifest_for_catalog(payload))
