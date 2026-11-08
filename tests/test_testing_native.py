"""Explicit testing-channel trust, immutable identity and native stable recovery."""

from __future__ import annotations

import hashlib
import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from tests.test_backend_lifecycle import native
from tests.test_management_releases import (
    _TEST_KEY_ID,
    _TEST_KEY_RING,
    _TEST_PRIVATE_KEY,
    FakeDownloader,
    FakeRunner,
    _installed_layout,
    _manager,
    _protect_managed_directory,
)
from tests.test_scie_release import (
    REPO_ROOT,
    _recording_verifier_scie,
    _run_installer,
)
from tests.test_scie_release import (
    FakeRunner as ScieRunner,
)
from tools.build_scie_release import build_release_bundle
from xferry.management import bootstrap
from xferry.management import releases as release_module
from xferry.management.model import HostFacts
from xferry.management.release_contract import ReleaseManifest
from xferry.management.release_trust import (
    INSTALLER_SIGNATURE_TYPE,
    TESTING_MANIFEST_SIGNATURE_TYPE,
    ReleaseKeyRing,
    TrustedReleaseKey,
    create_detached_signature,
)

BASE = "https://releases.example.test/xferry/releases"
SOURCE = "a" * 40
BUILD = "123456.1"


def _testing_assets(version: str, payload: bytes = b"testing executable") -> dict[str, bytes]:
    manifest = ReleaseManifest.create_v3(
        version=version,
        platform="linux-x86_64",
        executable_size=len(payload),
        executable_sha256=hashlib.sha256(payload).hexdigest(),
        source_commit=SOURCE,
        workflow_run="123456",
        build_id=BUILD,
        signing_key_ids=(_TEST_KEY_ID,),
    ).to_bytes()
    base = f"{BASE}/download/testing-v{version}"
    name = "xferry-release-linux-x86_64.json"
    return {
        f"{base}/{name}": manifest,
        f"{base}/{name}.sig": create_detached_signature(
            manifest,
            payload_type=TESTING_MANIFEST_SIGNATURE_TYPE,
            key_id=_TEST_KEY_ID,
            signer=_TEST_PRIVATE_KEY,
        ),
        f"{base}/xferry-{version}-linux-x86_64": payload,
    }


def _testing_manager(tmp_path, layout, downloader, *, runner=None):
    manager = _manager(tmp_path, layout, downloader, runner=runner)
    manager.channel = "testing"
    manager.expected_source_commit = SOURCE
    manager.expected_build_id = BUILD
    return manager


@pytest.mark.parametrize("field", ["expected_source_commit", "expected_build_id"])
def test_testing_update_rejects_cli_runtime_identity_before_download(tmp_path, field):
    layout = _installed_layout(tmp_path)
    downloader = FakeDownloader(_testing_assets("0.5.1.dev1"))
    manager = _testing_manager(tmp_path, layout, downloader)
    setattr(manager, field, "different")

    result = manager.update("0.5.1.dev1", False)

    assert result.message == "release_build_identity_mismatch"
    assert not downloader.download_requests
    assert (layout.release_root / "current").readlink().name == "0.5.0"
    assert not layout.lock_file.exists()


def test_testing_update_rejects_production_key_without_fallback(tmp_path):
    layout = _installed_layout(tmp_path)
    downloader = FakeDownloader(_testing_assets("0.5.1.dev1"))
    manager = _testing_manager(tmp_path, layout, downloader)
    other = Ed25519PrivateKey.generate()
    manager.release_key_ring = ReleaseKeyRing(
        (TrustedReleaseKey("different-key", other.public_key().public_bytes_raw()),)
    )

    result = manager.update("0.5.1.dev1", False)

    assert result.exit_code != 0
    assert not downloader.download_requests
    assert all("/testing-v" in url for url, _limit in downloader.read_requests)


def test_testing_update_cannot_use_stable_version_or_origin(tmp_path):
    layout = _installed_layout(tmp_path)
    downloader = FakeDownloader({})
    manager = _testing_manager(tmp_path, layout, downloader)

    assert manager.update("0.5.1", False).message == "release_channel_mismatch"
    assert not downloader.requests


def test_native_deployment_records_testing_identity_and_stable_receipts(tmp_path, monkeypatch):
    monkeypatch.setattr(release_module, "key_ring_for_channel", lambda _channel: _TEST_KEY_RING)
    app, instance, _runner, layout = native(tmp_path, running=True)
    manager = _testing_manager(tmp_path, layout, FakeDownloader(_testing_assets("0.5.1.dev1")))
    backend = app._native_backend
    backend.release_manager = manager

    result = backend.operate("update", instance, version="0.5.1.dev1", channel="testing")

    assert result.exit_code == 0, result
    assert instance.spec.artifact["channel"] == "testing"
    assert instance.spec.artifact["source_commit"] == SOURCE
    assert instance.spec.artifact["build_id"] == BUILD
    layout.auth_file.write_text("admin:new-preview-password\n")
    manager.channel = "stable"
    result = backend.operate("rollback", instance, channel="stable")
    assert result.exit_code == 0, result
    assert instance.spec.artifact["channel"] == "stable"
    assert layout.auth_file.read_text() == "admin:new-preview-password\n"
    from xferry.management.deployment import resource_unchanged

    assert all(resource_unchanged(item) for item in instance.spec.ownership.resources)


def test_two_testing_updates_retain_and_restore_stable_configuration(tmp_path, monkeypatch):
    monkeypatch.setattr(release_module, "key_ring_for_channel", lambda _channel: _TEST_KEY_RING)
    layout = _installed_layout(tmp_path)
    profile = layout.config_file.parent / "profile.ini"
    profile.write_text("stable profile\n")
    profile.chmod(0o644)
    layout.unit_file.parent.mkdir(parents=True)
    _protect_managed_directory(layout, layout.unit_file.parent)
    layout.unit_file.write_text("stable unit\n")
    layout.unit_file.chmod(0o644)
    stable_config = layout.config_file.read_bytes()
    stable_deployment = (layout.config_file.parent / "deployment.json").read_bytes()
    assets = {**_testing_assets("0.5.1.dev1"), **_testing_assets("0.5.1.dev2")}
    manager = _testing_manager(tmp_path, layout, FakeDownloader(assets))

    assert manager.update("0.5.1.dev1", False).exit_code == 0
    profile.write_text("preview profile\n")
    layout.config_file.write_text("[server]\nconfig_version=1\nport=9090\n")
    layout.unit_file.write_text("preview unit\n")
    assert manager.update("0.5.1.dev2", False).exit_code == 0
    assert (layout.release_root / "releases/0.5.0/xferry").is_file()
    manager.channel = "stable"

    result = manager.rollback(None, False)

    assert result.exit_code == 0, result
    assert result.version == "0.5.0"
    assert (layout.release_root / "current").readlink().name == "0.5.0"
    assert profile.read_text() == "stable profile\n"
    assert layout.unit_file.read_text() == "stable unit\n"
    assert layout.config_file.read_bytes() == stable_config
    assert (layout.config_file.parent / "deployment.json").read_bytes() == stable_deployment
    assert layout.auth_file.read_text() == "admin:known-password\n"


def test_failed_stable_rollback_restores_testing_configuration(tmp_path, monkeypatch):
    monkeypatch.setattr(release_module, "key_ring_for_channel", lambda _channel: _TEST_KEY_RING)
    layout = _installed_layout(tmp_path)
    runner = FakeRunner()
    manager = _testing_manager(
        tmp_path, layout, FakeDownloader(_testing_assets("0.5.1.dev1")), runner=runner
    )
    assert manager.update("0.5.1.dev1", False).exit_code == 0
    preview = b"[server]\nconfig_version=1\nport=9090\n"
    layout.config_file.write_bytes(preview)
    runner.restart_failures = 1
    manager.channel = "stable"

    result = manager.rollback(None, False)

    assert result.exit_code != 0
    assert (layout.release_root / "current").readlink().name == "0.5.1.dev1"
    assert layout.config_file.read_bytes() == preview


@pytest.mark.parametrize("tamper", ["mode", "content", "symlink"])
def test_stable_snapshot_tampering_blocks_rollback_before_mutation(tmp_path, monkeypatch, tamper):
    monkeypatch.setattr(release_module, "key_ring_for_channel", lambda _channel: _TEST_KEY_RING)
    layout = _installed_layout(tmp_path)
    manager = _testing_manager(tmp_path, layout, FakeDownloader(_testing_assets("0.5.1.dev1")))
    assert manager.update("0.5.1.dev1", False).exit_code == 0
    snapshot = layout.release_root / "last-stable.json"
    if tamper == "mode":
        snapshot.chmod(0o644)
    elif tamper == "content":
        value = json.loads(snapshot.read_bytes())
        value["files"]["0"]["sha256"] = "0" * 64
        snapshot.write_text(json.dumps(value))
    else:
        snapshot.unlink()
        snapshot.symlink_to(layout.config_file)
    before = layout.config_file.read_bytes()
    manager.channel = "stable"

    result = manager.rollback(None, False)

    assert result.message == "stable_snapshot_unsafe"
    assert (layout.release_root / "current").readlink().name == "0.5.1.dev1"
    assert layout.config_file.read_bytes() == before


def test_corrupt_stable_snapshot_blocks_the_next_preview_before_activation(tmp_path):
    layout = _installed_layout(tmp_path)
    downloader = FakeDownloader({**_testing_assets("0.5.1.dev1"), **_testing_assets("0.5.1.dev2")})
    manager = _testing_manager(tmp_path, layout, downloader)
    assert manager.update("0.5.1.dev1", False).exit_code == 0
    (layout.release_root / "last-stable.json").write_text("corrupt")

    result = manager.update("0.5.1.dev2", False)

    assert result.message == "stable_snapshot_unsafe"
    assert (layout.release_root / "current").readlink().name == "0.5.1.dev1"
    assert not (layout.release_root / "releases/0.5.1.dev2").exists()


def test_testing_rollback_checks_the_retained_runtime_build_identity(tmp_path):
    layout = _installed_layout(tmp_path)
    downloader = FakeDownloader({**_testing_assets("0.5.1.dev1"), **_testing_assets("0.5.1.dev2")})
    manager = _testing_manager(tmp_path, layout, downloader)
    assert manager.update("0.5.1.dev1", False).exit_code == 0
    assert manager.update("0.5.1.dev2", False).exit_code == 0
    manager.expected_build_id = "123456.2"

    result = manager.rollback("0.5.1.dev1", False)

    assert result.message == "release_build_identity_mismatch"
    assert (layout.release_root / "current").readlink().name == "0.5.1.dev2"


@pytest.mark.parametrize("mismatch", [False, True])
def test_testing_bootstrap_verifies_exact_build_before_executing(tmp_path, monkeypatch, mismatch):
    monkeypatch.setattr(bootstrap.os, "geteuid", lambda: 0)
    monkeypatch.setattr(bootstrap, "current_platform_id", lambda: "linux-x86_64")
    monkeypatch.setattr(
        "xferry.management.platform.detect_host_facts",
        lambda: HostFacts("ubuntu", "24.04", "x86_64", True, 2048, 2, 10000),
    )
    private = Ed25519PrivateKey.generate()
    ring = ReleaseKeyRing(
        (TrustedReleaseKey("testing-key", private.public_key().public_bytes_raw()),)
    )
    script = b"#!/bin/sh\nexit 0\n"
    executable = b"runtime"
    version = "0.5.1.dev1"
    name = "install-linux-x86_64.sh"
    manifest = ReleaseManifest.create_v3(
        version=version,
        platform="linux-x86_64",
        executable_size=len(executable),
        executable_sha256=hashlib.sha256(executable).hexdigest(),
        source_commit=SOURCE,
        workflow_run="123456",
        build_id=BUILD,
        signing_key_ids=("testing-key",),
        artifact_digests={
            f"xferry-{version}-linux-x86_64": hashlib.sha256(executable).hexdigest(),
            name: hashlib.sha256(script).hexdigest(),
        },
    ).to_bytes()
    base = f"https://github.com/kgmnotes/xferry/releases/download/testing-v{version}"
    downloader = FakeDownloader(
        {
            f"{base}/xferry-release-linux-x86_64.json": manifest,
            f"{base}/xferry-release-linux-x86_64.json.sig": create_detached_signature(
                manifest,
                payload_type=TESTING_MANIFEST_SIGNATURE_TYPE,
                key_id="testing-key",
                signer=private,
            ),
            f"{base}/{name}": script,
            f"{base}/{name}.sig": create_detached_signature(
                script, payload_type=INSTALLER_SIGNATURE_TYPE, key_id="testing-key", signer=private
            ),
        }
    )
    runner = FakeRunner()

    result = bootstrap.install_release(
        version,
        channel="testing",
        expected_source_commit="b" * 40 if mismatch else SOURCE,
        expected_build_id=BUILD,
        downloader=downloader,
        runner=runner,
        key_ring=ring,
    )

    assert (result.exit_code == 0) is not mismatch, result
    assert bool(runner.commands) is not mismatch
    assert all("testing-v" in url for url, _limit in downloader.read_requests)


def test_testing_shell_installer_verifies_and_persists_a_signed_v3_envelope(tmp_path):
    private = Ed25519PrivateKey.generate()
    payload = (
        _recording_verifier_scie(private.public_key().public_bytes_raw())
        .decode()
        .replace(
            'parser.add_argument("--version", required=True)',
            'parser.add_argument("--channel", required=True, choices=["testing"])\n'
            'parser.add_argument("--version", required=True)',
        )
        .replace(
            "expected_version=arguments.version,",
            "expected_version=arguments.version,\n        channel=arguments.channel,",
        )
        .encode()
    )
    version = "0.5.1.dev1"
    bundle = build_release_bundle(
        REPO_ROOT,
        tmp_path / "bundle",
        version,
        ScieRunner(payload),
        platform_id="linux-x86_64",
        source_commit=SOURCE,
        workflow_run="123456",
        signing_key_id="test-release-2026",
        require_hosted_signature=True,
        channel="testing",
        build_id=BUILD,
    )
    signature = create_detached_signature(
        bundle.manifest.read_bytes(),
        payload_type=TESTING_MANIFEST_SIGNATURE_TYPE,
        key_id="test-release-2026",
        signer=private,
    )

    result = _run_installer(
        bundle,
        tmp_path / "installed",
        payload,
        manifest_payload=bundle.manifest.read_bytes(),
        signature_payload=signature,
    )

    assert result.returncode == 0, result.stderr
    installed = tmp_path / "installed/root/opt/xferry/releases" / version
    assert (installed / "xferry-release.json").read_bytes() == bundle.manifest.read_bytes()
    assert (installed / "xferry-release.json.sig").read_bytes() == signature
    assert "--channel\ntesting\n" in (tmp_path / "installed/verifier-arguments").read_text()
