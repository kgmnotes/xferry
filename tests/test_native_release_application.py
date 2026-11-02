"""Native previews must preserve release validation through the application adapter."""

from __future__ import annotations

import json

import pytest

from tests.test_backend_lifecycle import native
from tests.test_management_releases import FakeDownloader, _manager, _remote_assets
from xferry.management.releases import ReleaseResult


@pytest.mark.parametrize("action", ["update", "rollback"])
@pytest.mark.parametrize("exit_code", [0, 6])
def test_native_release_preview_delegates_and_never_mutates_identity(
    tmp_path, monkeypatch, action, exit_code
):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "operator"))
    app, instance, runner, layout = native(tmp_path, running=True)
    manifest_before = instance.manifest.read_bytes()
    profile_before = instance.config.read_bytes()
    current_before = (layout.release_root / "current").readlink()
    calls = []

    class Releases:
        def update(self, version, dry_run):
            calls.append(("update", version, dry_run))
            return ReleaseResult(
                exit_code,
                "update_dry_run" if exit_code == 0 else "release_signature_invalid",
                version=version,
                dry_run=dry_run,
                before="0.5.0",
                target=version,
                active="0.5.0",
                rollback="not_needed",
            )

        def rollback(self, version, dry_run):
            calls.append(("rollback", version, dry_run))
            return ReleaseResult(exit_code, "rollback_dry_run", version=version, dry_run=dry_run)

    app._native_backend.release_manager = Releases()
    result = app.operate(action, instance, version="0.5.1", dry_run=True)

    assert calls == [(action, "0.5.1", True)]
    assert result.exit_code == exit_code
    assert result.details["dry_run"] is True
    assert result.details["version"] == "0.5.1"
    assert instance.manifest.read_bytes() == manifest_before
    assert instance.config.read_bytes() == profile_before
    assert (layout.release_root / "current").readlink() == current_before
    assert not layout.lock_file.exists()
    assert all(
        command[:2] not in {("systemctl", "restart"), ("systemctl", "stop")}
        for command in runner.commands
    )


@pytest.mark.parametrize("tampered", [False, True])
def test_native_update_preview_verifies_signed_metadata_before_claiming_success(
    tmp_path, monkeypatch, tampered
):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "operator"))
    app, instance, runner, layout = native(tmp_path, running=True)
    base_url = "https://releases.example.test/xferry/releases"
    assets = _remote_assets(base_url, "0.5.1", b"candidate executable")
    if tampered:
        signature_url = next(url for url in assets if url.endswith(".sig"))
        signature = json.loads(assets[signature_url])["signature"]
        corrupted = ("A" if signature[0] != "A" else "B") + signature[1:]
        assets[signature_url] = assets[signature_url].replace(
            signature.encode(), corrupted.encode()
        )
    downloader = FakeDownloader(assets)
    app._native_backend.release_manager = _manager(tmp_path, layout, downloader)
    manifest_before = instance.manifest.read_bytes()
    current_before = (layout.release_root / "current").readlink()

    result = app.operate("update", instance, version="0.5.1", dry_run=True)

    assert (result.exit_code == 0) is (not tampered), result.message
    assert result.details["dry_run"] is True
    if not tampered:
        assert result.details["code"] == "update_dry_run"
        assert result.details["before"] == result.details["active"] == "0.5.0"
        assert result.details["target"] == "0.5.1"
        assert len(downloader.read_requests) == 2
    else:
        assert result.details["code"] == "release_signature_invalid"
    assert downloader.download_requests == []
    assert instance.manifest.read_bytes() == manifest_before
    assert (layout.release_root / "current").readlink() == current_before
    assert not layout.lock_file.exists()
    assert all(command[:2] != ("systemctl", "restart") for command in runner.commands)


@pytest.mark.parametrize("action", ["update", "rollback"])
@pytest.mark.parametrize("dry_run", [False, True])
def test_native_release_rejects_pre_architecture_target_before_discovery_or_network(
    tmp_path, monkeypatch, action, dry_run
):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "operator"))
    app, instance, runner, layout = native(tmp_path, running=True)
    downloader = FakeDownloader({})
    manager = _manager(tmp_path, layout, downloader)

    def forbidden_discovery():
        pytest.fail("pre-architecture target reached managed-state discovery")

    monkeypatch.setattr(manager, "_require_supported_managed_installation", forbidden_discovery)
    app._native_backend.release_manager = manager
    manifest_before = instance.manifest.read_bytes()
    current_before = (layout.release_root / "current").readlink()

    result = app.operate(action, instance, version="0.4.9", dry_run=dry_run)

    assert result.exit_code == 2
    assert result.details["code"] == "unsupported_deployment_release"
    assert downloader.requests == []
    assert instance.manifest.read_bytes() == manifest_before
    assert (layout.release_root / "current").readlink() == current_before
    assert not layout.lock_file.exists()
    assert all(command[:2] != ("systemctl", "restart") for command in runner.commands)


@pytest.mark.parametrize("action", ["update", "rollback"])
def test_native_release_rejects_incompatible_active_installation_before_network(
    tmp_path, monkeypatch, action
):
    from tests.test_management_releases import _v2_manifest

    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "operator"))
    app, instance, _, layout = native(tmp_path, running=True)
    release = layout.release_root / "releases"
    (release / "0.5.0").rename(release / "0.4.9")
    (release / "0.4.9/xferry-release.json").write_bytes(_v2_manifest("0.4.9", b"runtime"))
    current = layout.release_root / "current"
    current.unlink()
    current.symlink_to("releases/0.4.9")
    downloader = FakeDownloader({})
    app._native_backend.release_manager = _manager(tmp_path, layout, downloader)
    manifest_before = instance.manifest.read_bytes()

    result = app.operate(action, instance, version="0.5.1", dry_run=True)

    assert result.exit_code != 0
    assert result.details["code"] in {"unsupported_managed_state", "unsupported_deployment_release"}
    assert downloader.requests == []
    assert instance.manifest.read_bytes() == manifest_before
    assert current.readlink().as_posix() == "releases/0.4.9"
    assert not layout.lock_file.exists()


def test_default_native_rollback_skips_newer_mtime_incompatible_retained_release(
    tmp_path, monkeypatch
):
    import os

    from tests.test_management_releases import _v2_manifest

    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "operator"))
    app, instance, _, layout = native(tmp_path, running=True)
    releases = layout.release_root / "releases"
    for version, timestamp in (("0.5.1", 1), ("0.4.9", 2)):
        release = releases / version
        release.mkdir(mode=0o755)
        (release / "xferry").write_bytes(b"runtime")
        (release / "xferry").chmod(0o755)
        (release / "xferry-release.json").write_bytes(_v2_manifest(version, b"runtime"))
        (release / "xferry-release.json").chmod(0o644)
        os.utime(release, ns=(timestamp, timestamp))
    downloader = FakeDownloader({})
    app._native_backend.release_manager = _manager(tmp_path, layout, downloader)
    manifest_before = instance.manifest.read_bytes()

    result = app.operate("rollback", instance, dry_run=True)

    assert result.exit_code == 0, result.message
    assert result.details["version"] == "0.5.1"
    assert result.details["code"] == "rollback_dry_run"
    assert downloader.requests == []
    assert instance.manifest.read_bytes() == manifest_before
    assert (layout.release_root / "current").readlink().as_posix() == "releases/0.5.0"
    assert not layout.lock_file.exists()
