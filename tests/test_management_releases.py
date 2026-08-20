"""Verified release update, rollback, and conservative uninstall tests."""

from __future__ import annotations

import hashlib
import json
import logging
import os
import stat
import urllib.request
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from email.message import Message
from pathlib import Path

import pytest

from xferry.management import cli
from xferry.management import releases as release_module
from xferry.management.health import HealthEndpoint, HealthResult
from xferry.management.model import ManagedLayout
from xferry.management.releases import (
    HttpsDownloader,
    ReleaseManager,
    ReleaseManifest,
    ReleaseResult,
)
from xferry.management.system import CommandResult, MutationLocked, managed_mutation


def _layout(tmp_path: Path) -> ManagedLayout:
    return ManagedLayout(
        release_root=tmp_path / "opt/xferry",
        config_file=tmp_path / "etc/xferry/xferry.ini",
        auth_file=tmp_path / "etc/xferry/auth",
        data_root=tmp_path / "var/lib/xferry",
        lock_file=tmp_path / "run/lock/xferry-ops.lock",
        unit_file=tmp_path / "etc/systemd/system/xferry.service",
        cli_link=tmp_path / "usr/local/bin/xferry",
    )


def test_release_lifecycle_derives_managed_acme_state_from_the_data_root(tmp_path: Path) -> None:
    """Default uninstall state must follow the sandbox-accessible managed runtime home."""
    layout = _layout(tmp_path)

    manager = ReleaseManager(layout=layout)

    assert manager.acme_root == tmp_path / "var/lib/xferry/.xferry"


def _manifest(version: str, payload: bytes, *, platform: str = "linux-x86_64") -> bytes:
    return (
        json.dumps(
            {
                "schema_version": 1,
                "version": version,
                "tag": f"v{version}",
                "platform": platform,
                "executable": {
                    "name": f"xferry-{version}-{platform}",
                    "size": len(payload),
                    "sha256": hashlib.sha256(payload).hexdigest(),
                },
            }
        )
        + "\n"
    ).encode()


def _manifest_document(
    version: str = "0.2.0", payload: bytes = b"release-two"
) -> dict[str, object]:
    return json.loads(_manifest(version, payload))


class FakeDownloader:
    """Write fixed remote assets into the manager-provided staging directory."""

    def __init__(
        self,
        assets: dict[str, bytes | BaseException],
        *,
        before_write: Callable[[str, Path], None] | None = None,
    ) -> None:
        self.assets = assets
        self.before_write = before_write
        self.requests: list[tuple[str, Path, int]] = []

    def download(self, url: str, destination: Path, max_bytes: int) -> None:
        self.requests.append((url, destination, max_bytes))
        if self.before_write is not None:
            self.before_write(url, destination)
        value = self.assets[url]
        if isinstance(value, BaseException):
            raise value
        destination.write_bytes(value)


class FakeRunner:
    """Stateful fixed-command boundary for config checks and systemd."""

    def __init__(
        self,
        *,
        config_ok: bool = True,
        restart_failures: int = 0,
        restore_restart_failure: bool = False,
        stop_failure: bool = False,
        stop_failures: int = 0,
        active: bool = True,
        enabled: bool = True,
        state_query_results: Sequence[tuple[int, str]] = (),
        on_config: Callable[[], None] | None = None,
        on_restart: Callable[[], None] | None = None,
        on_disable: Callable[[], None] | None = None,
    ) -> None:
        self.config_ok = config_ok
        self.restart_failures = restart_failures
        self.restore_restart_failure = restore_restart_failure
        self.stop_failure = stop_failure
        self.stop_failures = stop_failures
        self.active = active
        self.enabled = enabled
        self.state_query_results = list(state_query_results)
        self.on_config = on_config
        self.on_restart = on_restart
        self.on_disable = on_disable
        self.commands: list[tuple[str, ...]] = []
        self.restart_count = 0

    def run(self, argv: Sequence[str]) -> CommandResult:
        command = tuple(str(item) for item in argv)
        self.commands.append(command)
        if command and command[-1] == "--check-config":
            if self.on_config is not None:
                self.on_config()
            return CommandResult(command, 0 if self.config_ok else 2)
        if command == ("systemctl", "restart", "xferry.service"):
            self.restart_count += 1
            if self.on_restart is not None:
                self.on_restart()
            if self.restart_failures:
                self.restart_failures -= 1
                self.active = False
                return CommandResult(command, 1)
            if self.restore_restart_failure and self.restart_count > 1:
                self.active = False
                return CommandResult(command, 1)
            self.active = True
            return CommandResult(command, 0)
        if command == (
            "systemctl",
            "show",
            "--property=ActiveState",
            "--value",
            "xferry.service",
        ):
            if self.state_query_results:
                returncode, stdout = self.state_query_results.pop(0)
                return CommandResult(command, returncode, stdout=stdout)
            state = "active" if self.active else "inactive"
            return CommandResult(command, 0, stdout=f"{state}\n")
        if command == ("systemctl", "stop", "xferry.service"):
            if self.stop_failure or self.stop_failures:
                if self.stop_failures:
                    self.stop_failures -= 1
                return CommandResult(command, 1)
            self.active = False
            return CommandResult(command, 0)
        if command == ("systemctl", "disable", "--now", "xferry.service"):
            if self.on_disable is not None:
                self.on_disable()
            self.enabled = False
            self.active = False
            return CommandResult(command, 0)
        if command == ("systemctl", "daemon-reload"):
            return CommandResult(command, 0)
        return CommandResult(command, 0)


def _seed_config(layout: ManagedLayout, password: str = "known-password") -> None:
    layout.config_file.parent.mkdir(parents=True, exist_ok=True)
    _protect_managed_directory(layout, layout.config_file.parent)
    layout.config_file.write_text("[server]\nport = 8080\n", encoding="utf-8")
    layout.auth_file.write_text(f"admin:{password}\n", encoding="utf-8")
    layout.config_file.chmod(0o644)
    layout.auth_file.chmod(0o600)


def _protect_managed_directory(layout: ManagedLayout, directory: Path) -> None:
    layout_base = layout.release_root.parents[1]
    while directory != layout_base:
        directory.chmod(0o755)
        directory = directory.parent


def _seed_release(
    layout: ManagedLayout,
    version: str,
    payload: bytes,
    *,
    verified: bool = True,
) -> Path:
    release = layout.release_root / "releases" / version
    release.mkdir(parents=True, exist_ok=True)
    _protect_managed_directory(layout, release)
    executable = release / "xferry"
    executable.write_bytes(payload)
    executable.chmod(0o755)
    if verified:
        metadata = release / "xferry-release.json"
        metadata.write_bytes(_manifest(version, payload))
        metadata.chmod(0o644)
    return release


def _set_current(layout: ManagedLayout, version: str) -> None:
    layout.release_root.mkdir(parents=True, exist_ok=True)
    current = layout.release_root / "current"
    current.unlink(missing_ok=True)
    current.symlink_to(Path("releases") / version)


def _installed_layout(tmp_path: Path) -> ManagedLayout:
    layout = _layout(tmp_path)
    _seed_config(layout)
    _seed_release(layout, "0.1.0", b"release-one")
    _set_current(layout, "0.1.0")
    return layout


def _installed_layout_at(
    tmp_path: Path, version: str = "0.1.0", payload: bytes = b"release-current"
) -> ManagedLayout:
    layout = _layout(tmp_path)
    _seed_config(layout)
    _seed_release(layout, version, payload)
    _set_current(layout, version)
    return layout


def _remote_assets(
    base_url: str,
    version: str,
    payload: bytes,
    *,
    manifest: bytes | None = None,
    latest: bool = False,
) -> dict[str, bytes]:
    tag = f"v{version}"
    manifest_url = (
        f"{base_url}/latest/download/xferry-release.json"
        if latest
        else f"{base_url}/download/{tag}/xferry-release.json"
    )
    return {
        manifest_url: manifest if manifest is not None else _manifest(version, payload),
        f"{base_url}/download/{tag}/xferry-{version}-linux-x86_64": payload,
    }


def _manager(
    tmp_path: Path,
    layout: ManagedLayout,
    downloader: FakeDownloader,
    *,
    runner: FakeRunner | None = None,
    health: Callable[[HealthEndpoint, str, str, float], HealthResult] | None = None,
    effective_uid: Callable[[], int] = lambda: 0,
) -> ReleaseManager:
    return ReleaseManager(
        layout=layout,
        runner=runner or FakeRunner(),
        downloader=downloader,
        health_check=health or (lambda *_args: HealthResult(True, "healthy")),
        effective_uid=effective_uid,
        root_uid=os.getuid(),
        release_base_url="https://releases.example.test/xferry/releases",
        platform_id=lambda: "linux-x86_64",
        unit_path=tmp_path / "etc/systemd/system/xferry.service",
        cli_link=tmp_path / "usr/local/bin/xferry",
        acme_root=layout.acme_root,
        staging_parent=tmp_path / "staging",
    )


@pytest.mark.parametrize("version", ["1.0.0", "4.1.0", "99.0.0"])
def test_explicit_update_rejects_unsupported_candidate_before_release_boundaries(
    tmp_path: Path,
    version: str,
) -> None:
    """An unsupported update must not download, stage, lock, install, or switch state."""
    layout = _installed_layout_at(tmp_path)
    downloader = FakeDownloader({})
    runner = FakeRunner()

    result = _manager(tmp_path, layout, downloader, runner=runner).update(version, False)

    assert result == ReleaseResult(2, "unsupported_release_major", version=version)
    assert downloader.requests == []
    assert not layout.lock_file.exists()
    assert (layout.release_root / "current").readlink() == Path("releases/0.1.0")
    assert runner.commands == []


@pytest.mark.parametrize("version", ["0.2", "0.02.0", "0.2.0.0", "0.2.00"])
def test_explicit_update_rejects_noncanonical_versions_before_release_boundaries(
    tmp_path: Path,
    version: str,
) -> None:
    """Noncanonical labels must not cross the release manager's network or lock boundary."""
    layout = _installed_layout_at(tmp_path)
    downloader = FakeDownloader({})
    runner = FakeRunner()

    result = _manager(tmp_path, layout, downloader, runner=runner).update(version, False)

    assert result == ReleaseResult(2, "invalid_release_version")
    assert downloader.requests == []
    assert not layout.lock_file.exists()
    assert (layout.release_root / "current").readlink() == Path("releases/0.1.0")
    assert runner.commands == []


def test_latest_update_rejects_non_0_manifest_before_candidate_download_or_lock(
    tmp_path: Path,
) -> None:
    """A non-0.x latest manifest may be inspected but must not reach candidate mutation."""
    layout = _installed_layout_at(tmp_path)
    base_url = "https://releases.example.test/xferry/releases"
    downloader = FakeDownloader(
        _remote_assets(base_url, "42.9.0", b"release-forty-two-nine", latest=True)
    )
    runner = FakeRunner()

    result = _manager(tmp_path, layout, downloader, runner=runner).update(None, False)

    assert result == ReleaseResult(2, "unsupported_release_major", version="42.9.0")
    assert [request[0] for request in downloader.requests] == [
        f"{base_url}/latest/download/xferry-release.json"
    ]
    assert not layout.lock_file.exists()
    assert (layout.release_root / "current").readlink() == Path("releases/0.1.0")
    assert not (layout.release_root / "releases/2.9.0").exists()
    assert runner.commands == []


@pytest.mark.parametrize("version", ["1.0.0", "4.1.0", "99.0.0"])
def test_explicit_rollback_rejects_unsupported_target_before_lock_restart_or_switch(
    tmp_path: Path,
    version: str,
) -> None:
    """An unsupported release must not be accepted as an explicit rollback target."""
    layout = _installed_layout_at(tmp_path)
    runner = FakeRunner()

    result = _manager(tmp_path, layout, FakeDownloader({}), runner=runner).rollback(version, False)

    assert result == ReleaseResult(2, "unsupported_release_major", version=version)
    assert not layout.lock_file.exists()
    assert (layout.release_root / "current").readlink() == Path("releases/0.1.0")
    assert runner.commands == []


@pytest.mark.parametrize(
    "operation",
    [
        "update",
        "rollback",
        "update-dry-run",
        "rollback-dry-run",
        "uninstall",
        "uninstall-dry-run",
    ],
)
def test_unsupported_managed_state_inventory_blocks_every_release_entrypoint_before_effects(
    tmp_path: Path,
    operation: str,
) -> None:
    layout = _installed_layout_at(tmp_path, "0.1.0", b"release-zero-one")
    _seed_release(layout, "99.0.0", b"unsupported-release")
    downloader = FakeDownloader({})
    runner = FakeRunner()
    manager = _manager(tmp_path, layout, downloader, runner=runner)

    if operation == "update":
        result = manager.update("0.2.0", False)
    elif operation == "rollback":
        result = manager.rollback(None, False)
    elif operation == "update-dry-run":
        result = manager.update("0.2.0", True)
    elif operation == "rollback-dry-run":
        result = manager.rollback(None, True)
    elif operation == "uninstall":
        result = manager.uninstall(False, False, False)
    else:
        result = manager.uninstall(False, False, True)

    assert result.message == "unsupported_managed_state"
    assert downloader.requests == []
    assert not layout.lock_file.exists()
    assert runner.commands == []
    assert layout.release_root.joinpath("current").readlink() == Path("releases/0.1.0")
    assert layout.release_root.joinpath("releases/99.0.0").is_dir()


def _invoke_release_entrypoint(manager: ReleaseManager, operation: str) -> ReleaseResult:
    if operation == "update":
        return manager.update("0.2.0", False)
    if operation == "rollback":
        return manager.rollback(None, False)
    if operation == "update-dry-run":
        return manager.update("0.2.0", True)
    if operation == "rollback-dry-run":
        return manager.rollback(None, True)
    if operation == "uninstall":
        return manager.uninstall(False, False, False)
    return manager.uninstall(False, False, True)


_RELEASE_ENTRYPOINTS = (
    "update",
    "rollback",
    "update-dry-run",
    "rollback-dry-run",
    "uninstall",
    "uninstall-dry-run",
)


@pytest.mark.parametrize("operation", _RELEASE_ENTRYPOINTS)
@pytest.mark.parametrize(
    "ambiguity",
    [
        "unsupported-release-a",
        "unsupported-release-b",
        "malformed-name",
        "missing-metadata",
        "version-mismatch",
        "tag-mismatch",
        "digest-mismatch",
    ],
)
def test_ambiguous_release_inventory_blocks_every_entrypoint_before_effects(
    tmp_path: Path,
    operation: str,
    ambiguity: str,
) -> None:
    layout = _installed_layout_at(tmp_path, "0.1.0", b"release-zero-one")
    releases = layout.release_root / "releases"
    ambiguous_path: Path
    if ambiguity == "unsupported-release-a":
        ambiguous_path = _seed_release(layout, "1.0.0", b"unsupported-a")
    elif ambiguity == "unsupported-release-b":
        ambiguous_path = _seed_release(layout, "4.1.0", b"unsupported-b")
    elif ambiguity == "malformed-name":
        ambiguous_path = releases / "not-a-release"
        ambiguous_path.mkdir()
        ambiguous_path.chmod(0o755)
    elif ambiguity == "missing-metadata":
        ambiguous_path = _seed_release(layout, "0.1.1", b"missing", verified=False)
    elif ambiguity == "version-mismatch":
        ambiguous_path = _seed_release(layout, "0.1.1", b"mismatch")
        ambiguous_path.joinpath("xferry-release.json").write_bytes(_manifest("0.1.2", b"mismatch"))
    elif ambiguity == "tag-mismatch":
        ambiguous_path = _seed_release(layout, "0.1.1", b"bad-tag")
        manifest_path = ambiguous_path / "xferry-release.json"
        document = json.loads(manifest_path.read_bytes())
        document["tag"] = "v0.1.2"
        manifest_path.write_text(json.dumps(document), encoding="utf-8")
    else:
        ambiguous_path = _seed_release(layout, "0.1.1", b"original")
        executable = ambiguous_path / "xferry"
        payload = executable.read_bytes()
        executable.write_bytes(bytes([payload[0] ^ 1]) + payload[1:])
        executable.chmod(0o755)

    downloader = FakeDownloader({})
    runner = FakeRunner()

    result = _invoke_release_entrypoint(
        _manager(tmp_path, layout, downloader, runner=runner), operation
    )

    assert result.message == "unsupported_managed_state"
    assert downloader.requests == []
    assert not layout.lock_file.exists()
    assert runner.commands == []
    assert layout.release_root.joinpath("current").readlink() == Path("releases/0.1.0")
    assert ambiguous_path.exists()


@pytest.mark.parametrize("operation", _RELEASE_ENTRYPOINTS)
def test_unsafe_current_blocks_every_release_entrypoint_before_effects(
    tmp_path: Path,
    operation: str,
) -> None:
    layout = _installed_layout_at(tmp_path)
    current = layout.release_root / "current"
    current.unlink()
    current.symlink_to(Path("../outside"))
    downloader = FakeDownloader({})
    runner = FakeRunner()

    result = _invoke_release_entrypoint(
        _manager(tmp_path, layout, downloader, runner=runner), operation
    )

    assert result.message == "unsupported_managed_state"
    assert downloader.requests == []
    assert not layout.lock_file.exists()
    assert runner.commands == []
    assert current.readlink() == Path("../outside")


@pytest.mark.parametrize("operation", _RELEASE_ENTRYPOINTS)
def test_unmarked_owned_path_blocks_every_release_entrypoint_before_effects(
    tmp_path: Path,
    operation: str,
) -> None:
    layout = _layout(tmp_path)
    layout.unit_file.parent.mkdir(parents=True)
    _protect_managed_directory(layout, layout.unit_file.parent)
    layout.unit_file.write_text("unmarked unit\n", encoding="utf-8")
    layout.unit_file.chmod(0o644)
    downloader = FakeDownloader({})
    runner = FakeRunner()

    result = _invoke_release_entrypoint(
        _manager(tmp_path, layout, downloader, runner=runner), operation
    )

    assert result.message == "unsupported_managed_state"
    assert downloader.requests == []
    assert not layout.lock_file.exists()
    assert runner.commands == []
    assert layout.unit_file.read_text(encoding="utf-8") == "unmarked unit\n"


def test_update_rechecks_unsupported_managed_state_inventory_under_lock_before_candidate_validation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    layout = _installed_layout(tmp_path)
    base_url = "https://releases.example.test/xferry/releases"
    downloader = FakeDownloader(_remote_assets(base_url, "0.2.0", b"release-two"))
    runner = FakeRunner()
    checks = iter((False, True))
    monkeypatch.setattr(
        release_module,
        "has_unsupported_managed_state",
        lambda _layout: next(checks),
        raising=False,
    )

    result = _manager(tmp_path, layout, downloader, runner=runner).update("0.2.0", False)

    assert result == ReleaseResult(1, "unsupported_managed_state", version="0.2.0")
    assert len(downloader.requests) == 2
    assert runner.commands == []
    assert (layout.release_root / "current").readlink() == Path("releases/0.1.0")
    assert not (layout.release_root / "releases/0.2.0").exists()


def test_rollback_rechecks_unsupported_managed_state_inventory_under_lock_before_target_selection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    layout = _installed_layout(tmp_path)
    _seed_release(layout, "0.1.1", b"release-prior")
    runner = FakeRunner()
    checks = iter((False, True))
    monkeypatch.setattr(
        release_module,
        "has_unsupported_managed_state",
        lambda _layout: next(checks),
        raising=False,
    )

    result = _manager(tmp_path, layout, FakeDownloader({}), runner=runner).rollback(None, False)

    assert result == ReleaseResult(1, "unsupported_managed_state")
    assert runner.commands == []
    assert (layout.release_root / "current").readlink() == Path("releases/0.1.0")


def test_uninstall_rechecks_unsupported_managed_state_inventory_under_lock_before_any_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    layout = _layout(tmp_path)
    unit, cli_link, _acme, _config_root = _seed_uninstall_state(tmp_path, layout)
    runner = FakeRunner()
    checks = iter((False, True))
    monkeypatch.setattr(
        release_module,
        "has_unsupported_managed_state",
        lambda _layout: next(checks),
        raising=False,
    )

    result = _manager(tmp_path, layout, FakeDownloader({}), runner=runner).uninstall(
        False, False, False
    )

    assert result == ReleaseResult(1, "unsupported_managed_state")
    assert runner.commands == []
    assert unit.is_file()
    assert cli_link.is_symlink()
    assert layout.release_root.is_dir()


@pytest.mark.parametrize(
    "document",
    [
        b"not json",
        b"[]",
        b'{"schema_version":1}',
        json.dumps(_manifest_document() | {"schema_version": 2}).encode(),
        json.dumps(_manifest_document() | {"unexpected": True}).encode(),
        json.dumps(_manifest_document() | {"tag": "v9.9.9"}).encode(),
        b'{"schema_version":1,"schema_version":1}',
    ],
)
def test_manifest_parser_rejects_malformed_or_version_mismatched_documents(
    document: bytes,
) -> None:
    """Accepting loose schemas or a mismatched tag would verify the wrong release."""
    with pytest.raises(ValueError, match="^invalid release manifest$"):
        ReleaseManifest.parse(document)


@pytest.mark.parametrize(
    "name",
    ["../xferry", "nested/xferry", r"nested\xferry", ".", "..", "/tmp/xferry"],
)
def test_manifest_parser_rejects_unsafe_or_traversal_asset_names(name: str) -> None:
    """Using an asset name as a path must never escape the isolated staging directory."""
    document = _manifest_document()
    executable = dict(document["executable"])  # type: ignore[arg-type]
    executable["name"] = name
    document["executable"] = executable

    with pytest.raises(ValueError, match="^invalid release manifest$"):
        ReleaseManifest.parse(json.dumps(document).encode())


def test_manifest_parser_accepts_the_exact_release_bundle_contract() -> None:
    """Changing Task 1's literal bundle fields must be detected by the lifecycle parser."""
    parsed = ReleaseManifest.parse(_manifest("0.2.0", b"release-two"))

    assert parsed.schema_version == 1
    assert parsed.version == "0.2.0"
    assert parsed.tag == "v0.2.0"
    assert parsed.platform == "linux-x86_64"
    assert parsed.executable_name == "xferry-0.2.0-linux-x86_64"
    assert parsed.executable_size == 11
    assert parsed.executable_sha256 == hashlib.sha256(b"release-two").hexdigest()


@pytest.mark.parametrize(
    "version",
    [
        "0.1.0",
        "0.2.0",
        "0.2.0-rc.1",
        "0.2.0+build.1",
        "1.0.0",
        "4.1.0",
        "99.0.0",
    ],
)
def test_manifest_parser_accepts_canonical_versions_for_archive_inspection(version: str) -> None:
    """Archive inspection recognizes canonical versions independent of update-major support."""
    parsed = ReleaseManifest.parse(_manifest(version, b"release-two"))

    assert parsed.version == version


@pytest.mark.parametrize("version", ["0.2", "0.02.0", "0.2.0.0", "0.2.00"])
def test_manifest_parser_rejects_noncanonical_versions(version: str) -> None:
    """Loose version labels would make manifest publication disagree with installer parsing."""
    with pytest.raises(ValueError, match="^invalid release manifest$"):
        ReleaseManifest.parse(_manifest(version, b"release-two"))


@pytest.mark.parametrize(
    ("remote_payload", "manifest_payload"),
    [(b"short", b"release-two"), (b"release-evil", b"release-two")],
)
def test_update_rejects_size_or_hash_corruption_without_opt_mutation(
    tmp_path: Path,
    remote_payload: bytes,
    manifest_payload: bytes,
) -> None:
    """A corrupt executable must never create or switch an installed release."""
    layout = _installed_layout(tmp_path)
    base_url = "https://releases.example.test/xferry/releases"
    assets = _remote_assets(base_url, "0.2.0", remote_payload)
    assets[f"{base_url}/download/v0.2.0/xferry-release.json"] = _manifest("0.2.0", manifest_payload)

    result = _manager(tmp_path, layout, FakeDownloader(assets)).update("0.2.0", False)

    assert result.exit_code == 1
    assert (layout.release_root / "current").readlink() == Path("releases/0.1.0")
    assert not (layout.release_root / "releases/0.2.0").exists()


def test_update_rejects_platform_mismatch_before_asset_download(tmp_path: Path) -> None:
    """Installing a release for another platform would fail only after damaging service state."""
    layout = _installed_layout(tmp_path)
    base_url = "https://releases.example.test/xferry/releases"
    manifest = _manifest("0.2.0", b"arm", platform="linux-aarch64")
    manifest_url = f"{base_url}/download/v0.2.0/xferry-release.json"
    downloader = FakeDownloader({manifest_url: manifest})

    result = _manager(tmp_path, layout, downloader).update("0.2.0", False)

    assert result.exit_code == 4
    assert [request[0] for request in downloader.requests] == [manifest_url]
    assert (layout.release_root / "current").readlink() == Path("releases/0.1.0")


def test_exact_update_rejects_a_manifest_for_another_requested_version(tmp_path: Path) -> None:
    """Trusting the download location instead of manifest version would install the wrong tag."""
    layout = _installed_layout(tmp_path)
    base_url = "https://releases.example.test/xferry/releases"
    manifest_url = f"{base_url}/download/v0.2.0/xferry-release.json"
    downloader = FakeDownloader({manifest_url: _manifest("0.1.0", b"release-three")})

    result = _manager(tmp_path, layout, downloader).update("0.2.0", False)

    assert result.exit_code == 1
    assert len(downloader.requests) == 1


def test_latest_update_pins_asset_to_the_manifest_exact_tag_and_stages_outside_opt(
    tmp_path: Path,
) -> None:
    """A second latest lookup or staging in /opt creates a race before verification."""
    layout = _installed_layout(tmp_path)
    base_url = "https://releases.example.test/xferry/releases"
    payload = b"release-two"
    assets = _remote_assets(base_url, "0.2.0", payload, latest=True)

    def before_download(_url: str, destination: Path) -> None:
        assert not destination.resolve().is_relative_to(layout.release_root.resolve())
        assert (layout.release_root / "current").readlink() == Path("releases/0.1.0")
        assert not (layout.release_root / "releases/0.2.0").exists()

    downloader = FakeDownloader(assets, before_write=before_download)
    result = _manager(tmp_path, layout, downloader).update(None, False)

    assert result.exit_code == 0
    assert [request[0] for request in downloader.requests] == [
        f"{base_url}/latest/download/xferry-release.json",
        f"{base_url}/download/v0.2.0/xferry-0.2.0-linux-x86_64",
    ]


def test_update_rejects_non_https_release_origin_before_network(tmp_path: Path) -> None:
    """Allowing a plaintext release origin would make manifest and checksum replacement trivial."""
    layout = _installed_layout(tmp_path)
    downloader = FakeDownloader({})
    manager = _manager(tmp_path, layout, downloader)
    manager.release_base_url = "http://releases.example.test/xferry/releases"

    result = manager.update("0.2.0", False)

    assert result == ReleaseResult(5, "release_url_unsafe", version="0.2.0")
    assert downloader.requests == []


@pytest.mark.parametrize(
    "location",
    [
        "http://assets.example.test/xferry",
        "https://user:password@assets.example.test/xferry",
        "https://assets.example.test/xferry#fragment",
    ],
)
def test_https_redirect_handler_rejects_downgrade_userinfo_and_fragment(
    location: str,
) -> None:
    """Automatic redirects must not bypass the credential-free HTTPS transport policy."""
    request = urllib.request.Request(
        "https://releases.example.test/download/v0.2.0/xferry",
        method="GET",
    )

    with pytest.raises(RuntimeError, match="release_url_unsafe"):
        release_module._HttpsRedirectHandler().redirect_request(  # type: ignore[attr-defined]
            request,
            None,
            302,
            "Found",
            Message(),
            location,
        )


@pytest.mark.parametrize(
    ("location", "expected"),
    [
        (
            "../v0.2.0/xferry",
            "https://releases.example.test/download/v0.2.0/xferry",
        ),
        (
            "https://assets.example.test/xferry?opaque-signature=1",
            "https://assets.example.test/xferry?opaque-signature=1",
        ),
    ],
)
def test_https_redirect_handler_accepts_safe_relative_and_signed_https_locations(
    location: str,
    expected: str,
) -> None:
    """Safe HTTPS redirects needed by hosted release assets must remain usable."""
    request = urllib.request.Request(
        "https://releases.example.test/download/latest/xferry",
        method="GET",
    )

    redirected = release_module._HttpsRedirectHandler().redirect_request(  # type: ignore[attr-defined]
        request,
        None,
        302,
        "Found",
        Message(),
        location,
    )

    assert redirected is not None
    assert redirected.full_url == expected


class _FakeHttpsResponse:
    def __init__(self, final_url: str, payload: bytes = b"payload") -> None:
        self.final_url = final_url
        self.payload = payload
        self.offset = 0

    def __enter__(self) -> _FakeHttpsResponse:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def geturl(self) -> str:
        return self.final_url

    def read(self, size: int) -> bytes:
        chunk = self.payload[self.offset : self.offset + size]
        self.offset += len(chunk)
        return chunk


class _FakeHttpsOpener:
    def __init__(self, final_url: str) -> None:
        self.final_url = final_url

    def open(self, _request: object, *, timeout: float) -> _FakeHttpsResponse:
        del timeout
        return _FakeHttpsResponse(self.final_url)


def test_https_downloader_rejects_an_unsafe_final_response_url(tmp_path: Path) -> None:
    """Even a custom or cached response must pass final HTTPS destination validation."""
    destination = tmp_path / "download"
    downloader = HttpsDownloader(opener=_FakeHttpsOpener("http://assets.example.test/xferry"))

    with pytest.raises(RuntimeError, match="release_url_unsafe"):
        downloader.download(
            "https://releases.example.test/download/v0.2.0/xferry",
            destination,
            100,
        )

    assert not destination.exists()


def test_candidate_config_failure_prevents_install_and_service_restart(tmp_path: Path) -> None:
    """Skipping candidate config validation would switch to an executable that cannot start."""
    layout = _installed_layout(tmp_path)
    base_url = "https://releases.example.test/xferry/releases"
    payload = b"release-two"
    downloader = FakeDownloader(_remote_assets(base_url, "0.2.0", payload))
    runner = FakeRunner(config_ok=False)

    result = _manager(tmp_path, layout, downloader, runner=runner).update("0.2.0", False)

    assert result.exit_code == 2
    assert runner.commands[0][0].startswith(str(tmp_path / "staging"))
    assert runner.commands[0][-4:] == (
        "run",
        "--config",
        str(layout.config_file),
        "--check-config",
    )
    assert not any(command[:2] == ("systemctl", "restart") for command in runner.commands)
    assert (layout.release_root / "current").readlink() == Path("releases/0.1.0")
    assert not (layout.release_root / "releases/0.2.0").exists()


def test_successful_update_atomically_switches_records_verification_and_prunes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A non-atomic link write, absent metadata, or unbounded releases breaks rollback safety."""
    layout = _installed_layout(tmp_path)
    _seed_release(layout, "0.1.1", b"release-zero")
    base_url = "https://releases.example.test/xferry/releases"
    payload = b"release-two"
    downloader = FakeDownloader(_remote_assets(base_url, "0.2.0", payload))
    replace_destinations: list[Path] = []
    real_replace = os.replace

    def observed_replace(source: str | Path, destination: str | Path) -> None:
        replace_destinations.append(Path(destination))
        real_replace(source, destination)

    monkeypatch.setattr("xferry.management.releases.os.replace", observed_replace)
    runner = FakeRunner(
        on_restart=lambda: (
            (layout.release_root / "current").readlink() == Path("releases/0.2.0")
            or pytest.fail("service restarted before current pointed at the candidate")
        )
    )

    result = _manager(tmp_path, layout, downloader, runner=runner).update("0.2.0", False)

    installed = layout.release_root / "releases/0.2.0"
    assert result == ReleaseResult(0, "update_complete", version="0.2.0")
    assert (layout.release_root / "current").readlink() == Path("releases/0.2.0")
    assert installed.joinpath("xferry").read_bytes() == payload
    assert stat.S_IMODE(installed.stat().st_mode) == 0o755
    assert installed.stat().st_uid == os.getuid()
    assert stat.S_IMODE(installed.joinpath("xferry").stat().st_mode) == 0o755
    assert stat.S_IMODE(installed.joinpath("xferry-release.json").stat().st_mode) == 0o644
    assert ReleaseManifest.parse(
        installed.joinpath("xferry-release.json").read_bytes()
    ).version == ("0.2.0")
    assert layout.release_root / "current" in replace_destinations
    assert sorted(path.name for path in (layout.release_root / "releases").iterdir()) == [
        "0.1.0",
        "0.2.0",
    ]
    assert runner.commands[-2:] == [
        ("systemctl", "restart", "xferry.service"),
        (
            "systemctl",
            "show",
            "--property=ActiveState",
            "--value",
            "xferry.service",
        ),
    ]


def test_successful_update_restores_a_confirmed_prior_inactive_service(tmp_path: Path) -> None:
    """A healthy candidate must not turn an intentionally stopped installation back on."""
    layout = _installed_layout(tmp_path)
    base_url = "https://releases.example.test/xferry/releases"
    downloader = FakeDownloader(_remote_assets(base_url, "0.2.0", b"release-two"))
    runner = FakeRunner(active=False)

    result = _manager(tmp_path, layout, downloader, runner=runner).update("0.2.0", False)

    assert result == ReleaseResult(0, "update_complete", version="0.2.0")
    assert (layout.release_root / "current").readlink() == Path("releases/0.2.0")
    assert runner.active is False
    assert ("systemctl", "stop", "xferry.service") in runner.commands


def test_successful_rollback_restores_a_confirmed_prior_inactive_service(tmp_path: Path) -> None:
    """Rollback must preserve the same stopped/running state contract as update."""
    layout = _installed_layout(tmp_path)
    _seed_release(layout, "0.2.0", b"release-two")
    _set_current(layout, "0.2.0")
    runner = FakeRunner(active=False)

    result = _manager(
        tmp_path,
        layout,
        FakeDownloader({}),
        runner=runner,
    ).rollback("0.1.0", False)

    assert result == ReleaseResult(0, "rollback_complete", version="0.1.0")
    assert (layout.release_root / "current").readlink() == Path("releases/0.1.0")
    assert runner.active is False
    assert ("systemctl", "stop", "xferry.service") in runner.commands


def test_successful_candidate_with_failed_final_stop_restores_previous_inactive_state(
    tmp_path: Path,
) -> None:
    """A failed final stop must surface while restoring the old link and stopped state safely."""
    layout = _installed_layout(tmp_path)
    base_url = "https://releases.example.test/xferry/releases"
    downloader = FakeDownloader(_remote_assets(base_url, "0.2.0", b"release-two"))
    runner = FakeRunner(active=False, stop_failures=1)

    result = _manager(tmp_path, layout, downloader, runner=runner).update("0.2.0", False)

    assert result == ReleaseResult(6, "candidate_state_restore_failed", version="0.2.0")
    assert (layout.release_root / "current").readlink() == Path("releases/0.1.0")
    assert runner.active is False


def test_successful_candidate_with_failed_final_probe_restores_previous_inactive_state(
    tmp_path: Path,
) -> None:
    """An unprovable final inactive state must fail closed and restore the previous release."""
    layout = _installed_layout(tmp_path)
    base_url = "https://releases.example.test/xferry/releases"
    downloader = FakeDownloader(_remote_assets(base_url, "0.2.0", b"release-two"))
    runner = FakeRunner(
        active=False,
        state_query_results=[
            (0, "inactive\n"),
            (0, "active\n"),
            (1, ""),
            (0, "inactive\n"),
        ],
    )

    result = _manager(tmp_path, layout, downloader, runner=runner).update("0.2.0", False)

    assert result == ReleaseResult(6, "candidate_state_restore_failed", version="0.2.0")
    assert (layout.release_root / "current").readlink() == Path("releases/0.1.0")
    assert runner.active is False


def test_same_version_update_blocks_a_tampered_inventory_before_download(tmp_path: Path) -> None:
    """A matching label cannot make tampered installed bytes safe for maintenance."""
    layout = _installed_layout(tmp_path)
    installed = layout.release_root / "releases/0.1.0/xferry"
    installed.write_bytes(b"tampered-release")
    base_url = "https://releases.example.test/xferry/releases"
    downloader = FakeDownloader(_remote_assets(base_url, "0.1.0", b"release-one"))
    runner = FakeRunner()

    result = _manager(tmp_path, layout, downloader, runner=runner).update("0.1.0", False)

    assert result == ReleaseResult(1, "unsupported_managed_state", version="0.1.0")
    assert downloader.requests == []
    assert not layout.lock_file.exists()
    assert installed.read_bytes() == b"tampered-release"
    assert runner.commands == []


def test_update_aborts_before_release_mutation_when_initial_service_state_probe_fails(
    tmp_path: Path,
) -> None:
    """An unavailable systemd state must not be guessed inactive before an update."""
    layout = _installed_layout(tmp_path)
    base_url = "https://releases.example.test/xferry/releases"
    downloader = FakeDownloader(_remote_assets(base_url, "0.2.0", b"release-two"))
    runner = FakeRunner(
        state_query_results=[(1, "")],
    )

    result = _manager(tmp_path, layout, downloader, runner=runner).update("0.2.0", False)

    assert result == ReleaseResult(1, "release_operation_failed", version="0.2.0")
    assert (layout.release_root / "current").readlink() == Path("releases/0.1.0")
    assert sorted(path.name for path in (layout.release_root / "releases").iterdir()) == ["0.1.0"]
    assert runner.restart_count == 0


def test_rollback_aborts_before_link_mutation_when_initial_service_state_probe_fails(
    tmp_path: Path,
) -> None:
    """An unavailable systemd state must not be guessed inactive before rollback."""
    layout = _installed_layout(tmp_path)
    _seed_release(layout, "0.2.0", b"release-two")
    _set_current(layout, "0.2.0")
    runner = FakeRunner(
        state_query_results=[(0, "")],
    )

    result = _manager(
        tmp_path,
        layout,
        FakeDownloader({}),
        runner=runner,
    ).rollback("0.1.0", False)

    assert result == ReleaseResult(1, "release_operation_failed", version="0.1.0")
    assert (layout.release_root / "current").readlink() == Path("releases/0.2.0")
    assert sorted(path.name for path in (layout.release_root / "releases").iterdir()) == [
        "0.1.0",
        "0.2.0",
    ]
    assert runner.restart_count == 0


def test_restart_failure_restores_link_service_health_and_removes_new_release(
    tmp_path: Path,
) -> None:
    """Leaving the failed candidate current after restart failure defeats transactional update."""
    layout = _installed_layout(tmp_path)
    base_url = "https://releases.example.test/xferry/releases"
    downloader = FakeDownloader(_remote_assets(base_url, "0.2.0", b"release-two"))
    runner = FakeRunner(restart_failures=1)
    health_versions: list[str] = []

    def health(*_args: object) -> HealthResult:
        health_versions.append((layout.release_root / "current").readlink().name)
        return HealthResult(True, "healthy")

    result = _manager(tmp_path, layout, downloader, runner=runner, health=health).update(
        "0.2.0", False
    )

    assert result.exit_code == 6
    assert result.message == "candidate_restart_failed"
    assert (layout.release_root / "current").readlink() == Path("releases/0.1.0")
    assert runner.active is True
    assert runner.restart_count == 2
    assert health_versions == ["0.1.0"]
    assert not (layout.release_root / "releases/0.2.0").exists()


def test_unhealthy_candidate_restores_and_verifies_previous_release(tmp_path: Path) -> None:
    """A health failure must restore both link and a demonstrably healthy previous service."""
    layout = _installed_layout(tmp_path)
    base_url = "https://releases.example.test/xferry/releases"
    downloader = FakeDownloader(_remote_assets(base_url, "0.2.0", b"release-two"))
    observed: list[str] = []

    def health(*_args: object) -> HealthResult:
        version = (layout.release_root / "current").readlink().name
        observed.append(version)
        return HealthResult(version == "0.1.0", "healthy" if version == "0.1.0" else "bad")

    runner = FakeRunner()
    result = _manager(tmp_path, layout, downloader, runner=runner, health=health).update(
        "0.2.0", False
    )

    assert result == ReleaseResult(6, "candidate_unhealthy", version="0.2.0")
    assert observed == ["0.2.0", "0.1.0"]
    assert runner.restart_count == 2
    assert runner.active is True
    assert (layout.release_root / "current").readlink() == Path("releases/0.1.0")


def test_update_blocks_a_current_release_with_missing_metadata_before_download(
    tmp_path: Path,
) -> None:
    """Missing metadata makes current state ambiguous before any remote release is read."""
    layout = _layout(tmp_path)
    _seed_config(layout)
    _seed_release(layout, "0.1.0", b"release-one", verified=False)
    _set_current(layout, "0.1.0")
    base_url = "https://releases.example.test/xferry/releases"
    downloader = FakeDownloader(_remote_assets(base_url, "0.2.0", b"release-two"))
    runner = FakeRunner()

    result = _manager(tmp_path, layout, downloader, runner=runner).update("0.2.0", False)

    assert result == ReleaseResult(1, "unsupported_managed_state", version="0.2.0")
    assert downloader.requests == []
    assert not layout.lock_file.exists()
    assert runner.commands == []
    assert (layout.release_root / "current").readlink() == Path("releases/0.1.0")


def test_failed_update_restores_a_previously_inactive_service_without_ping(
    tmp_path: Path,
) -> None:
    """A stopped service before update must remain stopped after candidate failure."""
    layout = _installed_layout(tmp_path)
    base_url = "https://releases.example.test/xferry/releases"
    downloader = FakeDownloader(_remote_assets(base_url, "0.2.0", b"release-two"))
    runner = FakeRunner(active=False)
    health_versions: list[str] = []

    def health(*_args: object) -> HealthResult:
        health_versions.append((layout.release_root / "current").readlink().name)
        return HealthResult(False, "candidate unhealthy")

    result = _manager(tmp_path, layout, downloader, runner=runner, health=health).update(
        "0.2.0", False
    )

    assert result == ReleaseResult(6, "candidate_unhealthy", version="0.2.0")
    assert (layout.release_root / "current").readlink() == Path("releases/0.1.0")
    assert runner.active is False
    assert health_versions == ["0.2.0"]
    assert ("systemctl", "stop", "xferry.service") in runner.commands


def test_update_reports_incomplete_restore_when_post_stop_state_probe_fails(
    tmp_path: Path,
) -> None:
    """A successful stop is insufficient when inactive state cannot be confirmed."""
    layout = _installed_layout(tmp_path)
    base_url = "https://releases.example.test/xferry/releases"
    downloader = FakeDownloader(_remote_assets(base_url, "0.2.0", b"release-two"))
    runner = FakeRunner(
        state_query_results=[(0, "inactive\n"), (0, "active\n"), (1, "")],
    )

    result = _manager(
        tmp_path,
        layout,
        downloader,
        runner=runner,
        health=lambda *_args: HealthResult(False, "candidate unhealthy"),
    ).update("0.2.0", False)

    assert result == ReleaseResult(1, "restore_incomplete", version="0.2.0")
    assert (layout.release_root / "current").readlink() == Path("releases/0.1.0")
    assert ("systemctl", "stop", "xferry.service") in runner.commands


def test_rollback_reports_incomplete_restore_when_post_stop_state_probe_fails(
    tmp_path: Path,
) -> None:
    """Rollback must not accept a stopped service whose final state probe failed."""
    layout = _installed_layout(tmp_path)
    _seed_release(layout, "0.2.0", b"release-two")
    _set_current(layout, "0.2.0")
    runner = FakeRunner(
        state_query_results=[(0, "inactive\n"), (0, "active\n"), (1, "")],
    )

    result = _manager(
        tmp_path,
        layout,
        FakeDownloader({}),
        runner=runner,
        health=lambda *_args: HealthResult(False, "candidate unhealthy"),
    ).rollback("0.1.0", False)

    assert result == ReleaseResult(1, "restore_incomplete", version="0.1.0")
    assert (layout.release_root / "current").readlink() == Path("releases/0.2.0")
    assert ("systemctl", "stop", "xferry.service") in runner.commands


def test_documented_inactive_state_is_restored_without_old_release_ping(
    tmp_path: Path,
) -> None:
    """A successful ActiveState=inactive query is confirmed inactive, not an error."""
    layout = _installed_layout(tmp_path)
    base_url = "https://releases.example.test/xferry/releases"
    downloader = FakeDownloader(_remote_assets(base_url, "0.2.0", b"release-two"))
    runner = FakeRunner(
        state_query_results=[
            (0, "inactive\n"),
            (0, "active\n"),
            (0, "inactive\n"),
        ],
    )
    health_versions: list[str] = []

    def health(*_args: object) -> HealthResult:
        version = (layout.release_root / "current").readlink().name
        health_versions.append(version)
        return HealthResult(False, "candidate unhealthy")

    result = _manager(
        tmp_path,
        layout,
        downloader,
        runner=runner,
        health=health,
    ).update("0.2.0", False)

    assert result == ReleaseResult(6, "candidate_unhealthy", version="0.2.0")
    assert (layout.release_root / "current").readlink() == Path("releases/0.1.0")
    assert runner.active is False
    assert health_versions == ["0.2.0"]
    assert ("systemctl", "stop", "xferry.service") in runner.commands


def test_failed_restoration_is_reported_as_incomplete_operation(tmp_path: Path) -> None:
    """Returning only the candidate error would conceal a broken rollback service state."""
    layout = _installed_layout(tmp_path)
    base_url = "https://releases.example.test/xferry/releases"
    downloader = FakeDownloader(_remote_assets(base_url, "0.2.0", b"release-two"))
    runner = FakeRunner(restore_restart_failure=True)

    result = _manager(
        tmp_path,
        layout,
        downloader,
        runner=runner,
        health=lambda *_args: HealthResult(False, "bad"),
    ).update("0.2.0", False)

    assert result.exit_code == 1
    assert result.message == "restore_incomplete"
    assert (layout.release_root / "current").readlink() == Path("releases/0.1.0")
    assert runner.active is False


def test_incomplete_link_restoration_never_leaves_current_dangling(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Cleanup after a failed restore must retain whichever release current still targets."""
    layout = _installed_layout(tmp_path)
    base_url = "https://releases.example.test/xferry/releases"
    downloader = FakeDownloader(_remote_assets(base_url, "0.2.0", b"release-two"))
    real_replace = os.replace
    current_switches = 0

    def fail_restore_replace(source: str | Path, destination: str | Path) -> None:
        nonlocal current_switches
        if Path(destination) == layout.release_root / "current":
            current_switches += 1
            if current_switches == 2:
                raise OSError("sanitized restore failure")
        real_replace(source, destination)

    monkeypatch.setattr("xferry.management.releases.os.replace", fail_restore_replace)
    result = _manager(
        tmp_path,
        layout,
        downloader,
        health=lambda *_args: HealthResult(False, "bad"),
    ).update("0.2.0", False)

    current = layout.release_root / "current"
    assert result == ReleaseResult(1, "restore_incomplete", version="0.2.0")
    assert current.readlink() == Path("releases/0.2.0")
    assert current.joinpath("xferry").is_file()


def test_failed_rollback_restores_a_previously_inactive_service_without_ping(
    tmp_path: Path,
) -> None:
    """Rollback candidate failure must restore the old link and stopped service state."""
    layout = _installed_layout(tmp_path)
    _seed_release(layout, "0.2.0", b"release-two")
    _set_current(layout, "0.2.0")
    runner = FakeRunner(active=False)
    health_versions: list[str] = []

    def health(*_args: object) -> HealthResult:
        health_versions.append((layout.release_root / "current").readlink().name)
        return HealthResult(False, "candidate unhealthy")

    result = _manager(
        tmp_path,
        layout,
        FakeDownloader({}),
        runner=runner,
        health=health,
    ).rollback("0.1.0", False)

    assert result == ReleaseResult(6, "candidate_unhealthy", version="0.1.0")
    assert (layout.release_root / "current").readlink() == Path("releases/0.2.0")
    assert runner.active is False
    assert health_versions == ["0.1.0"]
    assert ("systemctl", "stop", "xferry.service") in runner.commands


def test_inactive_service_restoration_reports_a_failed_stop_as_incomplete(
    tmp_path: Path,
) -> None:
    """A failed stop must not be reported as a complete restoration of inactive state."""
    layout = _installed_layout(tmp_path)
    base_url = "https://releases.example.test/xferry/releases"
    downloader = FakeDownloader(_remote_assets(base_url, "0.2.0", b"release-two"))
    runner = FakeRunner(active=False, stop_failure=True)

    def health(*_args: object) -> HealthResult:
        version = (layout.release_root / "current").readlink().name
        return HealthResult(version == "0.1.0", "sanitized")

    result = _manager(tmp_path, layout, downloader, runner=runner, health=health).update(
        "0.2.0", False
    )

    assert result == ReleaseResult(1, "restore_incomplete", version="0.2.0")
    assert (layout.release_root / "current").readlink() == Path("releases/0.1.0")
    assert runner.active is True


def test_default_rollback_selects_previous_verified_release_and_keeps_old_current(
    tmp_path: Path,
) -> None:
    """Default rollback must select the prior verified release, not an arbitrary directory."""
    layout = _installed_layout(tmp_path)
    _seed_release(layout, "0.2.0", b"release-two")
    _seed_release(layout, "0.3.0", b"release-three")
    _set_current(layout, "0.3.0")
    releases = layout.release_root / "releases"
    os.utime(releases / "0.1.0", ns=(1, 1))
    os.utime(releases / "0.2.0", ns=(2, 2))
    os.utime(releases / "0.3.0", ns=(3, 3))
    runner = FakeRunner()

    result = _manager(tmp_path, layout, FakeDownloader({}), runner=runner).rollback(None, False)

    assert result == ReleaseResult(0, "rollback_complete", version="0.2.0")
    assert (layout.release_root / "current").readlink() == Path("releases/0.2.0")
    assert sorted(path.name for path in releases.iterdir()) == ["0.2.0", "0.3.0"]
    assert runner.restart_count == 1


def test_exact_rollback_uses_only_a_verified_installed_target(tmp_path: Path) -> None:
    """Exact rollback must use only the requested verified installed version."""
    layout = _installed_layout(tmp_path)
    _seed_release(layout, "0.2.0", b"release-two")
    _seed_release(layout, "0.3.0", b"release-three")
    _set_current(layout, "0.3.0")
    runner = FakeRunner()

    result = _manager(tmp_path, layout, FakeDownloader({}), runner=runner).rollback("0.1.0", False)

    assert result == ReleaseResult(0, "rollback_complete", version="0.1.0")
    assert (layout.release_root / "current").readlink() == Path("releases/0.1.0")
    assert sorted(path.name for path in (layout.release_root / "releases").iterdir()) == [
        "0.1.0",
        "0.3.0",
    ]


@pytest.mark.parametrize(
    ("target", "message"),
    [("0.9.9", "rollback_target_unverified"), ("0.2.0", "unsupported_managed_state")],
)
def test_rollback_rejects_missing_or_unverified_target(
    tmp_path: Path,
    target: str,
    message: str,
) -> None:
    """Presence alone cannot authorize rollback to an executable without matching metadata."""
    layout = _installed_layout(tmp_path)
    if target == "0.2.0":
        _seed_release(layout, target, b"release-two", verified=False)
    runner = FakeRunner()

    result = _manager(tmp_path, layout, FakeDownloader({}), runner=runner).rollback(target, False)

    assert result.exit_code == 1
    assert result.message == message
    assert (layout.release_root / "current").readlink() == Path("releases/0.1.0")
    assert runner.restart_count == 0


def test_release_failures_never_expose_credentials_in_urls_argv_logs_or_results(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Caught network and health exceptions must never serialize managed credentials."""
    secret = "never-print-release-secret"
    layout = _installed_layout(tmp_path)
    _seed_config(layout, secret)
    base_url = "https://releases.example.test/xferry/releases"
    manifest_url = f"{base_url}/download/v0.2.0/xferry-release.json"
    downloader = FakeDownloader({manifest_url: OSError(f"failed with {secret}")})
    runner = FakeRunner()

    with caplog.at_level(logging.DEBUG, logger="xferry"):
        result = _manager(tmp_path, layout, downloader, runner=runner).update("0.2.0", False)

    combined_urls = " ".join(request[0] for request in downloader.requests)
    combined_argv = " ".join(" ".join(command) for command in runner.commands)
    assert result == ReleaseResult(5, "release_download_failed", version="0.2.0")
    assert secret not in combined_urls
    assert secret not in combined_argv
    assert secret not in repr(result)
    assert secret not in caplog.text


def test_health_exception_text_never_exposes_credentials_during_restoration(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A health callback exception must be sanitized while the old release is restored."""
    secret = "never-print-health-secret"
    layout = _installed_layout(tmp_path)
    _seed_config(layout, secret)
    base_url = "https://releases.example.test/xferry/releases"
    downloader = FakeDownloader(_remote_assets(base_url, "0.2.0", b"release-two"))
    runner = FakeRunner()

    def failed_health(*_args: object) -> HealthResult:
        raise OSError(f"socket contained {secret}")

    with caplog.at_level(logging.DEBUG, logger="xferry"):
        result = _manager(
            tmp_path,
            layout,
            downloader,
            runner=runner,
            health=failed_health,
        ).update("0.2.0", False)

    assert result == ReleaseResult(1, "restore_incomplete", version="0.2.0")
    assert (layout.release_root / "current").readlink() == Path("releases/0.1.0")
    assert secret not in repr(result)
    assert secret not in " ".join(" ".join(command) for command in runner.commands)
    assert secret not in caplog.text


def test_real_update_requires_root_before_network_or_filesystem_effects(tmp_path: Path) -> None:
    """A non-root update must fail before downloading or creating the shared lock."""
    layout = _installed_layout(tmp_path)
    downloader = FakeDownloader({})

    result = _manager(tmp_path, layout, downloader, effective_uid=lambda: 1000).update(
        "0.2.0", False
    )

    assert result == ReleaseResult(3, "release_requires_root")
    assert downloader.requests == []
    assert not layout.lock_file.exists()


def test_update_holds_shared_lock_through_authenticated_health(tmp_path: Path) -> None:
    """Releasing the shared lock before health would let another mutation corrupt rollback state."""
    layout = _installed_layout(tmp_path)
    base_url = "https://releases.example.test/xferry/releases"
    downloader = FakeDownloader(_remote_assets(base_url, "0.2.0", b"release-two"))
    lock_observed: list[bool] = []

    def health(*_args: object) -> HealthResult:
        with pytest.raises(MutationLocked):
            with managed_mutation(
                layout.lock_file,
                effective_uid=lambda: 0,
                root_uid=os.getuid(),
            ):
                pass
        lock_observed.append(True)
        return HealthResult(True, "healthy")

    result = _manager(tmp_path, layout, downloader, health=health).update("0.2.0", False)

    assert result.exit_code == 0
    assert lock_observed == [True]


def _seed_uninstall_state(tmp_path: Path, layout: ManagedLayout) -> tuple[Path, Path, Path, Path]:
    _seed_config(layout)
    _seed_release(layout, "0.1.0", b"release-one")
    _set_current(layout, "0.1.0")
    unit = layout.unit_file
    unit.parent.mkdir(parents=True, exist_ok=True)
    _protect_managed_directory(layout, unit.parent)
    unit.write_text("managed unit\n", encoding="utf-8")
    unit.chmod(0o644)
    cli_link = layout.cli_link
    cli_link.parent.mkdir(parents=True, exist_ok=True)
    _protect_managed_directory(layout, cli_link.parent)
    cli_link.symlink_to("/opt/xferry/current/xferry")
    acme = layout.acme_root
    acme.mkdir(parents=True)
    _protect_managed_directory(layout, acme)
    acme.joinpath("certificate.pem").write_text("certificate", encoding="utf-8")
    layout.data_root.mkdir(parents=True, exist_ok=True)
    _protect_managed_directory(layout, layout.data_root)
    layout.data_root.joinpath("state.db").write_text("state", encoding="utf-8")
    return unit, cli_link, acme, layout.config_file.parent


def test_default_uninstall_removes_only_managed_runtime_and_preserves_state(
    tmp_path: Path,
) -> None:
    """Default uninstall must not delete configuration, data, credentials, or ACME state."""
    layout = _layout(tmp_path)
    unit, cli_link, acme, config_root = _seed_uninstall_state(tmp_path, layout)
    runner = FakeRunner()

    result = _manager(tmp_path, layout, FakeDownloader({}), runner=runner).uninstall(
        False, False, False
    )

    assert result == ReleaseResult(0, "uninstall_complete")
    assert not unit.exists()
    assert not cli_link.exists() and not cli_link.is_symlink()
    assert not layout.release_root.exists()
    assert config_root.joinpath("xferry.ini").is_file()
    assert config_root.joinpath("auth").is_file()
    assert layout.data_root.joinpath("state.db").is_file()
    assert acme.joinpath("certificate.pem").is_file()
    assert runner.commands == [
        ("systemctl", "disable", "--now", "xferry.service"),
        ("systemctl", "daemon-reload"),
    ]


def test_purge_requires_explicit_flag_and_confirmation_before_any_mutation(
    tmp_path: Path,
) -> None:
    """A purge flag without confirmation must leave every managed and preserved path intact."""
    layout = _layout(tmp_path)
    unit, cli_link, acme, config_root = _seed_uninstall_state(tmp_path, layout)
    runner = FakeRunner()

    result = _manager(tmp_path, layout, FakeDownloader({}), runner=runner).uninstall(
        True, False, False
    )

    assert result == ReleaseResult(2, "purge_confirmation_required")
    assert unit.is_file()
    assert cli_link.is_symlink()
    assert layout.release_root.is_dir()
    assert config_root.is_dir()
    assert layout.data_root.is_dir()
    assert acme.is_dir()
    assert runner.commands == []


def test_confirmed_purge_removes_preserved_config_data_and_acme(tmp_path: Path) -> None:
    """Both purge gates together must remove exactly the documented preserved state."""
    layout = _layout(tmp_path)
    _unit, _cli_link, acme, config_root = _seed_uninstall_state(tmp_path, layout)

    result = _manager(tmp_path, layout, FakeDownloader({})).uninstall(True, True, False)

    assert result == ReleaseResult(0, "purge_complete")
    assert not config_root.exists()
    assert not layout.data_root.exists()
    assert not acme.exists()


def test_purge_rejects_broadened_custom_roots_before_disabling_or_deleting(
    tmp_path: Path,
) -> None:
    """A misconfigured config path must never broaden purge from /etc/xferry to its parent."""
    shared_etc = tmp_path / "shared/etc"
    shared_etc.mkdir(parents=True)
    # Make the ambiguous parent explicit so this unsupported managed-state contract is
    # independent of umask.
    shared_etc.chmod(0o775)
    sentinel = shared_etc / "unrelated.conf"
    sentinel.write_text("preserve", encoding="utf-8")
    layout = ManagedLayout(
        release_root=tmp_path / "opt/xferry",
        config_file=shared_etc / "xferry.ini",
        auth_file=shared_etc / "auth",
        data_root=tmp_path / "var/lib/xferry",
        lock_file=tmp_path / "run/lock/xferry-ops.lock",
    )
    runner = FakeRunner()

    result = _manager(tmp_path, layout, FakeDownloader({}), runner=runner).uninstall(
        True, True, False
    )

    assert result == ReleaseResult(1, "unsupported_managed_state")
    assert sentinel.read_text(encoding="utf-8") == "preserve"
    assert runner.commands == []
    assert not layout.lock_file.exists()


@pytest.mark.parametrize("lookalike", ["srv/xferry", "backup/xferry"])
def test_uninstall_rejects_lookalike_release_roots_before_service_mutation(
    tmp_path: Path,
    lookalike: str,
) -> None:
    """A final xferry basename outside opt/xferry must never authorize recursive deletion."""
    layout = _layout(tmp_path)
    lookalike_root = tmp_path / lookalike
    lookalike_root.mkdir(parents=True)
    sentinel = lookalike_root / "unrelated.bin"
    sentinel.write_text("preserve", encoding="utf-8")
    layout = ManagedLayout(
        release_root=lookalike_root,
        config_file=layout.config_file,
        auth_file=layout.auth_file,
        data_root=layout.data_root,
        lock_file=layout.lock_file,
    )
    runner = FakeRunner()

    result = _manager(tmp_path, layout, FakeDownloader({}), runner=runner).uninstall(
        False, False, False
    )

    assert result == ReleaseResult(1, "unsupported_managed_state")
    assert sentinel.read_text(encoding="utf-8") == "preserve"
    assert runner.commands == []
    assert not layout.lock_file.exists()


def test_purge_rejects_a_backup_lookalike_data_root_before_service_mutation(
    tmp_path: Path,
) -> None:
    """A backup/xferry data lookalike must not satisfy the canonical var/lib suffix."""
    layout = _layout(tmp_path)
    lookalike_data = tmp_path / "backup/xferry"
    lookalike_data.mkdir(parents=True)
    sentinel = lookalike_data / "unrelated.db"
    sentinel.write_text("preserve", encoding="utf-8")
    layout = ManagedLayout(
        release_root=layout.release_root,
        config_file=layout.config_file,
        auth_file=layout.auth_file,
        data_root=lookalike_data,
        lock_file=layout.lock_file,
    )
    runner = FakeRunner()

    result = _manager(tmp_path, layout, FakeDownloader({}), runner=runner).uninstall(
        True, True, False
    )

    assert result == ReleaseResult(1, "unsupported_managed_state")
    assert sentinel.read_text(encoding="utf-8") == "preserve"
    assert runner.commands == []
    assert not layout.lock_file.exists()


def test_uninstall_rejects_an_ancestor_symlink_before_service_mutation(tmp_path: Path) -> None:
    """No-follow validation must reject a safe-looking suffix reached through an ancestor link."""
    real_root = tmp_path / "real-root"
    release_root = real_root / "opt/xferry"
    release_root.mkdir(parents=True)
    sentinel = release_root / "unrelated.bin"
    sentinel.write_text("preserve", encoding="utf-8")
    linked_root = tmp_path / "linked-root"
    linked_root.symlink_to(real_root, target_is_directory=True)
    base_layout = _layout(tmp_path)
    layout = ManagedLayout(
        release_root=linked_root / "opt/xferry",
        config_file=base_layout.config_file,
        auth_file=base_layout.auth_file,
        data_root=base_layout.data_root,
        lock_file=base_layout.lock_file,
    )
    runner = FakeRunner()

    result = _manager(tmp_path, layout, FakeDownloader({}), runner=runner).uninstall(
        False, False, False
    )

    assert result == ReleaseResult(1, "unsupported_managed_state")
    assert sentinel.read_text(encoding="utf-8") == "preserve"
    assert runner.commands == []
    assert not layout.lock_file.exists()


def test_purge_revalidates_all_roots_after_service_disable_before_deletion(
    tmp_path: Path,
) -> None:
    """An ancestor swap during systemctl must be caught before any managed path deletion."""
    layout = _layout(tmp_path)
    unit, cli_link, acme, config_root = _seed_uninstall_state(tmp_path, layout)
    original_etc = tmp_path / "etc-original"
    victim_parent = tmp_path / "victim"
    victim_config = victim_parent / "xferry"
    victim_config.mkdir(parents=True)
    victim = victim_config / "unrelated.conf"
    victim.write_text("preserve", encoding="utf-8")

    def swap_ancestor() -> None:
        (tmp_path / "etc").rename(original_etc)
        (tmp_path / "etc").symlink_to(victim_parent, target_is_directory=True)

    runner = FakeRunner(on_disable=swap_ancestor)
    result = _manager(tmp_path, layout, FakeDownloader({}), runner=runner).uninstall(
        True, True, False
    )

    assert result == ReleaseResult(1, "uninstall_path_unsafe")
    assert victim.read_text(encoding="utf-8") == "preserve"
    assert original_etc.joinpath("xferry/xferry.ini").is_file()
    assert original_etc.joinpath("systemd/system/xferry.service").is_file()
    assert layout.release_root.is_dir()
    assert unit.relative_to(tmp_path / "etc").as_posix() == "systemd/system/xferry.service"
    assert cli_link.is_symlink()
    assert acme.is_dir()
    assert config_root == tmp_path / "etc/xferry"


def test_all_dry_runs_leave_files_processes_and_lock_unchanged(tmp_path: Path) -> None:
    """Dry-run must not switch links, restart/disable systemd, prune, delete, or create a lock."""
    layout = _layout(tmp_path)
    unit, cli_link, acme, config_root = _seed_uninstall_state(tmp_path, layout)
    _seed_release(layout, "0.1.1", b"release-zero")
    base_url = "https://releases.example.test/xferry/releases"
    downloader = FakeDownloader(_remote_assets(base_url, "0.2.0", b"release-two"))
    runner = FakeRunner()
    manager = _manager(tmp_path, layout, downloader, runner=runner, effective_uid=lambda: 1000)

    update = manager.update("0.2.0", True)
    rollback = manager.rollback("0.1.1", True)
    uninstall = manager.uninstall(False, False, True)

    assert update == ReleaseResult(0, "update_dry_run", version="0.2.0", dry_run=True)
    assert rollback == ReleaseResult(0, "rollback_dry_run", version="0.1.1", dry_run=True)
    assert uninstall == ReleaseResult(0, "uninstall_dry_run", dry_run=True)
    assert (layout.release_root / "current").readlink() == Path("releases/0.1.0")
    assert sorted(path.name for path in (layout.release_root / "releases").iterdir()) == [
        "0.1.0",
        "0.1.1",
    ]
    assert unit.is_file() and cli_link.is_symlink()
    assert config_root.is_dir() and layout.data_root.is_dir() and acme.is_dir()
    assert not layout.lock_file.exists()
    assert not any(command[0] == "systemctl" for command in runner.commands)


@dataclass
class FakeReleaseManager:
    """Capture the CLI-to-release-manager boundary without host effects."""

    calls: list[tuple[object, ...]]

    def update(self, version: str | None, dry_run: bool) -> ReleaseResult:
        self.calls.append(("update", version, dry_run))
        return ReleaseResult(0, "update_complete", version=version or "0.2.0")

    def rollback(self, to_version: str | None, dry_run: bool) -> ReleaseResult:
        self.calls.append(("rollback", to_version, dry_run))
        return ReleaseResult(0, "rollback_complete", version=to_version or "0.1.0")

    def uninstall(self, purge_data: bool, confirmed: bool, dry_run: bool) -> ReleaseResult:
        self.calls.append(("uninstall", purge_data, confirmed, dry_run))
        return ReleaseResult(0, "purge_complete" if purge_data else "uninstall_complete")


def test_cli_dispatches_release_options_and_double_gates_noninteractive_purge(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Dropping a CLI option or treating noninteractive purge as confirmed changes safety."""
    fake = FakeReleaseManager([])
    monkeypatch.setattr("xferry.management.releases.default_release_manager", lambda: fake)
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)

    assert cli.main(["update", "--version", "0.2.0", "--dry-run"]) == 0
    assert cli.main(["rollback", "--to", "0.1.0", "--dry-run"]) == 0
    assert cli.main(["uninstall", "--purge-data"]) == 0
    assert fake.calls == [
        ("update", "0.2.0", True),
        ("rollback", "0.1.0", True),
        ("uninstall", True, False, False),
    ]
    assert "not implemented" not in (capsys.readouterr().out + capsys.readouterr().err).lower()
