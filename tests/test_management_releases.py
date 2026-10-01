"""Verified release update, rollback, and conservative uninstall tests."""

from __future__ import annotations

import hashlib
import json
import logging
import os
import stat
import urllib.request
from collections.abc import Callable, Sequence
from dataclasses import dataclass, fields
from email.message import Message
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from hypothesis import given
from hypothesis import strategies as st

from xferry.management import cli
from xferry.management import releases as release_module
from xferry.management.health import HealthEndpoint, HealthResult
from xferry.management.model import HostFacts, ManagedLayout
from xferry.management.release_contract import PlatformId
from xferry.management.release_trust import (
    DEFAULT_RELEASE_KEY_RING,
    MANIFEST_SIGNATURE_TYPE,
    ReleaseKeyRing,
    ReleaseKeyStatus,
    TrustedReleaseKey,
    create_detached_signature,
    verify_detached_signature,
    verify_signed_manifest,
)
from xferry.management.releases import (
    HttpsDownloader,
    ReleaseManager,
    ReleaseManifest,
    ReleaseResult,
)
from xferry.management.system import CommandResult, MutationLocked, managed_mutation
from xferry.settings import (
    ServerSettings,
    SettingsError,
    load_settings_text,
    resolve_settings,
    sample_config_text,
)


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


_TEST_SOURCE_COMMIT = "a" * 40
_TEST_WORKFLOW_RUN = "123456"
_TEST_KEY_ID = "test-release-2026"
_TEST_PRIVATE_KEY = Ed25519PrivateKey.generate()
_TEST_KEY_RING = ReleaseKeyRing(
    (
        TrustedReleaseKey(
            _TEST_KEY_ID,
            _TEST_PRIVATE_KEY.public_key().public_bytes_raw(),
        ),
    )
)


def _v1_manifest(version: str, payload: bytes, *, platform: str = "linux-x86_64") -> bytes:
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


def _v2_manifest(
    version: str,
    payload: bytes,
    *,
    platform: PlatformId = "linux-x86_64",
    signed: bool = False,
    key_id: str = _TEST_KEY_ID,
) -> bytes:
    return ReleaseManifest.create_v2(
        version=version,
        platform=platform,
        executable_size=len(payload),
        executable_sha256=hashlib.sha256(payload).hexdigest(),
        source_commit=_TEST_SOURCE_COMMIT,
        workflow_run=_TEST_WORKFLOW_RUN,
        signing_key_ids=(key_id,) if signed else (),
    ).to_bytes()


def _manifest_signature(
    manifest_payload: bytes,
    *,
    key_id: str = _TEST_KEY_ID,
    private_key: Ed25519PrivateKey = _TEST_PRIVATE_KEY,
) -> bytes:
    return create_detached_signature(
        manifest_payload,
        payload_type=MANIFEST_SIGNATURE_TYPE,
        key_id=key_id,
        signer=private_key,
    )


def _manifest_document(
    version: str = "0.2.0", payload: bytes = b"release-two"
) -> dict[str, object]:
    return json.loads(_v2_manifest(version, payload))


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
        self.read_requests: list[tuple[str, int]] = []
        self.download_requests: list[tuple[str, Path, int]] = []

    def read(self, url: str, max_bytes: int) -> bytes:
        self.read_requests.append((url, max_bytes))
        self.requests.append((url, Path("<memory>"), max_bytes))
        value = self.assets[url]
        if isinstance(value, BaseException):
            raise value
        if len(value) > max_bytes:
            raise OSError("download exceeded the permitted size")
        return value

    def download(self, url: str, destination: Path, max_bytes: int) -> None:
        request = (url, destination, max_bytes)
        self.download_requests.append(request)
        self.requests.append(request)
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


@dataclass
class FakeClock:
    """Advance readiness deadlines without making release tests sleep."""

    current: float = 0.0

    def monotonic(self) -> float:
        return self.current

    def sleep(self, delay: float) -> None:
        self.current += delay


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
    platform: str = "linux-x86_64",
) -> Path:
    release = layout.release_root / "releases" / version
    release.mkdir(parents=True, exist_ok=True)
    _protect_managed_directory(layout, release)
    executable = release / "xferry"
    executable.write_bytes(payload)
    executable.chmod(0o755)
    if verified:
        metadata = release / "xferry-release.json"
        metadata.write_bytes(_v1_manifest(version, payload, platform=platform))
        metadata.chmod(0o644)
    return release


def _set_current(layout: ManagedLayout, version: str) -> None:
    layout.release_root.mkdir(parents=True, exist_ok=True)
    current = layout.release_root / "current"
    current.unlink(missing_ok=True)
    current.symlink_to(Path("releases") / version)


def _installed_layout(tmp_path: Path, platform: str = "linux-x86_64") -> ManagedLayout:
    layout = _layout(tmp_path)
    _seed_config(layout)
    _seed_release(layout, "0.1.0", b"release-one", platform=platform)
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


def _host_facts(
    *,
    os_id: str = "debian",
    os_version: str = "12",
    machine: str = "x86_64",
    has_systemd: bool = True,
) -> HostFacts:
    return HostFacts(
        os_id=os_id,
        os_version=os_version,
        machine=machine,
        has_systemd=has_systemd,
        ram_mib=4096,
        cpu_count=2,
        disk_free_mib=8192,
    )


def _remote_assets(
    base_url: str,
    version: str,
    payload: bytes,
    *,
    manifest: bytes | None = None,
    latest: bool = False,
    platform: PlatformId = "linux-x86_64",
) -> dict[str, bytes]:
    tag = f"v{version}"
    manifest_name = f"xferry-release-{platform}.json"
    manifest_url = (
        f"{base_url}/latest/download/{manifest_name}"
        if latest
        else f"{base_url}/download/{tag}/{manifest_name}"
    )
    manifest_payload = (
        manifest
        if manifest is not None
        else _v2_manifest(
            version,
            payload,
            platform=platform,
            signed=True,
        )
    )
    return {
        manifest_url: manifest_payload,
        f"{manifest_url}.sig": _manifest_signature(manifest_payload),
        f"{base_url}/download/{tag}/xferry-{version}-{platform}": payload,
    }


def _manager(
    tmp_path: Path,
    layout: ManagedLayout,
    downloader: FakeDownloader,
    *,
    runner: FakeRunner | None = None,
    health: Callable[[HealthEndpoint, str, str, float], HealthResult] | None = None,
    effective_uid: Callable[[], int] = lambda: 0,
    key_ring: ReleaseKeyRing = _TEST_KEY_RING,
    platform: PlatformId = "linux-x86_64",
    facts: HostFacts | None = None,
) -> ReleaseManager:
    clock = FakeClock()
    return ReleaseManager(
        layout=layout,
        runner=runner or FakeRunner(),
        downloader=downloader,
        health_check=health
        or (
            lambda *_args: HealthResult(
                True,
                "healthy",
                (layout.release_root / "current").readlink().name,
            )
        ),
        effective_uid=effective_uid,
        root_uid=os.getuid(),
        release_base_url="https://releases.example.test/xferry/releases",
        platform_id=lambda: platform,
        unit_path=tmp_path / "etc/systemd/system/xferry.service",
        cli_link=tmp_path / "usr/local/bin/xferry",
        acme_root=layout.acme_root,
        staging_parent=tmp_path / "staging",
        readiness_timeout=1.0,
        monotonic=clock.monotonic,
        sleep=clock.sleep,
        remote_updates_enabled=True,
        release_key_ring=key_ring,
        host_facts=lambda: (
            facts or _host_facts(machine="aarch64" if platform == "linux-aarch64" else "x86_64")
        ),
    )


def _update_result(
    exit_code: int,
    message: str,
    *,
    active: str | None,
    rollback: str,
    before: str = "0.1.0",
) -> ReleaseResult:
    return ReleaseResult(
        exit_code,
        message,
        version="0.2.0",
        before=before,
        target="0.2.0",
        active=active,
        rollback=rollback,
    )


@pytest.mark.parametrize("dry_run", [False, True], ids=["real", "dry-run"])
def test_remote_update_is_disabled_before_any_release_boundary(
    tmp_path: Path,
    dry_run: bool,
) -> None:
    """Source-only defaults must reject update before parsing, I/O, network, or locks."""

    def unexpected_boundary() -> int:
        raise AssertionError("disabled update crossed a release boundary")

    class UnexpectedDownloader:
        def download(self, url: str, destination: Path, max_bytes: int) -> None:
            raise AssertionError(
                f"disabled update attempted download: {url} {destination} {max_bytes}"
            )

    runner = FakeRunner()
    manager = ReleaseManager(
        layout=_layout(tmp_path),
        runner=runner,
        downloader=UnexpectedDownloader(),
        health_check=lambda *_args: pytest.fail("disabled update attempted a health check"),
        effective_uid=unexpected_boundary,
        platform_id=lambda: pytest.fail("disabled update inspected the platform"),
        staging_parent=tmp_path / "staging",
    )

    assert manager.update("not-a-version", dry_run) == ReleaseResult(
        2,
        "remote_updates_disabled",
        dry_run=dry_run,
    )
    assert not (tmp_path / "staging").exists()
    assert not manager.layout.lock_file.exists()
    assert runner.commands == []


@pytest.mark.parametrize("enable_value", [1, "true"], ids=["integer", "string"])
def test_remote_update_rejects_truthy_non_boolean_enable_values(
    tmp_path: Path,
    enable_value: object,
) -> None:
    """Only the literal internal boolean opt-in may cross the remote boundary."""
    manager = ReleaseManager(
        layout=_layout(tmp_path),
        remote_updates_enabled=enable_value,  # type: ignore[arg-type]
    )

    assert manager.update("0.2.0", True) == ReleaseResult(
        2,
        "remote_updates_disabled",
        dry_run=True,
    )


def test_remote_update_enablement_has_no_settings_or_environment_surface() -> None:
    """Operator-controlled settings must not expose the dormant updater opt-in."""
    field_names = {settings_field.name for settings_field in fields(ServerSettings)}

    assert "remote_updates_enabled" not in field_names
    assert "remote_update" not in sample_config_text().casefold()
    assert resolve_settings(env={"XFERRY_REMOTE_UPDATES_ENABLED": "true"}) == resolve_settings()
    with pytest.raises(SettingsError, match="unknown config key"):
        load_settings_text("[server]\nremote_updates_enabled = true\n")


def test_default_disabled_update_does_not_disable_local_release_operations(
    tmp_path: Path,
) -> None:
    """Source-only admission must preserve verified rollback and conservative uninstall."""
    layout = _layout(tmp_path)
    unit, cli_link, acme, config_root = _seed_uninstall_state(tmp_path, layout)
    _seed_release(layout, "0.1.1", b"release-prior")
    runner = FakeRunner()
    manager = ReleaseManager(
        layout=layout,
        runner=runner,
        downloader=FakeDownloader({}),
        health_check=lambda *_args: HealthResult(
            True,
            "healthy",
            (layout.release_root / "current").readlink().name,
        ),
        effective_uid=lambda: 0,
        root_uid=os.getuid(),
        unit_path=layout.unit_file,
        cli_link=layout.cli_link,
        acme_root=layout.acme_root,
        staging_parent=tmp_path / "staging",
    )

    assert manager.rollback("0.1.1", False) == ReleaseResult(
        0,
        "rollback_complete",
        version="0.1.1",
    )
    assert (layout.release_root / "current").readlink() == Path("releases/0.1.1")

    assert manager.uninstall(False, False, False) == ReleaseResult(0, "uninstall_complete")
    assert not unit.exists()
    assert not cli_link.exists() and not cli_link.is_symlink()
    assert not layout.release_root.exists()
    assert config_root.joinpath("xferry.ini").is_file()
    assert config_root.joinpath("auth").is_file()
    assert layout.data_root.joinpath("state.db").is_file()
    assert acme.joinpath("certificate.pem").is_file()


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

    assert result == ReleaseResult(
        2,
        "unsupported_release_major",
        version=version,
        target=version,
    )
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


@pytest.mark.parametrize(
    ("os_id", "os_version", "platform", "machine"),
    [
        (os_id, os_version, platform, machine)
        for os_id, versions in (("ubuntu", ("22.04", "24.04", "26.04")), ("debian", ("12", "13")))
        for os_version in versions
        for platform, machine in (
            ("linux-x86_64", "x86_64"),
            ("linux-aarch64", "aarch64"),
        )
    ],
)
def test_update_admits_the_exact_ten_managed_host_pairs_before_metadata_read(
    tmp_path: Path,
    os_id: str,
    os_version: str,
    platform: PlatformId,
    machine: str,
) -> None:
    """Dropping any supported distro/architecture pair would contradict setup admission."""
    layout = _installed_layout(tmp_path, platform)
    base_url = "https://releases.example.test/xferry/releases"
    downloader = FakeDownloader(
        _remote_assets(base_url, "0.2.0", b"release-two", platform=platform)
    )

    result = _manager(
        tmp_path,
        layout,
        downloader,
        platform=platform,
        facts=_host_facts(os_id=os_id, os_version=os_version, machine=machine),
    ).update("0.2.0", True)

    assert result.exit_code == 0
    assert len(downloader.read_requests) == 2
    assert downloader.download_requests == []


@pytest.mark.parametrize(
    "facts",
    [
        _host_facts(os_id="fedora", os_version="40"),
        _host_facts(os_id="ubuntu", os_version="20.04"),
        _host_facts(machine="riscv64"),
        _host_facts(has_systemd=False),
    ],
    ids=("distribution", "version", "architecture", "systemd"),
)
def test_update_rejects_unsupported_managed_hosts_before_remote_access(
    tmp_path: Path,
    facts: HostFacts,
) -> None:
    """Update must reuse the full managed-host contract instead of guessing from Linux alone."""
    layout = _installed_layout(tmp_path)
    downloader = FakeDownloader({})

    result = _manager(tmp_path, layout, downloader, facts=facts).update("0.2.0", True)

    assert result.exit_code == 4
    assert result.message == "managed_host_unsupported"
    assert "Supported matrix:" in result.detail
    assert result.target == "0.2.0"
    assert "pipx upgrade xferry" in " ".join(result.next_actions)
    assert downloader.requests == []
    assert not (tmp_path / "staging").exists()
    assert not layout.lock_file.exists()


def test_update_portable_admission_returns_only_pipx_action_without_remote_access(
    tmp_path: Path,
) -> None:
    """A pipx/source installation must never be converted into a root-managed installation."""
    layout = _layout(tmp_path)
    downloader = FakeDownloader({})

    result = _manager(tmp_path, layout, downloader).update("0.2.0", True)

    assert result == ReleaseResult(
        4,
        "portable_installation",
        version="0.2.0",
        detail="No supported XFerry managed installation was found; no changes were made.",
        dry_run=True,
        target="0.2.0",
        next_actions=("Run `pipx upgrade xferry` for a portable installation.",),
    )
    assert downloader.requests == []
    assert not (tmp_path / "staging").exists()
    assert not layout.lock_file.exists()


@pytest.mark.parametrize("dry_run", [False, True], ids=("apply", "dry-run"))
def test_update_requires_root_before_host_inspection_or_remote_access(
    tmp_path: Path,
    dry_run: bool,
) -> None:
    """Both update modes are managed-root operations even though dry-run is mutation-free."""
    layout = _installed_layout(tmp_path)
    downloader = FakeDownloader({})

    manager = _manager(
        tmp_path,
        layout,
        downloader,
        effective_uid=lambda: 1000,
    )
    manager.host_facts = lambda: pytest.fail("non-root update inspected the host")
    result = manager.update("0.2.0", dry_run)

    assert result == ReleaseResult(
        3,
        "release_requires_root",
        version="0.2.0",
        dry_run=dry_run,
        target="0.2.0",
        next_actions=("Run this managed update as root with `sudo`.",),
    )
    assert downloader.requests == []
    assert not layout.lock_file.exists()


def test_update_requires_explicit_version_before_candidate_download_or_lock(
    tmp_path: Path,
) -> None:
    """A mutable latest lookup must remain unreachable even through the manager boundary."""
    layout = _installed_layout_at(tmp_path)
    downloader = FakeDownloader({})
    runner = FakeRunner()

    result = _manager(tmp_path, layout, downloader, runner=runner).update(None, False)

    assert result == ReleaseResult(2, "invalid_release_version")
    assert downloader.requests == []
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
        ambiguous_path.joinpath("xferry-release.json").write_bytes(
            _v1_manifest("0.1.2", b"mismatch")
        )
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
        lambda _layout, *, platform_id: next(checks),
        raising=False,
    )

    result = _manager(tmp_path, layout, downloader, runner=runner).update("0.2.0", False)

    assert result == _update_result(
        1,
        "unsupported_managed_state",
        active="0.1.0",
        rollback="not_attempted",
    )
    assert len(downloader.requests) == 3
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
        lambda _layout, *, platform_id: next(checks),
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
        lambda _layout, *, platform_id: next(checks),
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
        json.dumps(_manifest_document() | {"schema_version": 3}).encode(),
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
    parsed = ReleaseManifest.parse(_v2_manifest("0.2.0", b"release-two"))

    assert parsed.schema_version == 2
    assert parsed.version == "0.2.0"
    assert parsed.tag == "v0.2.0"
    assert parsed.platform == "linux-x86_64"
    assert parsed.executable_name == "xferry-0.2.0-linux-x86_64"
    assert parsed.executable_size == 11
    assert parsed.executable_sha256 == hashlib.sha256(b"release-two").hexdigest()
    assert parsed.source_commit == _TEST_SOURCE_COMMIT
    assert parsed.workflow_run == _TEST_WORKFLOW_RUN
    assert parsed.signing_scheme == "unsigned"


def test_manifest_parser_preserves_exact_v1_read_compatibility() -> None:
    """Existing installed v1 metadata remains readable during migration and rollback."""
    parsed = ReleaseManifest.parse(_v1_manifest("0.1.0", b"release-one"))

    assert parsed.schema_version == 1
    assert parsed.version == "0.1.0"
    assert ReleaseManifest.parse(parsed.to_bytes()) == parsed


def test_new_release_parser_rejects_v1_as_a_schema_downgrade() -> None:
    """A legacy shape is for installed-state migration, not a newly downloaded release."""
    with pytest.raises(ValueError, match="^invalid release manifest$"):
        ReleaseManifest.parse_new(_v1_manifest("0.2.0", b"release-two"))


@given(
    major=st.integers(min_value=0, max_value=999),
    minor=st.integers(min_value=0, max_value=999),
    patch=st.integers(min_value=0, max_value=999),
    platform=st.sampled_from(("linux-x86_64", "linux-aarch64")),
)
def test_v2_manifest_round_trip_is_canonical_for_every_modeled_platform(
    major: int,
    minor: int,
    patch: int,
    platform: PlatformId,
) -> None:
    """Canonical versions/platforms must round-trip without widening the schema."""
    version = f"{major}.{minor}.{patch}"
    payload = f"{version}-{platform}".encode()

    manifest = ReleaseManifest.create_v2(
        version=version,
        platform=platform,
        executable_size=len(payload),
        executable_sha256=hashlib.sha256(payload).hexdigest(),
        source_commit=_TEST_SOURCE_COMMIT,
        workflow_run=_TEST_WORKFLOW_RUN,
    )

    assert ReleaseManifest.parse_new(manifest.to_bytes()) == manifest


def test_signed_v2_manifest_verifies_offline_and_binds_every_canonical_byte() -> None:
    manifest_payload = _v2_manifest("0.2.0", b"release-two", signed=True)
    signature_payload = _manifest_signature(manifest_payload)
    executable_digest = hashlib.sha256(b"release-two").hexdigest()
    tampered_digest = ("0" if executable_digest[0] != "0" else "1") + executable_digest[1:]

    manifest = verify_signed_manifest(
        manifest_payload,
        signature_payload,
        key_ring=_TEST_KEY_RING,
    )

    assert manifest.signing_scheme == "ed25519"
    assert manifest.signing_key_ids == (_TEST_KEY_ID,)
    for original, replacement, replace_all in (
        (b'"commit": "aaaaaaaa', b'"commit": "baaaaaaa', False),
        (b'"workflow_run": "123456"', b'"workflow_run": "123457"', False),
        (executable_digest.encode(), tampered_digest.encode(), True),
        (b"linux-x86_64", b"linux-aarch64", True),
    ):
        tampered = manifest_payload.replace(
            original,
            replacement,
            -1 if replace_all else 1,
        )
        with pytest.raises(ValueError, match="release_signature_invalid"):
            verify_signed_manifest(tampered, signature_payload, key_ring=_TEST_KEY_RING)

    noncanonical_signature = signature_payload.replace(b"{\n", b"{ \n", 1)
    with pytest.raises(ValueError, match="release_signature_invalid"):
        verify_signed_manifest(
            manifest_payload,
            noncanonical_signature,
            key_ring=_TEST_KEY_RING,
        )


def test_release_key_rotation_overlap_and_revocation_are_enforced() -> None:
    next_key_id = "test-release-2027"
    next_private_key = Ed25519PrivateKey.generate()
    overlap_ring = ReleaseKeyRing(
        (
            _TEST_KEY_RING.keys[0],
            TrustedReleaseKey(
                next_key_id,
                next_private_key.public_key().public_bytes_raw(),
            ),
        )
    )
    old_manifest = _v2_manifest("0.2.0", b"old", signed=True)
    next_manifest = _v2_manifest(
        "0.2.1",
        b"next",
        signed=True,
        key_id=next_key_id,
    )

    assert (
        verify_signed_manifest(
            old_manifest,
            _manifest_signature(old_manifest),
            key_ring=overlap_ring,
        ).version
        == "0.2.0"
    )
    assert (
        verify_signed_manifest(
            next_manifest,
            _manifest_signature(
                next_manifest,
                key_id=next_key_id,
                private_key=next_private_key,
            ),
            key_ring=overlap_ring,
        ).version
        == "0.2.1"
    )

    revoked_ring = ReleaseKeyRing(
        (
            TrustedReleaseKey(
                _TEST_KEY_ID,
                _TEST_PRIVATE_KEY.public_key().public_bytes_raw(),
                ReleaseKeyStatus.REVOKED,
            ),
            overlap_ring.keys[1],
        )
    )
    with pytest.raises(ValueError, match="release_signing_key_revoked"):
        verify_signed_manifest(
            old_manifest,
            _manifest_signature(old_manifest),
            key_ring=revoked_ring,
        )
    assert (
        verify_signed_manifest(
            next_manifest,
            _manifest_signature(
                next_manifest,
                key_id=next_key_id,
                private_key=next_private_key,
            ),
            key_ring=revoked_ring,
        ).version
        == "0.2.1"
    )


def test_default_release_key_ring_verifies_reviewed_enrollment_proof() -> None:
    """The shipped trust root must verify an owner-authorized proof offline."""
    proof_payload = b"xferry production release key enrollment proof v1\n"
    proof_signature = (
        b"{\n"
        b'  "schema_version": 1,\n'
        b'  "algorithm": "ed25519",\n'
        b'  "key_id": "xferry-release-2026-09",\n'
        b'  "payload_type": "release-manifest-v2",\n'
        b'  "signature": "iZgariO9VZwNNyDqkX/4rYWMxy3NQYsh+4cxPRRB'
        b'r6Gv056Lhy2CznwAmPXLE4/W/y9NW92OLlODL9dxHxakDQ=="\n'
        b"}\n"
    )

    assert (
        verify_detached_signature(
            proof_payload,
            proof_signature,
            payload_type=MANIFEST_SIGNATURE_TYPE,
            key_ring=DEFAULT_RELEASE_KEY_RING,
        )
        == "xferry-release-2026-09"
    )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("platform", "linux-riscv64"),
        ("executable.size", 0),
        ("executable.size", True),
        ("executable.sha256", "A" * 64),
        ("source.commit", "A" * 40),
        ("source.workflow_run", "0"),
        ("artifact_digests", {}),
        ("artifact_digests", {"other-asset": "0" * 64}),
        ("signing.scheme", "ed25519"),
        ("signing.key_ids", ["future-key"]),
    ],
)
def test_v2_manifest_rejects_unknown_or_incomplete_contract_metadata(
    field: str,
    value: object,
) -> None:
    """Provenance, inventory, platform, and future signing metadata fail closed."""
    document = _manifest_document()
    if "." in field:
        parent, child = field.split(".", 1)
        nested = dict(document[parent])  # type: ignore[arg-type]
        nested[child] = value
        document[parent] = nested
    else:
        document[field] = value

    with pytest.raises(ValueError, match="^invalid release manifest$"):
        ReleaseManifest.parse_new(json.dumps(document).encode())


def test_v2_manifest_rejects_a_duplicate_nested_key() -> None:
    """JSON duplicate rejection applies recursively, not only to top-level fields."""
    payload = _v2_manifest("0.2.0", b"release-two")
    duplicate = payload.replace(
        b'    "workflow_run": "123456"',
        b'    "workflow_run": "123456",\n    "workflow_run": "123456"',
        1,
    )

    with pytest.raises(ValueError, match="^invalid release manifest$"):
        ReleaseManifest.parse_new(duplicate)


def test_v2_manifest_bounds_the_complete_artifact_digest_set() -> None:
    """A bounded inventory keeps canonical installed serialization below the parser cap."""
    document = _manifest_document()
    digest = "0" * 64
    document["artifact_digests"] = {
        **dict(document["artifact_digests"]),  # type: ignore[arg-type]
        **{f"asset-{index:03d}": digest for index in range(128)},
    }

    with pytest.raises(ValueError, match="^invalid release manifest$"):
        ReleaseManifest.parse_new(json.dumps(document).encode())


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
    parsed = ReleaseManifest.parse(_v1_manifest(version, b"release-two"))

    assert parsed.version == version


@pytest.mark.parametrize("version", ["0.2", "0.02.0", "0.2.0.0", "0.2.00"])
def test_manifest_parser_rejects_noncanonical_versions(version: str) -> None:
    """Loose version labels would make manifest publication disagree with installer parsing."""
    with pytest.raises(ValueError, match="^invalid release manifest$"):
        ReleaseManifest.parse(_v1_manifest(version, b"release-two"))


def test_update_rejects_unsigned_remote_manifest_before_signature_or_candidate_download(
    tmp_path: Path,
) -> None:
    layout = _installed_layout(tmp_path)
    base_url = "https://releases.example.test/xferry/releases"
    manifest_url = f"{base_url}/download/v0.2.0/xferry-release-linux-x86_64.json"
    downloader = FakeDownloader({manifest_url: _v2_manifest("0.2.0", b"release-two")})

    result = _manager(tmp_path, layout, downloader).update("0.2.0", False)

    assert result == _update_result(
        1,
        "release_manifest_unsigned",
        active="0.1.0",
        rollback="not_attempted",
    )
    assert [request[0] for request in downloader.requests] == [manifest_url]
    assert (layout.release_root / "current").readlink() == Path("releases/0.1.0")
    assert not (layout.release_root / "releases/0.2.0").exists()


def test_update_rejects_noncanonical_signed_manifest_before_signature_download(
    tmp_path: Path,
) -> None:
    layout = _installed_layout(tmp_path)
    base_url = "https://releases.example.test/xferry/releases"
    manifest_url = f"{base_url}/download/v0.2.0/xferry-release-linux-x86_64.json"
    canonical = _v2_manifest("0.2.0", b"release-two", signed=True)
    noncanonical = canonical.replace(b"{\n", b"{ \n", 1)
    downloader = FakeDownloader({manifest_url: noncanonical})

    result = _manager(tmp_path, layout, downloader).update("0.2.0", False)

    assert result == _update_result(
        1,
        "release_manifest_noncanonical",
        active="0.1.0",
        rollback="not_attempted",
    )
    assert [request[0] for request in downloader.requests] == [manifest_url]
    assert not (layout.release_root / "releases/0.2.0").exists()


@pytest.mark.parametrize(
    ("key_ring", "signature_factory", "expected_message"),
    [
        (
            ReleaseKeyRing(()),
            _manifest_signature,
            "release_signing_key_unknown",
        ),
        (
            ReleaseKeyRing(
                (
                    TrustedReleaseKey(
                        _TEST_KEY_ID,
                        _TEST_PRIVATE_KEY.public_key().public_bytes_raw(),
                        ReleaseKeyStatus.REVOKED,
                    ),
                )
            ),
            _manifest_signature,
            "release_signing_key_revoked",
        ),
        (
            _TEST_KEY_RING,
            lambda payload: _manifest_signature(
                payload,
                private_key=Ed25519PrivateKey.generate(),
            ),
            "release_signature_invalid",
        ),
    ],
    ids=("unknown", "revoked", "wrong-key"),
)
def test_update_rejects_untrusted_signatures_before_candidate_download_or_mutation(
    tmp_path: Path,
    key_ring: ReleaseKeyRing,
    signature_factory: Callable[[bytes], bytes],
    expected_message: str,
) -> None:
    layout = _installed_layout(tmp_path)
    base_url = "https://releases.example.test/xferry/releases"
    manifest_url = f"{base_url}/download/v0.2.0/xferry-release-linux-x86_64.json"
    manifest = _v2_manifest("0.2.0", b"release-two", signed=True)
    downloader = FakeDownloader(
        {
            manifest_url: manifest,
            f"{manifest_url}.sig": signature_factory(manifest),
        }
    )
    runner = FakeRunner()

    result = _manager(
        tmp_path,
        layout,
        downloader,
        runner=runner,
        key_ring=key_ring,
    ).update("0.2.0", False)

    assert result == _update_result(
        1,
        expected_message,
        active="0.1.0",
        rollback="not_attempted",
    )
    assert [request[0] for request in downloader.requests] == [
        manifest_url,
        f"{manifest_url}.sig",
    ]
    assert runner.commands == []
    assert (layout.release_root / "current").readlink() == Path("releases/0.1.0")
    assert not (layout.release_root / "releases/0.2.0").exists()


def test_update_rejects_signed_metadata_mutation_before_candidate_download(
    tmp_path: Path,
) -> None:
    layout = _installed_layout(tmp_path)
    base_url = "https://releases.example.test/xferry/releases"
    manifest_url = f"{base_url}/download/v0.2.0/xferry-release-linux-x86_64.json"
    original = _v2_manifest("0.2.0", b"release-two", signed=True)
    mutated = original.replace(b'"commit": "aaaaaaaa', b'"commit": "baaaaaaa', 1)
    downloader = FakeDownloader(
        {
            manifest_url: mutated,
            f"{manifest_url}.sig": _manifest_signature(original),
        }
    )

    result = _manager(tmp_path, layout, downloader).update("0.2.0", False)

    assert result == _update_result(
        1,
        "release_signature_invalid",
        active="0.1.0",
        rollback="not_attempted",
    )
    assert [request[0] for request in downloader.requests] == [
        manifest_url,
        f"{manifest_url}.sig",
    ]
    assert not (layout.release_root / "releases/0.2.0").exists()


@pytest.mark.parametrize(
    ("current_version", "candidate_version"),
    [
        ("0.2.0", "0.1.0"),
        ("0.2.0+new", "0.2.0+old"),
    ],
    ids=("older-precedence", "equal-precedence-different-identity"),
)
def test_update_rejects_a_signed_version_downgrade_before_candidate_download(
    tmp_path: Path,
    current_version: str,
    candidate_version: str,
) -> None:
    layout = _installed_layout_at(tmp_path, current_version, b"release-current")
    base_url = "https://releases.example.test/xferry/releases"
    downloader = FakeDownloader(_remote_assets(base_url, candidate_version, b"release-old"))

    result = _manager(tmp_path, layout, downloader).update(candidate_version, False)

    assert result == ReleaseResult(
        1,
        "release_downgrade_blocked",
        version=candidate_version,
        before=current_version,
        target=candidate_version,
        active=current_version,
    )
    assert [request[0] for request in downloader.requests] == [
        f"{base_url}/download/v{candidate_version}/xferry-release-linux-x86_64.json",
        f"{base_url}/download/v{candidate_version}/xferry-release-linux-x86_64.json.sig",
    ]
    assert (layout.release_root / "current").readlink() == Path("releases") / current_version


def test_update_rechecks_downgrade_under_lock_before_candidate_execution(
    tmp_path: Path,
) -> None:
    """A concurrent newer update must not be replaced from a stale pre-download view."""
    layout = _installed_layout(tmp_path)
    base_url = "https://releases.example.test/xferry/releases"
    runner = FakeRunner()

    def advance_current(url: str, _destination: Path) -> None:
        if url.endswith("/xferry-0.2.0-linux-x86_64"):
            _seed_release(layout, "0.3.0", b"release-three")
            _set_current(layout, "0.3.0")

    downloader = FakeDownloader(
        _remote_assets(base_url, "0.2.0", b"release-two"),
        before_write=advance_current,
    )

    result = _manager(tmp_path, layout, downloader, runner=runner).update("0.2.0", False)

    assert result == ReleaseResult(
        1,
        "release_downgrade_blocked",
        version="0.2.0",
        before="0.1.0",
        target="0.2.0",
        active="0.3.0",
    )
    assert runner.commands == []
    assert (layout.release_root / "current").readlink() == Path("releases/0.3.0")
    assert not (layout.release_root / "releases/0.2.0").exists()


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
    manifest_url = f"{base_url}/download/v0.2.0/xferry-release-linux-x86_64.json"
    signed_manifest = _v2_manifest(
        "0.2.0",
        manifest_payload,
        signed=True,
    )
    assets[manifest_url] = signed_manifest
    assets[f"{manifest_url}.sig"] = _manifest_signature(signed_manifest)

    result = _manager(tmp_path, layout, FakeDownloader(assets)).update("0.2.0", False)

    assert result.exit_code == 1
    assert (layout.release_root / "current").readlink() == Path("releases/0.1.0")
    assert not (layout.release_root / "releases/0.2.0").exists()


def test_update_rejects_platform_mismatch_before_asset_download(tmp_path: Path) -> None:
    """Installing a release for another platform would fail only after damaging service state."""
    layout = _installed_layout(tmp_path)
    base_url = "https://releases.example.test/xferry/releases"
    manifest = _v2_manifest(
        "0.2.0",
        b"arm",
        platform="linux-aarch64",
        signed=True,
    )
    manifest_url = f"{base_url}/download/v0.2.0/xferry-release-linux-x86_64.json"
    downloader = FakeDownloader(
        {
            manifest_url: manifest,
            f"{manifest_url}.sig": _manifest_signature(manifest),
        }
    )

    result = _manager(tmp_path, layout, downloader).update("0.2.0", False)

    assert result.exit_code == 4
    assert [request[0] for request in downloader.requests] == [
        manifest_url,
        f"{manifest_url}.sig",
    ]
    assert (layout.release_root / "current").readlink() == Path("releases/0.1.0")


def test_update_rejects_a_remote_v1_schema_downgrade_before_asset_download(
    tmp_path: Path,
) -> None:
    """Legacy manifests remain readable on disk but cannot authorize a new download."""
    layout = _installed_layout(tmp_path)
    base_url = "https://releases.example.test/xferry/releases"
    manifest_url = f"{base_url}/download/v0.2.0/xferry-release-linux-x86_64.json"
    downloader = FakeDownloader({manifest_url: _v1_manifest("0.2.0", b"release-two")})

    result = _manager(tmp_path, layout, downloader).update("0.2.0", False)

    assert result == _update_result(
        1,
        "release_manifest_invalid",
        active="0.1.0",
        rollback="not_attempted",
    )
    assert [request[0] for request in downloader.requests] == [manifest_url]
    assert (layout.release_root / "current").readlink() == Path("releases/0.1.0")


def test_exact_update_rejects_a_manifest_for_another_requested_version(tmp_path: Path) -> None:
    """Trusting the download location instead of manifest version would install the wrong tag."""
    layout = _installed_layout(tmp_path)
    base_url = "https://releases.example.test/xferry/releases"
    manifest_url = f"{base_url}/download/v0.2.0/xferry-release-linux-x86_64.json"
    manifest = _v2_manifest("0.1.0", b"release-three", signed=True)
    downloader = FakeDownloader(
        {
            manifest_url: manifest,
            f"{manifest_url}.sig": _manifest_signature(manifest),
        }
    )

    result = _manager(tmp_path, layout, downloader).update("0.2.0", False)

    assert result.exit_code == 1
    assert len(downloader.requests) == 2


def test_exact_update_pins_asset_to_the_manifest_tag_and_stages_outside_opt(
    tmp_path: Path,
) -> None:
    """A second metadata lookup or staging in /opt creates a race before verification."""
    layout = _installed_layout(tmp_path)
    base_url = "https://releases.example.test/xferry/releases"
    payload = b"release-two"
    assets = _remote_assets(base_url, "0.2.0", payload)

    def before_download(_url: str, destination: Path) -> None:
        assert not destination.resolve().is_relative_to(layout.release_root.resolve())
        assert (layout.release_root / "current").readlink() == Path("releases/0.1.0")
        assert not (layout.release_root / "releases/0.2.0").exists()

    downloader = FakeDownloader(assets, before_write=before_download)
    result = _manager(tmp_path, layout, downloader).update("0.2.0", False)

    assert result.exit_code == 0
    assert [request[0] for request in downloader.requests] == [
        f"{base_url}/download/v0.2.0/xferry-release-linux-x86_64.json",
        f"{base_url}/download/v0.2.0/xferry-release-linux-x86_64.json.sig",
        f"{base_url}/download/v0.2.0/xferry-0.2.0-linux-x86_64",
    ]


def test_update_rejects_non_https_release_origin_before_network(tmp_path: Path) -> None:
    """Allowing a plaintext release origin would make manifest and checksum replacement trivial."""
    layout = _installed_layout(tmp_path)
    downloader = FakeDownloader({})
    manager = _manager(tmp_path, layout, downloader)
    manager.release_base_url = "http://releases.example.test/xferry/releases"

    result = manager.update("0.2.0", False)

    assert result == ReleaseResult(
        5,
        "release_url_unsafe",
        version="0.2.0",
        target="0.2.0",
    )
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
    def __init__(self, final_url: str, payload: bytes = b"payload") -> None:
        self.final_url = final_url
        self.payload = payload

    def open(self, _request: object, *, timeout: float) -> _FakeHttpsResponse:
        del timeout
        return _FakeHttpsResponse(self.final_url, self.payload)


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


def test_https_downloader_memory_read_rejects_payload_over_the_exact_cap() -> None:
    """Metadata reads must detect max+1 bytes instead of accepting a truncated envelope."""
    url = "https://assets.example.test/xferry-release-linux-x86_64.json"
    downloader = HttpsDownloader(opener=_FakeHttpsOpener(url, b"x" * 101))

    with pytest.raises(OSError, match="exceeded"):
        downloader.read(url, 100)


def test_release_envelope_verifier_binds_signature_identity_and_executable(
    tmp_path: Path,
) -> None:
    """A hash-authenticated SCIE may authorize only its exact signed platform envelope."""
    from xferry.management.release_verifier import (
        ReleaseEnvelopeError,
        verify_release_envelope,
    )

    executable = tmp_path / "xferry"
    executable.write_bytes(b"release-two")
    manifest_payload = _v2_manifest("0.2.0", executable.read_bytes(), signed=True)
    manifest = tmp_path / "xferry-release-linux-x86_64.json"
    signature = tmp_path / "xferry-release-linux-x86_64.json.sig"
    manifest.write_bytes(manifest_payload)
    signature.write_bytes(_manifest_signature(manifest_payload))

    verified = verify_release_envelope(
        manifest,
        signature,
        executable,
        expected_version="0.2.0",
        expected_platform="linux-x86_64",
        key_ring=_TEST_KEY_RING,
    )

    assert verified.to_bytes() == manifest_payload
    executable.write_bytes(b"tampered-release")
    with pytest.raises(ReleaseEnvelopeError, match="release_integrity_failed"):
        verify_release_envelope(
            manifest,
            signature,
            executable,
            expected_version="0.2.0",
            expected_platform="linux-x86_64",
            key_ring=_TEST_KEY_RING,
        )


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
    assert result == _update_result(
        0,
        "update_complete",
        active="0.2.0",
        rollback="not_needed",
    )
    assert (layout.release_root / "current").readlink() == Path("releases/0.2.0")
    assert installed.joinpath("xferry").read_bytes() == payload
    assert stat.S_IMODE(installed.stat().st_mode) == 0o755
    assert installed.stat().st_uid == os.getuid()
    assert stat.S_IMODE(installed.joinpath("xferry").stat().st_mode) == 0o755
    assert stat.S_IMODE(installed.joinpath("xferry-release.json").stat().st_mode) == 0o644
    assert stat.S_IMODE(installed.joinpath("xferry-release.json.sig").stat().st_mode) == 0o644
    installed_manifest = ReleaseManifest.parse(
        installed.joinpath("xferry-release.json").read_bytes()
    )
    assert installed_manifest.schema_version == 2
    assert installed_manifest.version == "0.2.0"
    assert installed_manifest.signing_scheme == "ed25519"
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


@pytest.mark.parametrize("platform", ["linux-x86_64", "linux-aarch64"])
def test_update_uses_platform_remote_metadata_and_canonical_local_names(
    tmp_path: Path,
    platform: PlatformId,
) -> None:
    """Each architecture needs unique hosted metadata but one stable installed layout."""
    layout = _installed_layout(tmp_path, platform)
    base_url = "https://releases.example.test/xferry/releases"
    payload = f"release-two-{platform}".encode()
    assets = _remote_assets(base_url, "0.2.0", payload, platform=platform)
    downloader = FakeDownloader(assets)

    result = _manager(
        tmp_path,
        layout,
        downloader,
        platform=platform,
    ).update("0.2.0", False)

    assert result.exit_code == 0
    remote_manifest = f"xferry-release-{platform}.json"
    assert [request[0] for request in downloader.requests] == [
        f"{base_url}/download/v0.2.0/{remote_manifest}",
        f"{base_url}/download/v0.2.0/{remote_manifest}.sig",
        f"{base_url}/download/v0.2.0/xferry-0.2.0-{platform}",
    ]
    installed = layout.release_root / "releases/0.2.0"
    assert sorted(path.name for path in installed.iterdir()) == [
        "xferry",
        "xferry-release.json",
        "xferry-release.json.sig",
    ]
    assert (
        installed.joinpath("xferry-release.json").read_bytes()
        == assets[f"{base_url}/download/v0.2.0/{remote_manifest}"]
    )
    assert (
        installed.joinpath("xferry-release.json.sig").read_bytes()
        == assets[f"{base_url}/download/v0.2.0/{remote_manifest}.sig"]
    )


def test_install_persists_the_exact_authenticated_manifest_bytes(tmp_path: Path) -> None:
    """Future serializer drift must not replace the exact bytes authorized by the signature."""
    layout = _installed_layout(tmp_path)
    payload = b"release-two"
    manifest_payload = _v2_manifest("0.2.0", payload, signed=True)
    signature_payload = _manifest_signature(manifest_payload)
    parsed = ReleaseManifest.parse_new(manifest_payload)

    class SerializerDriftManifest:
        version = parsed.version

        @staticmethod
        def to_bytes() -> bytes:
            return b"different-unauthenticated-serialization\n"

    candidate = tmp_path / "candidate"
    candidate.write_bytes(payload)
    manager = _manager(tmp_path, layout, FakeDownloader({}))
    verified = release_module._VerifiedRemoteManifest(  # type: ignore[attr-defined]
        SerializerDriftManifest(),  # type: ignore[arg-type]
        manifest_payload,
        signature_payload,
    )

    assert manager._install_verified_release(verified, candidate) is True

    installed = layout.release_root / "releases/0.2.0"
    assert installed.joinpath("xferry-release.json").read_bytes() == manifest_payload
    assert installed.joinpath("xferry-release.json.sig").read_bytes() == signature_payload
    assert (
        verify_signed_manifest(
            installed.joinpath("xferry-release.json").read_bytes(),
            installed.joinpath("xferry-release.json.sig").read_bytes(),
            key_ring=_TEST_KEY_RING,
        )
        == parsed
    )


def test_successful_update_restores_a_confirmed_prior_inactive_service(tmp_path: Path) -> None:
    """A healthy candidate must not turn an intentionally stopped installation back on."""
    layout = _installed_layout(tmp_path)
    base_url = "https://releases.example.test/xferry/releases"
    downloader = FakeDownloader(_remote_assets(base_url, "0.2.0", b"release-two"))
    runner = FakeRunner(active=False)

    result = _manager(tmp_path, layout, downloader, runner=runner).update("0.2.0", False)

    assert result == _update_result(
        0,
        "update_complete",
        active="0.2.0",
        rollback="not_needed",
    )
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

    assert result == _update_result(
        6,
        "candidate_state_restore_failed",
        active="0.1.0",
        rollback="restored",
    )
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

    assert result == _update_result(
        6,
        "candidate_state_restore_failed",
        active="0.1.0",
        rollback="restored",
    )
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

    assert result == ReleaseResult(
        1,
        "unsupported_managed_state",
        version="0.1.0",
        target="0.1.0",
    )
    assert downloader.requests == []
    assert not layout.lock_file.exists()
    assert installed.read_bytes() == b"tampered-release"
    assert runner.commands == []


def test_same_version_update_is_a_metadata_verified_noop(tmp_path: Path) -> None:
    """An exact installed release must not be downloaded, executed, restarted, or pruned again."""
    layout = _installed_layout(tmp_path)
    base_url = "https://releases.example.test/xferry/releases"
    assets = _remote_assets(base_url, "0.2.0", b"release-two")
    first_downloader = FakeDownloader(assets)
    first_runner = FakeRunner()
    first = _manager(
        tmp_path,
        layout,
        first_downloader,
        runner=first_runner,
    ).update("0.2.0", False)
    assert first.exit_code == 0

    downloader = FakeDownloader(assets)
    runner = FakeRunner()
    result = _manager(tmp_path, layout, downloader, runner=runner).update("0.2.0", False)

    assert result == _update_result(
        0,
        "update_noop",
        active="0.2.0",
        rollback="not_needed",
        before="0.2.0",
    )
    assert len(downloader.read_requests) == 2
    assert downloader.download_requests == []
    assert runner.commands == []
    assert sorted(path.name for path in (layout.release_root / "releases").iterdir()) == [
        "0.1.0",
        "0.2.0",
    ]


@pytest.mark.parametrize("tamper", ["missing", "invalid", "untrusted"])
def test_update_rejects_an_unverifiable_current_rollback_candidate_before_network(
    tmp_path: Path,
    tamper: str,
) -> None:
    """A new update must not prune the last usable rollback in favor of an untrusted current."""
    layout = _installed_layout(tmp_path)
    base_url = "https://releases.example.test/xferry/releases"
    downloader = FakeDownloader(_remote_assets(base_url, "0.2.0", b"release-two"))
    manager = _manager(tmp_path, layout, downloader)
    assert manager.update("0.2.0", False).exit_code == 0
    current = layout.release_root / "releases/0.2.0"
    signature = current / "xferry-release.json.sig"
    if tamper == "missing":
        signature.unlink()
    elif tamper == "invalid":
        signature.write_bytes(b'{"invalid":true}\n')
    else:
        unknown_key = Ed25519PrivateKey.generate()
        manifest = _v2_manifest(
            "0.2.0",
            b"release-two",
            signed=True,
            key_id="unknown-release-key",
        )
        current.joinpath("xferry-release.json").write_bytes(manifest)
        signature.write_bytes(
            _manifest_signature(
                manifest,
                key_id="unknown-release-key",
                private_key=unknown_key,
            )
        )
    requests_before = list(downloader.requests)
    downloader.assets.update(_remote_assets(base_url, "0.3.0", b"release-three"))

    result = manager.update("0.3.0", False)

    assert result.message == "unsupported_managed_state"
    assert downloader.requests == requests_before
    assert layout.release_root.joinpath("current").readlink() == Path("releases/0.2.0")
    assert sorted(path.name for path in layout.release_root.joinpath("releases").iterdir()) == [
        "0.1.0",
        "0.2.0",
    ]


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

    assert result == _update_result(
        1,
        "release_operation_failed",
        active="0.1.0",
        rollback="not_attempted",
    )
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
        version = (layout.release_root / "current").readlink().name
        health_versions.append(version)
        return HealthResult(True, "healthy", version)

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


def test_update_waits_for_eventual_exact_target_health_after_restart(tmp_path: Path) -> None:
    """A transient first PING must not roll back a candidate that becomes ready."""
    layout = _installed_layout(tmp_path)
    base_url = "https://releases.example.test/xferry/releases"
    downloader = FakeDownloader(_remote_assets(base_url, "0.2.0", b"release-two"))
    attempts: dict[str, int] = {}

    def health(*_args: object) -> HealthResult:
        version = (layout.release_root / "current").readlink().name
        attempts[version] = attempts.get(version, 0) + 1
        if version == "0.2.0" and attempts[version] == 1:
            return HealthResult(False, "connection failed")
        return HealthResult(True, "healthy", version)

    result = _manager(tmp_path, layout, downloader, health=health).update("0.2.0", False)

    assert result == _update_result(
        0,
        "update_complete",
        active="0.2.0",
        rollback="not_needed",
    )
    assert attempts == {"0.2.0": 2}
    assert (layout.release_root / "current").readlink() == Path("releases/0.2.0")


def test_restore_waits_for_eventual_exact_previous_health_after_restart(
    tmp_path: Path,
) -> None:
    """A transient first PING must not hide a successfully restored prior release."""
    layout = _installed_layout(tmp_path)
    base_url = "https://releases.example.test/xferry/releases"
    downloader = FakeDownloader(_remote_assets(base_url, "0.2.0", b"release-two"))
    runner = FakeRunner(restart_failures=1)
    attempts = 0

    def health(*_args: object) -> HealthResult:
        nonlocal attempts
        attempts += 1
        version = (layout.release_root / "current").readlink().name
        if attempts == 1:
            return HealthResult(False, "connection failed")
        return HealthResult(True, "healthy", version)

    result = _manager(
        tmp_path,
        layout,
        downloader,
        runner=runner,
        health=health,
    ).update("0.2.0", False)

    assert result == _update_result(
        6,
        "candidate_restart_failed",
        active="0.1.0",
        rollback="restored",
    )
    assert attempts == 2
    assert (layout.release_root / "current").readlink() == Path("releases/0.1.0")


def test_update_readiness_deadline_never_uses_a_non_positive_health_timeout(
    tmp_path: Path,
) -> None:
    """An expired readiness budget must stop before an invalid zero-timeout probe."""
    layout = _installed_layout(tmp_path)
    base_url = "https://releases.example.test/xferry/releases"
    downloader = FakeDownloader(_remote_assets(base_url, "0.2.0", b"release-two"))
    timeouts: list[float] = []

    def health(
        _endpoint: HealthEndpoint,
        _username: str,
        _password: str,
        timeout: float,
    ) -> HealthResult:
        version = (layout.release_root / "current").readlink().name
        timeouts.append(timeout)
        if version == "0.2.0":
            return HealthResult(False, "connection failed")
        return HealthResult(True, "healthy", version)

    result = _manager(tmp_path, layout, downloader, health=health).update("0.2.0", False)

    assert result == _update_result(
        6,
        "candidate_unhealthy",
        active="0.1.0",
        rollback="restored",
    )
    assert timeouts == [2.0, 1.75, 1.25, 0.25, 2.0]
    assert all(timeout > 0 for timeout in timeouts)


def test_unhealthy_candidate_restores_and_verifies_previous_release(tmp_path: Path) -> None:
    """A health failure must restore both link and a demonstrably healthy previous service."""
    layout = _installed_layout(tmp_path)
    base_url = "https://releases.example.test/xferry/releases"
    downloader = FakeDownloader(_remote_assets(base_url, "0.2.0", b"release-two"))
    observed: list[str] = []

    def health(*_args: object) -> HealthResult:
        version = (layout.release_root / "current").readlink().name
        observed.append(version)
        return HealthResult(
            version == "0.1.0",
            "healthy" if version == "0.1.0" else "bad",
            version,
        )

    runner = FakeRunner()
    result = _manager(tmp_path, layout, downloader, runner=runner, health=health).update(
        "0.2.0", False
    )

    assert result == _update_result(
        6,
        "candidate_unhealthy",
        active="0.1.0",
        rollback="restored",
    )
    assert observed == ["0.2.0", "0.1.0"]
    assert runner.restart_count == 2
    assert runner.active is True
    assert (layout.release_root / "current").readlink() == Path("releases/0.1.0")


def test_ready_old_process_is_rejected_and_previous_exact_version_is_restored(
    tmp_path: Path,
) -> None:
    """Readiness from the old process must not authorize activation of a new symlink target."""
    layout = _installed_layout(tmp_path)
    base_url = "https://releases.example.test/xferry/releases"
    downloader = FakeDownloader(_remote_assets(base_url, "0.2.0", b"release-two"))
    observed: list[str] = []

    def health(*_args: object) -> HealthResult:
        observed.append((layout.release_root / "current").readlink().name)
        return HealthResult(True, "healthy", "0.1.0")

    result = _manager(tmp_path, layout, downloader, health=health).update("0.2.0", False)

    assert result.message == "candidate_unhealthy"
    assert result.rollback == "restored"
    assert result.active == "0.1.0"
    assert observed == ["0.2.0", "0.1.0"]
    assert (layout.release_root / "current").readlink() == Path("releases/0.1.0")


def test_restore_rejects_ready_response_for_the_wrong_previous_version(tmp_path: Path) -> None:
    """A restored link is insufficient when another ready XFerry process answers the probe."""
    layout = _installed_layout(tmp_path)
    base_url = "https://releases.example.test/xferry/releases"
    downloader = FakeDownloader(_remote_assets(base_url, "0.2.0", b"release-two"))
    responses = iter(
        (
            HealthResult(False, "candidate unhealthy", "0.2.0"),
            HealthResult(True, "healthy", "0.0.9"),
        )
    )

    result = _manager(
        tmp_path,
        layout,
        downloader,
        health=lambda *_args: next(responses),
    ).update("0.2.0", False)

    assert result.message == "restore_incomplete"
    assert result.rollback == "incomplete"
    assert result.active == "0.1.0"


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

    assert result == ReleaseResult(
        1,
        "unsupported_managed_state",
        version="0.2.0",
        target="0.2.0",
    )
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

    assert result == _update_result(
        6,
        "candidate_unhealthy",
        active="0.1.0",
        rollback="restored",
    )
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

    assert result == _update_result(
        1,
        "restore_incomplete",
        active="0.1.0",
        rollback="incomplete",
    )
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

    assert result == _update_result(
        6,
        "candidate_unhealthy",
        active="0.1.0",
        rollback="restored",
    )
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
    assert result == _update_result(
        1,
        "restore_incomplete",
        active="0.2.0",
        rollback="incomplete",
    )
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
        return HealthResult(version == "0.1.0", "sanitized", version)

    result = _manager(tmp_path, layout, downloader, runner=runner, health=health).update(
        "0.2.0", False
    )

    assert result == _update_result(
        1,
        "restore_incomplete",
        active="0.1.0",
        rollback="incomplete",
    )
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


def test_release_preflight_uses_the_managers_platform_source(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An injected platform must govern both inventory validation and rollback."""
    layout = _installed_layout(tmp_path)
    _seed_release(layout, "0.2.0", b"release-two")
    monkeypatch.setattr(
        "xferry.management.managed_state.current_platform_id",
        lambda: "linux-aarch64",
    )

    result = _manager(tmp_path, layout, FakeDownloader({})).rollback("0.2.0", True)

    assert result == ReleaseResult(
        0,
        "rollback_dry_run",
        version="0.2.0",
        dry_run=True,
    )


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
    manifest_url = f"{base_url}/download/v0.2.0/xferry-release-linux-x86_64.json"
    downloader = FakeDownloader({manifest_url: OSError(f"failed with {secret}")})
    runner = FakeRunner()

    with caplog.at_level(logging.DEBUG, logger="xferry"):
        result = _manager(tmp_path, layout, downloader, runner=runner).update("0.2.0", False)

    combined_urls = " ".join(request[0] for request in downloader.requests)
    combined_argv = " ".join(" ".join(command) for command in runner.commands)
    assert result == _update_result(
        5,
        "release_download_failed",
        active="0.1.0",
        rollback="not_attempted",
    )
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

    assert result == _update_result(
        1,
        "restore_incomplete",
        active="0.1.0",
        rollback="incomplete",
    )
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

    assert result == ReleaseResult(
        3,
        "release_requires_root",
        version="0.2.0",
        target="0.2.0",
        next_actions=("Run this managed update as root with `sudo`.",),
    )
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
        version = (layout.release_root / "current").readlink().name
        return HealthResult(True, "healthy", version)

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
    manager = _manager(tmp_path, layout, downloader, runner=runner)

    update = manager.update("0.2.0", True)
    rollback = manager.rollback("0.1.1", True)
    uninstall = manager.uninstall(False, False, True)

    assert update == ReleaseResult(
        0,
        "update_dry_run",
        version="0.2.0",
        dry_run=True,
        detail=(
            "Signed metadata verified. Apply will download and verify the executable, "
            "validate the managed configuration, restart the service, require exact-version "
            "health, and retain 0.1.0 for rollback."
        ),
        before="0.1.0",
        target="0.2.0",
        active="0.1.0",
        rollback="not_needed",
        next_actions=("Run `sudo xferry update --to 0.2.0` to apply.",),
    )
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
    assert runner.commands == []
    assert not (tmp_path / "staging").exists()
    assert downloader.read_requests == [
        (
            f"{base_url}/download/v0.2.0/xferry-release-linux-x86_64.json",
            release_module._MAX_MANIFEST_BYTES,
        ),
        (
            f"{base_url}/download/v0.2.0/xferry-release-linux-x86_64.json.sig",
            release_module._MAX_SIGNATURE_BYTES,
        ),
    ]
    assert downloader.download_requests == []


@dataclass
class FakeReleaseManager:
    """Capture the CLI-to-release-manager boundary without host effects."""

    calls: list[tuple[object, ...]]

    def update(self, to_version: str, dry_run: bool) -> ReleaseResult:
        self.calls.append(("update", to_version, dry_run))
        return ReleaseResult(
            0,
            "update_dry_run" if dry_run else "update_complete",
            version=to_version,
            dry_run=dry_run,
            detail=(
                "Signed metadata verified; apply will verify the artifact and configuration, "
                "restart the service, and require exact-version health."
            ),
            before="0.1.0",
            target=to_version,
            active="0.1.0" if dry_run else to_version,
            rollback="not_needed",
            next_actions=(f"Run `sudo xferry update --to {to_version}` to apply.",)
            if dry_run
            else (),
        )

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
    monkeypatch.setattr("xferry.management.releases.default_update_manager", lambda: fake)
    monkeypatch.setattr("xferry.management.releases.default_release_manager", lambda: fake)
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)

    assert cli.main(["update", "--to", "0.2.0", "--dry-run"]) == 0
    assert cli.main(["rollback", "--to", "0.1.0", "--dry-run"]) == 0
    assert cli.main(["uninstall", "--purge-data"]) == 0
    assert fake.calls == [
        ("update", "0.2.0", True),
        ("rollback", "0.1.0", True),
        ("uninstall", True, False, False),
    ]
    assert "not implemented" not in (capsys.readouterr().out + capsys.readouterr().err).lower()


def test_cli_update_json_schema_is_complete_and_language_independent(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Changing locale or omitting recovery fields must not destabilize automation output."""
    fake = FakeReleaseManager([])
    monkeypatch.setattr("xferry.management.releases.default_update_manager", lambda: fake)

    assert cli.main(["--lang", "ru", "update", "--to", "0.2.0", "--dry-run", "--json"]) == 0

    assert json.loads(capsys.readouterr().out) == {
        "active": "0.1.0",
        "before": "0.1.0",
        "code": "update_dry_run",
        "detail": (
            "Signed metadata verified; apply will verify the artifact and configuration, "
            "restart the service, and require exact-version health."
        ),
        "dry_run": True,
        "exit_code": 0,
        "message": "XFerry 0.2.0 passed update verification; no managed state changed.",
        "next_actions": ["Run `sudo xferry update --to 0.2.0` to apply."],
        "rollback": "not_needed",
        "status": "ok",
        "target": "0.2.0",
        "version": "0.2.0",
    }
    assert fake.calls == [("update", "0.2.0", True)]


def test_cli_update_text_renders_dry_run_plan_and_next_action(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Plain-text operators need the verified plan and the exact apply command."""
    fake = FakeReleaseManager([])
    monkeypatch.setattr("xferry.management.releases.default_update_manager", lambda: fake)

    assert cli.main(["update", "--to", "0.2.0", "--dry-run"]) == 0

    output = capsys.readouterr().out
    assert "Signed metadata verified" in output
    assert "sudo xferry update --to 0.2.0" in output


def test_cli_update_text_renders_portable_pipx_action(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Portable users must see the lifecycle command instead of only a generic rejection."""
    fake = FakeReleaseManager([])
    fake.update = lambda to_version, dry_run: ReleaseResult(  # type: ignore[method-assign]
        4,
        "portable_installation",
        version=to_version,
        dry_run=dry_run,
        detail="No supported XFerry managed installation was found; no changes were made.",
        target=to_version,
        next_actions=("Run `pipx upgrade xferry` for a portable installation.",),
    )
    monkeypatch.setattr("xferry.management.releases.default_update_manager", lambda: fake)

    assert cli.main(["update", "--to", "0.2.0"]) == 4

    output = capsys.readouterr().err
    assert "No supported XFerry managed installation was found" in output
    assert "pipx upgrade xferry" in output


def test_cli_update_json_failure_preserves_dry_run_and_known_release_identities(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Automation must not mistake a failed dry-run for apply or lose known state."""
    layout = _installed_layout(tmp_path)
    base_url = "https://releases.example.test/xferry/releases"
    manifest_url = f"{base_url}/download/v0.2.0/xferry-release-linux-x86_64.json"
    manager = _manager(
        tmp_path,
        layout,
        FakeDownloader({manifest_url: OSError("transport details must stay secret")}),
    )
    monkeypatch.setattr("xferry.management.releases.default_update_manager", lambda: manager)

    assert cli.main(["update", "--to", "0.2.0", "--dry-run", "--json"]) == 5

    payload = json.loads(capsys.readouterr().out)
    assert payload["code"] == "release_download_failed"
    assert payload["dry_run"] is True
    assert payload["before"] == "0.1.0"
    assert payload["target"] == "0.2.0"
    assert payload["active"] == "0.1.0"
    assert "transport details" not in json.dumps(payload)
