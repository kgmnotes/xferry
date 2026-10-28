"""Canonical backend lifecycle and explicit legacy migration regressions."""

from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest

from tests.test_deployment_wizard import DockerRunner
from tests.test_management_releases import (
    FakeDownloader,
    _layout,
    _manager,
    _remote_assets,
    _seed_release,
    _seed_uninstall_state,
    _set_current,
)
from tests.test_management_setup import FakeRunner as SetupRunner
from tests.test_management_setup import _executor
from xferry.management import docker_deploy
from xferry.management.health import HealthResult
from xferry.management.managed_state import (
    RETAINED_STATE_CONTENT,
    has_retained_state,
    has_unsupported_managed_state,
    retained_state_path,
)
from xferry.management.migration import canonicalize_legacy_text, migrate_config
from xferry.settings import load_settings_file


@pytest.fixture(autouse=True)
def isolated_instance_registry(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "user-data"))


def _docker(tmp_path: Path) -> Path:
    output = tmp_path / "deployment"
    result = docker_deploy.deploy_docker(
        output,
        files_dir=tmp_path / "files",
        private=True,
        runner=DockerRunner(),
        image="ghcr.io/kgmnotes/xferry:v0.2.0",
    )
    assert result.exit_code == 0, result.message
    return output


def test_docker_edit_keeps_selected_image_after_host_cli_upgrade(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output = _docker(tmp_path)
    monkeypatch.setattr(docker_deploy, "__version__", "0.2.99")
    result = docker_deploy.deploy_docker(
        output, settings_changes={"max_size_mb": 42}, runner=DockerRunner()
    )
    assert result.exit_code == 0, result.message
    compose = json.loads((output / "compose.yaml").read_text())
    assert {service["image"] for service in compose["services"].values()} == {
        "ghcr.io/kgmnotes/xferry:v0.2.0"
    }


@pytest.mark.parametrize("purge", [False, True])
def test_docker_uninstall_reinstall_keeps_host_files_and_resumes(
    tmp_path: Path, purge: bool
) -> None:
    output = _docker(tmp_path)
    config = output / "xferry.ini"
    auth = output / "secrets/xferry_auth"
    prior_auth = auth.read_bytes()
    upload = tmp_path / "files/keep.txt"
    upload.write_text("uploaded data")
    removed = docker_deploy.docker_operation(
        config, "uninstall", purge_data=purge, runner=DockerRunner()
    )
    assert removed.exit_code == 0, removed.message
    assert removed.details and removed.details["running"] is False
    assert removed.details["status"] == ("purged" if purge else "removed")
    assert upload.read_text() == "uploaded data"
    runner = DockerRunner(running=False)
    reinstalled = docker_deploy.deploy_docker(output, runner=runner)
    assert reinstalled.exit_code == 0, reinstalled.message
    assert any("up" in command for command in runner.commands)
    assert (auth.read_bytes() != prior_auth) is purge
    assert (reinstalled.password is not None) is purge


def test_docker_operation_results_describe_the_new_server_state(tmp_path: Path) -> None:
    output = _docker(tmp_path)
    stopped = docker_deploy.docker_operation(
        output / "xferry.ini", "stop", runner=DockerRunner(running=True)
    )
    assert stopped.exit_code == 0 and stopped.details
    assert stopped.details["status"] == "stopped" and stopped.details["running"] is False
    started = docker_deploy.docker_operation(
        output / "xferry.ini", "start", runner=DockerRunner(running=False)
    )
    assert started.exit_code == 0 and started.details
    assert started.details["status"] == "running" and started.details["running"] is True


@pytest.mark.parametrize("running", [False, True])
def test_docker_update_and_rollback_preserve_password_and_active_state(
    tmp_path: Path, running: bool
) -> None:
    output = _docker(tmp_path)
    config = output / "xferry.ini"
    password = (output / "secrets/xferry_auth").read_bytes()
    runner = DockerRunner(running=running)
    updated = docker_deploy.docker_operation(config, "update", version="0.2.1", runner=runner)
    assert updated.exit_code == 0, updated.message
    assert updated.details and updated.details["version"] == "0.2.1"
    assert updated.details["running"] is running
    assert ("up" in {part for command in runner.commands for part in command}) is running
    assert json.loads((output / ".xferry-deployment.json").read_text())["version"] == "0.2.1"
    runner.commands.clear()
    rollback = docker_deploy.docker_operation(config, "rollback", runner=runner)
    assert rollback.exit_code == 0, rollback.message
    assert rollback.details and rollback.details["version"] == "0.2.0"
    assert json.loads((output / ".xferry-deployment.json").read_text())["version"] == "0.2.0"
    assert (output / "secrets/xferry_auth").read_bytes() == password
    assert ("up" in {part for command in runner.commands for part in command}) is running


def test_failed_docker_health_restores_release_and_history(tmp_path: Path) -> None:
    output = _docker(tmp_path)
    paths = [output / name for name in ("compose.yaml", "xferry.ini", ".xferry-deployment.json")]
    before = {path: path.read_bytes() for path in paths}
    result = docker_deploy.docker_operation(
        output / "xferry.ini", "update", version="0.2.1", runner=DockerRunner(fail_up=1)
    )
    assert result.exit_code != 0
    assert {path: path.read_bytes() for path in paths} == before
    assert not (output / ".xferry-history.json").exists()


def test_migration_keeps_old_files_notes_certificate_state_and_inline_password(
    tmp_path: Path,
) -> None:
    root = tmp_path / "old-state"
    for folder in (root / "uploads", root / "notes", root / ".xferry"):
        folder.mkdir(parents=True, exist_ok=True)
        (folder / "keep").write_text("retained")
    config = tmp_path / "legacy.ini"
    original = (
        "[server]\npreset=local\nroot_dir=" + str(root) + "\n"
        "quiet=true\njson_log=true\nopen_browser=true\n"
        "[security]\nauth=operator:existing-password\n"
    )
    config.write_text(original)
    result = migrate_config(config)
    assert result.exit_code == 0 and result.changed, result.message
    current = load_settings_file(config)
    assert current.root_dir == str(root)
    assert current.files_dir == str(root / "uploads")
    assert current.access == "private" and current.https_mode == "off"
    assert current.log_level == "warning" and current.log_format == "json"
    assert (tmp_path / "auth").read_text() == "operator:existing-password\n"
    assert stat.S_IMODE((tmp_path / "auth").stat().st_mode) == 0o600
    assert (tmp_path / ".legacy.ini.before-migration").read_text() == original
    assert stat.S_IMODE((tmp_path / ".legacy.ini.before-migration").stat().st_mode) == 0o600
    assert all(
        (root / name / "keep").read_text() == "retained" for name in ("uploads", "notes", ".xferry")
    )
    assert "existing-password" not in repr(result)


def test_migration_never_guesses_old_working_directory(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="working directory"):
        canonicalize_legacy_text("[server]\npreset=local\n", auth_file=tmp_path / "auth")
    plan = canonicalize_legacy_text(
        "[server]\npreset=local\nroot_dir=old-root\n",
        auth_file=tmp_path / "auth",
        state_dir=tmp_path,
    )
    assert plan.state_dir == tmp_path / "old-root"
    with pytest.raises(ValueError, match="differs from the deployment"):
        canonicalize_legacy_text(
            f"[server]\npreset=local\nroot_dir={tmp_path / 'old'}\n",
            auth_file=tmp_path / "auth",
            state_dir=tmp_path / "new",
        )


@pytest.mark.parametrize("name", ["files_dir", "auth_file", "cert_file", "key_file"])
def test_migration_rejects_relative_auxiliary_paths(tmp_path: Path, name: str) -> None:
    section = "server" if name == "files_dir" else "security" if name == "auth_file" else "tls"
    text = f"[server]\npreset=local\nroot_dir={tmp_path / 'state'}\n"
    text += f"{name}=relative\n" if section == "server" else f"[{section}]\n{name}=relative\n"
    with pytest.raises(ValueError, match=f"legacy {name} absolute"):
        canonicalize_legacy_text(text, auth_file=tmp_path / "auth", state_dir=tmp_path / "state")


def test_migration_keeps_concurrent_edit_instead_of_rolling_it_back(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from contextlib import contextmanager

    from xferry.management import configuration

    config = tmp_path / "legacy.ini"
    config.write_text(f"[server]\npreset=local\nroot_dir={tmp_path / 'state'}\n")
    original_lock = configuration._portable_lock
    concurrent = config.read_text() + "# another operator edited this\n"

    @contextmanager
    def edited_lock(path):
        with original_lock(path):
            path.write_text(concurrent)
            yield

    monkeypatch.setattr(configuration, "_portable_lock", edited_lock)
    result = migrate_config(config)
    assert result.exit_code != 0 and not result.changed
    assert config.read_text() == concurrent
    assert not (tmp_path / ".legacy.ini.before-migration").exists()


def test_migration_rejects_ambiguous_and_unsafe_targets_without_writes(tmp_path: Path) -> None:
    config = tmp_path / "legacy.ini"
    original = f"[server]\npreset=local\nroot_dir={tmp_path / 'data'}\n[security]\nauth=random\n"
    config.write_text(original)
    target = tmp_path / "outside"
    target.write_text("private")
    (tmp_path / ".legacy.ini.state.json").symlink_to(target)
    result = migrate_config(config)
    assert result.exit_code != 0 and not result.changed
    assert config.read_text() == original and target.read_text() == "private"
    assert not (tmp_path / "auth").exists()


def test_migration_cancel_and_weak_public_posture_preserve_source(tmp_path: Path) -> None:
    config = tmp_path / "legacy.ini"
    config.write_text(f"[server]\npreset=local\nroot_dir={tmp_path / 'data'}\n")
    before = config.read_bytes()
    cancelled = migrate_config(config, confirm=lambda _: False)
    assert cancelled.exit_code == 0 and not cancelled.changed
    assert config.read_bytes() == before and not (tmp_path / ".legacy.ini.state.json").exists()
    with pytest.raises(ValueError, match="disabled its protections"):
        canonicalize_legacy_text(
            "[server]\npreset=public-direct\npublic_direct=false\n",
            auth_file=tmp_path / "auth",
            state_dir=tmp_path,
        )


def test_portable_migration_does_not_import_native_lifecycle(tmp_path: Path) -> None:
    script = """
import importlib.abc
import sys
from pathlib import Path

class BlockNative(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname in {'grp', 'pwd', 'xferry.management.system'}:
            raise AssertionError('portable workflow imported native lifecycle')
        return None

sys.meta_path.insert(0, BlockNative())
from xferry.management.migration import migrate_config
from xferry.management.docker_deploy import DockerResult
root = Path(sys.argv[1])
config = root / 'legacy.ini'
config.write_text('[server]\\npreset=local\\nroot_dir=' + str(root / 'state') + '\\n')
result = migrate_config(config)
assert result.exit_code == 0, result.message
assert result.changed
"""
    result = subprocess.run(
        [sys.executable, "-c", script, str(tmp_path)], capture_output=True, text=True, check=False
    )
    assert result.returncode == 0, result.stderr


def test_native_retained_receipt_allows_reinstall_and_later_purge(tmp_path: Path) -> None:
    layout = _layout(tmp_path)
    _seed_uninstall_state(tmp_path, layout)
    manager = _manager(tmp_path, layout, FakeDownloader({}))
    removed = manager.uninstall(False, False, False)
    assert removed.exit_code == 0, removed.message
    assert retained_state_path(layout).read_bytes() == RETAINED_STATE_CONTENT
    assert has_retained_state(layout)
    assert not has_unsupported_managed_state(layout, platform_id="linux-x86_64")
    purged = manager.uninstall(True, True, False)
    assert purged.exit_code == 0, purged.message
    assert not layout.config_file.parent.exists() and not layout.data_root.exists()


@pytest.mark.parametrize("healthy", [True, False])
def test_native_reinstall_resumes_saved_configuration_without_rotating_password(
    tmp_path: Path, healthy: bool
) -> None:
    layout = _layout(tmp_path)
    _seed_uninstall_state(tmp_path, layout)
    files = layout.data_root / "files"
    files.mkdir()
    (files / "uploaded.txt").write_text("keep")
    layout.config_file.write_text(
        "[server]\naccess=private\nport=8080\nfiles_dir="
        + str(files)
        + "\n[security]\nauth_file="
        + str(layout.auth_file)
        + "\n[tls]\nhttps_mode=off\n"
    )
    config, password = layout.config_file.read_bytes(), layout.auth_file.read_bytes()
    assert (
        _manager(tmp_path, layout, FakeDownloader({})).uninstall(False, False, False).exit_code == 0
    )
    _seed_release(layout, "0.2.1", b"signed reinstalled runtime")
    _set_current(layout, "0.2.1")
    seen = []

    def health(endpoint, username, secret, timeout):
        seen.append((username, secret))
        return HealthResult(healthy, "healthy" if healthy else "connection failed")

    result = _executor(tmp_path, SetupRunner(), health=health).resume(layout)
    assert (result.exit_code == 0) is healthy, result.message
    assert result.credentials is None
    assert layout.config_file.read_bytes() == config and layout.auth_file.read_bytes() == password
    assert (files / "uploaded.txt").read_text() == "keep"
    assert has_retained_state(layout) is not healthy
    assert seen and all(secret == "known-password" for _, secret in seen)


@pytest.mark.parametrize("kind", ["wrong-content", "public-mode", "hardlink", "symlink"])
def test_native_retained_receipt_rejects_ambiguous_state(tmp_path: Path, kind: str) -> None:
    layout = _layout(tmp_path)
    _seed_uninstall_state(tmp_path, layout)
    assert (
        _manager(tmp_path, layout, FakeDownloader({})).uninstall(False, False, False).exit_code == 0
    )
    path = retained_state_path(layout)
    if kind == "wrong-content":
        path.write_bytes(b"not a receipt\n")
    elif kind == "public-mode":
        path.chmod(0o644)
    elif kind == "hardlink":
        os.link(path, path.with_name("other"))
    else:
        path.unlink()
        target = path.with_name("other")
        target.write_bytes(RETAINED_STATE_CONTENT)
        target.chmod(0o600)
        path.symlink_to(target)
    assert not has_retained_state(layout)
    assert has_unsupported_managed_state(layout, platform_id="linux-x86_64")


@pytest.mark.parametrize("existing_private_files", [False, True])
def test_migration_write_failure_restores_configuration_and_prior_private_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, existing_private_files: bool
) -> None:
    from xferry.management import migration

    config, auth = tmp_path / "legacy.ini", tmp_path / "auth"
    sidecar = tmp_path / ".legacy.ini.state.json"
    state = tmp_path / "state"
    state.mkdir()
    (state / "important.txt").write_text("existing private state")
    before = f"[server]\npreset=local\nroot_dir={state}\n[security]\nauth=random\n"
    config.write_text(before)
    config.chmod(0o640)
    prior_auth = b"admin:abc234def567\n"
    prior_sidecar = (
        json.dumps({"schema": 1, "state_dir": str(state), "files_dir": str(state / "uploads")})
        + "\n"
    ).encode()
    if existing_private_files:
        auth.write_bytes(prior_auth)
        auth.chmod(0o600)
        sidecar.write_bytes(prior_sidecar)
        sidecar.chmod(0o600)
    monkeypatch.setattr(migration, "generate_password", lambda: "abc234def567")
    original_write = migration._write
    failed = False

    def fail_final_publication(path, content, mode):
        nonlocal failed
        if path == config and not failed:
            failed = True
            raise OSError("filesystem became read-only during configuration publication")
        original_write(path, content, mode)

    monkeypatch.setattr(migration, "_write", fail_final_publication)
    result = migrate_config(config)
    assert result.exit_code != 0 and not result.changed and result.credentials is None
    assert config.read_text() == before and stat.S_IMODE(config.stat().st_mode) == 0o640
    if existing_private_files:
        assert auth.read_bytes() == prior_auth and sidecar.read_bytes() == prior_sidecar
    else:
        assert not auth.exists() and not sidecar.exists()
    assert (state / "important.txt").read_text() == "existing private state"
    backup = tmp_path / ".legacy.ini.before-migration"
    assert backup.read_text() == before and stat.S_IMODE(backup.stat().st_mode) == 0o600
    assert "abc234def567" not in repr(result)


@pytest.mark.parametrize("conflict", ["backup", "auth"])
def test_migration_does_not_overwrite_unrelated_backup_or_credentials(
    tmp_path: Path, conflict: str
) -> None:
    config = tmp_path / "legacy.ini"
    config.write_text(
        f"[server]\npreset=local\nroot_dir={tmp_path / 'state'}\n[security]\nauth=random\n"
    )
    source = config.read_bytes()
    protected = tmp_path / (".legacy.ini.before-migration" if conflict == "backup" else "auth")
    protected.write_bytes(b"existing operator-owned material\n")
    protected.chmod(0o600)
    result = migrate_config(config)
    assert result.exit_code != 0 and not result.changed
    assert protected.read_bytes() == b"existing operator-owned material\n"
    assert config.read_bytes() == source
    assert not (tmp_path / ".legacy.ini.state.json").exists()


def test_migration_parser_errors_do_not_expose_inline_password(tmp_path: Path) -> None:
    config = tmp_path / "legacy.ini"
    config.write_text(
        "[server]\npreset=local\n[security]\nauth=operator:keep-this-private\nauth=operator:another-private-value\n"
    )
    original = config.read_bytes()
    result = migrate_config(config, state_dir=tmp_path / "state")
    assert result.exit_code != 0 and "duplicate INI" in result.message
    assert (
        "keep-this-private" not in result.message and "another-private-value" not in result.message
    )
    assert config.read_bytes() == original and not (tmp_path / "auth").exists()


def test_current_configuration_does_not_create_migration_artifacts(tmp_path: Path) -> None:
    config = tmp_path / "xferry.ini"
    config.write_text("[server]\naccess=private\n[tls]\nhttps_mode=off\n")
    before = config.read_bytes()
    result = migrate_config(config)
    assert result.exit_code == 0 and not result.changed and result.credentials is None
    assert config.read_bytes() == before
    assert sorted(path.name for path in tmp_path.iterdir()) == ["xferry.ini"]


def _seed_legacy_managed_service(tmp_path: Path):
    layout = _layout(tmp_path)
    _seed_uninstall_state(tmp_path, layout)
    uploads = layout.data_root / "uploads"
    uploads.mkdir()
    (uploads / "keep.txt").write_text("legacy upload")
    layout.config_file.write_text(
        f"[server]\npreset=local\nroot_dir={layout.data_root}\nport=8080\n"
        f"[security]\nauth_file={layout.auth_file}\n[tls]\ntls=false\n"
    )
    layout.unit_file.write_text(
        "[Service]\nExecStartPre=/opt/xferry/current/xferry run "
        "--config /etc/xferry/xferry.ini --check-config\n"
    )
    return layout


def test_legacy_managed_migration_refuses_before_prompt_or_writing_any_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    layout = _seed_legacy_managed_service(tmp_path)
    before = {
        path: path.read_bytes() for path in (layout.config_file, layout.auth_file, layout.unit_file)
    }
    monkeypatch.setattr("xferry.management.model.ManagedLayout", lambda: layout)
    result = migrate_config(
        layout.config_file,
        state_dir=layout.data_root,
        confirm=lambda _: pytest.fail("old running service must be rejected before confirmation"),
    )
    assert result.exit_code == 2 and not result.changed
    assert "without --purge-data" in result.message
    assert "docs/migration.md" in result.message
    assert {path: path.read_bytes() for path in before} == before
    assert not list(layout.config_file.parent.glob(".*before-migration"))
    assert not list(layout.config_file.parent.glob(".*state.json"))
    assert not layout.lock_file.exists()


@pytest.mark.parametrize("dry_run", [True, False])
def test_legacy_managed_update_uses_verified_new_release_without_reinstall(
    tmp_path: Path, dry_run: bool
) -> None:
    layout = _seed_legacy_managed_service(tmp_path)
    before = layout.config_file.read_bytes(), layout.unit_file.read_bytes()
    downloader = FakeDownloader(
        _remote_assets("https://releases.example.test/xferry/releases", "0.3.0", b"new-runtime")
    )
    manager = _manager(tmp_path, layout, downloader)
    result = manager.update("0.3.0", dry_run)
    assert result.exit_code == 0
    assert result.dry_run is dry_run and result.before == "0.1.0"
    if dry_run:
        assert (layout.config_file.read_bytes(), layout.unit_file.read_bytes()) == before
        assert not downloader.download_requests
        assert not layout.lock_file.exists()
    else:
        assert "access = private" in layout.config_file.read_text()
        assert " config check " in layout.unit_file.read_text()
        assert (layout.release_root / "current").readlink().name == "0.3.0"
    assert (layout.data_root / "uploads/keep.txt").read_text() == "legacy upload"


def test_portable_migration_remains_available_beside_an_older_managed_service(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    layout = _seed_legacy_managed_service(tmp_path)
    portable = tmp_path / "portable.ini"
    portable.write_text(f"[server]\npreset=local\nroot_dir={tmp_path / 'portable-state'}\n")
    managed_before = layout.config_file.read_bytes()
    monkeypatch.setattr("xferry.management.model.ManagedLayout", lambda: layout)
    result = migrate_config(portable)
    assert result.exit_code == 0 and result.changed
    assert load_settings_file(portable).root_dir == str(tmp_path / "portable-state")
    assert layout.config_file.read_bytes() == managed_before


def test_legacy_native_retained_reinstall_migrates_after_removal_and_resumes_with_new_unit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from xferry.management import system

    layout = _seed_legacy_managed_service(tmp_path)
    auth = layout.auth_file.read_bytes()
    original = layout.config_file.read_bytes()
    monkeypatch.setattr("xferry.management.model.ManagedLayout", lambda: layout)
    native_lock = system.managed_mutation
    monkeypatch.setattr(
        system,
        "managed_mutation",
        lambda path: native_lock(path, effective_uid=lambda: 0, root_uid=os.getuid()),
    )
    assert migrate_config(layout.config_file, state_dir=layout.data_root).exit_code == 2
    removed = _manager(tmp_path, layout, FakeDownloader({})).uninstall(False, False, False)
    assert removed.exit_code == 0, removed.message
    assert has_retained_state(layout)
    assert not layout.current_executable.exists() and not layout.unit_file.exists()
    migrated = migrate_config(layout.config_file, state_dir=layout.data_root)
    assert migrated.exit_code == 0 and migrated.changed, migrated.message
    assert (layout.config_file.parent / ".xferry.ini.before-migration").read_bytes() == original
    assert load_settings_file(layout.config_file).files_dir == str(layout.data_root / "uploads")
    assert layout.auth_file.read_bytes() == auth
    _seed_release(layout, "0.2.1", b"new signed runtime")
    _set_current(layout, "0.2.1")
    runner = SetupRunner()
    resumed = _executor(tmp_path, runner).resume(layout)
    assert resumed.exit_code == 0 and resumed.credentials is None, resumed.message
    assert not has_retained_state(layout)
    assert "--check-config" not in layout.unit_file.read_text()
    assert "config check --config" in layout.unit_file.read_text()
    assert "Environment=XFERRY_STATE_HOME=/var/lib/xferry" in layout.unit_file.read_text()
    assert layout.auth_file.read_bytes() == auth
    assert (layout.data_root / "uploads/keep.txt").read_text() == "legacy upload"
    assert any(command[:2] == ("systemctl", "start") for command in runner.commands)
