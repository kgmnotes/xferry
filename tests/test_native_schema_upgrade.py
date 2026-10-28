"""A new maintenance CLI upgrades and rolls back a frozen legacy service safely."""

from __future__ import annotations

import configparser
import json
import os
from pathlib import Path

import pytest

from tests.test_management_releases import (
    FakeDownloader,
    FakeRunner,
    _installed_layout_at,
    _manager,
    _protect_managed_directory,
    _remote_assets,
)
from xferry.management.health import HealthResult
from xferry.management.model import ManagedLayout
from xferry.management.release_configuration import ReleaseConfigurationStore
from xferry.settings import load_settings_text

_BASE = "https://releases.example.test/xferry/releases"


def _legacy(tmp_path: Path) -> ManagedLayout:
    layout = _installed_layout_at(tmp_path, "0.2.1", b"legacy-runtime")
    layout.unit_file.parent.mkdir(parents=True)
    _protect_managed_directory(layout, layout.unit_file.parent)
    layout.unit_file.write_text(
        "[Service]\nUser=xferry\n"
        "ExecStartPre=/opt/xferry/current/xferry run "
        "--config /etc/xferry/xferry.ini --check-config\n"
        "ExecStart=/opt/xferry/current/xferry run --config /etc/xferry/xferry.ini\n"
    )
    layout.unit_file.chmod(0o644)
    layout.config_file.write_text(
        f"[server]\npreset=local\nroot_dir={layout.data_root}\nport=8080\nquiet=true\n"
        f"[security]\nauth_file={layout.auth_file}\n[tls]\ntls=false\n"
    )
    layout.config_file.chmod(0o640)
    for relative, content in (
        ("uploads/keep.txt", b"uploaded-file"),
        ("notes/keep.json", b"encrypted-note"),
        (".xferry/acme/account.key", b"retained-acme-key"),
    ):
        path = layout.data_root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
    _protect_managed_directory(layout, layout.data_root)
    (layout.data_root / ".xferry").chmod(0o700)
    return layout


def _data(layout: ManagedLayout) -> dict[str, bytes]:
    return {
        str(path.relative_to(layout.data_root)): path.read_bytes()
        for path in layout.data_root.rglob("*")
        if path.is_file()
    }


class SchemaRunner(FakeRunner):
    """Reject the command/config/unit combinations that the real old/new binaries reject."""

    def __init__(self, layout: ManagedLayout, **kwargs):
        super().__init__(**kwargs)
        self.layout = layout
        self.validated: list[str] = []

    def run(self, argv):
        command = tuple(str(part) for part in argv)
        if command[1:3] == ("config", "check"):
            text = Path(command[-1]).read_text()
            settings = load_settings_text(text, state_dir=self.layout.data_root)
            assert settings.access == "private"
            assert "root_dir=" not in text and "root_dir =" not in text
            self.validated.append("canonical")
        elif command[-1:] == ("--check-config",):
            assert command[1:3] == ("run", "--config")
            text = Path(command[-2]).read_text()
            parsed = configparser.ConfigParser()
            parsed.read_string(text)
            assert parsed["server"]["preset"] == "local" and "access" not in parsed["server"]
            self.validated.append("legacy")
        elif command == ("systemctl", "restart", "xferry.service"):
            version = (self.layout.release_root / "current").readlink().name
            unit = self.layout.unit_file.read_text()
            config = self.layout.config_file.read_text()
            if version == "0.2.1":
                parsed = configparser.ConfigParser()
                parsed.read_string(config)
                assert "--check-config" in unit and parsed["server"]["preset"] == "local"
            else:
                assert " config check " in unit and "access = private" in config
        return super().run(command)


def _release_manager(tmp_path: Path, layout: ManagedLayout, **runner_options):
    downloader = FakeDownloader(_remote_assets(_BASE, "0.3.0", b"canonical-runtime"))
    runner = SchemaRunner(layout, **runner_options)

    def health(_endpoint, username, password, _timeout):
        assert (username, password) == ("admin", "known-password")
        return HealthResult(True, "healthy", (layout.release_root / "current").readlink().name)

    return _manager(tmp_path, layout, downloader, runner=runner, health=health), runner


@pytest.mark.parametrize("active", [True, False])
def test_native_update_rollback_and_reupgrade_keep_each_matching_schema(tmp_path, active):
    layout = _legacy(tmp_path)
    old = (
        layout.config_file.read_bytes(),
        layout.unit_file.read_bytes(),
        layout.auth_file.read_bytes(),
    )
    data = _data(layout)
    manager, runner = _release_manager(tmp_path, layout, active=active)

    updated = manager.update("0.3.0", False)
    assert updated.exit_code == 0, updated
    assert updated.before == "0.2.1" and updated.active == "0.3.0"
    canonical = layout.config_file.read_bytes(), layout.unit_file.read_bytes()
    assert b"--check-config" not in canonical[1]
    assert layout.auth_file.read_bytes() == old[2]
    assert _data(layout) == data and runner.active is active
    private = layout.config_file.parent / "release-configs/0.2.1.json"
    assert private.stat().st_mode & 0o777 == 0o600
    assert private.parent.stat().st_mode & 0o777 == 0o700

    reverted = manager.rollback("0.2.1", False)
    assert reverted.exit_code == 0, reverted
    assert (layout.config_file.read_bytes(), layout.unit_file.read_bytes()) == old[:2]
    assert layout.auth_file.read_bytes() == old[2]
    assert not layout.config_file.with_name(".xferry.ini.state.json").exists()
    assert _data(layout) == data and runner.active is active
    assert runner.validated == ["canonical", "legacy"]

    again = manager.update("0.3.0", False)
    assert again.exit_code == 0, again
    assert (layout.config_file.read_bytes(), layout.unit_file.read_bytes()) == canonical
    assert layout.auth_file.read_bytes() == old[2]
    assert _data(layout) == data and runner.active is active


@pytest.mark.parametrize("active", [True, False])
def test_failed_cross_schema_restart_restores_old_files_unit_and_service(tmp_path, active):
    layout = _legacy(tmp_path)
    store = ReleaseConfigurationStore(layout, root_uid=os.getuid())
    before, data = store.capture(), _data(layout)
    manager, runner = _release_manager(tmp_path, layout, active=active, restart_failures=1)
    result = manager.update("0.3.0", False)
    assert result.exit_code == 6 and result.rollback == "restored"
    assert result.active == "0.2.1"
    assert store.capture() == before
    assert _data(layout) == data and runner.active is active
    assert not (layout.release_root / "releases/0.3.0").exists()


def test_failed_legacy_rollback_restores_canonical_files_before_restart(tmp_path):
    layout = _legacy(tmp_path)
    manager, runner = _release_manager(tmp_path, layout)
    assert manager.update("0.3.0", False).exit_code == 0
    store = ReleaseConfigurationStore(layout, root_uid=os.getuid())
    before = store.capture()
    runner.restart_failures = 1
    result = manager.rollback("0.2.1", False)
    assert result.exit_code == 6 and result.rollback == "restored"
    assert result.active == "0.3.0"
    assert store.capture() == before
    assert runner.active is True


def test_tampered_snapshot_cannot_redirect_rollback_or_change_active_files(tmp_path):
    layout = _legacy(tmp_path)
    manager, runner = _release_manager(tmp_path, layout)
    assert manager.update("0.3.0", False).exit_code == 0
    store = ReleaseConfigurationStore(layout, root_uid=os.getuid())
    before = store.capture()
    checkpoint = layout.config_file.parent / "release-configs/0.2.1.json"
    document = json.loads(checkpoint.read_text())
    document["manifest_sha256"] = "0" * 64
    checkpoint.write_text(json.dumps(document))
    commands = len(runner.commands)
    result = manager.rollback("0.2.1", False)
    assert result.exit_code == 1
    assert store.capture() == before
    assert len(runner.commands) == commands
    assert (layout.release_root / "current").readlink().name == "0.3.0"


@pytest.mark.parametrize("unsafe", ["symlink", "hardlink", "permissions"])
def test_unsafe_checkpoint_is_rejected_before_a_live_switch(tmp_path, unsafe):
    layout = _legacy(tmp_path)
    manager, runner = _release_manager(tmp_path, layout)
    assert manager.update("0.3.0", False).exit_code == 0
    checkpoint = layout.config_file.parent / "release-configs/0.2.1.json"
    original = checkpoint.read_bytes()
    if unsafe == "permissions":
        checkpoint.chmod(0o644)
    else:
        other = checkpoint.with_name("unrelated.json")
        other.write_bytes(original)
        checkpoint.unlink()
        if unsafe == "symlink":
            checkpoint.symlink_to(other)
        else:
            os.link(other, checkpoint)
    before = layout.config_file.read_bytes(), layout.unit_file.read_bytes()
    result = manager.rollback("0.2.1", False)
    assert result.exit_code == 1
    assert (layout.config_file.read_bytes(), layout.unit_file.read_bytes()) == before
    assert (layout.release_root / "current").readlink().name == "0.3.0"
    assert runner.active


def test_snapshot_publication_failure_does_not_change_the_service(tmp_path, monkeypatch):
    layout = _legacy(tmp_path)
    manager, runner = _release_manager(tmp_path, layout)
    store = ReleaseConfigurationStore(layout, root_uid=os.getuid())
    before = store.capture()

    def fail(*_args, **_kwargs):
        raise OSError("private checkpoint could not be written")

    monkeypatch.setattr(ReleaseConfigurationStore, "save", fail)
    result = manager.update("0.3.0", False)
    assert result.exit_code == 1
    assert store.capture() == before
    assert not any(command[1:2] == ("restart",) for command in runner.commands)
    assert (layout.release_root / "current").readlink().name == "0.2.1"
    assert not (layout.release_root / "releases/0.3.0").exists()


def test_failed_partial_file_publication_restores_previous_deployment(tmp_path, monkeypatch):
    from xferry.management import release_configuration

    layout = _legacy(tmp_path)
    manager, runner = _release_manager(tmp_path, layout)
    store = ReleaseConfigurationStore(layout, root_uid=os.getuid())
    before = store.capture()
    real_write = release_configuration._atomic_write
    failed = False

    def fail_once(path, value):
        nonlocal failed
        if path == layout.unit_file and not failed:
            failed = True
            raise OSError("unit write failed")
        real_write(path, value)

    monkeypatch.setattr(release_configuration, "_atomic_write", fail_once)
    result = manager.update("0.3.0", False)
    assert result.exit_code == 1 and result.rollback == "restored"
    assert store.capture() == before and runner.active
    assert (layout.release_root / "current").readlink().name == "0.2.1"


def test_password_rotation_survives_rollback_and_reupgrade(tmp_path):
    layout = _legacy(tmp_path)
    manager, _runner = _release_manager(tmp_path, layout)
    assert manager.update("0.3.0", False).exit_code == 0
    rotated = b"admin:replacement-password\n"
    layout.auth_file.write_bytes(rotated)

    def health(_endpoint, username, password, _timeout):
        assert (username, password) == ("admin", "replacement-password")
        assert layout.auth_file.read_bytes() == rotated
        return HealthResult(True, "healthy", (layout.release_root / "current").readlink().name)

    manager.health_check = health
    assert manager.rollback("0.2.1", False).exit_code == 0
    assert layout.auth_file.read_bytes() == rotated
    assert manager.update("0.3.0", False).exit_code == 0
    assert layout.auth_file.read_bytes() == rotated


def test_inline_credentials_are_not_replaced_by_an_unused_auth_file(tmp_path):
    layout = _legacy(tmp_path)
    text = layout.config_file.read_text().replace(
        f"auth_file={layout.auth_file}", "auth=operator:inline-password"
    )
    layout.config_file.write_text(text)
    manager, _runner = _release_manager(tmp_path, layout)

    def health(_endpoint, username, password, _timeout):
        assert (username, password) == ("operator", "inline-password")
        assert layout.auth_file.read_bytes() == b"operator:inline-password\n"
        return HealthResult(True, "healthy", (layout.release_root / "current").readlink().name)

    manager.health_check = health
    assert manager.update("0.3.0", False).exit_code == 0
    rotated = b"operator:rotated-password\n"
    layout.auth_file.write_bytes(rotated)

    def rotated_health(_endpoint, username, password, _timeout):
        assert (username, password) == ("operator", "rotated-password")
        assert layout.auth_file.read_bytes() == rotated
        return HealthResult(True, "healthy", (layout.release_root / "current").readlink().name)

    manager.health_check = rotated_health
    assert manager.rollback("0.2.1", False).exit_code == 0
    restored = configparser.ConfigParser()
    restored.read_string(layout.config_file.read_text())
    assert "auth" not in restored["security"]
    assert restored["security"]["auth_file"] == str(layout.auth_file)
    assert layout.auth_file.read_bytes() == rotated
    assert manager.update("0.3.0", False).exit_code == 0
    assert layout.auth_file.read_bytes() == rotated


def test_failed_cross_schema_health_restores_previous_deployment(tmp_path):
    layout = _legacy(tmp_path)
    manager, runner = _release_manager(tmp_path, layout)
    store = ReleaseConfigurationStore(layout, root_uid=os.getuid())
    before = store.capture()

    def health(_endpoint, _username, _password, _timeout):
        version = (layout.release_root / "current").readlink().name
        return HealthResult(version == "0.2.1", "unhealthy", version)

    manager.health_check = health
    result = manager.update("0.3.0", False)
    assert result.exit_code == 6 and result.message == "candidate_unhealthy"
    assert result.rollback == "restored" and result.active == "0.2.1"
    assert store.capture() == before and runner.active


def test_failed_unit_reload_restores_old_deployment_before_activation(tmp_path, monkeypatch):
    from xferry.management.system import CommandResult

    layout = _legacy(tmp_path)
    manager, runner = _release_manager(tmp_path, layout)
    store = ReleaseConfigurationStore(layout, root_uid=os.getuid())
    before = store.capture()
    real_run = runner.run
    failed = False

    def fail_once(argv):
        nonlocal failed
        if tuple(argv) == ("systemctl", "daemon-reload") and not failed:
            failed = True
            return CommandResult(tuple(argv), 1)
        return real_run(argv)

    monkeypatch.setattr(runner, "run", fail_once)
    result = manager.update("0.3.0", False)
    assert result.exit_code == 6 and result.rollback == "restored"
    assert store.capture() == before and runner.active
    assert (layout.release_root / "current").readlink().name == "0.2.1"


def test_failed_candidate_and_restoration_reports_the_actual_version(tmp_path):
    layout = _legacy(tmp_path)
    manager, runner = _release_manager(tmp_path, layout, restart_failures=2)
    result = manager.update("0.3.0", False)
    assert result.message == "restore_incomplete" and result.rollback == "incomplete"
    assert result.active == "0.2.1" and not runner.active
    assert b"preset=local" in layout.config_file.read_bytes()
    assert b"--check-config" in layout.unit_file.read_bytes()


def test_reupgrade_restores_prior_canonical_settings_and_uses_matching_endpoint(tmp_path):
    layout = _legacy(tmp_path)
    manager, _runner = _release_manager(tmp_path, layout)
    assert manager.update("0.3.0", False).exit_code == 0
    text = layout.config_file.read_text().replace("port = 8080", "port = 9090")
    layout.config_file.write_text(text)

    def health(endpoint, _username, _password, _timeout):
        version = (layout.release_root / "current").readlink().name
        assert endpoint.port == (8080 if version == "0.2.1" else 9090)
        return HealthResult(True, "healthy", version)

    manager.health_check = health
    assert manager.rollback("0.2.1", False).exit_code == 0
    assert "port=8080" in layout.config_file.read_text()
    assert manager.update("0.3.0", False).exit_code == 0
    assert layout.config_file.read_text() == text


@pytest.mark.parametrize("swap", ["already", "after-open", "before-rename"])
def test_binding_parent_swap_cannot_redirect_root_publication(tmp_path, monkeypatch, swap):
    from xferry.management import release_configuration as module
    from xferry.management.release_configuration import DeploymentFile, apply_encrypted_binding

    state, outside = tmp_path / "state", tmp_path / "unrelated"
    parent = state / ".xferry"
    parent.mkdir(parents=True, mode=0o700)
    parent.chmod(0o700)
    outside.mkdir()
    target = parent / "encrypted-storage-root"
    unrelated = outside / target.name
    unrelated.write_bytes(b"unrelated protected contents")
    value = DeploymentFile(b"verified binding", 0o600, os.getuid(), os.getgid())
    moved = state / "original-private-directory"

    def replace_parent():
        parent.rename(moved)
        parent.symlink_to(outside, target_is_directory=True)

    real_open, real_replace = module.os.open, module.os.replace
    if swap == "already":
        replace_parent()
    elif swap == "after-open":
        changed = False

        def swapped_open(path, *args, **kwargs):
            nonlocal changed
            descriptor = real_open(path, *args, **kwargs)
            if Path(path) == parent and not changed:
                changed = True
                replace_parent()
            return descriptor

        monkeypatch.setattr(module.os, "open", swapped_open)
    else:

        def swapped_replace(source, destination, **kwargs):
            if kwargs.get("src_dir_fd") is not None:
                replace_parent()
            return real_replace(source, destination, **kwargs)

        monkeypatch.setattr(module.os, "replace", swapped_replace)

    with pytest.raises((OSError, ValueError)):
        apply_encrypted_binding(target, value, owner=os.getuid())
    assert unrelated.read_bytes() == b"unrelated protected contents"
    assert sorted(path.name for path in outside.iterdir()) == [target.name]


def test_private_snapshot_does_not_expose_credential_bytes_in_repr(tmp_path):
    from xferry.management.release_configuration import DeploymentFile

    secret = b"operator:do-not-print-this-password"
    value = DeploymentFile(secret, 0o600, os.getuid(), os.getgid())
    assert "do-not-print" not in repr(value)


@pytest.mark.parametrize(
    "tamper", ["unknown-path", "invalid-base64", "owner", "mode", "missing-unit"]
)
def test_checkpoint_content_cannot_change_the_known_paths_or_file_identity(tmp_path, tamper):
    layout = _legacy(tmp_path)
    store = ReleaseConfigurationStore(layout, root_uid=os.getuid())
    manifest = (layout.release_root / "releases/0.2.1/xferry-release.json").read_bytes()
    before = store.capture()
    store.save("0.2.1", manifest, before, legacy=True)
    checkpoint = layout.config_file.parent / "release-configs/0.2.1.json"
    document = json.loads(checkpoint.read_text())
    if tamper == "unknown-path":
        document["files"]["../../unrelated"] = document["files"]["config"]
    elif tamper == "invalid-base64":
        document["files"]["config"]["content"] = "not:base64!"
    elif tamper == "owner":
        document["files"]["config"]["uid"] = os.getuid() + 1
    elif tamper == "mode":
        document["files"]["config"]["mode"] = 0o7777
    else:
        document["files"]["unit"] = None
    checkpoint.write_text(json.dumps(document))
    with pytest.raises(ValueError, match="checkpoint"):
        store.load("0.2.1", manifest)
    assert store.capture() == before


def test_encrypted_legacy_upload_survives_update_rollback_and_reupgrade(tmp_path):
    from tests.test_encrypted_storage import FILE_ID, _manifest
    from xferry.encrypted_storage import EncryptedStorageService
    from xferry.storage import UploadStorageService

    layout = _legacy(tmp_path)
    files = layout.data_root / "uploads"
    files.chmod(0o700)
    original = EncryptedStorageService(
        layout.data_root,
        UploadStorageService(files),
        max_plaintext_size=1024,
        incomplete_ttl=86400,
    )
    original.create(_manifest())
    binding = layout.data_root / ".xferry/encrypted-storage-root"
    binding.unlink()  # A real pre-binding release left these same journals/ciphertext.
    layout.config_file.write_text(
        layout.config_file.read_text().replace("[server]\n", "[server]\nencrypted_uploads=true\n")
    )
    # Use real new binding admission during the mocked service's health check.
    ciphertext = files / ".xferry-encrypted" / f"{FILE_ID}.part"
    journal = layout.data_root / ".xferry/encrypted-uploads" / f"{FILE_ID}.json"
    before = ciphertext.read_bytes(), journal.read_bytes()
    manager, _runner = _release_manager(tmp_path, layout)

    def health(_endpoint, _username, _password, _timeout):
        version = (layout.release_root / "current").readlink().name
        if version == "0.3.0":
            storage = EncryptedStorageService(
                layout.data_root,
                UploadStorageService(files),
                max_plaintext_size=1024,
                incomplete_ttl=86400,
                allow_legacy_adoption=False,
            )
            assert storage.get(FILE_ID) is not None
        return HealthResult(True, "healthy", version)

    manager.health_check = health
    assert manager.update("0.3.0", False).exit_code == 0
    assert binding.is_file()
    assert (ciphertext.read_bytes(), journal.read_bytes()) == before
    assert manager.rollback("0.2.1", False).exit_code == 0
    assert not binding.exists()
    assert (ciphertext.read_bytes(), journal.read_bytes()) == before
    assert manager.update("0.3.0", False).exit_code == 0
    assert binding.is_file()
    assert (ciphertext.read_bytes(), journal.read_bytes()) == before


def _portable_encrypted_legacy(tmp_path, *, bound=False):
    from tests.test_encrypted_storage import FILE_ID, _manifest
    from xferry.encrypted_storage import EncryptedStorageService
    from xferry.storage import UploadStorageService

    root = tmp_path / "private-state"
    files = root / "uploads"
    files.mkdir(parents=True, mode=0o700)
    root.chmod(0o700)
    files.chmod(0o700)
    service = EncryptedStorageService(
        root, UploadStorageService(files), max_plaintext_size=1024, incomplete_ttl=86400
    )
    service.create(_manifest())
    (root / ".xferry").chmod(0o700)
    binding = root / ".xferry/encrypted-storage-root"
    if not bound:
        binding.unlink()
    config = tmp_path / "legacy.ini"
    config.write_text(f"[server]\npreset=local\nroot_dir={root}\nencrypted_uploads=true\n")
    journal = root / ".xferry/encrypted-uploads" / f"{FILE_ID}.json"
    ciphertext = files / ".xferry-encrypted" / f"{FILE_ID}.part"
    return config, root, files, binding, journal, ciphertext


def test_portable_migration_adopts_only_the_existing_legacy_encrypted_root(tmp_path):
    from tests.test_encrypted_storage import FILE_ID
    from xferry.encrypted_storage import EncryptedStorageService
    from xferry.management.migration import migrate_config
    from xferry.settings import load_settings_file
    from xferry.storage import UploadStorageService

    config, root, files, binding, journal, ciphertext = _portable_encrypted_legacy(tmp_path)
    before = journal.read_bytes(), ciphertext.read_bytes()
    result = migrate_config(config)
    assert result.exit_code == 0 and result.changed
    assert binding.stat().st_uid == binding.parent.stat().st_uid
    assert binding.stat().st_gid == binding.parent.stat().st_gid
    assert binding.stat().st_mode & 0o777 == 0o600
    loaded = load_settings_file(config).to_server_config()
    assert loaded.root_dir == root and loaded.files_dir == files
    storage = EncryptedStorageService(
        root,
        UploadStorageService(files),
        max_plaintext_size=1024,
        incomplete_ttl=86400,
        allow_legacy_adoption=False,
    )
    assert storage.get(FILE_ID) is not None
    assert (journal.read_bytes(), ciphertext.read_bytes()) == before


@pytest.mark.parametrize("bound", [True, False])
def test_failed_portable_migration_restores_prior_encrypted_binding(tmp_path, monkeypatch, bound):
    from xferry.management import migration

    config, _root, _files, binding, journal, ciphertext = _portable_encrypted_legacy(
        tmp_path, bound=bound
    )
    before = config.read_bytes(), journal.read_bytes(), ciphertext.read_bytes()
    previous_binding = binding.read_bytes() if bound else None
    original = migration._write
    failed = False

    def fail_last_write(path, content, mode):
        nonlocal failed
        if path == config and not failed:
            failed = True
            raise OSError("configuration publication failed")
        original(path, content, mode)

    monkeypatch.setattr(migration, "_write", fail_last_write)
    result = migration.migrate_config(config)
    assert failed
    assert result.exit_code == 2
    assert (config.read_bytes(), journal.read_bytes(), ciphertext.read_bytes()) == before
    assert (binding.read_bytes() if binding.exists() else None) == previous_binding
    assert not config.with_name(f".{config.name}.state.json").exists()


@pytest.mark.parametrize("published", ["config-only", "config-and-unit"])
@pytest.mark.parametrize("active", [True, False])
def test_same_version_rollback_recovers_interruption_before_current_switch(
    tmp_path, published, active
):
    layout = _legacy(tmp_path)
    manager, runner = _release_manager(tmp_path, layout, active=active)
    store = ReleaseConfigurationStore(layout, root_uid=os.getuid())
    before, data = store.capture(), _data(layout)
    manifest = manager._release_manifest_bytes("0.2.1")
    store.save("0.2.1", manifest, before, legacy=True)
    checkpoint = layout.config_file.parent / "release-configs/0.2.1.json"
    checkpoint_before = checkpoint.read_bytes()
    prepared = manager._migrated_deployment(before)
    interrupted = dict(before)
    if published == "config-only":
        interrupted["config"] = prepared["config"]
    else:
        interrupted = prepared
    store.apply(interrupted)  # Process exits here, before atomic current-link switch.
    assert (layout.release_root / "current").readlink().name == "0.2.1"

    result = manager.rollback("0.2.1", False)
    assert result.exit_code == 0, result
    assert store.capture() == before
    assert checkpoint.read_bytes() == checkpoint_before
    assert _data(layout) == data
    assert runner.active is active
    assert runner.validated == ["legacy"]


@pytest.mark.parametrize("active", [True, False])
def test_matching_current_version_and_schema_remain_a_noop(tmp_path, active):
    layout = _legacy(tmp_path)
    manager, runner = _release_manager(tmp_path, layout, active=active)
    store = ReleaseConfigurationStore(layout, root_uid=os.getuid())
    before = store.capture()
    store.save("0.2.1", manager._release_manifest_bytes("0.2.1"), before, legacy=True)
    result = manager.rollback("0.2.1", False)
    assert result.exit_code == 0
    assert store.capture() == before
    assert not runner.commands
    assert runner.active is active
