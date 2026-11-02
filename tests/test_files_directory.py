"""Exact host file directories and non-destructive encrypted storage binding."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from tests.conftest import make_request
from tests.server_factory import make_server
from tests.test_encrypted_storage import FILE_ID, _manifest
from xferry.encrypted_storage import EncryptedStorageConflict, EncryptedStorageService
from xferry.server_config import AuthConfig, ServerConfig, TLSConfig, resolve_server_config
from xferry.settings import SettingsError, load_settings_file, load_settings_text, resolve_settings
from xferry.storage import UploadStorageService


def _encrypted(root: Path, files: Path) -> EncryptedStorageService:
    files.mkdir(parents=True, exist_ok=True)
    return EncryptedStorageService(
        root, UploadStorageService(files), max_plaintext_size=1024, incomplete_ttl=86400
    )


def test_files_dir_is_exact_folder_for_existing_files_and_new_uploads(tmp_path: Path) -> None:
    root = tmp_path / "private"
    files = tmp_path / "мои файлы"
    files.mkdir()
    existing = files / "existing.txt"
    existing.write_bytes(b"already here")
    nested = files / "subfolder"
    nested.mkdir()
    (nested / "nested.txt").write_bytes(b"nested")
    server = make_server(root_dir=root, files_dir=files, quiet=True)

    assert server.upload_dir == files
    assert not (files / "uploads").exists()
    assert server._dispatch_handler(make_request("GET", "/uploads/existing.txt")).stream_path == (
        existing
    )
    assert (
        server._dispatch_handler(make_request("GET", "/uploads/subfolder/nested.txt")).stream_path
        == nested / "nested.txt"
    )
    response = server._dispatch_handler(
        make_request("POST", "/uploads", headers={"X-File-Name": "new.txt"}, body=b"new")
    )
    assert response.status_code == 201
    assert (files / "new.txt").read_bytes() == b"new"
    assert server.notes_dir == root / "notes"
    assert server._dispatch_handler(make_request("GET", "/uploads/../notes")).status_code == 404


def test_files_dir_surfaces_preserve_precedence_and_effective_path(tmp_path: Path) -> None:
    file_settings = load_settings_text(
        f"[server]\nconfig_version=1\nfiles_dir = {tmp_path / 'file'}\n"
    )
    settings = resolve_settings(
        file_settings=file_settings,
        env={"XFERRY_FILES_DIR": str(tmp_path / "environment")},
        cli_values={"files_dir": str(tmp_path / "command line")},
    )
    assert settings.to_server_config().files_dir == tmp_path / "command line"
    assert settings.runtime_posture().uploads_path == str(tmp_path / "command line")
    assert settings.to_redacted_dict()["files_dir"] == str(tmp_path / "command line")


def test_files_dir_cli_and_legacy_fallback(tmp_path: Path) -> None:
    from xferry.cli import create_parser

    assert create_parser().parse_args(["--files-dir", str(tmp_path)]).files_dir == str(tmp_path)
    server = make_server(root_dir=tmp_path, quiet=True)
    assert server.upload_dir == tmp_path / "uploads"


def test_files_dir_relative_path_is_normalized(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    config = resolve_server_config(ServerConfig(root_dir="private", files_dir="./shared files"))
    assert config.files_dir == tmp_path / "shared files"


@pytest.mark.parametrize("folder", [".", "notes", "notes/subfolder", ".xferry"])
def test_files_dir_cannot_expose_private_state(tmp_path: Path, folder: str) -> None:
    with pytest.raises(ValueError, match="files_dir.*private"):
        resolve_server_config(ServerConfig(root_dir=tmp_path, files_dir=tmp_path / folder))


@pytest.mark.parametrize("relation", ["exact", "nested", "parent", "symlink"])
@pytest.mark.skipif(not hasattr(os, "getuid"), reason="native mapping requires POSIX identities")
def test_native_mapping_cannot_publish_private_transfer_state(
    tmp_path: Path, relation: str
) -> None:
    from xferry.management.managed_files import stage_managed_files_folder
    from xferry.management.model import ManagedLayout
    from xferry.management.system import FilesystemTransaction

    layout = ManagedLayout(
        data_root=tmp_path / "state",
        config_file=tmp_path / "etc/xferry.ini",
        release_root=tmp_path / "releases",
        unit_file=tmp_path / "units/xferry.service",
    )
    private = layout.data_root / ".xferry"
    private.mkdir(parents=True)
    sentinel = private / "transfer-state.json"
    sentinel.write_bytes(b"private transfer metadata")
    selected = private
    if relation == "nested":
        selected = private / "chunks"
        selected.mkdir()
    elif relation == "parent":
        selected = layout.data_root
    elif relation == "symlink":
        selected = tmp_path / "alias"
        selected.symlink_to(private, target_is_directory=True)

    def snapshot():
        return {
            str(path): (info.st_mode, info.st_uid, info.st_gid, info.st_ino, info.st_size)
            for path in tmp_path.rglob("*")
            for info in [path.lstat()]
        }

    before = snapshot()
    transaction = FilesystemTransaction(chown=lambda *_: None)

    with pytest.raises(ValueError, match="expose private"):
        stage_managed_files_folder(layout, selected, transaction, os.getuid(), os.getgid())

    assert snapshot() == before
    assert sentinel.read_bytes() == b"private transfer metadata"
    assert not layout.unit_file.exists()


@pytest.mark.skipif(not hasattr(os, "getuid"), reason="native setup requires POSIX identities")
def test_native_first_setup_rejects_private_transfer_bind_alias(tmp_path: Path) -> None:
    from dataclasses import replace

    from tests.test_management_setup import FakeRunner, _executor, _plan

    plan = _plan(tmp_path)
    private = plan.layout.data_root / ".xferry"
    private.mkdir(parents=True)
    sentinel = private / "transfer-state.json"
    sentinel.write_bytes(b"private transfer metadata")
    plan = replace(plan, files_dir=private)
    runner = FakeRunner()
    executor = _executor(tmp_path, runner)
    executor.acme_root = plan.layout.acme_root

    result = executor.apply(plan)

    assert result.exit_code != 0
    assert sentinel.read_bytes() == b"private transfer metadata"
    assert not plan.layout.unit_file.exists()
    assert not plan.layout.config_file.exists()
    assert not plan.layout.auth_file.exists()
    assert not any(
        command[:2] in {("systemctl", "start"), ("systemctl", "restart")}
        for command in runner.commands
    )


@pytest.mark.parametrize("secret", ["auth", "cert", "key"])
def test_files_dir_cannot_expose_configured_secrets(tmp_path: Path, secret: str) -> None:
    files = tmp_path / "shared"
    auth = AuthConfig(auth_file=files / "auth") if secret == "auth" else AuthConfig()
    tls = (
        TLSConfig(cert_file=files / "cert", key_file=files / "key")
        if secret != "auth"
        else TLSConfig()
    )
    with pytest.raises(ValueError, match="files_dir.*authentication or TLS"):
        resolve_server_config(
            ServerConfig(root_dir=tmp_path / "private", files_dir=files, auth=auth, tls=tls)
        )


def test_config_file_cannot_be_placed_in_files_dir(tmp_path: Path) -> None:
    config = tmp_path / "xferry.ini"
    config.write_text(f"[server]\nconfig_version=1\nfiles_dir = {tmp_path}\n", encoding="utf-8")
    with pytest.raises(SettingsError, match="config file.*public files_dir"):
        load_settings_file(config)


def test_cli_override_cannot_make_config_file_public(tmp_path: Path) -> None:
    from xferry.cli import run_main

    config = tmp_path / "xferry.ini"
    config.write_text("[server]\nconfig_version=1\n", encoding="utf-8")
    with pytest.raises(SystemExit) as exc:
        run_main(["--config", str(config), "--files-dir", str(tmp_path)])
    assert exc.value.code == 2


def test_encrypted_folder_switch_preserves_journals_and_original_ciphertext(tmp_path: Path) -> None:
    root, files = tmp_path / "private", tmp_path / "files"
    service = _encrypted(root, files)
    service.create(_manifest())
    sidecar = service.state_dir / f"{FILE_ID}.json"
    ciphertext = service.data_dir / f"{FILE_ID}.part"
    saved = sidecar.read_bytes(), ciphertext.read_bytes()

    with pytest.raises(EncryptedStorageConflict, match="files_dir.*encrypted upload state"):
        _encrypted(root, tmp_path / "different")

    assert (sidecar.read_bytes(), ciphertext.read_bytes()) == saved
    assert _encrypted(root, files).get(FILE_ID) is not None


def test_encrypted_binding_detects_changed_mount_source_at_same_path(tmp_path: Path) -> None:
    root, files = tmp_path / "private", tmp_path / "files"
    service = _encrypted(root, files)
    service.create(_manifest())
    files.rename(tmp_path / "saved-files")
    files.mkdir()

    with pytest.raises(EncryptedStorageConflict, match="files_dir"):
        _encrypted(root, files)

    assert (service.state_dir / f"{FILE_ID}.json").exists()
    assert (tmp_path / "saved-files" / ".xferry-encrypted" / f"{FILE_ID}.part").exists()


def test_unowned_encrypted_folder_is_never_cleaned_when_selected(tmp_path: Path) -> None:
    files = tmp_path / "foreign"
    data = files / ".xferry-encrypted"
    data.mkdir(parents=True)
    ciphertext = data / f"{FILE_ID}.part"
    ciphertext.write_bytes(b"belongs to another installation")

    with pytest.raises(EncryptedStorageConflict, match="files_dir"):
        _encrypted(tmp_path / "private", files)

    assert ciphertext.read_bytes() == b"belongs to another installation"


def test_explicit_legacy_named_folder_does_not_adopt_foreign_ciphertext(tmp_path: Path) -> None:
    data = tmp_path / "uploads" / ".xferry-encrypted"
    data.mkdir(parents=True)
    ciphertext = data / f"{FILE_ID}.part"
    ciphertext.write_bytes(b"foreign ciphertext")

    with pytest.raises(EncryptedStorageConflict, match="files_dir"):
        make_server(
            root_dir=tmp_path, files_dir=tmp_path / "uploads", encrypted_uploads=True, quiet=True
        )

    assert ciphertext.read_bytes() == b"foreign ciphertext"


def test_empty_encrypted_storage_can_select_another_files_directory(tmp_path: Path) -> None:
    root = tmp_path / "private"
    _encrypted(root, tmp_path / "first")
    service = _encrypted(root, tmp_path / "second")
    assert service.list_files() == ()
    binding = json.loads((root / ".xferry" / "encrypted-storage-root").read_text("utf-8"))
    assert binding["files_dir"] == str(tmp_path / "second")


def test_unbound_encrypted_storage_fails_without_losing_data(tmp_path: Path) -> None:
    files = tmp_path / "uploads"
    service = _encrypted(tmp_path, files)
    service.create(_manifest())
    (tmp_path / ".xferry" / "encrypted-storage-root").unlink()

    with pytest.raises(EncryptedStorageConflict, match="files_dir"):
        _encrypted(tmp_path, files)
    assert (service.data_dir / f"{FILE_ID}.part").exists()
    assert (service.state_dir / f"{FILE_ID}.json").exists()


def test_corrupt_encrypted_binding_fails_without_reconciliation(tmp_path: Path) -> None:
    service = _encrypted(tmp_path, tmp_path / "uploads")
    service.create(_manifest())
    (tmp_path / ".xferry" / "encrypted-storage-root").write_bytes(b"broken")
    with pytest.raises(EncryptedStorageConflict, match="invalid encrypted storage folder binding"):
        _encrypted(tmp_path, tmp_path / "uploads")
    assert (service.data_dir / f"{FILE_ID}.part").exists()
    assert (service.state_dir / f"{FILE_ID}.json").exists()


def test_operator_configuration_uses_explicit_keyword_fields(tmp_path: Path) -> None:
    from xferry.server_config import ServerConfig
    from xferry.settings import ServerSettings

    config = ServerConfig("127.0.0.1", 8080, tmp_path, True, files_dir=tmp_path / "files")
    settings = ServerSettings(state_dir=str(tmp_path), log_level="warning")
    assert config.encrypted_uploads is True
    assert settings.log_level == "warning"
    assert settings.files_dir is None
