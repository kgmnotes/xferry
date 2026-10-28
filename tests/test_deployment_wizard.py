"""Host deployment tests with injected Docker/network boundaries."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import struct
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from xferry.management import bootstrap, docker_deploy, docker_init
from xferry.management.managed_files import managed_files_path, stage_managed_files_folder
from xferry.management.model import HostFacts, ManagedLayout, SetupMode, SetupOptions
from xferry.management.planning import build_setup_plan, render_managed_config
from xferry.management.release_contract import ReleaseManifest, artifact_name
from xferry.management.release_trust import (
    INSTALLER_SIGNATURE_TYPE,
    MANIFEST_SIGNATURE_TYPE,
    ReleaseKeyRing,
    TrustedReleaseKey,
    create_detached_signature,
)
from xferry.management.system import FilesystemTransaction
from xferry.settings import load_settings_text


@pytest.fixture(autouse=True)
def isolated_instance_registry(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "user-data"))


class DockerRunner:
    def __init__(self, fail_up: int = 0, *, running: bool = True) -> None:
        self.commands: list[tuple[str, ...]] = []
        self.fail_up = fail_up
        self.running = running

    def run(self, argv: tuple[str, ...]) -> SimpleNamespace:
        self.commands.append(tuple(argv))
        if argv[:3] == ("docker", "ps", "-q"):
            return SimpleNamespace(
                returncode=0, stdout="container-id" if self.running else "", stderr=""
            )
        if "up" in argv and self.fail_up:
            self.fail_up -= 1
            return SimpleNamespace(returncode=1, stdout="", stderr="test failure")
        return SimpleNamespace(returncode=0, stdout="", stderr="")


def test_docker_first_success_preserves_host_folder_and_returns_credentials_once(
    tmp_path: Path,
) -> None:
    files = tmp_path / "shared files"
    files.mkdir()
    (files / "existing.txt").write_text("keep")
    original_mode = files.stat().st_mode
    output = tmp_path / "deployment"
    runner = DockerRunner()
    first = docker_deploy.deploy_docker(output, files_dir=files, private=True, runner=runner)
    assert first.exit_code == 0, first.message
    assert first.username == "admin" and first.password and len(first.password) == 12
    secret = (output / "secrets/xferry_auth").read_bytes()
    assert stat.S_IMODE((output / "xferry.ini").stat().st_mode) == 0o644
    assert stat.S_IMODE((output / "secrets/xferry_auth").stat().st_mode) == 0o600
    compose = json.loads((output / "compose.yaml").read_text())
    mounts = compose["services"]["xferry"]["volumes"]
    assert {
        "type": "bind",
        "source": str(files),
        "target": "/data/files",
        "bind": {"create_host_path": False},
    } in mounts
    assert (files / "existing.txt").read_text() == "keep"
    assert files.stat().st_mode == original_mode
    assert "xferry-secrets:/run/secrets:ro" in mounts
    assert any("secrets-init" in command and "run" in command for command in runner.commands)
    assert any("--wait" in command for command in runner.commands)
    second = docker_deploy.deploy_docker(output, runner=runner)
    assert second.exit_code == 0 and second.password is None
    assert second.project == first.project
    assert (output / "secrets/xferry_auth").read_bytes() == secret


def test_docker_failed_update_restores_ini_and_password(tmp_path: Path) -> None:
    output = tmp_path / "deployment"
    files = tmp_path / "files"
    assert (
        docker_deploy.deploy_docker(
            output, files_dir=files, private=True, runner=DockerRunner()
        ).exit_code
        == 0
    )
    original = (output / "xferry.ini").read_bytes()
    auth = (output / "secrets/xferry_auth").read_bytes()
    failed = docker_deploy.deploy_docker(
        output, settings_changes={"max_size_mb": 42}, runner=DockerRunner(fail_up=1)
    )
    assert failed.exit_code == 1
    assert "restored" in failed.message
    assert (output / "xferry.ini").read_bytes() == original
    assert (output / "secrets/xferry_auth").read_bytes() == auth
    assert stat.S_IMODE((output / "xferry.ini").stat().st_mode) == 0o644


def test_docker_repairs_legacy_config_permissions_without_exposing_inline_auth(
    tmp_path: Path,
) -> None:
    output = tmp_path / "deployment"
    assert (
        docker_deploy.deploy_docker(
            output, files_dir=tmp_path / "files", private=True, runner=DockerRunner()
        ).exit_code
        == 0
    )
    config = output / "xferry.ini"
    config.chmod(0o600)
    assert docker_deploy.deploy_docker(output, runner=DockerRunner()).exit_code == 0
    assert stat.S_IMODE(config.stat().st_mode) == 0o644
    config.write_text(
        config.read_text().replace(
            "auth_file = /run/secrets/xferry_auth", "auth = operator:plaintext-credential"
        )
    )
    config.chmod(0o600)
    original = config.read_bytes()
    runner = DockerRunner()
    result = docker_deploy.deploy_docker(output, runner=runner)
    assert result.exit_code != 0 and "plaintext-credential" not in result.message
    assert config.read_bytes() == original
    assert stat.S_IMODE(config.stat().st_mode) == 0o600
    assert not any("up" in command or "run" in command for command in runner.commands)


def test_docker_failed_first_start_still_returns_same_credentials_after_retry(
    tmp_path: Path,
) -> None:
    output = tmp_path / "deployment"
    first = docker_deploy.deploy_docker(
        output, files_dir=tmp_path / "files", private=True, runner=DockerRunner(fail_up=1)
    )
    assert first.exit_code == 1 and first.password is None
    secret = (output / "secrets/xferry_auth").read_text().strip().split(":", 1)[1]
    retry = docker_deploy.deploy_docker(output, runner=DockerRunner())
    assert retry.exit_code == 0 and retry.password == secret


def test_docker_rejects_foreign_directory_and_encrypted_folder_switch(tmp_path: Path) -> None:
    foreign = tmp_path / "foreign"
    foreign.mkdir()
    (foreign / "compose.yaml").write_text("foreign")
    assert docker_deploy.deploy_docker(foreign, private=True, runner=DockerRunner()).exit_code != 0
    output, files = tmp_path / "deployment", tmp_path / "files"
    assert (
        docker_deploy.deploy_docker(
            output, files_dir=files, private=True, runner=DockerRunner()
        ).exit_code
        == 0
    )
    (files / ".xferry-encrypted").mkdir()
    result = docker_deploy.deploy_docker(
        output, files_dir=tmp_path / "another", runner=DockerRunner()
    )
    assert result.exit_code != 0 and "migration" in result.message


def test_docker_dry_run_does_not_create_files(tmp_path: Path) -> None:
    output, files = tmp_path / "deployment", tmp_path / "files"
    result = docker_deploy.deploy_docker(
        output, files_dir=files, private=True, dry_run=True, runner=DockerRunner()
    )
    assert result.exit_code == 0
    assert not output.exists() and not files.exists()


def test_docker_network_change_preserves_custom_settings_and_comments(tmp_path: Path) -> None:
    output = tmp_path / "deployment"
    first = docker_deploy.deploy_docker(
        output,
        files_dir=tmp_path / "files",
        private=True,
        settings_changes={"max_size_mb": 42, "encrypted_uploads": True},
        runner=DockerRunner(),
    )
    assert first.exit_code == 0
    config = output / "xferry.ini"
    config.write_text("# operator comment\n" + config.read_text())
    result = docker_deploy.deploy_docker(output, domain="files.example.com", runner=DockerRunner())
    assert result.exit_code == 0, result.message
    assert config.read_text().startswith("# operator comment\n")
    settings = load_settings_text(config.read_text())
    assert settings.max_size_mb == 42 and settings.encrypted_uploads
    assert settings.domain == "files.example.com"


def test_docker_detects_bundle_change_before_commit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output = tmp_path / "deployment"
    assert (
        docker_deploy.deploy_docker(
            output, files_dir=tmp_path / "files", private=True, runner=DockerRunner()
        ).exit_code
        == 0
    )
    original_lock = docker_deploy._bundle_lock

    @contextmanager
    def changed_lock(path: Path):
        with original_lock(path):
            config = path / "xferry.ini"
            config.write_text("# external edit\n" + config.read_text())
            yield

    monkeypatch.setattr(docker_deploy, "_bundle_lock", changed_lock)
    result = docker_deploy.deploy_docker(
        output, settings_changes={"max_size_mb": 42}, runner=DockerRunner()
    )
    assert result.exit_code == 1 and "changed" in result.message
    assert (output / "xferry.ini").read_text().startswith("# external edit\n")


def test_docker_failed_bundle_write_restores_before_activation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output = tmp_path / "deployment"
    assert (
        docker_deploy.deploy_docker(
            output, files_dir=tmp_path / "files", private=True, runner=DockerRunner()
        ).exit_code
        == 0
    )
    original_config = (output / "xferry.ini").read_bytes()
    original_compose = (output / "compose.yaml").read_bytes()
    original_write = docker_deploy._atomic_write
    failed = False

    def fail_once(path: Path, data: bytes, mode: int = 0o600) -> None:
        nonlocal failed
        if path.name == "xferry.ini" and not failed:
            failed = True
            raise OSError("test write failure")
        original_write(path, data, mode)

    monkeypatch.setattr(docker_deploy, "_atomic_write", fail_once)
    runner = DockerRunner()
    result = docker_deploy.deploy_docker(output, domain="files.example.com", runner=runner)
    assert result.exit_code == 1 and "restored" in result.message
    assert (output / "xferry.ini").read_bytes() == original_config
    assert (output / "compose.yaml").read_bytes() == original_compose
    assert not any("up" in command for command in runner.commands)


def test_new_managed_plan_has_stable_exact_files_folder(tmp_path: Path) -> None:
    layout = ManagedLayout(data_root=tmp_path / "state")
    facts = HostFacts("ubuntu", "24.04", "x86_64", True, 2048, 2, 10000)
    plan = build_setup_plan(SetupOptions(mode=SetupMode.PRIVATE, layout=layout), facts)
    assert plan.files_dir == tmp_path / "state/files"
    settings = load_settings_text(render_managed_config(plan))
    assert settings.files_dir == str(tmp_path / "state/files")
    custom = replace(plan, files_dir=tmp_path / "shared")
    assert load_settings_text(render_managed_config(custom)).files_dir == settings.files_dir


def test_managed_host_mapping_preserves_existing_ownership_and_rolls_back(tmp_path: Path) -> None:
    files = tmp_path / "shared files"
    files.mkdir(mode=0o700)
    before = files.stat()
    (files / "keep.txt").write_text("keep")
    layout = ManagedLayout(
        data_root=tmp_path / "state",
        config_file=tmp_path / "etc/xferry.ini",
        unit_file=tmp_path / "unit/xferry.service",
    )
    transaction = FilesystemTransaction(chown=lambda path, uid, gid: None)
    stage_managed_files_folder(layout, files, transaction, os.getuid(), os.getgid())
    assert managed_files_path(layout) == files
    unit = layout.unit_file.read_text()
    assert "BindPaths=" in unit and "shared\\x20files" in unit
    assert "ProtectHome=true" in unit
    assert files.stat().st_uid == before.st_uid and files.stat().st_mode == before.st_mode
    transaction.rollback()
    assert not layout.unit_file.exists()
    assert (files / "keep.txt").read_text() == "keep"


@pytest.mark.parametrize("relative", ["state/.xferry/acme", "state/notes/public", "etc/share"])
def test_managed_mapping_rejects_sources_inside_private_state(
    tmp_path: Path, relative: str
) -> None:
    layout = ManagedLayout(data_root=tmp_path / "state", config_file=tmp_path / "etc/xferry.ini")
    transaction = FilesystemTransaction(chown=lambda path, uid, gid: None)
    with pytest.raises(ValueError, match="private"):
        stage_managed_files_folder(
            layout, tmp_path / relative, transaction, os.getuid(), os.getgid()
        )
    assert not (tmp_path / relative).exists()


def test_managed_mapping_rejects_actual_host_tls_file(tmp_path: Path) -> None:
    layout = ManagedLayout(data_root=tmp_path / "state", config_file=tmp_path / "etc/xferry.ini")
    source = tmp_path / "shared"
    transaction = FilesystemTransaction(chown=lambda path, uid, gid: None)
    with pytest.raises(ValueError, match="TLS"):
        stage_managed_files_folder(
            layout,
            source,
            transaction,
            os.getuid(),
            os.getgid(),
            private_files=(source / "private.key",),
        )
    assert not source.exists()


def test_new_public_folder_and_encrypted_state_survive_failed_activation(tmp_path: Path) -> None:
    layout = ManagedLayout(
        data_root=tmp_path / "state",
        config_file=tmp_path / "etc/xferry.ini",
        unit_file=tmp_path / "unit/xferry.service",
    )
    transaction = FilesystemTransaction(chown=lambda path, uid, gid: None)
    transaction.ensure_directory(layout.data_root, mode=0o750, uid=os.getuid(), gid=os.getgid())
    transaction.ensure_directory(layout.acme_root, mode=0o750, uid=os.getuid(), gid=os.getgid())
    public = layout.data_root / "files"
    stage_managed_files_folder(layout, public, transaction, os.getuid(), os.getgid())
    (public / "uploaded.txt").write_text("concurrent upload")
    sidecars = layout.data_root / ".xferry/encrypted-uploads"
    sidecars.mkdir()
    (sidecars / "state.json").write_text("recovery metadata")
    transaction.rollback()
    assert (public / "uploaded.txt").read_text() == "concurrent upload"
    assert (sidecars / "state.json").read_text() == "recovery metadata"
    assert not layout.unit_file.exists()


def test_named_acl_grant_preserves_previously_masked_access(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    entries = [
        (1, 7, 0xFFFFFFFF),
        (2, 7, 99),
        (4, 7, 0xFFFFFFFF),
        (8, 7, 33),
        (16, 4, 0xFFFFFFFF),
        (32, 0, 0xFFFFFFFF),
    ]
    original = struct.pack("<I", 2) + b"".join(struct.pack("<HHI", *entry) for entry in entries)
    changed: list[bytes] = []
    monkeypatch.setattr(os, "getxattr", lambda *args: original)
    monkeypatch.setattr(os, "setxattr", lambda path, name, payload: changed.append(payload))
    docker_init._grant_directory_acl(tmp_path, 10001, 88)
    for raw in changed:
        values = [struct.unpack_from("<HHI", raw, i) for i in range(4, len(raw), 8)]
        assert (2, 4, 99) in values
        assert (4, 4, 0xFFFFFFFF) in values
        assert (8, 4, 33) in values
        assert (2, 7, 10001) in values
        assert (16, 7, 0xFFFFFFFF) in values


def test_stopped_docker_deployment_is_not_started_by_reconfigure(tmp_path: Path) -> None:
    output = tmp_path / "deployment"
    assert (
        docker_deploy.deploy_docker(
            output, files_dir=tmp_path / "files", private=True, runner=DockerRunner()
        ).exit_code
        == 0
    )
    runner = DockerRunner(running=False)
    result = docker_deploy.deploy_docker(
        output, settings_changes={"max_size_mb": 42}, runner=runner
    )
    assert result.exit_code == 0 and "stopped" in result.message
    assert not any("up" in command for command in runner.commands)
    secret = (output / "secrets/xferry_auth").read_bytes()
    denied = docker_deploy.deploy_docker(output, reset_credentials=True, runner=runner)
    assert denied.exit_code != 0
    assert (output / "secrets/xferry_auth").read_bytes() == secret


def test_docker_password_rotation_is_explicit_and_health_gated(tmp_path: Path) -> None:
    output = tmp_path / "deployment"
    first = docker_deploy.deploy_docker(
        output, files_dir=tmp_path / "files", private=True, runner=DockerRunner()
    )
    rotated = docker_deploy.deploy_docker(output, reset_credentials=True, runner=DockerRunner())
    assert rotated.exit_code == 0 and rotated.password and rotated.password != first.password
    secret = (output / "secrets/xferry_auth").read_bytes()
    failed = docker_deploy.deploy_docker(
        output, reset_credentials=True, runner=DockerRunner(fail_up=1)
    )
    assert failed.exit_code == 1 and failed.password is None
    assert (output / "secrets/xferry_auth").read_bytes() == secret


@pytest.mark.parametrize("corrupt_digest", [False, True])
def test_installer_executes_only_after_authenticated_release_match(
    monkeypatch: pytest.MonkeyPatch, corrupt_digest: bool
) -> None:
    script = b"#!/bin/sh\nexit 0\n"
    platform = "linux-x86_64"
    monkeypatch.setattr(bootstrap.os, "geteuid", lambda: 0)
    monkeypatch.setattr(bootstrap, "current_platform_id", lambda: platform)
    monkeypatch.setattr(
        "xferry.management.platform.detect_host_facts",
        lambda: HostFacts("ubuntu", "24.04", "x86_64", True, 2048, 2, 10000),
    )
    manifest = SimpleNamespace(
        version="0.2.1",
        platform=platform,
        artifact_digests=(
            (
                f"install-{platform}.sh",
                "0" * 64 if corrupt_digest else hashlib.sha256(script).hexdigest(),
            ),
        ),
    )
    events: list[str] = []
    monkeypatch.setattr(
        bootstrap, "verify_signed_manifest", lambda body, signature, *, key_ring: manifest
    )

    def checked_signature(payload, signature, *, payload_type, key_ring):
        assert key_ring is bootstrap.DEFAULT_RELEASE_KEY_RING
        assert payload_type == bootstrap.INSTALLER_SIGNATURE_TYPE
        events.append("verified")

    monkeypatch.setattr(bootstrap, "verify_detached_signature", checked_signature)

    class Download:
        def read(self, url: str, maximum: int) -> bytes:
            return script if url.endswith(".sh") else b"metadata"

    class Runner:
        def run(self, argv: tuple[str, ...]) -> SimpleNamespace:
            assert events == ["verified"]
            assert Path(argv[1]).read_bytes() == script
            events.append("executed")
            return SimpleNamespace(returncode=0)

    result = bootstrap.install_release("0.2.1", downloader=Download(), runner=Runner())
    assert (result.exit_code == 0) is not corrupt_digest
    assert ("executed" in events) is not corrupt_digest


@pytest.mark.parametrize("tampered", [False, True])
def test_bootstrap_verifies_real_ed25519_manifest_and_installer(
    monkeypatch: pytest.MonkeyPatch,
    tampered: bool,
) -> None:
    version, platform, key_id = "0.2.1", "linux-x86_64", "bootstrap-test-key"
    private_key = Ed25519PrivateKey.generate()
    ring = ReleaseKeyRing((TrustedReleaseKey(key_id, private_key.public_key().public_bytes_raw()),))
    installer = b"#!/bin/sh\nexit 0\n"
    executable = b"test executable"
    installer_name = f"install-{platform}.sh"
    manifest = ReleaseManifest.create_v2(
        version=version,
        platform=platform,
        executable_size=len(executable),
        executable_sha256=hashlib.sha256(executable).hexdigest(),
        source_commit="a" * 40,
        workflow_run="12345",
        signing_key_ids=(key_id,),
        artifact_digests={
            artifact_name(version, platform): hashlib.sha256(executable).hexdigest(),
            installer_name: hashlib.sha256(installer).hexdigest(),
        },
    ).to_bytes()
    assets = {
        f"xferry-release-{platform}.json": manifest,
        f"xferry-release-{platform}.json.sig": create_detached_signature(
            manifest,
            payload_type=MANIFEST_SIGNATURE_TYPE,
            key_id=key_id,
            signer=private_key,
        ),
        installer_name: installer + (b"# tampered\n" if tampered else b""),
        f"{installer_name}.sig": create_detached_signature(
            installer,
            payload_type=INSTALLER_SIGNATURE_TYPE,
            key_id=key_id,
            signer=private_key,
        ),
    }
    monkeypatch.setattr(bootstrap.os, "geteuid", lambda: 0)
    monkeypatch.setattr(bootstrap, "current_platform_id", lambda: platform)
    monkeypatch.setattr(
        "xferry.management.platform.detect_host_facts",
        lambda: HostFacts("ubuntu", "24.04", "x86_64", True, 2048, 2, 10000),
    )
    executed = []

    class Download:
        def read(self, url: str, max_bytes: int) -> bytes:
            return assets[url.rsplit("/", 1)[1]]

    class Runner:
        def run(self, argv: tuple[str, ...]) -> SimpleNamespace:
            executed.append(Path(argv[1]).read_bytes())
            return SimpleNamespace(returncode=0)

    result = bootstrap.install_release(
        version, downloader=Download(), runner=Runner(), key_ring=ring
    )
    assert (result.exit_code == 0) is not tampered
    assert executed == ([] if tampered else [installer])
