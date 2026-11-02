"""Host deployment tests with injected Docker/network boundaries."""

from __future__ import annotations

import hashlib
import os
import struct
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from xferry.management import bootstrap, ownership
from xferry.management.managed_files import stage_managed_files_folder
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
    assert not (layout.config_file.parent / "deployment.json").exists()
    unit = layout.unit_file.read_text()
    assert "BindPaths=" in unit and "shared\\x20files" in unit
    assert "ProtectHome=true" in unit
    assert files.stat().st_uid == before.st_uid and files.stat().st_mode == before.st_mode
    transaction.rollback()
    assert not layout.unit_file.exists()
    assert (files / "keep.txt").read_text() == "keep"


@pytest.mark.parametrize("relative", ["state/acme", "state/notes/public", "etc/share"])
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
    sidecars.mkdir(parents=True)
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
    changed.append(ownership._grant(original, tmp_path.stat().st_mode, 10001))
    for raw in changed:
        values = [struct.unpack_from("<HHI", raw, i) for i in range(4, len(raw), 8)]
        assert (2, 4, 99) in values
        assert (4, 4, 0xFFFFFFFF) in values
        assert (8, 4, 33) in values
        assert (2, 7, 10001) in values
        assert (16, 7, 0xFFFFFFFF) in values


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
        version="0.5.0",
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

    result = bootstrap.install_release("0.5.0", downloader=Download(), runner=Runner())
    assert (result.exit_code == 0) is not corrupt_digest
    assert ("executed" in events) is not corrupt_digest


@pytest.mark.parametrize("tampered", [False, True])
def test_bootstrap_verifies_real_ed25519_manifest_and_installer(
    monkeypatch: pytest.MonkeyPatch,
    tampered: bool,
) -> None:
    version, platform, key_id = "0.5.0", "linux-x86_64", "bootstrap-test-key"
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
