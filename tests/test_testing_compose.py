"""Signed preview Docker consumers and recovery of compatible stable bundles."""

from __future__ import annotations

import hashlib
import json
from subprocess import CompletedProcess

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from tests.test_backend_lifecycle import IMAGE, Runner, docker
from xferry import build_info, config
from xferry.management import release_trust
from xferry.management.channels import MAX_TESTING_IMAGES_BYTES, manifest_url
from xferry.management.compose_backend import ComposeBackend
from xferry.management.configuration import edit_ini
from xferry.management.deployment import resource_unchanged
from xferry.management.release_contract import ReleaseManifest
from xferry.management.release_trust import (
    TESTING_MANIFEST_SIGNATURE_TYPE,
    ReleaseKeyRing,
    TrustedReleaseKey,
    create_detached_signature,
)

PRIVATE = Ed25519PrivateKey.generate()
KEY_ID = "compose-testing-key"
RING = ReleaseKeyRing((TrustedReleaseKey(KEY_ID, PRIVATE.public_key().public_bytes_raw()),))


def _identity(number):
    return f"0.5.1.dev{number}", f"{number:040x}", f"12345.{number}"


def _image(number):
    return "ghcr.io/kgmnotes/xferry-testing@sha256:" + f"{number:064x}"


def _assets(number=1, *, catalog_changes=None, manifest_source=None):
    version, source, build = _identity(number)
    document = {
        "schema": 1,
        "channel": "testing",
        "version": version,
        "source_commit": source,
        "build_id": build,
        "image": _image(number),
    }
    document.update(catalog_changes or {})
    catalog = (json.dumps(document, indent=2) + "\n").encode()
    manifest = ReleaseManifest.create_v3(
        version=version,
        platform="linux-x86_64",
        executable_size=7,
        executable_sha256=hashlib.sha256(b"runtime").hexdigest(),
        source_commit=manifest_source or source,
        workflow_run="12345",
        build_id=build,
        artifact_digests={
            f"xferry-{version}-linux-x86_64": hashlib.sha256(b"runtime").hexdigest(),
            "testing-images.json": hashlib.sha256(catalog).hexdigest(),
        },
        signing_key_ids=(KEY_ID,),
    ).to_bytes()
    url = manifest_url(version, "linux-x86_64", "testing")
    return {
        url: manifest,
        url + ".sig": create_detached_signature(
            manifest,
            payload_type=TESTING_MANIFEST_SIGNATURE_TYPE,
            key_id=KEY_ID,
            signer=PRIVATE,
        ),
        url.rsplit("/", 1)[0] + "/testing-images.json": catalog,
    }


class Reader:
    def __init__(self, assets):
        self.assets = assets
        self.requests = []

    def read(self, url, max_bytes):
        self.requests.append((url, max_bytes))
        if url not in self.assets:
            raise OSError("missing preview asset")
        result = self.assets[url]
        if len(result) > max_bytes:
            raise OSError("asset exceeds its size limit")
        return result


class TestingRunner(Runner):
    __test__ = False

    def __init__(self):
        super().__init__()
        self.labels = {}

    def run(self, argv, **kwargs):
        command = tuple(str(value) for value in argv)
        if command[:2] == ("docker", "pull") and "@sha256:" in command[-1]:
            self.next_image = command[-1]
        if command[:3] == ("docker", "image", "inspect") and ".Config.Labels" in command[-2]:
            self.commands.append(command)
            return CompletedProcess(command, 0, json.dumps(self.labels), "")
        return super().run(command, **kwargs)


def _stamp(monkeypatch, runner, number):
    version, source, build = _identity(number)
    monkeypatch.setattr(config, "__version__", version)
    monkeypatch.setattr(build_info, "BUILD_CHANNEL", "testing")
    monkeypatch.setattr(build_info, "SOURCE_COMMIT", source)
    monkeypatch.setattr(build_info, "BUILD_ID", build)
    runner.labels = {
        "org.opencontainers.image.version": version,
        "org.opencontainers.image.revision": source,
        "io.xferry.build-id": build,
        "io.xferry.channel": "testing",
    }
    return version


def _deployment(tmp_path, monkeypatch, *, assets=None):
    monkeypatch.setattr(release_trust, "DEFAULT_TESTING_KEY_RING", RING)
    app, instance, runner = docker(tmp_path, TestingRunner())
    backend = app._compose_backend
    backend.reader = Reader(_assets() if assets is None else assets)
    return backend, instance, runner


def test_testing_docker_dry_run_verifies_catalog_without_pull_or_mutation(tmp_path, monkeypatch):
    backend, instance, runner = _deployment(tmp_path, monkeypatch)
    version = _stamp(monkeypatch, runner, 1)
    before = {
        path: path.read_bytes() for path in instance.config.parent.rglob("*") if path.is_file()
    }
    runner.commands.clear()

    result = backend.operate("update", instance, version=version, channel="testing", dry_run=True)

    assert result.exit_code == 0, result
    assert result.details["image"] == _image(1)
    assert {path: path.read_bytes() for path in before} == before
    assert not (instance.config.parent / ".xferry-last-stable.json").exists()
    assert not any(command[:2] == ("docker", "pull") for command in runner.commands)
    assert backend.reader.requests[-1][1] == MAX_TESTING_IMAGES_BYTES
    assert all("/testing-v" in url for url, _limit in backend.reader.requests)


@pytest.mark.parametrize(
    "failure", ["missing", "signature", "source", "image", "channel", "oversize"]
)
def test_testing_docker_rejects_untrusted_assets_without_bundle_changes(
    tmp_path, monkeypatch, failure
):
    assets = _assets(
        catalog_changes=(
            {"image": "ghcr.io/kgmnotes/xferry@sha256:" + "a" * 64}
            if failure == "image"
            else {"channel": "stable"}
            if failure == "channel"
            else None
        ),
        manifest_source="f" * 40 if failure == "source" else None,
    )
    url = manifest_url("0.5.1.dev1", "linux-x86_64", "testing")
    if failure == "missing":
        assets.pop(url.rsplit("/", 1)[0] + "/testing-images.json")
    elif failure == "signature":
        document = json.loads(assets[url + ".sig"])
        document["signature"] = "A" * len(document["signature"])
        assets[url + ".sig"] = json.dumps(document).encode()
    elif failure == "oversize":
        assets[url.rsplit("/", 1)[0] + "/testing-images.json"] = b" " * (
            MAX_TESTING_IMAGES_BYTES + 1
        )
    backend, instance, runner = _deployment(tmp_path, monkeypatch, assets=assets)
    version = _stamp(monkeypatch, runner, 1)
    before = instance.manifest.read_bytes()
    runner.commands.clear()

    with pytest.raises((OSError, ValueError)):
        backend.operate("update", instance, version=version, channel="testing")

    assert instance.manifest.read_bytes() == before
    assert not any(command[:2] == ("docker", "pull") for command in runner.commands)


def test_testing_docker_rejects_pulled_image_label_mismatch(tmp_path, monkeypatch):
    backend, instance, runner = _deployment(tmp_path, monkeypatch)
    version = _stamp(monkeypatch, runner, 1)
    runner.labels["io.xferry.build-id"] = "12345.99"
    before = instance.manifest.read_bytes()

    with pytest.raises(ValueError, match="same build"):
        backend.operate("update", instance, version=version, channel="testing")

    assert instance.manifest.read_bytes() == before
    assert not (instance.config.parent / ".xferry-last-stable.json").exists()


def test_testing_docker_requires_matching_cli_before_fetching_or_pulling(tmp_path, monkeypatch):
    backend, instance, runner = _deployment(tmp_path, monkeypatch)
    _stamp(monkeypatch, runner, 2)
    runner.commands.clear()

    with pytest.raises(ValueError, match="exact testing CLI"):
        backend.operate("update", instance, version="0.5.1.dev1", channel="testing")

    assert not any(command[:2] == ("docker", "pull") for command in runner.commands)
    assert not backend.reader.requests


def test_stable_docker_snapshot_survives_history_pruning_and_restores_configuration(
    tmp_path, monkeypatch
):
    assets = {}
    for number in range(1, 8):
        assets.update(_assets(number))
    backend, instance, runner = _deployment(tmp_path, monkeypatch, assets=assets)
    root = instance.config.parent
    stable = {
        name: (root / name).read_bytes() for name in ("xferry.ini", "runtime.ini", "compose.yaml")
    }
    version = _stamp(monkeypatch, runner, 1)
    assert backend.operate("update", instance, version=version, channel="testing").exit_code == 0
    snapshot = (root / ".xferry-last-stable.json").read_bytes()
    previous = instance.config.read_text()
    candidate = edit_ini(previous, {"port": 9090})
    assert backend.configure(instance, candidate, expected_text=previous, apply=True).exit_code == 0
    assert backend.credentials(instance, password="preview-password-123").exit_code == 0
    credentials = (root / "secrets/xferry_auth").read_bytes()
    for number in range(2, 8):
        version = _stamp(monkeypatch, runner, number)
        assert backend.operate("update", instance, version=version).exit_code == 0
        assert (root / ".xferry-last-stable.json").read_bytes() == snapshot
    assert len(json.loads((root / ".xferry-history.json").read_bytes())) == 5
    assert not any(
        item["image"] == IMAGE for item in json.loads((root / ".xferry-history.json").read_bytes())
    )

    result = backend.operate("rollback", instance, channel="stable")

    assert result.exit_code == 0, result
    assert instance.spec.artifact["image"] == IMAGE
    assert {name: (root / name).read_bytes() for name in stable} == stable
    assert (root / "secrets/xferry_auth").read_bytes() == credentials
    assert all(resource_unchanged(item) for item in instance.spec.ownership.resources)


@pytest.mark.parametrize("action", ["update", "rollback"])
def test_failed_testing_docker_switch_restores_bundle_and_runtime(tmp_path, monkeypatch, action):
    backend, instance, runner = _deployment(tmp_path, monkeypatch)
    version = _stamp(monkeypatch, runner, 1)
    if action == "rollback":
        assert (
            backend.operate("update", instance, version=version, channel="testing").exit_code == 0
        )
        previous = instance.config.read_text()
        candidate = edit_ini(previous, {"port": 9090})
        assert (
            backend.configure(instance, candidate, expected_text=previous, apply=True).exit_code
            == 0
        )
    root = instance.config.parent
    before = {path: path.read_bytes() for path in root.rglob("*") if path.is_file()}
    runner.fail_up = 1

    result = backend.operate(
        action,
        instance,
        version=version if action == "update" else None,
        channel="testing" if action == "update" else "stable",
    )

    assert result.exit_code == 1
    assert {path: path.read_bytes() for path in before} == before
    assert runner.running
    if action == "update":
        assert not (root / ".xferry-last-stable.json").exists()


@pytest.mark.parametrize("tamper", ["content", "mode", "symlink"])
def test_testing_docker_refuses_modified_stable_snapshot(tmp_path, monkeypatch, tamper):
    backend, instance, runner = _deployment(tmp_path, monkeypatch)
    version = _stamp(monkeypatch, runner, 1)
    assert backend.operate("update", instance, version=version, channel="testing").exit_code == 0
    snapshot = instance.config.parent / ".xferry-last-stable.json"
    if tamper == "content":
        snapshot.write_text(snapshot.read_text() + "\n")
    elif tamper == "mode":
        snapshot.chmod(0o666)
    else:
        snapshot.unlink()
        snapshot.symlink_to(instance.config)
    before = instance.manifest.read_bytes()

    with pytest.raises(ValueError):
        backend.operate("rollback", instance, channel="stable")

    assert instance.manifest.read_bytes() == before
    assert instance.spec.artifact["channel"] == "testing"


def test_testing_setup_dry_run_verifies_before_creating_files(tmp_path, monkeypatch):
    monkeypatch.setattr(release_trust, "DEFAULT_TESTING_KEY_RING", RING)
    runner = TestingRunner()
    version = _stamp(monkeypatch, runner, 1)
    backend = ComposeBackend(runner, reader=Reader(_assets()))
    output = tmp_path / "new-bundle"

    result = backend.setup(
        output,
        files_dir=tmp_path / "files",
        version=version,
        access="private",
        channel="testing",
        dry_run=True,
    )

    assert result.exit_code == 0
    assert result.details["channel"] == "testing"
    assert not output.exists()
    assert not runner.commands


def test_testing_docker_rollback_selects_the_installed_cli_version(tmp_path, monkeypatch):
    backend, instance, runner = _deployment(
        tmp_path, monkeypatch, assets={**_assets(1), **_assets(2), **_assets(3)}
    )
    for number in (1, 2, 3):
        version = _stamp(monkeypatch, runner, number)
        assert (
            backend.operate("update", instance, version=version, channel="testing").exit_code == 0
        )
    _stamp(monkeypatch, runner, 1)

    result = backend.operate("rollback", instance)

    assert result.exit_code == 0
    assert instance.spec.artifact["version"] == "0.5.1.dev1"
    assert instance.spec.artifact["image"] == _image(1)


def test_stopped_testing_docker_updates_and_stable_rollback_keep_the_server_stopped(
    tmp_path, monkeypatch
):
    backend, instance, runner = _deployment(tmp_path, monkeypatch)
    backend.operate("stop", instance)
    version = _stamp(monkeypatch, runner, 1)

    assert backend.operate("update", instance, version=version, channel="testing").exit_code == 0
    assert not runner.running
    assert backend.operate("rollback", instance, channel="stable").exit_code == 0
    assert not runner.running
