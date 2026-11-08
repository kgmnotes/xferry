"""Shared deployment contracts, observed state and transactional backend behavior."""

from __future__ import annotations

import hashlib
import json
import os
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path

import pytest

from xferry.management.application import ManagementApplication
from xferry.management.compiler import compile_profile, public_url
from xferry.management.compose_backend import ComposeBackend
from xferry.management.configuration import edit_ini
from xferry.management.deployment import (
    DeploymentSpec,
    OperationResult,
    OwnershipReceipt,
    load_manifest,
    resource_receipt,
    write_manifest,
)
from xferry.management.instances import (
    Instance,
    discover_instances,
    register_instance,
    resolve_instance,
    target_for_config,
)
from xferry.management.model import ManagedLayout
from xferry.management.native_backend import NativeBackend
from xferry.management.ownership import grant_directory_access, restore_directory_access
from xferry.settings import load_settings_file, render_sample_profile, resolve_settings

IMAGE = "ghcr.io/kgmnotes/xferry@sha256:" + "a" * 64
IMAGE_NEXT = "ghcr.io/kgmnotes/xferry@sha256:" + "b" * 64


@pytest.fixture(autouse=True)
def isolated_registry(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "operator"))


class Runner:
    def __init__(self):
        self.commands = []
        self.exists = False
        self.running = False
        self.fail_up = 0
        self.fail_restart = 0
        self.next_image = IMAGE

    def run(self, argv, **kwargs):
        from subprocess import CompletedProcess

        command = tuple(str(value) for value in argv)
        self.commands.append(command)
        code, stdout = 0, ""
        if command[:3] == ("docker", "image", "inspect"):
            stdout = json.dumps([self.next_image])
        elif command[:2] == ("docker", "ps"):
            stdout = "true\n" if self.exists else ""
        elif "--all" in command and "ps" in command:
            stdout = (
                json.dumps(
                    [{"Service": "xferry", "State": "running" if self.running else "exited"}]
                )
                if self.exists
                else "[]"
            )
        elif "up" in command:
            self.exists = True
            if self.fail_up:
                self.fail_up -= 1
                code = 1
            else:
                self.running = True
        elif "stop" in command or "down" in command:
            self.running = False
            if "down" in command:
                self.exists = False
        elif command[:2] == ("systemctl", "is-active"):
            stdout = "active" if self.running else "inactive"
            code = 0 if self.running else 3
        elif command[:2] == ("systemctl", "is-enabled"):
            stdout = "enabled"
        elif command[:2] in {("systemctl", "restart"), ("systemctl", "start")}:
            if self.fail_restart:
                self.fail_restart -= 1
                code = 1
            else:
                self.running = True
        return CompletedProcess(command, code, stdout, "")


def docker(tmp_path, runner=None):
    runner = runner or Runner()
    app = ManagementApplication(runner=runner)
    output = tmp_path / "bundle"
    result = app.setup(
        backend="docker", output=output, files_dir=tmp_path / "files", access="private"
    )
    assert result.exit_code == 0, result.message
    instance = resolve_instance(output / ".xferry-deployment.json")
    return app, instance, runner


def native(tmp_path, running=False):
    runner = Runner()
    runner.running = running
    layout = ManagedLayout(
        release_root=tmp_path / "opt/xferry",
        config_file=tmp_path / "etc/xferry/xferry.ini",
        auth_file=tmp_path / "etc/xferry/auth",
        data_root=tmp_path / "var/lib/xferry",
        lock_file=tmp_path / "run/lock/xferry.lock",
        unit_file=tmp_path / "etc/systemd/system/xferry.service",
        cli_link=tmp_path / "usr/local/bin/xferry",
    )
    profile = layout.config_file.parent / "profile.ini"
    files = tmp_path / "files"
    files.mkdir()
    layout.data_root.mkdir(parents=True)
    profile.parent.mkdir(parents=True)
    text = edit_ini(
        render_sample_profile("systemd"),
        {
            "access": "private",
            "https_mode": "off",
            "port": 8080,
            "host": "127.0.0.1",
            "files_dir": str(files),
            "state_dir": str(layout.data_root),
            "auth_file": str(layout.auth_file),
            "allowed_hosts": "localhost 127.0.0.1",
        },
    )
    profile.write_text(text)
    layout.auth_file.write_text("admin:oldpassword\n")
    layout.auth_file.chmod(0o600)
    from xferry.management.release_contract import ReleaseManifest

    release = layout.release_root / "releases/0.5.0"
    release.mkdir(parents=True)
    (release / "xferry").write_bytes(b"runtime")
    (release / "xferry").chmod(0o755)
    (release / "xferry-release.json").write_bytes(
        ReleaseManifest.create_v2(
            version="0.5.0",
            platform="linux-x86_64",
            executable_size=7,
            executable_sha256=hashlib.sha256(b"runtime").hexdigest(),
            source_commit="a" * 40,
            workflow_run="local",
        ).to_bytes()
    )
    (layout.release_root / "current").symlink_to("releases/0.5.0")
    layout.unit_file.parent.mkdir(parents=True)
    layout.unit_file.write_text("unit")
    spec = DeploymentSpec.new(
        "native",
        profile,
        files,
        layout.data_root,
        {"version": "0.5.0", "sha256": hashlib.sha256(b"runtime").hexdigest()},
    )
    layout.config_file.write_text(compile_profile(text, spec))
    spec = replace(
        spec,
        ownership=OwnershipReceipt(
            tuple(
                resource_receipt(path, kind="secret" if path == layout.auth_file else "file")
                for path in (profile, layout.config_file, layout.auth_file, layout.unit_file)
            )
            + (resource_receipt(layout.data_root, kind="tree"),)
        ),
    )
    manifest = profile.parent / "deployment.json"
    write_manifest(manifest, spec)
    for path in tmp_path.rglob("*"):
        if path.is_symlink():
            continue
        path.chmod(
            0o755
            if path.is_dir() or path == release / "xferry"
            else 0o600
            if path == layout.auth_file
            else 0o644
        )
    spec = replace(
        spec,
        ownership=replace(
            spec.ownership,
            resources=tuple(
                resource_receipt(Path(resource.path), kind=resource.kind)
                for resource in spec.ownership.resources
            ),
        ),
    )
    write_manifest(manifest, spec)
    register_instance(manifest)
    instance = Instance(spec.instance_id, "native", profile, manifest)
    backend = NativeBackend(runner, layout=layout, effective_uid=lambda: 0, root_uid=os.getuid())
    backend._health = lambda spec: True
    app = ManagementApplication(runner=runner, native_backend=backend)
    return app, instance, runner, layout


def test_discovery_ignores_ini_and_adjacent_unvalidated_metadata(tmp_path):
    folder = tmp_path / "operator/xferry/deployment"
    folder.mkdir(parents=True)
    config = folder / "xferry.ini"
    config.write_text("[server]\nconfig_version=1\n")
    (folder / ".xferry-deployment.json").write_text('{"schema":1,"kind":"docker"}')
    assert discover_instances() == ()
    assert target_for_config(config) == "portable"
    with pytest.raises(ValueError, match="unsupported deployment schema"):
        resolve_instance(folder / ".xferry-deployment.json")


def test_registry_indexes_only_validated_manifests(tmp_path):
    app, instance, _ = docker(tmp_path)
    assert app.resolve(instance.id) == instance
    document = json.loads((tmp_path / "operator/xferry/instances.json").read_text())
    assert document["schema"] == 2 and document["manifests"] == [str(instance.manifest)]
    assert "configs" not in document
    with pytest.raises(ValueError):
        register_instance(instance.config)


def test_manifest_has_identity_and_exact_digest_but_no_process_state(tmp_path):
    _, instance, _ = docker(tmp_path)
    manifest = json.loads(instance.manifest.read_text())
    assert manifest["schema"] == 2 and manifest["artifact"]["image"] == IMAGE
    assert "status" not in manifest and "running" not in manifest
    assert manifest["ownership"]["resources"]


def test_profile_has_host_semantics_and_compiler_has_container_semantics(tmp_path):
    runner = Runner()
    app = ManagementApplication(runner=runner)
    result = app.setup(
        backend="docker",
        output=tmp_path / "bundle",
        files_dir=tmp_path / "files",
        domain="files.example.com",
    )
    assert result.exit_code == 0
    host = load_settings_file(tmp_path / "bundle/xferry.ini")
    runtime = load_settings_file(tmp_path / "bundle/runtime.ini")
    assert host.port == 443 and host.files_dir == str(tmp_path / "files")
    assert (
        runtime.port == 8443 and runtime.files_dir == "/data/files" and runtime.state_dir == "/data"
    )
    compose = json.loads((tmp_path / "bundle/compose.yaml").read_text())
    assert compose["services"]["xferry"]["ports"] == ["80:8080", "443:8443"]
    binds = {
        volume["target"]: volume["source"]
        for volume in compose["services"]["xferry"]["volumes"]
        if isinstance(volume, dict)
    }
    assert binds == {
        "/etc/xferry/xferry.ini": str(tmp_path / "bundle/runtime.ini"),
        runtime.files_dir: host.files_dir,
    }


@pytest.mark.parametrize(
    "values,expected",
    [
        (
            {"https_mode": "files", "allowed_hosts": ("files.example.com",)},
            "https://files.example.com/",
        ),
        (
            {
                "https_mode": "files",
                "allowed_hosts": ("localhost", "127.0.0.1", "::1", "files.example.com"),
                "port": 8443,
            },
            "https://files.example.com:8443/",
        ),
        (
            {"https_mode": "files", "allowed_hosts": ("2001:db8::10",)},
            "https://[2001:db8::10]/",
        ),
        (
            {"https_mode": "domain", "domain": "files.example.com"},
            "https://files.example.com/",
        ),
        (
            {"https_mode": "auto", "public_ip": "8.8.8.8"},
            "https://8-8-8-8.sslip.io/",
        ),
        (
            {
                "access": "private",
                "https_mode": "off",
                "host": "127.0.0.1",
                "port": 8080,
                "allowed_hosts": ("files.example.com",),
            },
            "http://127.0.0.1:8080/",
        ),
    ],
)
def test_public_url_uses_configured_tls_identity(values, expected):
    settings = resolve_settings(
        cli_values={
            "access": "public",
            "auth_file": "/private/auth",
            **(
                {"cert_file": "/private/cert.pem", "key_file": "/private/key.pem"}
                if values["https_mode"] == "files"
                else {}
            ),
            **values,
        }
    )
    assert public_url(settings) == expected


@pytest.mark.parametrize("backend", ["native", "docker"])
def test_files_tls_password_reset_returns_public_hostname(tmp_path, backend):
    app, item, *_ = native(tmp_path) if backend == "native" else docker(tmp_path)
    if backend == "docker":
        assert app.operate("stop", item).exit_code == 0
    configured = app.configure(
        item,
        {
            "access": "public",
            "host": "0.0.0.0",
            "port": 443,
            "https_mode": "files",
            "cert_file": str(tmp_path / "cert.pem"),
            "key_file": str(tmp_path / "key.pem"),
            "allowed_hosts": "localhost 127.0.0.1 files.example.com",
        },
        apply=True,
    )
    assert configured.exit_code == 0, configured.message
    result = app.credentials(item, password="easykeyboard42")
    assert result.exit_code == 0, result.message
    assert result.credentials is not None
    assert result.credentials.url == "https://files.example.com/"


@pytest.mark.parametrize("backend", ["native", "docker"])
def test_configuring_stopped_server_keeps_it_stopped(tmp_path, backend):
    if backend == "native":
        app, item, runner, _ = native(tmp_path)
    else:
        app, item, runner = docker(tmp_path)
        app.operate("stop", item)
    runner.commands.clear()
    before_artifact = dict(item.spec.artifact)
    result = app.configure(item, {"max_size_mb": 42}, apply=True)
    assert result.exit_code == 0, result.message
    assert app.observe(item).state == "stopped"
    assert item.spec.artifact == before_artifact
    assert not any("up" in cmd or "restart" in cmd or "pull" in cmd for cmd in runner.commands)
    assert load_settings_file(item.config).max_size_mb == 42


@pytest.mark.parametrize("backend", ["native", "docker"])
def test_failed_config_apply_restores_previous_profile_and_runtime(tmp_path, backend):
    if backend == "native":
        app, item, runner, layout = native(tmp_path, running=True)
        runtime = layout.config_file
        runner.fail_restart = 1
    else:
        app, item, runner = docker(tmp_path)
        runtime = item.config.parent / "runtime.ini"
        runner.fail_up = 1
    paths = (item.config, runtime, item.manifest)
    before = {path: path.read_bytes() for path in paths}
    before_modes = {path: path.stat().st_mode for path in paths}
    result = app.configure(item, {"max_size_mb": 42}, apply=True)
    assert result.exit_code == 1
    assert {path: path.read_bytes() for path in paths} == before
    assert {path: path.stat().st_mode for path in paths} == before_modes
    assert app.observe(item).running is True


@pytest.mark.parametrize("backend", ["native", "docker"])
def test_preview_and_cas_never_overwrite_a_concurrent_edit(tmp_path, backend):
    app, item, runner, *_ = native(tmp_path) if backend == "native" else docker(tmp_path)
    before = item.config.read_text()
    result = app.configure(item, {"max_size_mb": 42}, apply=False, expected_text=before)
    assert result.exit_code == 0 and "max_size_mb" in result.details["diff"]
    assert item.config.read_text() == before
    item.config.write_text(before + "\n# concurrent operator edit\n")
    with pytest.raises(ValueError, match="changed during editing"):
        app.configure(item, {"max_size_mb": 42}, apply=True, expected_text=before)
    assert "concurrent operator edit" in item.config.read_text()


@pytest.mark.parametrize("backend", ["native", "docker"])
def test_default_health_is_not_checked_and_doctor_works_for_both(tmp_path, backend):
    app, item, *_ = native(tmp_path) if backend == "native" else docker(tmp_path)
    result = app.doctor(item)
    assert result.exit_code == 0
    assert result.state.health == "not_checked"
    assert result.details["checks"]["health"]["status"] == "not_checked"
    assert "oldpassword" not in json.dumps(result.to_json())


def test_compose_update_and_rollback_preserve_credentials_and_stop_state(tmp_path):
    app, item, runner = docker(tmp_path)
    app.operate("stop", item)
    password = (item.config.parent / "secrets/xferry_auth").read_bytes()
    runner.next_image = IMAGE_NEXT
    assert app.operate("update", item, version="0.5.1").exit_code == 0
    assert item.spec.artifact["image"] == IMAGE_NEXT
    assert app.observe(item).state == "stopped"
    assert app.operate("rollback", item).exit_code == 0
    assert item.spec.artifact["image"] == IMAGE
    assert app.observe(item).state == "stopped"
    assert (item.config.parent / "secrets/xferry_auth").read_bytes() == password


def test_failed_compose_update_restores_pinned_artifact(tmp_path):
    app, item, runner = docker(tmp_path)
    before = {p: p.read_bytes() for p in (item.manifest, item.config.parent / "compose.yaml")}
    runner.next_image, runner.fail_up = IMAGE_NEXT, 1
    result = app.operate("update", item, version="0.5.1")
    assert result.exit_code == 1
    assert {p: p.read_bytes() for p in before} == before
    assert not (item.config.parent / ".xferry-history.json").exists()
    assert app.observe(item).running


@pytest.mark.parametrize("backend", ["native", "docker"])
def test_stopped_credentials_rotation_keeps_server_stopped_and_secret_out_of_json(
    tmp_path, backend
):
    app, item, runner, *_ = native(tmp_path) if backend == "native" else docker(tmp_path)
    if backend == "docker":
        app.operate("stop", item)
    result = app.credentials(item, password="easykeyboard42")
    assert result.exit_code == 0, result.message
    assert result.credentials.password == "easykeyboard42"
    assert app.observe(item).state == "stopped"
    assert "easykeyboard42" not in repr(result)
    assert "easykeyboard42" not in json.dumps(result.to_json())
    assert not any("easykeyboard42" in str(command) for command in runner.commands)


def test_compose_uninstall_retains_state_and_reinstall_keeps_password(tmp_path):
    app, item, _ = docker(tmp_path)
    auth = item.config.parent / "secrets/xferry_auth"
    password = auth.read_bytes()
    (item.spec.files_dir / "keep.txt").write_text("keep")
    assert app.operate("uninstall", item).exit_code == 0
    assert app.observe(item).state == "retained"
    assert auth.read_bytes() == password
    result = app.setup(backend="docker", instance_id=item.id)
    assert result.exit_code == 0 and auth.read_bytes() == password
    assert app.observe(item).running


@pytest.mark.parametrize("backend", ["native", "docker"])
@pytest.mark.parametrize("confirmation", [None, False, "yes", 1])
def test_application_purge_refuses_before_resolution_lock_or_backend_work(
    tmp_path, monkeypatch, backend, confirmation
):
    class BackendProbe:
        def operate(self, *args, **kwargs):
            pytest.fail("an unconfirmed purge must not reach the backend")

    probe = BackendProbe()
    runner = Runner()
    app = ManagementApplication(
        runner=runner,
        native_backend=probe if backend == "native" else None,
        compose_backend=probe if backend == "docker" else None,
    )

    def unexpected(*args, **kwargs):
        pytest.fail("an unconfirmed purge must not resolve state or acquire a mutation lock")

    monkeypatch.setattr(app, "resolve", unexpected)
    monkeypatch.setattr("xferry.management.application.deployment_setup_lock", unexpected)
    options = {"purge": True}
    if confirmation is not None:
        options["confirmed"] = confirmation

    result = app.operate("uninstall", "selected-instance", **options)

    assert result.exit_code == 2
    assert "confirm" in result.message.lower()
    assert runner.commands == []
    assert not (tmp_path / "operator").exists()


@pytest.mark.parametrize("backend", ["native", "docker"])
@pytest.mark.parametrize(
    "options,lock_expected",
    [
        pytest.param({"purge": True, "confirmed": True}, True, id="confirmed-purge"),
        pytest.param({"purge": True, "dry_run": True}, False, id="unconfirmed-dry-run"),
        pytest.param({}, True, id="ordinary-uninstall"),
        pytest.param({"purge": False, "confirmed": False}, True, id="ordinary-unconfirmed"),
    ],
)
def test_application_uninstall_dispatches_only_allowed_confirmation_modes(
    tmp_path, monkeypatch, backend, options, lock_expected
):
    events = []

    class BackendProbe:
        def operate(self, action, selected, **supplied):
            events.append(("backend", action, selected.id, supplied))
            return OperationResult(0, "allowed backend operation")

    @contextmanager
    def mutation_lock():
        events.append("lock")
        yield

    probe = BackendProbe()
    spec = DeploymentSpec.new(
        backend,
        tmp_path / "profile.ini",
        tmp_path / "files",
        tmp_path / "state",
        {"version": "0.5.0", "sha256": "a" * 64} if backend == "native" else {"image": IMAGE},
        backend_options={"project": "xferry-confirmation"} if backend == "docker" else {},
    )
    manifest = tmp_path / "deployment.json"
    write_manifest(manifest, spec)
    item = Instance(spec.instance_id, backend, spec.profile, manifest)
    app = ManagementApplication(
        runner=Runner(),
        native_backend=probe if backend == "native" else None,
        compose_backend=probe if backend == "docker" else None,
    )
    monkeypatch.setattr("xferry.management.application.deployment_setup_lock", mutation_lock)

    result = app.operate("uninstall", item, **options)

    assert result.exit_code == 0
    expected = [("backend", "uninstall", item.id, options)]
    assert events == (["lock", *expected] if lock_expected else expected)


@pytest.mark.parametrize("backend", ["native", "docker"])
@pytest.mark.parametrize("confirmation", [None, False, "yes", 1])
def test_direct_adapter_purge_refuses_before_validation_observation_or_commands(
    tmp_path, monkeypatch, backend, confirmation
):
    runner = Runner()
    adapter = NativeBackend(runner) if backend == "native" else ComposeBackend(runner)

    def unexpected(*args, **kwargs):
        pytest.fail("an unconfirmed adapter purge must not inspect or mutate deployment state")

    monkeypatch.setattr(adapter, "_validate", unexpected)
    monkeypatch.setattr(adapter, "observe", unexpected)
    item = Instance("not-resolved", backend, tmp_path / "profile.ini", tmp_path / "absent.json")
    options = {"purge": True}
    if confirmation is not None:
        options["confirmed"] = confirmation

    result = adapter.operate("uninstall", item, **options)

    assert result.exit_code == 2
    assert "confirm" in result.message.lower()
    assert runner.commands == []
    assert not item.manifest.exists()


def test_compose_purge_removes_bundle_and_registry_but_preserves_files(tmp_path):
    app, item, _ = docker(tmp_path)
    files = item.spec.files_dir
    (files / "keep.txt").write_text("keep")
    result = app.operate("uninstall", item, purge=True, confirmed=True)
    assert result.exit_code == 0
    assert (files / "keep.txt").read_text() == "keep"
    assert not item.manifest.exists()
    assert discover_instances() == ()
    assert not item.config.exists()
    assert not item.config.parent.exists()


def test_compose_purge_retains_independently_changed_profile(tmp_path):
    app, item, _ = docker(tmp_path)
    item.config.write_text(item.config.read_text() + "\n# operator changed this\n")
    result = app.operate("uninstall", item, purge=True, confirmed=True)
    assert result.exit_code == 0
    assert item.config.exists()
    assert str(item.config) in result.details["retained"]
    assert not item.manifest.exists()


def test_acl_grant_is_non_recursive_reversible_and_conditional(tmp_path):
    files = tmp_path / "files"
    files.mkdir(mode=0o750)
    child = files / "keep"
    child.write_text("unchanged")
    metadata = files.stat()
    before = child.stat()
    receipt = grant_directory_access(files, 10001)
    assert receipt is not None
    assert files.stat().st_uid == metadata.st_uid
    assert child.stat() == before
    assert restore_directory_access(receipt)
    assert files.stat().st_mode == metadata.st_mode
    receipt = grant_directory_access(files, 10001)
    files.chmod(0o700)
    assert restore_directory_access(receipt) is False


def test_manifest_refuses_unsupported_state_without_mutation(tmp_path):
    path = tmp_path / "deployment.json"
    data = b'{"schema":1,"kind":"docker","files_dir":"/srv/files"}\n'
    path.write_bytes(data)
    with pytest.raises(ValueError, match="unsupported deployment schema"):
        load_manifest(path)
    assert path.read_bytes() == data


def test_digest_resolution_refuses_unverifiable_image(tmp_path):
    runner = Runner()
    runner.next_image = "other.example/xferry@sha256:" + "a" * 64
    app = ManagementApplication(runner=runner)
    with pytest.raises(ValueError, match="no verifiable"):
        app.setup(backend="docker", access="private", output=tmp_path / "bundle")
    assert not (tmp_path / "bundle").exists()


def test_failed_first_start_reveals_same_credentials_only_after_successful_retry(tmp_path):
    runner = Runner()
    runner.fail_up = 1
    app = ManagementApplication(runner=runner)
    output = tmp_path / "bundle"
    with pytest.raises(RuntimeError):
        app.setup(backend="docker", access="private", output=output, files_dir=tmp_path / "files")
    auth = (output / "secrets/xferry_auth").read_text().strip().split(":", 1)
    item = app.resolve(output / ".xferry-deployment.json")
    assert item.spec.backend_options["credentials_revealed"] is False
    result = app.setup(backend="docker", output=output)
    assert result.exit_code == 0
    assert result.credentials.username == auth[0] and result.credentials.password == auth[1]
    assert item.spec.backend_options["credentials_revealed"] is True
    assert app.setup(backend="docker", output=output).credentials is None


def test_failed_unpublished_bundle_write_is_retryable_and_preserves_public_folder(
    tmp_path, monkeypatch
):
    from xferry.management import compose_backend

    runner = Runner()
    app = ManagementApplication(runner=runner)
    output, files = tmp_path / "bundle", tmp_path / "files"
    files.mkdir()
    (files / "keep.txt").write_text("keep")
    original = compose_backend._atomic_write

    def fail_once(path, data, mode=None):
        if path.name == "runtime.ini":
            raise OSError("disk full")
        original(path, data, mode)

    monkeypatch.setattr(compose_backend, "_atomic_write", fail_once)
    with pytest.raises(OSError, match="disk full"):
        app.setup(backend="docker", access="private", output=output, files_dir=files)
    assert not (output / ".xferry-deployment.json").exists()
    assert (files / "keep.txt").read_text() == "keep"
    monkeypatch.setattr(compose_backend, "_atomic_write", original)
    assert (
        app.setup(backend="docker", access="private", output=output, files_dir=files).exit_code == 0
    )


def test_native_status_is_read_only_without_root_or_private_profile_access(tmp_path, monkeypatch):
    app, item, _, _ = native(tmp_path)
    backend = app._native_backend
    backend.effective_uid = lambda: 1001
    original = Path.read_text

    def protected_read(path, *args, **kwargs):
        if path == item.config:
            pytest.fail("status read the private operator profile")
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", protected_read)
    result = app.operate("status", item)
    assert result.exit_code == 0
    assert result.state.state == "stopped" and result.state.config == "not_checked"


def test_native_update_does_not_claim_independently_edited_unit(tmp_path):
    from xferry.management.deployment import resource_unchanged
    from xferry.management.releases import ReleaseResult

    app, item, _, layout = native(tmp_path)
    before = next(
        resource
        for resource in item.spec.ownership.resources
        if resource.path == str(layout.unit_file)
    )
    layout.unit_file.write_text("independent unit")

    class Releases:
        def update(self, version, dry_run):
            return ReleaseResult(0, "updated", version="0.5.0")

    app._native_backend.release_manager = Releases()
    assert app.operate("update", item, version="0.5.0").exit_code == 0
    after = next(
        resource
        for resource in item.spec.ownership.resources
        if resource.path == str(layout.unit_file)
    )
    assert after == before and not resource_unchanged(after)
    denied = app.operate("uninstall", item, purge=True, confirmed=True)
    assert denied.exit_code == 1 and str(layout.unit_file) in denied.details["retained"]


def test_compose_receipts_cannot_name_an_unrelated_resource_even_through_symlink(tmp_path):
    app, item, _ = docker(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    victim = outside / "keep"
    victim.write_text("unrelated")
    alias = item.config.parent / "alias"
    alias.symlink_to(outside, target_is_directory=True)
    spec = item.spec
    receipt = replace(resource_receipt(victim), path=str(alias / "keep"))
    write_manifest(
        item.manifest,
        replace(
            spec, ownership=replace(spec.ownership, resources=(*spec.ownership.resources, receipt))
        ),
    )
    with pytest.raises(ValueError, match="symlinks|outside generated"):
        app.operate("uninstall", item, purge=True, confirmed=True)
    assert victim.read_text() == "unrelated"


def test_native_setup_does_not_route_a_foreign_manifest_to_the_global_installation(tmp_path):
    app, item, runner, _ = native(tmp_path)
    foreign = tmp_path / "foreign/deployment.json"
    write_manifest(foreign, item.spec)
    runner.commands.clear()
    with pytest.raises(ValueError, match="canonical"):
        app.setup(backend="native", instance_id=str(foreign))
    assert runner.commands == []


def test_explicit_candidate_image_must_match_its_actual_repository_digest(tmp_path):
    runner = Runner()
    candidate = "127.0.0.1:5000/xferry@sha256:" + "d" * 64
    runner.next_image = candidate
    app = ManagementApplication(runner=runner)
    result = app.setup(
        backend="docker", image=candidate, output=tmp_path / "candidate", access="private"
    )
    assert result.exit_code == 0
    assert (
        app.resolve(tmp_path / "candidate/.xferry-deployment.json").spec.artifact["image"]
        == candidate
    )
    assert (
        app.resolve(tmp_path / "candidate/.xferry-deployment.json").spec.artifact["version"] is None
    )
    assert ("docker", "pull", candidate) in runner.commands


@pytest.mark.parametrize("backend", ["native", "docker"])
def test_setup_refuses_old_release_before_probe_or_mutation(tmp_path, backend):
    runner = Runner()
    result = ManagementApplication(runner=runner).setup(
        backend=backend, version="0.2.1", output=tmp_path / "bundle"
    )
    assert result.exit_code == 2
    assert runner.commands == [] and not (tmp_path / "bundle").exists()


def test_compose_reports_its_actual_state_volume_and_omits_host_state_path(tmp_path):
    app, item, _ = docker(tmp_path)
    storage = item.spec.backend_options["state_storage"]
    assert storage == {
        "kind": "docker_volume",
        "name": item.spec.backend_options["project"] + "_xferry-data",
        "runtime_root": "/data",
    }
    assert "state_dir =" not in item.config.read_text()
    assert load_settings_file(item.config.parent / "runtime.ini").state_dir == "/data"
    status = app.operate("status", item)
    assert status.details["state_storage"] == storage
    doctor = app.doctor(item)
    assert doctor.details["state_storage"] == storage
    assert doctor.details["checks"]["state_storage"]["status"] == "available"
    removed = app.operate("uninstall", item)
    assert "docker-volume:" + storage["name"] in removed.details["retained"]
    assert str(item.spec.state_dir) not in removed.details["retained"]


@pytest.mark.parametrize("purge", [False, True])
def test_native_uninstall_contract_retains_files_and_conditionally_private_state(tmp_path, purge):
    import shutil

    from xferry.management.managed_state import RETAINED_STATE_CONTENT, retained_state_path
    from xferry.management.releases import ReleaseResult

    app, item, runner, layout = native(tmp_path, running=True)
    profile, files = item.config, item.spec.files_dir
    (files / "keep.txt").write_text("keep")
    (layout.data_root / "notes").mkdir()
    (layout.data_root / "notes/private.txt").write_text("private")

    class Releases:
        def uninstall(self, purge_data, confirmed, dry_run):
            assert (purge_data, confirmed, dry_run) == (False, True, False)
            runner.running = False
            retained_state_path(layout).write_bytes(RETAINED_STATE_CONTENT)
            retained_state_path(layout).chmod(0o600)
            layout.unit_file.unlink()
            shutil.rmtree(layout.release_root)
            return ReleaseResult(0, "uninstalled")

    app._native_backend.release_manager = Releases()
    result = app.operate("uninstall", item, purge=purge, confirmed=purge)
    assert result.exit_code == 0, result.message
    assert (files / "keep.txt").read_text() == "keep"
    assert not layout.unit_file.exists() and not layout.release_root.exists()
    if purge:
        assert not profile.exists() and not item.manifest.exists()
        assert not layout.auth_file.exists() and not layout.data_root.exists()
        assert discover_instances() == ()
    else:
        assert profile.exists() and layout.auth_file.exists()
        assert (layout.data_root / "notes/private.txt").read_text() == "private"
        assert app.observe(item).state == "retained"


def _simulate_native_runtime_removal(app, runner, layout):
    import shutil

    from xferry.management.managed_state import RETAINED_STATE_CONTENT, retained_state_path
    from xferry.management.releases import ReleaseResult

    class Releases:
        def uninstall(self, purge_data, confirmed, dry_run):
            assert (purge_data, confirmed, dry_run) == (False, True, False)
            runner.running = False
            retained_state_path(layout).write_bytes(RETAINED_STATE_CONTENT)
            retained_state_path(layout).chmod(0o600)
            layout.unit_file.unlink()
            shutil.rmtree(layout.release_root)
            return ReleaseResult(0, "uninstalled")

    app._native_backend.release_manager = Releases()


def test_native_purge_retains_independently_changed_state_permissions(tmp_path):
    app, item, runner, layout = native(tmp_path, running=True)
    notes = layout.data_root / "notes"
    notes.mkdir()
    private = notes / "private.txt"
    private.write_text("preserve edited state")
    layout.data_root.chmod(0o700)
    _simulate_native_runtime_removal(app, runner, layout)

    result = app.operate("uninstall", item, purge=True, confirmed=True)

    assert result.exit_code == 0
    assert private.read_text() == "preserve edited state"
    assert layout.data_root.stat().st_mode & 0o777 == 0o700
    assert str(layout.data_root) in result.details["retained"]


def test_native_purge_accepts_primary_group_already_removed_by_userdel(tmp_path, monkeypatch):
    import grp
    import pwd
    from subprocess import CompletedProcess
    from types import SimpleNamespace

    app, item, runner, layout = native(tmp_path, running=True)
    # An absent external share has no retained UID ownership, so this created
    # service identity is unused and eligible for removal.
    item.spec.files_dir.rmdir()
    spec = item.spec
    write_manifest(
        item.manifest,
        replace(spec, ownership=replace(spec.ownership, accounts=("user:xferry", "group:xferry"))),
    )
    identities = {"user": True, "group": True}

    def user(name):
        if not identities["user"]:
            raise KeyError(name)
        return SimpleNamespace(pw_uid=os.getuid())

    def group(name):
        if not identities["group"]:
            raise KeyError(name)
        return SimpleNamespace(gr_gid=os.getgid(), gr_mem=[])

    original = runner.run

    def command(argv, **kwargs):
        if tuple(argv) == ("userdel", "xferry"):
            identities.update(user=False, group=False)
        if tuple(argv) == ("groupdel", "xferry"):
            runner.commands.append(tuple(argv))
            return CompletedProcess(argv, 6, "", "group is already absent")
        return original(argv, **kwargs)

    monkeypatch.setattr(pwd, "getpwnam", user)
    monkeypatch.setattr(grp, "getgrnam", group)
    monkeypatch.setattr(runner, "run", command)
    _simulate_native_runtime_removal(app, runner, layout)

    result = app.operate("uninstall", item, purge=True, confirmed=True)

    assert result.exit_code == 0
    assert ("userdel", "xferry") in runner.commands
    assert ("groupdel", "xferry") not in runner.commands
    assert "group:xferry" not in result.details["retained"]
    assert "user:xferry" not in result.details["retained"]


def test_compose_purge_retains_an_independently_edited_release_history(tmp_path):
    app, item, runner = docker(tmp_path)
    runner.next_image = IMAGE_NEXT
    assert app.operate("update", item, version="0.5.1").exit_code == 0
    history = item.config.parent / ".xferry-history.json"
    history.write_text(history.read_text() + "\n ")
    result = app.operate("uninstall", item, purge=True, confirmed=True)
    assert result.exit_code == 0
    assert history.exists() and str(history) in result.details["retained"]


@pytest.mark.parametrize("choice", ["same", "inside", "parent", "symlink"])
def test_new_deployment_refuses_a_known_share_before_pull_or_mutation(tmp_path, choice):
    app, item, _ = docker(tmp_path)
    files = item.spec.files_dir
    selected = files
    if choice == "inside":
        selected = files / "nested"
    elif choice == "parent":
        selected = files.parent
    elif choice == "symlink":
        selected = tmp_path / "alias"
        selected.symlink_to(files, target_is_directory=True)
    runner = Runner()
    output = tmp_path / "second-bundle"
    with pytest.raises(ValueError, match="reserved|real directory|must be separate"):
        ManagementApplication(runner=runner).setup(
            backend="docker", output=output, files_dir=selected, access="private"
        )
    assert not output.exists() and runner.commands == []
    assert app.observe(item).running


def test_default_compose_share_is_dedicated_to_its_bundle(tmp_path):
    app = ManagementApplication(runner=Runner())
    assert app.setup(backend="docker", output=tmp_path / "first", access="private").exit_code == 0
    assert app.setup(backend="docker", output=tmp_path / "second", access="private").exit_code == 0
    first = app.resolve(tmp_path / "first/.xferry-deployment.json")
    second = app.resolve(tmp_path / "second/.xferry-deployment.json")
    assert first.spec.files_dir == tmp_path / "first-files"
    assert second.spec.files_dir == tmp_path / "second-files"


def test_native_known_folder_blocks_compose_before_pull(tmp_path):
    _, item, _, _ = native(tmp_path)
    runner = Runner()
    with pytest.raises(ValueError, match="reserved"):
        ManagementApplication(runner=runner).setup(
            backend="docker",
            output=tmp_path / "docker",
            files_dir=item.spec.files_dir,
            access="private",
        )
    assert runner.commands == []


def test_setup_claim_is_global_across_outputs_until_manifest_is_indexed(tmp_path):
    import threading
    from concurrent.futures import ThreadPoolExecutor

    from xferry.settings import SettingsError

    entered, release = threading.Event(), threading.Event()

    class BlockingRunner(Runner):
        def run(self, argv, **kwargs):
            if tuple(argv)[:2] == ("docker", "pull"):
                entered.set()
                assert release.wait(5)
            return super().run(argv, **kwargs)

    first = ManagementApplication(runner=BlockingRunner())
    second_runner = Runner()
    second = ManagementApplication(runner=second_runner)
    folder = tmp_path / "files"
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(
            first.setup,
            backend="docker",
            output=tmp_path / "one",
            files_dir=folder,
            access="private",
        )
        assert entered.wait(3)
        try:
            with pytest.raises(SettingsError, match="another.*operation"):
                second.setup(
                    backend="docker", output=tmp_path / "two", files_dir=folder, access="private"
                )
            assert second_runner.commands == []
        finally:
            release.set()
        assert future.result().exit_code == 0
    with pytest.raises(ValueError, match="reserved"):
        second.setup(backend="docker", output=tmp_path / "two", files_dir=folder, access="private")
    assert second_runner.commands == []


def test_share_reservation_detects_an_inode_alias_before_pull(tmp_path, monkeypatch):
    _, item, _ = docker(tmp_path)
    alias = tmp_path / "inode-alias"
    alias.mkdir()
    original = Path.stat
    metadata = item.spec.files_dir.stat()

    def aliased_stat(path, *args, **kwargs):
        if path == alias:
            return metadata
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, "stat", aliased_stat)
    runner = Runner()
    with pytest.raises(ValueError, match="reserved"):
        ManagementApplication(runner=runner).setup(
            backend="docker", output=tmp_path / "new", files_dir=alias, access="private"
        )
    assert runner.commands == []
