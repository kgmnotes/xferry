"""Progress observes real operations without changing their results or secrets."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Sequence
from dataclasses import fields
from pathlib import Path
from types import SimpleNamespace

import pytest

from xferry.management import bootstrap, compose_backend
from xferry.management.application import ManagementApplication
from xferry.management.execution import CommandResult
from xferry.management.instances import Instance
from xferry.management.model import HostFacts, ManagedLayout, PreflightFailure, SetupPreflight
from xferry.management.progress import (
    ProgressEvent,
    observe_progress,
    run_stage,
)


def test_returned_failure_is_not_reported_as_success() -> None:
    events: list[ProgressEvent] = []
    result = CommandResult(("test",), 7)
    with observe_progress(events.append):
        assert run_stage("start", lambda: result, ok=lambda value: value.returncode == 0) is result
    assert events == [ProgressEvent("start", "running"), ProgressEvent("start", "failed")]


def test_interrupted_operation_reports_failure_and_clears_observer() -> None:
    events: list[ProgressEvent] = []

    def interrupted() -> None:
        raise KeyboardInterrupt

    with pytest.raises(KeyboardInterrupt), observe_progress(events.append):
        run_stage("wait_ready", interrupted)
    run_stage("prepare", lambda: None)
    assert events == [ProgressEvent("wait_ready", "running"), ProgressEvent("wait_ready", "failed")]


def test_native_preflight_failure_finishes_before_any_mutation(
    tmp_path: Path,
) -> None:
    from xferry.management.setup import SetupExecutor

    events: list[ProgressEvent] = []
    layout = ManagedLayout(config_file=tmp_path / "xferry.ini", data_root=tmp_path / "state")
    preflight = SetupPreflight(
        executable_ready=False,
        required_bind_ports=(8080,),
        unavailable_bind_ports=(),
        ufw_active=False,
        failures=(PreflightFailure("executable-missing", "runtime is missing"),),
    )
    executor = SetupExecutor(
        effective_uid=lambda: 0,
        preflight_check=lambda _plan: preflight,
        progress=events.append,
    )
    result = executor.apply(SimpleNamespace(layout=layout, files_dir=None))
    assert result.exit_code != 0
    assert events == [ProgressEvent("preflight", "running"), ProgressEvent("preflight", "failed")]
    assert not layout.config_file.exists()
    assert not layout.data_root.exists()


class DockerRunner:
    def __init__(self) -> None:
        self.fail_up = 0
        self.commands: list[tuple[str, ...]] = []

    def run(self, argv: Sequence[str]) -> CommandResult:
        command = tuple(argv)
        self.commands.append(command)
        if command[:3] == ("docker", "image", "inspect"):
            return CommandResult(
                command, 0, stdout=json.dumps(["ghcr.io/kgmnotes/xferry@sha256:" + "a" * 64])
            )
        if "ps" in command and "--all" in command:
            return CommandResult(command, 0, stdout='[{"Service":"xferry","State":"running"}]')
        if "up" in command and self.fail_up:
            self.fail_up -= 1
            return CommandResult(command, 1, stderr="unhealthy")
        return CommandResult(command, 0)


def docker_application(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[ManagementApplication, DockerRunner]:
    monkeypatch.setattr(compose_backend, "grant_directory_access", lambda *_: None)
    runner = DockerRunner()
    return ManagementApplication(runner=runner), runner


def test_dynamic_application_observer_reaches_cached_backend_without_secrets(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    app, _runner = docker_application(tmp_path, monkeypatch)
    events: list[ProgressEvent] = []
    app.progress = events.append
    output = tmp_path / "deployment"
    result = app.setup(
        backend="docker", output=output, files_dir=tmp_path / "files", access="private"
    )
    assert result.exit_code == 0
    assert result.credentials is not None
    assert ProgressEvent("download", "done") in events
    assert ProgressEvent("prepare", "done") in events
    assert events[-2:] == [
        ProgressEvent("wait_ready", "running"),
        ProgressEvent("wait_ready", "done"),
    ]
    assert result.credentials.password not in repr(events)
    assert str(output) not in repr(events)
    assert [field.name for field in fields(ProgressEvent)] == ["stage", "state"]

    first_events = list(events)
    second_events: list[ProgressEvent] = []
    app.progress = second_events.append
    instance = Instance(
        str(result.details["instance_id"]),
        "docker",
        output / "xferry.ini",
        output / ".xferry-deployment.json",
    )
    configured = app.configure(instance, {"max_size_mb": "25"}, apply=True)
    assert configured.exit_code == 0
    assert events == first_events
    assert ProgressEvent("validate_config", "done") in second_events
    assert second_events[-1] == ProgressEvent("apply_config", "done")

    app.progress = None
    app.configure(instance, {"max_size_mb": "26"}, apply=True)
    assert second_events[-1] == ProgressEvent("apply_config", "done")


def test_failed_configuration_reports_failed_stage_then_verified_restore(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    app, runner = docker_application(tmp_path, monkeypatch)
    output = tmp_path / "deployment"
    installed = app.setup(
        backend="docker", output=output, files_dir=tmp_path / "files", access="private"
    )
    assert installed.exit_code == 0
    instance = Instance(
        str(installed.details["instance_id"]),
        "docker",
        output / "xferry.ini",
        output / ".xferry-deployment.json",
    )
    before = instance.config.read_bytes()
    runner.fail_up = 1
    events: list[ProgressEvent] = []
    app.progress = events.append
    result = app.configure(instance, {"max_size_mb": "25"}, apply=True)
    assert result.exit_code == 1
    assert instance.config.read_bytes() == before
    assert ProgressEvent("wait_ready", "failed") in events
    assert ProgressEvent("apply_config", "failed") in events
    assert events[-1] == ProgressEvent("restore", "done")


def test_setup_cleanup_reports_acl_restore_failure_even_when_bundle_restore_succeeds(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    app, runner = docker_application(tmp_path, monkeypatch)
    cleanup: list[str] = []
    monkeypatch.setattr(
        compose_backend, "grant_directory_access", lambda path, _uid: {"path": str(path)}
    )

    def failed_acl_restore(_receipt: dict[str, object]) -> bool:
        cleanup.append("acl")
        return False

    def successful_bundle_restore(_snapshots: object) -> bool:
        cleanup.append("bundle")
        return True

    def failed_write(*_args: object) -> None:
        raise OSError("injected write failure")

    monkeypatch.setattr(compose_backend, "restore_directory_access", failed_acl_restore)
    monkeypatch.setattr(compose_backend, "_restore_bundle", successful_bundle_restore)
    monkeypatch.setattr(compose_backend, "_atomic_write", failed_write)
    events: list[ProgressEvent] = []
    app.progress = events.append
    with pytest.raises(OSError, match="injected write failure"):
        app.setup(
            backend="docker",
            output=tmp_path / "deployment",
            files_dir=tmp_path / "files",
            access="private",
        )
    assert cleanup == ["acl", "bundle"]
    assert runner.commands[-1][-2:] == ("down", "--remove-orphans")
    assert events[-1] == ProgressEvent("restore", "failed")


def test_observer_failure_does_not_change_setup_or_configuration(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    app, _runner = docker_application(tmp_path, monkeypatch)

    def broken_terminal(_event: ProgressEvent) -> None:
        raise OSError("terminal disconnected")

    app.progress = broken_terminal
    result = app.setup(
        backend="docker",
        output=tmp_path / "deployment",
        files_dir=tmp_path / "files",
        access="private",
    )
    assert result.exit_code == 0
    assert (tmp_path / "deployment" / ".xferry-deployment.json").exists()


@pytest.mark.parametrize("installer_exit", [0, 1])
def test_bootstrap_reports_verified_downloads_and_actual_installer_exit(
    monkeypatch: pytest.MonkeyPatch, installer_exit: int
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
        artifact_digests=((f"install-{platform}.sh", hashlib.sha256(script).hexdigest()),),
    )
    monkeypatch.setattr(bootstrap, "verify_signed_manifest", lambda *_args, **_kwargs: manifest)
    monkeypatch.setattr(bootstrap, "verify_detached_signature", lambda *_args, **_kwargs: None)

    class Download:
        def read(self, url: str, _maximum: int) -> bytes:
            return script if url.endswith(".sh") else b"metadata"

    class Runner:
        def run(self, _argv: Sequence[str]) -> CommandResult:
            return CommandResult(("test",), installer_exit)

    events: list[ProgressEvent] = []
    result = bootstrap.install_release(
        "0.5.0", downloader=Download(), runner=Runner(), progress=events.append
    )
    assert result.exit_code == installer_exit
    assert events[0] == ProgressEvent("download", "running")
    assert ProgressEvent("verify", "done") in events
    assert events[-1] == ProgressEvent("install", "failed" if installer_exit else "done")
