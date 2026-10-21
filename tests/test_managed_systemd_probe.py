"""Executable safety/contract tests; mocks are not systemd lifecycle evidence."""

from __future__ import annotations

import base64
import json
import os
import shutil
import subprocess
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from tools import managed_systemd_probe as probe


@pytest.fixture
def sandbox(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[probe.ProbeOptions, probe.SystemPaths]:
    paths = probe.SystemPaths(
        pid1_comm=tmp_path / "proc-comm",
        container_marker=tmp_path / "container",
        cgroup_namespace=tmp_path / "cgroup-ns",
        os_release=tmp_path / "os-release",
        release_root=tmp_path / "opt" / "xferry",
        config_root=tmp_path / "etc" / "xferry",
        data_root=tmp_path / "var" / "lib" / "xferry",
        unit=tmp_path / "etc" / "systemd" / "system" / "xferry.service",
        cli=tmp_path / "usr" / "local" / "bin" / "xferry",
    )
    paths.pid1_comm.write_text("systemd\n")
    paths.container_marker.write_text("docker\n")
    paths.cgroup_namespace.symlink_to("cgroup:[200]")
    paths.os_release.write_text('ID=ubuntu\nVERSION_ID="24.04"\n')
    options = probe.ProbeOptions(
        fixtures_root=tmp_path / "fixtures",
        tls_dir=tmp_path / "tls",
        evidence=tmp_path / "evidence" / "lifecycle.json",
        distro="ubuntu",
        distro_version="24.04",
        machine="x86_64",
        platform="linux-x86_64",
        host_cgroup_namespace="cgroup:[100]",
    )
    options.fixtures_root.mkdir()
    options.tls_dir.mkdir()
    (options.tls_dir / "server.crt").write_bytes(b"unit certificate fixture")
    (options.tls_dir / "server.key").write_bytes(b"unit TLS fixture, not a production key")
    monkeypatch.setattr(probe.os, "geteuid", lambda: 0)
    monkeypatch.setattr(probe.os, "uname", lambda: SimpleNamespace(machine="x86_64"))
    monkeypatch.setenv("XFERRY_SYSTEMD_REHEARSAL", "1")
    monkeypatch.setattr(probe, "_command", lambda *args, **kwargs: b"not-found\n")
    return options, paths


def _create_private_state(
    paths: probe.SystemPaths, auth: str = "admin:unit-test-sensitive%value\n"
) -> None:
    paths.config_root.mkdir(parents=True, exist_ok=True)
    paths.data_root.mkdir(parents=True, exist_ok=True)
    paths.config.write_text(
        "[server]\nhost = 127.0.0.1\nport = 8080\n[security]\nauth_file = /etc/xferry/auth\n"
    )
    paths.auth.write_text(auth)


def _response(body: bytes, headers: bytes = b"", status: bytes = b"200 OK") -> bytes:
    return (
        b"HTTP/1.1 "
        + status
        + b"\r\nContent-Length: "
        + str(len(body)).encode()
        + b"\r\n"
        + headers
        + b"\r\n"
        + body
    )


def test_guard_accepts_only_actual_expected_container_facts(sandbox: Any) -> None:
    options, paths = sandbox
    result = probe.guard(options, paths)
    assert result == {
        "distro": "ubuntu",
        "distro_version": "24.04",
        "machine": "x86_64",
        "platform": "linux-x86_64",
        "pid1": "systemd",
        "container": "docker",
        "effective_uid": 0,
        "private_cgroup_namespace": True,
        "cgroup_namespace": "cgroup:[200]",
        "host_cgroup_namespace": "cgroup:[100]",
    }


@pytest.mark.parametrize(
    "invalid",
    [
        "uid",
        "opt_in",
        "pid1",
        "container",
        "host_namespace",
        "own_namespace",
        "distro",
        "version",
        "machine",
        "platform",
        "existing_unit",
        "loaded_service",
        "config_root",
        "data_root",
        "release_root",
        "cli_dangling",
        "tls_under_fixtures",
        "tls_symlink",
    ],
)
def test_guard_failure_prevents_all_lifecycle_mutations(
    sandbox: Any,
    monkeypatch: pytest.MonkeyPatch,
    invalid: str,
) -> None:
    options, paths = sandbox
    commands: list[tuple[str, ...]] = []
    mutation_boundary_calls: list[bool] = []

    def command(argv: tuple[str, ...], **kwargs: Any) -> bytes:
        commands.append(tuple(argv))
        return b"loaded\n" if invalid == "loaded_service" else b"not-found\n"

    def forbidden_server(*args: Any, **kwargs: Any) -> None:
        mutation_boundary_calls.append(True)
        raise AssertionError("mutation boundary reached after a rejected guard")

    monkeypatch.setattr(probe, "_command", command)
    monkeypatch.setattr(probe, "serve_fixtures", forbidden_server)
    if invalid == "uid":
        monkeypatch.setattr(probe.os, "geteuid", lambda: 1000)
    elif invalid == "opt_in":
        monkeypatch.delenv("XFERRY_SYSTEMD_REHEARSAL")
    elif invalid == "pid1":
        paths.pid1_comm.write_text("python3\n")
    elif invalid == "container":
        paths.container_marker.write_text("podman\n")
    elif invalid == "host_namespace":
        options = replace(options, host_cgroup_namespace="cgroup:[200]")
    elif invalid == "own_namespace":
        paths.cgroup_namespace.unlink()
        paths.cgroup_namespace.symlink_to("unvalidated-sensitive-text")
    elif invalid == "distro":
        paths.os_release.write_text('ID=alpine\nVERSION_ID="24.04"\n')
    elif invalid == "version":
        options = replace(options, distro_version="22.04")
    elif invalid == "machine":
        monkeypatch.setattr(probe.os, "uname", lambda: SimpleNamespace(machine="aarch64"))
    elif invalid == "platform":
        options = replace(options, platform="linux-aarch64")
    elif invalid == "existing_unit":
        paths.unit.parent.mkdir(parents=True)
        paths.unit.write_text("existing service")
    elif invalid in {"config_root", "data_root", "release_root"}:
        getattr(paths, invalid).mkdir(parents=True)
    elif invalid == "cli_dangling":
        paths.cli.parent.mkdir(parents=True)
        paths.cli.symlink_to("missing-executable")
    elif invalid == "tls_under_fixtures":
        options = replace(options, tls_dir=options.fixtures_root / "tls")
    elif invalid == "tls_symlink":
        key = options.tls_dir / "server.key"
        key.unlink()
        key.symlink_to("missing-key")

    evidence = probe.run_probe(options, paths)

    assert evidence["status"] == "failed"
    assert evidence["failure"]["phase"] == "guard"
    assert evidence["failure"]["code"] in probe._FAILURE_CODES
    assert len(evidence["stages"]) == 1
    assert mutation_boundary_calls == []
    assert all(argv[:3] == ("systemctl", "show", "xferry.service") for argv in commands)
    assert "unvalidated-sensitive-text" not in options.evidence.read_text()


@pytest.mark.parametrize("machine", ["x86_64", "aarch64"])
@pytest.mark.parametrize(
    "distro,version",
    [
        ("ubuntu", "22.04"),
        ("ubuntu", "24.04"),
        ("ubuntu", "26.04"),
        ("debian", "12"),
        ("debian", "13"),
    ],
)
def test_guard_enforces_all_ten_exact_native_pairs(
    sandbox: Any,
    monkeypatch: pytest.MonkeyPatch,
    machine: str,
    distro: str,
    version: str,
) -> None:
    options, paths = sandbox
    paths.os_release.write_text(f'ID={distro}\nVERSION_ID="{version}"\n')
    monkeypatch.setattr(probe.os, "uname", lambda: SimpleNamespace(machine=machine))
    options = replace(
        options, distro=distro, distro_version=version, machine=machine, platform=f"linux-{machine}"
    )
    assert probe.guard(options, paths)["platform"] == f"linux-{machine}"


@pytest.mark.parametrize("server", ["XFerry/0.1.1", "XFerry/0.1.2", "Other/0.1.1", None])
def test_health_parser_requires_exact_ready_server_version(server: Any) -> None:
    body = json.dumps({"health": "ready", "server": server}).encode()
    assert probe._parse_health(_response(body), "0.1.1") is (server == "XFerry/0.1.1")


@pytest.mark.parametrize(
    "response",
    [
        b"not HTTP",
        _response(b'{"health":"ready","server":"XFerry/0.1.1"}', status=b"401 Nope"),
        _response(b'{"health":"not-ready","server":"XFerry/0.1.1"}'),
        _response(b'{"health":"ready","server":"XFerry/0.1.1","server":"XFerry/0.1.2"}'),
        _response(b"invalid JSON"),
        _response(b"[]"),
        _response(b"{}", headers=b"Content-Length: 2\r\n"),
        _response(b"{}", headers=b"Transfer-Encoding: chunked\r\n"),
        _response(b"{}", headers=b"Padding: " + b"x" * 65536 + b"\r\n"),
        _response(b"x" * 65537),
        b"HTTP/1.1 200 OK\r\nContent-Length: -1\r\n\r\n{}",
    ],
)
def test_health_parser_rejects_bad_or_overlong_frames(response: bytes) -> None:
    assert probe._parse_health(response, "0.1.1") is False


def test_health_credentials_use_no_interpolation_or_secret_evidence(sandbox: Any) -> None:
    _, paths = sandbox
    _create_private_state(paths)
    token = probe._health_credentials(paths)
    assert base64.b64decode(token) == b"admin:unit-test-sensitive%value"


@pytest.mark.parametrize(
    "invalid", ["symlink", "fifo", "multiline", "empty", "wrong_user", "host", "port", "auth_path"]
)
def test_health_credential_reader_rejects_unsafe_state(sandbox: Any, invalid: str) -> None:
    _, paths = sandbox
    _create_private_state(paths)
    if invalid == "symlink":
        paths.auth.unlink()
        paths.auth.symlink_to(paths.config)
    elif invalid == "fifo":
        paths.auth.unlink()
        os.mkfifo(paths.auth)
    elif invalid == "multiline":
        paths.auth.write_text("admin:secret\nother:secret\n")
    elif invalid == "empty":
        paths.auth.write_text("admin:\n")
    elif invalid == "wrong_user":
        paths.auth.write_text("other:secret\n")
    else:
        replacements = {
            "host": ("127.0.0.1", "0.0.0.0"),
            "port": ("8080", "9000"),
            "auth_path": ("/etc/xferry/auth", "/tmp/auth"),
        }
        before, after = replacements[invalid]
        paths.config.write_text(paths.config.read_text().replace(before, after))
    with pytest.raises(probe.ProbeFailure):
        probe._health_credentials(paths)


def test_health_socket_failure_does_not_emit_request_or_exception(
    sandbox: Any,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _, paths = sandbox
    _create_private_state(paths)

    def fail_connection(*args: Any, **kwargs: Any) -> None:
        raise OSError("Authorization: Basic secret-token unit-test-sensitive%value")

    monkeypatch.setattr(probe.socket, "create_connection", fail_connection)
    with pytest.raises(probe.ProbeFailure, match="^health_connection_failed$"):
        probe.verify_health("0.1.1", paths)
    assert capsys.readouterr() == ("", "")


def test_authenticated_ping_uses_bounded_reads_and_validates_actual_frame(
    sandbox: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, paths = sandbox
    _create_private_state(paths)
    payload = _response(b'{"health":"ready","server":"XFerry/0.1.1"}')
    requests: list[bytes] = []
    sizes: list[int] = []

    class Socket:
        def __enter__(self) -> Socket:
            return self

        def __exit__(self, *args: Any) -> None:
            pass

        def settimeout(self, timeout: int) -> None:
            assert timeout == 5

        def sendall(self, request: bytes) -> None:
            requests.append(request)

        def recv(self, size: int) -> bytes:
            nonlocal payload
            sizes.append(size)
            chunk, payload = payload[:size], payload[size:]
            return chunk

    monkeypatch.setattr(probe.socket, "create_connection", lambda *args, **kwargs: Socket())
    probe.verify_health("0.1.1", paths)
    assert requests[0].startswith(b"PING / HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Basic ")
    assert base64.b64encode(b"admin:unit-test-sensitive%value") in requests[0]
    assert all(0 < size <= 4096 for size in sizes)


def test_state_hashes_stay_in_memory_and_preservation_is_only_boolean(sandbox: Any) -> None:
    _, paths = sandbox
    _create_private_state(paths)
    paths.sentinel.write_bytes(b"nonsecret sentinel")
    baseline = probe._state_hashes(paths)
    assert probe._preservation(baseline, paths) == {"config": True, "auth": True, "sentinel": True}
    paths.auth.write_text("admin:changed\n")
    assert probe._preservation(baseline, paths) == {"config": True, "auth": False, "sentinel": True}
    paths.auth.unlink()
    paths.auth.symlink_to(paths.sentinel)
    assert probe._preservation(baseline, paths)["auth"] is False


def test_command_captures_without_echoing_and_discards_setup_secret_stderr(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    calls: list[dict[str, Any]] = []

    def run(argv: Any, **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        calls.append(kwargs)
        return subprocess.CompletedProcess(
            argv, 1, stdout=b"secret in failed output", stderr=b"Credentials: admin:secret"
        )

    monkeypatch.setattr(probe.subprocess, "run", run)
    with pytest.raises(probe.ProbeFailure, match="^command_failed$"):
        probe._command(("xferry", "setup", "--private", "--json"), discard_stderr=True)
    assert calls[0]["stdout"] == subprocess.PIPE
    assert calls[0]["stderr"] == subprocess.DEVNULL
    assert capsys.readouterr() == ("", "")
    assert str(probe.ProbeFailure("Credentials: admin:secret")) == "probe_failed"


@pytest.mark.parametrize(
    "payload",
    [
        b'{"status":"ok","exit_code":false}',
        b'{"status":"ok","exit_code":0,"exit_code":1}',
        b'{"status":"error","exit_code":0,"detail":"sensitive error"}',
        b'["sensitive malformed result"]',
        b"sensitive non-JSON output",
    ],
)
def test_malformed_command_outcomes_fail_without_leaking_payload(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    payload: bytes,
) -> None:
    monkeypatch.setattr(probe, "_command", lambda *args, **kwargs: payload)
    with pytest.raises(probe.ProbeFailure) as failure:
        probe._json_command(("xferry", "setup", "--private", "--json"))
    assert str(failure.value) in {"command_json_invalid", "command_outcome_invalid"}
    assert "sensitive" not in str(failure.value)
    assert capsys.readouterr() == ("", "")


@pytest.mark.parametrize(
    "target_kind", ["directory", "outside", "symlink_inside", "symlink_parent"]
)
def test_fixture_http_handler_never_serves_tls_or_symlink_targets(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    target_kind: str,
) -> None:
    root = tmp_path / "fixtures"
    root.mkdir()
    outside = tmp_path / "fixture-tls" / "server.key"
    outside.parent.mkdir()
    outside.write_bytes(b"unit-only fixture key outside served root")
    inside = root / "verified-release"
    inside.write_bytes(b"verified fixture")
    if target_kind == "directory":
        target = root
    elif target_kind == "outside":
        target = outside
    elif target_kind == "symlink_inside":
        target = root / "symlink"
        target.symlink_to(inside)
    else:
        nested = root / "nested"
        nested.mkdir()
        (nested / "release").write_bytes(b"fixture")
        link = root / "link"
        link.symlink_to(nested, target_is_directory=True)
        target = link / "release"
    handler = object.__new__(probe._QuietHandler)
    handler.directory = str(root)
    handler.path = "/verified-release"
    errors: list[int] = []
    monkeypatch.setattr(handler, "translate_path", lambda _: str(target))
    monkeypatch.setattr(handler, "send_error", errors.append)
    assert handler.send_head() is None
    assert errors == [403]


@pytest.mark.parametrize(
    "main_pid,load_state,enabled",
    [
        ("0", "loaded", b"enabled\n"),
        ("-1", "loaded", b"enabled\n"),
        ("123", "not-found", b"enabled\n"),
        ("123", "loaded", b"disabled\n"),
    ],
)
def test_active_service_requires_real_loaded_pid_and_enabled_state(
    monkeypatch: pytest.MonkeyPatch,
    main_pid: str,
    load_state: str,
    enabled: bytes,
) -> None:
    def command(argv: Any, **kwargs: Any) -> bytes:
        if "is-enabled" in argv:
            return enabled
        return f"ActiveState=active\nMainPID={main_pid}\nLoadState={load_state}\n".encode()

    monkeypatch.setattr(probe, "_command", command)
    with pytest.raises(probe.ProbeFailure, match="^service_state_invalid$"):
        probe._service(True)


@pytest.mark.parametrize(
    "output", [b"xferry 0.1.2\n", b"prefix xferry 0.1.1\n", b"xferry 0.1.1\nsecret output\n"]
)
def test_cli_version_rejects_nonexact_output(sandbox: Any, monkeypatch: Any, output: bytes) -> None:
    _, paths = sandbox
    monkeypatch.setattr(probe, "_command", lambda *args, **kwargs: output)
    with pytest.raises(probe.ProbeFailure, match="^cli_version_mismatch$"):
        probe._version(paths, "0.1.1")


def test_bootstrap_uses_only_guarded_exec_staging_without_changing_global_environment(
    sandbox: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    options, _ = sandbox
    monkeypatch.setenv("TMPDIR", "/untrusted/unit-only-temp")
    commands: list[tuple[tuple[str, ...], dict[str, Any]]] = []

    def command(argv: Any, **kwargs: Any) -> bytes:
        commands.append((tuple(argv), kwargs))
        return b"installed"

    monkeypatch.setattr(probe, "_command", command)
    probe._bootstrap(options)
    assert len(commands) == 1
    argv, kwargs = commands[0]
    assert argv == (
        "sh",
        str(options.fixtures_root / "releases/download/v0.1.1/install-linux-x86_64.sh"),
    )
    assert kwargs["environment"] == os.environ | {
        "TMPDIR": "/var/tmp",
        "XFERRY_RELEASE_BASE_URL": "https://127.0.0.1:44443/releases/download/v0.1.1",
        "CURL_CA_BUNDLE": str(options.tls_dir / "server.crt"),
    }
    assert os.environ["TMPDIR"] == "/untrusted/unit-only-temp"


@pytest.mark.parametrize(
    ("substep", "code"),
    [
        ("bootstrap", "install_bootstrap_failed"),
        ("version", "version_query_failed"),
        ("unit_properties", "service_query_failed"),
        ("unit_enabled", "service_query_failed"),
    ],
)
def test_install_substep_failure_is_specific_and_never_creates_private_setup_state(
    sandbox: Any, monkeypatch: pytest.MonkeyPatch, substep: str, code: str
) -> None:
    options, paths = sandbox
    calls: list[tuple[str, ...]] = []

    @contextmanager
    def fixture_server(_: Any) -> Iterator[None]:
        yield

    def command(argv: Any, **kwargs: Any) -> bytes:
        argv = tuple(argv)
        calls.append(argv)
        if argv[0] == "sh":
            if substep == "bootstrap":
                raise probe.ProbeFailure("command_failed")
            return b"installed"
        if argv[1] == "--version":
            if substep == "version":
                raise probe.ProbeFailure("command_failed")
            return b"xferry 0.1.1\n"
        if argv[:2] == ("systemctl", "show"):
            if substep == "unit_properties":
                raise probe.ProbeFailure("command_failed")
            return b"MainPID=0\nLoadState=not-found\nActiveState=inactive\n"
        if argv[:2] == ("systemctl", "is-enabled"):
            assert substep == "unit_enabled"
            raise probe.ProbeFailure("command_failed")
        pytest.fail("setup or later phase must never run")

    monkeypatch.setattr(probe, "guard", lambda *_: {"unitTestGuardOnly": True})
    monkeypatch.setattr(probe, "serve_fixtures", fixture_server)
    monkeypatch.setattr(probe, "_release_state", lambda *_: {})
    monkeypatch.setattr(probe, "_command", command)
    result = probe.run_probe(options, paths)
    assert result["status"] == "failed"
    assert result["failure"] == {"phase": "install", "code": code}
    assert not any("setup" in argv for argv in calls)
    assert not paths.config.exists() and not paths.auth.exists()
    assert not paths.unit.exists() and not paths.data_root.exists()


@pytest.mark.parametrize("fail_update", [False, True])
def test_mocked_lifecycle_sequence_and_safe_receipts(
    sandbox: Any,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    fail_update: bool,
) -> None:
    options, paths = sandbox
    monkeypatch.setenv("TMPDIR", "/untrusted/unit-only-temp")
    calls: list[tuple[tuple[str, ...], dict[str, Any]]] = []
    health_versions: list[str] = []
    tls_events: list[str] = []
    installed = False
    active = False
    version = "0.1.1"

    @contextmanager
    def fixture_server(_: probe.ProbeOptions) -> Iterator[None]:
        tls_events.append("start")
        try:
            yield
        finally:
            tls_events.append("stop")

    def activate(target: str) -> None:
        nonlocal version
        version = target
        release = paths.release_root / "releases" / target
        release.mkdir(parents=True, exist_ok=True)
        current = paths.release_root / "current"
        if current.is_symlink():
            current.unlink()
        current.symlink_to(f"releases/{target}")

    def command(argv: Any, **kwargs: Any) -> bytes:
        nonlocal installed, active
        argv = tuple(argv)
        calls.append((argv, kwargs))
        if argv[0] == "systemctl":
            if "--value" in argv:
                return b"not-found\n"
            if "is-enabled" in argv:
                return b"enabled\n" if active else b"not-found\n"
            return (
                b"ActiveState=active\nMainPID=123\nLoadState=loaded\n"
                if active
                else b"ActiveState=inactive\nMainPID=0\nLoadState=not-found\n"
            )
        if argv[0] == "sh":
            installed = True
            activate("0.1.1")
            paths.cli.parent.mkdir(parents=True)
            paths.cli.write_bytes(b"mock executable")
            assert (
                kwargs["environment"]["XFERRY_RELEASE_BASE_URL"]
                == "https://127.0.0.1:44443/releases/download/v0.1.1"
            )
            assert kwargs["environment"]["CURL_CA_BUNDLE"] == str(options.tls_dir / "server.crt")
            assert kwargs["environment"]["TMPDIR"] == "/var/tmp"
            return b"installed"
        assert installed
        if argv[1] == "--version":
            return f"xferry {version}\n".encode()
        if argv[1] == "setup":
            assert argv[2:] == ("--private", "--json")
            assert kwargs["discard_stderr"] is True
            assert "environment" not in kwargs
            _create_private_state(paths)
            paths.unit.parent.mkdir(parents=True)
            paths.unit.write_bytes(b"unmodified mock service")
            active = True
            return json.dumps(
                {"status": "ok", "exit_code": 0, "url": "http://127.0.0.1:8080"}
            ).encode()
        if argv[1] == "doctor":
            assert argv[2:] == ("--deep", "--json")
            assert "environment" not in kwargs
            result = dict.fromkeys(probe._DOCTOR_FIELDS, "unemitted diagnostic")
            result.update(
                status="ok",
                exit_code=0,
                code="doctor-ok",
                checks={
                    key: {"status": value, "detail": "unemitted sensitive diagnostic"}
                    for key, value in probe._DOCTOR_STATUSES.items()
                },
            )
            return json.dumps(result).encode()
        result = dict.fromkeys(probe._RELEASE_FIELDS)
        result.update(
            status="ok",
            exit_code=0,
            detail="unemitted sensitive detail",
            message="unemitted message",
            next_actions=[],
            dry_run=False,
            rollback="not_attempted",
        )
        if argv[1] == "update":
            dry_run = "--dry-run" in argv
            assert kwargs["environment"]["SSL_CERT_FILE"] == str(options.tls_dir / "server.crt")
            assert kwargs["environment"]["TMPDIR"] == (
                "/untrusted/unit-only-temp" if "--dry-run" in argv else "/var/tmp"
            )
            if not dry_run and fail_update:
                raise RuntimeError("Credentials: admin:unit-test-sensitive%value")
            if not dry_run:
                activate("0.1.2")
            result.update(
                code="update_dry_run" if dry_run else "update_complete",
                dry_run=dry_run,
                before="0.1.1",
                target="0.1.2",
                version="0.1.2",
                active=version,
                rollback="not_needed",
            )
        elif argv[1] == "rollback":
            assert "environment" not in kwargs
            assert argv[2:] == ("--to", "0.1.1", "--json")
            activate("0.1.1")
            result.update(code="rollback_complete", version="0.1.1")
        elif argv[1] == "uninstall":
            assert "environment" not in kwargs
            assert argv[2:] == ("--json",)
            shutil.rmtree(paths.release_root)
            paths.unit.unlink()
            paths.cli.unlink()
            active = False
            result.update(code="uninstall_complete")
        else:
            raise AssertionError("unexpected command in mocked lifecycle")
        return json.dumps(result).encode()

    monkeypatch.setattr(probe, "_command", command)
    monkeypatch.setattr(probe, "serve_fixtures", fixture_server)
    monkeypatch.setattr(probe, "verify_health", lambda v, p: health_versions.append(v))
    monkeypatch.setattr(probe, "_listener_gone", lambda: True)

    result = probe.run_probe(options, paths)

    assert result["status"] == ("failed" if fail_update else "passed")
    assert tls_events == ["start", "stop"]
    assert capsys.readouterr() == ("", "")
    evidence_text = options.evidence.read_text()
    for banned in ("Credentials:", "unit-test-sensitive", "unemitted", "Authorization:"):
        assert banned not in evidence_text
    assert json.loads(evidence_text) == result
    phases = [stage["phase"] for stage in result["stages"]]
    assert phases == ["guard", "install", "setup", "doctor", "dry_run", "update"] + (
        [] if fail_update else ["rollback", "uninstall"]
    )
    cli_actions = [
        argv[1] for argv, _ in calls if argv[0] == str(paths.cli) and argv[1] != "--version"
    ]
    assert cli_actions == ["setup", "doctor", "update", "update"] + (
        [] if fail_update else ["rollback", "uninstall"]
    )
    assert health_versions == ["0.1.1", "0.1.1", "0.1.1"] + (
        [] if fail_update else ["0.1.2", "0.1.1"]
    )
    if fail_update:
        assert result["failure"] == {"phase": "update", "code": "command_json_invalid"}
    else:
        assert all(stage["status"] == "passed" for stage in result["stages"])
        for stage in result["stages"][4:]:
            assert stage["preserved"] == {"config": True, "auth": True, "sentinel": True}
        final = result["stages"][-1]
        assert final["service"] == {
            "active": False,
            "main_pid": 0,
            "enabled": False,
            "load_state": "not-found",
            "listener_gone": True,
        }
        assert paths.auth.read_text() == "admin:unit-test-sensitive%value\n"
        assert paths.sentinel.is_file()
