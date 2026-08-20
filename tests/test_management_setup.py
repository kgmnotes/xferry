"""Transactional managed setup, credentials, and authenticated health tests."""

from __future__ import annotations

import base64
import builtins
import hashlib
import json
import logging
import os
import socket
import stat
import subprocess
import sys
import threading
from collections.abc import Callable, Mapping, Sequence
from dataclasses import replace
from pathlib import Path, PosixPath

import pytest

from xferry.management import managed_state
from xferry.management.cli import main
from xferry.management.health import HealthEndpoint, HealthResult, authenticated_ping
from xferry.management.managed_state import has_unsupported_managed_state
from xferry.management.model import (
    HostFacts,
    ManagedLayout,
    PreflightFailure,
    ResourcePlan,
    SetupMode,
    SetupPlan,
    SetupPreflight,
    SetupProbes,
)
from xferry.management.planning import check_setup_preflight, render_managed_config
from xferry.management.setup import (
    CredentialsContext,
    SetupExecutor,
    default_setup_preflight,
    generate_password,
    preflight_result,
    reset_credentials,
    ufw_is_active,
)
from xferry.management.system import (
    CommandResult,
    FilesystemTransaction,
    MutationError,
    MutationLocked,
    managed_mutation,
)

APPROVED_PASSWORD_ALPHABET = frozenset("abcdefghjkmnpqrstuvwxyz23456789")
UNSUPPORTED_MANAGED_STATE_INSTRUCTION_CLAUSES = (
    (
        "Unsupported or ambiguous XFerry managed state was detected and preserved; "
        "no changes were made."
    ),
    "Back up the existing XFerry configuration and data.",
    "Remove the managed state with its original tooling.",
    "Then install XFerry in a clean environment.",
)


class _LexicalEvidencePath(PosixPath):
    __slots__ = ("_lexical_evidence",)

    def __new__(
        cls,
        path: Path,
        lexical_evidence: tuple[str, ...] | None = None,
    ) -> _LexicalEvidencePath:
        return super().__new__(cls, path)

    def __init__(
        self,
        path: Path,
        lexical_evidence: tuple[str, ...] | None = None,
    ) -> None:
        if PosixPath.__init__ is not object.__init__:
            super().__init__(path)
        self._lexical_evidence = lexical_evidence

    @property
    def parts(self) -> tuple[str, ...]:
        evidence = getattr(self, "_lexical_evidence", None)
        if evidence is not None:
            return evidence
        return super().parts


def _facts() -> HostFacts:
    return HostFacts(
        os_id="ubuntu",
        os_version="24.04",
        machine="x86_64",
        has_systemd=True,
        ram_mib=2048,
        cpu_count=2,
        disk_free_mib=8192,
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


def test_managed_layout_keeps_runtime_home_and_acme_below_data_root(tmp_path: Path) -> None:
    """Moving managed ACME state back under /home breaks ProtectHome=true at runtime."""
    layout = _layout(tmp_path)

    assert layout.runtime_home == tmp_path / "var/lib/xferry"
    assert layout.acme_root == tmp_path / "var/lib/xferry/.xferry"


def test_managed_setup_config_uses_the_canonical_root_dir_key(tmp_path: Path) -> None:
    """Keeping the removed ``dir`` alias would emit an invalid managed config."""
    rendered = render_managed_config(_plan(tmp_path))

    assert f"root_dir = {tmp_path / 'var/lib/xferry'}\n" in rendered
    assert "\ndir = " not in rendered


def _plan(
    tmp_path: Path,
    *,
    mode: SetupMode = SetupMode.PRIVATE,
    firewall_action: str | None = None,
) -> SetupPlan:
    public = mode is not SetupMode.PRIVATE
    return SetupPlan(
        layout=_layout(tmp_path),
        facts=_facts(),
        resources=ResourcePlan(
            body_budget_mib=256,
            max_upload_mib=100,
            workers=6,
            reserve_mib=512,
            upload_storage_mib=4096,
        ),
        mode=mode,
        bind_host="0.0.0.0" if public else "127.0.0.1",
        port=443 if public else 8080,
        acme_port=80 if public else None,
        domain="8-8-8-8.sslip.io" if public else None,
        public_ip="8.8.8.8" if public else None,
        email=None,
        firewall_answer=True if firewall_action else None,
        firewall_action="allow" if firewall_action else None,
        firewall_ports=(443, 80) if firewall_action else (),
    )


def _ok_preflight(plan: SetupPlan) -> SetupPreflight:
    ports = (plan.port,) + ((plan.acme_port,) if plan.acme_port is not None else ())
    return SetupPreflight(
        executable_ready=True,
        required_bind_ports=ports,
        unavailable_bind_ports=(),
        ufw_active=False,
    )


def _seed_release(
    layout: ManagedLayout,
    version: str,
    *,
    current: bool = False,
    manifest_version: str | None = None,
) -> Path:
    payload = f"xferry-{version}".encode()
    release = layout.release_root / "releases" / version
    release.mkdir(parents=True)
    layout.release_root.parent.chmod(0o755)
    layout.release_root.chmod(0o755)
    release.parent.chmod(0o755)
    release.chmod(0o755)
    executable = release / "xferry"
    executable.write_bytes(payload)
    executable.chmod(0o755)
    described_version = manifest_version or version
    manifest = release / "xferry-release.json"
    manifest.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "version": described_version,
                "tag": f"v{described_version}",
                "platform": "linux-x86_64",
                "executable": {
                    "name": f"xferry-{described_version}-linux-x86_64",
                    "size": len(payload),
                    "sha256": hashlib.sha256(payload).hexdigest(),
                },
            }
        )
        + "\n",
        encoding="utf-8",
    )
    manifest.chmod(0o644)
    if current:
        layout.release_root.joinpath("current").symlink_to(Path("releases") / version)
    return release


def _seed_owned_entry(layout: ManagedLayout, owned_path: str) -> Path:
    path = getattr(layout, owned_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    layout_base = layout.release_root.parents[1]
    directory = path.parent
    while True:
        directory.chmod(0o755)
        if directory == layout_base:
            break
        directory = directory.parent
    if owned_path == "data_root":
        path.mkdir()
    elif owned_path == "cli_link":
        path.symlink_to("/opt/xferry/current/xferry")
    else:
        path.write_text(f"managed {owned_path}\n", encoding="utf-8")
    return path


def _replace_owned_entry(path: Path, owned_path: str) -> None:
    checked = path.with_name(f"{path.name}.checked")
    path.rename(checked)
    if owned_path == "data_root":
        path.mkdir()
    elif owned_path == "cli_link":
        path.symlink_to("/untrusted/xferry")
    else:
        path.write_text("replacement\n", encoding="utf-8")


def _classify_in_bounded_subprocess(
    layout: ManagedLayout,
    *,
    timeout: float,
) -> subprocess.CompletedProcess[str]:
    script = """
import sys
from pathlib import Path
from xferry.management.managed_state import has_unsupported_managed_state
from xferry.management.model import ManagedLayout

paths = [Path(value) for value in sys.argv[1:]]
layout = ManagedLayout(*paths)
print(has_unsupported_managed_state(layout))
"""
    return subprocess.run(  # noqa: S603
        [
            sys.executable,
            "-c",
            script,
            str(layout.release_root),
            str(layout.config_file),
            str(layout.auth_file),
            str(layout.data_root),
            str(layout.lock_file),
            str(layout.unit_file),
            str(layout.cli_link),
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


class FakeRunner:
    """Stateful fake for root account, systemd, and UFW process boundaries."""

    def __init__(
        self,
        *,
        fail_at: str | None = None,
        group_exists: bool = True,
        user_exists: bool = True,
        enabled: bool = False,
        active: bool = False,
        ufw_active: bool = False,
        ufw_rules: set[int] | None = None,
        fail_restore: str | None = None,
        service_present: bool = True,
        service_probe_failures: set[int] | None = None,
        ufw_status_returncode: int = 0,
        ufw_absent: bool = False,
        localized_ufw_without_c_locale: bool = False,
    ) -> None:
        self.fail_at = fail_at
        self.start_failures_remaining = 1 if fail_at == "start" else 0
        self.reload_failures_remaining = 1 if fail_at == "reload" else 0
        self.group_exists = group_exists
        self.user_exists = user_exists
        self.enabled = enabled
        self.active = active
        self.ufw_active = ufw_active
        self.ufw_rules = set(ufw_rules or set())
        self.fail_restore = fail_restore
        self.service_present = service_present
        self.service_probe_failures = set(service_probe_failures or set())
        self.service_probe_count = 0
        self.ufw_status_returncode = ufw_status_returncode
        self.ufw_absent = ufw_absent
        self.localized_ufw_without_c_locale = localized_ufw_without_c_locale
        self.commands: list[tuple[str, ...]] = []
        self.command_environments: list[Mapping[str, str] | None] = []

    def run(
        self,
        argv: Sequence[str],
        *,
        env: Mapping[str, str] | None = None,
    ) -> CommandResult:
        command = tuple(str(item) for item in argv)
        self.commands.append(command)
        self.command_environments.append(env)
        if command[:2] == ("getent", "group"):
            return self._result(command, 0 if self.group_exists else 2)
        if command[:2] == ("id", "-u"):
            return self._result(command, 0 if self.user_exists else 1)
        if command and command[0] == "groupadd":
            if self.fail_at == "identity":
                return self._result(command, 1)
            self.group_exists = True
            return self._result(command)
        if command and command[0] == "useradd":
            if self.fail_at == "identity":
                return self._result(command, 1)
            self.user_exists = True
            return self._result(command)
        if command[:1] == ("userdel",):
            self.user_exists = False
            return self._result(command)
        if command[:1] == ("groupdel",):
            self.group_exists = False
            return self._result(command)
        if command[:2] == ("systemctl", "is-enabled"):
            return self._result(command, 0 if self.enabled else 1)
        if command[:2] == ("systemctl", "is-active"):
            return self._result(command, 0 if self.active else 3)
        if command == (
            "systemctl",
            "show",
            "--property=LoadState",
            "--property=UnitFileState",
            "--property=ActiveState",
            "xferry.service",
        ):
            self.service_probe_count += 1
            if self.service_probe_count in self.service_probe_failures:
                return self._result(command, 1, stderr="systemd probe failed")
            if not self.service_present:
                return self._result(
                    command,
                    stdout="LoadState=not-found\nUnitFileState=\nActiveState=inactive\n",
                )
            return self._result(
                command,
                stdout=(
                    "LoadState=loaded\n"
                    f"UnitFileState={'enabled' if self.enabled else 'disabled'}\n"
                    f"ActiveState={'active' if self.active else 'inactive'}\n"
                ),
            )
        if command[:2] == ("systemctl", "daemon-reload"):
            if self.reload_failures_remaining:
                self.reload_failures_remaining -= 1
                return self._result(command, 1)
            return self._result(command)
        if command[:2] == ("systemctl", "enable"):
            self.enabled = True
            return self._result(command)
        if command[:2] == ("systemctl", "disable"):
            if self.fail_restore == "disable":
                return self._result(command, 1)
            self.enabled = False
            return self._result(command)
        if command[:2] == ("systemctl", "start"):
            if self.start_failures_remaining:
                self.start_failures_remaining -= 1
                return self._result(command, 1)
            self.active = True
            return self._result(command)
        if command[:2] == ("systemctl", "restart"):
            if self.start_failures_remaining:
                self.start_failures_remaining -= 1
                return self._result(command, 1)
            self.active = True
            return self._result(command)
        if command[:2] == ("systemctl", "stop"):
            if self.fail_restore == "stop":
                return self._result(command, 1)
            self.active = False
            return self._result(command)
        if command[:2] == ("ufw", "status"):
            if self.ufw_absent:
                return CommandResult(command, 127, not_found=True)
            if self.ufw_status_returncode:
                return self._result(command, self.ufw_status_returncode, stderr="ufw failed")
            stable_c = env is not None and env.get("LC_ALL") == "C" and env.get("LANG") == "C"
            if self.localized_ufw_without_c_locale and not stable_c:
                status = "Состояние: активно\n" if self.ufw_active else "Состояние: неактивно\n"
            else:
                status = "Status: active\n" if self.ufw_active else "Status: inactive\n"
            for port in sorted(self.ufw_rules):
                status += f"{port}/tcp ALLOW Anywhere\n"
            return self._result(command, stdout=status)
        if len(command) == 3 and command[:2] == ("ufw", "allow"):
            port = int(command[2].removesuffix("/tcp"))
            if self.fail_at == f"ufw-{port}":
                return self._result(command, 1)
            self.ufw_rules.add(port)
            return self._result(command)
        if len(command) == 5 and command[:4] == ("ufw", "--force", "delete", "allow"):
            if self.fail_restore == "ufw-delete":
                return self._result(command, 1)
            if self.fail_restore == "ufw-delete-noop":
                return self._result(command)
            self.ufw_rules.discard(int(command[4].removesuffix("/tcp")))
            return self._result(command)
        if command and command[-1] == "--check-config":
            return self._result(command, 1 if self.fail_at == "config" else 0)
        return self._result(command)

    @staticmethod
    def _result(
        argv: tuple[str, ...],
        returncode: int = 0,
        *,
        stdout: str = "",
        stderr: str = "",
    ) -> CommandResult:
        return CommandResult(argv=argv, returncode=returncode, stdout=stdout, stderr=stderr)


class FakeClock:
    """Deterministic monotonic clock advanced only by the injected sleeper."""

    def __init__(self) -> None:
        self.now = 0.0
        self.sleeps: list[float] = []

    def monotonic(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now += seconds


def _executor(
    tmp_path: Path,
    runner: FakeRunner,
    *,
    health: Callable[[HealthEndpoint, str, str, float], HealthResult] | None = None,
    preflight: Callable[[SetupPlan], SetupPreflight] = _ok_preflight,
) -> SetupExecutor:
    current_uid = os.getuid()
    current_gid = os.getgid()
    clock = FakeClock()
    return SetupExecutor(
        runner=runner,
        preflight_check=preflight,
        health_check=health or (lambda *_args: HealthResult(ok=True, detail="healthy")),
        effective_uid=lambda: 0,
        root_uid=current_uid,
        resolve_identity=lambda: (current_uid, current_gid),
        chown=lambda _path, _uid, _gid: None,
        unit_path=tmp_path / "etc/systemd/system/xferry.service",
        acme_root=tmp_path / "var/lib/xferry/.xferry",
        readiness_timeout=120.0,
        monotonic=clock.monotonic,
        sleep=clock.sleep,
    )


def _seed_managed_state(tmp_path: Path) -> dict[Path, tuple[bytes, int]]:
    paths = {
        tmp_path / "etc/xferry/xferry.ini": (b"original config\n", 0o600),
        tmp_path / "etc/xferry/auth": (b"admin:originalpass\n", 0o400),
        tmp_path / "etc/systemd/system/xferry.service": (b"original unit\n", 0o644),
    }
    for path, (content, mode) in paths.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        path.chmod(mode)
    return paths


def _assert_seed_restored(seed: dict[Path, tuple[bytes, int]]) -> None:
    for path, (content, mode) in seed.items():
        assert path.read_bytes() == content
        assert stat.S_IMODE(path.stat().st_mode) == mode


def test_generated_password_has_exact_length_and_approved_alphabet() -> None:
    """Changing password length or admitting ambiguous characters weakens the contract."""
    generated = {generate_password() for _ in range(100)}

    assert len(generated) > 1
    assert all(len(password) == 12 for password in generated)
    assert all(set(password) <= APPROVED_PASSWORD_ALPHABET for password in generated)


def _authenticated_ping_for_response(response: bytes) -> tuple[HealthResult, bytes]:
    """Exercise the real socket exchange against one controlled HTTP response."""
    received = bytearray()
    ready = threading.Event()
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = int(listener.getsockname()[1])

    def serve_once() -> None:
        ready.set()
        connection, _address = listener.accept()
        with connection:
            while b"\r\n\r\n" not in received:
                received.extend(connection.recv(4096))
            connection.sendall(response)
        listener.close()

    server = threading.Thread(target=serve_once)
    server.start()
    assert ready.wait(timeout=1)
    result = authenticated_ping(
        HealthEndpoint(
            connect_host="127.0.0.1",
            port=port,
            host="BÜCHER.Example.",
            tls=False,
        ),
        "admin",
        "safehealth42",
        1,
    )
    server.join(timeout=1)
    return result, bytes(received)


def test_authenticated_ping_uses_basic_auth_and_requires_ready_json() -> None:
    """Catches health readiness falling back to an obsolete pong response header."""
    password = "safehealth42"
    body = b'{"health":"ready"}'
    result, received = _authenticated_ping_for_response(
        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: "
        + str(len(body)).encode()
        + b"\r\n\r\n"
        + body
    )

    token = base64.b64encode(f"admin:{password}".encode()).decode()
    assert result.ok is True
    assert result.detail == "healthy"
    assert received.startswith(b"PING / HTTP/1.1\r\nHost: xn--bcher-kva.example\r\n")
    assert f"Authorization: Basic {token}\r\n".encode() in received


@pytest.mark.parametrize(
    "body",
    [
        b'{"health":"degraded"}',
        b"not-json",
        b'{"health":"ready","padding":"' + b"x" * 65537 + b'"}',
    ],
    ids=("non-ready", "malformed", "oversized"),
)
def test_authenticated_ping_rejects_non_ready_malformed_or_oversized_json(body: bytes) -> None:
    """Catches legacy pong headers masking invalid or unbounded PING JSON bodies."""
    result, _received = _authenticated_ping_for_response(
        b"HTTP/1.1 200 OK\r\nX-Ping-Response: pong\r\nContent-Type: application/json\r\n"
        b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body
    )

    assert result == HealthResult(ok=False, detail="invalid health response")


@pytest.mark.parametrize(
    ("content_length", "body"),
    [
        ("65537", b'{"health":"ready"}'),
        ("-1", b'{"health":"ready"}'),
        ("invalid", b'{"health":"ready"}'),
        ("19", b'{"health":"ready"}'),
    ],
    ids=("over-limit", "negative", "invalid", "truncated"),
)
def test_authenticated_ping_rejects_invalid_or_incomplete_declared_json_body(
    content_length: str,
    body: bytes,
) -> None:
    """Catches declared PING framing being ignored after a ready JSON prefix."""
    result, _received = _authenticated_ping_for_response(
        b"HTTP/1.1 200 OK\r\nContent-Length: " + content_length.encode() + b"\r\n\r\n" + body
    )

    assert result == HealthResult(ok=False, detail="invalid health response")


def test_authenticated_ping_accepts_bounded_ready_json_without_content_length() -> None:
    """Catches no-length PING responses becoming invalid while preserving bounded reads."""
    result, _received = _authenticated_ping_for_response(
        b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{"health":"ready"}'
    )

    assert result == HealthResult(ok=True, detail="healthy")


def test_authenticated_ping_rejects_oversized_ready_json_without_content_length() -> None:
    """Catches no-length PING reads exceeding the same bounded body limit."""
    body = b'{"health":"ready","padding":"' + b"x" * 65537 + b'"}'
    result, _received = _authenticated_ping_for_response(b"HTTP/1.1 200 OK\r\n\r\n" + body)

    assert result == HealthResult(ok=False, detail="invalid health response")


@pytest.mark.parametrize(
    "host",
    ["health.example\r\nX-Injected: yes", "health.\x00example", "-bad.example", "bad..example"],
)
def test_authenticated_ping_rejects_unsafe_host_before_connecting(host: str) -> None:
    """Controls or invalid labels must never reach the HTTP Host header or socket boundary."""
    result = authenticated_ping(
        HealthEndpoint("127.0.0.1", 1, host, tls=False),
        "admin",
        "safehealth42",
        0.05,
    )

    assert result == HealthResult(ok=False, detail="invalid health endpoint")


def test_authenticated_ping_failure_does_not_reveal_password(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Including request material in health errors or logs would disclose the password."""
    password = "dontprintme2"
    with caplog.at_level(logging.DEBUG, logger="xferry"):
        result = authenticated_ping(
            HealthEndpoint("127.0.0.1", 1, "health.example", tls=False),
            "admin",
            password,
            0.05,
        )

    assert result.ok is False
    assert password not in result.detail
    assert password not in repr(result)
    assert password not in caplog.text


def test_setup_writes_atomic_strict_files_and_keeps_secret_out_of_processes(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Loose auth mode or a subprocess credential argument would expose new credentials."""
    runner = FakeRunner()
    plan = _plan(tmp_path)

    with caplog.at_level(logging.DEBUG, logger="xferry"):
        result = _executor(tmp_path, runner).apply(plan)

    assert result.exit_code == 0
    assert result.credentials is not None
    password = result.credentials.password
    assert plan.layout.auth_file.read_text(encoding="utf-8") == f"admin:{password}\n"
    assert stat.S_IMODE(plan.layout.auth_file.stat().st_mode) == 0o400
    assert stat.S_IMODE(plan.layout.config_file.stat().st_mode) == 0o640
    unit_path = tmp_path / "etc/systemd/system/xferry.service"
    assert stat.S_IMODE(unit_path.stat().st_mode) == 0o644
    assert not list(tmp_path.rglob(".xferry-*.tmp"))
    assert all(password not in " ".join(command) for command in runner.commands)
    captured = capsys.readouterr()
    assert password not in captured.out + captured.err + caplog.text
    assert password not in repr(result)


def test_setup_runs_the_current_executable_with_canonical_run_for_validation(
    tmp_path: Path,
) -> None:
    """Using the legacy venv path or omitting run would validate a different deployment."""
    runner = FakeRunner()
    plan = _plan(tmp_path)

    result = _executor(tmp_path, runner).apply(plan)

    assert result.exit_code == 0
    assert (
        str(plan.layout.current_executable),
        "run",
        "--config",
        str(plan.layout.config_file),
        "--check-config",
    ) in runner.commands


def test_setup_readiness_waits_past_the_old_attempt_window_without_real_sleep(
    tmp_path: Path,
) -> None:
    """A normal delayed ACME first bind must not fail after the former 4.75-second window."""
    runner = FakeRunner()
    clock = FakeClock()
    calls = 0

    def delayed_health(*_args: object) -> HealthResult:
        nonlocal calls
        calls += 1
        if calls < 26:
            return HealthResult(False, "connection failed")
        return HealthResult(True, "healthy")

    current_uid = os.getuid()
    executor = SetupExecutor(
        runner=runner,
        preflight_check=_ok_preflight,
        health_check=delayed_health,
        effective_uid=lambda: 0,
        root_uid=current_uid,
        resolve_identity=lambda: (current_uid, os.getgid()),
        chown=lambda _path, _uid, _gid: None,
        unit_path=tmp_path / "etc/systemd/system/xferry.service",
        readiness_timeout=120.0,
        monotonic=clock.monotonic,
        sleep=clock.sleep,
    )

    result = executor.apply(_plan(tmp_path, mode=SetupMode.SSLIP))

    assert result.exit_code == 0
    assert calls == 26
    assert clock.now > 4.75
    assert max(clock.sleeps) <= 2.0


def test_public_setup_unbound_until_readiness_deadline_maps_to_network_exit(
    tmp_path: Path,
) -> None:
    """A public ACME process that never binds is a network/ACME failure, not exit 6."""
    clock = FakeClock()
    runner = FakeRunner()
    current_uid = os.getuid()
    executor = SetupExecutor(
        runner=runner,
        preflight_check=_ok_preflight,
        health_check=lambda *_args: HealthResult(False, "connection failed"),
        effective_uid=lambda: 0,
        root_uid=current_uid,
        resolve_identity=lambda: (current_uid, os.getgid()),
        chown=lambda _path, _uid, _gid: None,
        unit_path=tmp_path / "etc/systemd/system/xferry.service",
        readiness_timeout=1.0,
        monotonic=clock.monotonic,
        sleep=clock.sleep,
    )

    result = executor.apply(_plan(tmp_path, mode=SetupMode.SSLIP))

    assert result.exit_code == 5
    assert result.credentials is None
    assert clock.now >= 120.0
    assert max(clock.sleeps) <= 2.0


def test_public_setup_bound_but_unhealthy_at_deadline_maps_to_unhealthy_exit(
    tmp_path: Path,
) -> None:
    """A responding candidate with an invalid PING remains a genuine unhealthy service."""
    clock = FakeClock()
    runner = FakeRunner()
    current_uid = os.getuid()
    executor = SetupExecutor(
        runner=runner,
        preflight_check=_ok_preflight,
        health_check=lambda *_args: HealthResult(False, "invalid health response"),
        effective_uid=lambda: 0,
        root_uid=current_uid,
        resolve_identity=lambda: (current_uid, os.getgid()),
        chown=lambda _path, _uid, _gid: None,
        unit_path=tmp_path / "etc/systemd/system/xferry.service",
        readiness_timeout=120.0,
        monotonic=clock.monotonic,
        sleep=clock.sleep,
    )

    result = executor.apply(_plan(tmp_path, mode=SetupMode.SSLIP))

    assert result.exit_code == 6
    assert result.credentials is None
    assert clock.now >= 120.0


def test_setup_creates_the_managed_runtime_home_used_by_the_systemd_sandbox(
    tmp_path: Path,
) -> None:
    """A hidden /home runtime state directory is inaccessible with ProtectHome=true."""
    runner = FakeRunner(group_exists=False, user_exists=False)
    plan = _plan(tmp_path)
    current_uid = os.getuid()
    current_gid = os.getgid()
    executor = SetupExecutor(
        runner=runner,
        preflight_check=_ok_preflight,
        health_check=lambda *_args: HealthResult(ok=True, detail="healthy"),
        effective_uid=lambda: 0,
        root_uid=current_uid,
        resolve_identity=lambda: (current_uid, current_gid),
        chown=lambda _path, _uid, _gid: None,
        unit_path=tmp_path / "etc/systemd/system/xferry.service",
        acme_root=None,
        sleep=lambda _seconds: None,
    )

    result = executor.apply(plan)

    assert result.exit_code == 0
    assert plan.layout.acme_root.is_dir()
    useradd = next(command for command in runner.commands if command[0] == "useradd")
    assert useradd[useradd.index("--home-dir") + 1] == str(plan.layout.runtime_home)


def test_setup_requires_root_before_opening_the_mutation_lock(tmp_path: Path) -> None:
    """Host probes or managed state before the privilege gate violate the setup boundary."""
    runner = FakeRunner()

    def forbidden_preflight(_plan: SetupPlan) -> SetupPreflight:
        pytest.fail("non-root setup must not run preflight probes")

    executor = SetupExecutor(
        runner=runner,
        preflight_check=forbidden_preflight,
        health_check=lambda *_args: HealthResult(ok=True, detail="healthy"),
        effective_uid=lambda: 1000,
        unit_path=tmp_path / "unit",
        acme_root=tmp_path / "acme",
    )

    result = executor.apply(_plan(tmp_path))

    assert result.exit_code == 3
    assert runner.commands == []
    assert not (tmp_path / "run/lock/xferry-ops.lock").exists()
    assert not (tmp_path / "etc/xferry").exists()


def test_failed_preflight_never_enters_root_or_mutation_boundary(tmp_path: Path) -> None:
    """An unsupported host must fail before root checks, lock creation, or managed writes."""
    runner = FakeRunner()
    calls = 0

    def failed_preflight(_plan: SetupPlan) -> SetupPreflight:
        nonlocal calls
        calls += 1
        return SetupPreflight(
            executable_ready=True,
            required_bind_ports=(8080,),
            unavailable_bind_ports=(),
            ufw_active=False,
            failures=(PreflightFailure("unsupported-platform", "unsupported"),),
        )

    executor = _executor(tmp_path, runner, preflight=failed_preflight)
    result = executor.apply(_plan(tmp_path))

    assert result.exit_code == 4
    assert calls == 1
    assert runner.commands == []
    assert not (tmp_path / "run/lock/xferry-ops.lock").exists()


def test_default_setup_guard_blocks_unsupported_managed_config_before_any_mutation(
    tmp_path: Path,
) -> None:
    """Ambiguous config without a verified release marker must stop before mutation."""
    plan = _plan(tmp_path)
    plan.layout.config_file.parent.mkdir(parents=True)
    original = b"[server]\ndir = /unsupported-data\n"
    plan.layout.config_file.write_bytes(original)
    runner = FakeRunner(ufw_active=True)
    current_uid = os.getuid()
    current_gid = os.getgid()
    executor = SetupExecutor(
        runner=runner,
        health_check=lambda *_args: HealthResult(ok=True, detail="healthy"),
        effective_uid=lambda: 0,
        root_uid=current_uid,
        resolve_identity=lambda: (current_uid, current_gid),
        chown=lambda _path, _uid, _gid: None,
        unit_path=tmp_path / "etc/systemd/system/xferry.service",
        acme_root=tmp_path / "var/lib/xferry/.xferry",
        sleep=lambda _seconds: None,
    )

    result = executor.apply(plan)

    assert result.exit_code == 1
    assert all(clause in result.message for clause in UNSUPPORTED_MANAGED_STATE_INSTRUCTION_CLAUSES)
    assert result.credentials is None
    assert runner.commands == []
    assert plan.layout.config_file.read_bytes() == original
    assert not plan.layout.lock_file.exists()
    assert not plan.layout.release_root.exists()
    assert not plan.layout.auth_file.exists()
    assert not plan.layout.data_root.exists()
    assert not plan.layout.unit_file.exists()
    assert not plan.layout.cli_link.exists()


def test_setup_guard_preserves_a_symlinked_managed_parent_without_any_effect(
    tmp_path: Path,
) -> None:
    plan = _plan(tmp_path)
    _seed_release(plan.layout, "0.1.0", current=True)
    outside = tmp_path / "outside-config"
    outside.mkdir()
    outside_config = outside / "xferry.ini"
    outside_auth = outside / "auth"
    config_bytes = b"[server]\nroot_dir = /outside\n"
    auth_bytes = b"admin:outside\n"
    outside_config.write_bytes(config_bytes)
    outside_auth.write_bytes(auth_bytes)
    plan.layout.config_file.parent.parent.mkdir(parents=True)
    plan.layout.config_file.parent.symlink_to(outside, target_is_directory=True)
    runner = FakeRunner(ufw_active=True)
    current_uid = os.getuid()
    current_gid = os.getgid()

    def guarded_preflight(candidate: SetupPlan) -> SetupPreflight:
        return check_setup_preflight(
            candidate,
            SetupProbes(
                executable_is_ready=lambda _path: True,
                port_is_available=lambda _host, _port: True,
                ufw_is_active=lambda: False,
                unsupported_managed_state_detected=has_unsupported_managed_state,
            ),
        )

    executor = SetupExecutor(
        runner=runner,
        preflight_check=guarded_preflight,
        health_check=lambda *_args: HealthResult(ok=True, detail="healthy"),
        effective_uid=lambda: 0,
        root_uid=current_uid,
        resolve_identity=lambda: (current_uid, current_gid),
        chown=lambda _path, _uid, _gid: None,
        unit_path=plan.layout.unit_file,
        acme_root=plan.layout.acme_root,
        sleep=lambda _seconds: None,
    )

    result = executor.apply(plan)

    assert result.exit_code == 1
    assert all(clause in result.message for clause in UNSUPPORTED_MANAGED_STATE_INSTRUCTION_CLAUSES)
    assert result.credentials is None
    assert runner.commands == []
    assert plan.layout.config_file.parent.is_symlink()
    assert outside_config.read_bytes() == config_bytes
    assert outside_auth.read_bytes() == auth_bytes
    assert not plan.layout.lock_file.exists()
    assert not plan.layout.data_root.exists()
    assert not plan.layout.unit_file.exists()
    assert not plan.layout.cli_link.exists()


@pytest.mark.parametrize(
    "owned_path",
    ["config_file", "auth_file", "data_root", "unit_file", "cli_link"],
)
def test_managed_state_classifier_blocks_unmarked_xferry_owned_state(
    tmp_path: Path,
    owned_path: str,
) -> None:
    """Unmarked config, data, unit, or CLI state is ambiguous and must be preserved."""
    layout = _layout(tmp_path)
    path = getattr(layout, owned_path)
    if owned_path == "data_root":
        path.mkdir(parents=True)
    elif owned_path == "cli_link":
        path.parent.mkdir(parents=True)
        path.symlink_to("/unsupported/xferry")
    else:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("unsupported sentinel\n", encoding="utf-8")

    assert has_unsupported_managed_state(layout) is True


def test_managed_state_classifier_allows_owned_state_with_a_verified_current_release(
    tmp_path: Path,
) -> None:
    """Treating a healthy managed rerun as ambiguous would make setup non-idempotent."""
    layout = _layout(tmp_path)
    _seed_release(layout, "0.1.0", current=True)
    for owned_path in ("config_file", "auth_file", "data_root", "unit_file", "cli_link"):
        _seed_owned_entry(layout, owned_path)

    assert has_unsupported_managed_state(layout) is False


@pytest.mark.parametrize(
    "owned_path",
    ["config_file", "auth_file", "data_root", "unit_file", "cli_link"],
)
def test_managed_state_classifier_accepts_each_owned_entry_with_its_expected_kind(
    tmp_path: Path,
    owned_path: str,
) -> None:
    layout = _layout(tmp_path)
    _seed_release(layout, "0.1.0", current=True)
    _seed_owned_entry(layout, owned_path)

    assert has_unsupported_managed_state(layout) is False


@pytest.mark.parametrize(
    "owned_path",
    ["config_file", "auth_file", "data_root", "unit_file", "cli_link"],
)
def test_managed_state_classifier_blocks_an_owned_leaf_replaced_after_its_snapshot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    owned_path: str,
) -> None:
    layout = _layout(tmp_path)
    _seed_release(layout, "0.1.0", current=True)
    path = _seed_owned_entry(layout, owned_path)
    original_inspect = managed_state._inspect_owned_entry
    replaced = False

    def replace_after_snapshot(*args: object, **kwargs: object) -> object:
        nonlocal replaced
        witness = original_inspect(*args, **kwargs)
        if args[0] == path and not replaced:
            _replace_owned_entry(path, owned_path)
            replaced = True
        return witness

    monkeypatch.setattr(managed_state, "_inspect_owned_entry", replace_after_snapshot)

    assert has_unsupported_managed_state(layout) is True
    assert replaced is True


def test_managed_state_classifier_rechecks_earlier_owned_entries_as_one_set(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    layout = _layout(tmp_path)
    _seed_release(layout, "0.1.0", current=True)
    config = _seed_owned_entry(layout, "config_file")
    _seed_owned_entry(layout, "auth_file")
    original_inspect = managed_state._inspect_owned_entry
    replaced = False

    def replace_config_while_inspecting_auth(*args: object, **kwargs: object) -> object:
        nonlocal replaced
        witness = original_inspect(*args, **kwargs)
        if args[0] == layout.auth_file and not replaced:
            _replace_owned_entry(config, "config_file")
            replaced = True
        return witness

    monkeypatch.setattr(
        managed_state,
        "_inspect_owned_entry",
        replace_config_while_inspecting_auth,
    )

    assert has_unsupported_managed_state(layout) is True
    assert replaced is True


@pytest.mark.parametrize(
    "owned_path",
    ["config_file", "data_root", "unit_file", "cli_link"],
)
def test_managed_state_classifier_blocks_an_owned_parent_changed_after_traversal(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    owned_path: str,
) -> None:
    layout = _layout(tmp_path)
    _seed_release(layout, "0.1.0", current=True)
    path = _seed_owned_entry(layout, owned_path)
    original_inspect = managed_state._inspect_owned_entry
    changed = False

    def chmod_after_traversal(*args: object, **kwargs: object) -> object:
        nonlocal changed
        witness = original_inspect(*args, **kwargs)
        if args[0] == path and not changed:
            path.parent.chmod(0o777)
            changed = True
        return witness

    monkeypatch.setattr(managed_state, "_inspect_owned_entry", chmod_after_traversal)

    assert has_unsupported_managed_state(layout) is True
    assert changed is True


def test_managed_state_classifier_rechecks_the_exact_cli_target_after_readlink(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    layout = _layout(tmp_path)
    _seed_release(layout, "0.1.0", current=True)
    cli_link = _seed_owned_entry(layout, "cli_link")
    original_inspect = managed_state._inspect_owned_entry
    changed = False

    def retarget_after_readlink(*args: object, **kwargs: object) -> object:
        nonlocal changed
        witness = original_inspect(*args, **kwargs)
        if args[0] == cli_link and not changed:
            cli_link.unlink()
            cli_link.symlink_to("/untrusted/xferry")
            changed = True
        return witness

    monkeypatch.setattr(managed_state, "_inspect_owned_entry", retarget_after_readlink)

    assert has_unsupported_managed_state(layout) is True
    assert changed is True


@pytest.mark.parametrize(
    "owned_path",
    ["config_file", "auth_file", "data_root", "unit_file", "cli_link"],
)
@pytest.mark.parametrize("mode", [0o775, 0o757])
def test_managed_state_classifier_blocks_writable_owned_parents(
    tmp_path: Path,
    owned_path: str,
    mode: int,
) -> None:
    layout = _layout(tmp_path)
    _seed_release(layout, "0.1.0", current=True)
    path = _seed_owned_entry(layout, owned_path)
    path.parent.chmod(mode)

    assert has_unsupported_managed_state(layout) is True


@pytest.mark.parametrize(
    "owned_path",
    ["config_file", "auth_file", "data_root", "unit_file", "cli_link"],
)
def test_managed_state_classifier_blocks_owned_parents_outside_the_trusted_owner_set(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    owned_path: str,
) -> None:
    layout = _layout(tmp_path)
    _seed_release(layout, "0.1.0", current=True)
    path = _seed_owned_entry(layout, owned_path)
    parent_inode = path.parent.stat().st_ino
    original_owner_check = managed_state._metadata_owner_is_trusted

    def reject_owned_parent(metadata: os.stat_result, effective_uid: int) -> bool:
        if metadata.st_ino == parent_inode:
            return False
        return original_owner_check(metadata, effective_uid)

    monkeypatch.setattr(managed_state, "_metadata_owner_is_trusted", reject_owned_parent)

    assert has_unsupported_managed_state(layout) is True


def test_managed_state_classifier_accepts_secure_absence_below_trusted_parents(
    tmp_path: Path,
) -> None:
    layout = _layout(tmp_path)

    assert has_unsupported_managed_state(layout) is False


def test_managed_state_classifier_accepts_a_missing_release_root_below_a_trusted_parent(
    tmp_path: Path,
) -> None:
    release_parent = tmp_path / "trusted-release-parent"
    release_parent.mkdir(mode=0o755)
    layout = replace(_layout(tmp_path), release_root=release_parent / "xferry")

    assert has_unsupported_managed_state(layout) is False


@pytest.mark.parametrize(
    "layout_path",
    [
        "release_root",
        "config_file",
        "auth_file",
        "data_root",
        "lock_file",
        "unit_file",
        "cli_link",
    ],
)
def test_managed_state_classifier_blocks_dot_dot_in_every_layout_path(
    tmp_path: Path,
    layout_path: str,
) -> None:
    layout = _layout(tmp_path)
    if layout_path != "release_root":
        _seed_release(layout, "0.1.0", current=True)
    trusted_parent = tmp_path / "trusted-data-parent"
    trusted_parent.mkdir(mode=0o755)
    victim = trusted_parent / "victim"
    original = b"preserve victim\n"
    victim.write_bytes(original)
    ambiguous_path = trusted_parent / "missing" / ".." / victim.name
    assert ".." in ambiguous_path.parts
    layout = replace(layout, **{layout_path: ambiguous_path})

    assert has_unsupported_managed_state(layout) is True
    assert not (trusted_parent / "missing").exists()
    assert victim.is_file()
    assert victim.read_bytes() == original


@pytest.mark.parametrize("unsafe_component", ["", "."])
def test_managed_state_classifier_blocks_preserved_unsafe_lexical_components(
    tmp_path: Path,
    unsafe_component: str,
) -> None:
    layout = _layout(tmp_path)
    _seed_release(layout, "0.1.0", current=True)
    victim = tmp_path / "lexical-victim"
    original = b"preserve lexical victim\n"
    victim.write_bytes(original)
    lexical_path = _LexicalEvidencePath(
        victim,
        (*victim.parts[:-1], unsafe_component, victim.name),
    )
    layout = replace(layout, config_file=lexical_path)

    assert has_unsupported_managed_state(layout) is True
    assert victim.read_bytes() == original


def test_managed_state_classifier_blocks_a_missing_release_root_below_a_sticky_parent(
    tmp_path: Path,
) -> None:
    release_root = Path("/tmp") / f"xferry-missing-{os.getpid()}-{tmp_path.name}"
    assert not release_root.exists()
    layout = replace(_layout(tmp_path), release_root=release_root)

    assert has_unsupported_managed_state(layout) is True


def test_managed_state_classifier_blocks_absence_directly_below_a_sticky_directory(
    tmp_path: Path,
) -> None:
    layout = _layout(tmp_path)
    _seed_release(layout, "0.1.0", current=True)
    absent = Path("/tmp") / f"xferry-absent-{os.getpid()}-{tmp_path.name}"
    assert not absent.exists()
    layout = replace(layout, config_file=absent)

    assert has_unsupported_managed_state(layout) is True


def test_managed_state_classifier_blocks_a_missing_suffix_created_after_its_snapshot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    layout = _layout(tmp_path)
    _seed_release(layout, "0.1.0", current=True)
    original_inspect = managed_state._inspect_owned_entry
    created = False

    def create_missing_suffix(*args: object, **kwargs: object) -> object:
        nonlocal created
        witness = original_inspect(*args, **kwargs)
        if args[0] == layout.config_file and not created:
            layout.config_file.parent.mkdir(parents=True)
            created = True
        return witness

    monkeypatch.setattr(managed_state, "_inspect_owned_entry", create_missing_suffix)

    assert has_unsupported_managed_state(layout) is True
    assert created is True


def test_managed_state_classifier_accepts_a_destdir_below_a_sticky_ancestor(
    tmp_path: Path,
) -> None:
    layout = _layout(tmp_path)
    _seed_release(layout, "0.1.0", current=True)
    for owned_path in ("config_file", "auth_file", "data_root", "unit_file", "cli_link"):
        _seed_owned_entry(layout, owned_path)

    assert has_unsupported_managed_state(layout) is False


def test_managed_state_classifier_accepts_a_trusted_existing_entry_below_a_sticky_parent(
    tmp_path: Path,
) -> None:
    layout = _layout(tmp_path)
    _seed_release(layout, "0.1.0", current=True)
    data_root = Path("/tmp") / f"xferry-owned-{os.getpid()}-{tmp_path.name}"
    data_root.mkdir(mode=0o700)
    try:
        assert has_unsupported_managed_state(replace(layout, data_root=data_root)) is False
    finally:
        data_root.rmdir()


def test_managed_state_classifier_blocks_an_untrusted_existing_entry_below_a_sticky_parent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    layout = _layout(tmp_path)
    _seed_release(layout, "0.1.0", current=True)
    data_root = Path("/tmp") / f"xferry-untrusted-{os.getpid()}-{tmp_path.name}"
    data_root.mkdir(mode=0o700)
    data_inode = data_root.stat().st_ino
    original_owner_check = managed_state._metadata_owner_is_trusted

    def reject_data_owner(metadata: os.stat_result, effective_uid: int) -> bool:
        if metadata.st_ino == data_inode:
            return False
        return original_owner_check(metadata, effective_uid)

    monkeypatch.setattr(managed_state, "_metadata_owner_is_trusted", reject_data_owner)
    try:
        assert has_unsupported_managed_state(replace(layout, data_root=data_root)) is True
    finally:
        data_root.rmdir()


def test_managed_state_classifier_blocks_an_ordinary_world_writable_destdir(
    tmp_path: Path,
) -> None:
    destdir = tmp_path / "destdir"
    layout = _layout(destdir)
    _seed_release(layout, "0.1.0", current=True)
    destdir.chmod(0o777)

    assert has_unsupported_managed_state(layout) is True


def test_managed_state_classifier_accepts_simulated_root_owned_state_for_a_non_root_caller(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    layout = _layout(tmp_path)
    _seed_release(layout, "0.1.0", current=True)
    actual_uid = os.geteuid()
    simulated_effective_uid = actual_uid + 1

    def simulate_root_owned_metadata(
        metadata: os.stat_result,
        effective_uid: int,
    ) -> bool:
        simulated_owner = 0 if metadata.st_uid == actual_uid else metadata.st_uid
        return simulated_owner in {0, effective_uid}

    monkeypatch.setattr(managed_state.os, "geteuid", lambda: simulated_effective_uid)
    monkeypatch.setattr(
        managed_state,
        "_metadata_owner_is_trusted",
        simulate_root_owned_metadata,
    )

    assert has_unsupported_managed_state(layout) is False


def test_managed_state_classifier_balances_owned_witness_descriptors_under_stress(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    descriptor_directory = Path("/proc/self/fd")
    if not descriptor_directory.is_dir():
        pytest.skip("descriptor inventory is unavailable")

    valid_layout = _layout(tmp_path / "valid")
    _seed_release(valid_layout, "0.1.0", current=True)
    for owned_path in ("config_file", "auth_file", "data_root", "unit_file", "cli_link"):
        _seed_owned_entry(valid_layout, owned_path)

    blocked_layout = _layout(tmp_path / "blocked")
    _seed_release(blocked_layout, "0.1.0", current=True)
    blocked_config = _seed_owned_entry(blocked_layout, "config_file")
    blocked_config.parent.chmod(0o777)

    absent_release_parent = tmp_path / "absent-release-parent"
    absent_release_parent.mkdir(mode=0o755)
    safe_absent_layout = replace(
        _layout(tmp_path),
        release_root=absent_release_parent / "xferry",
    )
    sticky_absent_layout = replace(
        _layout(tmp_path),
        release_root=Path("/tmp") / f"xferry-fd-stress-{os.getpid()}-{tmp_path.name}",
    )
    fifo_layouts: list[ManagedLayout] = []
    for leaf_name in ("xferry-release.json", "xferry"):
        fifo_layout = _layout(tmp_path / f"fifo-{leaf_name}")
        fifo_release = _seed_release(fifo_layout, "0.1.0", current=True)
        fifo_leaf = fifo_release / leaf_name
        fifo_leaf.unlink()
        os.mkfifo(fifo_leaf, mode=0o600)
        fifo_layouts.append(fifo_layout)

    baseline = len(tuple(descriptor_directory.iterdir()))
    for _ in range(100):
        assert has_unsupported_managed_state(valid_layout) is False
        assert has_unsupported_managed_state(blocked_layout) is True
        assert has_unsupported_managed_state(safe_absent_layout) is False
        assert has_unsupported_managed_state(sticky_absent_layout) is True
        for fifo_layout in fifo_layouts:
            assert has_unsupported_managed_state(fifo_layout) is True
    after_classification = len(tuple(descriptor_directory.iterdir()))

    def forced_exception(*_args: object, **_kwargs: object) -> object:
        raise OSError("forced owned-entry inspection failure")

    monkeypatch.setattr(managed_state, "_inspect_owned_entry", forced_exception)
    for _ in range(100):
        assert has_unsupported_managed_state(valid_layout) is True
    after_exceptions = len(tuple(descriptor_directory.iterdir()))

    assert (baseline, after_classification, after_exceptions) == (
        baseline,
        baseline,
        baseline,
    )


@pytest.mark.parametrize("version", ["0.2", "0.02.0", "0.2.0.0", "0.2.00"])
def test_managed_state_classifier_blocks_noncanonical_release_footprints(
    tmp_path: Path,
    version: str,
) -> None:
    """A loose 0.x directory cannot certify an existing managed installation as safe."""
    layout = _layout(tmp_path)
    _seed_release(layout, version, current=True)

    assert has_unsupported_managed_state(layout) is True


@pytest.mark.parametrize(
    ("version", "blocked"),
    [
        ("0.1.0", False),
        ("0.2.0-rc.1", False),
        ("0.2.0+build.1", False),
        ("1.0.0", True),
        ("4.1.0", True),
        ("99.0.0", True),
    ],
)
def test_managed_state_classifier_accepts_only_the_supported_release_line(
    tmp_path: Path,
    version: str,
    blocked: bool,
) -> None:
    layout = _layout(tmp_path)
    _seed_release(layout, version, current=True)

    assert has_unsupported_managed_state(layout) is blocked


def test_managed_state_classifier_blocks_a_release_whose_bytes_do_not_match_metadata(
    tmp_path: Path,
) -> None:
    layout = _layout(tmp_path)
    release = _seed_release(layout, "0.1.0", current=True)
    executable = release / "xferry"
    original = executable.read_bytes()
    executable.write_bytes(bytes([original[0] ^ 1]) + original[1:])
    executable.chmod(0o755)

    assert has_unsupported_managed_state(layout) is True


@pytest.mark.parametrize(
    "boundary",
    ["release-root", "releases", "release-entry", "executable"],
)
def test_managed_state_classifier_does_not_follow_release_inventory_symlinks(
    tmp_path: Path,
    boundary: str,
) -> None:
    layout = _layout(tmp_path)
    release = _seed_release(layout, "0.1.0", current=True)
    paths = {
        "release-root": layout.release_root,
        "releases": layout.release_root / "releases",
        "release-entry": release,
        "executable": release / "xferry",
    }
    path = paths[boundary]
    outside = tmp_path / f"outside-{boundary}"
    path.rename(outside)
    path.symlink_to(outside, target_is_directory=outside.is_dir())

    assert has_unsupported_managed_state(layout) is True


@pytest.mark.parametrize("leaf_name", ["xferry-release.json", "xferry"])
def test_managed_state_classifier_promptly_blocks_fifo_release_leaves(
    tmp_path: Path,
    leaf_name: str,
) -> None:
    layout = _layout(tmp_path)
    release = _seed_release(layout, "0.1.0", current=True)
    leaf = release / leaf_name
    leaf.unlink()
    os.mkfifo(leaf, mode=0o600)

    completed = _classify_in_bounded_subprocess(layout, timeout=1.0)

    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip() == "True"


@pytest.mark.parametrize(
    "owned_path",
    ["config_file", "auth_file", "data_root", "unit_file", "cli_link"],
)
def test_managed_state_classifier_blocks_symlinked_managed_parent_components(
    tmp_path: Path,
    owned_path: str,
) -> None:
    layout = _layout(tmp_path)
    _seed_release(layout, "0.1.0", current=True)
    path = getattr(layout, owned_path)
    outside = tmp_path / f"outside-{owned_path}"
    outside.mkdir()

    if owned_path == "data_root":
        outside.joinpath(path.name).mkdir()
    elif owned_path == "cli_link":
        outside.joinpath(path.name).symlink_to("/opt/xferry/current/xferry")
    else:
        outside.joinpath(path.name).write_text("managed\n", encoding="utf-8")

    path.parent.parent.mkdir(parents=True, exist_ok=True)
    path.parent.symlink_to(outside, target_is_directory=True)

    assert has_unsupported_managed_state(layout) is True


def test_managed_state_classifier_blocks_a_release_entry_swapped_after_inventory_scan(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    layout = _layout(tmp_path)
    release = _seed_release(layout, "0.1.0", current=True)
    checked_release = release.with_name("0.1.0-checked")
    outside_layout = replace(layout, release_root=tmp_path / "outside-release-root")
    outside_release = _seed_release(outside_layout, "0.1.0")
    original_read_manifest = managed_state._read_manifest
    swapped = False

    def swap_before_manifest(*args: object, **kwargs: object) -> object:
        nonlocal swapped
        if not swapped:
            release.rename(checked_release)
            release.symlink_to(outside_release, target_is_directory=True)
            swapped = True
        return original_read_manifest(*args, **kwargs)

    monkeypatch.setattr(managed_state, "_read_manifest", swap_before_manifest)

    assert has_unsupported_managed_state(layout) is True
    assert release.is_symlink()


def test_managed_state_classifier_blocks_a_manifest_swapped_after_it_was_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    layout = _layout(tmp_path)
    release = _seed_release(layout, "0.1.0", current=True)
    manifest = release / "xferry-release.json"
    checked_manifest = manifest.with_name("xferry-release.checked.json")
    outside_manifest = tmp_path / "outside-manifest.json"
    outside_manifest.write_bytes(manifest.read_bytes())
    original_read_manifest = managed_state._read_manifest
    swapped = False

    def swap_after_manifest_read(*args: object, **kwargs: object) -> object:
        nonlocal swapped
        result = original_read_manifest(*args, **kwargs)
        if not swapped:
            manifest.rename(checked_manifest)
            manifest.symlink_to(outside_manifest)
            swapped = True
        return result

    monkeypatch.setattr(managed_state, "_read_manifest", swap_after_manifest_read)

    assert has_unsupported_managed_state(layout) is True
    assert manifest.is_symlink()


def test_managed_state_classifier_blocks_an_executable_swapped_after_it_was_hashed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    layout = _layout(tmp_path)
    release = _seed_release(layout, "0.1.0", current=True)
    executable = release / "xferry"
    checked_executable = executable.with_name("xferry.checked")
    outside_executable = tmp_path / "outside-xferry"
    outside_executable.write_bytes(b"unverified executable\n")
    outside_executable.chmod(0o755)
    original_valid_executable = managed_state._valid_executable
    swapped = False

    def swap_after_executable_hash(*args: object, **kwargs: object) -> object:
        nonlocal swapped
        result = original_valid_executable(*args, **kwargs)
        if result and not swapped:
            executable.rename(checked_executable)
            executable.symlink_to(outside_executable)
            swapped = True
        return result

    monkeypatch.setattr(managed_state, "_valid_executable", swap_after_executable_hash)

    assert has_unsupported_managed_state(layout) is True
    assert executable.is_symlink()


@pytest.mark.parametrize("directory", ["release-root", "releases", "release-entry"])
@pytest.mark.parametrize("mode", [0o775, 0o757])
def test_managed_state_classifier_blocks_a_writable_release_chain_directory(
    tmp_path: Path,
    directory: str,
    mode: int,
) -> None:
    layout = _layout(tmp_path)
    release = _seed_release(layout, "0.1.0", current=True)
    paths = {
        "release-root": layout.release_root,
        "releases": layout.release_root / "releases",
        "release-entry": release,
    }
    paths[directory].chmod(mode)

    assert has_unsupported_managed_state(layout) is True


def test_managed_state_classifier_blocks_a_release_chain_not_owned_by_the_effective_user(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    layout = _layout(tmp_path)
    _seed_release(layout, "0.1.0", current=True)
    actual_effective_uid = os.geteuid()
    monkeypatch.setattr(managed_state.os, "geteuid", lambda: actual_effective_uid + 1)

    assert has_unsupported_managed_state(layout) is True


@pytest.mark.parametrize(
    ("leaf", "mode"),
    [("manifest", 0o666), ("executable", 0o777)],
)
def test_managed_state_classifier_blocks_a_writable_release_leaf(
    tmp_path: Path,
    leaf: str,
    mode: int,
) -> None:
    layout = _layout(tmp_path)
    release = _seed_release(layout, "0.1.0", current=True)
    paths = {
        "manifest": release / "xferry-release.json",
        "executable": release / "xferry",
    }
    paths[leaf].chmod(mode)

    assert has_unsupported_managed_state(layout) is True


@pytest.mark.parametrize("leaf", ["manifest", "executable"])
def test_managed_state_classifier_blocks_a_release_leaf_not_owned_by_the_effective_user(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    leaf: str,
) -> None:
    layout = _layout(tmp_path)
    release = _seed_release(layout, "0.1.0", current=True)
    path = {
        "manifest": release / "xferry-release.json",
        "executable": release / "xferry",
    }[leaf]
    leaf_inode = path.stat().st_ino
    wrong_uid = os.geteuid() + 1
    original_fstat = managed_state.os.fstat

    def fstat_with_wrong_leaf_owner(descriptor: int) -> os.stat_result:
        metadata = original_fstat(descriptor)
        if metadata.st_ino != leaf_inode:
            return metadata
        fields = list(metadata)
        fields[4] = wrong_uid
        return os.stat_result(fields)

    monkeypatch.setattr(managed_state.os, "fstat", fstat_with_wrong_leaf_owner)

    assert has_unsupported_managed_state(layout) is True


def test_managed_state_classifier_blocks_a_manifest_overwritten_in_place_after_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    layout = _layout(tmp_path)
    release = _seed_release(layout, "0.1.0", current=True)
    manifest = release / "xferry-release.json"
    original_bytes = manifest.read_bytes()
    overwritten_bytes = b"[" + original_bytes[1:]
    original_inode = manifest.stat().st_ino
    original_read_manifest = managed_state._read_manifest
    overwritten = False

    def overwrite_after_manifest_read(*args: object, **kwargs: object) -> object:
        nonlocal overwritten
        try:
            return original_read_manifest(*args, **kwargs)
        finally:
            if not overwritten:
                manifest.write_bytes(overwritten_bytes)
                overwritten = True

    monkeypatch.setattr(managed_state, "_read_manifest", overwrite_after_manifest_read)

    assert has_unsupported_managed_state(layout) is True
    assert manifest.stat().st_ino == original_inode
    assert manifest.read_bytes() == overwritten_bytes


def test_managed_state_classifier_blocks_an_executable_overwritten_in_place_after_hash(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    layout = _layout(tmp_path)
    release = _seed_release(layout, "0.1.0", current=True)
    executable = release / "xferry"
    original_bytes = executable.read_bytes()
    overwritten_bytes = bytes([original_bytes[0] ^ 1]) + original_bytes[1:]
    original_inode = executable.stat().st_ino
    original_valid_executable = managed_state._valid_executable
    overwritten = False

    def overwrite_after_executable_hash(*args: object, **kwargs: object) -> object:
        nonlocal overwritten
        try:
            return original_valid_executable(*args, **kwargs)
        finally:
            if not overwritten:
                executable.write_bytes(overwritten_bytes)
                overwritten = True

    monkeypatch.setattr(managed_state, "_valid_executable", overwrite_after_executable_hash)

    assert has_unsupported_managed_state(layout) is True
    assert executable.stat().st_ino == original_inode
    assert executable.read_bytes() == overwritten_bytes


def test_managed_state_classifier_blocks_an_executable_changed_while_it_is_hashed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    layout = _layout(tmp_path)
    release = _seed_release(layout, "0.1.0", current=True)
    executable = release / "xferry"
    original_bytes = executable.read_bytes()
    overwritten_bytes = bytes([original_bytes[0] ^ 1]) + original_bytes[1:]
    original_sha256 = managed_state.hashlib.sha256
    overwritten = False

    class MutatingDigest:
        def __init__(self) -> None:
            self._digest = original_sha256()

        def update(self, payload: bytes) -> None:
            nonlocal overwritten
            self._digest.update(payload)
            if not overwritten:
                executable.write_bytes(overwritten_bytes)
                overwritten = True

        def hexdigest(self) -> str:
            return self._digest.hexdigest()

    monkeypatch.setattr(managed_state.hashlib, "sha256", MutatingDigest)

    assert has_unsupported_managed_state(layout) is True
    assert overwritten is True
    assert executable.read_bytes() == overwritten_bytes


def test_managed_state_classifier_blocks_a_writable_release_root_parent(tmp_path: Path) -> None:
    layout = _layout(tmp_path)
    _seed_release(layout, "0.1.0", current=True)
    layout.release_root.parent.chmod(0o777)

    assert has_unsupported_managed_state(layout) is True


def test_managed_state_classifier_blocks_a_root_swapped_after_the_path_recheck(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    layout = _layout(tmp_path)
    _seed_release(layout, "0.1.0", current=True)
    checked_root = layout.release_root.with_name("xferry-checked")
    original_path_matches_directory = managed_state._path_matches_directory
    swapped = False

    def swap_after_path_recheck(*args: object, **kwargs: object) -> bool:
        nonlocal swapped
        result = original_path_matches_directory(*args, **kwargs)
        if result and not swapped and args[0] == layout.release_root:
            layout.release_root.parent.chmod(0o777)
            layout.release_root.rename(checked_root)
            layout.release_root.symlink_to(checked_root, target_is_directory=True)
            swapped = True
        return result

    monkeypatch.setattr(managed_state, "_path_matches_directory", swap_after_path_recheck)

    assert has_unsupported_managed_state(layout) is True
    assert layout.release_root.is_symlink()


@pytest.mark.parametrize(
    "owned_path",
    ["config_file", "auth_file", "data_root", "unit_file", "cli_link"],
)
def test_managed_state_classifier_blocks_wrong_owned_path_kinds_beside_a_valid_release(
    tmp_path: Path,
    owned_path: str,
) -> None:
    layout = _layout(tmp_path)
    _seed_release(layout, "0.1.0", current=True)
    path = getattr(layout, owned_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if owned_path == "data_root":
        path.write_text("not a directory\n", encoding="utf-8")
    elif owned_path == "cli_link":
        path.write_text("not a symlink\n", encoding="utf-8")
    else:
        path.mkdir()

    assert has_unsupported_managed_state(layout) is True


@pytest.mark.parametrize(
    ("manifest_size", "blocked"),
    [(65536, False), (65537, True)],
)
def test_managed_state_classifier_enforces_the_manifest_size_boundary(
    tmp_path: Path,
    manifest_size: int,
    blocked: bool,
) -> None:
    layout = _layout(tmp_path)
    release = _seed_release(layout, "0.1.0", current=True)
    manifest = release / "xferry-release.json"
    payload = manifest.read_bytes()
    manifest.write_bytes(payload + b" " * (manifest_size - len(payload)))

    assert manifest.stat().st_size == manifest_size
    assert has_unsupported_managed_state(layout) is blocked


def test_managed_state_classifier_blocks_unsupported_release_beside_valid_current_release(
    tmp_path: Path,
) -> None:
    """A valid current marker must not conceal archived unsupported managed-state releases."""
    layout = _layout(tmp_path)
    _seed_release(layout, "0.1.0", current=True)
    _seed_release(layout, "4.1.0")

    assert has_unsupported_managed_state(layout) is True


def test_managed_state_classifier_blocks_unsupported_current_target_without_following_it(
    tmp_path: Path,
) -> None:
    """An explicit unsupported managed-state current target must block even when it is absent."""
    layout = _layout(tmp_path)
    _seed_release(layout, "0.1.0")
    layout.release_root.joinpath("current").symlink_to("releases/2.1.0")

    assert has_unsupported_managed_state(layout) is True


def test_managed_state_classifier_blocks_unsupported_manifest_under_a_current_release_name(
    tmp_path: Path,
) -> None:
    """Directory naming must not hide an unsupported version in managed metadata."""
    layout = _layout(tmp_path)
    _seed_release(layout, "0.1.0", current=True, manifest_version="4.1.0")

    assert has_unsupported_managed_state(layout) is True


def test_managed_state_classifier_does_not_follow_a_manifest_symlink(tmp_path: Path) -> None:
    """A manifest symlink outside the managed release must fail closed."""
    layout = _layout(tmp_path)
    release = _seed_release(layout, "0.1.0", current=True)
    manifest = release / "xferry-release.json"
    outside = tmp_path / "outside-manifest.json"
    outside.write_bytes(manifest.read_bytes())
    manifest.unlink()
    manifest.symlink_to(outside)

    assert has_unsupported_managed_state(layout) is True


def test_managed_state_classifier_rejects_current_symlink_outside_the_managed_release_tree(
    tmp_path: Path,
) -> None:
    """Following an attacker-controlled current link could misclassify external state."""
    layout = _layout(tmp_path)
    layout.release_root.mkdir(parents=True)
    layout.release_root.joinpath("current").symlink_to(tmp_path / "outside")

    assert has_unsupported_managed_state(layout) is True


@pytest.mark.parametrize(
    ("entry_count", "blocked"),
    [(128, False), (129, True)],
)
def test_managed_state_classifier_enforces_the_release_inventory_boundary(
    tmp_path: Path,
    entry_count: int,
    blocked: bool,
) -> None:
    layout = _layout(tmp_path)
    for index in range(entry_count):
        _seed_release(layout, f"0.1.{index}", current=index == 0)

    assert has_unsupported_managed_state(layout) is blocked


def test_setup_guard_blocks_a_locked_executable_swap_before_any_command_or_write(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan = _plan(tmp_path)
    release = _seed_release(plan.layout, "0.1.0", current=True)
    executable = release / "xferry"
    original_bytes = executable.read_bytes()
    checked_executable = executable.with_name("xferry.checked")
    outside_executable = tmp_path / "outside-xferry"
    outside_bytes = b"unverified executable\n"
    outside_executable.write_bytes(outside_bytes)
    outside_executable.chmod(0o755)
    plan.layout.lock_file.parent.mkdir(parents=True)
    lock_bytes = b"pre-existing lock\n"
    plan.layout.lock_file.write_bytes(lock_bytes)
    plan.layout.lock_file.chmod(0o600)
    original_valid_executable = managed_state._valid_executable
    validations = 0

    def swap_during_locked_preflight(*args: object, **kwargs: object) -> object:
        nonlocal validations
        result = original_valid_executable(*args, **kwargs)
        validations += 1
        if validations == 2 and result:
            executable.rename(checked_executable)
            executable.symlink_to(outside_executable)
        return result

    monkeypatch.setattr(managed_state, "_valid_executable", swap_during_locked_preflight)

    def guarded_preflight(candidate: SetupPlan) -> SetupPreflight:
        return check_setup_preflight(
            candidate,
            SetupProbes(
                executable_is_ready=lambda _path: True,
                port_is_available=lambda _host, _port: True,
                ufw_is_active=lambda: False,
                unsupported_managed_state_detected=has_unsupported_managed_state,
            ),
        )

    runner = FakeRunner()
    result = _executor(tmp_path, runner, preflight=guarded_preflight).apply(plan)

    assert validations == 2
    assert result.exit_code == 1
    assert all(clause in result.message for clause in UNSUPPORTED_MANAGED_STATE_INSTRUCTION_CLAUSES)
    assert result.credentials is None
    assert runner.commands == []
    assert executable.is_symlink()
    assert checked_executable.read_bytes() == original_bytes
    assert outside_executable.read_bytes() == outside_bytes
    assert plan.layout.lock_file.read_bytes() == lock_bytes
    assert not plan.layout.config_file.exists()
    assert not plan.layout.auth_file.exists()
    assert not plan.layout.data_root.exists()
    assert not plan.layout.unit_file.exists()
    assert not plan.layout.cli_link.exists()


def test_setup_guard_blocks_a_locked_in_place_overwrite_before_any_command_or_write(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan = _plan(tmp_path)
    release = _seed_release(plan.layout, "0.1.0", current=True)
    executable = release / "xferry"
    original_bytes = executable.read_bytes()
    overwritten_bytes = bytes([original_bytes[0] ^ 1]) + original_bytes[1:]
    original_inode = executable.stat().st_ino
    plan.layout.lock_file.parent.mkdir(parents=True)
    lock_bytes = b"pre-existing lock\n"
    plan.layout.lock_file.write_bytes(lock_bytes)
    plan.layout.lock_file.chmod(0o600)
    original_valid_executable = managed_state._valid_executable
    validations = 0

    def overwrite_during_locked_preflight(*args: object, **kwargs: object) -> object:
        nonlocal validations
        result = original_valid_executable(*args, **kwargs)
        validations += 1
        if validations == 2:
            executable.write_bytes(overwritten_bytes)
        return result

    monkeypatch.setattr(managed_state, "_valid_executable", overwrite_during_locked_preflight)

    def guarded_preflight(candidate: SetupPlan) -> SetupPreflight:
        return check_setup_preflight(
            candidate,
            SetupProbes(
                executable_is_ready=lambda _path: True,
                port_is_available=lambda _host, _port: True,
                ufw_is_active=lambda: False,
                unsupported_managed_state_detected=has_unsupported_managed_state,
            ),
        )

    runner = FakeRunner()
    result = _executor(tmp_path, runner, preflight=guarded_preflight).apply(plan)

    assert validations == 2
    assert result.exit_code == 1
    assert all(clause in result.message for clause in UNSUPPORTED_MANAGED_STATE_INSTRUCTION_CLAUSES)
    assert result.credentials is None
    assert runner.commands == []
    assert executable.stat().st_ino == original_inode
    assert executable.read_bytes() == overwritten_bytes
    assert plan.layout.lock_file.read_bytes() == lock_bytes
    assert not plan.layout.config_file.exists()
    assert not plan.layout.auth_file.exists()
    assert not plan.layout.data_root.exists()
    assert not plan.layout.unit_file.exists()
    assert not plan.layout.cli_link.exists()


def test_setup_guard_blocks_a_locked_release_root_swap_before_any_effect(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan = _plan(tmp_path)
    _seed_release(plan.layout, "0.1.0", current=True)
    checked_root = plan.layout.release_root.with_name("xferry-checked")
    plan.layout.lock_file.parent.mkdir(parents=True)
    lock_bytes = b"pre-existing lock\n"
    plan.layout.lock_file.write_bytes(lock_bytes)
    plan.layout.lock_file.chmod(0o600)
    original_path_matches_directory = managed_state._path_matches_directory
    root_checks = 0

    def swap_during_locked_preflight(*args: object, **kwargs: object) -> bool:
        nonlocal root_checks
        result = original_path_matches_directory(*args, **kwargs)
        if args[0] == plan.layout.release_root:
            root_checks += 1
            if root_checks == 2 and result:
                plan.layout.release_root.parent.chmod(0o777)
                plan.layout.release_root.rename(checked_root)
                plan.layout.release_root.symlink_to(
                    checked_root,
                    target_is_directory=True,
                )
        return result

    monkeypatch.setattr(managed_state, "_path_matches_directory", swap_during_locked_preflight)

    def guarded_preflight(candidate: SetupPlan) -> SetupPreflight:
        return check_setup_preflight(
            candidate,
            SetupProbes(
                executable_is_ready=lambda _path: True,
                port_is_available=lambda _host, _port: True,
                ufw_is_active=lambda: False,
                unsupported_managed_state_detected=has_unsupported_managed_state,
            ),
        )

    runner = FakeRunner()
    result = _executor(tmp_path, runner, preflight=guarded_preflight).apply(plan)

    assert root_checks == 2
    assert result.exit_code == 1
    assert all(clause in result.message for clause in UNSUPPORTED_MANAGED_STATE_INSTRUCTION_CLAUSES)
    assert result.credentials is None
    assert runner.commands == []
    assert plan.layout.release_root.is_symlink()
    assert checked_root.is_dir()
    assert plan.layout.lock_file.read_bytes() == lock_bytes
    assert not plan.layout.config_file.exists()
    assert not plan.layout.auth_file.exists()
    assert not plan.layout.data_root.exists()
    assert not plan.layout.unit_file.exists()
    assert not plan.layout.cli_link.exists()


def test_setup_guard_blocks_a_locked_owned_leaf_swap_before_any_effect(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan = _plan(tmp_path)
    _seed_release(plan.layout, "0.1.0", current=True)
    config = _seed_owned_entry(plan.layout, "config_file")
    original_config = config.read_bytes()
    plan.layout.lock_file.parent.mkdir(parents=True)
    lock_bytes = b"pre-existing lock\n"
    plan.layout.lock_file.write_bytes(lock_bytes)
    plan.layout.lock_file.chmod(0o600)
    original_inspect = managed_state._inspect_owned_entry
    config_inspections = 0

    def swap_during_locked_preflight(*args: object, **kwargs: object) -> object:
        nonlocal config_inspections
        witness = original_inspect(*args, **kwargs)
        if args[0] == config:
            config_inspections += 1
            if config_inspections == 2:
                _replace_owned_entry(config, "config_file")
        return witness

    monkeypatch.setattr(managed_state, "_inspect_owned_entry", swap_during_locked_preflight)

    def guarded_preflight(candidate: SetupPlan) -> SetupPreflight:
        return check_setup_preflight(
            candidate,
            SetupProbes(
                executable_is_ready=lambda _path: True,
                port_is_available=lambda _host, _port: True,
                ufw_is_active=lambda: False,
                unsupported_managed_state_detected=has_unsupported_managed_state,
            ),
        )

    runner = FakeRunner()
    result = _executor(tmp_path, runner, preflight=guarded_preflight).apply(plan)

    assert config_inspections == 2
    assert result.exit_code == 1
    assert all(clause in result.message for clause in UNSUPPORTED_MANAGED_STATE_INSTRUCTION_CLAUSES)
    assert result.credentials is None
    assert runner.commands == []
    assert config.read_bytes() == b"replacement\n"
    assert config.with_name("xferry.ini.checked").read_bytes() == original_config
    assert plan.layout.lock_file.read_bytes() == lock_bytes
    assert not plan.layout.auth_file.exists()
    assert not plan.layout.data_root.exists()
    assert not plan.layout.unit_file.exists()
    assert not plan.layout.cli_link.exists()


def test_setup_guard_blocks_a_release_root_absence_that_becomes_replaceable_under_lock(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan = _plan(tmp_path)
    release_parent = tmp_path / "trusted-release-parent"
    release_parent.mkdir(mode=0o755)
    layout = replace(plan.layout, release_root=release_parent / "xferry")
    plan = replace(plan, layout=layout)
    plan.layout.lock_file.parent.mkdir(parents=True)
    lock_bytes = b"pre-existing lock\n"
    plan.layout.lock_file.write_bytes(lock_bytes)
    plan.layout.lock_file.chmod(0o600)
    original_inspect = managed_state._inspect_protected_absence
    release_absence_inspections = 0

    def make_release_absence_replaceable(
        *args: object,
        **kwargs: object,
    ) -> object:
        nonlocal release_absence_inspections
        witness = original_inspect(*args, **kwargs)
        if args[0] == plan.layout.release_root:
            release_absence_inspections += 1
            if release_absence_inspections == 2:
                release_parent.chmod(0o1777)
        return witness

    monkeypatch.setattr(
        managed_state,
        "_inspect_protected_absence",
        make_release_absence_replaceable,
    )

    def guarded_preflight(candidate: SetupPlan) -> SetupPreflight:
        return check_setup_preflight(
            candidate,
            SetupProbes(
                executable_is_ready=lambda _path: True,
                port_is_available=lambda _host, _port: True,
                ufw_is_active=lambda: False,
                unsupported_managed_state_detected=has_unsupported_managed_state,
            ),
        )

    runner = FakeRunner()
    result = _executor(tmp_path, runner, preflight=guarded_preflight).apply(plan)

    assert release_absence_inspections == 2
    assert result.exit_code == 1
    assert all(clause in result.message for clause in UNSUPPORTED_MANAGED_STATE_INSTRUCTION_CLAUSES)
    assert result.credentials is None
    assert runner.commands == []
    assert plan.layout.lock_file.read_bytes() == lock_bytes
    assert not plan.layout.release_root.exists()
    assert not plan.layout.config_file.exists()
    assert not plan.layout.auth_file.exists()
    assert not plan.layout.data_root.exists()
    assert not plan.layout.unit_file.exists()
    assert not plan.layout.cli_link.exists()


def test_setup_guard_blocks_missing_before_dot_dot_under_lock_without_any_effect(
    tmp_path: Path,
) -> None:
    plan = _plan(tmp_path)
    _seed_release(plan.layout, "0.1.0", current=True)
    trusted_parent = tmp_path / "trusted-data-parent"
    trusted_parent.mkdir(mode=0o755)
    victim = trusted_parent / "victim"
    original = b"preserve victim\n"
    victim.write_bytes(original)
    ambiguous_data_root = trusted_parent / "missing" / ".." / victim.name
    assert ".." in ambiguous_data_root.parts
    plan = replace(
        plan,
        layout=replace(plan.layout, data_root=ambiguous_data_root),
    )
    plan.layout.lock_file.parent.mkdir(parents=True)
    lock_bytes = b"pre-existing lock\n"
    plan.layout.lock_file.write_bytes(lock_bytes)
    plan.layout.lock_file.chmod(0o600)
    preflight_calls = 0

    def guarded_locked_preflight(candidate: SetupPlan) -> SetupPreflight:
        nonlocal preflight_calls
        preflight_calls += 1
        if preflight_calls == 1:
            return _ok_preflight(candidate)
        return check_setup_preflight(
            candidate,
            SetupProbes(
                executable_is_ready=lambda _path: True,
                port_is_available=lambda _host, _port: True,
                ufw_is_active=lambda: False,
                unsupported_managed_state_detected=has_unsupported_managed_state,
            ),
        )

    runner = FakeRunner(group_exists=False, user_exists=False)
    result = _executor(tmp_path, runner, preflight=guarded_locked_preflight).apply(plan)

    assert preflight_calls == 2
    assert result.exit_code == 1
    assert all(clause in result.message for clause in UNSUPPORTED_MANAGED_STATE_INSTRUCTION_CLAUSES)
    assert result.credentials is None
    assert runner.commands == []
    assert runner.group_exists is False
    assert runner.user_exists is False
    assert plan.layout.lock_file.read_bytes() == lock_bytes
    assert not (trusted_parent / "missing").exists()
    assert victim.is_file()
    assert victim.read_bytes() == original
    assert not plan.layout.config_file.exists()
    assert not plan.layout.auth_file.exists()
    assert not plan.layout.unit_file.exists()
    assert not plan.layout.cli_link.exists()


@pytest.mark.parametrize(
    "unsafe_chain",
    [
        "owner",
        "writable-mode",
        "writable-root-parent",
        "writable-manifest",
        "writable-executable",
    ],
)
def test_setup_guard_blocks_an_untrusted_release_chain_before_any_effect(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    unsafe_chain: str,
) -> None:
    plan = _plan(tmp_path)
    release = _seed_release(plan.layout, "0.1.0", current=True)
    if unsafe_chain == "owner":
        actual_effective_uid = os.geteuid()
        monkeypatch.setattr(managed_state.os, "geteuid", lambda: actual_effective_uid + 1)
    elif unsafe_chain == "writable-mode":
        plan.layout.release_root.chmod(0o775)
    elif unsafe_chain == "writable-root-parent":
        plan.layout.release_root.parent.chmod(0o777)
    elif unsafe_chain == "writable-manifest":
        release.joinpath("xferry-release.json").chmod(0o666)
    else:
        release.joinpath("xferry").chmod(0o777)

    def guarded_preflight(candidate: SetupPlan) -> SetupPreflight:
        return check_setup_preflight(
            candidate,
            SetupProbes(
                executable_is_ready=lambda _path: True,
                port_is_available=lambda _host, _port: True,
                ufw_is_active=lambda: False,
                unsupported_managed_state_detected=has_unsupported_managed_state,
            ),
        )

    runner = FakeRunner()
    result = _executor(tmp_path, runner, preflight=guarded_preflight).apply(plan)

    assert result.exit_code == 1
    assert all(clause in result.message for clause in UNSUPPORTED_MANAGED_STATE_INSTRUCTION_CLAUSES)
    assert result.credentials is None
    assert runner.commands == []
    assert not plan.layout.lock_file.exists()
    assert not plan.layout.config_file.exists()
    assert not plan.layout.auth_file.exists()
    assert not plan.layout.data_root.exists()
    assert not plan.layout.unit_file.exists()
    assert not plan.layout.cli_link.exists()


@pytest.mark.parametrize(
    "missing_capability",
    [
        "O_CLOEXEC",
        "O_DIRECTORY",
        "O_NOFOLLOW",
        "O_NONBLOCK",
        "geteuid",
        "fstat",
        "fdopen",
        "close",
    ],
)
def test_managed_state_classifier_imports_and_fails_closed_without_unix_descriptor_support(
    missing_capability: str,
) -> None:
    script = f"""
import os
name = {missing_capability!r}
if hasattr(os, name):
    delattr(os, name)
from xferry.management.managed_state import has_unsupported_managed_state
from xferry.management.model import ManagedLayout
print(has_unsupported_managed_state(ManagedLayout()))
"""

    completed = subprocess.run(  # noqa: S603
        [sys.executable, "-c", script],
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip() == "True"


def test_unsupported_managed_state_preflight_short_circuits_port_and_firewall_probes(
    tmp_path: Path,
) -> None:
    """Remediation must win even when an unsupported managed service occupies ports."""
    plan = _plan(tmp_path, mode=SetupMode.SSLIP)

    def forbidden(*_args: object) -> bool:
        pytest.fail("managed-state classifier must precede executable, port, and firewall probes")

    preflight = check_setup_preflight(
        plan,
        SetupProbes(
            executable_is_ready=forbidden,
            port_is_available=forbidden,
            ufw_is_active=forbidden,
            unsupported_managed_state_detected=lambda _layout: True,
        ),
    )

    result = preflight_result(preflight)
    assert result.exit_code == 1
    assert all(clause in result.message for clause in UNSUPPORTED_MANAGED_STATE_INSTRUCTION_CLAUSES)


def test_setup_dry_run_reports_unsupported_managed_state_instructions_without_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Dry-run must not present an install plan over ambiguous managed state."""
    from xferry.management import cli

    plan = _plan(tmp_path)
    plan.layout.config_file.parent.mkdir(parents=True)
    original = b"[server]\ndir = /unsupported\n"
    plan.layout.config_file.write_bytes(original)
    runner = FakeRunner(ufw_active=True)

    def prepare(_args: object) -> tuple[SetupPlan, SetupPreflight]:
        return plan, default_setup_preflight(plan, runner, interactive=False)

    monkeypatch.setattr(cli, "_prepare_setup_plan", prepare)

    assert main(["setup", "--private", "--dry-run"]) == 1
    captured = capsys.readouterr()
    assert all(clause in captured.err for clause in UNSUPPORTED_MANAGED_STATE_INSTRUCTION_CLAUSES)
    assert runner.commands == []
    assert plan.layout.config_file.read_bytes() == original
    assert not plan.layout.lock_file.exists()


def test_setup_rechecks_the_same_plan_under_the_shared_lock(tmp_path: Path) -> None:
    """Mutating after only a stale CLI preflight would admit port or firewall drift."""
    runner = FakeRunner()
    seen: list[SetupPlan] = []

    def drifting_preflight(plan: SetupPlan) -> SetupPreflight:
        seen.append(plan)
        if len(seen) == 1:
            return _ok_preflight(plan)
        return SetupPreflight(
            executable_ready=True,
            required_bind_ports=(8080,),
            unavailable_bind_ports=(8080,),
            ufw_active=False,
            failures=(PreflightFailure("port-unavailable", "occupied"),),
        )

    plan = _plan(tmp_path)
    result = _executor(tmp_path, runner, preflight=drifting_preflight).apply(plan)

    assert result.exit_code == 5
    assert seen == [plan, plan]
    assert runner.commands == []
    assert not plan.layout.auth_file.exists()


def test_setup_aborts_before_managed_mutation_when_initial_systemd_probe_fails(
    tmp_path: Path,
) -> None:
    """Treating a D-Bus probe error as disabled/inactive can destroy the prior service state."""
    runner = FakeRunner(service_probe_failures={1})
    plan = _plan(tmp_path)

    result = _executor(tmp_path, runner).apply(plan)

    assert result.exit_code == 1
    assert result.message == "service state probe failed"
    assert runner.commands == [
        (
            "systemctl",
            "show",
            "--property=LoadState",
            "--property=UnitFileState",
            "--property=ActiveState",
            "xferry.service",
        )
    ]
    assert not plan.layout.config_file.exists()


def test_setup_accepts_a_structurally_confirmed_absent_unit_state(tmp_path: Path) -> None:
    """A missing old unit is a known restorable state, unlike an unreadable systemd response."""
    runner = FakeRunner(service_present=False)

    result = _executor(tmp_path, runner).apply(_plan(tmp_path))

    assert result.exit_code == 0
    assert runner.service_probe_count == 1


def test_managed_mutation_rejects_a_second_holder(tmp_path: Path) -> None:
    """Allowing overlapping operations would make snapshots and rollbacks unsafe."""
    lock_path = tmp_path / "run/lock/xferry-ops.lock"

    with managed_mutation(lock_path, effective_uid=lambda: 0, root_uid=os.getuid()):
        with pytest.raises(MutationLocked):
            with managed_mutation(lock_path, effective_uid=lambda: 0, root_uid=os.getuid()):
                pass


def test_managed_mutation_rejects_symlink_without_changing_target_mode(tmp_path: Path) -> None:
    """Following a lock symlink would let a local attacker chmod and lock another file."""
    lock_path = tmp_path / "run/lock/xferry-ops.lock"
    lock_path.parent.mkdir(parents=True)
    target = tmp_path / "attacker-target"
    target.write_text("do not touch", encoding="utf-8")
    target.chmod(0o644)
    lock_path.symlink_to(target)

    with pytest.raises(MutationError):
        with managed_mutation(lock_path, effective_uid=lambda: 0):
            pass

    assert stat.S_IMODE(target.stat().st_mode) == 0o644


def test_managed_mutation_rejects_attacker_owned_existing_file(tmp_path: Path) -> None:
    """Accepting a non-root-owned lock lets another user coordinate or replace operations."""
    lock_path = tmp_path / "run/lock/xferry-ops.lock"
    lock_path.parent.mkdir(parents=True)
    lock_path.write_text("attacker", encoding="utf-8")
    lock_path.chmod(0o600)

    with pytest.raises(MutationError):
        with managed_mutation(lock_path, effective_uid=lambda: 0, root_uid=0):
            pass


def test_setup_returns_operation_failure_for_unsafe_lock_without_touching_target(
    tmp_path: Path,
) -> None:
    """An unsafe shared lock must fail cleanly instead of escaping through the CLI."""
    plan = _plan(tmp_path)
    plan.layout.lock_file.parent.mkdir(parents=True)
    target = tmp_path / "attacker-target"
    target.write_text("do not touch", encoding="utf-8")
    target.chmod(0o644)
    plan.layout.lock_file.symlink_to(target)

    result = _executor(tmp_path, FakeRunner()).apply(plan)

    assert result.exit_code == 1
    assert result.message == "managed mutation lock is unsafe"
    assert stat.S_IMODE(target.stat().st_mode) == 0o644


@pytest.mark.parametrize(
    ("fail_at", "expected_exit"),
    [("config", 2), ("reload", 1), ("start", 6), ("health", 6)],
)
def test_setup_failure_restores_files_activation_and_hides_credentials(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    caplog: pytest.LogCaptureFixture,
    fail_at: str,
    expected_exit: int,
) -> None:
    """A partial managed setup must not replace prior files, service state, or secrets."""
    seed = _seed_managed_state(tmp_path)
    runner = FakeRunner(fail_at=None if fail_at == "health" else fail_at, enabled=True, active=True)
    health = (
        (lambda *_args: HealthResult(ok=False, detail="invalid health response"))
        if fail_at == "health"
        else None
    )

    with caplog.at_level(logging.DEBUG, logger="xferry"):
        result = _executor(tmp_path, runner, health=health).apply(_plan(tmp_path))

    assert result.exit_code == expected_exit
    assert result.credentials is None
    _assert_seed_restored(seed)
    assert runner.enabled is True
    assert runner.active is True
    captured = capsys.readouterr()
    assert "admin:" not in captured.out + captured.err + caplog.text
    assert all("admin:" not in " ".join(command) for command in runner.commands)


def test_config_failure_does_not_touch_service_activation(tmp_path: Path) -> None:
    """A failure before daemon reload must not restart or toggle the existing service."""
    _seed_managed_state(tmp_path)
    runner = FakeRunner(fail_at="config", enabled=True, active=True)

    result = _executor(tmp_path, runner).apply(_plan(tmp_path))

    assert result.exit_code == 2
    mutating_systemctl = [
        command
        for command in runner.commands
        if command[:2]
        not in {
            ("systemctl", "is-enabled"),
            ("systemctl", "is-active"),
            ("systemctl", "show"),
        }
        and command[:1] == ("systemctl",)
    ]
    assert mutating_systemctl == []


def test_config_failure_surfaces_filesystem_rollback_failure(tmp_path: Path) -> None:
    """A config error must not be reported as safely restored when file restoration fails."""

    class FailingRollbackTransaction(FilesystemTransaction):
        def rollback(self) -> None:
            raise OSError("simulated restore failure")

    runner = FakeRunner(fail_at="config")
    executor = _executor(tmp_path, runner)
    executor.transaction_factory = lambda: FailingRollbackTransaction(chown=executor.chown)

    result = executor.apply(_plan(tmp_path))

    assert result.exit_code == 1
    assert result.message == "managed setup failed and rollback is incomplete"
    assert result.credentials is None


def test_start_failure_surfaces_enabled_state_restore_failure(tmp_path: Path) -> None:
    """A failed disable must be detected when start rollback should restore disabled state."""
    runner = FakeRunner(fail_at="start", fail_restore="disable")

    result = _executor(tmp_path, runner).apply(_plan(tmp_path))

    assert result.exit_code == 1
    assert result.message == "managed setup failed and rollback is incomplete"
    assert runner.enabled is True


def test_health_failure_surfaces_active_state_restore_failure(tmp_path: Path) -> None:
    """A failed stop must be detected when health rollback should restore inactivity."""
    runner = FakeRunner(fail_restore="stop")

    result = _executor(
        tmp_path,
        runner,
        health=lambda *_args: HealthResult(ok=False, detail="invalid health response"),
    ).apply(_plan(tmp_path))

    assert result.exit_code == 1
    assert result.message == "managed setup failed and rollback is incomplete"


def test_health_failure_surfaces_unknown_post_rollback_systemd_probe(
    tmp_path: Path,
) -> None:
    """A successful restore command is insufficient when its resulting state cannot be proven."""
    runner = FakeRunner(
        enabled=True,
        active=True,
        service_probe_failures={2},
    )
    seed = _seed_managed_state(tmp_path)

    result = _executor(
        tmp_path,
        runner,
        health=lambda *_args: HealthResult(ok=False, detail="invalid health response"),
    ).apply(_plan(tmp_path))

    assert result.exit_code == 1
    assert result.message == "managed setup failed and rollback is incomplete"
    _assert_seed_restored(seed)
    assert runner.active is True


def test_health_failure_surfaces_ufw_rule_restore_failure(tmp_path: Path) -> None:
    """A failed UFW delete must not be hidden behind the original unhealthy result."""
    runner = FakeRunner(ufw_active=True, fail_restore="ufw-delete")

    result = _executor(
        tmp_path,
        runner,
        health=lambda *_args: HealthResult(ok=False, detail="invalid health response"),
    ).apply(_plan(tmp_path, mode=SetupMode.SSLIP, firewall_action="allow"))

    assert result.exit_code == 1
    assert result.message == "managed setup failed and rollback is incomplete"
    assert runner.ufw_rules == {80, 443}


def test_health_failure_detects_successful_ufw_delete_that_leaves_rule(
    tmp_path: Path,
) -> None:
    """A zero delete exit is not restoration proof when the added rule still exists."""
    runner = FakeRunner(ufw_active=True, fail_restore="ufw-delete-noop")

    result = _executor(
        tmp_path,
        runner,
        health=lambda *_args: HealthResult(ok=False, detail="invalid health response"),
    ).apply(_plan(tmp_path, mode=SetupMode.SSLIP, firewall_action="allow"))

    assert result.exit_code == 1
    assert result.message == "managed setup failed and rollback is incomplete"
    assert runner.ufw_rules == {80, 443}
    assert runner.commands.count(("ufw", "status")) >= 2


@pytest.mark.parametrize(
    ("fail_at", "expected_exit"),
    [("config", 2), ("reload", 1), ("start", 6), ("health", 6)],
)
def test_failed_clean_setup_removes_new_files_directories_and_identities(
    tmp_path: Path,
    fail_at: str,
    expected_exit: int,
) -> None:
    """A failed first setup must not retain generated auth or newly managed identities."""
    runner = FakeRunner(
        fail_at=None if fail_at == "health" else fail_at,
        group_exists=False,
        user_exists=False,
    )
    result = _executor(
        tmp_path,
        runner,
        health=(
            (lambda *_args: HealthResult(ok=False, detail="invalid health response"))
            if fail_at == "health"
            else None
        ),
    ).apply(_plan(tmp_path))

    assert result.exit_code == expected_exit
    assert not (tmp_path / "etc/xferry").exists()
    assert not (tmp_path / "etc/systemd/system/xferry.service").exists()
    assert not (tmp_path / "var/lib/xferry").exists()
    assert not (tmp_path / "home/xferry").exists()
    assert runner.user_exists is False
    assert runner.group_exists is False
    assert ("userdel", "xferry") in runner.commands
    assert ("groupdel", "xferry") in runner.commands


def test_identity_lookup_failure_removes_accounts_created_by_setup(tmp_path: Path) -> None:
    """A post-creation identity lookup failure must not strand the new user or group."""
    runner = FakeRunner(group_exists=False, user_exists=False)
    executor = _executor(tmp_path, runner)
    executor.resolve_identity = lambda: (_ for _ in ()).throw(KeyError("xferry"))

    result = executor.apply(_plan(tmp_path))

    assert result.exit_code == 1
    assert runner.user_exists is False
    assert runner.group_exists is False
    assert ("userdel", "xferry") in runner.commands
    assert ("groupdel", "xferry") in runner.commands
    assert not (tmp_path / "etc/xferry/auth").exists()


def test_approved_firewall_rules_run_only_while_ufw_is_still_active(tmp_path: Path) -> None:
    """Treating approval as proof of current UFW state would mutate an inactive firewall."""
    runner = FakeRunner(ufw_active=False)

    result = _executor(tmp_path, runner).apply(
        _plan(tmp_path, mode=SetupMode.SSLIP, firewall_action="allow")
    )

    assert result.exit_code == 0
    assert not any(command[:2] == ("ufw", "allow") for command in runner.commands)
    assert not any("enable" in command for command in runner.commands if command[:1] == ("ufw",))


def test_ufw_probe_uses_an_injected_stable_c_locale() -> None:
    """Inherited localization must not make an active firewall look inactive."""
    runner = FakeRunner(ufw_active=True, localized_ufw_without_c_locale=True)

    assert ufw_is_active(runner) is True
    assert runner.command_environments == [{"LANG": "C", "LC_ALL": "C"}]


def test_absent_ufw_is_distinct_from_an_unknown_probe_failure() -> None:
    """A missing optional UFW executable is inactive policy, not a generic command failure."""
    runner = FakeRunner(ufw_absent=True)

    assert ufw_is_active(runner) is False
    assert runner.commands == [("ufw", "status")]


def test_unexpected_ufw_probe_failure_aborts_before_any_managed_mutation(
    tmp_path: Path,
) -> None:
    """Treating a nonzero UFW status as inactive would mutate a host with unknown policy."""
    runner = FakeRunner(ufw_status_returncode=2)
    plan = _plan(tmp_path, mode=SetupMode.SSLIP)

    def preflight(candidate: SetupPlan) -> SetupPreflight:
        return check_setup_preflight(
            candidate,
            SetupProbes(
                executable_is_ready=lambda _path: True,
                port_is_available=lambda _host, _port: True,
                ufw_is_active=lambda: ufw_is_active(runner),
                interactive=False,
            ),
        )

    result = _executor(tmp_path, runner, preflight=preflight).apply(plan)

    assert result.exit_code == 1
    assert result.message == "managed setup preflight failed"
    assert runner.commands == [("ufw", "status")]
    assert not plan.layout.config_file.exists()
    assert not plan.layout.lock_file.exists()


def test_firewall_uses_only_plan_ports_and_never_enables_ufw(tmp_path: Path) -> None:
    """Adding inferred ports or enabling UFW would exceed the operator's approval."""
    runner = FakeRunner(ufw_active=True)

    result = _executor(tmp_path, runner).apply(
        _plan(tmp_path, mode=SetupMode.SSLIP, firewall_action="allow")
    )

    assert result.exit_code == 0
    assert runner.ufw_rules == {80, 443}
    assert ("ufw", "allow", "80/tcp") in runner.commands
    assert ("ufw", "allow", "443/tcp") in runner.commands
    assert not any(command[:2] == ("ufw", "enable") for command in runner.commands)


def test_executor_rejects_arbitrary_firewall_port_before_any_ufw_command(tmp_path: Path) -> None:
    """The mutation boundary must defend even when an injected preflight wrongly returns OK."""
    runner = FakeRunner(ufw_active=True)
    malformed = replace(
        _plan(tmp_path, mode=SetupMode.SSLIP, firewall_action="allow"),
        firewall_ports=(22, 443),
    )

    result = _executor(tmp_path, runner).apply(malformed)

    assert result.exit_code == 2
    assert not any(command[:1] == ("ufw",) for command in runner.commands)


def test_firewall_rollback_removes_only_rules_added_by_setup(tmp_path: Path) -> None:
    """Removing a pre-existing allow rule during rollback would damage host policy."""
    runner = FakeRunner(ufw_active=True, ufw_rules={443})

    result = _executor(
        tmp_path,
        runner,
        health=lambda *_args: HealthResult(ok=False, detail="invalid health response"),
    ).apply(_plan(tmp_path, mode=SetupMode.SSLIP, firewall_action="allow"))

    assert result.exit_code == 6
    assert runner.ufw_rules == {443}
    assert ("ufw", "--force", "delete", "allow", "80/tcp") in runner.commands
    assert ("ufw", "--force", "delete", "allow", "443/tcp") not in runner.commands


def test_partial_firewall_failure_removes_the_rule_already_added(tmp_path: Path) -> None:
    """A later UFW command failure must not strand an earlier rule from the same setup."""
    runner = FakeRunner(fail_at="ufw-80", ufw_active=True)

    result = _executor(tmp_path, runner).apply(
        _plan(tmp_path, mode=SetupMode.SSLIP, firewall_action="allow")
    )

    assert result.exit_code == 1
    assert runner.ufw_rules == set()
    assert ("ufw", "--force", "delete", "allow", "443/tcp") in runner.commands


def test_public_setup_health_uses_domain_for_host_and_sni_but_connects_locally(
    tmp_path: Path,
) -> None:
    """Using 127.0.0.1 for TLS SNI would fail verification of the managed certificate."""
    runner = FakeRunner()
    endpoints: list[HealthEndpoint] = []

    def health(
        endpoint: HealthEndpoint,
        _username: str,
        _password: str,
        _timeout: float,
    ) -> HealthResult:
        endpoints.append(endpoint)
        return HealthResult(ok=True, detail="healthy")

    result = _executor(tmp_path, runner, health=health).apply(_plan(tmp_path, mode=SetupMode.SSLIP))

    assert result.exit_code == 0
    assert endpoints == [
        HealthEndpoint(
            connect_host="127.0.0.1",
            port=443,
            host="8-8-8-8.sslip.io",
            tls=True,
        )
    ]


def test_credentials_reset_is_atomic_locked_and_prints_nothing(tmp_path: Path) -> None:
    """Credential reset must not bypass the shared lock or reveal before CLI health success."""
    plan = _plan(tmp_path)
    plan.layout.auth_file.parent.mkdir(parents=True)
    plan.layout.auth_file.write_text("admin:originalpass\n", encoding="utf-8")
    plan.layout.auth_file.chmod(0o400)
    runner = FakeRunner(active=True)
    current_uid = os.getuid()
    current_gid = os.getgid()
    context = CredentialsContext(
        layout=plan.layout,
        endpoint=HealthEndpoint("127.0.0.1", 8080, "127.0.0.1", tls=False),
        runner=runner,
        health_check=lambda *_args: HealthResult(ok=True, detail="healthy"),
        effective_uid=lambda: 0,
        root_uid=current_uid,
        resolve_identity=lambda: (current_uid, current_gid),
        sleep=lambda _seconds: None,
    )

    result = reset_credentials(context)

    assert result.exit_code == 0
    assert result.credentials is not None
    assert plan.layout.auth_file.read_text() == f"admin:{result.credentials.password}\n"
    assert stat.S_IMODE(plan.layout.auth_file.stat().st_mode) == 0o400
    assert plan.layout.lock_file.exists()
    assert ("systemctl", "restart", "xferry.service") in runner.commands


def test_failed_credentials_health_restores_auth_and_returns_no_secret(tmp_path: Path) -> None:
    """Failed reset health must put the old credential back and withhold the new one."""
    plan = _plan(tmp_path)
    plan.layout.auth_file.parent.mkdir(parents=True)
    plan.layout.auth_file.write_text("admin:originalpass\n", encoding="utf-8")
    plan.layout.auth_file.chmod(0o400)
    runner = FakeRunner(active=True)
    clock = FakeClock()
    context = CredentialsContext(
        layout=plan.layout,
        endpoint=HealthEndpoint("127.0.0.1", 8080, "127.0.0.1", tls=False),
        runner=runner,
        health_check=lambda *_args: HealthResult(ok=False, detail="invalid health response"),
        effective_uid=lambda: 0,
        root_uid=os.getuid(),
        resolve_identity=lambda: (os.getuid(), os.getgid()),
        readiness_timeout=120.0,
        monotonic=clock.monotonic,
        sleep=clock.sleep,
    )

    result = reset_credentials(context)

    assert result.exit_code == 6
    assert result.credentials is None
    assert plan.layout.auth_file.read_text() == "admin:originalpass\n"
    assert runner.commands.count(("systemctl", "restart", "xferry.service")) == 2


@pytest.mark.parametrize(
    "argv",
    [
        ["setup", "--private", "--public-ip", "8.8.8.8"],
        ["setup", "--private", "--email", "ops@example.com"],
        ["setup", "--domain", "files.example.com", "--public-ip", "8.8.8.8"],
    ],
)
def test_setup_rejects_incompatible_mode_options_before_host_probes(
    argv: list[str], capsys: pytest.CaptureFixture[str]
) -> None:
    """Silently ignoring public-only flags would make setup intent ambiguous."""
    assert main(argv) == 2
    assert "error:" in capsys.readouterr().err


def test_non_root_real_setup_returns_privilege_before_planning_or_host_probes(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Network discovery, UFW, and bind probes must not precede the real-setup root gate."""
    from xferry.management import cli

    monkeypatch.setattr(cli.os, "geteuid", lambda: 1000)
    monkeypatch.setattr(
        cli,
        "_prepare_setup_plan",
        lambda _args: pytest.fail("non-root real setup must not prepare or preflight a plan"),
    )

    assert main(["setup", "--private"]) == 3
    assert "requires root" in capsys.readouterr().err


def test_non_root_setup_dry_run_remains_a_pure_planning_operation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The documented unprivileged dry run must still be able to inspect a complete plan."""
    from xferry.management import cli

    plan = _plan(tmp_path)
    prepared: list[object] = []

    def prepare(args: object) -> tuple[SetupPlan, SetupPreflight]:
        prepared.append(args)
        return plan, _ok_preflight(plan)

    monkeypatch.setattr(cli.os, "geteuid", lambda: 1000)
    monkeypatch.setattr(cli, "_prepare_setup_plan", prepare)

    assert main(["setup", "--private", "--dry-run"]) == 0
    assert len(prepared) == 1
    assert "Dry run" in capsys.readouterr().out


@pytest.mark.parametrize("config_error", [FileNotFoundError("missing"), PermissionError("denied")])
def test_non_root_credentials_returns_privilege_before_reading_managed_config(
    config_error: OSError,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Missing or unreadable config must not mask the credentials privilege contract."""
    from xferry import settings
    from xferry.management import cli

    calls = 0

    def forbidden_load(_path: str) -> object:
        nonlocal calls
        calls += 1
        raise config_error

    monkeypatch.setattr(cli.os, "geteuid", lambda: 1000)
    monkeypatch.setattr(settings, "load_settings_file", forbidden_load)

    assert main(["credentials", "reset"]) == 3
    assert calls == 0
    assert "requires root" in capsys.readouterr().err


def test_root_credentials_keeps_configuration_errors_distinct(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """After the root gate, a missing managed config remains a usage/configuration error."""
    from xferry import settings
    from xferry.management import cli

    monkeypatch.setattr(cli.os, "geteuid", lambda: 0)
    monkeypatch.setattr(
        settings,
        "load_settings_file",
        lambda _path: (_ for _ in ()).throw(FileNotFoundError("missing")),
    )

    assert main(["credentials", "reset"]) == 2
    assert "missing" in capsys.readouterr().err


def test_interactive_active_ufw_prompts_once_for_exact_public_ports(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A vague or repeated firewall prompt would not capture precise operator consent."""
    from xferry.management import cli

    runner = FakeRunner(ufw_active=True)
    seen_plans: list[SetupPlan] = []
    prompts: list[str] = []

    class InteractiveInput:
        @staticmethod
        def isatty() -> bool:
            return True

    def answer(prompt: str) -> str:
        prompts.append(prompt)
        return "yes"

    def preflight(
        plan: SetupPlan,
        _runner: FakeRunner,
        *,
        interactive: bool,
    ) -> SetupPreflight:
        assert interactive is True
        seen_plans.append(plan)
        return _ok_preflight(plan)

    monkeypatch.setattr("xferry.management.system.CommandRunner", lambda: runner)
    monkeypatch.setattr("xferry.management.platform.detect_host_facts", lambda **_kwargs: _facts())
    monkeypatch.setattr("xferry.management.setup.default_setup_preflight", preflight)
    monkeypatch.setattr(cli.sys, "stdin", InteractiveInput())
    monkeypatch.setattr(builtins, "input", answer)

    assert main(["setup", "--public-ip", "8.8.8.8", "--dry-run"]) == 0
    assert prompts == ["Allow UFW rules for 80/tcp and 443/tcp? [y/N] "]
    assert len(seen_plans) == 1
    assert seen_plans[0].firewall_action == "allow"
    assert seen_plans[0].firewall_ports == (443, 80)


def test_success_output_reveals_credentials_once_only_after_health(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Printing before executor health or printing twice would leak unusable credentials."""
    from xferry.management import cli
    from xferry.management.setup import Credentials, SetupResult

    password = "abcdefgh2345"
    plan = _plan(tmp_path)
    monkeypatch.setattr(cli.os, "geteuid", lambda: 0)
    monkeypatch.setattr(cli, "_prepare_setup_plan", lambda _args: (plan, _ok_preflight(plan)))
    monkeypatch.setattr(
        cli,
        "_apply_setup_plan",
        lambda _plan, _preflight: SetupResult(
            exit_code=0,
            message="healthy",
            credentials=Credentials(
                username="admin",
                password=password,
                url="http://127.0.0.1:8080",
            ),
        ),
    )

    assert main(["setup", "--private"]) == 0
    output = capsys.readouterr().out
    assert output.count(password) == 1
    assert "http://127.0.0.1:8080" in output


def test_json_setup_status_excludes_secret_while_one_time_credential_is_separate(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Serializing the generated password would put it into machine logs and reports."""
    from xferry.management import cli
    from xferry.management.setup import Credentials, SetupResult

    password = "abcdefgh2345"
    plan = _plan(tmp_path)
    monkeypatch.setattr(cli.os, "geteuid", lambda: 0)
    monkeypatch.setattr(cli, "_prepare_setup_plan", lambda _args: (plan, _ok_preflight(plan)))
    monkeypatch.setattr(
        cli,
        "_apply_setup_plan",
        lambda _plan, _preflight: SetupResult(
            exit_code=0,
            message="healthy",
            credentials=Credentials(
                username="admin",
                password=password,
                url="http://127.0.0.1:8080",
            ),
        ),
    )

    assert main(["setup", "--private", "--json"]) == 0
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert payload == {
        "exit_code": 0,
        "status": "ok",
        "url": "http://127.0.0.1:8080",
    }
    assert password not in captured.out
    assert "admin" not in captured.out
    assert captured.err.count(password) == 1
    assert captured.err.count("admin") == 1
