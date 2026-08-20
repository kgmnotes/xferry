"""Managed service operations and diagnostics tests."""

from __future__ import annotations

import json
import os
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Literal, cast

import pytest

from xferry.management import cli
from xferry.management.health import HealthEndpoint, HealthResult
from xferry.management.model import HostFacts, ManagedLayout
from xferry.management.service import (
    DoctorOptions,
    ServiceContext,
    run_doctor,
    service_action,
    service_status,
    stream_logs,
)
from xferry.management.system import CommandResult, CommandRunner


def _facts(*, supported: bool = True) -> HostFacts:
    return HostFacts(
        os_id="ubuntu" if supported else "fedora",
        os_version="24.04" if supported else "40",
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
    )


def _install(layout: ManagedLayout, *, config: str | None = "[server]\nport = 8080\n") -> None:
    layout.current_executable.parent.mkdir(parents=True)
    layout.current_executable.touch()
    if config is not None:
        layout.config_file.parent.mkdir(parents=True)
        layout.config_file.write_text(config, encoding="utf-8")
    layout.auth_file.parent.mkdir(parents=True, exist_ok=True)
    layout.auth_file.write_text("admin:known-password\n", encoding="utf-8")


class FakeRunner:
    """Deterministic systemd and journal boundary without a host service."""

    def __init__(
        self,
        *,
        active: bool = True,
        enabled: bool = True,
        failed: bool = False,
        journal_exit: int = 0,
        action_exit: int = 0,
    ) -> None:
        self.active = active
        self.enabled = enabled
        self.failed = failed
        self.journal_exit = journal_exit
        self.action_exit = action_exit
        self.commands: list[tuple[str, ...]] = []
        self.stream_commands: list[tuple[str, ...]] = []

    def run(self, argv: Sequence[str]) -> CommandResult:
        command = tuple(str(item) for item in argv)
        self.commands.append(command)
        if command == ("systemctl", "is-active", "xferry.service"):
            if self.failed:
                return CommandResult(command, 3, stdout="failed\n")
            return CommandResult(command, 0 if self.active else 3, stdout="active\n")
        if command == ("systemctl", "is-enabled", "xferry.service"):
            return CommandResult(command, 0 if self.enabled else 1)
        if command[:2] == ("systemctl", "show"):
            state = "failed" if self.failed else ("active" if self.active else "inactive")
            return CommandResult(command, 0, stdout=f"{state}\n")
        if command[:1] == ("journalctl",):
            return CommandResult(command, self.journal_exit, stdout="safe log\n")
        if command[:1] == ("systemctl",):
            return CommandResult(command, self.action_exit)
        return CommandResult(command, 0)

    def stream(self, argv: Sequence[str]) -> int:
        command = tuple(str(item) for item in argv)
        self.stream_commands.append(command)
        return self.journal_exit


def _context(
    tmp_path: Path,
    runner: FakeRunner,
    *,
    facts: HostFacts | None = None,
    health: Callable[[HealthEndpoint, str, str, float], HealthResult] | None = None,
    reachable: Callable[[HealthEndpoint, float], bool] | None = None,
    effective_uid: int = 0,
) -> ServiceContext:
    layout = _layout(tmp_path)
    return ServiceContext(
        layout=layout,
        runner=runner,
        facts=lambda: facts or _facts(),
        health_check=health or (lambda *_args: HealthResult(True, "healthy")),
        endpoint_reachable=reachable or (lambda *_args: True),
        effective_uid=lambda: effective_uid,
        root_uid=os.getuid(),
    )


def test_status_uses_only_the_fixed_unit_and_stable_json_fields(tmp_path: Path) -> None:
    """Changing the unit or JSON field names would break scripts and unsafe scoping."""
    runner = FakeRunner()
    context = _context(tmp_path, runner)
    _install(context.layout)

    status = service_status(context)

    assert status.exit_code == 0
    assert status.to_json() == {
        "config": "valid",
        "enabled": "enabled",
        "exit_code": 0,
        "health": "unknown",
        "installation": "installed",
        "service": "active",
        "status": "ok",
    }
    assert runner.commands == [
        (
            str(context.layout.current_executable),
            "run",
            "--config",
            str(context.layout.config_file),
            "--check-config",
        ),
        ("systemctl", "is-enabled", "xferry.service"),
        ("systemctl", "show", "--property=ActiveState", "--value", "xferry.service"),
    ]


def test_non_root_status_stops_before_protected_config_and_systemd_reads(tmp_path: Path) -> None:
    """Protected managed state must map to exit 3 before it can collapse into config exit 2."""
    runner = FakeRunner()
    context = _context(tmp_path, runner, effective_uid=1000)
    _install(context.layout)
    context.layout.config_file.chmod(0)
    context.layout.auth_file.chmod(0)

    status = service_status(context)

    assert status.exit_code == 3
    assert runner.commands == []
    assert not context.layout.lock_file.exists()


@pytest.mark.parametrize("action", ["start", "stop", "restart"])
def test_actions_require_root_before_systemd_mutation(action: str, tmp_path: Path) -> None:
    """Removing the privilege gate would let unprivileged callers alter the service."""
    runner = FakeRunner()
    context = _context(tmp_path, runner, effective_uid=1000)

    assert service_action(action, context) == 3
    assert runner.commands == []


@pytest.mark.parametrize("action", ["start", "stop", "restart"])
def test_actions_lock_and_scope_systemctl_to_xferry_service(action: str, tmp_path: Path) -> None:
    """Dropping the shared lock or fixed unit would race setup or permit unit injection."""
    runner = FakeRunner()
    context = _context(tmp_path, runner)

    assert service_action(action, context) == 0
    assert runner.commands == [("systemctl", action, "xferry.service")]
    assert context.layout.lock_file.is_file()


def test_action_rejects_an_unrecognized_systemctl_verb(tmp_path: Path) -> None:
    """Accepting a new verb without review would widen the managed mutation surface."""
    runner = FakeRunner()
    context = _context(tmp_path, runner)

    assert service_action(cast(Literal["start", "stop", "restart"], "reload"), context) == 2
    assert runner.commands == []


def test_logs_builds_fixed_journal_query_and_propagates_follow_exit(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Changing journal arguments or swallowing its exit status hides operator failures."""
    runner = FakeRunner(journal_exit=7)
    context = _context(tmp_path, runner)

    assert stream_logs(25, "2026-07-30 10:00:00", True, context) == 1
    assert runner.commands == []
    assert runner.stream_commands == [
        (
            "journalctl",
            "--unit",
            "xferry.service",
            "--lines",
            "25",
            "--since",
            "2026-07-30 10:00:00",
            "--follow",
            "--no-pager",
        )
    ]
    assert capsys.readouterr().out == ""


@pytest.mark.parametrize("follow", [False, True])
def test_logs_maps_any_child_failure_to_stable_operation_exit(follow: bool, tmp_path: Path) -> None:
    """Returning a child-specific journal status would violate the stable exit taxonomy."""
    runner = FakeRunner(journal_exit=127)
    context = _context(tmp_path, runner)

    assert stream_logs(10, None, follow, context) == 1


def test_follow_logs_use_the_injected_streaming_boundary_not_capture(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Routing follow mode through run would buffer journal output until the process exits."""
    runner = FakeRunner()
    context = _context(tmp_path, runner)

    assert stream_logs(3, None, True, context) == 0
    assert runner.commands == []
    assert runner.stream_commands == [
        ("journalctl", "--unit", "xferry.service", "--lines", "3", "--follow", "--no-pager")
    ]
    assert capsys.readouterr().out == ""


def test_command_runner_stream_inherits_output_instead_of_requesting_capture(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Adding capture_output here would make an endless journal follow buffer indefinitely."""
    received: list[tuple[tuple[str, ...], bool]] = []

    class Completed:
        returncode = 0

    def fake_run(argv: Sequence[str], *, check: bool) -> Completed:
        received.append((tuple(argv), check))
        return Completed()

    monkeypatch.setattr("xferry.management.system.subprocess.run", fake_run)

    assert CommandRunner().stream(("journalctl", "--follow")) == 0
    assert received == [(("journalctl", "--follow"), False)]


def test_doctor_reports_missing_installation_without_reading_secrets(tmp_path: Path) -> None:
    """Treating an absent managed release as healthy would mislead recovery automation."""
    runner = FakeRunner()
    context = _context(tmp_path, runner)

    report = run_doctor(DoctorOptions(), context)

    assert report.exit_code == 1
    assert report.checks["installation"].status == "missing"
    assert "known-password" not in json.dumps(report.to_json())


@pytest.mark.parametrize("config", [None, "[server]\nport = not-a-port\n"])
def test_doctor_maps_missing_or_invalid_config_to_usage_exit(
    config: str | None, tmp_path: Path
) -> None:
    """Ignoring unavailable config would defer a deterministic operator error to runtime."""
    runner = FakeRunner()
    context = _context(tmp_path, runner)
    _install(context.layout, config=config)

    report = run_doctor(DoctorOptions(), context)

    assert report.exit_code == 2
    assert report.checks["configuration"].status in {"missing", "invalid"}


@pytest.mark.parametrize(("active", "failed"), [(False, False), (False, True)])
def test_doctor_maps_inactive_or_failed_service_to_unhealthy(
    active: bool, failed: bool, tmp_path: Path
) -> None:
    """Downgrading a stopped or failed daemon to success would make monitoring lie."""
    runner = FakeRunner(active=active, failed=failed)
    context = _context(tmp_path, runner)
    _install(context.layout)

    report = run_doctor(DoctorOptions(skip_network=True), context)

    assert report.exit_code == 6
    assert report.checks["service"].status in {"inactive", "failed"}


@pytest.mark.parametrize(("active", "failed"), [(False, False), (False, True)])
def test_default_doctor_prioritizes_inactive_or_failed_service_over_network(
    active: bool, failed: bool, tmp_path: Path
) -> None:
    """A stopped local service must be unhealthy even if its endpoint is unreachable."""
    runner = FakeRunner(active=active, failed=failed)
    context = _context(tmp_path, runner, reachable=lambda *_args: False)
    _install(context.layout)

    assert run_doctor(DoctorOptions(), context).exit_code == 6


def test_deep_doctor_requires_authenticated_ping_and_redacts_auth(tmp_path: Path) -> None:
    """Generic reachability or rendered credentials would hide auth failures or leak secrets."""
    runner = FakeRunner()
    credentials: list[tuple[str, str]] = []

    def failing_health(
        _endpoint: HealthEndpoint, username: str, password: str, _timeout: float
    ) -> HealthResult:
        credentials.append((username, password))
        return HealthResult(False, "invalid health response")

    context = _context(
        tmp_path,
        runner,
        health=failing_health,
    )
    _install(context.layout)

    report = run_doctor(DoctorOptions(deep=True), context)

    assert report.exit_code == 6
    assert report.checks["health"].status == "unhealthy"
    assert credentials == [("admin", "known-password")]
    assert "known-password" not in json.dumps(report.to_json())


def test_default_managed_sslip_doctor_uses_public_hostname_for_tls_identity(
    tmp_path: Path,
) -> None:
    """Loopback SNI cannot verify the certificate issued for the default sslip hostname."""
    runner = FakeRunner()
    endpoints: list[HealthEndpoint] = []

    def reachable(endpoint: HealthEndpoint, _timeout: float) -> bool:
        endpoints.append(endpoint)
        return True

    def health(
        endpoint: HealthEndpoint,
        _username: str,
        _password: str,
        _timeout: float,
    ) -> HealthResult:
        endpoints.append(endpoint)
        return HealthResult(True, "healthy")

    context = _context(tmp_path, runner, health=health, reachable=reachable)
    _install(
        context.layout,
        config=(
            "[server]\n"
            "preset = public-direct\n"
            "public_direct = true\n"
            "host = 0.0.0.0\n"
            "port = 443\n"
            f"root_dir = {context.layout.data_root}\n"
            "[security]\n"
            f"auth_file = {context.layout.auth_file}\n"
            "[tls]\n"
            "sslip = true\n"
            "public_ip = 8.8.8.8\n"
            "acme_http_port = 80\n"
            "[limits]\n"
            "max_size_mb = 100\n"
            "body_memory_budget_mb = 256\n"
            "upload_storage_limit_mb = 4096\n"
            "upload_reserve_free_mb = 512\n"
        ),
    )

    report = run_doctor(DoctorOptions(deep=True), context)

    expected = HealthEndpoint("127.0.0.1", 443, "8-8-8-8.sslip.io", tls=True)
    assert report.exit_code == 0
    assert endpoints == [expected, expected]


def test_non_root_doctor_stops_before_facts_config_auth_and_systemd_reads(tmp_path: Path) -> None:
    """Doctor must return privilege exit 3 without touching any protected managed boundary."""
    runner = FakeRunner()
    context = _context(tmp_path, runner, effective_uid=1000)
    _install(context.layout)
    context.layout.config_file.chmod(0)
    context.layout.auth_file.chmod(0)

    def facts_must_not_run() -> HostFacts:
        raise AssertionError("facts were read before the root gate")

    context = ServiceContext(
        layout=context.layout,
        runner=runner,
        facts=facts_must_not_run,
        effective_uid=lambda: 1000,
    )

    report = run_doctor(DoctorOptions(deep=True), context)

    assert report.exit_code == 3
    assert runner.commands == []
    assert not context.layout.lock_file.exists()


def test_deep_doctor_maps_tls_health_failure_to_network_exit(tmp_path: Path) -> None:
    """Reporting certificate validation as generic unhealthy hides the network remediation path."""
    runner = FakeRunner()
    context = _context(
        tmp_path,
        runner,
        health=lambda *_args: HealthResult(False, "TLS verification failed"),
    )
    _install(context.layout)

    report = run_doctor(DoctorOptions(deep=True), context)

    assert report.exit_code == 5
    assert report.checks["health"].detail == "TLS verification failed"


@pytest.mark.parametrize("auth", [None, "not-a-credential\n"])
def test_deep_doctor_requires_valid_auth_file_without_rendering_it(
    auth: str | None, tmp_path: Path
) -> None:
    """A requested authenticated check without credentials must not report healthy."""
    runner = FakeRunner()
    context = _context(tmp_path, runner)
    _install(context.layout)
    if auth is None:
        context.layout.auth_file.unlink()
    else:
        context.layout.auth_file.write_text(auth, encoding="utf-8")

    report = run_doctor(DoctorOptions(deep=True), context)

    assert report.exit_code == 6
    assert report.checks["health"].status == "unhealthy"
    assert auth is None or auth.strip() not in json.dumps(report.to_json())


@pytest.mark.parametrize(
    ("facts", "reachable", "expected"),
    [(_facts(supported=False), lambda *_args: True, 4), (_facts(), lambda *_args: False, 5)],
)
def test_doctor_maps_platform_and_network_failures(
    facts: HostFacts,
    reachable: Callable[[HealthEndpoint, float], bool],
    expected: int,
    tmp_path: Path,
) -> None:
    """Collapsing platform and network failures into health obscures the remediation path."""
    runner = FakeRunner()
    context = _context(tmp_path, runner, facts=facts, reachable=reachable)
    _install(context.layout)

    assert run_doctor(DoctorOptions(), context).exit_code == expected


def test_skip_network_skips_only_network_checks_and_keeps_local_diagnostics(tmp_path: Path) -> None:
    """Skipping network must not bypass configuration or service-state diagnostics."""
    runner = FakeRunner()
    context = _context(tmp_path, runner, reachable=lambda *_args: False)
    _install(context.layout)

    report = run_doctor(DoctorOptions(deep=True, skip_network=True), context)

    assert report.exit_code == 0
    assert report.checks["configuration"].status == "valid"
    assert report.checks["service"].status == "active"
    assert report.checks["network"].status == "skipped"
    assert report.checks["health"].status == "skipped"


def test_cli_status_and_doctor_render_secret_free_stable_json(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Removing JSON dispatch or including a credential would break machine-safe automation."""
    runner = FakeRunner()
    context = _context(tmp_path, runner)
    _install(context.layout)
    monkeypatch.setattr("xferry.management.service.default_service_context", lambda: context)

    assert cli.main(["status", "--json"]) == 0
    assert json.loads(capsys.readouterr().out) == {
        "config": "valid",
        "enabled": "enabled",
        "exit_code": 0,
        "health": "unknown",
        "installation": "installed",
        "service": "active",
        "status": "ok",
    }

    assert cli.main(["doctor", "--deep", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["checks"]["health"]["status"] == "healthy"
    assert "known-password" not in json.dumps(payload)


def test_cli_logs_forwards_options_and_preserves_journal_exit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Dropping CLI log options or normalizing journal failure to success misleads automation."""
    runner = FakeRunner(journal_exit=7)
    context = _context(tmp_path, runner)
    monkeypatch.setattr("xferry.management.service.default_service_context", lambda: context)

    assert cli.main(["logs", "--lines", "4", "--since", "yesterday", "--follow"]) == 1
    assert runner.commands == []
    assert runner.stream_commands == [
        (
            "journalctl",
            "--unit",
            "xferry.service",
            "--lines",
            "4",
            "--since",
            "yesterday",
            "--follow",
            "--no-pager",
        )
    ]


def test_russian_text_output_translates_doctor_statuses_and_lifecycle_actions(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Interpolating machine enums into Russian templates leaves operator output untranslated."""
    from xferry.management.service import DoctorCheck, DoctorReport, ServiceStatus

    monkeypatch.setattr(
        "xferry.management.service.run_doctor",
        lambda *_args: DoctorReport(
            0,
            {
                "platform": DoctorCheck("supported", "supported platform"),
                "health": DoctorCheck("healthy", "authenticated health check passed"),
            },
        ),
    )
    monkeypatch.setattr(
        "xferry.management.service.service_status",
        lambda *_args: ServiceStatus(0, "installed", "valid", "enabled", "active"),
    )
    monkeypatch.setattr("xferry.management.service.service_action", lambda *_args: 0)

    assert cli.main(["--lang", "ru", "doctor", "--skip-network"]) == 0
    doctor_text = capsys.readouterr().out
    assert "Платформа: поддерживается" in doctor_text
    assert "Здоровье: исправно" in doctor_text
    assert "platform" not in doctor_text
    assert "supported" not in doctor_text
    assert "authenticated health check passed" not in doctor_text

    assert cli.main(["--lang", "ru", "status"]) == 0
    status_text = capsys.readouterr().out
    assert "Установка: установлена" in status_text
    assert "служба: активна" in status_text
    assert "installed" not in status_text

    assert cli.main(["--lang", "ru", "start"]) == 0
    action_text = capsys.readouterr().out
    assert "запуск" in action_text
    assert "start" not in action_text

    assert cli.main(["doctor", "--skip-network"]) == 0
    english_text = capsys.readouterr().out
    assert "Platform: supported" in english_text
    assert "Health: healthy" in english_text
