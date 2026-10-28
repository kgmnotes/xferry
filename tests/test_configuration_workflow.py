"""Configuration edits preserve operator choices and never leak credentials."""

from __future__ import annotations

import json
import stat
from pathlib import Path
from types import SimpleNamespace

import pytest

from xferry.management.cli import main
from xferry.management.configuration import (
    change_configuration,
    configuration_diff,
    describe_settings,
    edit_ini,
    parse_assignments,
    reset_portable_password,
    resolve_with_origins,
)
from xferry.management.wizard import configure, menu
from xferry.settings import SettingsError, load_settings_text
from xferry.settings_schema import SETTING_SPECS


def test_editor_preserves_unmodified_text_and_explicit_defaults() -> None:
    source = (
        "# operator comment\n[server]\nport: 8080\nlog_level = info\n"
        "\n[limits]\n# keep this\nworkers = 3\n"
    )
    # workers belongs to server, so an invalid unknown-section assignment fails
    # rather than being silently moved or dropped.
    with pytest.raises(SettingsError):
        edit_ini(source, {"port": "18080"})
    source = source.replace("workers = 3", "max_size_mb = 3")
    edited = edit_ini(source, {"port": "18080", "encrypted_uploads": "true"})
    assert "# operator comment\n[server]\nport: 18080\nlog_level = info\n" in edited
    assert "# keep this\nmax_size_mb = 3\n" in edited
    assert edited.count("[server]") == 1
    assert load_settings_text(edited).encrypted_uploads


def test_editor_replaces_multiline_value_without_stale_continuations() -> None:
    source = (
        "[security]\nallowed_hosts = example.test\n    second.test\n# retain\n[server]\nport = 8080"
    )
    edited = edit_ini(source, {"allowed_hosts": "new.test", "max_size_mb": "10"})
    assert "second.test" not in edited
    assert "# retain" in edited
    assert load_settings_text(edited).allowed_hosts == ("new.test",)


def test_editor_serializes_typed_values_using_the_runtime_grammar() -> None:
    edited = edit_ini(
        "",
        {
            "access": "private",
            "https_mode": "off",
            "allowed_hosts": ("localhost", "example.test"),
            "domain": None,
        },
    )
    settings = load_settings_text(edited)
    assert settings.access == "private" and settings.https_mode == "off"
    assert settings.allowed_hosts == ("localhost", "example.test")
    assert settings.domain is None


def test_origins_track_explicit_default_and_layers() -> None:
    settings, origins = resolve_with_origins(
        "[server]\naccess = private\nport = 8080\n[security]\nauth_file = /private/auth\n",
        env={"XFERRY_LOG_LEVEL": "warning", "XFERRY_PORT": "18080"},
        cli_values={"log_level": "info"},
    )
    assert settings.port == 18080 and origins["port"] == "environment"
    assert origins["log_level"] == "cli" and origins["auth_file"] == "file"
    assert origins["https_mode"] == "automatic"


def test_complete_reference_and_diff_redact_migration_secret() -> None:
    rows = describe_settings("", all_settings=True)
    assert {row["name"] for row in rows} == {spec.name for spec in SETTING_SPECS}
    assert all(row["description"] and row["source"] and row["example"] for row in rows)
    source = "[security]\nauth = operator:very-sensitive-password\n"
    diff = configuration_diff(
        source, source.replace("operator:very-sensitive-password", "other:secret")
    )
    assert "very-sensitive-password" not in diff and "other:secret" not in diff


@pytest.mark.parametrize("assignment", ["auth=user:password", "port=80\nquiet=true", "typo=1"])
def test_unsafe_and_unknown_assignments_rejected(assignment: str) -> None:
    with pytest.raises(SettingsError):
        parse_assignments([assignment])


def test_invalid_config_edit_and_cancel_do_not_change_source(tmp_path: Path) -> None:
    path = tmp_path / "config.ini"
    original = "# keep\n[server]\nport = 8080\n"
    path.write_text(original)
    with pytest.raises(SettingsError):
        change_configuration(path, {"port": "99999"})
    assert path.read_text() == original
    result = change_configuration(path, {"port": "18080"}, confirm=lambda _diff: False)
    assert result.exit_code == 0 and not result.changed
    assert path.read_text() == original


def test_portable_edit_preserves_permissions_and_reports_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "config.ini"
    path.write_text("# retained\n[server]\nport = 8080\n")
    path.chmod(0o640)
    monkeypatch.setenv("XFERRY_PORT", "18081")
    result = change_configuration(path, {"port": "18080"})
    assert result.changed and not result.applied
    assert "Environment overrides" in result.message
    assert load_settings_text(path.read_text()).port == 18080
    assert stat.S_IMODE(path.stat().st_mode) == 0o640
    assert "# retained" in path.read_text()


def test_public_files_folder_cannot_include_config_file(tmp_path: Path) -> None:
    path = tmp_path / "config.ini"
    path.write_text("[server]\naccess = private\n")
    with pytest.raises(SettingsError, match="configuration file"):
        change_configuration(path, {"files_dir": str(tmp_path)})


def test_config_cli_interspersed_flags_dry_run_and_json(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = tmp_path / "config.ini"
    assert main(["config", "set", "--config", str(path), "--dry-run", "port=18080"]) == 0
    assert not path.exists()
    capsys.readouterr()
    assert main(["config", "set", "port=18080", "--config", str(path), "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["changed"]
    assert main(["config", "explain", "--config", str(path), "--json", "port"]) == 0
    row = json.loads(capsys.readouterr().out)[0]
    assert row["name"] == "port" and row["source"] == "file"


def test_config_cli_does_not_load_linux_backend_for_portable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    import sys

    monkeypatch.setattr(sys, "platform", "win32")
    path = tmp_path / "config.ini"
    path.write_text("[server]\nport = 8080\n")
    assert main(["config", "show", "--all", "--config", str(path), "--json"]) == 0
    assert json.loads(capsys.readouterr().out)


def test_docker_cli_detects_backend_and_applies_changes_automatically(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    import xferry.management.docker_deploy as docker

    (tmp_path / ".xferry-deployment.json").write_text("{}")
    path = tmp_path / "xferry.ini"
    path.write_text("[server]\naccess = lab\n")
    calls = []

    def deploy(output, **kwargs):
        calls.append((output, kwargs))
        return SimpleNamespace(exit_code=0, message="healthy")

    monkeypatch.setattr(docker, "deploy_docker", deploy)
    assert main(["config", "set", "--config", str(path), "workers=8", "--json"]) == 0
    assert calls[0][0] == tmp_path
    assert calls[0][1]["settings_changes"] == {"workers": "8"}
    assert json.loads(capsys.readouterr().out)["exit_code"] == 0


def test_docker_show_reports_host_path_and_retains_runtime_path(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (tmp_path / "xferry.ini").write_text("[server]\naccess = lab\nfiles_dir = /data/files\n")
    host = tmp_path / "host-files"
    (tmp_path / ".xferry-deployment.json").write_text(json.dumps({"files_dir": str(host)}))
    assert main(["config", "show", "--config", str(tmp_path / "xferry.ini"), "--json"]) == 0
    rows = json.loads(capsys.readouterr().out)
    folder = next(row for row in rows if row["name"] == "files_dir")
    assert folder["value"] == str(host)
    assert folder["runtime_value"] == "/data/files"


def test_cancel_new_wizard_creates_nothing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "not-created" / "config.ini"
    monkeypatch.setattr("builtins.input", lambda _prompt: "0")
    assert configure(path, "portable", "en") == 0
    assert not path.parent.exists()


def test_wizard_can_correct_invalid_draft_before_saving(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "config.ini"
    path.write_text("[server]\nport = 8080\n")
    answers = iter(["2", "-1", "2", "10", "9", "yes"])
    monkeypatch.setattr("builtins.input", lambda _prompt: next(answers))
    assert configure(path, "portable", "en") == 0
    assert load_settings_text(path.read_text()).max_size_mb == 10


def test_menu_foreground_uses_saved_configuration(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import xferry.management.instances as instances

    saved = tmp_path / "xferry.ini"
    saved.write_text("[server]\nport = 18081\n")
    monkeypatch.setattr(instances, "foreground_config", lambda: saved)
    monkeypatch.setattr("builtins.input", lambda _prompt: "2")
    invocations = []
    assert menu("en", lambda argv: invocations.append(argv) or 0) == 0
    assert invocations == [["run", "--config", str(saved)]]


@pytest.mark.parametrize("restart_fails", [False, True])
def test_managed_apply_restores_config_on_failure_and_preserves_stopped_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, restart_fails: bool
) -> None:
    from contextlib import nullcontext

    import xferry.management.configuration as configuration
    import xferry.management.model as model
    import xferry.management.system as system

    path = tmp_path / "config.ini"
    original = "[server]\nport = 8080\n"
    path.write_text(original)
    layout = SimpleNamespace(
        config_file=path,
        data_root=tmp_path / "state",
        lock_file=tmp_path / "lock",
        current_executable=tmp_path / "xferry",
        auth_file=tmp_path / "auth",
    )
    calls = []

    class Runner:
        def run(self, argv):
            calls.append(tuple(argv))
            if "is-active" in argv:
                return SimpleNamespace(returncode=0 if restart_fails else 3)
            if "restart" in argv:
                return SimpleNamespace(returncode=1)
            return SimpleNamespace(returncode=0)

    monkeypatch.setattr(configuration.os, "geteuid", lambda: 0)
    monkeypatch.setattr(model, "ManagedLayout", lambda: layout)
    monkeypatch.setattr(system, "CommandRunner", Runner)
    monkeypatch.setattr(system, "managed_mutation", lambda _path: nullcontext())
    # Keep transaction semantics real while avoiding host-privileged chown.
    original_transaction = system.FilesystemTransaction
    monkeypatch.setattr(
        system, "FilesystemTransaction", lambda: original_transaction(chown=lambda *_args: None)
    )
    result = configuration.change_configuration(
        path, {"port": "18080"}, target="managed", apply=True
    )
    if restart_fails:
        assert result.exit_code == 1
        assert path.read_text() == original
    else:
        assert result.exit_code == 0
        assert "remains stopped" in result.message
        assert not any("restart" in call for call in calls)


def test_active_managed_changes_apply_without_opt_in(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from contextlib import nullcontext

    import xferry.management.configuration as configuration
    import xferry.management.model as model
    import xferry.management.system as system

    path = tmp_path / "xferry.ini"
    path.write_text("[server]\nport = 8080\n")
    auth = tmp_path / "auth"
    auth.write_text("admin:abcdefgh2345\n")
    layout = SimpleNamespace(
        config_file=path,
        lock_file=tmp_path / "lock",
        data_root=tmp_path / "state",
        auth_file=auth,
        current_executable=tmp_path / "xferry",
    )
    calls = []

    class Runner:
        def run(self, argv):
            calls.append(tuple(argv))
            return SimpleNamespace(returncode=0)

    monkeypatch.setattr(configuration.os, "geteuid", lambda: 0)
    monkeypatch.setattr(model, "ManagedLayout", lambda: layout)
    monkeypatch.setattr(system, "CommandRunner", Runner)
    monkeypatch.setattr(system, "managed_mutation", lambda _path: nullcontext())
    transaction = system.FilesystemTransaction
    monkeypatch.setattr(system, "FilesystemTransaction", lambda: transaction(chown=lambda *_: None))
    monkeypatch.setattr(
        "xferry.management.setup._wait_for_health",
        lambda *_a, **_kw: SimpleNamespace(health=SimpleNamespace(ok=True)),
    )
    result = change_configuration(path, {"port": "18080"}, target="managed")
    assert result.exit_code == 0 and result.applied
    assert ("systemctl", "restart", "xferry.service") in calls
    assert load_settings_text(path.read_text()).port == 18080


def test_portable_password_is_private_and_configured_without_secret_in_repr(tmp_path: Path) -> None:
    path = tmp_path / "xferry.ini"
    path.write_text("# keep\n[server]\naccess = private\n")
    result = reset_portable_password(path)
    assert result.exit_code == 0 and result.password and len(result.password) == 12
    assert result.password not in repr(result)
    assert result.password not in path.read_text()
    settings = load_settings_text(path.read_text())
    auth = Path(settings.auth_file)
    assert auth.read_text() == f"admin:{result.password}\n"
    assert stat.S_IMODE(auth.stat().st_mode) == 0o600
    assert "# keep" in path.read_text()
    assert settings.auth is None


def test_portable_password_failure_restores_prior_auth(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import xferry.management.configuration as configuration

    path = tmp_path / "xferry.ini"
    auth = tmp_path / "xferry.auth"
    before = f"[security]\nauth_file = {auth}\n"
    path.write_text(before)
    auth.write_text("admin:previous-password\n")
    original_write = configuration._atomic_write
    failed = False

    def write(target, data, **kwargs):
        nonlocal failed
        if target == path and not failed:
            failed = True
            raise OSError("simulated disk error")
        return original_write(target, data, **kwargs)

    monkeypatch.setattr(configuration, "_atomic_write", write)
    result = reset_portable_password(path)
    assert result.exit_code == 1 and result.password is None
    assert auth.read_text() == "admin:previous-password\n"
    assert path.read_text() == before


def test_managed_bind_source_cannot_publish_new_certificate_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from contextlib import nullcontext

    import xferry.management.configuration as configuration
    import xferry.management.model as model
    import xferry.management.system as system

    path = tmp_path / "xferry.ini"
    state = tmp_path / "private"
    host_files = tmp_path / "public-files"
    host_files.mkdir()
    before = f"[server]\nfiles_dir = {state / 'files'}\n"
    path.write_text(before)
    (tmp_path / "deployment.json").write_text(
        json.dumps({"schema": 1, "kind": "managed", "files_dir": str(host_files)})
    )
    layout = SimpleNamespace(config_file=path, lock_file=tmp_path / "lock", data_root=state)

    class Runner:
        def run(self, _argv):
            return SimpleNamespace(returncode=3)

    monkeypatch.setattr(configuration.os, "geteuid", lambda: 0)
    monkeypatch.setattr(model, "ManagedLayout", lambda: layout)
    monkeypatch.setattr(system, "CommandRunner", Runner)
    monkeypatch.setattr(system, "managed_mutation", lambda _path: nullcontext())
    with pytest.raises(SettingsError, match="certificate, private key or auth"):
        change_configuration(
            path,
            {
                "https_mode": "files",
                "cert_file": str(host_files / "cert.pem"),
                "key_file": str(host_files / "key.pem"),
            },
            target="managed",
            apply=True,
        )
    assert path.read_text() == before


def test_portable_password_rejects_authentication_environment_overrides(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "xferry.ini"
    path.write_text("[server]\nport = 8080\n")
    monkeypatch.setenv("XFERRY_AUTH", "other:secret")
    with pytest.raises(SettingsError, match="environment overrides"):
        reset_portable_password(path)
    assert not (tmp_path / "xferry.auth").exists()


def test_configuration_lock_is_reusable_after_crashed_process(tmp_path: Path) -> None:
    import subprocess
    import sys

    from xferry.management.configuration import _portable_lock

    path = tmp_path / "xferry.ini"
    subprocess.run(
        [
            sys.executable,
            "-c",
            "import os,sys\nfrom pathlib import Path\n"
            "from xferry.management.configuration import _portable_lock\n"
            "with _portable_lock(Path(sys.argv[1])): os._exit(0)\n",
            str(path),
        ],
        check=True,
    )
    assert path.with_name(f".{path.name}.lock").exists()
    with _portable_lock(path):
        with pytest.raises(SettingsError, match="another configuration operation"):
            with _portable_lock(path):
                pytest.fail("concurrent editor acquired a held lock")
    with _portable_lock(path):
        pass


def test_atomic_config_and_password_writes_without_fchmod(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import xferry.management.configuration as configuration

    path = tmp_path / "xferry.ini"
    auth = tmp_path / "auth"
    auth.write_text("admin:old-password\n")
    auth.chmod(0o644)
    path.write_text(f"[security]\nauth_file = {auth}\n")
    path.chmod(0o640)
    monkeypatch.delattr(configuration.os, "fchmod", raising=False)
    result = reset_portable_password(path)
    assert result.exit_code == 0
    assert stat.S_IMODE(path.stat().st_mode) == 0o640
    assert stat.S_IMODE(auth.stat().st_mode) == 0o600
    assert auth.read_text() == f"admin:{result.password}\n"


def test_reference_distinguishes_workflows_and_transfer_rate_units() -> None:
    rows = {row["name"]: row for row in describe_settings("", all_settings=True)}
    assert "files-folder workflow" in rows["files_dir"]["apply"]
    assert "HTTPS workflow" in rows["domain"]["apply"]
    assert "credentials workflow" in rows["auth_file"]["apply"]
    assert rows["workers"]["apply"] == "restart"
    assert rows["body_min_rate"]["unit"] == "bytes/s"


def test_docker_wizard_password_action_calls_dedicated_rotation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    import xferry.management.docker_deploy as docker

    path = tmp_path / "xferry.ini"
    path.write_text("[server]\naccess = lab\nfiles_dir = /data/files\n")
    (tmp_path / ".xferry-deployment.json").write_text(json.dumps({"files_dir": "/host/files"}))
    calls = []

    def deploy(output, **kwargs):
        calls.append((output, kwargs))
        return SimpleNamespace(
            exit_code=0, message="healthy", username="admin", password="abcdefgh2345"
        )

    monkeypatch.setattr(docker, "deploy_docker", deploy)
    answers = iter(["8", "yes"])
    monkeypatch.setattr("builtins.input", lambda _prompt: next(answers))
    assert configure(path, "docker", "en") == 0
    assert calls == [(tmp_path, {"reset_credentials": True})]
    assert "Credentials: admin:abcdefgh2345" in capsys.readouterr().out


@pytest.mark.parametrize("mode", ["automatic", "domain", "private"])
def test_docker_access_wizard_generates_coordinated_deployment_dry_run(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    mode: str,
) -> None:
    import xferry.management.docker_deploy as docker
    import xferry.security.tls as tls

    class Runner:
        def run(self, argv):
            return SimpleNamespace(
                returncode=0,
                stdout="container" if argv[:3] == ("docker", "ps", "-q") else "",
                stderr="",
            )

    output = tmp_path / "deployment"
    files = tmp_path / "existing shared files"
    runner = Runner()
    initial = docker.deploy_docker(
        output,
        files_dir=files,
        private=mode != "private",
        domain="old.example.com" if mode == "private" else None,
        runner=runner,
    )
    assert initial.exit_code == 0, initial.message
    config = output / "xferry.ini"
    config.write_text(
        edit_ini(
            config.read_text(),
            {
                "max_size_mb": 37,
                "workers": 4,
                "upload_storage_limit_mb": 2500,
                "note_count_limit": 51,
            },
        )
    )
    before = config.read_text()
    auth = (output / "secrets/xferry_auth").read_bytes()
    monkeypatch.setattr(tls, "resolve_public_ipv4", lambda: "8.8.8.8")
    real_deploy = docker.deploy_docker
    real_compose = docker._compose
    calls = []
    generated = []

    def capture_compose(*args, **kwargs):
        rendered = real_compose(*args, **kwargs)
        generated.append(json.loads(rendered))
        return rendered

    def dry_deploy(path, **kwargs):
        calls.append(kwargs)
        return real_deploy(path, runner=runner, dry_run=True, **kwargs)

    monkeypatch.setattr(docker, "_compose", capture_compose)
    monkeypatch.setattr(docker, "deploy_docker", dry_deploy)
    answers = {
        "automatic": ["6", "1", "", "9", "yes"],
        "domain": ["6", "2", "files.example.com", "9", "yes"],
        "private": ["6", "3", "9", "yes"],
    }[mode]
    answer_iterator = iter(answers)
    monkeypatch.setattr("builtins.input", lambda _prompt: next(answer_iterator))
    capsys.readouterr()
    assert configure(config, "docker", "en") == 0
    printed = capsys.readouterr().out
    assert "deployment validated" in printed
    changes = calls[0]["settings_changes"]
    candidate = load_settings_text(edit_ini(before, changes))
    assert candidate.max_size_mb == 37
    assert candidate.workers == 4
    assert candidate.upload_storage_limit_mb == 2500
    assert candidate.note_count_limit == 51
    assert candidate.files_dir == "/data/files"
    assert candidate.auth_file == "/run/secrets/xferry_auth"
    assert (output / "secrets/xferry_auth").read_bytes() == auth
    assert config.read_text() == before
    assert candidate.host == "0.0.0.0"
    compose = generated[-1]["services"]["xferry"]
    if mode == "private":
        assert not candidate.public_direct and not candidate.effective_tls_enabled()
        assert candidate.port == 8080 and candidate.acme_http_port == 80
        assert compose["ports"] == ["127.0.0.1:8080:8080"]
        assert '"port": "8080"' in printed
    else:
        hostname = "files.example.com" if mode == "domain" else tls.sslip_domain_for_ip("8.8.8.8")
        assert candidate.public_direct and candidate.effective_tls_enabled()
        assert candidate.port == 8443 and candidate.acme_http_port == 8080
        assert hostname in compose["healthcheck"]["test"][-1]
        assert compose["ports"] == ["80:8080", "443:8443"]
        assert '"port": "8443"' in printed
        if mode == "automatic":
            assert candidate.public_ip == "8.8.8.8"


@pytest.mark.parametrize("target", ["portable", "managed"])
@pytest.mark.parametrize("mode", ["1", "2"])
def test_https_wizard_removes_old_file_certificate_options(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    target: str,
    mode: str,
) -> None:
    from xferry.management.wizard import _tls_changes

    source = (
        "[security]\nauth_file = /private/auth\n"
        f"[tls]\n# keep certificate history\ncert_file = {tmp_path / 'cert.pem'}\n"
        f"key_file = {tmp_path / 'key.pem'}\n"
    )
    answers = iter([mode, "" if mode == "1" else "files.example.com"])
    monkeypatch.setattr("builtins.input", lambda _prompt: next(answers))
    changes = {}
    _tls_changes(changes, "en", target)
    candidate = edit_ini(source, changes)
    assert "# keep certificate history" in candidate
    assert "cert_file =" not in candidate and "key_file =" not in candidate
    settings = load_settings_text(candidate)
    assert settings.cert_file is None and settings.key_file is None
    assert settings.sslip if mode == "1" else settings.letsencrypt
    settings.to_server_config()


def test_clearing_certificate_paths_in_editor_does_not_relax_runtime_validation() -> None:
    from xferry.settings import ServerSettings

    assert edit_ini("", {"cert_file": None, "key_file": ""}) == ""
    with pytest.raises(SettingsError, match="must not be empty"):
        ServerSettings(cert_file="", key_file="").validate()


def test_config_set_clears_certificate_options_but_raw_run_rejects_empty_paths(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = tmp_path / "xferry.ini"
    path.write_text(
        f"[tls]\ncert_file = {tmp_path / 'cert.pem'}\nkey_file = {tmp_path / 'key.pem'}\n"
    )
    assert (
        main(
            [
                "config",
                "set",
                "--config",
                str(path),
                "cert_file=",
                "key_file=",
                "https_mode=self-signed",
            ]
        )
        == 0
    )
    settings = load_settings_text(path.read_text())
    assert (
        settings.https_mode == "self-signed"
        and settings.cert_file is None
        and settings.key_file is None
    )
    capsys.readouterr()
    with pytest.raises(SystemExit) as error:
        main(["run", "--https", "files", "--cert", "", "--key", ""])
    assert error.value.code == 2
    assert "must not be empty" in capsys.readouterr().err


def test_managed_https_resolves_automatic_authority_before_health_check(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from xferry.management.service import _endpoint
    from xferry.management.wizard import _tls_changes

    answers = iter(("1", ""))
    monkeypatch.setattr("builtins.input", lambda _: next(answers))
    monkeypatch.setattr("xferry.security.tls.resolve_public_ipv4", lambda: "8.8.8.8")
    changes: dict[str, str] = {}
    _tls_changes(changes, "en", "managed")
    settings = load_settings_text(edit_ini("[security]\nauth_file = /private/auth\n", changes))
    endpoint = _endpoint(settings)
    assert settings.public_ip == "8.8.8.8"
    assert endpoint is not None and endpoint.host == "8-8-8-8.sslip.io"
