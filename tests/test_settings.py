"""Public configuration, automatic paths and exposure-boundary regression tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from xferry.paths import (
    automatic_state_dir,
    default_config_path,
    default_files_dir,
    state_for_config,
)
from xferry.settings import (
    RETIRED_SETTINGS,
    ServerSettings,
    SettingsError,
    load_settings_file,
    load_settings_text,
    resolve_settings,
)
from xferry.settings_schema import SETTING_SPECS


def test_defaults_are_private_and_independent_of_launch_directory(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    first = resolve_settings()
    other = tmp_path / "other"
    other.mkdir()
    monkeypatch.chdir(other)
    second = resolve_settings()
    assert first == second
    assert first.access == "private"
    assert first.host == "127.0.0.1"
    assert first.port == 8080
    assert first.https_mode == "off"
    assert Path(first.files_dir) == default_files_dir()
    assert not Path(first.root_dir).is_relative_to(Path(first.files_dir))


def test_precedence_preserves_explicit_default_false_and_zero(tmp_path):
    path = tmp_path / "xferry.ini"
    path.write_text(
        "[server]\naccess = lab\nport = 9000\nencrypted_uploads = true\n"
        "[limits]\nupload_file_limit = 15\nworkers = 4\n",
        encoding="utf-8",
    )
    # workers belongs to server, so unknown section/key combinations stay errors.
    with pytest.raises(SettingsError, match="unknown config key"):
        load_settings_file(path)
    path.write_text(
        "[server]\naccess = lab\nport = 9000\nencrypted_uploads = true\nworkers = 4\n"
        "[limits]\nupload_file_limit = 15\n",
        encoding="utf-8",
    )
    settings = resolve_settings(
        file_settings=load_settings_file(path, validate=False),
        env={"XFERRY_PORT": "9001", "XFERRY_UPLOAD_FILE_LIMIT": "16"},
        cli_values={"port": 8080, "encrypted_uploads": False, "upload_file_limit": 0},
    )
    assert settings.port == 8080
    assert settings.encrypted_uploads is False
    assert settings.upload_file_limit == 0
    assert settings.workers == 4
    assert settings._origins["port"] == "cli"
    assert settings._origins["workers"] == "file"
    assert settings._origins["https_mode"] == "automatic"


@pytest.mark.parametrize("field", sorted(RETIRED_SETTINGS))
def test_retired_names_are_rejected_in_every_public_source(field):
    replacement = RETIRED_SETTINGS[field]
    for action in (
        lambda: load_settings_text(f"[server]\n{field} = user:do-not-print-this\n"),
        lambda: resolve_settings(env={f"XFERRY_{field.upper()}": "user:do-not-print-this"}),
        lambda: resolve_settings(cli_values={field: "user:do-not-print-this"}),
    ):
        with pytest.raises(SettingsError) as error:
            action()
        assert "removed" in str(error.value)
        assert replacement in str(error.value)
        assert "do-not-print-this" not in str(error.value)


@pytest.mark.parametrize("host", ["0.0.0.0", "::", "192.168.1.3", "example.com"])
def test_private_rejects_every_nonloopback_bind(host):
    with pytest.raises(SettingsError, match="loopback"):
        resolve_settings(cli_values={"host": host})


@pytest.mark.parametrize("host", ["127.0.0.1", "127.2.3.4", "::1", "localhost"])
def test_private_accepts_loopback_without_dns(host):
    assert resolve_settings(cli_values={"host": host}).host == host


def test_lab_must_be_explicit_to_use_plain_http_on_network():
    settings = resolve_settings(cli_values={"access": "lab", "host": "0.0.0.0"})
    assert settings.https_mode == "off"
    assert settings.public_direct is False
    assert {warning.code for warning in settings.runtime_posture().warnings} == {
        "lab-network-access"
    }


def test_public_has_secure_defaults_and_requires_credentials():
    with pytest.raises(SettingsError, match="auth_file"):
        resolve_settings(cli_values={"access": "public"})
    settings = resolve_settings(cli_values={"access": "public", "auth_file": "/private/auth"})
    assert settings.public_direct is True
    assert settings.https_mode == "auto"
    assert settings.sslip is True
    assert settings.host == "0.0.0.0"
    assert settings.port == 8443
    assert settings.body_memory_budget_mb == 512
    assert settings.upload_storage_limit_mb == 4096
    assert settings._origins["host"] == "automatic"


@pytest.mark.parametrize("mode", ["off", "self-signed"])
def test_public_cannot_disable_verified_https(mode):
    with pytest.raises(SettingsError, match="verified HTTPS"):
        resolve_settings(cli_values={"access": "public", "https_mode": mode, "auth_file": "auth"})


@pytest.mark.parametrize(
    "values,message",
    [
        ({"https_mode": "domain"}, "requires domain"),
        ({"https_mode": "files"}, "cert_file and key_file"),
        ({"https_mode": "files", "cert_file": "cert"}, "cert_file and key_file"),
        ({"cert_file": "cert", "key_file": "key"}, "https_mode = files"),
        ({"https_mode": "auto", "domain": "example.com"}, "https_mode = domain"),
        (
            {"https_mode": "domain", "domain": "example.com", "public_ip": "1.2.3.4"},
            "https_mode = auto",
        ),
        ({"email": "user@example.com"}, "https_mode = auto or domain"),
        ({"acme_server": "http://example.com/directory"}, "HTTPS directory"),
    ],
)
def test_tls_modes_reject_incompatible_inputs(values, message):
    with pytest.raises(SettingsError, match=message):
        resolve_settings(cli_values=values)


def test_domain_and_files_modes_derive_runtime_switches():
    domain = resolve_settings(cli_values={"https_mode": "domain", "domain": "files.example.com"})
    assert domain.letsencrypt and not domain.sslip
    files = resolve_settings(
        cli_values={"https_mode": "files", "cert_file": "cert", "key_file": "key"}
    )
    assert files.effective_tls_enabled()
    assert not files.letsencrypt and not files.sslip


def test_public_domain_posture_shows_connectable_hostname_instead_of_bind_address():
    settings = resolve_settings(
        cli_values={
            "access": "public",
            "https_mode": "domain",
            "domain": "files.example.com",
            "auth_file": "/private/auth",
        }
    )
    assert settings.host == "0.0.0.0"
    assert settings.runtime_posture().effective_url == "https://files.example.com:8443"
    assert settings.runtime_posture().https_mode == "domain"
    assert settings._origins["https_mode"] == "cli"


def test_acme_staging_has_one_explicit_setting():
    settings = resolve_settings(cli_values={"https_mode": "auto", "acme_server": "staging"})
    assert "staging" in settings.acme_server
    assert settings.acme_staging is False


@pytest.mark.parametrize(
    "values,message",
    [
        ({"body_timeout": 0}, "body timeouts"),
        ({"body_idle_timeout": 0}, "body timeouts"),
        ({"stream_send_timeout": 0}, "stream send timeouts"),
        ({"cors_origin": "*"}, "wildcard"),
        ({"plugin_allowlist": ("example:plugin",)}, "disables plugins"),
        (
            {"upload_storage_limit_mb": 0, "upload_file_limit": 0, "upload_reserve_free_mb": 0},
            "greater than zero",
        ),
    ],
)
def test_public_guards_are_mandatory(values, message):
    with pytest.raises(SettingsError, match=message):
        resolve_settings(cli_values={"access": "public", "auth_file": "auth", **values})


def test_external_storage_quota_is_an_explicit_public_alternative():
    settings = resolve_settings(
        cli_values={
            "access": "public",
            "auth_file": "auth",
            "upload_storage_limit_mb": 0,
            "upload_file_limit": 0,
            "upload_reserve_free_mb": 0,
            "upload_quota_externally_managed": True,
        }
    )
    assert settings.public_direct


def test_public_wildcard_file_certificates_require_allowed_hosts():
    values = {
        "access": "public",
        "https_mode": "files",
        "cert_file": "cert",
        "key_file": "key",
        "auth_file": "auth",
    }
    with pytest.raises(SettingsError, match="allowed_hosts"):
        resolve_settings(cli_values=values)
    assert resolve_settings(
        cli_values={**values, "allowed_hosts": ("files.example.com",)}
    ).public_direct


def test_lists_keep_their_distinct_grammars():
    settings = load_settings_text(
        "[security]\nallowed_hosts = first.example\tsecond.example\n"
        "[plugins]\nplugin_allowlist = first:plugin, second:plugin\n"
    )
    assert settings.allowed_hosts == ("first.example", "second.example")
    assert settings.plugin_allowlist == ("first:plugin", "second:plugin")
    reset = resolve_settings(file_settings=settings, env={"XFERRY_ALLOWED_HOSTS": ""})
    assert reset.allowed_hosts == ()
    with pytest.raises(SettingsError):
        load_settings_text("[security]\nallowed_hosts = first.example,second.example\n")


def test_automatic_limits_are_effective_in_posture_and_runtime():
    settings = resolve_settings(cli_values={"workers": 6, "max_size_mb": 25})
    posture = settings.runtime_posture()
    config = settings.to_server_config()
    assert posture.body_admission_budget_mb == 150
    assert posture.max_websocket_connections == 3
    assert config.limits.body_memory_budget == 150 * 1024 * 1024
    assert config.websocket.max_connections == 3
    assert "Access: private" in "\n".join(posture.render_lines())
    assert "custom/legacy" not in "\n".join(posture.render_lines())
    serialized = posture.to_dict()
    assert serialized["access"] == "private"
    assert serialized["https_mode"] == "off"
    assert not {"preset", "public_direct", "public_direct_validated"} & serialized.keys()


def test_redacted_settings_only_include_public_metadata():
    rendered = ServerSettings(auth="user:secret", auth_file="/private/auth").to_redacted_dict()
    assert set(rendered) == {spec.name for spec in SETTING_SPECS} | {"effective_tls"}
    assert "secret" not in json.dumps(rendered)
    assert rendered["auth_file"] == "/private/auth"


def test_relative_files_are_explicit_and_share_the_default_profile_state(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.chdir(tmp_path)
    first = resolve_settings(cli_values={"files_dir": "one"})
    second = resolve_settings(cli_values={"files_dir": "two"})
    assert Path(first.files_dir) == tmp_path / "one"
    assert first.root_dir == second.root_dir
    assert Path(first.root_dir) == automatic_state_dir(tmp_path / "one")


def test_config_identity_is_retained_across_deferred_validation(tmp_path):
    files = tmp_path / "shared"
    first_path = tmp_path / "one.ini"
    second_path = tmp_path / "two.ini"
    text = f"[server]\nfiles_dir = {files}\n"
    first_path.write_text(text)
    second_path.write_text(text)
    first = resolve_settings(file_settings=load_settings_file(first_path, validate=False))
    second = resolve_settings(file_settings=load_settings_file(second_path, validate=False))
    assert first.root_dir != second.root_dir
    assert Path(first.root_dir) == automatic_state_dir(files, first_path)


def test_first_default_profile_save_keeps_existing_private_state(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    initial = resolve_settings()
    config = default_config_path()
    config.parent.mkdir(parents=True)
    config.write_text("[server]\nport = 8080\n")
    saved = load_settings_file(config)
    assert saved.root_dir == initial.root_dir
    config.write_text(f"[server]\nfiles_dir = {tmp_path / 'new-share'}\n")
    changed = load_settings_file(config)
    assert changed.root_dir == initial.root_dir
    assert changed.files_dir != initial.files_dir


def test_migrated_private_state_is_used_without_legacy_setting(tmp_path):
    path = tmp_path / "xferry.ini"
    files = tmp_path / "uploads"
    state = tmp_path / "old-root"
    path.write_text(f"[server]\nfiles_dir = {files}\n")
    sidecar = path.with_name(f".{path.name}.state.json")
    sidecar.write_text(json.dumps({"schema": 1, "state_dir": str(state), "files_dir": str(files)}))
    assert state_for_config(path) == state
    assert Path(load_settings_file(path).root_dir) == state
    assert (
        Path(load_settings_file(path, state_dir=tmp_path / "override").root_dir)
        == tmp_path / "override"
    )


@pytest.mark.parametrize(
    "content",
    ["{}", "not json", '{"schema":1,"state_dir":"relative","files_dir":"/files"}', "x" * 16385],
)
def test_invalid_state_context_is_rejected(tmp_path, content):
    path = tmp_path / "xferry.ini"
    path.with_name(f".{path.name}.state.json").write_text(content)
    with pytest.raises(ValueError, match="state context"):
        state_for_config(path)


def test_state_context_cannot_be_a_symlink(tmp_path):
    path = tmp_path / "xferry.ini"
    target = tmp_path / "other"
    target.write_text("{}")
    path.with_name(f".{path.name}.state.json").symlink_to(target)
    with pytest.raises(ValueError, match="state context"):
        state_for_config(path)


def test_configuration_and_private_state_cannot_be_downloadable(tmp_path):
    path = tmp_path / "xferry.ini"
    path.write_text(f"[server]\nfiles_dir = {tmp_path}\n")
    with pytest.raises(SettingsError, match="outside the public"):
        load_settings_file(path)
    with pytest.raises(ValueError, match="separate"):
        resolve_settings(
            cli_values={"files_dir": str(tmp_path)}, state_dir=tmp_path
        ).to_server_config()


@pytest.mark.parametrize(
    "values",
    [
        {"access": "invalid"},
        {"https_mode": "invalid"},
        {"log_level": "invalid"},
        {"log_format": "invalid"},
        {"unknown": 1},
    ],
)
def test_unknown_values_are_rejected(values):
    with pytest.raises(SettingsError):
        resolve_settings(cli_values=values)


@pytest.mark.parametrize("validate", [False, True])
@pytest.mark.parametrize("explicit_state", [None, "/explicit-xferry-state"])
def test_packaged_state_or_explicit_override_does_not_read_protected_migration_context(
    tmp_path, monkeypatch, validate, explicit_state
):
    path = tmp_path / "xferry.ini"
    path.write_text(f"[server]\nfiles_dir = {tmp_path / 'files'}\n")
    sidecar = path.with_name(f".{path.name}.state.json")
    sidecar.write_text(
        json.dumps({"schema": 1, "state_dir": "/old-state", "files_dir": "/old-files"})
    )
    reads = []
    real_open = Path.open

    def protected_context(candidate, *args, **kwargs):
        if candidate == sidecar:
            reads.append(candidate)
            raise PermissionError("migration context belongs to root")
        return real_open(candidate, *args, **kwargs)

    monkeypatch.setattr(Path, "open", protected_context)
    monkeypatch.setenv("XFERRY_STATE_HOME", "/var/lib/xferry")
    loaded = load_settings_file(path, validate=validate, state_dir=explicit_state)
    expected = explicit_state or "/var/lib/xferry"
    assert loaded.root_dir == expected
    resolved = resolve_settings(file_settings=loaded)
    assert resolved.root_dir == expected
    assert str(resolved.to_server_config().root_dir) == expected
    assert reads == []

    if explicit_state is None:
        monkeypatch.delenv("XFERRY_STATE_HOME")
        with pytest.raises(ValueError, match="migrated state context"):
            load_settings_file(path, validate=validate)
        assert reads == [sidecar]


def test_packaged_state_takes_precedence_over_deferred_portable_migration_state(
    tmp_path, monkeypatch
):
    monkeypatch.delenv("XFERRY_STATE_HOME", raising=False)
    path = tmp_path / "xferry.ini"
    path.write_text(f"[server]\nfiles_dir = {tmp_path / 'files'}\n")
    state = tmp_path / "portable-state"
    path.with_name(f".{path.name}.state.json").write_text(
        json.dumps({"schema": 1, "state_dir": str(state), "files_dir": str(tmp_path / "files")})
    )
    deferred = load_settings_file(path, validate=False)
    assert deferred.root_dir == str(state)
    assert resolve_settings(file_settings=deferred).root_dir == str(state)
    monkeypatch.setenv("XFERRY_STATE_HOME", "/var/lib/xferry")
    assert resolve_settings(file_settings=deferred).root_dir == "/var/lib/xferry"


def test_explicit_state_survives_deferred_text_loading_and_packaging_environment(monkeypatch):
    deferred = load_settings_text(
        "[server]\nport = 8080\n", validate=False, state_dir="/explicit-state"
    )
    monkeypatch.setenv("XFERRY_STATE_HOME", "/var/lib/xferry")
    assert resolve_settings(file_settings=deferred).root_dir == "/explicit-state"
    assert resolve_settings(file_settings=deferred, state_dir="/new-explicit-state").root_dir == (
        "/new-explicit-state"
    )
