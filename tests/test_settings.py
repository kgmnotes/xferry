"""Tests for operator-facing configuration loading and validation."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from xferry.settings import (
    BODY_ADMISSION_BUDGET_NOTE,
    WEBSOCKET_WORKER_NOTE,
    LaunchPreset,
    ServerSettings,
    SettingsError,
    derive_runtime_posture,
    load_settings_file,
    load_settings_text,
    resolve_settings,
    sample_config_text,
)


def test_default_settings_match_cli_runtime_defaults() -> None:
    settings = ServerSettings()

    assert settings.host == "127.0.0.1"
    assert settings.port == 8080
    assert settings.root_dir == "."
    assert not hasattr(settings, "profile")
    assert settings.max_size_mb == 100
    assert settings.upload_quota_externally_managed is False
    assert settings.workers == 10

    config = settings.to_server_config()
    assert config.host == "127.0.0.1"
    assert config.port == 8080
    assert config.root_dir == Path().resolve()
    assert config.limits.max_upload_size == 100 * 1024 * 1024
    assert config.limits.max_workers == 10


def test_ini_file_env_and_cli_precedence(tmp_path: Path) -> None:
    config_file = tmp_path / "xferry.ini"
    config_file.write_text(
        """
        [server]
        host = 0.0.0.0
        port = 9000
        root_dir = /srv/xferry

        [limits]
        max_size_mb = 64
        body_memory_budget_mb = 256

        [security]
        auth_file = /etc/xferry/auth
        """,
        encoding="utf-8",
    )

    file_settings = load_settings_file(config_file)
    settings = resolve_settings(
        file_settings=file_settings,
        env={"XFERRY_PORT": "9443"},
        cli_values={"host": "127.0.0.1"},
    )

    assert settings.host == "127.0.0.1"
    assert settings.port == 9443
    assert settings.root_dir == "/srv/xferry"
    assert settings.max_size_mb == 64
    assert settings.body_memory_budget_mb == 256
    assert settings.auth_file == "/etc/xferry/auth"


def test_smuggle_temp_limits_follow_file_env_and_cli_precedence(tmp_path: Path) -> None:
    config_file = tmp_path / "xferry.ini"
    config_file.write_text(
        """
        [limits]
        smuggle_temp_age = 900
        smuggle_temp_file_limit = 12
        smuggle_temp_storage_limit_mb = 64
        """,
        encoding="utf-8",
    )

    settings = resolve_settings(
        file_settings=load_settings_file(config_file),
        env={"XFERRY_SMUGGLE_TEMP_FILE_LIMIT": "24"},
        cli_values={"smuggle_temp_age": 30},
    )

    assert settings.smuggle_temp_age == 30
    assert settings.smuggle_temp_file_limit == 24
    assert settings.smuggle_temp_storage_limit_mb == 64

    config = settings.to_server_config()
    assert config.limits.smuggle_temp_max_age == 30
    assert config.limits.smuggle_temp_file_limit == 24
    assert config.limits.smuggle_temp_storage_limit == 64 * 1024 * 1024


def test_upload_quota_ownership_follows_file_env_and_cli_precedence() -> None:
    file_settings = load_settings_text(
        """
        [limits]
        upload_quota_externally_managed = true
        """
    )

    env_settings = resolve_settings(
        file_settings=file_settings,
        env={"XFERRY_UPLOAD_QUOTA_EXTERNALLY_MANAGED": "false"},
    )
    cli_settings = resolve_settings(
        file_settings=file_settings,
        env={"XFERRY_UPLOAD_QUOTA_EXTERNALLY_MANAGED": "false"},
        cli_values={"upload_quota_externally_managed": True},
    )

    assert file_settings.upload_quota_externally_managed is True
    assert env_settings.upload_quota_externally_managed is False
    assert cli_settings.upload_quota_externally_managed is True


def test_public_direct_requires_real_tls_auth_file_and_memory_budget() -> None:
    settings = ServerSettings(
        host="0.0.0.0",
        port=443,
        public_direct=True,
        tls=True,
        auth_file="/etc/xferry/auth",
        body_memory_budget_mb=512,
    )

    with pytest.raises(SettingsError, match="real TLS"):
        settings.validate()

    settings = ServerSettings(
        host="0.0.0.0",
        port=443,
        public_direct=True,
        sslip=True,
        body_memory_budget_mb=512,
    )

    with pytest.raises(SettingsError, match="auth_file"):
        settings.validate()


def test_public_direct_secure_sslip_validates() -> None:
    settings = ServerSettings(
        host="0.0.0.0",
        port=443,
        public_direct=True,
        sslip=True,
        auth_file="/etc/xferry/auth",
        body_memory_budget_mb=512,
        upload_storage_limit_mb=4096,
    )

    settings.validate()
    config = settings.to_server_config()
    assert config.tls.enabled is True
    assert config.tls.sslip is True
    assert config.auth.auth_file == Path("/etc/xferry/auth")
    assert config.limits.body_memory_budget == 512 * 1024 * 1024


def test_public_direct_rejects_all_zero_upload_disk_controls() -> None:
    settings = ServerSettings(
        public_direct=True,
        sslip=True,
        auth_file="/etc/xferry/auth",
        body_memory_budget_mb=512,
    )

    with pytest.raises(SettingsError, match="upload_quota_externally_managed"):
        settings.validate()


def test_public_direct_allows_explicit_external_upload_quota_ownership() -> None:
    settings = ServerSettings(
        public_direct=True,
        sslip=True,
        auth_file="/etc/xferry/auth",
        body_memory_budget_mb=512,
        upload_quota_externally_managed=True,
    )

    settings.validate()

    assert settings.to_server_config().limits.upload_quota_externally_managed is True


def test_deferred_file_validation_allows_higher_precedence_quota_ownership() -> None:
    config = """
        [server]
        public_direct = true

        [security]
        auth_file = /etc/xferry/auth

        [tls]
        sslip = true

        [limits]
        body_memory_budget_mb = 512
        upload_storage_limit_mb = 0
        upload_file_limit = 0
        upload_reserve_free_mb = 0
        upload_quota_externally_managed = false
    """

    with pytest.raises(SettingsError, match="upload_quota_externally_managed"):
        load_settings_text(config)

    file_settings = load_settings_text(config, validate=False)
    settings = resolve_settings(
        file_settings=file_settings,
        env={"XFERRY_UPLOAD_QUOTA_EXTERNALLY_MANAGED": "true"},
    )

    assert settings.upload_quota_externally_managed is True


def test_public_direct_rejects_plugins_without_explicit_allowance() -> None:
    plugin_settings = ServerSettings(
        public_direct=True,
        sslip=True,
        auth_file="/etc/xferry/auth",
        body_memory_budget_mb=512,
        upload_storage_limit_mb=4096,
        plugin_allowlist=("demo_plugin",),
    )
    with pytest.raises(SettingsError, match="plugins"):
        plugin_settings.validate()


def test_redacted_json_does_not_expose_inline_auth_secret() -> None:
    settings = ServerSettings(auth="admin:secret", auth_file="/etc/xferry/auth")

    rendered = json.dumps(settings.to_redacted_dict())

    assert "secret" not in rendered
    assert '"auth": "***"' in rendered
    assert "/etc/xferry/auth" in rendered


def test_redacted_json_reports_effective_tls_when_enabled_via_sslip() -> None:
    settings = ServerSettings(sslip=True)

    rendered = settings.to_redacted_dict()

    assert rendered["tls"] is False
    assert rendered["effective_tls"] is True


def test_sample_config_is_parseable() -> None:
    config = sample_config_text()

    settings = load_settings_text(config)

    assert settings.root_dir == "/var/lib/xferry"
    assert settings.public_direct is True
    assert settings.auth_file == "/etc/xferry/auth"
    assert settings.upload_storage_limit_mb == 4096
    assert settings.upload_file_limit == 4096
    assert settings.upload_reserve_free_mb == 1024
    assert settings.upload_quota_externally_managed is False


def test_profile_config_key_is_rejected() -> None:
    with pytest.raises(SettingsError, match="unknown config key: server.profile"):
        load_settings_text(
            """
            [server]
            profile = workspace
            """
        )


def test_profile_env_key_is_ignored() -> None:
    settings = resolve_settings(env={"XFERRY_PROFILE": "experimental"})

    assert not hasattr(settings, "profile")


@pytest.mark.parametrize(
    ("config_text", "message"),
    [
        ("[server]\ndir = /srv/legacy", "unknown config key: server.dir"),
        ("[server]\nopen = true", "unknown config key: server.open"),
        ("[cors]\norigin = https://app.example", "unknown config key: cors.origin"),
        ("[plugins]\nallowlist = demo_plugin", "unknown config key: plugins.allowlist"),
        (
            "[plugins]\nallow_public_direct = true",
            "unknown config key: plugins.allow_public_direct",
        ),
        ("[plugins]\noverride_core = true", "unknown config key: plugins.override_core"),
    ],
)
def test_deprecated_config_aliases_are_rejected(config_text: str, message: str) -> None:
    """Accepting shorthand INI keys would preserve the removed config compatibility surface."""
    with pytest.raises(SettingsError, match=message):
        load_settings_text(config_text)


def test_deprecated_env_aliases_are_ignored_without_affecting_settings() -> None:
    """Legacy env names must stay unknown rather than overriding canonical settings."""
    settings = resolve_settings(
        env={
            "XFERRY_DIR": "/srv/legacy",
            "XFERRY_OPEN": "true",
            "XFERRY_ROOT": "/srv/legacy",
        }
    )

    assert settings.root_dir == "."
    assert settings.open_browser is False


def test_canonical_env_names_replace_removed_aliases() -> None:
    settings = resolve_settings(
        env={
            "XFERRY_ROOT_DIR": "/srv/xferry",
            "XFERRY_OPEN_BROWSER": "true",
        }
    )

    assert settings.root_dir == "/srv/xferry"
    assert settings.open_browser is True


def test_no_preset_preserves_legacy_defaults_and_server_config() -> None:
    legacy = ServerSettings()
    resolved = resolve_settings()

    assert resolved.preset is None
    assert resolved == legacy
    assert resolved.to_server_config() == legacy.to_server_config()


@pytest.mark.parametrize("source", ["file", "env", "cli"])
@pytest.mark.parametrize("expected", list(LaunchPreset))
def test_all_presets_are_accepted_from_each_configuration_source(
    source: str,
    expected: LaunchPreset,
) -> None:
    file_text = ""
    env: dict[str, str] = {}
    cli_values: dict[str, object] = {}

    if source == "file":
        file_text = f"[server]\npreset = {expected.value}\n"
    elif source == "env":
        env["XFERRY_PRESET"] = expected.value
    else:
        cli_values["preset"] = expected.value

    if expected is LaunchPreset.PUBLIC_DIRECT:
        cli_values.update(
            {
                "sslip": True,
                "auth_file": "/run/secrets/xferry_auth",
            }
        )

    settings = resolve_settings(
        file_settings=load_settings_text(file_text, validate=False),
        env=env,
        cli_values=cli_values,
    )

    assert settings.preset is expected


def test_preset_selection_uses_file_then_env_then_cli_precedence() -> None:
    file_settings = load_settings_text(
        """
        [server]
        preset = public-direct

        [security]
        auth_file = /run/secrets/xferry_auth

        [tls]
        sslip = true
        """,
        validate=False,
    )

    env_wins = resolve_settings(
        file_settings=file_settings,
        env={"XFERRY_PRESET": "local-secure"},
    )
    cli_wins = resolve_settings(
        file_settings=file_settings,
        env={"XFERRY_PRESET": "local-secure"},
        cli_values={"preset": "local"},
    )

    assert env_wins.preset is LaunchPreset.LOCAL_SECURE
    assert cli_wins.preset is LaunchPreset.LOCAL


@pytest.mark.parametrize(
    ("raw", "source"),
    [
        ("", "file"),
        ("workspace", "file"),
        ("", "env"),
        ("experimental", "env"),
        ("", "cli"),
        ("public", "cli"),
    ],
)
def test_invalid_or_empty_preset_is_rejected(raw: str, source: str) -> None:
    file_settings = None
    env: dict[str, str] = {}
    cli_values: dict[str, object] = {}
    if source == "file":
        with pytest.raises(SettingsError, match="preset must be one of"):
            load_settings_text(f"[server]\npreset = {raw}", validate=False)
        return
    if source == "env":
        env["XFERRY_PRESET"] = raw
    else:
        cli_values["preset"] = raw

    with pytest.raises(SettingsError, match="preset must be one of"):
        resolve_settings(
            file_settings=file_settings,
            env=env,
            cli_values=cli_values,
        )


def test_explicit_file_values_override_higher_source_preset_defaults() -> None:
    file_settings = load_settings_text(
        """
        [server]
        host = 127.0.0.1
        port = 8080

        [tls]
        tls = false

        [security]
        auth =

        [limits]
        upload_storage_limit_mb = 0
        """,
        validate=False,
    )

    settings = resolve_settings(
        file_settings=file_settings,
        env={"XFERRY_PRESET": "local-secure"},
    )

    assert settings.preset is LaunchPreset.LOCAL_SECURE
    assert settings.host == "127.0.0.1"
    assert settings.port == 8080
    assert settings.tls is False
    assert settings.auth is None
    assert settings.upload_storage_limit_mb == 0


@pytest.mark.parametrize("preset_source", ["file", "env", "cli"])
@pytest.mark.parametrize("override_source", ["file", "env", "cli"])
def test_every_explicit_source_overrides_every_preset_source(
    preset_source: str,
    override_source: str,
) -> None:
    server_lines: list[str] = []
    tls_lines: list[str] = []
    env: dict[str, str] = {}
    cli_values: dict[str, object] = {}

    if preset_source == "file":
        server_lines.append("preset = local-secure")
    elif preset_source == "env":
        env["XFERRY_PRESET"] = "local-secure"
    else:
        cli_values["preset"] = "local-secure"

    if override_source == "file":
        tls_lines.append("tls = false")
    elif override_source == "env":
        env["XFERRY_TLS"] = "false"
    else:
        cli_values["tls"] = False

    file_text = ""
    if server_lines:
        file_text += "[server]\n" + "\n".join(server_lines) + "\n"
    if tls_lines:
        file_text += "[tls]\n" + "\n".join(tls_lines) + "\n"

    settings = resolve_settings(
        file_settings=load_settings_text(file_text, validate=False),
        env=env,
        cli_values=cli_values,
    )

    assert settings.preset is LaunchPreset.LOCAL_SECURE
    assert settings.tls is False


def test_file_env_and_cli_values_all_override_public_direct_preset_defaults() -> None:
    file_settings = load_settings_text(
        """
        [server]
        preset = public-direct
        host = 127.0.0.1
        port = 8080
        public_direct = false

        [limits]
        upload_storage_limit_mb = 0
        """,
        validate=False,
    )

    settings = resolve_settings(
        file_settings=file_settings,
        env={"XFERRY_PORT": "9443", "XFERRY_UPLOAD_FILE_LIMIT": "0"},
        cli_values={"host": "localhost", "body_memory_budget_mb": 256},
    )

    assert settings.preset is LaunchPreset.PUBLIC_DIRECT
    assert settings.host == "localhost"
    assert settings.port == 9443
    assert settings.public_direct is False
    assert settings.body_memory_budget_mb == 256
    assert settings.upload_storage_limit_mb == 0
    assert settings.upload_file_limit == 0
    assert "public-direct-hardening-disabled" in {
        warning.code for warning in derive_runtime_posture(settings).warnings
    }


@pytest.mark.parametrize(
    ("file_fragment", "expected"),
    [
        ("[security]\nauth_file = /run/secrets/xferry_auth", "file"),
        ("[tls]\ncert_file = cert.pem\nkey_file = key.pem", "certificate-files"),
        ("[tls]\nletsencrypt = true\ndomain = files.example.com", "acme-domain"),
        ("[tls]\nsslip = true", "acme-sslip"),
    ],
)
def test_explicit_security_alternative_suppresses_local_secure_fallback(
    file_fragment: str,
    expected: str,
) -> None:
    settings = resolve_settings(
        file_settings=load_settings_text(
            f"[server]\npreset = local-secure\n{file_fragment}",
            validate=False,
        )
    )
    posture = derive_runtime_posture(settings)

    if expected == "file":
        assert settings.auth is None
        assert settings.auth_file == "/run/secrets/xferry_auth"
        assert posture.auth_mode == "file"
    else:
        assert settings.tls is False
        assert posture.tls_mode == expected


def test_explicit_auth_conflicts_still_fail_after_preset_resolution() -> None:
    with pytest.raises(SettingsError, match="auth.*auth-file|auth_file"):
        resolve_settings(
            file_settings=load_settings_text(
                """
                [server]
                preset = local-secure

                [security]
                auth_file = /run/secrets/xferry_auth
                """,
                validate=False,
            ),
            env={"XFERRY_AUTH": "admin:explicit"},
        )


def test_public_direct_preset_engages_existing_hardened_validation() -> None:
    with pytest.raises(SettingsError, match="real TLS"):
        resolve_settings(cli_values={"preset": "public-direct"})

    with pytest.raises(SettingsError, match="auth_file"):
        resolve_settings(
            cli_values={
                "preset": "public-direct",
                "sslip": True,
            }
        )

    settings = resolve_settings(
        cli_values={
            "preset": "public-direct",
            "sslip": True,
            "auth_file": "/run/secrets/xferry_auth",
        }
    )

    assert settings.public_direct is True
    assert settings.host == "0.0.0.0"
    assert settings.port == 8443
    assert settings.body_memory_budget_mb == 512
    assert settings.upload_storage_limit_mb == 4096
    assert settings.upload_file_limit == 4096
    assert settings.upload_reserve_free_mb == 1024


@pytest.mark.parametrize(
    "tls_values",
    [
        {"cert_file": "cert.pem", "key_file": "key.pem"},
        {"letsencrypt": True, "domain": "files.example.com"},
        {"sslip": True},
    ],
)
def test_public_direct_preset_accepts_each_real_tls_source(
    tls_values: dict[str, object],
) -> None:
    settings = resolve_settings(
        cli_values={
            "preset": "public-direct",
            "auth_file": "/run/secrets/xferry_auth",
            **tls_values,
        }
    )

    assert settings.public_direct is True
    assert derive_runtime_posture(settings).public_direct_validated is True


def test_runtime_posture_derives_effective_limits_paths_and_security(
    tmp_path: Path,
) -> None:
    settings = resolve_settings(
        cli_values={
            "preset": "local-secure",
            "root_dir": str(tmp_path / "data"),
            "workers": 7,
            "max_size_mb": 12,
        }
    )

    posture = derive_runtime_posture(settings)
    rendered = posture.to_dict()

    assert posture.preset is LaunchPreset.LOCAL_SECURE
    assert posture.effective_url == "https://127.0.0.1:8080"
    assert posture.exposure == "loopback"
    assert posture.data_root == str((tmp_path / "data").resolve())
    assert posture.uploads_path == str((tmp_path / "data" / "uploads").resolve())
    assert posture.notes_path == str((tmp_path / "data" / "notes").resolve())
    assert posture.persistence == "operator-managed"
    assert posture.tls_mode == "self-signed"
    assert posture.auth_mode == "generated"
    assert posture.body_admission_budget_mb == 84
    assert posture.max_websocket_connections == 3
    assert BODY_ADMISSION_BUDGET_NOTE in rendered["notes"]
    assert WEBSOCKET_WORKER_NOTE in rendered["notes"]
    assert "auth" not in rendered


def test_runtime_posture_warns_on_non_loopback_without_breaking_validation() -> None:
    settings = resolve_settings(cli_values={"host": "0.0.0.0"})
    posture = derive_runtime_posture(settings)

    assert posture.exposure == "all-interfaces"
    assert "non-loopback-without-public-direct" in {warning.code for warning in posture.warnings}


@pytest.mark.parametrize(
    ("host", "exposure", "effective_url"),
    [
        ("127.0.0.1", "loopback", "http://127.0.0.1:8080"),
        ("127.8.9.10", "loopback", "http://127.8.9.10:8080"),
        ("localhost", "loopback", "http://localhost:8080"),
        ("::1", "loopback", "http://[::1]:8080"),
        ("0.0.0.0", "all-interfaces", "http://0.0.0.0:8080"),
        ("::", "all-interfaces", "http://[::]:8080"),
        ("192.0.2.10", "network", "http://192.0.2.10:8080"),
        ("files.internal", "network", "http://files.internal:8080"),
    ],
)
def test_runtime_posture_classifies_bind_without_dns_side_effects(
    host: str,
    exposure: str,
    effective_url: str,
) -> None:
    posture = derive_runtime_posture(resolve_settings(cli_values={"host": host}))

    assert posture.exposure == exposure
    assert posture.effective_url == effective_url


def test_runtime_posture_reports_weakened_presets_without_secrets() -> None:
    settings = resolve_settings(
        file_settings=load_settings_text(
            """
            [server]
            preset = local-secure

            [tls]
            tls = false

            [security]
            auth = admin:supersecret
            """,
            validate=False,
        )
    )
    rendered = json.dumps(derive_runtime_posture(settings).to_dict())

    assert "supersecret" not in rendered
    assert '"auth_mode": "inline"' in rendered
    assert "local-secure-weakened" in rendered


def test_redacted_settings_exclude_provenance_and_include_string_preset() -> None:
    settings = resolve_settings(cli_values={"preset": "local-secure"})
    rendered = settings.to_redacted_dict()

    assert rendered["preset"] == "local-secure"
    assert "_explicit_fields" not in rendered


def test_sample_config_selects_public_direct_preset() -> None:
    settings = load_settings_text(sample_config_text())

    assert settings.preset is LaunchPreset.PUBLIC_DIRECT
    assert settings.public_direct is True
