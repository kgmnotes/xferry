from __future__ import annotations

import inspect
import logging
from dataclasses import FrozenInstanceError, is_dataclass, replace
from pathlib import Path
from typing import get_type_hints

import pytest

from xferry.settings import ServerSettings


def test_server_config_models_are_frozen_slotted_and_composed(tmp_path: Path) -> None:
    """Catches mutable runtime config objects leaking across server construction."""
    from xferry.server_config import (
        AuthConfig,
        LoggingConfig,
        PluginConfig,
        ServerConfig,
        ServerLimits,
        TLSConfig,
        WebSocketConfig,
    )

    limits = ServerLimits(max_upload_size=1024, max_workers=2)
    websocket = WebSocketConfig(frame_idle_timeout=1.0)
    tls = TLSConfig()
    auth = AuthConfig()
    logging_config = LoggingConfig()
    plugins = PluginConfig()
    config = ServerConfig(
        host="127.0.0.1",
        port=8080,
        root_dir=tmp_path,
        limits=limits,
        websocket=websocket,
        tls=tls,
        auth=auth,
        logging=logging_config,
        plugins=plugins,
    )

    for model in (limits, websocket, tls, auth, logging_config, plugins, config):
        assert is_dataclass(model)
        assert not hasattr(model, "__dict__")

    with pytest.raises(FrozenInstanceError):
        config.port = 8081  # type: ignore[misc]

    assert config.limits is limits
    assert config.websocket is websocket
    assert config.tls is tls
    assert config.auth is auth
    assert config.logging is logging_config
    assert config.plugins is plugins


def test_server_settings_to_server_config_resolves_units_paths_cors_tls_and_derived_limits(
    tmp_path: Path,
) -> None:
    """Catches settings adapters that return kwargs or defer normalization into the server."""
    settings = ServerSettings(
        host="0.0.0.0",
        port=8443,
        root_dir=str(tmp_path / "site" / ".." / "site"),
        max_size_mb=3,
        upload_storage_limit_mb=7,
        upload_file_limit=9,
        upload_reserve_free_mb=2,
        note_storage_limit_mb=5,
        note_count_limit=6,
        smuggle_temp_age=0,
        smuggle_temp_file_limit=0,
        smuggle_temp_storage_limit_mb=0,
        max_header_size_kb=8,
        body_memory_budget_mb=None,
        body_idle_timeout=0,
        body_timeout=0,
        body_min_rate=12.5,
        stream_send_idle_timeout=1.25,
        stream_send_timeout=0,
        workers=4,
        websocket_frame_idle_timeout=1.0,
        cert_file=str(tmp_path / "cert.pem"),
        key_file=str(tmp_path / "key.pem"),
        auth_file=str(tmp_path / "auth.txt"),
        cors_origin=" https://app.example ,https://admin.example ",
        plugin_allowlist=("tests.fake_plugin:plugin", "tests.fake_plugin:plugin"),
        plugins_override_core=True,
        plugins_allow_public_direct=True,
        quiet=True,
        debug=True,
        open_browser=True,
        json_log=True,
        public_direct=False,
    )

    config = settings.to_server_config()

    assert not hasattr(ServerSettings, "to_server_kwargs")
    assert config.host == "0.0.0.0"
    assert config.port == 8443
    assert config.root_dir == (tmp_path / "site").resolve()
    assert config.limits.max_upload_size == 3 * 1024 * 1024
    assert config.limits.upload_storage_limit == 7 * 1024 * 1024
    assert config.limits.upload_file_limit == 9
    assert config.limits.upload_reserved_free_space == 2 * 1024 * 1024
    assert config.limits.note_storage_limit == 5 * 1024 * 1024
    assert config.limits.note_count_limit == 6
    assert config.limits.smuggle_temp_max_age is None
    assert config.limits.smuggle_temp_file_limit is None
    assert config.limits.smuggle_temp_storage_limit is None
    assert config.limits.max_header_size == 8 * 1024
    assert config.limits.body_memory_budget == 12 * 1024 * 1024
    assert config.limits.body_idle_timeout is None
    assert config.limits.body_timeout is None
    assert config.limits.body_min_rate == 12.5
    assert config.limits.stream_send_idle_timeout == 1.25
    assert config.limits.stream_send_timeout is None
    assert config.limits.max_workers == 4
    assert config.websocket.max_connections == 2
    assert config.websocket.frame_idle_timeout == 1.0
    assert config.tls.enabled is True
    assert config.tls.cert_file == (tmp_path / "cert.pem").resolve()
    assert config.tls.key_file == (tmp_path / "key.pem").resolve()
    assert config.auth.auth is None
    assert config.auth.auth_file == (tmp_path / "auth.txt").resolve()
    assert config.logging.quiet is True
    assert config.logging.debug is True
    assert config.logging.open_browser is True
    assert config.logging.json_log is True
    assert config.cors_origin == "https://app.example,https://admin.example"
    assert config.cors_origins == ("https://app.example", "https://admin.example")
    assert config.plugins.module_entries == ("tests.fake_plugin:plugin",)
    assert config.plugins.override_core is True
    assert config.plugins.allow_public_direct is True
    assert config.public_direct is False


@pytest.mark.parametrize(
    ("tls_lines", "message"),
    [
        ("cert_file =", "provided together"),
        ("key_file =", "provided together"),
        ("cert_file =\nkey_file =", "values must not be empty"),
    ],
    ids=("empty-cert", "empty-key", "both-empty"),
)
def test_ini_explicit_empty_tls_paths_fail_closed(tls_lines: str, message: str) -> None:
    """Catches INI coercion erasing explicitly empty certificate paths."""
    from xferry.settings import SettingsError, load_settings_text

    with pytest.raises(SettingsError, match=message):
        load_settings_text(f"[tls]\n{tls_lines}\n")


def test_direct_server_config_normalizes_disabled_zero_policies_to_none() -> None:
    """Catches direct configs retaining zero where runtime uses disabled/None policy."""
    from xferry.server_config import ServerConfig, ServerLimits, resolve_server_config

    config = resolve_server_config(
        ServerConfig(
            limits=ServerLimits(
                upload_storage_limit=0,
                upload_file_limit=0,
                note_storage_limit=0,
                note_count_limit=0,
                smuggle_temp_max_age=0,
                smuggle_temp_file_limit=0,
                smuggle_temp_storage_limit=0,
            )
        )
    )

    assert config.limits.upload_storage_limit is None
    assert config.limits.upload_file_limit is None
    assert config.limits.note_storage_limit is None
    assert config.limits.note_count_limit is None
    assert config.limits.smuggle_temp_max_age is None
    assert config.limits.smuggle_temp_file_limit is None
    assert config.limits.smuggle_temp_storage_limit is None


def test_direct_public_config_requires_explicit_body_memory_budget(tmp_path: Path) -> None:
    """Catches public-direct silently accepting a worker-derived body budget."""
    from xferry.server_config import (
        AuthConfig,
        ServerConfig,
        ServerLimits,
        TLSConfig,
        resolve_server_config,
    )

    config = ServerConfig(
        public_direct=True,
        limits=ServerLimits(
            max_upload_size=1024,
            max_workers=2,
            body_memory_budget=None,
            upload_storage_limit=1024,
        ),
        tls=TLSConfig(letsencrypt=True, domain="files.example"),
        auth=AuthConfig(auth_file=tmp_path / "auth.txt"),
    )

    with pytest.raises(ValueError, match="body_memory_budget"):
        resolve_server_config(config)


def test_server_constructor_signature_and_cli_construct_with_one_config(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Catches kwargs compatibility constructors and CLI bypassing the config boundary."""
    from xferry import cli
    from xferry.server import XFerryServer
    from xferry.server_config import ServerConfig

    signature = inspect.signature(XFerryServer)
    assert list(signature.parameters) == ["config"]
    parameter = signature.parameters["config"]
    assert parameter.default is inspect.Signature.empty
    assert get_type_hints(XFerryServer.__init__)["config"] is ServerConfig

    received: list[ServerConfig] = []

    class RecordingServer:
        def __init__(self, config: ServerConfig) -> None:
            received.append(config)

        def start(self) -> None:
            return None

        def stop(self) -> None:
            return None

    monkeypatch.setattr(cli, "XFerryServer", RecordingServer)
    assert cli.run_main(["--dir", ".", "--port", "8765"]) == 0

    assert len(received) == 1
    assert isinstance(received[0], ServerConfig)
    assert received[0].port == 8765


@pytest.mark.parametrize("inspection_flag", ["--check-config", "--print-config"])
def test_cli_inspection_rejects_invalid_cors_before_server_construction(
    inspection_flag: str,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Catches check/print branches bypassing shared runtime-config validation."""
    from xferry import cli

    monkeypatch.setattr(
        cli,
        "XFerryServer",
        lambda _config: pytest.fail("inspection must not construct the server"),
    )

    with pytest.raises(SystemExit) as exc_info:
        cli.run_main([inspection_flag, "--cors-origin", "not-an-origin"])

    assert exc_info.value.code == 2
    assert "invalid CORS origin" in capsys.readouterr().err


@pytest.mark.parametrize("inspection_flag", ["--check-config", "--print-config"])
def test_cli_inspection_rejects_invalid_plugin_allowlist_before_import(
    inspection_flag: str,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Catches inspection accepting malformed plugin module declarations."""
    from xferry import cli

    monkeypatch.setenv("XFERRY_PLUGIN_ALLOWLIST", "not-valid!:plugin")
    monkeypatch.setattr(
        cli,
        "XFerryServer",
        lambda _config: pytest.fail("inspection must not construct the server"),
    )
    monkeypatch.setattr(
        "xferry.extensions.importlib.import_module",
        lambda _name: pytest.fail("inspection validation must not import plugins"),
    )

    with pytest.raises(SystemExit) as exc_info:
        cli.run_main([inspection_flag])

    assert exc_info.value.code == 2
    assert "invalid plugin module entry" in capsys.readouterr().err


def test_server_request_cors_uses_resolved_origins_without_reparsing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Catches request handling reparsing the already validated CORS string."""
    from xferry.http import HTTPRequest
    from xferry.server import XFerryServer

    server = XFerryServer(
        ServerSettings(
            root_dir=str(tmp_path),
            quiet=True,
            cors_origin="https://app.example",
        ).to_server_config()
    )
    monkeypatch.setattr(
        "xferry.http.cors.parse_cors_origins",
        lambda _configured: pytest.fail("request CORS must use config.cors_origins"),
    )
    request = HTTPRequest(
        b"GET / HTTP/1.1\r\nHost: server.example\r\nOrigin: https://app.example\r\n\r\n"
    )

    assert server._resolve_cors_origin(request) == "https://app.example"


@pytest.mark.parametrize(
    "invalid_category",
    ["auth", "tls", "cors", "plugin", "public-direct"],
)
def test_each_invalid_config_category_rejects_before_runtime_side_effects(
    invalid_category: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Catches any independent validation category running after runtime setup."""
    from xferry.server import XFerryServer
    from xferry.server_config import (
        AuthConfig,
        LoggingConfig,
        PluginConfig,
        ServerConfig,
        ServerLimits,
        TLSConfig,
        WebSocketConfig,
    )

    root = tmp_path / "missing-root"
    auth_file = tmp_path / "auth.txt"
    auth_file.write_text("operator:secret", encoding="utf-8")
    cert_file = tmp_path / "cert.pem"
    logger = logging.getLogger("xferry")
    original_handlers = list(logger.handlers)
    original_level = logger.level

    import_calls: list[str] = []

    def fail_import(name: str):
        import_calls.append(name)
        raise AssertionError("plugin import must not run for invalid config")

    monkeypatch.setattr("xferry.extensions.importlib.import_module", fail_import)
    monkeypatch.setattr(
        "xferry.server.generate_random_credentials",
        lambda: pytest.fail("auth generation must not run for invalid config"),
    )
    monkeypatch.setattr(
        XFerryServer,
        "_read_auth_file",
        staticmethod(lambda _path: pytest.fail("auth file must not be read for invalid config")),
    )
    monkeypatch.setattr(
        "xferry.server.TLSManager",
        lambda **_kwargs: pytest.fail("TLS manager must not be built for invalid config"),
    )
    monkeypatch.setattr(
        "xferry.server.threading.BoundedSemaphore",
        lambda _value: pytest.fail("semaphores must not be built for invalid config"),
    )

    base = ServerConfig(
        host="127.0.0.1",
        port=8080,
        root_dir=root,
        limits=ServerLimits(
            max_upload_size=1024,
            max_workers=2,
            body_memory_budget=2048,
        ),
        websocket=WebSocketConfig(max_connections=1, frame_idle_timeout=1.0),
        logging=LoggingConfig(quiet=False, debug=True, json_log=True),
    )
    expected_message = invalid_category
    if invalid_category == "auth":
        config = replace(base, auth=AuthConfig(auth="random", auth_file=auth_file))
    elif invalid_category == "tls":
        config = replace(base, tls=TLSConfig(cert_file=cert_file))
        expected_message = "cert"
    elif invalid_category == "cors":
        config = replace(base, cors_origin="not-an-origin")
        expected_message = "CORS"
    elif invalid_category == "plugin":
        config = replace(
            base,
            plugins=PluginConfig(module_entries=("not-valid!:plugin",)),
        )
    else:
        config = replace(
            base,
            public_direct=True,
            limits=replace(
                base.limits,
                body_memory_budget=None,
                upload_storage_limit=1024,
            ),
            tls=TLSConfig(letsencrypt=True, domain="files.example"),
            auth=AuthConfig(auth_file=auth_file),
        )
        expected_message = "body_memory_budget"

    with pytest.raises(ValueError, match=expected_message):
        XFerryServer(config)

    assert not root.exists()
    assert logger.handlers == original_handlers
    assert logger.level == original_level
    assert import_calls == []
