"""Foreground CLI wiring and its concise human-facing command contract."""

from __future__ import annotations

import os
import signal
import socket
import subprocess
import sys
import time
from dataclasses import replace
from pathlib import Path

import pytest

import xferry.cli as cli
from tests.server_factory import make_server
from xferry.cli import create_parser
from xferry.config import __version__
from xferry.paths import default_config_path
from xferry.server import XFerryServer
from xferry.server_config import LoggingConfig, ServerConfig
from xferry.settings_schema import SETTING_SPECS

REPO_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(autouse=True)
def isolated_user_config(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "user-data"))
    for name in tuple(os.environ):
        if name.startswith("XFERRY_"):
            monkeypatch.delenv(name)


class TestCLIParser:
    def setup_method(self):
        self.parser = create_parser()

    def test_canonical_modes_and_launch_action(self):
        args = self.parser.parse_args(
            [
                "--access",
                "public",
                "--https",
                "domain",
                "--domain",
                "files.example.com",
                "--log-level",
                "debug",
                "--log-format",
                "json",
                "--files-dir",
                "./shared",
                "--open",
            ]
        )
        assert args.access == "public"
        assert args.https_mode == "domain"
        assert args.log_level == "debug"
        assert args.log_format == "json"
        assert args.files_dir == "./shared"
        assert args.open_browser is True

    @pytest.mark.parametrize(
        "flag,value",
        [
            ("--access", "invalid"),
            ("--https", "invalid"),
            ("--log-level", "invalid"),
            ("--log-format", "invalid"),
        ],
    )
    def test_invalid_modes_are_rejected(self, flag, value):
        with pytest.raises(SystemExit) as error:
            self.parser.parse_args([flag, value])
        assert error.value.code == 2

    @pytest.mark.parametrize(
        "argv",
        [
            ["--auth", "admin:private-secret"],
            ["--auth=admin:private-secret"],
            ["--preset", "local"],
            ["--tls"],
            ["--letsencrypt"],
            ["--sslip"],
            ["--acme-staging"],
            ["--dir", "./data"],
            ["-d./data"],
            ["--quiet"],
            ["--debug"],
            ["--json-log"],
            ["--check-config"],
            ["--print-config"],
            ["--write-sample-config", "./sample.ini"],
        ],
    )
    def test_retired_options_fail_with_replacement_without_secret(self, argv, capsys):
        with pytest.raises(SystemExit) as error:
            self.parser.parse_args(argv)
        assert error.value.code == 2
        output = capsys.readouterr().err
        assert "removed option" in output
        assert "use " in output
        assert "private-secret" not in output

    def test_normal_help_is_short_and_has_working_examples(self):
        text = self.parser.format_help()
        assert "xferry run --open" in text
        assert "xferry run --files-dir ./shared" in text
        assert "xferry config" in text
        assert "--preset" not in text
        assert "--body-memory-budget" not in text
        assert "Capacity model" not in text
        assert "--help-all" in text

    def test_full_help_lists_every_public_setting(self):
        text = create_parser(show_all_help=True).format_help()
        for spec in SETTING_SPECS:
            if spec.cli:
                assert all(option in text for option in spec.cli.option_strings)

    def test_custom_host_port(self):
        args = self.parser.parse_args(["-H", "0.0.0.0", "-p", "443"])
        assert args.host == "0.0.0.0"
        assert args.port == 443

    @pytest.mark.parametrize(
        "argv",
        [
            ["--port", "0"],
            ["--port", "-1"],
            ["--port", "65536"],
            ["--max-size", "0"],
            ["--max-size", "-1"],
            ["--upload-storage-limit", "-1"],
            ["--upload-file-limit", "-1"],
            ["--upload-reserve-free", "-1"],
            ["--note-storage-limit", "-1"],
            ["--note-count-limit", "-1"],
            ["--smuggle-temp-age", "-1"],
            ["--smuggle-temp-file-limit", "-1"],
            ["--smuggle-temp-storage-limit", "-1"],
            ["--max-header-size", "0"],
            ["--max-header-size", "-1"],
            ["--body-memory-budget", "0"],
            ["--body-memory-budget", "-1"],
            ["--body-idle-timeout", "-1"],
            ["--body-timeout", "-1"],
            ["--body-min-rate", "-1"],
            ["--stream-send-idle-timeout", "0"],
            ["--stream-send-idle-timeout", "-1"],
            ["--stream-send-timeout", "-1"],
            ["--max-websocket-connections", "-1"],
            ["--websocket-frame-idle-timeout", "0"],
            ["--websocket-frame-idle-timeout", "-1"],
            ["--workers", "0"],
            ["--workers", "-1"],
            ["--acme-http-port", "0"],
            ["--acme-http-port", "65536"],
        ],
    )
    def test_numeric_limits_are_rejected_at_parse_time(self, argv):
        with pytest.raises(SystemExit) as exc_info:
            self.parser.parse_args(argv)
        assert exc_info.value.code == 2

    @pytest.mark.parametrize("flag", ["--opsec", "--sandbox", "-o", "-s"])
    def test_removed_mode_flags_are_rejected(self, flag):
        with pytest.raises(SystemExit) as exc_info:
            self.parser.parse_args([flag])
        assert exc_info.value.code == 2

    def test_cert_key(self):
        args = self.parser.parse_args(["--cert", "/tmp/c.pem", "--key", "/tmp/k.pem"])
        assert args.cert == "/tmp/c.pem"
        assert args.key == "/tmp/k.pem"

    def test_auth_file(self):
        args = self.parser.parse_args(["--auth-file", "/run/secrets/xferry_auth"])
        assert args.auth_file == "/run/secrets/xferry_auth"

    def test_max_size(self):
        args = self.parser.parse_args(["-m", "500"])
        assert args.max_size == 500

    def test_workers(self):
        args = self.parser.parse_args(["-w", "20"])
        assert args.workers == 20

    def test_body_memory_budget(self):
        args = self.parser.parse_args(["--body-memory-budget", "512"])
        assert args.body_memory_budget == 512

    @pytest.mark.parametrize(
        ("flag", "expected"),
        [
            ("--upload-quota-externally-managed", True),
            ("--no-upload-quota-externally-managed", False),
        ],
    )
    def test_upload_quota_ownership_flags(self, flag, expected):
        args = self.parser.parse_args([flag])

        assert args.upload_quota_externally_managed is expected

    def test_body_and_stream_timeout_flags(self):
        args = self.parser.parse_args(
            [
                "--body-idle-timeout",
                "1.5",
                "--body-timeout",
                "20",
                "--body-min-rate",
                "128",
                "--stream-send-idle-timeout",
                "2.5",
                "--stream-send-timeout",
                "30",
            ]
        )
        assert args.body_idle_timeout == 1.5
        assert args.body_timeout == 20.0
        assert args.body_min_rate == 128.0
        assert args.stream_send_idle_timeout == 2.5
        assert args.stream_send_timeout == 30.0

    def test_websocket_limit_flags(self):
        args = self.parser.parse_args(
            [
                "--max-websocket-connections",
                "7",
                "--websocket-frame-idle-timeout",
                "0.25",
            ]
        )
        assert args.max_websocket_connections == 7
        assert args.websocket_frame_idle_timeout == 0.25

    def test_cors_origin_flag(self):
        args = self.parser.parse_args(["--cors-origin", "https://app.example"])
        assert args.cors_origin == "https://app.example"

    @pytest.mark.parametrize("argv", [["--advanced-upload"], ["--profile", "workspace"]])
    def test_removed_profile_flags_are_rejected(self, argv):
        with pytest.raises(SystemExit) as exc_info:
            self.parser.parse_args(argv)
        assert exc_info.value.code == 2

    def test_version_flag(self, capsys):
        with pytest.raises(SystemExit) as exc_info:
            self.parser.parse_args(["--version"])
        assert exc_info.value.code == 0
        captured = capsys.readouterr()
        assert captured.out == f"xferry run {__version__}\n"

    def test_help_all_prints_to_stdout_and_exits_before_runtime_work(
        self,
        capsys,
    ):
        with pytest.raises(SystemExit) as exc_info:
            cli.run_main(["--help-all"])

        captured = capsys.readouterr()
        assert exc_info.value.code == 0
        assert "--body-memory-budget" in captured.out
        assert "--https" in captured.out
        assert captured.err == ""

    def test_server_parser_help_is_scoped_under_run(self):
        """Omitting the run prefix from help would advertise the removed root server CLI."""
        help_text = create_parser(show_all_help=True).format_help()

        assert create_parser().format_usage().startswith("usage: xferry run ")
        assert "xferry run --open" in help_text
        assert "xferry run --files-dir ./shared" in help_text
        assert "--preset" not in help_text

    def test_server_help_is_stable_across_supported_python_versions(self):
        """Stdlib argparse changes must not rewrite the generated CLI contract."""
        help_text = self.parser.format_help()

        assert "  -H HOST, --host HOST  Bind host (default: 127.0.0.1)" in help_text
        assert "  -p PORT, --port PORT  Listen port (default: 8080)" in help_text
        assert "  --files-dir DIR" in help_text
        assert "-H, --host HOST" not in help_text
        assert "(default: False)" not in help_text
        assert "--https {off,auto,domain,files,self-signed}" in help_text

    @pytest.mark.parametrize("columns", [0, 40, 160])
    def test_server_help_is_stable_across_terminal_widths(self, monkeypatch, columns):
        """Runner terminal geometry must not rewrite the generated CLI contract."""
        expected = self.parser.format_help()
        monkeypatch.setattr(
            "shutil.get_terminal_size",
            lambda fallback=(80, 24): os.terminal_size((columns, fallback[1])),
        )

        assert create_parser().format_help() == expected

    def test_help_text_is_cp1252_encodable(self):
        help_text = self.parser.format_help()

        help_text.encode("cp1252", errors="strict")


class TestCLIMain:
    @pytest.fixture
    def captured_configs(self, monkeypatch):
        captured = []

        class FakeServer:
            def __init__(self, config):
                captured.append(config)

            def start(self):
                pass

            def stop(self):
                pass

        monkeypatch.setattr(cli, "XFerryServer", FakeServer)
        return captured

    def test_defaults_and_open_action(self, captured_configs):
        assert cli.run_main(["--open"]) == 0
        config = captured_configs[0]
        assert config.host == "127.0.0.1"
        assert config.port == 8080
        assert config.logging.open_browser is True
        assert config.files_dir.name == "files"
        assert config.root_dir != Path.cwd()

    def test_saved_user_config_loads_automatically(self, captured_configs):
        path = default_config_path()
        path.parent.mkdir(parents=True)
        path.write_text("[server]\nport = 9021\nworkers = 4\n")
        assert cli.run_main([]) == 0
        assert captured_configs[0].port == 9021
        assert captured_configs[0].limits.max_workers == 4

    def test_explicit_config_env_and_cli_precedence(self, tmp_path, monkeypatch, captured_configs):
        path = tmp_path / "config.ini"
        path.write_text("[server]\nport = 9000\nworkers = 4\n[limits]\nupload_file_limit = 9\n")
        monkeypatch.setenv("XFERRY_PORT", "9001")
        monkeypatch.setenv("XFERRY_UPLOAD_FILE_LIMIT", "10")
        assert cli.run_main(["--config", str(path), "-p8080", "--upload-file-limit", "0"]) == 0
        config = captured_configs[0]
        assert config.port == 8080
        assert config.limits.max_workers == 4
        assert config.limits.upload_file_limit is None

    def test_explicit_missing_config_fails(self, tmp_path, captured_configs):
        with pytest.raises(SystemExit) as error:
            cli.run_main(["--config", str(tmp_path / "missing")])
        assert error.value.code == 2
        assert captured_configs == []

    def test_cli_cannot_expose_saved_config_as_download(self, tmp_path, captured_configs):
        path = default_config_path()
        path.parent.mkdir(parents=True)
        path.write_text("[server]\nport = 8080\n")
        with pytest.raises(SystemExit):
            cli.run_main(["--files-dir", str(path.parent)])
        assert captured_configs == []

    def test_public_guards_run_before_start(self, captured_configs):
        with pytest.raises(SystemExit):
            cli.run_main(["--access", "public", "--https", "off"])
        assert captured_configs == []

    def test_retired_environment_secret_is_not_echoed(self, monkeypatch, capsys, captured_configs):
        monkeypatch.setenv("XFERRY_AUTH", "admin:secret-never-print")
        with pytest.raises(SystemExit):
            cli.run_main([])
        assert "secret-never-print" not in capsys.readouterr().err
        assert captured_configs == []

    def test_keyboard_interrupt_and_unexpected_errors_have_stable_exit_codes(
        self, monkeypatch, capsys
    ):
        class InterruptingServer:
            def __init__(self, _config):
                pass

            def start(self):
                raise KeyboardInterrupt

        monkeypatch.setattr(cli, "XFerryServer", InterruptingServer)
        assert cli.run_main([]) == 0

        class FailingServer(InterruptingServer):
            def start(self):
                raise RuntimeError("boom")

        monkeypatch.setattr(cli, "XFerryServer", FailingServer)
        assert cli.run_main([]) == 1
        assert "Error: boom" in capsys.readouterr().err


def test_package_metadata_has_no_legacy_crypto_extra():
    text = (REPO_ROOT / "pyproject.toml").read_text()
    assert "\ncrypto =" not in text


@pytest.mark.skipif(
    not hasattr(signal, "SIGTERM") or sys.platform == "win32", reason="POSIX signal lifecycle"
)
def test_cli_process_handles_sigterm_gracefully(tmp_path):
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    env = {**os.environ, "PYTHONUNBUFFERED": "1"}
    process = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "xferry",
            "run",
            "--port",
            str(port),
            "--files-dir",
            str(tmp_path / "files"),
            "--log-level",
            "warning",
        ],
        cwd=REPO_ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env,
    )
    try:
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.2) as connection:
                    connection.sendall(
                        (
                            f"PING / HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n"
                            "Connection: close\r\n\r\n"
                        ).encode()
                    )
                    if b"200 OK" in connection.recv(4096):
                        break
            except OSError:
                time.sleep(0.05)
        else:
            raise AssertionError("CLI server did not start")
        process.send_signal(signal.SIGTERM)
        stdout, stderr = process.communicate(timeout=5)
    finally:
        if process.poll() is None:
            process.kill()
            process.communicate(timeout=5)
    assert process.returncode == 0
    assert "Access: private" in stdout
    assert "Files folder:" in stdout
    assert "HTTPS: off" in stdout
    assert stderr == ""


class TestServerConstructorValidation:
    def test_constructor_creates_missing_root_tree(self, temp_dir: Path):
        root_dir = temp_dir / "missing" / "root"

        server = make_server(
            root_dir=str(root_dir),
            quiet=True,
        )

        assert server.root_dir == root_dir.resolve()
        assert server.upload_dir == root_dir.resolve() / "uploads"
        assert server.notes_dir == root_dir.resolve() / "notes"
        assert server.upload_dir.is_dir()
        assert server.notes_dir.is_dir()

    def test_zero_upload_storage_limits_disable_policy(self, temp_dir: Path):
        server = make_server(
            root_dir=str(temp_dir),
            quiet=True,
            upload_storage_limit=0,
            upload_file_limit=0,
            upload_reserved_free_space=0,
            note_storage_limit=0,
            note_count_limit=0,
            smuggle_temp_max_age=0,
            smuggle_temp_file_limit=0,
            smuggle_temp_storage_limit=0,
        )

        assert server.upload_storage_policy.max_total_bytes is None
        assert server.upload_storage_policy.max_file_count is None
        assert server.upload_storage_policy.reserved_free_bytes == 0
        assert server.note_storage_policy.max_total_bytes is None
        assert server.note_storage_policy.max_note_count is None
        assert server.note_storage_policy.max_listed_notes == 1000
        assert server.smuggle_temp_policy.max_age_seconds is None
        assert server.smuggle_temp_policy.max_file_count is None
        assert server.smuggle_temp_policy.max_total_bytes is None

    @pytest.mark.parametrize(
        ("field", "value", "message"),
        [
            ("port", 0, "port must be between 1 and 65535"),
            ("port", -1, "port must be between 1 and 65535"),
            ("port", 65536, "port must be between 1 and 65535"),
            ("max_upload_size", 0, "max_upload_size must be at least 1"),
            ("max_upload_size", -1, "max_upload_size must be at least 1"),
            ("upload_storage_limit", -1, "upload_storage_limit must be at least 0"),
            ("upload_file_limit", -1, "upload_file_limit must be at least 0"),
            (
                "upload_reserved_free_space",
                -1,
                "upload_reserved_free_space must be at least 0",
            ),
            ("note_storage_limit", -1, "note_storage_limit must be at least 0"),
            ("note_count_limit", -1, "note_count_limit must be at least 0"),
            ("smuggle_temp_max_age", -1, "smuggle_temp_max_age must be at least 0"),
            (
                "smuggle_temp_file_limit",
                -1,
                "smuggle_temp_file_limit must be at least 0",
            ),
            (
                "smuggle_temp_storage_limit",
                -1,
                "smuggle_temp_storage_limit must be at least 0",
            ),
            ("max_header_size", 0, "max_header_size must be at least 1"),
            ("max_header_size", -1, "max_header_size must be at least 1"),
            ("body_memory_budget", 0, "body_memory_budget must be at least 1"),
            ("body_memory_budget", -1, "body_memory_budget must be at least 1"),
            ("body_idle_timeout", 0, "body_idle_timeout must be greater than 0"),
            ("body_idle_timeout", -1, "body_idle_timeout must be greater than 0"),
            ("body_timeout", 0, "body_timeout must be greater than 0"),
            ("body_timeout", -1, "body_timeout must be greater than 0"),
            ("body_min_rate", -1, "body_min_rate must be at least 0"),
            (
                "stream_send_idle_timeout",
                0,
                "stream_send_idle_timeout must be greater than 0",
            ),
            (
                "stream_send_idle_timeout",
                -1,
                "stream_send_idle_timeout must be greater than 0",
            ),
            ("stream_send_timeout", 0, "stream_send_timeout must be greater than 0"),
            ("stream_send_timeout", -1, "stream_send_timeout must be greater than 0"),
            ("max_websocket_connections", -1, "max_websocket_connections must be at least 0"),
            (
                "websocket_frame_idle_timeout",
                0,
                "websocket_frame_idle_timeout must be greater than 0",
            ),
            (
                "websocket_frame_idle_timeout",
                -1,
                "websocket_frame_idle_timeout must be greater than 0",
            ),
            ("max_workers", 0, "max_workers must be at least 1"),
            ("max_workers", -1, "max_workers must be at least 1"),
        ],
    )
    def test_invalid_primary_limits_fail_before_filesystem_side_effects(
        self,
        temp_dir: Path,
        field,
        value,
        message,
    ):
        config = ServerConfig(root_dir=temp_dir, logging=LoggingConfig(quiet=True))
        if field == "port":
            config = replace(config, port=value)
        elif field in {"max_websocket_connections", "websocket_frame_idle_timeout"}:
            websocket_field = (
                "max_connections" if field == "max_websocket_connections" else "frame_idle_timeout"
            )
            config = replace(
                config,
                websocket=replace(
                    config.websocket,
                    **{websocket_field: value},
                ),
            )
        else:
            config = replace(config, limits=replace(config.limits, **{field: value}))
        with pytest.raises(ValueError, match=message):
            XFerryServer(config)

        assert not (temp_dir / "uploads").exists()
        assert not (temp_dir / "notes").exists()
