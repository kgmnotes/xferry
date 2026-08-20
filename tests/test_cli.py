"""Tests for CLI argument parsing and main() wiring."""

from __future__ import annotations

import json
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
from xferry.features import registry_methods
from xferry.server import XFerryServer
from xferry.server_config import LoggingConfig, ServerConfig

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10 compatibility
    from setuptools._vendor import tomli as tomllib  # type: ignore[no-redef]


REPO_ROOT = Path(__file__).resolve().parents[1]


def _find_free_port() -> int:
    """Reserve an ephemeral local port and return it."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _wait_for_server(port: int, timeout: float = 5.0) -> None:
    """Poll the live server until it answers a minimal PING request."""
    deadline = time.time() + timeout
    request = (f"PING / HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n").encode(
        "ascii"
    )
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2) as sock:
                sock.settimeout(0.5)
                sock.sendall(request)
                if b"200 OK" in sock.recv(4096):
                    return
        except OSError:
            time.sleep(0.05)
    raise AssertionError("CLI server did not start in time")


class TestCLIParser:
    """Test CLI argument parsing without starting the server."""

    def setup_method(self):
        self.parser = create_parser()

    def test_defaults(self):
        args = self.parser.parse_args([])
        assert args.preset is None
        assert args.host == "127.0.0.1"
        assert args.port == 8080
        assert args.dir == "."
        assert args.quiet is False
        assert args.debug is False
        assert args.tls is False
        assert args.auth is None
        assert args.auth_file is None
        assert args.max_size == 100
        assert args.upload_storage_limit == 0
        assert args.upload_file_limit == 0
        assert args.upload_reserve_free == 0
        assert args.upload_quota_externally_managed is False
        assert args.note_storage_limit == 256
        assert args.note_count_limit == 1000
        assert args.smuggle_temp_age == 3600
        assert args.smuggle_temp_file_limit == 32
        assert args.smuggle_temp_storage_limit == 128
        assert args.max_header_size == 64
        assert args.body_memory_budget is None
        assert args.body_idle_timeout == 5.0
        assert args.body_timeout == 300.0
        assert args.body_min_rate == 0.0
        assert args.stream_send_idle_timeout == 5.0
        assert args.stream_send_timeout == 300.0
        assert args.max_websocket_connections is None
        assert args.websocket_frame_idle_timeout == 5.0
        assert args.workers == 10
        assert args.cors_origin == ""
        assert not hasattr(args, "advanced_upload")
        assert not hasattr(args, "profile")
        assert args.sslip is False
        assert args.public_ip is None
        assert args.acme_staging is False
        assert args.acme_server is None
        assert args.acme_http_address == ""
        assert args.acme_http_port == 80

    @pytest.mark.parametrize(
        "preset",
        ["local", "local-secure", "public-direct"],
    )
    def test_launch_preset_names(self, preset):
        args = self.parser.parse_args(["--preset", preset])

        assert args.preset == preset

    @pytest.mark.parametrize("preset", ["", "workspace", "public"])
    def test_invalid_launch_preset_names_are_rejected(self, preset):
        with pytest.raises(SystemExit) as exc_info:
            self.parser.parse_args(["--preset", preset])

        assert exc_info.value.code == 2

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

    def test_short_flags(self):
        args = self.parser.parse_args(["-q"])
        assert args.quiet is True

    def test_tls_flags(self):
        args = self.parser.parse_args(["--tls"])
        assert args.tls is True

    def test_cert_key(self):
        args = self.parser.parse_args(["--cert", "/tmp/c.pem", "--key", "/tmp/k.pem"])
        assert args.cert == "/tmp/c.pem"
        assert args.key == "/tmp/k.pem"

    def test_auth_random(self):
        args = self.parser.parse_args(["--auth", "random"])
        assert args.auth == "random"

    def test_auth_user_pass(self):
        args = self.parser.parse_args(["--auth", "admin:secret"])
        assert args.auth == "admin:secret"

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

    def test_debug_flag(self):
        args = self.parser.parse_args(["--debug"])
        assert args.debug is True

    def test_open_flag(self):
        args = self.parser.parse_args(["--open"])
        assert args.open is True

    def test_cors_origin_flag(self):
        args = self.parser.parse_args(["--cors-origin", "https://app.example"])
        assert args.cors_origin == "https://app.example"

    @pytest.mark.parametrize("argv", [["--advanced-upload"], ["--profile", "workspace"]])
    def test_removed_profile_flags_are_rejected(self, argv):
        with pytest.raises(SystemExit) as exc_info:
            self.parser.parse_args(argv)
        assert exc_info.value.code == 2

    def test_letsencrypt_requires_domain(self):
        """--letsencrypt without --domain should be caught by main()."""
        # Parser itself accepts it; validation is in main()
        args = self.parser.parse_args(["--letsencrypt"])
        assert args.letsencrypt is True
        assert args.domain is None

    def test_letsencrypt_with_domain(self):
        args = self.parser.parse_args(["--letsencrypt", "--domain", "example.com"])
        assert args.letsencrypt is True
        assert args.domain == "example.com"

    def test_sslip_flags(self):
        args = self.parser.parse_args(["--sslip", "--public-ip", "8.8.8.8"])
        assert args.sslip is True
        assert args.public_ip == "8.8.8.8"

    def test_acme_flags(self):
        args = self.parser.parse_args(
            [
                "--acme-staging",
                "--acme-server",
                "https://acme.example/directory",
                "--acme-http-address",
                "127.0.0.1",
                "--acme-http-port",
                "5002",
            ]
        )
        assert args.acme_staging is True
        assert args.acme_server == "https://acme.example/directory"
        assert args.acme_http_address == "127.0.0.1"
        assert args.acme_http_port == 5002

    def test_version_flag(self, capsys):
        with pytest.raises(SystemExit) as exc_info:
            self.parser.parse_args(["--version"])
        assert exc_info.value.code == 0
        captured = capsys.readouterr()
        assert captured.out == "xferry run 0.1.0\n"

    def test_dir_flag(self):
        args = self.parser.parse_args(["-d", "/tmp/serve"])
        assert args.dir == "/tmp/serve"

    def test_json_log_flag(self):
        args = self.parser.parse_args(["--json-log"])
        assert args.json_log is True

    def test_json_log_default_false(self):
        args = self.parser.parse_args([])
        assert args.json_log is False

    def test_config_control_flags(self):
        args = self.parser.parse_args(
            [
                "--config",
                "/etc/xferry/xferry.ini",
                "--check-config",
                "--print-config",
                "--write-sample-config",
                "/tmp/xferry.ini",
            ]
        )

        assert args.config == "/etc/xferry/xferry.ini"
        assert args.check_config is True
        assert args.print_config is True
        assert args.write_sample_config == "/tmp/xferry.ini"

    def test_help_examples_prefer_trusted_experimental_and_public_direct_paths(self):
        help_text = self.parser.format_help()

        assert "Public HTTPS" not in help_text
        assert "local-secure" in help_text
        assert "public-direct" in help_text
        assert "--write-sample-config" in help_text
        assert "--config ./xferry.ini --check-config" in help_text
        assert "--help-all" in help_text

    def test_normal_help_is_journey_first_and_hides_exhaustive_tuning_flags(self):
        help_text = self.parser.format_help()

        assert help_text.index("local") < help_text.index("options:")
        assert "--preset" in help_text
        assert "--body-memory-budget" not in help_text
        assert "--smuggle-temp-age" not in help_text

    def test_full_help_retains_every_registered_option_and_capacity_contract(self):
        help_text = create_parser(show_all_help=True).format_help()

        for option in (
            "--body-memory-budget",
            "--smuggle-temp-age",
            "--max-websocket-connections",
            "--upload-quota-externally-managed",
        ):
            assert option in help_text
        assert "admission budget" in help_text
        assert "not an RSS ceiling" in help_text
        assert "Each active WebSocket occupies one worker" in help_text

    def test_help_all_prints_to_stdout_and_exits_before_runtime_work(
        self,
        capsys,
    ):
        with pytest.raises(SystemExit) as exc_info:
            cli.run_main(["--help-all"])

        captured = capsys.readouterr()
        assert exc_info.value.code == 0
        assert "--body-memory-budget" in captured.out
        assert "Core methods:" in captured.out
        assert captured.err == ""

    def test_help_footer_lists_full_core_methods(self):
        help_text = create_parser(show_all_help=True).format_help()

        assert "Experimental-only methods" not in help_text
        assert "Core methods: " + ", ".join(registry_methods()) in help_text
        assert "Core methods:" not in self.parser.format_help()

    def test_server_parser_help_is_scoped_under_run(self):
        """Omitting the run prefix from help would advertise the removed root server CLI."""
        help_text = create_parser(show_all_help=True).format_help()

        assert create_parser().format_usage().startswith("usage: xferry run ")
        assert "xferry run --preset local --open" in help_text
        assert "xferry run --preset local-secure" in help_text
        assert "xferry --preset local-secure" not in help_text

    def test_help_text_is_cp1252_encodable(self):
        help_text = self.parser.format_help()

        help_text.encode("cp1252", errors="strict")


def test_package_metadata_has_no_legacy_crypto_extra() -> None:
    """Leaving the empty crypto extra would preserve a removed install compatibility path."""
    with (REPO_ROOT / "pyproject.toml").open("rb") as pyproject_file:
        pyproject = tomllib.load(pyproject_file)

    optional_dependencies = pyproject["project"]["optional-dependencies"]

    assert "crypto" not in optional_dependencies
    assert all("crypto" not in dependency for dependency in optional_dependencies["all"])


class TestCLIMain:
    def test_public_console_main_prints_root_help_without_server_dispatch(
        self,
        monkeypatch,
        capsys,
    ):
        """The console entry point must not treat empty argv as a server start."""

        def fail_if_called(_argv=None):
            raise AssertionError("root console help must not call server run_main")

        monkeypatch.setattr(cli, "run_main", fail_if_called)

        assert cli.main([]) == 0
        rendered = capsys.readouterr()
        assert "usage: xferry [--lang LANG] COMMAND [OPTIONS]" in rendered.out
        assert "xferry run --preset local" in rendered.out
        assert rendered.err == ""

    def test_main_check_config_validates_without_starting_server(
        self,
        monkeypatch,
        temp_dir: Path,
        capsys,
    ):
        config_file = temp_dir / "xferry.ini"
        config_file.write_text(
            """
            [server]
            host = 127.0.0.1
            port = 8090
            """,
            encoding="utf-8",
        )

        def fail_if_called(*_args, **_kwargs):
            raise AssertionError("server should not start for --check-config")

        monkeypatch.setattr(cli, "XFerryServer", fail_if_called)

        assert cli.run_main(["--config", str(config_file), "--check-config"]) == 0
        rendered = capsys.readouterr().out
        assert "Configuration valid." in rendered
        assert "Runtime posture:" in rendered
        assert "Exposure: loopback" in rendered

    def test_main_print_config_redacts_auth_and_does_not_start(
        self,
        monkeypatch,
        capsys,
    ):
        def fail_if_called(*_args, **_kwargs):
            raise AssertionError("server should not start for --print-config")

        monkeypatch.setattr(cli, "XFerryServer", fail_if_called)

        assert cli.run_main(["--auth", "admin:supersecret", "--print-config"]) == 0
        rendered = capsys.readouterr().out
        assert '"auth": "***"' in rendered
        assert '"runtime_posture"' in rendered
        assert '"auth_mode": "inline"' in rendered
        assert "supersecret" not in rendered

    def test_main_print_config_reports_effective_tls_for_sslip(
        self,
        monkeypatch,
        capsys,
    ):
        def fail_if_called(*_args, **_kwargs):
            raise AssertionError("server should not start for --print-config")

        monkeypatch.setattr(cli, "XFerryServer", fail_if_called)

        assert cli.run_main(["--sslip", "--print-config"]) == 0
        rendered = capsys.readouterr().out
        assert '"tls": false' in rendered
        assert '"effective_tls": true' in rendered
        assert '"tls_mode": "acme-sslip"' in rendered

    def test_main_check_and_print_use_same_runtime_posture(
        self,
        monkeypatch,
        capsys,
    ):
        def fail_if_called(*_args, **_kwargs):
            raise AssertionError("server should not start for config inspection")

        monkeypatch.setattr(cli, "XFerryServer", fail_if_called)

        assert cli.run_main(["--preset", "local", "--check-config"]) == 0
        checked = capsys.readouterr().out
        assert "Preset: local" in checked
        assert "Exposure: loopback" in checked

        assert cli.run_main(["--preset", "local", "--print-config"]) == 0
        printed = json.loads(capsys.readouterr().out)
        posture = printed["runtime_posture"]
        assert posture["preset"] == "local"
        assert posture["exposure"] == "loopback"
        assert posture["effective_url"] == "http://127.0.0.1:8080"

    def test_main_non_loopback_warning_is_non_breaking_and_structured(
        self,
        monkeypatch,
        capsys,
    ):
        def fail_if_called(*_args, **_kwargs):
            raise AssertionError("server should not start for --check-config")

        monkeypatch.setattr(cli, "XFerryServer", fail_if_called)

        assert cli.run_main(["--host", "0.0.0.0", "--check-config"]) == 0
        checked = capsys.readouterr().out
        assert "WARNING [non-loopback-without-public-direct]" in checked

        assert cli.run_main(["--host", "0.0.0.0", "--print-config"]) == 0
        posture = json.loads(capsys.readouterr().out)["runtime_posture"]
        assert posture["exposure"] == "all-interfaces"
        assert "non-loopback-without-public-direct" in {
            warning["code"] for warning in posture["warnings"]
        }

    def test_main_local_secure_interactive_uses_generated_auth_and_shared_posture(
        self,
        monkeypatch,
    ):
        captured: dict[str, object] = {}

        class ServerStub:
            def __init__(self, config):
                captured["config"] = config

            def start(self):
                captured["started"] = True

        monkeypatch.setattr(cli, "XFerryServer", ServerStub)
        monkeypatch.setattr(cli, "_stdout_is_interactive", lambda: True)

        assert cli.run_main(["--preset", "local-secure"]) == 0
        config = captured.pop("config")
        posture = config.runtime_posture

        assert config.tls.enabled is True
        assert config.auth.auth == "random"
        assert config.auth.auth_file is None
        assert captured["started"] is True
        assert posture.auth_mode == "generated"

    def test_main_local_secure_rejects_generated_auth_before_noninteractive_start(
        self,
        monkeypatch,
        capsys,
    ):
        def fail_if_called(*_args, **_kwargs):
            raise AssertionError("server should not be constructed")

        monkeypatch.setattr(cli, "XFerryServer", fail_if_called)
        monkeypatch.setattr(cli, "_stdout_is_interactive", lambda: False)

        with pytest.raises(SystemExit) as exc_info:
            cli.run_main(["--preset", "local-secure"])

        assert exc_info.value.code == 2
        rendered = capsys.readouterr()
        assert "local-secure" in rendered.err
        assert "--auth-file" in rendered.err
        assert "random" not in rendered.out

    def test_main_local_secure_check_and_print_never_generate_credentials(
        self,
        monkeypatch,
        capsys,
    ):
        def fail_if_called(*_args, **_kwargs):
            raise AssertionError("config inspection must not construct the server")

        monkeypatch.setattr(cli, "XFerryServer", fail_if_called)
        monkeypatch.setattr(cli, "_stdout_is_interactive", lambda: False)

        assert (
            cli.run_main(
                [
                    "--preset",
                    "local-secure",
                    "--no-tls",
                    "--check-config",
                ]
            )
            == 0
        )
        checked = capsys.readouterr().out
        assert "generated-auth-requires-tty" in checked
        assert "local-secure-weakened" in checked
        assert "Generated credentials:" not in checked

        assert (
            cli.run_main(
                [
                    "--preset",
                    "local-secure",
                    "--no-tls",
                    "--print-config",
                ]
            )
            == 0
        )
        printed = json.loads(capsys.readouterr().out)
        assert printed["tls"] is False
        assert printed["auth"] == "***"
        assert printed["runtime_posture"]["auth_mode"] == "generated"

    def test_main_local_secure_noninteractive_accepts_file_credentials(
        self,
        monkeypatch,
    ):
        captured: dict[str, object] = {}

        class ServerStub:
            def __init__(self, config):
                captured["config"] = config

            def start(self):
                captured["started"] = True

        monkeypatch.setattr(cli, "XFerryServer", ServerStub)
        monkeypatch.setattr(cli, "_stdout_is_interactive", lambda: False)

        assert (
            cli.run_main(
                [
                    "--preset",
                    "local-secure",
                    "--auth-file",
                    "/run/secrets/xferry_auth",
                ]
            )
            == 0
        )
        config = captured.pop("config")
        posture = config.runtime_posture

        assert config.auth.auth is None
        assert config.auth.auth_file == Path("/run/secrets/xferry_auth").resolve()
        assert captured["started"] is True
        assert posture.auth_mode == "file"

    def test_main_public_direct_preset_runs_hardened_validation(
        self,
        monkeypatch,
        capsys,
    ):
        def fail_if_called(*_args, **_kwargs):
            raise AssertionError("server should not start for --check-config")

        monkeypatch.setattr(cli, "XFerryServer", fail_if_called)

        with pytest.raises(SystemExit) as exc_info:
            cli.run_main(["--preset", "public-direct", "--check-config"])
        assert exc_info.value.code == 2
        assert "real TLS" in capsys.readouterr().err

        assert (
            cli.run_main(
                [
                    "--preset",
                    "public-direct",
                    "--sslip",
                    "--auth-file",
                    "/run/secrets/xferry_auth",
                    "--check-config",
                ]
            )
            == 0
        )
        checked = capsys.readouterr().out
        assert "Public-direct validation: validated" in checked

    def test_main_resolves_preset_from_ini_environment_and_cli(
        self,
        monkeypatch,
        temp_dir: Path,
        capsys,
    ):
        config_file = temp_dir / "xferry.ini"
        config_file.write_text(
            """
            [server]
            preset = public-direct
            host = 127.0.0.1
            public_direct = false
            """,
            encoding="utf-8",
        )
        monkeypatch.setenv("XFERRY_PRESET", "local-secure")

        assert (
            cli.run_main(
                [
                    "--config",
                    str(config_file),
                    "--preset",
                    "local",
                    "--print-config",
                ]
            )
            == 0
        )
        printed = json.loads(capsys.readouterr().out)

        assert printed["preset"] == "local"
        assert printed["host"] == "127.0.0.1"
        assert printed["public_direct"] is False

    def test_main_write_sample_config(self, monkeypatch, temp_dir: Path):
        output = temp_dir / "sample.ini"

        def fail_if_called(*_args, **_kwargs):
            raise AssertionError("server should not start for --write-sample-config")

        monkeypatch.setattr(cli, "XFerryServer", fail_if_called)

        assert cli.run_main(["--write-sample-config", str(output)]) == 0
        rendered = output.read_text(encoding="utf-8")
        assert "[server]" in rendered
        assert "public_direct = true" in rendered
        assert "upload_storage_limit_mb = 4096" in rendered
        assert "upload_file_limit = 4096" in rendered
        assert "upload_reserve_free_mb = 1024" in rendered
        assert "upload_quota_externally_managed = false" in rendered

    def test_main_cli_can_acknowledge_external_quota_for_all_zero_file(
        self,
        monkeypatch,
        temp_dir: Path,
    ):
        config_file = temp_dir / "xferry.ini"
        config_file.write_text(
            """
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
            """,
            encoding="utf-8",
        )
        monkeypatch.delenv("XFERRY_UPLOAD_QUOTA_EXTERNALLY_MANAGED", raising=False)

        result = cli.run_main(
            [
                "--config",
                str(config_file),
                "--upload-quota-externally-managed",
                "--check-config",
            ]
        )

        assert result == 0

    def test_main_negative_cli_flag_overrides_external_quota_environment(
        self,
        monkeypatch,
        temp_dir: Path,
        capsys,
    ):
        config_file = temp_dir / "xferry.ini"
        config_file.write_text(
            """
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
            """,
            encoding="utf-8",
        )
        monkeypatch.setenv("XFERRY_UPLOAD_QUOTA_EXTERNALLY_MANAGED", "true")

        assert cli.run_main(["--config", str(config_file), "--check-config"]) == 0

        with pytest.raises(SystemExit) as exc_info:
            cli.run_main(
                [
                    "--config",
                    str(config_file),
                    "--no-upload-quota-externally-managed",
                    "--check-config",
                ]
            )

        assert exc_info.value.code == 2
        assert "upload_quota_externally_managed" in capsys.readouterr().err

    def test_main_config_file_is_overridden_by_explicit_cli(self, monkeypatch, temp_dir: Path):
        config_file = temp_dir / "xferry.ini"
        config_file.write_text(
            """
            [server]
            host = 0.0.0.0
            port = 9000
            root_dir = /srv/xferry

            [limits]
            max_size_mb = 64
            """,
            encoding="utf-8",
        )
        captured: dict[str, object] = {}

        class ServerStub:
            def __init__(self, config):
                captured["config"] = config

            def start(self):
                captured["started"] = True

        monkeypatch.setattr(cli, "XFerryServer", ServerStub)

        result = cli.run_main(["--config", str(config_file), "--port", "8080"])

        assert result == 0
        config = captured["config"]
        assert config.host == "0.0.0.0"
        assert config.port == 8080
        assert config.root_dir == Path("/srv/xferry").resolve()
        assert config.limits.max_upload_size == 64 * 1024 * 1024
        assert captured["started"] is True

    def test_main_attached_short_option_overrides_preset_default(
        self,
        monkeypatch,
        capsys,
    ):
        def fail_if_called(*_args, **_kwargs):
            raise AssertionError("server should not start for --print-config")

        monkeypatch.setattr(cli, "XFerryServer", fail_if_called)

        assert (
            cli.run_main(
                [
                    "--preset",
                    "local",
                    "-p9443",
                    "--print-config",
                ]
            )
            == 0
        )
        printed = json.loads(capsys.readouterr().out)

        assert printed["port"] == 9443

    @pytest.mark.parametrize("argv", [["--advanced-upload"], ["--profile", "experimental"]])
    def test_main_rejects_removed_profile_flags(self, argv):
        with pytest.raises(SystemExit) as exc_info:
            cli.run_main(argv)
        assert exc_info.value.code == 2

    def test_main_starts_server_with_expected_config(self, monkeypatch):
        captured: dict[str, object] = {}

        class ServerStub:
            def __init__(self, config):
                captured["config"] = config

            def start(self):
                captured["started"] = True

        monkeypatch.setattr(cli, "XFerryServer", ServerStub)

        result = cli.run_main(
            [
                "-H",
                "0.0.0.0",
                "-p",
                "9090",
                "-d",
                "/srv/data",
                "--quiet",
                "--debug",
                "--open",
                "--json-log",
                "--cors-origin",
                "https://app.example",
                "-m",
                "250",
                "--upload-storage-limit",
                "1000",
                "--upload-file-limit",
                "25",
                "--upload-reserve-free",
                "500",
                "--note-storage-limit",
                "128",
                "--note-count-limit",
                "50",
                "--smuggle-temp-age",
                "120",
                "--smuggle-temp-file-limit",
                "5",
                "--smuggle-temp-storage-limit",
                "32",
                "--max-header-size",
                "128",
                "--body-memory-budget",
                "512",
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
                "--max-websocket-connections",
                "7",
                "--websocket-frame-idle-timeout",
                "0.25",
                "-w",
                "20",
                "--auth",
                "admin:secret",
            ]
        )

        assert result == 0
        config = captured.pop("config")
        posture = config.runtime_posture
        assert posture.effective_url == "http://0.0.0.0:9090"
        assert posture.auth_mode == "inline"
        assert config.host == "0.0.0.0"
        assert config.port == 9090
        assert config.root_dir == Path("/srv/data").resolve()
        assert config.limits == config.limits.__class__(
            max_upload_size=250 * 1024 * 1024,
            upload_storage_limit=1000 * 1024 * 1024,
            upload_file_limit=25,
            upload_reserved_free_space=500 * 1024 * 1024,
            note_storage_limit=128 * 1024 * 1024,
            note_count_limit=50,
            smuggle_temp_max_age=120,
            smuggle_temp_file_limit=5,
            smuggle_temp_storage_limit=32 * 1024 * 1024,
            max_header_size=128 * 1024,
            body_memory_budget=512 * 1024 * 1024,
            body_idle_timeout=1.5,
            body_timeout=20.0,
            body_min_rate=128.0,
            stream_send_idle_timeout=2.5,
            stream_send_timeout=30.0,
            max_workers=20,
        )
        assert config.websocket.max_connections == 7
        assert config.websocket.frame_idle_timeout == 0.25
        assert config.logging.quiet is True
        assert config.logging.debug is True
        assert config.logging.open_browser is True
        assert config.logging.json_log is True
        assert config.tls.enabled is False
        assert config.auth.auth == "admin:secret"
        assert config.auth.auth_file is None
        assert config.cors_origin == "https://app.example"
        assert captured == {"started": True}

    def test_main_does_not_pass_profile_to_server(self, monkeypatch):
        captured: dict[str, object] = {}

        class ServerStub:
            def __init__(self, config):
                captured["config"] = config

            def start(self):
                captured["started"] = True

        monkeypatch.setattr(cli, "XFerryServer", ServerStub)

        result = cli.run_main([])

        assert result == 0
        assert captured["config"].runtime_posture is not None
        assert captured["started"] is True

    def test_main_passes_auth_file_to_server(self, monkeypatch):
        captured: dict[str, object] = {}

        class ServerStub:
            def __init__(self, config):
                captured["config"] = config

            def start(self):
                captured["started"] = True

        monkeypatch.setattr(cli, "XFerryServer", ServerStub)

        result = cli.run_main(["--auth-file", "/run/secrets/xferry_auth"])

        assert result == 0
        config = captured["config"]
        assert config.auth.auth is None
        assert config.auth.auth_file == Path("/run/secrets/xferry_auth").resolve()

    @pytest.mark.parametrize(
        ("argv", "expected_tls"),
        [
            (["--tls"], True),
            (["--cert", "/tmp/cert.pem", "--key", "/tmp/key.pem"], True),
            (["--letsencrypt", "--domain", "example.com"], True),
            (["--sslip"], True),
        ],
    )
    def test_main_enables_tls_when_any_tls_input_is_present(
        self,
        monkeypatch,
        argv,
        expected_tls,
    ):
        captured: dict[str, object] = {}

        class ServerStub:
            def __init__(self, config):
                captured["config"] = config

            def start(self):
                return None

        monkeypatch.setattr(cli, "XFerryServer", ServerStub)

        result = cli.run_main(argv)

        assert result == 0
        assert captured["config"].tls.enabled is expected_tls

    def test_main_requires_domain_for_letsencrypt(self):
        with pytest.raises(SystemExit) as exc_info:
            cli.run_main(["--letsencrypt"])
        assert exc_info.value.code == 2

    @pytest.mark.parametrize(
        ("argv", "message"),
        [
            (["--cert", "cert.pem"], "--cert and --key must be provided together"),
            (["--key", "key.pem"], "--cert and --key must be provided together"),
            (["--cert", ""], "--cert and --key must be provided together"),
            (["--key", ""], "--cert and --key must be provided together"),
            (["--cert", "", "--key", ""], "--cert and --key values must not be empty"),
            (
                [
                    "--cert",
                    "cert.pem",
                    "--key",
                    "key.pem",
                    "--letsencrypt",
                    "--domain",
                    "example.com",
                ],
                "--cert/--key cannot be combined with --letsencrypt or --sslip",
            ),
            (
                ["--cert", "cert.pem", "--key", "key.pem", "--sslip"],
                "--cert/--key cannot be combined with --letsencrypt or --sslip",
            ),
        ],
    )
    def test_main_rejects_invalid_tls_source_combinations(
        self,
        monkeypatch,
        capsys,
        argv,
        message,
    ):
        def fail_if_called(*_args, **_kwargs):
            raise AssertionError("server should not be constructed for invalid CLI config")

        monkeypatch.setattr(cli, "XFerryServer", fail_if_called)

        with pytest.raises(SystemExit) as exc_info:
            cli.run_main(argv)

        assert exc_info.value.code == 2
        assert message in capsys.readouterr().err

    def test_main_allows_letsencrypt_with_sslip_without_domain(self, monkeypatch):
        captured: dict[str, object] = {}

        class ServerStub:
            def __init__(self, config):
                captured["config"] = config

            def start(self):
                return None

        monkeypatch.setattr(cli, "XFerryServer", ServerStub)

        result = cli.run_main(["--letsencrypt", "--sslip"])

        assert result == 0
        config = captured["config"]
        assert config.tls.enabled is True
        assert config.tls.letsencrypt is True
        assert config.tls.sslip is True

    @pytest.mark.parametrize(
        "argv",
        [
            ["--sslip", "--domain", "example.com"],
            ["--public-ip", "8.8.8.8"],
            ["--acme-http-port", "0"],
            ["--acme-http-port", "70000"],
            ["--auth-file", ""],
        ],
    )
    def test_main_rejects_invalid_acme_combinations(self, argv):
        with pytest.raises(SystemExit) as exc_info:
            cli.run_main(argv)
        assert exc_info.value.code == 2

    def test_main_rejects_conflicting_auth_sources_without_echoing_secret(
        self,
        monkeypatch,
        capsys,
    ):
        def fail_if_called(*_args, **_kwargs):
            raise AssertionError("server should not be constructed for invalid CLI config")

        monkeypatch.setattr(cli, "XFerryServer", fail_if_called)

        with pytest.raises(SystemExit) as exc_info:
            cli.run_main(["--auth", "admin:supersecret", "--auth-file", "/run/secrets/auth"])

        assert exc_info.value.code == 2
        captured = capsys.readouterr()
        assert "--auth and --auth-file cannot be combined" in captured.err
        assert "supersecret" not in captured.err

    def test_main_auth_file_parse_failure_does_not_echo_secret(self, temp_dir: Path, capsys):
        auth_file = temp_dir / "auth.txt"
        auth_file.write_text("admin:supersecret\nother:credential\n", encoding="utf-8")

        result = cli.run_main(["-d", str(temp_dir), "--auth-file", str(auth_file)])
        captured = capsys.readouterr()

        assert result == 1
        assert "auth file must contain exactly one user:password line" in captured.err
        assert "supersecret" not in captured.err

    def test_main_returns_zero_on_keyboard_interrupt(self, monkeypatch):
        class ServerStub:
            def __init__(self, _config):
                pass

            def start(self):
                raise KeyboardInterrupt

        monkeypatch.setattr(cli, "XFerryServer", ServerStub)

        assert cli.run_main([]) == 0

    def test_main_returns_one_and_prints_error_on_exception(self, monkeypatch, capsys):
        class ServerStub:
            def __init__(self, _config):
                raise RuntimeError("boom")

        monkeypatch.setattr(cli, "XFerryServer", ServerStub)

        result = cli.run_main([])
        captured = capsys.readouterr()

        assert result == 1
        assert "Error: boom" in captured.err

    @pytest.mark.skipif(
        not hasattr(signal, "SIGTERM") or sys.platform == "win32",
        reason="subprocess SIGTERM graceful shutdown is not portable to Windows",
    )
    def test_cli_process_handles_sigterm_gracefully(self, temp_dir: Path):
        port = _find_free_port()
        (temp_dir / "index.html").write_text("<html>ok</html>", encoding="utf-8")
        repo_root = Path(__file__).resolve().parents[1]
        env = {**os.environ, "PYTHONUNBUFFERED": "1"}
        process = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "xferry",
                "run",
                "--host",
                "127.0.0.1",
                "--port",
                str(port),
                "--dir",
                str(temp_dir),
                "--quiet",
            ],
            cwd=repo_root,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=env,
        )
        try:
            _wait_for_server(port)
            process.send_signal(signal.SIGTERM)
            stdout, stderr = process.communicate(timeout=5.0)
        finally:
            if process.poll() is None:
                process.kill()
                process.communicate(timeout=5.0)

        assert process.returncode == 0
        assert "Runtime posture:" in stdout
        assert "Exposure: loopback" in stdout
        assert "Data persistence: operator-managed" in stdout
        assert "TLS: disabled; Auth: disabled" in stdout
        assert "Public-direct validation: not requested" in stdout
        assert "not an RSS ceiling" in stdout
        assert "Each active WebSocket occupies one worker" in stdout
        assert "Server stopped" in stdout
        assert stderr == ""

        with pytest.raises(OSError):
            socket.create_connection(("127.0.0.1", port), timeout=0.2)


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
