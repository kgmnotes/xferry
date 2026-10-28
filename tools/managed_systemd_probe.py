"""Secret-safe native managed lifecycle probe for a dedicated systemd container.

The host verifies the signed ephemeral fixtures before mounting them read-only.
This stdlib-only child never imports XFerry from source, alters its service unit,
or writes authentication/configuration hashes to evidence.
"""

from __future__ import annotations

import argparse
import base64
import configparser
import hashlib
import json
import os
import re
import socket
import ssl
import stat
import subprocess
import threading
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

SOURCE_VERSION = "0.1.1"
TARGET_VERSION = "0.1.2"
RELEASE_BASE_URL = "https://127.0.0.1:44443/releases"
MAX_HEALTH_BYTES = 64 * 1024
_RELEASE_FIELDS = {
    "active",
    "before",
    "code",
    "detail",
    "dry_run",
    "exit_code",
    "message",
    "next_actions",
    "rollback",
    "status",
    "target",
}
_DOCTOR_FIELDS = {
    "checks",
    "code",
    "detail",
    "detected",
    "exit_code",
    "message",
    "next_actions",
    "status",
    "supported_matrix",
}
_DOCTOR_STATUSES = {
    "platform": "supported",
    "installation": "installed",
    "configuration": "valid",
    "service": "active",
    "network": "reachable",
    "health": "healthy",
}
_FAILURE_CODES = frozenset(
    {
        "command_failed",
        "install_bootstrap_failed",
        "version_query_failed",
        "service_query_failed",
        "command_output_invalid",
        "host_mismatch",
        "root_required",
        "rehearsal_opt_in_required",
        "systemd_pid1_required",
        "docker_required",
        "private_cgroup_namespace_required",
        "existing_managed_state",
        "existing_managed_service",
        "fixture_layout_invalid",
        "protected_state_invalid",
        "health_config_invalid",
        "health_auth_invalid",
        "health_response_invalid",
        "health_connection_failed",
        "command_json_invalid",
        "command_outcome_invalid",
        "cli_version_mismatch",
        "release_state_invalid",
        "service_state_invalid",
        "setup_outcome_invalid",
        "doctor_outcome_invalid",
        "update_outcome_invalid",
        "release_outcome_invalid",
        "rollback_outcome_invalid",
        "state_preservation_failed",
        "uninstall_state_invalid",
        "probe_failed",
    }
)


class ProbeFailure(RuntimeError):
    """A fixed diagnostic code, never a caught command/request/error message."""

    def __init__(self, code: str) -> None:
        super().__init__(code if code in _FAILURE_CODES else "probe_failed")


def _require(condition: bool, code: str) -> None:
    if not condition:
        raise ProbeFailure(code)


@dataclass(frozen=True)
class ProbeOptions:
    fixtures_root: Path
    tls_dir: Path
    evidence: Path
    distro: str
    distro_version: str
    machine: str
    platform: str
    host_cgroup_namespace: str


@dataclass(frozen=True)
class SystemPaths:
    """Fixed production layout; alternate paths are for unit tests, not CLI flags."""

    pid1_comm: Path = Path("/proc/1/comm")
    container_marker: Path = Path("/run/systemd/container")
    cgroup_namespace: Path = Path("/proc/self/ns/cgroup")
    os_release: Path = Path("/etc/os-release")
    release_root: Path = Path("/opt/xferry")
    config_root: Path = Path("/etc/xferry")
    data_root: Path = Path("/var/lib/xferry")
    unit: Path = Path("/etc/systemd/system/xferry.service")
    cli: Path = Path("/usr/local/bin/xferry")

    @property
    def config(self) -> Path:
        return self.config_root / "xferry.ini"

    @property
    def auth(self) -> Path:
        return self.config_root / "auth"

    @property
    def sentinel(self) -> Path:
        return self.data_root / "systemd-matrix-sentinel"


SYSTEM_PATHS = SystemPaths()


def _command(
    argv: Sequence[str],
    *,
    environment: Mapping[str, str] | None = None,
    discard_stderr: bool = False,
    allowed_codes: tuple[int, ...] = (0,),
) -> bytes:
    try:
        result = subprocess.run(
            list(argv),
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL if discard_stderr else subprocess.PIPE,
            env=None if environment is None else dict(environment),
            timeout=120,
        )
    except Exception:
        raise ProbeFailure("command_failed") from None
    _require(result.returncode in allowed_codes, "command_failed")
    _require(len(result.stdout) <= 1024 * 1024, "command_output_invalid")
    return result.stdout


def guard_host(
    *,
    distro: str,
    distro_version: str,
    machine: str,
    platform: str,
    host_cgroup_namespace: str,
    paths: SystemPaths = SYSTEM_PATHS,
) -> dict[str, object]:
    """Check the disposable native host before either lifecycle driver mutates it."""
    versions = {"ubuntu": {"22.04", "24.04", "26.04"}, "debian": {"12", "13"}}
    _require(distro_version in versions.get(distro, set()), "host_mismatch")
    _require(machine in {"x86_64", "aarch64"}, "host_mismatch")
    _require(platform == f"linux-{machine}", "host_mismatch")
    _require(os.geteuid() == 0, "root_required")
    _require(os.environ.get("XFERRY_SYSTEMD_REHEARSAL") == "1", "rehearsal_opt_in_required")
    _require(paths.pid1_comm.read_text().strip() == "systemd", "systemd_pid1_required")
    _require(paths.container_marker.read_text().strip() == "docker", "docker_required")
    own_namespace = str(paths.cgroup_namespace.readlink())
    namespace_pattern = r"cgroup:\[\d+\]"
    _require(
        re.fullmatch(namespace_pattern, own_namespace) is not None
        and re.fullmatch(namespace_pattern, host_cgroup_namespace) is not None
        and own_namespace != host_cgroup_namespace,
        "private_cgroup_namespace_required",
    )
    facts: dict[str, str] = {}
    for line in paths.os_release.read_text().splitlines():
        key, separator, value = line.partition("=")
        if separator and key in {"ID", "VERSION_ID"}:
            _require(key not in facts, "host_mismatch")
            facts[key] = value.strip().strip('"').strip("'")
    _require(
        facts == {"ID": distro, "VERSION_ID": distro_version} and os.uname().machine == machine,
        "host_mismatch",
    )
    for path in (paths.release_root, paths.config_root, paths.data_root, paths.unit, paths.cli):
        _require(not os.path.lexists(path), "existing_managed_state")
    state = _command(
        ("systemctl", "show", "xferry.service", "--property=LoadState", "--value"),
        allowed_codes=(0, 4),
    )
    _require(state.strip() == b"not-found", "existing_managed_service")
    return {
        "distro": distro,
        "distro_version": distro_version,
        "machine": machine,
        "platform": platform,
        "pid1": "systemd",
        "container": "docker",
        "effective_uid": 0,
        "private_cgroup_namespace": True,
        "cgroup_namespace": own_namespace,
        "host_cgroup_namespace": host_cgroup_namespace,
    }


def guard(options: ProbeOptions, paths: SystemPaths = SYSTEM_PATHS) -> dict[str, object]:
    """Keep the fixture-only input and host boundaries unchanged."""
    host = guard_host(
        distro=options.distro,
        distro_version=options.distro_version,
        machine=options.machine,
        platform=options.platform,
        host_cgroup_namespace=options.host_cgroup_namespace,
        paths=paths,
    )
    _require(
        options.fixtures_root.is_dir() and not options.fixtures_root.is_symlink(),
        "fixture_layout_invalid",
    )
    fixture_root = options.fixtures_root.resolve()
    _require(not options.tls_dir.resolve().is_relative_to(fixture_root), "fixture_layout_invalid")
    for name in ("server.crt", "server.key"):
        _regular_bytes(options.tls_dir / name, 64 * 1024)
    return host


def _regular_bytes(path: Path, limit: int) -> bytes:
    """Reject links/nonregular files and bound reads, including FIFO opens."""
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, "rb") as stream:
            metadata = os.fstat(stream.fileno())
            _require(
                stat.S_ISREG(metadata.st_mode) and metadata.st_size <= limit,
                "protected_state_invalid",
            )
            payload = stream.read(limit + 1)
            _require(len(payload) <= limit, "protected_state_invalid")
            return payload
    except ProbeFailure:
        raise
    except Exception:
        raise ProbeFailure("protected_state_invalid") from None


def _state_hashes(paths: SystemPaths) -> dict[str, str]:
    return {
        label: hashlib.sha256(_regular_bytes(path, MAX_HEALTH_BYTES)).hexdigest()
        for label, path in {
            "config": paths.config,
            "auth": paths.auth,
            "sentinel": paths.sentinel,
        }.items()
    }


def _preservation(baseline: Mapping[str, str], paths: SystemPaths) -> dict[str, bool]:
    preserved: dict[str, bool] = {}
    for label, path in {
        "config": paths.config,
        "auth": paths.auth,
        "sentinel": paths.sentinel,
    }.items():
        try:
            preserved[label] = (
                hashlib.sha256(_regular_bytes(path, MAX_HEALTH_BYTES)).hexdigest()
                == baseline[label]
            )
        except Exception:
            preserved[label] = False
    return preserved


def _health_credentials(paths: SystemPaths) -> bytes:
    try:
        config = configparser.ConfigParser(interpolation=None)
        config.read_string(_regular_bytes(paths.config, MAX_HEALTH_BYTES).decode("utf-8"))
        _require(
            config.get("server", "host") == "127.0.0.1"
            and config.get("server", "port") == "8080"
            and config.get("security", "auth_file") == "/etc/xferry/auth",
            "health_config_invalid",
        )
        auth = _regular_bytes(paths.auth, 4096).decode("utf-8").removesuffix("\n")
        _require(
            auth.startswith("admin:")
            and len(auth) > len("admin:")
            and not any(character in auth for character in "\r\n\x00"),
            "health_auth_invalid",
        )
        return base64.b64encode(auth.encode("utf-8"))
    except ProbeFailure:
        raise
    except Exception:
        raise ProbeFailure("health_config_invalid") from None


def _json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    document: dict[str, Any] = {}
    for key, value in pairs:
        if key in document:
            raise ValueError("duplicate JSON field")
        document[key] = value
    return document


def _parse_health(response: bytes, expected_version: str) -> bool:
    """Require a bounded, unambiguous authenticated PING identity response."""
    header, separator, body = response.partition(b"\r\n\r\n")
    if not separator or len(header) > MAX_HEALTH_BYTES or len(body) > MAX_HEALTH_BYTES:
        return False
    lines = header.split(b"\r\n")
    status = lines[0].split(b" ", 2)
    if len(status) < 2 or status[0] not in {b"HTTP/1.0", b"HTTP/1.1"} or status[1] != b"200":
        return False
    lengths: list[bytes] = []
    for line in lines[1:]:
        name, delimiter, value = line.partition(b":")
        if not delimiter or re.fullmatch(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+", name) is None:
            return False
        if name.lower() == b"transfer-encoding":
            return False
        if name.lower() == b"content-length":
            lengths.append(value.strip())
    if lengths and (
        len(lengths) != 1
        or not lengths[0].isdigit()
        or len(lengths[0]) > 5
        or int(lengths[0]) != len(body)
    ):
        return False
    try:
        document = json.loads(body, object_pairs_hook=_json_object)
    except (ValueError, UnicodeError):
        return False
    return (
        isinstance(document, dict)
        and document.get("health") == "ready"
        and document.get("server") == f"XFerry/{expected_version}"
    )


def verify_health(expected_version: str, paths: SystemPaths = SYSTEM_PATHS) -> None:
    token = _health_credentials(paths)
    request = (
        b"PING / HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Basic "
        + token
        + b"\r\nConnection: close\r\n\r\n"
    )
    response = bytearray()
    try:
        with socket.create_connection(("127.0.0.1", 8080), timeout=5) as connection:
            connection.settimeout(5)
            connection.sendall(request)
            while True:
                remaining = MAX_HEALTH_BYTES * 2 + 4 + 1 - len(response)
                if remaining <= 0:
                    raise ProbeFailure("health_response_invalid")
                chunk = connection.recv(min(4096, remaining))
                if not chunk:
                    break
                response.extend(chunk)
    except ProbeFailure:
        raise
    except Exception:
        raise ProbeFailure("health_connection_failed") from None
    _require(_parse_health(bytes(response), expected_version), "health_response_invalid")


class _QuietHandler(SimpleHTTPRequestHandler):
    def log_message(self, format: str, *args: Any) -> None:
        pass

    def send_head(self) -> Any:
        root = Path(self.directory).resolve()
        target = Path(self.translate_path(self.path))
        parsed = urlsplit(self.path)
        if (
            parsed.query
            or not target.resolve().is_relative_to(root)
            or not target.is_file()
            or any(
                part.is_symlink()
                for part in (target, *target.parents)
                if part != root and root in part.parents
            )
        ):
            self.send_error(403)
            return None
        return super().send_head()


class _QuietServer(ThreadingHTTPServer):
    def handle_error(self, request: Any, client_address: Any) -> None:
        pass


@contextmanager
def serve_fixtures(options: ProbeOptions) -> Iterator[None]:
    server = _QuietServer(
        ("127.0.0.1", 44443), partial(_QuietHandler, directory=str(options.fixtures_root))
    )
    thread: threading.Thread | None = None
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(options.tls_dir / "server.crt", options.tls_dir / "server.key")
        server.socket = context.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        yield
    finally:
        if thread is not None:
            server.shutdown()
            thread.join(timeout=5)
        server.server_close()


def _json_command(argv: Sequence[str], **kwargs: Any) -> dict[str, Any]:
    try:
        result = json.loads(_command(argv, **kwargs), object_pairs_hook=_json_object)
    except ProbeFailure:
        raise
    except Exception:
        raise ProbeFailure("command_json_invalid") from None
    _require(isinstance(result, dict), "command_json_invalid")
    _require(
        result.get("status") == "ok"
        and type(result.get("exit_code")) is int
        and result["exit_code"] == 0,
        "command_outcome_invalid",
    )
    return dict(result)


def _setup_outcome(result: Mapping[str, Any], *, files_dir: Path | None = None) -> None:
    """Require the exact setup JSON shape for the declared installed CLI contract."""
    fields = {"exit_code", "status", "url"}
    if files_dir is not None:
        fields.add("files_dir")
    _require(
        set(result) == fields
        and result["status"] == "ok"
        and type(result["exit_code"]) is int
        and result["exit_code"] == 0
        and result["url"] == "http://127.0.0.1:8080"
        and (files_dir is None or result["files_dir"] == str(files_dir)),
        "setup_outcome_invalid",
    )


def _version(paths: SystemPaths, expected: str) -> None:
    try:
        output = _command((str(paths.cli), "--version"))
    except ProbeFailure as exc:
        if str(exc) == "command_failed":
            raise ProbeFailure("version_query_failed") from None
        raise
    _require(
        output in {f"xferry {expected}".encode(), f"xferry {expected}\n".encode()},
        "cli_version_mismatch",
    )


def _release_state(
    paths: SystemPaths, version: str, retained: tuple[str, ...]
) -> dict[str, object]:
    current = paths.release_root / "current"
    releases = paths.release_root / "releases"
    _require(
        current.is_symlink() and str(current.readlink()) == f"releases/{version}",
        "release_state_invalid",
    )
    _require(releases.is_dir() and not releases.is_symlink(), "release_state_invalid")
    entries = list(releases.iterdir())
    _require(
        {entry.name for entry in entries} == set(retained)
        and all(entry.is_dir() and not entry.is_symlink() for entry in entries),
        "release_state_invalid",
    )
    return {
        "current_link": f"releases/{version}",
        "version": version,
        "retained_versions": list(retained),
    }


def _listener_gone() -> bool:
    try:
        with socket.create_connection(("127.0.0.1", 8080), timeout=2):
            return False
    except ConnectionRefusedError:
        return True
    except OSError:
        return False


def _service(active: bool) -> dict[str, object]:
    try:
        output = _command(
            (
                "systemctl",
                "show",
                "xferry.service",
                "--property=ActiveState",
                "--property=MainPID",
                "--property=LoadState",
            ),
            allowed_codes=(0, 4),
        )
        enabled = _command(
            ("systemctl", "is-enabled", "xferry.service"), allowed_codes=(0, 1, 4)
        ).strip()
    except ProbeFailure as exc:
        if str(exc) == "command_failed":
            raise ProbeFailure("service_query_failed") from None
        raise
    try:
        values = dict(line.split("=", 1) for line in output.decode("ascii").splitlines())
        pid = int(values["MainPID"])
    except Exception:
        raise ProbeFailure("service_state_invalid") from None
    _require(set(values) == {"ActiveState", "MainPID", "LoadState"}, "service_state_invalid")
    if active:
        _require(
            values["ActiveState"] == "active"
            and values["LoadState"] == "loaded"
            and pid > 0
            and enabled == b"enabled",
            "service_state_invalid",
        )
    else:
        _require(
            values["ActiveState"] == "inactive"
            and values["LoadState"] == "not-found"
            and pid == 0
            and enabled in {b"", b"not-found", b"disabled"}
            and _listener_gone(),
            "service_state_invalid",
        )
    return {
        "active": active,
        "main_pid": pid,
        "enabled": enabled == b"enabled",
        "load_state": values["LoadState"],
        "listener_gone": not active,
    }


def _bootstrap(options: ProbeOptions) -> None:
    """Run the unchanged signed installer using the container's exec staging area."""
    environment = os.environ | {
        "XFERRY_RELEASE_BASE_URL": f"{RELEASE_BASE_URL}/download/v{SOURCE_VERSION}",
        "CURL_CA_BUNDLE": str(options.tls_dir / "server.crt"),
        # /tmp deliberately stays noexec; mktemp honors this standard variable.
        "TMPDIR": "/var/tmp",
    }
    try:
        _command(
            (
                "sh",
                str(
                    options.fixtures_root
                    / "releases"
                    / "download"
                    / f"v{SOURCE_VERSION}"
                    / f"install-{options.platform}.sh"
                ),
            ),
            environment=environment,
        )
    except ProbeFailure as exc:
        if str(exc) == "command_failed":
            raise ProbeFailure("install_bootstrap_failed") from None
        raise


def run_probe(options: ProbeOptions, paths: SystemPaths = SYSTEM_PATHS) -> dict[str, object]:
    """Return/write only whitelisted evidence; every caught error is sanitized."""
    evidence: dict[str, Any] = {
        "schema": 1,
        "scope": "native-systemd-container-fixtures",
        "status": "failed",
        "stages": [],
    }
    phase = "guard"
    stage: dict[str, object] = {"phase": phase, "status": "started"}
    evidence["stages"].append(stage)
    try:
        evidence["host"] = guard(options, paths)
        stage["status"] = "passed"
        with serve_fixtures(options):
            phase = "install"
            stage = {"phase": phase, "status": "started"}
            evidence["stages"].append(stage)
            _bootstrap(options)
            _version(paths, SOURCE_VERSION)
            stage.update(_release_state(paths, SOURCE_VERSION, (SOURCE_VERSION,)))
            stage.update(service=_service(False), status="passed")

            phase = "setup"
            stage = {"phase": phase, "status": "started"}
            evidence["stages"].append(stage)
            setup = _json_command(
                (str(paths.cli), "setup", "--access", "private", "--json"), discard_stderr=True
            )
            _setup_outcome(setup, files_dir=paths.data_root / "files")
            _version(paths, SOURCE_VERSION)
            verify_health(SOURCE_VERSION, paths)
            descriptor = os.open(
                paths.sentinel, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
            )
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(b"xferry native systemd lifecycle rehearsal\n")
            baseline = _state_hashes(paths)
            stage.update(_release_state(paths, SOURCE_VERSION, (SOURCE_VERSION,)))
            stage.update(service=_service(True), health=True, status="passed")

            phase = "doctor"
            stage = {"phase": phase, "status": "started"}
            evidence["stages"].append(stage)
            doctor = _json_command((str(paths.cli), "doctor", "--deep", "--json"))
            _require(
                set(doctor) == _DOCTOR_FIELDS
                and doctor["code"] == "doctor-ok"
                and isinstance(doctor["checks"], dict)
                and set(doctor["checks"]) == set(_DOCTOR_STATUSES),
                "doctor_outcome_invalid",
            )
            checks = {
                name: isinstance(doctor["checks"][name], dict)
                and doctor["checks"][name].get("status") == status
                for name, status in _DOCTOR_STATUSES.items()
            }
            stage["checks"] = checks
            _require(all(checks.values()), "doctor_outcome_invalid")
            _version(paths, SOURCE_VERSION)
            verify_health(SOURCE_VERSION, paths)
            stage.update(_release_state(paths, SOURCE_VERSION, (SOURCE_VERSION,)))
            stage.update(service=_service(True), health=True, status="passed")

            for phase in ("dry_run", "update", "rollback", "uninstall"):
                stage = {"phase": phase, "status": "started"}
                evidence["stages"].append(stage)
                if phase in {"dry_run", "update"}:
                    argv = [str(paths.cli), "update", "--to", TARGET_VERSION]
                    if phase == "dry_run":
                        argv.append("--dry-run")
                    result = _json_command(
                        (*argv, "--json"),
                        environment=os.environ
                        | {
                            "SSL_CERT_FILE": str(options.tls_dir / "server.crt"),
                        }
                        | ({"TMPDIR": "/var/tmp"} if phase == "update" else {}),
                    )
                    version = SOURCE_VERSION if phase == "dry_run" else TARGET_VERSION
                    _require(
                        set(result) == _RELEASE_FIELDS | {"version"}
                        and result["code"]
                        == ("update_dry_run" if phase == "dry_run" else "update_complete")
                        and result["dry_run"] is (phase == "dry_run")
                        and result["before"] == SOURCE_VERSION
                        and result["target"] == result["version"] == TARGET_VERSION
                        and result["active"] == version
                        and result["rollback"] == "not_needed",
                        "update_outcome_invalid",
                    )
                else:
                    argv = [str(paths.cli), phase]
                    if phase == "rollback":
                        argv.extend(("--to", SOURCE_VERSION))
                    result = _json_command((*argv, "--json"))
                    expected_fields = _RELEASE_FIELDS | (
                        {"version"} if phase == "rollback" else set()
                    )
                    _require(
                        set(result) == expected_fields
                        and result["code"] == f"{phase}_complete"
                        and result["dry_run"] is False
                        and result["active"] is None
                        and result["before"] is None
                        and result["target"] is None
                        and result["rollback"] == "not_attempted",
                        "release_outcome_invalid",
                    )
                    version = SOURCE_VERSION
                    if phase == "rollback":
                        _require(result["version"] == version, "rollback_outcome_invalid")
                preserved = _preservation(baseline, paths)
                stage["preserved"] = preserved
                _require(all(preserved.values()), "state_preservation_failed")
                if phase == "uninstall":
                    _require(
                        all(
                            not os.path.lexists(path)
                            for path in (paths.release_root, paths.unit, paths.cli)
                        ),
                        "uninstall_state_invalid",
                    )
                    stage.update(service=_service(False), removed=True)
                else:
                    _version(paths, version)
                    verify_health(version, paths)
                    retained = (
                        (SOURCE_VERSION,)
                        if phase == "dry_run"
                        else (SOURCE_VERSION, TARGET_VERSION)
                    )
                    stage.update(_release_state(paths, version, retained))
                    stage.update(service=_service(True), health=True)
                stage["status"] = "passed"
        evidence["status"] = "passed"
    except Exception as exc:
        code = str(exc) if isinstance(exc, ProbeFailure) else "probe_failed"
        stage.update(status="failed", code=code)
        evidence["failure"] = {"phase": phase, "code": code}
    options.evidence.parent.mkdir(parents=True, exist_ok=True)
    options.evidence.write_text(
        json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return evidence


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("fixtures-root", "tls-dir", "evidence"):
        parser.add_argument(f"--{name}", type=Path, required=True)
    for name in ("distro", "distro-version", "machine", "platform", "host-cgroup-namespace"):
        parser.add_argument(f"--{name}", required=True)
    arguments = parser.parse_args(argv)
    try:
        result = run_probe(ProbeOptions(**vars(arguments)))
        print(json.dumps({key: result[key] for key in ("scope", "status")}))
        return 0 if result["status"] == "passed" else 1
    except Exception:
        print('{"status":"failed","phase":"evidence","code":"probe_failed"}')
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
