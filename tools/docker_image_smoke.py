#!/usr/bin/env python3
"""Hardened, disposable Docker image lifecycle smoke for XFerry."""

from __future__ import annotations

import argparse
import http.client
import json
import secrets
import shlex
import subprocess
import sys
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

CONTAINER_PORT = 8080
MEMORY_BYTES = 768 * 1024 * 1024
NANO_CPUS = 1_000_000_000
PIDS_LIMIT = 256
RUN_LABEL = "org.xferry.image-smoke"
RUNTIME_COMMAND = (
    "run",
    "--host",
    "0.0.0.0",
    "--port",
    str(CONTAINER_PORT),
    "--dir",
    "/data",
    "--body-memory-budget",
    "512",
)
TMPFS_OPTIONS = frozenset({"rw", "nosuid", "nodev", "noexec", "mode=1777"})
_FORBIDDEN_LEGACY_TOP_LEVEL_FIELDS = frozenset({"ok", "success", "status"})
_FORBIDDEN_LEGACY_INFO_FIELDS = _FORBIDDEN_LEGACY_TOP_LEVEL_FIELDS | frozenset(
    {"exists", "is_directory"}
)
_FORBIDDEN_LEGACY_INFO_CONTENT_FIELDS = frozenset({"is_dir"})
_FORBIDDEN_LEGACY_DELETE_FIELDS = _FORBIDDEN_LEGACY_TOP_LEVEL_FIELDS | frozenset({"path"})
_FORBIDDEN_LEGACY_MISSING_INFO_FIELDS = _FORBIDDEN_LEGACY_TOP_LEVEL_FIELDS | frozenset(
    {"exists", "is_directory", "is_dir", "path"}
)


class SmokeFailure(RuntimeError):
    """Raised when the image does not satisfy the smoke contract."""


@dataclass(frozen=True)
class ResourceNames:
    """Unique, targeted Docker resource names for one smoke invocation."""

    token: str
    anonymous_container: str
    persistent_first_container: str
    persistent_second_container: str
    named_volume: str


@dataclass(frozen=True)
class RuntimeInspection:
    """Validated runtime details needed by the live probes."""

    host_port: int
    data_volume: str


@dataclass(frozen=True)
class HTTPResponse:
    """Small HTTP response value used by the protocol probes."""

    status: int
    headers: Mapping[str, str]
    body: bytes


def make_resource_names(token: str | None = None) -> ResourceNames:
    """Return collision-resistant names that can be cleaned up individually."""
    run_token = token or secrets.token_hex(6)
    if not run_token or any(character not in "0123456789abcdef" for character in run_token):
        raise ValueError("resource token must contain lowercase hexadecimal characters only")
    prefix = f"xferry-image-smoke-{run_token}"
    return ResourceNames(
        token=run_token,
        anonymous_container=f"{prefix}-anonymous",
        persistent_first_container=f"{prefix}-persistent-1",
        persistent_second_container=f"{prefix}-persistent-2",
        named_volume=f"{prefix}-data",
    )


def validate_image_reference(image: str) -> str:
    """Reject values that Docker could interpret as CLI options."""
    value = image.strip()
    if not value:
        raise ValueError("--image must not be empty")
    if value.startswith("-"):
        raise ValueError("--image must be an image reference, not a Docker option")
    if any(character.isspace() for character in value):
        raise ValueError("--image must not contain whitespace")
    return value


def build_run_command(
    *,
    image: str,
    container_name: str,
    run_token: str,
    volume_name: str | None = None,
    docker_executable: str = "docker",
) -> list[str]:
    """Build the exact hardened Docker command used for every live container."""
    volume = f"{volume_name}:/data" if volume_name else "/data"
    return [
        docker_executable,
        "run",
        "--detach",
        "--rm",
        "--init",
        "--read-only",
        "--tmpfs",
        "/tmp:rw,nosuid,nodev,noexec,mode=1777",
        "--volume",
        volume,
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges=true",
        "--pids-limit",
        str(PIDS_LIMIT),
        "--memory",
        "768m",
        "--cpus",
        "1",
        "--publish",
        f"127.0.0.1::{CONTAINER_PORT}",
        "--name",
        container_name,
        "--label",
        f"{RUN_LABEL}={run_token}",
        image,
        *RUNTIME_COMMAND,
    ]


def _nested(mapping: Mapping[str, Any], *keys: str) -> Any:
    current: Any = mapping
    for key in keys:
        if not isinstance(current, Mapping):
            return None
        current = current.get(key)
    return current


def _sequence(value: Any) -> Sequence[Any]:
    if isinstance(value, Sequence) and not isinstance(value, str | bytes | bytearray):
        return value
    return ()


def reject_forbidden_fields(
    document: Mapping[str, Any],
    *,
    context: str,
    forbidden_fields: frozenset[str],
) -> None:
    """Reject removed response aliases even when canonical fields are present."""
    present = sorted(field for field in forbidden_fields if field in document)
    if present:
        raise SmokeFailure(f"{context} returned forbidden legacy fields: {', '.join(present)}")


def validate_container_inspect(
    inspect_data: Mapping[str, Any],
    *,
    expected_volume_name: str | None,
) -> RuntimeInspection:
    """Validate Docker inspect data and return the assigned port/volume."""
    errors: list[str] = []
    host_config = _nested(inspect_data, "HostConfig")
    if not isinstance(host_config, Mapping):
        raise SmokeFailure("Docker inspect did not contain HostConfig")

    expected_values = {
        "AutoRemove": True,
        "Init": True,
        "ReadonlyRootfs": True,
        "PidsLimit": PIDS_LIMIT,
        "Memory": MEMORY_BYTES,
        "NanoCpus": NANO_CPUS,
    }
    for field, expected in expected_values.items():
        actual = host_config.get(field)
        if actual != expected:
            errors.append(f"HostConfig.{field} is {actual!r}, expected {expected!r}")

    tmpfs = host_config.get("Tmpfs")
    tmpfs_value = tmpfs.get("/tmp") if isinstance(tmpfs, Mapping) else None
    tmpfs_options = {
        option.strip().lower() for option in str(tmpfs_value or "").split(",") if option.strip()
    }
    missing_tmpfs_options = sorted(TMPFS_OPTIONS - tmpfs_options)
    if missing_tmpfs_options:
        errors.append("HostConfig.Tmpfs[/tmp] is missing " + ", ".join(missing_tmpfs_options))

    cap_drop = {str(capability).upper() for capability in _sequence(host_config.get("CapDrop"))}
    if "ALL" not in cap_drop:
        errors.append("HostConfig.CapDrop does not contain ALL")

    security_options = {
        str(option).strip().lower().replace(":", "=")
        for option in _sequence(host_config.get("SecurityOpt"))
    }
    if not ({"no-new-privileges", "no-new-privileges=true"} & security_options):
        errors.append("HostConfig.SecurityOpt does not enable no-new-privileges")

    all_configured_bindings = host_config.get("PortBindings")
    if isinstance(all_configured_bindings, Mapping):
        for container_port, bindings in all_configured_bindings.items():
            for binding in _sequence(bindings):
                host_ip = binding.get("HostIp") if isinstance(binding, Mapping) else None
                if host_ip != "127.0.0.1":
                    errors.append(
                        f"published binding {container_port!r} uses non-loopback IP {host_ip!r}"
                    )

    configured_bindings = _nested(host_config, "PortBindings", f"{CONTAINER_PORT}/tcp")
    configured_binding_items = _sequence(configured_bindings)
    if len(configured_binding_items) != 1:
        errors.append(
            f"HostConfig.PortBindings[{CONTAINER_PORT}/tcp] must have exactly one binding"
        )
    else:
        configured_host = configured_binding_items[0]
        configured_ip = (
            configured_host.get("HostIp") if isinstance(configured_host, Mapping) else None
        )
        if configured_ip != "127.0.0.1":
            errors.append(f"published host IP is {configured_ip!r}, expected loopback '127.0.0.1'")

    runtime_bindings = _nested(
        inspect_data,
        "NetworkSettings",
        "Ports",
        f"{CONTAINER_PORT}/tcp",
    )
    runtime_binding_items = _sequence(runtime_bindings)
    host_port = 0
    if len(runtime_binding_items) != 1:
        errors.append(f"NetworkSettings.Ports[{CONTAINER_PORT}/tcp] must have exactly one binding")
    else:
        runtime_host = runtime_binding_items[0]
        runtime_ip = runtime_host.get("HostIp") if isinstance(runtime_host, Mapping) else None
        runtime_port = runtime_host.get("HostPort") if isinstance(runtime_host, Mapping) else None
        if runtime_ip != "127.0.0.1":
            errors.append(f"runtime host IP is {runtime_ip!r}, expected loopback '127.0.0.1'")
        try:
            host_port = int(str(runtime_port))
        except (TypeError, ValueError):
            errors.append(f"runtime host port is not numeric: {runtime_port!r}")
        else:
            if not 1 <= host_port <= 65535:
                errors.append(f"runtime host port is out of range: {host_port}")

    all_runtime_bindings = _nested(inspect_data, "NetworkSettings", "Ports")
    if isinstance(all_runtime_bindings, Mapping):
        for container_port, bindings in all_runtime_bindings.items():
            for binding in _sequence(bindings):
                host_ip = binding.get("HostIp") if isinstance(binding, Mapping) else None
                if host_ip != "127.0.0.1":
                    errors.append(
                        f"runtime binding {container_port!r} uses non-loopback IP {host_ip!r}"
                    )

    data_mounts = [
        mount
        for mount in _sequence(inspect_data.get("Mounts"))
        if isinstance(mount, Mapping) and mount.get("Destination") == "/data"
    ]
    data_volume = ""
    if len(data_mounts) != 1:
        errors.append("container must have exactly one /data mount")
    else:
        data_mount = data_mounts[0]
        if data_mount.get("Type") != "volume":
            errors.append(f"/data mount type is {data_mount.get('Type')!r}, expected 'volume'")
        if data_mount.get("RW") is not True:
            errors.append("/data volume is not writable")
        volume_value = data_mount.get("Name")
        if not isinstance(volume_value, str) or not volume_value:
            errors.append("/data volume does not have a Docker volume name")
        else:
            data_volume = volume_value
            if expected_volume_name is not None and data_volume != expected_volume_name:
                errors.append(f"/data volume is {data_volume!r}, expected {expected_volume_name!r}")

    if _nested(inspect_data, "State", "Running") is not True:
        errors.append("container is not running")

    configured_user = _nested(inspect_data, "Config", "User")
    if (
        not isinstance(configured_user, str)
        or not configured_user.strip()
        or configured_user.strip().lower() in {"0", "0:0", "root", "root:root"}
    ):
        errors.append(f"Config.User is not an explicit non-root user: {configured_user!r}")

    configured_command = tuple(
        str(item) for item in _sequence(_nested(inspect_data, "Config", "Cmd"))
    )
    if configured_command != RUNTIME_COMMAND:
        errors.append(
            f"Config.Cmd is {list(configured_command)!r}, expected {list(RUNTIME_COMMAND)!r}"
        )

    configured_entrypoint = tuple(
        str(item) for item in _sequence(_nested(inspect_data, "Config", "Entrypoint"))
    )
    if configured_entrypoint != ("xferry",):
        errors.append(f"Config.Entrypoint is {list(configured_entrypoint)!r}, expected ['xferry']")

    if errors:
        raise SmokeFailure("container hardening validation failed:\n- " + "\n- ".join(errors))
    return RuntimeInspection(host_port=host_port, data_volume=data_volume)


class DockerClient:
    """Minimal subprocess wrapper that never uses a shell."""

    def __init__(self, executable: str = "docker") -> None:
        self.executable = executable

    def invoke(
        self,
        arguments: Sequence[str],
        *,
        check: bool = True,
        announce: bool = True,
    ) -> subprocess.CompletedProcess[str]:
        command = [self.executable, *arguments]
        if announce:
            print(f"+ {shlex.join(command)}", flush=True)
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                check=False,
            )
        except FileNotFoundError as exc:
            raise SmokeFailure(f"Docker executable was not found: {self.executable}") from exc
        if check and result.returncode != 0:
            detail = result.stderr.strip() or result.stdout.strip() or "no command output"
            raise SmokeFailure(
                f"Docker command failed with exit code {result.returncode}: "
                f"{shlex.join(command)}\n{detail}"
            )
        return result

    def output(self, arguments: Sequence[str], *, announce: bool = True) -> str:
        return self.invoke(arguments, announce=announce).stdout.strip()

    def container_exists(self, name: str) -> bool:
        return (
            self.invoke(
                ["container", "inspect", name],
                check=False,
                announce=False,
            ).returncode
            == 0
        )

    def volume_exists(self, name: str) -> bool:
        return (
            self.invoke(
                ["volume", "inspect", name],
                check=False,
                announce=False,
            ).returncode
            == 0
        )

    def inspect_container(self, name: str) -> Mapping[str, Any]:
        raw = self.output(["container", "inspect", name])
        try:
            documents = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise SmokeFailure(f"Docker returned invalid inspect JSON for {name}") from exc
        if (
            not isinstance(documents, list)
            or len(documents) != 1
            or not isinstance(documents[0], Mapping)
        ):
            raise SmokeFailure(f"Docker returned an unexpected inspect document for {name}")
        return documents[0]


class ImageSmoke:
    """Run the disposable and explicit-persistence image lifecycle checks."""

    def __init__(
        self,
        *,
        image: str,
        client: DockerClient,
        startup_timeout: float,
        names: ResourceNames,
    ) -> None:
        self.image = image
        self.client = client
        self.startup_timeout = startup_timeout
        self.names = names
        self.owned_containers: set[str] = set()
        self.owned_volumes: set[str] = set()

    def _assert_container_target_absent(self, name: str) -> None:
        if self.client.container_exists(name):
            raise SmokeFailure(f"refusing to reuse existing container name: {name}")

    def _assert_volume_target_absent(self, name: str) -> None:
        if self.client.volume_exists(name):
            raise SmokeFailure(f"refusing to reuse existing volume name: {name}")

    def _start_container(
        self,
        name: str,
        *,
        volume_name: str | None = None,
    ) -> RuntimeInspection:
        self._assert_container_target_absent(name)
        command = build_run_command(
            image=self.image,
            container_name=name,
            run_token=self.names.token,
            volume_name=volume_name,
            docker_executable=self.client.executable,
        )
        result = self.client.invoke(command[1:])
        container_id = result.stdout.strip()
        if not container_id:
            raise SmokeFailure(f"Docker did not return a container ID for {name}")
        self.owned_containers.add(name)
        inspection = validate_container_inspect(
            self.client.inspect_container(name),
            expected_volume_name=volume_name,
        )
        self.owned_volumes.add(inspection.data_volume)
        self._wait_until_ready(name, inspection.host_port)
        return inspection

    def _wait_until_ready(self, container_name: str, host_port: int) -> None:
        deadline = time.monotonic() + self.startup_timeout
        last_error = "server did not answer"
        while time.monotonic() < deadline:
            if not self.client.container_exists(container_name):
                raise SmokeFailure(f"container exited before becoming ready: {container_name}")
            try:
                response = request("127.0.0.1", host_port, "PING", "/")
                assert_ping(response)
                return
            except (OSError, http.client.HTTPException, SmokeFailure) as exc:
                last_error = str(exc)
                time.sleep(0.25)
        logs = self.client.invoke(
            ["logs", container_name],
            check=False,
        )
        diagnostic = logs.stderr.strip() or logs.stdout.strip()
        raise SmokeFailure(
            f"container {container_name} was not ready within "
            f"{self.startup_timeout:g}s: {last_error}\n{diagnostic}"
        )

    def _stop_auto_remove_container(self, name: str) -> None:
        self.client.invoke(["stop", "--time", "10", name])
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if not self.client.container_exists(name):
                self.owned_containers.discard(name)
                return
            time.sleep(0.1)
        raise SmokeFailure(f"container still exists after stop/--rm: {name}")

    def _wait_for_volume_absence(self, name: str) -> None:
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if not self.client.volume_exists(name):
                self.owned_volumes.discard(name)
                return
            time.sleep(0.1)
        raise SmokeFailure(f"volume still exists after container removal: {name}")

    def _create_named_volume(self) -> None:
        volume = self.names.named_volume
        self._assert_volume_target_absent(volume)
        created = self.client.output(
            [
                "volume",
                "create",
                "--label",
                f"{RUN_LABEL}={self.names.token}",
                volume,
            ]
        )
        if created != volume:
            raise SmokeFailure(
                f"Docker reported unexpected created volume {created!r}, expected {volume!r}"
            )
        self.owned_volumes.add(volume)

    def _remove_named_volume(self) -> None:
        volume = self.names.named_volume
        self.client.invoke(["volume", "rm", volume])
        if self.client.volume_exists(volume):
            raise SmokeFailure(f"targeted volume removal did not remove {volume}")
        self.owned_volumes.discard(volume)

    def run(
        self,
        *,
        browser_first_run: Callable[[int], None] | None = None,
    ) -> None:
        anonymous_payload = b"xferry anonymous lifecycle\x00\xff\n"
        persistent_payload = b"xferry named-volume persistence\x00\xfe\n"
        anonymous_filename = f"anonymous-{self.names.token}.bin"
        persistent_filename = f"persistent-{self.names.token}.bin"

        print(f"Smoke run token: {self.names.token}")
        print("Checking disposable anonymous-volume lifecycle...")
        anonymous = self._start_container(self.names.anonymous_container)
        probe_container_filesystems(self.client, self.names.anonymous_container, self.names.token)
        if browser_first_run is not None:
            print("Checking the shared browser first-run against the hardened container...")
            browser_first_run(anonymous.host_port)
            print(f"PASS hardened image browser first-run: http://127.0.0.1:{anonymous.host_port}/")
        run_full_file_lifecycle(
            anonymous.host_port,
            filename=anonymous_filename,
            payload=anonymous_payload,
        )
        self._stop_auto_remove_container(self.names.anonymous_container)
        self._wait_for_volume_absence(anonymous.data_volume)
        print(
            "PASS anonymous cleanup: "
            f"container={self.names.anonymous_container} absent, "
            f"volume={anonymous.data_volume} absent"
        )

        print("Checking explicit named-volume persistence lifecycle...")
        self._create_named_volume()
        persistent_first = self._start_container(
            self.names.persistent_first_container,
            volume_name=self.names.named_volume,
        )
        uploaded_path = upload_file(
            persistent_first.host_port,
            filename=persistent_filename,
            payload=persistent_payload,
        )
        assert_file_browse_and_fetch(
            persistent_first.host_port,
            path=uploaded_path,
            payload=persistent_payload,
        )
        self._stop_auto_remove_container(self.names.persistent_first_container)
        if not self.client.volume_exists(self.names.named_volume):
            raise SmokeFailure("named volume disappeared with the first container")
        print(f"PASS named-volume survival after first removal: volume={self.names.named_volume}")

        persistent_second = self._start_container(
            self.names.persistent_second_container,
            volume_name=self.names.named_volume,
        )
        assert_file_browse_and_fetch(
            persistent_second.host_port,
            path=uploaded_path,
            payload=persistent_payload,
        )
        self._stop_auto_remove_container(self.names.persistent_second_container)
        if not self.client.volume_exists(self.names.named_volume):
            raise SmokeFailure("named volume disappeared with the recreated container")
        print(
            f"PASS named-volume survival after recreate/removal: volume={self.names.named_volume}"
        )

        self._remove_named_volume()
        print(f"PASS explicit targeted volume removal: volume={self.names.named_volume} absent")

    def cleanup(self) -> None:
        """Remove only resources whose unique names were created by this run."""
        for container_name in sorted(self.owned_containers):
            self.client.invoke(
                ["rm", "--force", "--volumes", container_name],
                check=False,
            )
        for volume_name in sorted(self.owned_volumes):
            self.client.invoke(
                ["volume", "rm", volume_name],
                check=False,
            )


def request(
    host: str,
    port: int,
    method: str,
    path: str,
    *,
    body: bytes | None = None,
    headers: Mapping[str, str] | None = None,
) -> HTTPResponse:
    """Issue one local HTTP request with custom XFerry methods supported."""
    request_headers = {
        "Accept-Encoding": "identity",
        "Connection": "close",
        **dict(headers or {}),
    }
    connection = http.client.HTTPConnection(host, port, timeout=3)
    try:
        connection.request(method, path, body=body, headers=request_headers)
        response = connection.getresponse()
        response_body = response.read()
        response_headers = {name.lower(): value for name, value in response.getheaders()}
        return HTTPResponse(
            status=response.status,
            headers=response_headers,
            body=response_body,
        )
    finally:
        connection.close()


def parse_json_response(response: HTTPResponse, *, context: str) -> Mapping[str, Any]:
    try:
        parsed = json.loads(response.body)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SmokeFailure(f"{context} returned invalid JSON") from exc
    if not isinstance(parsed, Mapping):
        raise SmokeFailure(f"{context} returned a non-object JSON document")
    return parsed


def require_status(response: HTTPResponse, expected: int, *, context: str) -> None:
    if response.status != expected:
        excerpt = response.body[:500].decode("utf-8", errors="replace")
        raise SmokeFailure(
            f"{context} returned HTTP {response.status}, expected {expected}: {excerpt}"
        )


def assert_ping(response: HTTPResponse) -> None:
    require_status(response, 200, context="PING")
    payload = parse_json_response(response, context="PING")
    reject_forbidden_fields(
        payload,
        context="PING",
        forbidden_fields=_FORBIDDEN_LEGACY_TOP_LEVEL_FIELDS,
    )
    if payload.get("health") != "ready":
        raise SmokeFailure(f"PING health is {payload.get('health')!r}, expected 'ready'")
    methods = set(_sequence(payload.get("supported_methods")))
    required_methods = {"PING", "POST", "INFO", "FETCH", "DELETE"}
    if not required_methods.issubset(methods):
        missing = ", ".join(sorted(required_methods - methods))
        raise SmokeFailure(f"PING is missing required methods: {missing}")


def upload_file(port: int, *, filename: str, payload: bytes) -> str:
    response = request(
        "127.0.0.1",
        port,
        "POST",
        "/",
        body=payload,
        headers={
            "Content-Type": "application/octet-stream",
            "X-File-Name": filename,
        },
    )
    require_status(response, 201, context="POST upload")
    document = parse_json_response(response, context="POST upload")
    reject_forbidden_fields(
        document,
        context="POST upload",
        forbidden_fields=_FORBIDDEN_LEGACY_TOP_LEVEL_FIELDS,
    )
    file = document.get("file")
    if not isinstance(file, Mapping):
        raise SmokeFailure(f"POST upload returned an unexpected payload: {document!r}")
    path = file.get("path")
    if not isinstance(path, str):
        raise SmokeFailure(f"POST upload returned an unexpected payload: {document!r}")
    if file.get("name") != filename or path != f"/uploads/{filename}":
        raise SmokeFailure(f"POST upload returned an inconsistent file identity: {document!r}")
    if file.get("size_bytes") != len(payload):
        raise SmokeFailure(
            f"POST upload reported size {file.get('size_bytes')!r}, expected {len(payload)}"
        )
    return path


def assert_file_browse_and_fetch(port: int, *, path: str, payload: bytes) -> None:
    filename = path.rsplit("/", maxsplit=1)[-1]
    info_response = request(
        "127.0.0.1",
        port,
        "INFO",
        "/uploads/?offset=0&limit=1000",
    )
    require_status(info_response, 200, context="INFO browse")
    info = parse_json_response(info_response, context="INFO browse")
    reject_forbidden_fields(
        info,
        context="INFO browse",
        forbidden_fields=_FORBIDDEN_LEGACY_INFO_FIELDS,
    )
    entry = info.get("entry")
    page = info.get("page")
    contents_value = info.get("contents")
    contents = _sequence(contents_value)
    matching_items = [
        item for item in contents if isinstance(item, Mapping) and item.get("name") == filename
    ]
    for item in contents:
        if isinstance(item, Mapping):
            reject_forbidden_fields(
                item,
                context="INFO browse contents item",
                forbidden_fields=_FORBIDDEN_LEGACY_INFO_CONTENT_FIELDS,
            )
    if (
        not isinstance(entry, Mapping)
        or entry.get("exists") is not True
        or entry.get("path") != "/uploads"
        or entry.get("kind") != "directory"
        or not isinstance(page, Mapping)
        or not isinstance(contents_value, list)
        or len(matching_items) != 1
        or matching_items[0].get("kind") != "file"
        or "inspection" not in matching_items[0]
        or matching_items[0].get("inspection") is not None
    ):
        raise SmokeFailure(f"INFO browse did not contain uploaded file {filename!r}")

    fetch_response = request("127.0.0.1", port, "FETCH", path)
    require_status(fetch_response, 200, context="FETCH download")
    if not fetch_response.headers.get("content-disposition"):
        raise SmokeFailure("FETCH did not include Content-Disposition")
    if fetch_response.body != payload:
        raise SmokeFailure(
            f"FETCH returned {len(fetch_response.body)} bytes, expected exact "
            f"{len(payload)}-byte payload"
        )


def run_full_file_lifecycle(port: int, *, filename: str, payload: bytes) -> None:
    ping_response = request("127.0.0.1", port, "PING", "/")
    assert_ping(ping_response)
    uploaded_path = upload_file(port, filename=filename, payload=payload)
    assert_file_browse_and_fetch(port, path=uploaded_path, payload=payload)

    delete_response = request("127.0.0.1", port, "DELETE", uploaded_path)
    require_status(delete_response, 200, context="DELETE")
    deleted = parse_json_response(delete_response, context="DELETE")
    reject_forbidden_fields(
        deleted,
        context="DELETE",
        forbidden_fields=_FORBIDDEN_LEGACY_DELETE_FIELDS,
    )
    deleted_file = deleted.get("deleted_file")
    if (
        not isinstance(deleted_file, Mapping)
        or deleted_file.get("name") != filename
        or deleted_file.get("path") != uploaded_path
    ):
        raise SmokeFailure(f"DELETE returned an unexpected payload: {deleted!r}")

    missing_response = request("127.0.0.1", port, "INFO", uploaded_path)
    require_status(missing_response, 404, context="post-delete INFO")
    missing = parse_json_response(missing_response, context="post-delete INFO")
    reject_forbidden_fields(
        missing,
        context="post-delete INFO",
        forbidden_fields=_FORBIDDEN_LEGACY_MISSING_INFO_FIELDS,
    )
    error = missing.get("error")
    details = error.get("details") if isinstance(error, Mapping) else None
    if (
        not isinstance(error, Mapping)
        or error.get("code") != "resource_not_found"
        or error.get("field") != "path"
        or not isinstance(details, Mapping)
        or details.get("path") != uploaded_path
    ):
        raise SmokeFailure(f"post-delete INFO did not prove absence: {missing!r}")

    listing_response = request("127.0.0.1", port, "INFO", "/uploads/")
    require_status(listing_response, 200, context="post-delete INFO browse")
    listing = parse_json_response(listing_response, context="post-delete INFO browse")
    reject_forbidden_fields(
        listing,
        context="post-delete INFO browse",
        forbidden_fields=_FORBIDDEN_LEGACY_INFO_FIELDS,
    )
    listing_entry = listing.get("entry")
    listing_page = listing.get("page")
    listing_contents = listing.get("contents")
    if (
        not isinstance(listing_entry, Mapping)
        or listing_entry.get("exists") is not True
        or listing_entry.get("path") != "/uploads"
        or listing_entry.get("kind") != "directory"
        or not isinstance(listing_page, Mapping)
        or not isinstance(listing_contents, list)
    ):
        raise SmokeFailure(f"post-delete INFO browse returned an unexpected payload: {listing!r}")
    for item in listing_contents:
        if isinstance(item, Mapping):
            reject_forbidden_fields(
                item,
                context="post-delete INFO browse contents item",
                forbidden_fields=_FORBIDDEN_LEGACY_INFO_CONTENT_FIELDS,
            )
    filename_after_delete = uploaded_path.rsplit("/", maxsplit=1)[-1]
    if any(
        isinstance(item, Mapping) and item.get("name") == filename_after_delete
        for item in listing_contents
    ):
        raise SmokeFailure("deleted file still appears in INFO browse")


def probe_container_filesystems(
    client: DockerClient,
    container_name: str,
    run_token: str,
) -> None:
    """Prove writable tmp/data mounts and a read-only user-owned image path."""
    script = f"""
import errno
import os
from pathlib import Path

if os.getuid() != 10001:
    raise SystemExit(f"container process UID is {{os.getuid()}}, expected 10001")

payload = b"xferry-filesystem-smoke"
writable = [
    Path("/tmp/xferry-smoke-{run_token}"),
    Path("/data/xferry-smoke-{run_token}"),
]
for path in writable:
    path.write_bytes(payload)
    if path.read_bytes() != payload:
        raise SystemExit(f"writable path round trip failed: {{path}}")
    path.unlink()

read_only_path = Path("/home/xferry/xferry-smoke-{run_token}")
try:
    read_only_path.write_bytes(payload)
except OSError as exc:
    if exc.errno != errno.EROFS:
        raise
else:
    read_only_path.unlink(missing_ok=True)
    raise SystemExit(f"non-data image path was writable: {{read_only_path}}")
""".strip()
    client.invoke(["exec", container_name, "python", "-c", script])


def run_browser_first_run(
    port: int,
    *,
    artifacts_dir: str | Path | None = None,
    python_executable: str = sys.executable,
) -> None:
    """Run the canonical external-target browser journey against one container."""
    browser_script = Path(__file__).resolve().with_name("browser_smoke.py")
    command = [
        python_executable,
        str(browser_script),
        "--mode",
        "first-run",
        "--target-url",
        f"http://127.0.0.1:{port}/",
    ]
    if artifacts_dir is not None:
        command.extend(["--artifacts-dir", str(Path(artifacts_dir).expanduser().resolve())])
    print(f"+ {shlex.join(command)}", flush=True)
    result = subprocess.run(
        command,
        cwd=browser_script.parents[1],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.stdout.strip():
        print(result.stdout.rstrip())
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or "no browser-smoke output"
        raise SmokeFailure(
            f"hardened image browser first-run failed with exit code {result.returncode}:\n{detail}"
        )


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Smoke an XFerry Docker image with hardened disposable and persistent lifecycles."
        )
    )
    parser.add_argument("--image", required=True, help="Local or registry Docker image reference")
    parser.add_argument(
        "--startup-timeout",
        type=float,
        default=45,
        help="Seconds to wait for each container to answer PING (default: 45)",
    )
    parser.add_argument(
        "--browser-first-run",
        action="store_true",
        help="Run the canonical browser first-run against the hardened anonymous container.",
    )
    parser.add_argument(
        "--browser-artifacts-dir",
        help="Directory for browser first-run result/failure diagnostics.",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_argument_parser().parse_args(argv)
    try:
        image = validate_image_reference(args.image)
        if args.startup_timeout <= 0:
            raise ValueError("--startup-timeout must be greater than zero")
        if args.browser_artifacts_dir and not args.browser_first_run:
            raise ValueError("--browser-artifacts-dir requires --browser-first-run")
        smoke = ImageSmoke(
            image=image,
            client=DockerClient(),
            startup_timeout=args.startup_timeout,
            names=make_resource_names(),
        )
        try:

            def configured_browser_probe(port: int) -> None:
                run_browser_first_run(
                    port,
                    artifacts_dir=args.browser_artifacts_dir,
                )

            smoke.run(
                browser_first_run=(configured_browser_probe if args.browser_first_run else None)
            )
        finally:
            smoke.cleanup()
    except (SmokeFailure, ValueError) as exc:
        print(f"docker image smoke failed: {exc}", file=sys.stderr)
        return 1
    print(f"Docker image smoke passed: {image}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
