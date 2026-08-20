"""Focused tests for the reusable hardened Docker image smoke."""

from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
from subprocess import CompletedProcess
from typing import Any

import pytest

from tools import docker_image_smoke
from tools.docker_image_smoke import (
    MEMORY_BYTES,
    NANO_CPUS,
    RUN_LABEL,
    RUNTIME_COMMAND,
    HTTPResponse,
    SmokeFailure,
    assert_file_browse_and_fetch,
    assert_ping,
    build_argument_parser,
    build_run_command,
    make_resource_names,
    run_browser_first_run,
    run_full_file_lifecycle,
    upload_file,
    validate_container_inspect,
    validate_image_reference,
)

REPO_ROOT = Path(__file__).resolve().parents[1]


def _json_response(*, status: int, document: dict[str, Any]) -> HTTPResponse:
    return HTTPResponse(status=status, headers={}, body=json.dumps(document).encode())


def _canonical_browse_document() -> dict[str, Any]:
    return {
        "entry": {"exists": True, "path": "/uploads", "kind": "directory"},
        "page": {"offset": 0, "limit": 1000, "total_items": 1, "returned_items": 1},
        "contents": [{"name": "probe.bin", "kind": "file", "inspection": None}],
    }


def test_smoke_ping_accepts_canonical_ready_json_without_a_pong_header() -> None:
    """Catches smoke readiness retaining the removed X-Ping-Response dependency."""
    assert_ping(
        HTTPResponse(
            status=200,
            headers={"x-ping-response": "not-pong"},
            body=(
                b'{"health":"ready","supported_methods":["PING","POST","INFO","FETCH","DELETE"]}'
            ),
        )
    )


def test_smoke_upload_reads_the_canonical_file_envelope(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Catches smoke upload validation reading flat aliases or X-Upload-Status."""
    monkeypatch.setattr(
        docker_image_smoke,
        "request",
        lambda *_args, **_kwargs: HTTPResponse(
            status=201,
            headers={},
            body=b'{"file":{"name":"probe.bin","path":"/uploads/probe.bin","size_bytes":4}}',
        ),
    )

    assert upload_file(49152, filename="probe.bin", payload=b"data") == "/uploads/probe.bin"


def test_smoke_fetch_checks_content_disposition_not_a_result_header(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Catches smoke FETCH validation retaining the removed X-Fetch-Status contract."""

    def request_response(*_args: object, **_kwargs: object) -> HTTPResponse:
        method = _args[2]
        if method == "INFO":
            return HTTPResponse(
                status=200,
                headers={},
                body=b'{"entry":{"exists":true,"path":"/uploads","kind":"directory"},'
                b'"page":{"offset":0,"limit":1000,"total_items":1,"returned_items":1},'
                b'"contents":[{"name":"probe.bin","kind":"file","inspection":null}]}',
            )
        return HTTPResponse(
            status=200,
            headers={"content-disposition": 'attachment; filename="probe.bin"'},
            body=b"data",
        )

    monkeypatch.setattr(docker_image_smoke, "request", request_response)

    assert_file_browse_and_fetch(49152, path="/uploads/probe.bin", payload=b"data")


@pytest.mark.parametrize(
    ("field", "value"),
    [("ok", True), ("success", True), ("status", 200)],
)
def test_smoke_rejects_top_level_legacy_aliases_in_canonical_ping(
    field: str,
    value: object,
) -> None:
    """Catches PING accepting legacy success aliases alongside canonical fields."""
    document = {
        "health": "ready",
        "supported_methods": ["PING", "POST", "INFO", "FETCH", "DELETE"],
        field: value,
    }

    with pytest.raises(SmokeFailure, match="forbidden legacy fields"):
        assert_ping(_json_response(status=200, document=document))


@pytest.mark.parametrize(
    ("field", "value"),
    [("ok", True), ("success", True), ("status", 201)],
)
def test_smoke_rejects_top_level_legacy_aliases_in_canonical_upload(
    monkeypatch: pytest.MonkeyPatch,
    field: str,
    value: object,
) -> None:
    """Catches upload accepting legacy success aliases alongside the file envelope."""
    document = {
        "file": {"name": "probe.bin", "path": "/uploads/probe.bin", "size_bytes": 4},
        field: value,
    }
    monkeypatch.setattr(
        docker_image_smoke,
        "request",
        lambda *_args, **_kwargs: _json_response(status=201, document=document),
    )

    with pytest.raises(SmokeFailure, match="forbidden legacy fields"):
        upload_file(49152, filename="probe.bin", payload=b"data")


@pytest.mark.parametrize(
    ("top_level_alias", "item_alias"),
    [
        ("ok", None),
        ("success", None),
        ("status", None),
        ("exists", None),
        ("is_directory", None),
        (None, "is_dir"),
    ],
)
def test_smoke_rejects_legacy_aliases_coexisting_with_canonical_info(
    monkeypatch: pytest.MonkeyPatch,
    top_level_alias: str | None,
    item_alias: str | None,
) -> None:
    """Catches INFO accepting legacy aliases when the 3.0 envelope is also present."""
    document = _canonical_browse_document()
    if top_level_alias is not None:
        document[top_level_alias] = 200 if top_level_alias == "status" else True
    if item_alias is not None:
        document["contents"][0][item_alias] = False

    def request_response(*args: object, **_kwargs: object) -> HTTPResponse:
        if args[2] == "INFO":
            return _json_response(status=200, document=document)
        return HTTPResponse(
            status=200,
            headers={"content-disposition": 'attachment; filename="probe.bin"'},
            body=b"data",
        )

    monkeypatch.setattr(docker_image_smoke, "request", request_response)

    with pytest.raises(SmokeFailure, match="forbidden legacy fields"):
        assert_file_browse_and_fetch(49152, path="/uploads/probe.bin", payload=b"data")


@pytest.mark.parametrize(
    ("target", "field", "value"),
    [
        (("DELETE", "/uploads/probe.bin"), "path", "/uploads/probe.bin"),
        (("INFO", "/uploads/probe.bin"), "exists", False),
        (("INFO", "/uploads/probe.bin"), "path", "/uploads/probe.bin"),
    ],
)
def test_smoke_rejects_legacy_aliases_coexisting_with_canonical_lifecycle_bodies(
    monkeypatch: pytest.MonkeyPatch,
    target: tuple[str, str],
    field: str,
    value: object,
) -> None:
    """Catches DELETE and missing-INFO compatibility leakage in full lifecycle checks."""
    uploaded_path = "/uploads/probe.bin"

    def request_response(*args: object, **_kwargs: object) -> HTTPResponse:
        method = args[2]
        path = args[3]
        assert isinstance(method, str)
        assert isinstance(path, str)
        if method == "PING":
            return _json_response(
                status=200,
                document={
                    "health": "ready",
                    "supported_methods": ["PING", "POST", "INFO", "FETCH", "DELETE"],
                },
            )
        if method == "POST":
            return _json_response(
                status=201,
                document={
                    "file": {
                        "name": "probe.bin",
                        "path": uploaded_path,
                        "size_bytes": 4,
                    }
                },
            )
        if method == "INFO" and path == "/uploads/?offset=0&limit=1000":
            return _json_response(status=200, document=_canonical_browse_document())
        if method == "FETCH":
            return HTTPResponse(
                status=200,
                headers={"content-disposition": 'attachment; filename="probe.bin"'},
                body=b"data",
            )
        if method == "DELETE":
            document: dict[str, Any] = {
                "deleted_file": {"name": "probe.bin", "path": uploaded_path}
            }
            if (method, path) == target:
                document[field] = value
            return _json_response(status=200, document=document)
        if method == "INFO" and path == uploaded_path:
            document = {
                "error": {
                    "code": "resource_not_found",
                    "message": "file is gone",
                    "field": "path",
                    "details": {"path": uploaded_path},
                }
            }
            if (method, path) == target:
                document[field] = value
            return _json_response(status=404, document=document)
        if method == "INFO" and path == "/uploads/":
            return _json_response(
                status=200,
                document={
                    "entry": {"exists": True, "path": "/uploads", "kind": "directory"},
                    "page": {"offset": 0, "limit": 100, "total_items": 0, "returned_items": 0},
                    "contents": [],
                },
            )
        raise AssertionError(f"unexpected smoke request: {method} {path}")

    monkeypatch.setattr(docker_image_smoke, "request", request_response)

    with pytest.raises(SmokeFailure, match="forbidden legacy fields"):
        run_full_file_lifecycle(49152, filename="probe.bin", payload=b"data")


def test_smoke_rejects_legacy_info_browse_aliases(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Catches INFO parsing that falls back to removed 2.x browse aliases."""

    def request_response(*args: object, **_kwargs: object) -> HTTPResponse:
        if args[2] == "INFO":
            return HTTPResponse(
                status=200,
                headers={},
                body=b'{"exists":true,"is_directory":true,"contents":['
                b'{"name":"probe.bin","is_dir":false}]}',
            )
        return HTTPResponse(
            status=200,
            headers={"content-disposition": 'attachment; filename="probe.bin"'},
            body=b"data",
        )

    monkeypatch.setattr(docker_image_smoke, "request", request_response)

    with pytest.raises(SmokeFailure, match="forbidden legacy fields"):
        assert_file_browse_and_fetch(49152, path="/uploads/probe.bin", payload=b"data")


def test_smoke_runs_the_full_file_lifecycle_against_canonical_3_contracts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Catches lifecycle checks retaining removed INFO, DELETE, or error envelopes."""
    uploaded_path = "/uploads/probe.bin"
    requests: list[tuple[str, str]] = []

    def request_response(*args: object, **_kwargs: object) -> HTTPResponse:
        method = args[2]
        path = args[3]
        assert isinstance(method, str)
        assert isinstance(path, str)
        requests.append((method, path))
        if method == "PING":
            return HTTPResponse(
                status=200,
                headers={},
                body=(
                    b'{"health":"ready","supported_methods":['
                    b'"PING","POST","INFO","FETCH","DELETE"]}'
                ),
            )
        if method == "POST":
            return HTTPResponse(
                status=201,
                headers={},
                body=(b'{"file":{"name":"probe.bin","path":"/uploads/probe.bin","size_bytes":4}}'),
            )
        if method == "INFO" and path == "/uploads/?offset=0&limit=1000":
            return HTTPResponse(
                status=200,
                headers={},
                body=(
                    b'{"entry":{"exists":true,"path":"/uploads","kind":"directory"},'
                    b'"page":{"offset":0,"limit":1000,"total_items":1,"returned_items":1},'
                    b'"contents":[{"name":"probe.bin","kind":"file","inspection":null}]}'
                ),
            )
        if method == "FETCH":
            return HTTPResponse(
                status=200,
                headers={"content-disposition": 'attachment; filename="probe.bin"'},
                body=b"data",
            )
        if method == "DELETE":
            return HTTPResponse(
                status=200,
                headers={},
                body=b'{"deleted_file":{"name":"probe.bin","path":"/uploads/probe.bin"}}',
            )
        if method == "INFO" and path == uploaded_path:
            return HTTPResponse(
                status=404,
                headers={},
                body=(
                    b'{"error":{"code":"resource_not_found","message":"file is gone",'
                    b'"field":"path","details":{"path":"/uploads/probe.bin"}}}'
                ),
            )
        if method == "INFO" and path == "/uploads/":
            return HTTPResponse(
                status=200,
                headers={},
                body=(
                    b'{"entry":{"exists":true,"path":"/uploads","kind":"directory"},'
                    b'"page":{"offset":0,"limit":100,"total_items":0,"returned_items":0},'
                    b'"contents":[]}'
                ),
            )
        raise AssertionError(f"unexpected smoke request: {method} {path}")

    monkeypatch.setattr(docker_image_smoke, "request", request_response)

    run_full_file_lifecycle(49152, filename="probe.bin", payload=b"data")

    assert requests == [
        ("PING", "/"),
        ("POST", "/"),
        ("INFO", "/uploads/?offset=0&limit=1000"),
        ("FETCH", uploaded_path),
        ("DELETE", uploaded_path),
        ("INFO", uploaded_path),
        ("INFO", "/uploads/"),
    ]


def _workflow_job(workflow: str, job_name: str) -> str:
    lines = workflow.splitlines()
    marker = f"  {job_name}:"
    try:
        start = lines.index(marker)
    except ValueError as exc:
        raise AssertionError(f"workflow job {job_name!r} is missing") from exc

    end = len(lines)
    for index in range(start + 1, len(lines)):
        line = lines[index]
        if len(line) - len(line.lstrip()) == 2 and line.endswith(":"):
            end = index
            break
    return "\n".join(lines[start:end])


def valid_inspect_document() -> dict[str, Any]:
    return {
        "State": {"Running": True},
        "Config": {
            "User": "xferry",
            "Entrypoint": ["xferry"],
            "Cmd": list(RUNTIME_COMMAND),
        },
        "HostConfig": {
            "AutoRemove": True,
            "Init": True,
            "ReadonlyRootfs": True,
            "Tmpfs": {"/tmp": "rw,nosuid,nodev,noexec,mode=1777"},
            "CapDrop": ["ALL"],
            "SecurityOpt": ["no-new-privileges=true"],
            "PidsLimit": 256,
            "Memory": MEMORY_BYTES,
            "NanoCpus": NANO_CPUS,
            "PortBindings": {
                "8080/tcp": [{"HostIp": "127.0.0.1", "HostPort": ""}],
            },
        },
        "NetworkSettings": {
            "Ports": {
                "8080/tcp": [{"HostIp": "127.0.0.1", "HostPort": "49152"}],
            }
        },
        "Mounts": [
            {
                "Type": "volume",
                "Name": "xferry-image-smoke-deadbeef-data",
                "Destination": "/data",
                "RW": True,
            }
        ],
    }


def test_anonymous_run_command_has_exact_hardening_and_loopback_publish() -> None:
    command = build_run_command(
        image="xferry:test",
        container_name="xferry-image-smoke-deadbeef-anonymous",
        run_token="deadbeef",
    )

    assert command == [
        "docker",
        "run",
        "--detach",
        "--rm",
        "--init",
        "--read-only",
        "--tmpfs",
        "/tmp:rw,nosuid,nodev,noexec,mode=1777",
        "--volume",
        "/data",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges=true",
        "--pids-limit",
        "256",
        "--memory",
        "768m",
        "--cpus",
        "1",
        "--publish",
        "127.0.0.1::8080",
        "--name",
        "xferry-image-smoke-deadbeef-anonymous",
        "--label",
        f"{RUN_LABEL}=deadbeef",
        "xferry:test",
        "run",
        "--host",
        "0.0.0.0",
        "--port",
        "8080",
        "--dir",
        "/data",
        "--body-memory-budget",
        "512",
    ]
    assert "prune" not in command


def test_dockerfile_effective_default_argv_starts_with_canonical_run_command() -> None:
    """Catches an image that retains root-level server flags after packaging succeeds."""
    dockerfile = (REPO_ROOT / "Dockerfile").read_text(encoding="utf-8")

    assert 'ENTRYPOINT ["xferry"]' in dockerfile
    assert 'CMD ["run", "--host", "0.0.0.0", "--port", "8080", "--dir", "/data"]' in dockerfile


def test_named_volume_run_changes_only_data_volume_source() -> None:
    anonymous = build_run_command(
        image="xferry:test",
        container_name="xferry-image-smoke-deadbeef-anonymous",
        run_token="deadbeef",
    )
    persistent = build_run_command(
        image="xferry:test",
        container_name="xferry-image-smoke-deadbeef-persistent",
        run_token="deadbeef",
        volume_name="xferry-image-smoke-deadbeef-data",
    )

    anonymous[anonymous.index("/data")] = "xferry-image-smoke-deadbeef-data:/data"
    anonymous[anonymous.index("xferry-image-smoke-deadbeef-anonymous")] = (
        "xferry-image-smoke-deadbeef-persistent"
    )
    assert persistent == anonymous


def test_resource_names_are_unique_and_targeted() -> None:
    first = make_resource_names()
    second = make_resource_names()

    assert first != second
    assert first.token in first.anonymous_container
    assert first.token in first.persistent_first_container
    assert first.token in first.persistent_second_container
    assert first.token in first.named_volume
    assert (
        len(
            {
                first.anonymous_container,
                first.persistent_first_container,
                first.persistent_second_container,
                first.named_volume,
            }
        )
        == 4
    )


@pytest.mark.parametrize("image", ["", "   ", "--privileged", "xferry:test\n--privileged"])
def test_image_reference_rejects_empty_options_and_whitespace(image: str) -> None:
    with pytest.raises(ValueError):
        validate_image_reference(image)


def test_inspect_validator_returns_assigned_loopback_port_and_volume() -> None:
    inspection = validate_container_inspect(
        valid_inspect_document(),
        expected_volume_name="xferry-image-smoke-deadbeef-data",
    )

    assert inspection.host_port == 49152
    assert inspection.data_volume == "xferry-image-smoke-deadbeef-data"


def test_inspect_validator_rejects_entrypoint_drift() -> None:
    """Catches a runnable image whose configured entrypoint is not XFerry."""
    document = valid_inspect_document()
    document["Config"]["Entrypoint"] = ["python"]

    with pytest.raises(SmokeFailure, match="Config.Entrypoint"):
        validate_container_inspect(
            document,
            expected_volume_name="xferry-image-smoke-deadbeef-data",
        )


@pytest.mark.parametrize(
    ("path", "value", "message"),
    [
        (("HostConfig", "AutoRemove"), False, "AutoRemove"),
        (("HostConfig", "Init"), False, "Init"),
        (("HostConfig", "ReadonlyRootfs"), False, "ReadonlyRootfs"),
        (("HostConfig", "Tmpfs"), {"/tmp": "rw,nosuid,nodev"}, "noexec"),
        (
            ("HostConfig", "Tmpfs"),
            {"/tmp": "rw,nosuid,nodev,noexec"},
            "mode=1777",
        ),
        (("HostConfig", "CapDrop"), [], "CapDrop"),
        (("HostConfig", "SecurityOpt"), [], "no-new-privileges"),
        (("HostConfig", "PidsLimit"), 255, "PidsLimit"),
        (("HostConfig", "Memory"), MEMORY_BYTES - 1, "Memory"),
        (("HostConfig", "NanoCpus"), NANO_CPUS - 1, "NanoCpus"),
        (
            ("HostConfig", "PortBindings"),
            {"8080/tcp": [{"HostIp": "0.0.0.0", "HostPort": ""}]},
            "loopback",
        ),
        (
            ("NetworkSettings", "Ports"),
            {"8080/tcp": [{"HostIp": "0.0.0.0", "HostPort": "49152"}]},
            "loopback",
        ),
        (("Mounts",), [], "exactly one /data"),
        (("State", "Running"), False, "not running"),
        (("Config", "User"), "", "non-root user"),
        (("Config", "User"), "root", "non-root user"),
        (
            ("Config", "Cmd"),
            ["--host", "0.0.0.0", "--port", "8080", "--dir", "/data"],
            "body-memory-budget",
        ),
    ],
)
def test_inspect_validator_rejects_hardening_drift(
    path: tuple[str, ...],
    value: object,
    message: str,
) -> None:
    document = deepcopy(valid_inspect_document())
    target: Any = document
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value

    with pytest.raises(SmokeFailure, match=message):
        validate_container_inspect(
            document,
            expected_volume_name="xferry-image-smoke-deadbeef-data",
        )


def test_inspect_validator_rejects_wrong_named_volume() -> None:
    with pytest.raises(SmokeFailure, match="expected 'different-volume'"):
        validate_container_inspect(
            valid_inspect_document(),
            expected_volume_name="different-volume",
        )


@pytest.mark.parametrize("section", ["HostConfig", "NetworkSettings"])
def test_inspect_validator_rejects_any_extra_non_loopback_binding(section: str) -> None:
    document = valid_inspect_document()
    if section == "HostConfig":
        document[section]["PortBindings"]["9999/tcp"] = [{"HostIp": "0.0.0.0", "HostPort": "9999"}]
    else:
        document[section]["Ports"]["9999/tcp"] = [{"HostIp": "::", "HostPort": "9999"}]

    with pytest.raises(SmokeFailure, match="non-loopback"):
        validate_container_inspect(
            document,
            expected_volume_name="xferry-image-smoke-deadbeef-data",
        )


def test_workflows_smoke_the_local_and_immutable_registry_image_identities() -> None:
    ci = (REPO_ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    release = (REPO_ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")

    assert "python tools/docker_image_smoke.py" in ci
    assert "--image xferry:ci" in ci
    assert "--browser-first-run" in ci
    assert "docker-first-run" in ci

    image_verify = _workflow_job(release, "image-verify")
    publish_ghcr = _workflow_job(release, "publish-ghcr")
    registry_smoke = _workflow_job(release, "registry-smoke")

    release_smoke = "python tools/docker_image_smoke.py"
    assert release_smoke in image_verify
    assert "--image xferry:release-smoke" in image_verify
    assert "--browser-first-run" in image_verify
    assert "image-first-run" in image_verify
    assert "docker/login-action" not in image_verify
    assert "docker/build-push-action" not in image_verify
    assert "push: true" not in image_verify

    assert release_smoke in publish_ghcr
    assert '--image "${IMAGE}@${DIGEST}"' in publish_ghcr
    assert "docker/build-push-action" not in publish_ghcr
    assert "uses: actions/checkout@" in publish_ghcr
    assert "persist-credentials: false" in publish_ghcr
    assert publish_ghcr.index("uses: actions/checkout@") < publish_ghcr.index(release_smoke)

    assert release_smoke in registry_smoke
    assert (
        "--image ghcr.io/kgmnotes/xferry@${{ needs.publish-ghcr.outputs.digest }}" in registry_smoke
    )


def test_browser_first_run_uses_canonical_external_target(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    captured: dict[str, object] = {}

    def fake_run(
        command: list[str],
        *,
        cwd: Path,
        capture_output: bool,
        text: bool,
        check: bool,
    ) -> CompletedProcess[str]:
        captured.update(
            command=command,
            cwd=cwd,
            capture_output=capture_output,
            text=text,
            check=check,
        )
        return CompletedProcess(command, 0, stdout='{"journey":"first-run"}\n', stderr="")

    monkeypatch.setattr(docker_image_smoke.subprocess, "run", fake_run)
    artifacts = tmp_path / "browser-artifacts"

    run_browser_first_run(
        49152,
        artifacts_dir=artifacts,
        python_executable="/test/python",
    )

    command = captured["command"]
    assert isinstance(command, list)
    assert command[0] == "/test/python"
    assert command[1].endswith("/tools/browser_smoke.py")
    assert command[command.index("--mode") + 1] == "first-run"
    assert command[command.index("--target-url") + 1] == "http://127.0.0.1:49152/"
    assert command[command.index("--artifacts-dir") + 1] == str(artifacts.resolve())
    assert captured["capture_output"] is True
    assert captured["check"] is False


def test_docker_smoke_parser_exposes_browser_gate() -> None:
    args = build_argument_parser().parse_args(
        [
            "--image",
            "xferry:test",
            "--browser-first-run",
            "--browser-artifacts-dir",
            "/tmp/browser-artifacts",
        ]
    )

    assert args.browser_first_run is True
    assert args.browser_artifacts_dir == "/tmp/browser-artifacts"
