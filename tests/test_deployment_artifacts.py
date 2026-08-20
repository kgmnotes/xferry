"""Static checks for operator deployment and release artifacts."""

from __future__ import annotations

import json
import os
import re
import shlex
import socket
import ssl
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from xferry.settings import LaunchPreset, load_settings_file

REPO_ROOT = Path(__file__).resolve().parents[1]


def _run_public_direct_healthcheck(
    monkeypatch: pytest.MonkeyPatch, response: bytes | tuple[bytes, ...]
) -> int:
    """Execute the rendered Compose healthcheck against a bounded fake TLS response."""
    compose = (REPO_ROOT / "deploy/docker/docker-compose.public-direct.yml").read_text(
        encoding="utf-8"
    )
    start = compose.index("          import base64")
    end = compose.index("      interval:", start)
    script = textwrap.dedent(compose[start:end])

    class FakeSocket:
        def __init__(self) -> None:
            self._chunks = list(response) if isinstance(response, tuple) else [response]

        def __enter__(self) -> FakeSocket:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def settimeout(self, _timeout: float) -> None:
            return None

        def sendall(self, _request: bytes) -> None:
            return None

        def recv(self, _size: int) -> bytes:
            return self._chunks.pop(0) if self._chunks else b""

    class FakeContext:
        def wrap_socket(self, raw_socket: FakeSocket, *, server_hostname: str) -> FakeSocket:
            assert server_hostname == "health.example"
            return raw_socket

    fake_socket = FakeSocket()
    monkeypatch.setenv("XFERRY_HEALTH_HOST", "health.example")
    monkeypatch.setenv("XFERRY_HEALTH_PORT", "8443")
    monkeypatch.setattr(socket, "create_connection", lambda *_args, **_kwargs: fake_socket)
    monkeypatch.setattr(ssl, "create_default_context", lambda: FakeContext())
    monkeypatch.setattr(Path, "read_text", lambda *_args, **_kwargs: "admin:secret\n")

    with pytest.raises(SystemExit) as result:
        exec(script, {"__name__": "__healthcheck__"})
    assert isinstance(result.value.code, int)
    return result.value.code


@pytest.mark.parametrize(
    ("content_length", "body", "expected_exit"),
    [
        ("65537", b'{"health":"ready"}', 1),
        ("-1", b'{"health":"ready"}', 1),
        ("invalid", b'{"health":"ready"}', 1),
        ("19", b'{"health":"ready"}', 1),
        (None, b'{"health":"ready"}', 0),
        (None, b'{"health":"ready","padding":"' + b"x" * 65537 + b'"}', 1),
    ],
    ids=(
        "over-limit",
        "negative",
        "invalid",
        "truncated",
        "bounded-no-length",
        "oversized-no-length",
    ),
)
def test_public_direct_healthcheck_validates_declared_ping_body_framing(
    monkeypatch: pytest.MonkeyPatch,
    content_length: str | None,
    body: bytes,
    expected_exit: int,
) -> None:
    """Catches Compose accepting a ready prefix despite invalid declared PING framing."""
    length_header = (
        b"" if content_length is None else b"Content-Length: " + content_length.encode() + b"\r\n"
    )
    response = b"HTTP/1.1 200 OK\r\n" + length_header + b"\r\n" + body

    assert _run_public_direct_healthcheck(monkeypatch, response) == expected_exit


def test_public_direct_healthcheck_accepts_split_bounded_no_length_ping_body(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Catches the rendered healthcheck stopping after no-length headers."""
    header = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n"
    body = b'{"health":"ready"}'

    assert _run_public_direct_healthcheck(monkeypatch, (header, body)) == 0


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


def _workflow_job_header(job: str) -> str:
    return job.split("\n    steps:", maxsplit=1)[0]


def _workflow_job_needs(job: str) -> set[str]:
    header = _workflow_job_header(job)
    lines = header.splitlines()
    for index, line in enumerate(lines):
        prefix = "    needs:"
        if not line.startswith(prefix):
            continue

        value = line.removeprefix(prefix).strip()
        if value.startswith("[") and value.endswith("]"):
            return {item.strip() for item in value[1:-1].split(",") if item.strip()}
        if value:
            return {value}

        dependencies: set[str] = set()
        for dependency_line in lines[index + 1 :]:
            if dependency_line.startswith("      - "):
                dependencies.add(dependency_line.removeprefix("      - ").strip())
                continue
            if dependency_line.strip():
                break
        return dependencies
    return set()


def _workflow_named_step(workflow: str, name: str) -> str:
    lines = workflow.splitlines()
    marker = f"      - name: {name}"
    try:
        start = lines.index(marker)
    except ValueError as exc:
        raise AssertionError(f"workflow step {name!r} is missing") from exc

    end = len(lines)
    for index in range(start + 1, len(lines)):
        line = lines[index]
        if line.startswith("      - name: ") or (
            len(line) - len(line.lstrip()) == 2 and line.endswith(":")
        ):
            end = index
            break
    return "\n".join(lines[start:end])


def _assert_release_source_version_step(job: str) -> None:
    step = _workflow_named_step(job, "Check release source version")

    assert "if:" not in step
    assert "XFERRY_RELEASE_REF: ${{ github.ref }}" in step
    assert "XFERRY_RELEASE_REF_NAME: ${{ github.ref_name }}" in step
    assert "from xferry.management.versions import is_supported_release_version" in step
    assert "is_supported_release_version(__version__)" in step
    assert "is_supported_release_version(tag_version)" in step
    assert 'ref.startswith("refs/tags/v")' in step
    assert 'tag_version = ref_name.removeprefix("v")' in step
    assert "tag_version != __version__" in step


def _assert_websocket_risk_lane_argv(step: str) -> None:
    run_marker = "        run: |\n"
    assert run_marker in step
    script = step.split(run_marker, maxsplit=1)[1].replace("\\\n", " ")
    assert shlex.split(script) == [
        "python",
        "-m",
        "pytest",
        "-q",
        "tests/test_websocket.py",
        "tests/test_websocket_handlers.py",
        "tests/test_handlers/test_notepad.py",
        "tests/test_security/test_websocket_upgrade.py",
    ]


def _workflow_docker_ping_parser(workflow: str) -> str:
    step = _workflow_named_step(workflow, "Docker smoke")
    match = re.search(r"python -c '([^']+)' \"\$\{output\}\" && return 0", step)
    assert match is not None, "Docker smoke PING parser is missing"
    return match.group(1)


def test_systemd_public_direct_config_and_unit_are_valid() -> None:
    config_path = REPO_ROOT / "deploy/systemd/xferry.ini.example"
    service_path = REPO_ROOT / "deploy/systemd/xferry.service"

    settings = load_settings_file(config_path)
    settings.validate()

    assert settings.preset is LaunchPreset.PUBLIC_DIRECT
    assert settings.public_direct is True
    assert settings.auth_file == "/etc/xferry/auth"
    assert settings.body_memory_budget_mb is not None
    assert settings.upload_storage_limit_mb == 4096
    assert settings.upload_file_limit == 4096
    assert settings.upload_reserve_free_mb == 1024
    assert settings.upload_quota_externally_managed is False

    service = service_path.read_text(encoding="utf-8")
    assert (
        "ExecStartPre=/opt/xferry/current/xferry run --config /etc/xferry/xferry.ini --check-config"
    ) in service
    assert "ExecStart=/opt/xferry/current/xferry run --config /etc/xferry/xferry.ini" in service
    assert "User=xferry" in service
    assert "Group=xferry" in service
    assert "AmbientCapabilities=CAP_NET_BIND_SERVICE" in service
    assert "CapabilityBoundingSet=CAP_NET_BIND_SERVICE" in service
    assert "NoNewPrivileges=true" in service
    assert "ProtectSystem=strict" in service
    assert "ProtectHome=true" in service
    assert "Environment=HOME=/var/lib/xferry" in service
    assert "ReadWritePaths=/var/lib/xferry" in service
    assert "/home/xferry/.xferry" not in service
    assert "PrivateTmp=true" in service
    assert "UMask=0077" in service

    packaged = REPO_ROOT / "xferry/management/data/xferry.service"
    assert packaged.read_text(encoding="utf-8") == service


def test_systemd_artifacts_do_not_advertise_an_unused_environment_file() -> None:
    """Keep the managed install surface limited to the supported INI contract."""
    env_example = REPO_ROOT / "deploy/systemd/xferry.env.example"

    assert not env_example.exists()

    for service_path in (
        REPO_ROOT / "deploy/systemd/xferry.service",
        REPO_ROOT / "xferry/management/data/xferry.service",
    ):
        assert "EnvironmentFile=" not in service_path.read_text(encoding="utf-8")


def test_systemd_install_script_has_valid_shell_syntax() -> None:
    script_path = REPO_ROOT / "deploy/systemd/install-systemd.sh"

    result = subprocess.run(
        ["bash", "-n", str(script_path)],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr


def test_systemd_install_script_delegates_arguments_to_the_managed_scie(
    tmp_path: Path,
) -> None:
    """The helper must execute the installed management flow, not recreate setup in shell."""
    script_path = REPO_ROOT / "deploy/systemd/install-systemd.sh"
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    fake_id = fake_bin / "id"
    fake_id.write_text("#!/bin/sh\nprintf '0\\n'\n", encoding="utf-8")
    fake_id.chmod(0o755)
    executable = tmp_path / "xferry"
    executable.write_text(
        '#!/bin/sh\nprintf \'%s\\n\' "$@" > "$XFERRY_TEST_CAPTURE"\n',
        encoding="utf-8",
    )
    executable.chmod(0o755)
    capture = tmp_path / "argv"
    env = os.environ.copy()
    env.update(
        {
            "PATH": f"{fake_bin}:{env['PATH']}",
            "XFERRY_EXECUTABLE": str(executable),
            "XFERRY_TEST_CAPTURE": str(capture),
        }
    )

    result = subprocess.run(
        ["bash", str(script_path), "--private", "--dry-run"],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert capture.read_text(encoding="utf-8").splitlines() == [
        "setup",
        "--private",
        "--dry-run",
    ]


def test_systemd_install_script_fails_clearly_when_the_managed_scie_is_missing(
    tmp_path: Path,
) -> None:
    """A source checkout alone must not be mistaken for an installable managed runtime."""
    script_path = REPO_ROOT / "deploy/systemd/install-systemd.sh"
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    fake_id = fake_bin / "id"
    fake_id.write_text("#!/bin/sh\nprintf '0\\n'\n", encoding="utf-8")
    fake_id.chmod(0o755)
    missing = tmp_path / "missing-xferry"
    env = os.environ.copy()
    env.update(
        {
            "PATH": f"{fake_bin}:{env['PATH']}",
            "XFERRY_EXECUTABLE": str(missing),
        }
    )

    result = subprocess.run(
        ["bash", str(script_path)],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 1
    assert result.stdout == ""
    assert result.stderr.strip() == f"installed XFerry executable is missing: {missing}"


def test_docker_public_direct_compose_uses_ghcr_image_and_config() -> None:
    compose_path = REPO_ROOT / "deploy/docker/docker-compose.public-direct.yml"
    config_path = REPO_ROOT / "deploy/docker/xferry.ini.example"

    settings = load_settings_file(config_path)
    settings.validate()

    assert settings.preset is LaunchPreset.PUBLIC_DIRECT
    assert settings.public_direct is True
    assert settings.host == "0.0.0.0"
    assert settings.port == 8443
    assert settings.acme_http_port == 8080
    assert settings.auth_file == "/run/secrets/xferry_auth"
    assert settings.upload_storage_limit_mb == 4096
    assert settings.upload_file_limit == 4096
    assert settings.upload_reserve_free_mb == 1024
    assert settings.upload_quota_externally_managed is False

    compose = compose_path.read_text(encoding="utf-8")
    assert "name: xferry-public-direct" in compose
    assert 'image: "${XFERRY_IMAGE:?' in compose
    assert "ghcr.io/kgmnotes/xferry@sha256:<digest>" in compose
    assert "latest" not in compose.lower()
    assert "container_name:" not in compose
    assert "    command:\n      - run\n      - --config" in compose
    assert "--config" in compose
    assert "./xferry.ini:/etc/xferry/xferry.ini:ro" in compose
    assert "./xferry.ini.example:/etc/xferry/xferry.ini" not in compose
    assert "xferry_auth:" in compose
    assert "80:8080" in compose
    assert "443:8443" in compose
    assert "mem_limit: 768m" in compose
    assert "cpus: 1.0" in compose
    assert "pids_limit: 256" in compose
    assert "disable: true" not in compose
    assert 'os.environ["XFERRY_HEALTH_HOST"]' in compose
    assert 'Path("/run/secrets/xferry_auth")' in compose
    assert "server_hostname=host" in compose
    assert 'f"Authorization: Basic {token}' in compose
    assert 'f"PING / HTTP/1.1' in compose
    assert "json.loads(body)" in compose
    assert 'payload.get("health") == "ready"' in compose
    assert 'b"x-ping-response"' not in compose


def test_docker_public_direct_runtime_files_are_ignored() -> None:
    docker_ignore = (REPO_ROOT / "deploy/docker/.gitignore").read_text(encoding="utf-8")
    secrets_ignore = (REPO_ROOT / "deploy/docker/secrets/.gitignore").read_text(encoding="utf-8")

    assert "xferry.ini" in docker_ignore.splitlines()
    assert "*" in secrets_ignore.splitlines()
    assert "!.gitignore" in secrets_ignore.splitlines()


def test_source_first_docs_publish_the_supported_operator_contract() -> None:
    """Keep source installation and unpublished-artifact status consistent."""
    readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    quick_start = (REPO_ROOT / "docs/quick-start.md").read_text(encoding="utf-8")
    operations = (REPO_ROOT / "docs/operations.md").read_text(encoding="utf-8")
    contributing = (REPO_ROOT / "CONTRIBUTING.md").read_text(encoding="utf-8")
    changelog = (REPO_ROOT / "CHANGELOG.md").read_text(encoding="utf-8")

    for document in (readme, quick_start):
        assert "No GitHub Release" in document
        assert "PyPI" in document
        assert "GHCR" in document
        assert "python -m pip install ." in document

    assert "git clone https://github.com/kgmnotes/xferry.git" in quick_start
    assert "xferry run --preset local --open" in quick_start
    assert quick_start.index("## Install") < quick_start.index("## Send a first file")
    assert quick_start.index("## Send a first file") < quick_start.index("## Try a custom method")
    assert quick_start.index("## Try a custom method") < quick_start.index(
        "## Stop and protect data"
    )

    assert "public distribution is source-only" in operations
    assert "Docker from the checkout" in operations
    assert "down --volumes" in operations
    assert "destructive" in operations
    assert "release workflow" in contributing
    assert "manual workflow run verifies artifacts but does not publish" in re.sub(
        r"\s+", " ", contributing
    )
    assert "source installation first" in contributing
    assert "## [0.1.0] - 2026-08-20" in changelog
    assert "Source distribution" in changelog


def test_public_direct_docs_cover_source_secrets_and_external_probe() -> None:
    public_direct = (REPO_ROOT / "docs/public-direct.md").read_text(encoding="utf-8")
    security = (REPO_ROOT / "SECURITY.md").read_text(encoding="utf-8")

    for required in (
        "/opt/xferry-source",
        "/etc/xferry/auth",
        "--write-sample-config",
        "--check-config",
        "--print-config",
        "--config /run/secrets/xferry-curl.conf",
        "direct TCP peer",
        '"health":"ready"',
        "no published binary or container image",
    ):
        assert required in public_direct

    for required in (
        "TLS with a hostname clients verify",
        "Strong Basic Auth read from a permission-restricted file",
        "Proxy-side per-client throttling",
        "Backups and a tested recovery procedure",
        "direct accepted-socket peer",
    ):
        assert required in security


def test_operator_docs_define_launch_presets_and_capacity_boundaries() -> None:
    corpus = "\n".join(
        (REPO_ROOT / path).read_text(encoding="utf-8")
        for path in ("docs/quick-start.md", "docs/operations.md", "SECURITY.md")
    )

    for preset in ("local", "local-secure", "public-direct"):
        assert preset in corpus
    assert "body-memory-budget" in corpus
    assert "RSS ceiling" in corpus
    assert "WebSocket" in corpus
    assert "worker" in corpus
    assert "file-backed credentials" in corpus


def test_release_workflow_verifies_both_artifact_types_before_publishing() -> None:
    workflow = (REPO_ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")

    build = _workflow_job(workflow, "build")
    image_verify = _workflow_job(workflow, "image-verify")
    release_gate = _workflow_job(workflow, "release-gate")
    publish_pypi = _workflow_job(workflow, "publish-pypi")
    publish_ghcr = _workflow_job(workflow, "publish-ghcr")
    publish_github_release = _workflow_job(workflow, "publish-github-release")
    registry_smoke = _workflow_job(workflow, "registry-smoke")

    assert _workflow_job_needs(release_gate) == {"build", "image-verify", "scie-verify"}
    assert _workflow_job_needs(publish_pypi) == {"release-gate"}
    assert _workflow_job_needs(publish_ghcr) == {"release-gate"}
    assert _workflow_job_needs(publish_github_release) == {"release-gate"}
    assert _workflow_job_needs(registry_smoke) == {
        "publish-pypi",
        "publish-ghcr",
        "publish-github-release",
    }

    publish_condition = "if: github.event_name == 'push' && startsWith(github.ref, 'refs/tags/v')"
    assert publish_condition in _workflow_job_header(publish_pypi)
    assert publish_condition in _workflow_job_header(publish_ghcr)
    assert publish_condition in _workflow_job_header(publish_github_release)
    assert publish_condition in _workflow_job_header(registry_smoke)

    _assert_release_source_version_step(build)
    _assert_release_source_version_step(image_verify)
    _assert_release_source_version_step(_workflow_job(workflow, "scie-verify"))

    assert "pypa/gh-action-pypi-publish" not in build
    assert "docker/login-action" not in image_verify
    assert "docker/build-push-action" not in image_verify
    assert "push: true" not in image_verify


def test_release_workflow_preserves_verified_scie_and_image_artifact_identity() -> None:
    """Catches a publisher rebuilding or selecting artifacts by mutable names."""
    workflow = (REPO_ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")

    image_verify = _workflow_job(workflow, "image-verify")
    scie_verify = _workflow_job(workflow, "scie-verify")
    release_gate = _workflow_job(workflow, "release-gate")

    assert "id: upload-image-archive" in image_verify
    assert "docker save xferry:release-smoke" in image_verify
    assert "sha256sum" in image_verify
    assert "docker image inspect --format '{{.Id}}' xferry:release-smoke" in image_verify
    assert "xferry-image-${{ github.run_id }}-${{ github.run_attempt }}" in image_verify
    assert (
        "docker-image-artifact-id: ${{ steps.upload-image-archive.outputs.artifact-id }}"
        in _workflow_job_header(image_verify)
    )

    assert "id: upload-scie" in scie_verify
    assert "xferry-scie-${{ github.run_id }}-${{ github.run_attempt }}" in scie_verify
    assert "scie-artifact-id: ${{ steps.upload-scie.outputs.artifact-id }}" in _workflow_job_header(
        scie_verify
    )

    for artifact_output in (
        "python-dists-artifact-id",
        "docker-image-artifact-id",
        "scie-artifact-id",
    ):
        assert artifact_output in _workflow_job_header(release_gate)
    for environment_name in (
        "PYTHON_DISTS_ARTIFACT_ID",
        "DOCKER_IMAGE_ARTIFACT_ID",
        "SCIE_ARTIFACT_ID",
    ):
        assert f'test -n "${{{environment_name}}}"' in release_gate


@pytest.mark.parametrize(
    ("workflow_path", "job_name", "build_step"),
    [
        (".github/workflows/ci.yml", "python314-readiness", "Build package artifacts"),
        (".github/workflows/release.yml", "build", "Build wheel and sdist"),
    ],
)
def test_python_artifact_jobs_share_ordered_validation_and_offline_install_gate(
    workflow_path: str,
    job_name: str,
    build_step: str,
) -> None:
    """Catches archive or fresh-install proof drifting between CI and release."""
    workflow = (REPO_ROOT / workflow_path).read_text(encoding="utf-8")
    job = _workflow_job(workflow, job_name)
    ordered_steps = (
        build_step,
        "Validate wheel and sdist contents",
        "Prepare Python artifact wheelhouse",
        "Offline wheel and sdist smoke",
    )
    offsets = [job.index(f"      - name: {step}") for step in ordered_steps]
    assert offsets == sorted(offsets)

    build = _workflow_named_step(workflow, build_step)
    validate = _workflow_named_step(workflow, "Validate wheel and sdist contents")
    prepare = _workflow_named_step(workflow, "Prepare Python artifact wheelhouse")
    offline = _workflow_named_step(workflow, "Offline wheel and sdist smoke")

    assert build.count("python -m build --sdist --wheel --outdir dist") == 1
    assert "python tools/verify_python_artifacts.py validate" in validate
    assert "--wheel 'dist/xferry-*.whl'" in validate
    assert "--sdist 'dist/xferry-*.tar.gz'" in validate
    assert "python tools/verify_python_artifacts.py prepare-wheelhouse" in prepare
    assert '--wheelhouse "$RUNNER_TEMP/xferry-artifact-wheelhouse"' in prepare
    assert "python tools/verify_python_artifacts.py offline-smoke" in offline
    assert '--fresh-root "$RUNNER_TEMP/xferry-fresh-artifacts"' in offline
    assert "--no-index" not in prepare

    if job_name == "build":
        assert job.index("Offline wheel and sdist smoke") < job.index("Static UI wheel asset check")
        assert (
            '"$RUNNER_TEMP/xferry-fresh-artifacts/wheel-venv" \\\n'
            '            "$RUNNER_TEMP/xferry-wheel-smoke"'
        ) in offline
        assert "${RUNNER_TEMP}/xferry-wheel-smoke/bin/xferry" in job
        assert "${RUNNER_TEMP}/xferry-wheel-smoke/bin/python" in job


def test_release_workflow_verifies_scie_assets_before_the_shared_gate() -> None:
    workflow = (REPO_ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")

    scie_verify = _workflow_job(workflow, "scie-verify")
    release_gate = _workflow_job(workflow, "release-gate")

    assert _workflow_job_needs(release_gate) == {"build", "image-verify", "scie-verify"}
    assert "python tools/build_scie_release.py --output-dir dist/scie" in scie_verify
    assert '"${executable}" run --version' in scie_verify
    assert '"${executable}" run --check-config' in scie_verify
    assert '"/release/${executable}" run --version' in scie_verify
    assert "ubuntu:22.04" in scie_verify
    assert "ubuntu:24.04" in scie_verify
    assert "ubuntu:26.04" in scie_verify
    assert "debian:12" in scie_verify
    assert "actions/attest@" in scie_verify
    assert "gh release upload" in _workflow_job(workflow, "publish-github-release")


@pytest.mark.parametrize(
    ("document", "expected_returncode"),
    [
        (
            {
                "health": "ready",
                "supported_methods": [
                    "PING",
                    "POST",
                    "INFO",
                    "FETCH",
                    "DELETE",
                    "NOTE",
                    "SMUGGLE",
                ],
            },
            0,
        ),
        (
            {
                "status": "pong",
                "supported_methods": ["PING", "NOTE", "SMUGGLE"],
            },
            1,
        ),
        (
            {
                "health": "ready",
                "supported_methods": ["PING", "NOTE", "SMUGGLE"],
                "status": "pong",
            },
            1,
        ),
        (
            {
                "health": "ready",
                "supported_methods": ["PING", "NOTE", "SMUGGLE"],
                "ok": True,
            },
            1,
        ),
        (
            {
                "health": "ready",
                "supported_methods": ["PING", "NOTE", "SMUGGLE"],
                "success": True,
            },
            1,
        ),
        ({"health": "ready", "supported_methods": ["PING", "NOTE"]}, 1),
        (
            {
                "health": "ready",
                "supported_methods": ["PING", "NOTE", "SMUGGLE"],
                "profile": "full",
            },
            1,
        ),
        (
            {
                "health": "ready",
                "supported_methods": ["PING", "NOTE", "SMUGGLE"],
                "capabilities": {},
            },
            1,
        ),
    ],
    ids=(
        "canonical-ready",
        "legacy-status-only",
        "canonical-plus-status",
        "canonical-plus-ok",
        "canonical-plus-success",
        "missing-smuggle",
        "profile-leakage",
        "capabilities-leakage",
    ),
)
def test_ci_docker_ping_probe_executes_only_the_canonical_ping_contract(
    tmp_path: Path, document: dict[str, object], expected_returncode: int
) -> None:
    """Catches restoring status/pong, accepting legacy aliases, or dropping PING requirements."""
    workflow = (REPO_ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    payload = tmp_path / "ping.json"
    payload.write_text(json.dumps(document), encoding="utf-8")

    result = subprocess.run(
        [sys.executable, "-c", _workflow_docker_ping_parser(workflow), str(payload)],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == expected_returncode, result.stderr


def test_ci_centrally_enforces_branch_coverage_at_85_percent_with_two_decimals() -> None:
    """Catches CI drifting to an override below the release coverage contract."""
    configuration = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    ci = (REPO_ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")

    assert '[tool.coverage.run]\nsource = ["xferry"]\nbranch = true' in configuration
    assert "[tool.coverage.report]\nfail_under = 85\nprecision = 2" in configuration
    assert "--cov-fail-under" not in ci
    assert "--cov-report=term-missing" in ci
    assert "--cov-report=xml" in ci


def test_ci_runs_toolchain_check_and_a_blocking_scie_bundle_gate() -> None:
    """Catches PR/push CI omitting the pinned-toolchain SCIE verification boundary."""
    workflow = (REPO_ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    test_job = _workflow_job(workflow, "test")
    scie_job = _workflow_job(workflow, "scie-verify")

    assert "python tools/check_toolchain_pins.py" in test_job
    assert "needs: test" in scie_job
    assert "python -m pip install build pex==2.99.0" in scie_job
    assert "python tools/build_scie_release.py --output-dir dist/scie" in scie_job
    assert '"${executable}" run --version' in scie_job
    assert '"${executable}" run --check-config' in scie_job
    assert "xferry-release.json" in scie_job
    assert "SHA256SUMS" in scie_job


def test_cross_platform_cli_smoke_exercises_module_and_console_help() -> None:
    """Catches Windows smoke dropping the portable module or installed-script help paths."""
    workflow = (REPO_ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    cross_platform_job = _workflow_job(workflow, "cross-platform")
    cli_smoke = _workflow_named_step(cross_platform_job, "CLI smoke")

    assert "python -m xferry run --help" in cli_smoke
    assert "xferry --help" in cli_smoke
    assert "xferry run --help" in cli_smoke


def test_ci_websocket_risk_lane_has_one_pytest_invocation_with_exact_paths() -> None:
    """Catches a duplicate pytest command becoming an argument in the WebSocket risk lane."""
    workflow = (REPO_ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    step = _workflow_named_step(workflow, "Risk lane - WebSocket and Notepad")

    _assert_websocket_risk_lane_argv(step)

    malformed_step = step.replace(
        "          python -m pytest -q \\\n",
        "          python -m pytest -q \\\n          python -m pytest -q \\\n",
        1,
    )
    with pytest.raises(AssertionError):
        _assert_websocket_risk_lane_argv(malformed_step)


def test_compose_contributor_commands_start_the_server_via_run() -> None:
    """Catches Compose forwarding server flags to the removed root CLI surface."""
    compose = (REPO_ROOT / "examples/docker/docker-compose.yml").read_text(encoding="utf-8")

    assert compose.count("    command:\n      - run\n      - --host") == 3


def test_release_workflow_manual_runs_use_safe_artifact_names_and_never_publish() -> None:
    workflow = (REPO_ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")

    build = _workflow_job(workflow, "build")
    image_verify = _workflow_job(workflow, "image-verify")
    publish_pypi = _workflow_job(workflow, "publish-pypi")
    publish_ghcr = _workflow_job(workflow, "publish-ghcr")
    publish_github_release = _workflow_job(workflow, "publish-github-release")
    registry_smoke = _workflow_job(workflow, "registry-smoke")

    assert '      - "v*"' in workflow
    assert "  workflow_dispatch:" in workflow
    _assert_release_source_version_step(build)
    _assert_release_source_version_step(image_verify)

    for verification_job in (build, image_verify):
        artifact_names = [
            line.strip()
            for line in verification_job.splitlines()
            if line.strip().startswith("name:") and "${{" in line
        ]
        assert artifact_names
        assert all("github.ref_name" not in line for line in artifact_names)
        assert all("github.run_id" in line for line in artifact_names)
        assert all("github.run_attempt" in line for line in artifact_names)

    publish_condition = "if: github.event_name == 'push' && startsWith(github.ref, 'refs/tags/v')"
    for publish_job in (publish_pypi, publish_ghcr, publish_github_release, registry_smoke):
        header = _workflow_job_header(publish_job)
        assert publish_condition in header
        assert "workflow_dispatch" not in header


def test_release_workflow_hands_verified_python_artifacts_to_pypi_by_id() -> None:
    workflow = (REPO_ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")

    build = _workflow_job(workflow, "build")
    release_gate = _workflow_job(workflow, "release-gate")
    publish_pypi = _workflow_job(workflow, "publish-pypi")

    assert "id: upload-python-dists" in build
    assert "uses: actions/upload-artifact@" in build
    assert (
        "python-dists-artifact-id: ${{ steps.upload-python-dists.outputs.artifact-id }}"
        in _workflow_job_header(build)
    )
    assert (
        "python-dists-artifact-id: ${{ needs.build.outputs.python-dists-artifact-id }}"
        in _workflow_job_header(release_gate)
    )

    assert "uses: actions/download-artifact@" in publish_pypi
    assert (
        "artifact-ids: ${{ needs.release-gate.outputs.python-dists-artifact-id }}" in publish_pypi
    )
    assert "path: dist" in publish_pypi
    assert "merge-multiple: true" in publish_pypi
    assert "pypa/gh-action-pypi-publish@" in publish_pypi


def test_release_workflow_publishes_only_verified_scie_release_assets() -> None:
    workflow = (REPO_ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")

    publish_github_release = _workflow_job(workflow, "publish-github-release")

    header = _workflow_job_header(publish_github_release)
    assert "contents: write" in header
    assert "packages: write" not in header
    assert "id-token: write" not in header
    assert "attestations: write" not in header
    assert "uses: actions/download-artifact" in publish_github_release
    assert (
        "artifact-ids: ${{ needs.release-gate.outputs.scie-artifact-id }}" in publish_github_release
    )
    assert "gh release create" in publish_github_release
    assert "gh release upload" in publish_github_release
    assert "--clobber" in publish_github_release
    for asset in (
        "xferry-*-linux-x86_64",
        "install.sh",
        "SHA256SUMS",
        "xferry-release.json",
        "xferry-scie-sbom.cdx.json",
    ):
        assert asset in publish_github_release


def test_release_workflow_republishes_the_smoke_tested_image_by_identity() -> None:
    workflow = (REPO_ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")

    publish_ghcr = _workflow_job(workflow, "publish-ghcr")

    assert "packages: write" in _workflow_job_header(publish_ghcr)
    assert "ghcr.io/kgmnotes/xferry" in publish_ghcr
    assert "uses: actions/download-artifact" in publish_ghcr
    assert (
        "artifact-ids: ${{ needs.release-gate.outputs.docker-image-artifact-id }}" in publish_ghcr
    )
    assert "sha256sum --check" in publish_ghcr
    assert "docker load" in publish_ghcr
    assert "docker image inspect --format '{{.Id}}' xferry:release-smoke" in publish_ghcr
    assert "candidate-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}" in publish_ghcr
    assert "docker build " not in publish_ghcr
    assert "context: ." not in publish_ghcr
    assert "docker/build-push-action" not in publish_ghcr
    assert "@${DIGEST}" in publish_ghcr
    assert "python tools/docker_image_smoke.py" in publish_ghcr
    immutable_smoke = _workflow_named_step(workflow, "Smoke immutable registry image")
    promotion = _workflow_named_step(workflow, "Promote verified digest to release tags")
    digest_preserving_create = (
        'docker buildx imagetools create --prefer-index=false --tag "${tag}" "${IMAGE}@${DIGEST}"'
    )
    promoted_digest_check = (
        'resolved="$(docker buildx imagetools inspect "${tag}" --format \'{{.Digest}}\')"'
    )
    assert publish_ghcr.index(immutable_smoke) < publish_ghcr.index(promotion)
    assert digest_preserving_create in promotion
    assert promoted_digest_check in promotion
    assert promotion.index(digest_preserving_create) < promotion.index(promoted_digest_check)
    assert promotion.index(promoted_digest_check) < promotion.index(
        'if [ "${resolved}" != "${DIGEST}" ]; then'
    )
    assert "does not resolve to verified digest" in publish_ghcr
    assert "actions/attest-build-provenance@" in publish_ghcr
    assert "push-to-registry: true" in publish_ghcr
    assert "digest: ${{ steps.resolve-digest.outputs.digest }}" in _workflow_job_header(
        publish_ghcr
    )


def test_release_workflow_smokes_the_public_registry_consumers_after_publication() -> None:
    workflow = (REPO_ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")

    registry_smoke = _workflow_job(workflow, "registry-smoke")
    header = _workflow_job_header(registry_smoke)

    assert "contents: read" in header
    assert "packages: write" not in header
    assert "id-token: write" not in header
    assert "python -m venv" in registry_smoke
    assert "--index-url https://pypi.org/simple" in registry_smoke
    assert '"xferry==${GITHUB_REF_NAME#v}"' in registry_smoke
    assert (
        "docker pull ghcr.io/kgmnotes/xferry@${{ needs.publish-ghcr.outputs.digest }}"
        in registry_smoke
    )
    assert "python tools/docker_image_smoke.py" in registry_smoke
    assert (
        "--image ghcr.io/kgmnotes/xferry@${{ needs.publish-ghcr.outputs.digest }}" in registry_smoke
    )
