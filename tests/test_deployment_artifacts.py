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

from tools import check_stale_docs
from xferry.config import __version__
from xferry.settings import load_settings_file

REPO_ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("document", ["docs/operations.md"])
def test_documented_public_compose_commands_set_required_health_host(
    tmp_path: Path, document: str
) -> None:
    """Catches copied up/down commands failing Compose's required host interpolation."""
    text = (REPO_ROOT / document).read_text(encoding="utf-8")
    blocks = [
        block
        for block in re.findall(r"```(?:console|bash)\n([\s\S]*?)```", text)
        if "docker-compose.public-direct.yml" in block
    ]
    assert blocks, "public Compose commands must be copyable"
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    capture = tmp_path / "docker-argv"
    docker = fake_bin / "docker"
    docker.write_text(
        "#!/bin/sh\n"
        'if [ "$XFERRY_HEALTH_HOST" != files.example.com ]; then\n'
        "  printf '%s\\n' 'missing or wrong XFERRY_HEALTH_HOST' >&2\n"
        "  exit 1\n"
        "fi\n"
        'printf \'%s\\t\' "$@" >> "$XFERRY_TEST_CAPTURE"\n'
        "printf '\\n' >> \"$XFERRY_TEST_CAPTURE\"\n",
        encoding="utf-8",
    )
    docker.chmod(0o755)
    for block in blocks:
        result = subprocess.run(
            ["/bin/bash", "-e", "-c", block],
            cwd=tmp_path,
            env={"PATH": str(fake_bin), "XFERRY_TEST_CAPTURE": str(capture)},
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == 0, result.stderr

    prefix = ["compose", "-f", "deploy/docker/docker-compose.public-direct.yml"]
    expected = [prefix + ["up", "-d"]]
    if document == "docs/operations.md":
        expected += [prefix + ["down"]]
    assert [line.split("\t")[:-1] for line in capture.read_text().splitlines()] == expected


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


def _assert_candidate_release_trigger(workflow: str) -> None:
    trigger_header = workflow.split("\npermissions:", maxsplit=1)[0]

    events, _ = check_stale_docs._workflow_events(workflow)
    assert events == frozenset({"workflow_call", "workflow_dispatch"})
    assert "candidate_tag:" in trigger_header
    assert "required: true" in trigger_header
    assert "type: string" in trigger_header


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

    assert settings.access == "public"
    assert settings.public_direct is True
    assert settings.auth_file == "/etc/xferry/auth"
    assert settings.body_memory_budget_mb is not None
    assert settings.upload_storage_limit_mb == 4096
    assert settings.upload_file_limit == 4096
    assert settings.upload_reserve_free_mb == 1024
    assert settings.upload_quota_externally_managed is False

    service = service_path.read_text(encoding="utf-8")
    assert (
        "ExecStartPre=/opt/xferry/current/xferry config check --config /etc/xferry/xferry.ini"
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
        ["bash", str(script_path), "--access", "private", "--dry-run"],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert capture.read_text(encoding="utf-8").splitlines() == [
        "setup",
        "--access",
        "private",
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


def test_docker_public_direct_compose_uses_an_immutable_registry_image_and_config() -> None:
    compose_path = REPO_ROOT / "deploy/docker/docker-compose.public-direct.yml"
    config_path = REPO_ROOT / "deploy/docker/xferry.ini.example"

    settings = load_settings_file(config_path)
    settings.validate()

    assert settings.access == "public"
    assert settings.public_direct is True
    assert settings.host == "0.0.0.0"
    assert settings.port == 8443
    assert settings.acme_http_port == 8080
    assert settings.auth_file == "/run/secrets/xferry_auth"
    assert settings.allowed_hosts == ()
    assert settings.upload_storage_limit_mb == 4096
    assert settings.upload_file_limit == 4096
    assert settings.upload_reserve_free_mb == 1024
    assert settings.upload_quota_externally_managed is False

    compose = compose_path.read_text(encoding="utf-8")
    assert "name: xferry-public-direct" in compose
    assert "    build:" not in compose
    # Published install examples follow the documented release, not an unpublished source bump.
    readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    published = re.findall(
        r"https://github\.com/kgmnotes/xferry/releases/tag/(v[0-9]+\.[0-9]+\.[0-9]+)",
        readme,
    )
    assert len(published) == 1
    pinned_images = re.findall(
        r"^    image: ghcr\.io/kgmnotes/xferry:(v[0-9]+\.[0-9]+\.[0-9]+)$",
        compose,
        re.MULTILINE,
    )
    assert pinned_images == published
    published_version = tuple(int(part) for part in published[0][1:].split("."))
    source_version = tuple(int(part) for part in __version__.split("."))
    assert (0, 3, 2) <= published_version <= source_version
    operations = (REPO_ROOT / "docs/operations.md").read_text(encoding="utf-8")
    assert f"pins the compatible `{published[0]}` image" in operations
    assert "ghcr.io/kgmnotes/xferry:latest" not in compose
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


def test_journey_docs_publish_portable_managed_container_and_contributor_contracts() -> None:
    """Keep every lifecycle owned by one documented, immutable distribution path."""
    readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    quick_start = (REPO_ROOT / "docs/quick-start.md").read_text(encoding="utf-8")
    operations = (REPO_ROOT / "docs/operations.md").read_text(encoding="utf-8")
    contributing = (REPO_ROOT / "CONTRIBUTING.md").read_text(encoding="utf-8")
    changelog = (REPO_ROOT / "CHANGELOG.md").read_text(encoding="utf-8")

    for document in (readme, quick_start):
        assert "pipx install xferry" in document
        assert "archive/0.2.0-installation.md" in document
        assert "ghcr.io/kgmnotes/xferry:latest" not in document
        assert "curl | sudo sh" not in document

    assert "git clone https://github.com/kgmnotes/xferry.git" not in quick_start
    assert "xferry run --open" in quick_start
    assert quick_start.index("## Portable") < quick_start.index("## Managed Linux")
    assert quick_start.index("## Managed Linux") < quick_start.index("## Container")

    assert "xferry update --to VERSION" in operations
    assert "xferry rollback" in operations
    assert "xferry uninstall" in operations
    assert "ghcr.io/kgmnotes/xferry@sha256:" in operations
    assert "--volumes" in operations
    assert "destructive" in operations
    normalized_contributing = re.sub(r"\s+", " ", contributing)
    assert "source checkout is the contributor workflow" in normalized_contributing
    assert "python -m pip install -e" in contributing
    assert "generated CLI reference" in normalized_contributing
    assert "## [Unreleased]" in changelog
    assert "## [0.2.0] - 2026-10-01" in changelog
    assert "## [0.1.0] - 2026-08-20" in changelog


def test_release_verification_workflow_is_manual_read_only_and_non_publishing() -> None:
    """Candidate transfer preserves release identity without enabling publishers."""
    workflow = (REPO_ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
    scie = (REPO_ROOT / ".github/workflows/candidate-scie.yml").read_text(encoding="utf-8")
    assert check_stale_docs.release_workflow_policy_findings(workflow) == []
    _assert_candidate_release_trigger(workflow)
    build = _workflow_job(workflow, "build")
    assert "needs: [preflight, quality-gates, security-gates]" in build
    assert "uses: ./.github/workflows/ci.yml" in workflow
    assert "candidate-gates: true" in workflow
    assert "uses: ./.github/workflows/security.yml" in workflow
    assert "python -m build --sdist --wheel --outdir dist" in build
    assert "Offline wheel and sdist smoke" in build
    assert workflow.count("python -m build") == 1
    assert "--platform linux/amd64,linux/arm64" in workflow
    assert "--output type=oci,dest=candidate/oci,tar=false" in workflow
    assert "--sbom=true --provenance=mode=max" in workflow
    image_build = _workflow_job(workflow, "image-verify")
    build_position = image_build.index("--output type=oci,dest=candidate/oci,tar=false")
    normalize_position = image_build.index("candidate_inventory.py normalize-oci")
    archive_position = image_build.index("Archive exact OCI outputs")
    assert build_position < normalize_position < archive_position
    assert "skopeo --insecure-policy copy" in workflow
    assert "Hardened local image lifecycle smoke" in workflow
    assert "--image xferry:candidate" in workflow
    assert "runner: ubuntu-24.04-arm" in workflow
    for platform in ("linux-x86_64", "linux-aarch64"):
        assert f"platform: {platform}" in workflow
    assert "--wheel-sha256" in scie and "--wheel" in scie
    assert "--require-hosted-signature" in scie
    assert "python -m build" not in scie
    for lane in ("Smoke SCIE without host Python", "Smoke SCIE on every supported Linux base"):
        assert lane in scie
    for image in ("ubuntu:22.04", "ubuntu:24.04", "ubuntu:26.04", "debian:12", "debian:13"):
        assert image in scie
    assert "Exercise isolated managed lifecycle and failure paths" in scie
    for text in (workflow, scie):
        for checkout_step in text.split("uses: actions/checkout@")[1:]:
            assert "persist-credentials: false" in checkout_step.split("\n      -", 1)[0]
        for forbidden in (
            "actions/attest",
            "docker/login-action",
            "docker push",
            "--push",
            "gh release",
            "gh-action-pypi-publish",
            "packages: write",
            "contents: write",
            "id-token: write",
            "attestations: write",
            "permissions: write-all",
            "${{ secrets.",
            "ghcr.io/kgmnotes/xferry",
            "hatch publish",
            "twine upload",
        ):
            assert forbidden not in text


def test_candidate_consumers_verify_independent_producer_digests_without_rebuilding() -> None:
    workflow = (REPO_ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
    for name in ("image-smoke", "portable-smoke", "inventory", "release-gate"):
        job = _workflow_job(workflow, name)
        assert "actions/download-artifact@" in job
        assert "artifact-ids:" in job
        assert "merge-multiple: true" in job
        assert "--expected-sha256" in job
        assert "candidate_inventory.py unpack" in job
        for rebuild in ("python -m build", "pip wheel", "docker build", "build_scie_release.py"):
            assert rebuild not in job
    gate = _workflow_job(workflow, "release-gate")
    assert "candidate_inventory.py verify" in gate
    assert "needs.inventory.outputs.inventory-sha256" in gate
    assert "needs.inventory.outputs.archive-sha256" in gate
    dockerfile = (REPO_ROOT / "packaging/Dockerfile.candidate").read_text(encoding="utf-8")
    assert "COPY --from=wheel" in dockerfile
    assert "python -m build" not in dockerfile
    assert "org.opencontainers.image.version=$RELEASE_VERSION" in dockerfile
    assert "org.opencontainers.image.revision=$SOURCE_COMMIT" in dockerfile


def test_candidate_runtime_matches_source_image_with_writable_private_state() -> None:
    """Catch candidate-only runtime drift that a rebuilt contributor image cannot expose."""

    def runtime(path: str) -> list[tuple[str, tuple[str, ...]]]:
        text = (REPO_ROOT / path).read_text(encoding="utf-8")
        lines = re.sub(r"\\\r?\n[ \t]*", " ", text).splitlines()
        active = False
        instructions = []
        shared = {
            "FROM",
            "ENV",
            "RUN",
            "USER",
            "WORKDIR",
            "EXPOSE",
            "HEALTHCHECK",
            "ENTRYPOINT",
            "CMD",
        }
        for line in lines:
            instruction, _, value = line.strip().partition(" ")
            if instruction == "FROM":
                active = value.endswith(" AS runtime")
            if active and (
                instruction in shared
                or instruction == "ARG"
                and value.startswith(("APP_USER=", "APP_UID="))
            ):
                instructions.append((instruction, tuple(shlex.split(value))))
        assert instructions, f"{path} must declare its runtime stage"
        return instructions

    source = runtime("Dockerfile")
    candidate = runtime("packaging/Dockerfile.candidate")
    assert candidate == source
    environment = {
        name: value
        for instruction, words in candidate
        if instruction == "ENV"
        for name, value in (word.split("=", 1) for word in words)
    }
    assert environment["XFERRY_STATE_HOME"] == "/data"
    base = next(words[0] for instruction, words in candidate if instruction == "FROM")
    assert re.fullmatch(r"python:\S+@sha256:[0-9a-f]{64}", base)
    assert any(
        words[:3] == ("mkdir", "-p", "/data/uploads")
        and "chown" in words
        and "${APP_USER}:${APP_USER}" in words
        and "/data" in words
        for instruction, words in candidate
        if instruction == "RUN"
    )


def test_pr_release_smoke_exercises_candidate_recipe_with_the_verified_source_wheel() -> None:
    """Catch a green PR that checks the contributor image but skips the publishing recipe."""
    workflow = (REPO_ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    smoke = _workflow_job(workflow, "smoke")
    source_wheel = _workflow_named_step(smoke, "Static UI release gates")
    installed_wheel = _workflow_named_step(smoke, "Prepare installed-wheel browser target")
    source_image = _workflow_named_step(smoke, "Docker smoke")
    candidate = _workflow_named_step(smoke, "Candidate Docker smoke")
    assert (
        smoke.index(source_wheel)
        < smoke.index(installed_wheel)
        < smoke.index(source_image)
        < smoke.index(candidate)
    )
    assert 'wheel_dir="${RUNNER_TEMP}/xferry-browser-wheel"' in source_wheel
    assert 'python -m pip wheel . --no-deps --wheel-dir "${wheel_dir}"' in source_wheel
    assert 'tools/check_static_ui_assets.py --wheel "${wheel_dir}"/xferry-*.whl' in source_wheel
    for step in (source_wheel, candidate):
        assert "if: ${{ !inputs.candidate-gates }}" in step
        assert "set -euo pipefail" in step
        assert "continue-on-error" not in step
        assert re.search(r"\|\|\s*true\b", step) is None
    for rebuild in ("pip wheel", "python -m build", "--wheel-dir"):
        assert rebuild not in candidate

    logical = re.sub(r"\\\r?\n[ \t]*", " ", candidate)
    commands = [shlex.split(line.strip()) for line in logical.splitlines()]
    builds = [command for command in commands if command[:3] == ["docker", "buildx", "build"]]
    assert len(builds) == 1
    build = builds[0]
    assert "--load" in build
    assert build[build.index("--file") + 1] == "packaging/Dockerfile.candidate"
    assert build[build.index("--build-context") + 1] == "wheel=${RUNNER_TEMP}/xferry-browser-wheel"
    build_arguments = {
        build[index + 1] for index, word in enumerate(build) if word == "--build-arg"
    }
    assert {"RELEASE_VERSION=${release_version}", "SOURCE_COMMIT=$GITHUB_SHA"} <= build_arguments
    image = build[build.index("--tag") + 1]
    assert image == "xferry:ci-candidate"
    assert build[-1] == "."
    assert ["python", "tools/verify_docker_image.py", "--image", image] in commands
    assert ["docker", "run", "--rm", image, "run", "--version"] in commands
    helpers = [
        command for command in commands if command[:2] == ["python", "tools/docker_image_smoke.py"]
    ]
    assert len(helpers) == 1
    helper = helpers[0]
    assert helper[helper.index("--image") + 1] == image
    assert "--browser-first-run" in helper
    assert helper[helper.index("--browser-artifacts-dir") + 1] == (
        "${RUNNER_TEMP}/browser-smoke-artifacts/candidate-docker-first-run"
    )


def test_candidate_artifact_id_downloads_use_the_expected_flat_archive_path() -> None:
    for path in ("release.yml", "candidate-scie.yml"):
        workflow = (REPO_ROOT / ".github/workflows" / path).read_text(encoding="utf-8")
        for block in workflow.split("uses: actions/download-artifact@")[1:]:
            step = block.split("\n      -", 1)[0]
            assert "artifact-ids:" in step
            assert "merge-multiple: true" in step


def test_reusable_candidate_source_gates_preserve_normal_ci_checks() -> None:
    workflow = (REPO_ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    assert "workflow_call:" in workflow
    assert "candidate-gates:" in workflow
    assert "group: ci-${{ github.workflow }}-${{ github.ref }}" in workflow
    for job_name in ("test", "docs", "risk-lanes", "smoke"):
        job = _workflow_job(workflow, job_name)
        assert "if: ${{ !inputs.candidate-gates }}" not in job.split("    steps:", 1)[0]
    for job_name in ("python314-readiness", "cross-platform", "scie-verify"):
        assert "if: ${{ !inputs.candidate-gates }}" in _workflow_job(workflow, job_name)
    security = (REPO_ROOT / ".github/workflows/security.yml").read_text(encoding="utf-8")
    assert "workflow_call:" in security
    assert "python -m pip_audit --strict --no-deps -r constraints/ci.txt" in security
    assert "bandit -r xferry -ll" in security


@pytest.mark.parametrize(
    "trigger",
    (
        "  push:\n    branches: [main]",
        "  pull_request:",
        "  schedule:\n    - cron: '0 0 * * *'",
        "  repository_dispatch:",
    ),
)
def test_release_workflow_guard_rejects_unsafe_extra_triggers(trigger: str) -> None:
    workflow = (REPO_ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
    mutated = workflow.replace("\npermissions:", f"\n{trigger}\npermissions:", 1)

    with pytest.raises(AssertionError):
        _assert_candidate_release_trigger(mutated)


def test_public_direct_docs_cover_source_secrets_and_external_probe() -> None:
    public_direct = (REPO_ROOT / "docs/public-direct.md").read_text(encoding="utf-8")
    security = (REPO_ROOT / "SECURITY.md").read_text(encoding="utf-8")

    for required in (
        "archive/0.2.0-installation.md",
        "ghcr.io/kgmnotes/xferry@sha256:",
        "protected file-backed authentication",
        "xferry config check",
        "xferry config show --all",
        "--user USER",
        "direct TCP peer",
        '"health":"ready"',
    ):
        assert required in public_direct
    assert "ghcr.io/kgmnotes/xferry:latest" not in public_direct

    for required in (
        "TLS with a hostname clients verify",
        "Strong Basic Auth read from a permission-restricted file",
        "Proxy-side per-client throttling",
        "Backups and a tested recovery procedure",
        "direct accepted-socket peer",
    ):
        assert required in security


def test_operator_docs_define_access_modes_and_capacity_boundaries() -> None:
    corpus = "\n".join(
        (REPO_ROOT / path).read_text(encoding="utf-8")
        for path in ("docs/quick-start.md", "docs/operations.md", "docs/settings.md", "SECURITY.md")
    )

    for mode in ("access=private", "access=public", "access=lab"):
        assert mode in corpus
    assert "body_memory_budget_mb" in corpus
    assert "RSS ceiling" in corpus
    assert "WebSocket" in corpus
    assert "worker" in corpus
    assert "file-backed authentication" in corpus


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
    assert 'python -m pip install -e ".[test]" build pex==2.99.0' in scie_job
    assert "linux-x86_64" in scie_job
    assert "linux-aarch64" in scie_job
    assert "runner: ubuntu-24.04-arm" in scie_job
    assert "--platform '${{ matrix.platform }}'" in scie_job
    assert "--output-dir 'dist/scie-${{ matrix.platform }}'" in scie_job
    assert 'PATH=/nonexistent "$executable" run --version' in scie_job
    assert 'PATH=/nonexistent "$executable" --help' in scie_job
    assert 'PATH=/nonexistent "$executable" config check' in scie_job
    assert "xferry-release.json" in scie_job
    assert "SHA256SUMS" in scie_job
    assert "ReleaseManifest.parse_new" in scie_job
    assert "evidence=native" in scie_job
    for image in (
        "ubuntu:22.04",
        "ubuntu:24.04",
        "ubuntu:26.04",
        "debian:12",
        "debian:13",
    ):
        assert image in scie_job
    for lifecycle in ("setup", "status", "doctor", "rollback", "uninstall"):
        assert lifecycle in scie_job


@pytest.mark.parametrize("workflow_name", ["ci.yml", "candidate-scie.yml"])
def test_scie_smokes_check_explicit_temporary_configs(workflow_name: str) -> None:
    """Fresh SCIE smoke hosts must validate a real config without a saved user profile."""
    workflow = (REPO_ROOT / ".github/workflows" / workflow_name).read_text(encoding="utf-8")
    host = _workflow_named_step(workflow, "Smoke SCIE without host Python")
    containers = _workflow_named_step(workflow, "Smoke SCIE on every supported Linux base")

    assert 'mktemp -d "${RUNNER_TEMP}/' in host
    assert 'PATH=/nonexistent "$executable" config check --config ' in host
    assert '"$candidate" config check --config /tmp/' in containers
    for step in (host, containers):
        checks = [line for line in step.splitlines() if " config check" in line]
        assert len(checks) == 1
        assert " --config " in checks[0]
        assert "[server]\\naccess = private\\nfiles_dir = " in step
        assert "/release/xferry.ini" not in step
        assert "$bundle/xferry.ini" not in step


def test_cross_platform_acceptance_transfers_one_wheel_across_all_nine_pairs() -> None:
    """Catches editable acceptance, rebuilt consumers, or an incomplete portable matrix."""
    workflow = (REPO_ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    assert "env:\n  PIP_CONSTRAINT: ${{ github.workspace }}/constraints/ci.txt" in workflow
    build = _workflow_job(workflow, "python314-readiness")
    portable = _workflow_job(workflow, "cross-platform")
    exhaustive = _workflow_job(workflow, "test")
    assert build.count("python -m build --sdist --wheel --outdir dist") == 1
    assert "wheel-sha256: ${{ steps.wheel-identity.outputs.sha256 }}" in build
    upload = _workflow_named_step(build, "Upload portable wheel")
    assert "name: portable-wheel" in upload
    assert "path: dist/xferry-*.whl" in upload
    assert "if-no-files-found: error" in upload
    assert "needs: python314-readiness" in portable
    assert "os: [ubuntu-latest, macos-15, windows-latest]" in portable
    assert 'python-version: ["3.10", "3.12", "3.14"]' in portable
    assert "python-version: ${{ matrix.python-version }}" in portable
    download = _workflow_named_step(portable, "Download exact portable wheel")
    assert "actions/download-artifact@" in download
    assert "name: portable-wheel" in download
    assert "path: portable-artifacts" in download
    acceptance = _workflow_named_step(portable, "Isolated packaged CLI and portable tests")
    assert "shell: bash" in acceptance
    assert "needs.python314-readiness.outputs.wheel-sha256" in acceptance
    assert "verify_python_artifacts.py portable-smoke" in acceptance
    assert "--wheel 'portable-artifacts/xferry-*.whl'" in acceptance
    assert '--wheel-sha256 "$PORTABLE_WHEEL_SHA256"' in acceptance
    assert '--fresh-root "$RUNNER_TEMP/xferry-portable-app"' in acceptance
    assert "pip install -e" not in portable
    assert "python -m build" not in portable
    assert 'python-version: ["3.10", "3.11", "3.12", "3.13", "3.14"]' in exhaustive
    assert "pytest --cov=xferry" in exhaustive


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

    assert (
        compose.count("    command:\n      - run\n      - --access\n      - lab\n      - --host")
        == 3
    )
