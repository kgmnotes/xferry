"""Opt-in application/backend lifecycle against a genuinely identified local image."""

from __future__ import annotations

import base64
import json
import os
import re
import secrets
import socket
import subprocess
import urllib.error
import urllib.request
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from pathlib import Path

import pytest

from xferry.management.application import ManagementApplication
from xferry.management.deployment import load_manifest, resource_unchanged
from xferry.management.execution import CommandResult
from xferry.management.instances import Instance, discover_instances
from xferry.settings import load_settings_file

IMAGE = os.environ.get("XFERRY_DOCKER_CONFIGURATION_IMAGE")
pytestmark = pytest.mark.skipif(
    not IMAGE, reason="requires an explicitly selected local Docker image"
)
_DIGEST = re.compile(r"[a-z0-9][a-z0-9._:/-]*@sha256:[0-9a-f]{64}\Z")


def _docker(argv: Sequence[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(tuple(argv), capture_output=True, text=True, check=False, timeout=240)


def _repo_digests(image: str) -> tuple[str, ...]:
    result = _docker(("docker", "image", "inspect", "--format", "{{json .RepoDigests}}", image))
    assert result.returncode == 0, "the explicitly selected local image must exist"
    document = json.loads(result.stdout)
    return tuple(
        value for value in document or () if isinstance(value, str) and _DIGEST.fullmatch(value)
    )


@contextmanager
def _identified_local_image(image: str) -> Iterator[str]:
    """Obtain a real RepoDigest, using only a private loopback registry if needed."""
    digests = _repo_digests(image)
    if "@sha256:" in image:
        assert image in digests, "the selected digest must exist in the local image metadata"
        yield image
        return
    if digests:
        yield digests[0]
        return

    # Classic Docker image stores may not assign a RepoDigest to a local build.
    # Publish only to this test's disposable loopback registry, never publicly.
    token = secrets.token_hex(6)
    registry_id: str | None = None
    local_tag: str | None = None
    try:
        registry = _docker(
            (
                "docker",
                "run",
                "--detach",
                "--rm",
                "--name",
                f"xferry-configuration-registry-{token}",
                "--label",
                f"io.xferry.configuration-test={token}",
                "--publish",
                "127.0.0.1::5000",
                "registry:2",
            )
        )
        assert registry.returncode == 0, "the private test registry could not start"
        registry_id = registry.stdout.strip()
        published = _docker(("docker", "port", registry_id, "5000/tcp"))
        assert published.returncode == 0
        host = published.stdout.strip()
        assert host.startswith("127.0.0.1:"), "the test registry must remain loopback-only"
        local_tag = f"{host}/xferry-configuration:{token}"
        assert _docker(("docker", "tag", image, local_tag)).returncode == 0
        pushed = _docker(("docker", "push", local_tag))
        assert pushed.returncode == 0, "the image could not be pushed to its private test registry"
        repository = local_tag.rsplit(":", 1)[0]
        matches = [
            digest for digest in _repo_digests(local_tag) if digest.startswith(repository + "@")
        ]
        assert len(matches) == 1, "the private registry must provide one actual repository digest"
        yield matches[0]
    finally:
        if registry_id:
            _docker(("docker", "rm", "--force", "--volumes", registry_id))
        if local_tag:
            _docker(("docker", "image", "rm", local_tag))


class VerifiedLocalImageRunner:
    """Skip network pull only after Docker confirms the exact existing RepoDigest."""

    def __init__(self, selected_digest: str) -> None:
        self.selected_digest = selected_digest
        self.commands: list[tuple[str, ...]] = []

    def run(self, argv: Sequence[str], *, env: Mapping[str, str] | None = None) -> CommandResult:
        command = tuple(argv)
        self.commands.append(command)
        if command == ("docker", "pull", self.selected_digest):
            assert self.selected_digest in _repo_digests(self.selected_digest)
            return CommandResult(command, 0)
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False,
            timeout=240,
            env=None if env is None else {**os.environ, **env},
        )
        return CommandResult(command, result.returncode, result.stdout, result.stderr)


def _free_port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def test_generated_deployment_file_lifecycle_and_reconfigure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert IMAGE is not None
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "operator-state"))
    # Exercise the real private setup contract before moving to a free host port
    # through the public configuration operation. Never rewrite owned Compose.
    with socket.socket() as listener:
        try:
            listener.bind(("127.0.0.1", 8080))
        except OSError:
            pytest.skip("initial private setup requires free loopback port 8080")

    with _identified_local_image(IMAGE) as digest:
        _run_application_lifecycle(tmp_path, digest)


def _run_application_lifecycle(tmp_path: Path, digest: str) -> None:
    files, output = tmp_path / "shared files", tmp_path / "deployment"
    files.mkdir(mode=0o700)
    existing = files / "existing.txt"
    existing.write_bytes(b"already on the host\n")
    original = existing.stat()
    folder_owner = files.stat().st_uid
    local_http = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    runner = VerifiedLocalImageRunner(digest)
    app = ManagementApplication(runner=runner)
    instance: Instance | None = None
    manifest = output / ".xferry-deployment.json"
    password = ""

    def diagnostic(message: str) -> str:
        if instance is None or not manifest.exists():
            return message
        result = app.operate("logs", instance, lines=20)
        return message + "\nRuntime logs:\n" + str(result.details.get("logs", ""))[-3000:]

    def request(
        path: str,
        *,
        method: str = "GET",
        data: bytes | None = None,
        authenticated: bool = True,
        auth_password: str | None = None,
    ) -> tuple[int, bytes]:
        assert instance is not None
        port = load_settings_file(instance.config).port
        headers = {}
        if authenticated:
            selected_password = password if auth_password is None else auth_password
            token = base64.b64encode(f"admin:{selected_password}".encode()).decode()
            headers["Authorization"] = f"Basic {token}"
        if data is not None:
            headers["X-File-Name"] = "new.txt"
        req = urllib.request.Request(
            f"http://127.0.0.1:{port}{path}", data=data, headers=headers, method=method
        )
        try:
            with local_http.open(req, timeout=10) as response:
                return response.status, response.read()
        except urllib.error.HTTPError as error:
            return error.code, error.read()

    try:
        result = app.setup(
            backend="docker", output=output, files_dir=files, access="private", image=digest
        )
        instance = app.resolve(manifest)
        assert result.exit_code == 0, diagnostic(result.message)
        assert result.credentials is not None and len(result.credentials.password) == 12
        password = result.credentials.password
        assert files.stat().st_uid == folder_owner
        assert instance.spec.artifact["image"] == digest
        project = str(instance.spec.backend_options["project"])
        document = json.loads((output / "compose.yaml").read_text())
        assert document["name"] == project
        assert {service["image"] for service in document["services"].values()} == {digest}
        assert all(resource_unchanged(resource) for resource in instance.spec.ownership.resources)

        secret = (output / "secrets/xferry_auth").read_bytes()
        changed = app.configure(
            instance,
            {"port": _free_port(), "max_size_mb": 2},
            apply=True,
            expected_text=instance.config.read_text(),
        )
        assert changed.exit_code == 0, diagnostic(changed.message)
        assert app.observe(instance).state == "running"
        assert (output / "secrets/xferry_auth").read_bytes() == secret
        assert instance.spec.artifact["image"] == digest
        assert request("/uploads/existing.txt", authenticated=False)[0] == 401
        assert request("/uploads/existing.txt") == (200, existing.read_bytes())
        assert request("/uploads", method="POST", data=b"new host content\n")[0] == 201
        assert (files / "new.txt").read_bytes() == b"new host content\n"
        assert not (files / "uploads").exists()
        assert request("/uploads/new.txt") == (200, b"new host content\n")
        assert request("/uploads/new.txt", method="DELETE")[0] == 200
        assert not (files / "new.txt").exists()

        old_password = password
        rotated = app.credentials(instance, password="typedkeyboard42")
        assert rotated.exit_code == 0, diagnostic(rotated.message)
        assert rotated.credentials is not None
        password = rotated.credentials.password
        assert request("/uploads/existing.txt", auth_password=old_password)[0] == 401
        assert request("/uploads/existing.txt") == (200, existing.read_bytes())
        rotated_secret = (output / "secrets/xferry_auth").read_bytes()
        assert rotated_secret != secret
        doctor = app.doctor(instance, check_http=True)
        assert doctor.exit_code == 0, diagnostic(doctor.message)
        assert doctor.state is not None and doctor.state.health == "healthy"
        assert doctor.details["state_storage"] == instance.spec.backend_options["state_storage"]

        stopped = app.operate("stop", instance)
        assert stopped.exit_code == 0, diagnostic(stopped.message)
        assert app.observe(instance).state == "stopped"
        saved = app.configure(
            instance, {"max_size_mb": 3}, apply=True, expected_text=instance.config.read_text()
        )
        assert saved.exit_code == 0, diagnostic(saved.message)
        assert app.operate("status", instance).state.state == "stopped"
        assert (output / "secrets/xferry_auth").read_bytes() == rotated_secret
        started = app.operate("start", instance)
        assert started.exit_code == 0, diagnostic(started.message)
        assert request("/uploads/existing.txt") == (200, existing.read_bytes())
        restarted = app.operate("restart", instance)
        assert restarted.exit_code == 0, diagnostic(restarted.message)

        removed = app.operate("uninstall", instance)
        assert removed.exit_code == 0, diagnostic(removed.message)
        assert app.observe(instance).state == "retained"
        assert (output / "secrets/xferry_auth").read_bytes() == rotated_secret
        resumed = app.setup(backend="docker", instance_id=instance.id)
        assert resumed.exit_code == 0, diagnostic(resumed.message)
        assert resumed.credentials is None
        assert request("/uploads/existing.txt") == (200, existing.read_bytes())
        assert (output / "secrets/xferry_auth").read_bytes() == rotated_secret
        assert (
            len([command for command in runner.commands if command[:2] == ("docker", "pull")]) == 1
        )

        purged = app.operate("uninstall", instance, purge=True, confirmed=True)
        assert purged.exit_code == 0, diagnostic(purged.message)
        assert not output.exists()
        assert discover_instances() == ()
        assert existing.read_bytes() == b"already on the host\n"
        retained = existing.stat()
        assert (
            retained.st_uid,
            retained.st_gid,
            retained.st_mode,
            retained.st_ino,
            retained.st_size,
            retained.st_mtime_ns,
        ) == (
            original.st_uid,
            original.st_gid,
            original.st_mode,
            original.st_ino,
            original.st_size,
            original.st_mtime_ns,
        )
        assert files.stat().st_uid == folder_owner
        assert _docker(("docker", "volume", "inspect", project + "_xferry-data")).returncode != 0
        assert _docker(("docker", "volume", "inspect", project + "_xferry-secrets")).returncode != 0
    finally:
        if manifest.exists():
            # Resolve the published identity even when initial activation failed.
            # Cleanup targets only this test's project and generated manifest.
            spec = load_manifest(manifest)
            try:
                app.operate("uninstall", app.resolve(manifest), purge=True, confirmed=True)
            except (OSError, RuntimeError, ValueError):
                _docker(
                    (
                        "docker",
                        "compose",
                        "-p",
                        str(spec.backend_options["project"]),
                        "-f",
                        str(output / "compose.yaml"),
                        "down",
                        "--volumes",
                        "--remove-orphans",
                    )
                )
