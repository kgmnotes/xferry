"""Opt-in end-to-end check of the generated deployment against a built image."""

from __future__ import annotations

import base64
import json
import os
import subprocess
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from xferry.management.docker_deploy import deploy_docker, docker_operation

IMAGE = os.environ.get("XFERRY_DOCKER_CONFIGURATION_IMAGE")
pytestmark = pytest.mark.skipif(
    not IMAGE, reason="requires an explicitly selected local Docker image"
)


def test_generated_deployment_file_lifecycle_and_reconfigure(tmp_path: Path) -> None:
    files, output = tmp_path / "shared files", tmp_path / "deployment"
    files.mkdir(mode=0o700)
    existing = files / "existing.txt"
    existing.write_bytes(b"already on the host\n")
    owner = files.stat().st_uid
    local_http = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    class LocalImageRunner:
        """Use the selected test image and an ephemeral loopback host port."""

        def run(self, argv):
            compose_path = output / "compose.yaml"
            if compose_path.exists():
                document = json.loads(compose_path.read_text())
                for service in document["services"].values():
                    service["image"] = IMAGE
                document["services"]["xferry"]["ports"] = ["127.0.0.1::8080"]
                compose_path.write_text(json.dumps(document))
            return subprocess.run(argv, capture_output=True, text=True, check=False, timeout=240)

    runner = LocalImageRunner()
    project = None

    def deployment_diagnostic(message: str) -> str:
        if project is None:
            return message
        logs = runner.run(
            (
                "docker",
                "compose",
                "-p",
                project,
                "-f",
                str(output / "compose.yaml"),
                "logs",
                "--no-color",
                "--tail",
                "20",
                "xferry",
            )
        )
        return message + "\nRuntime logs:\n" + logs.stdout[-3000:]

    try:
        result = deploy_docker(output, files_dir=files, private=True, runner=runner)
        metadata = output / ".xferry-deployment.json"
        if metadata.exists():
            project = json.loads(metadata.read_text())["project"]
        assert result.exit_code == 0, deployment_diagnostic(result.message)
        assert result.password and len(result.password) == 12
        password = result.password
        secret = (output / "secrets/xferry_auth").read_bytes()
        assert files.stat().st_uid == owner

        def endpoint() -> str:
            port = runner.run(
                (
                    "docker",
                    "compose",
                    "-p",
                    project,
                    "-f",
                    str(output / "compose.yaml"),
                    "port",
                    "xferry",
                    "8080",
                )
            )
            assert port.returncode == 0
            return f"http://{port.stdout.strip()}"

        def request(
            path: str, *, method: str = "GET", data: bytes | None = None, authenticated: bool = True
        ):
            headers = {}
            if authenticated:
                token = base64.b64encode(f"admin:{password}".encode()).decode()
                headers["Authorization"] = f"Basic {token}"
            if data is not None:
                headers["X-File-Name"] = "new.txt"
            req = urllib.request.Request(
                endpoint() + path, data=data, headers=headers, method=method
            )
            try:
                with local_http.open(req, timeout=10) as response:
                    return response.status, response.read()
            except urllib.error.HTTPError as error:
                return error.code, error.read()

        assert request("/uploads/existing.txt", authenticated=False)[0] == 401
        assert request("/uploads/existing.txt") == (200, existing.read_bytes())
        assert request("/uploads", method="POST", data=b"new host content\n")[0] == 201
        assert (files / "new.txt").read_bytes() == b"new host content\n"
        assert not (files / "uploads").exists()
        assert request("/uploads/new.txt") == (200, b"new host content\n")

        changed = deploy_docker(output, settings_changes={"max_size_mb": "2"}, runner=runner)
        assert changed.exit_code == 0, deployment_diagnostic(changed.message)
        assert changed.password is None
        assert (output / "secrets/xferry_auth").read_bytes() == secret
        assert request("/uploads/existing.txt") == (200, existing.read_bytes())
        assert request("/uploads/new.txt", method="DELETE")[0] == 200
        assert not (files / "new.txt").exists()
        assert existing.exists()

        # The public lifecycle must work without manual Compose commands.
        config = output / "xferry.ini"
        stopped = docker_operation(config, "stop", runner=runner)
        assert stopped.exit_code == 0, deployment_diagnostic(stopped.message)
        assert stopped.details and stopped.details["running"] is False
        saved = deploy_docker(output, settings_changes={"max_size_mb": "3"}, runner=runner)
        assert saved.exit_code == 0, deployment_diagnostic(saved.message)
        status = docker_operation(config, "status", runner=runner)
        assert status.details and status.details["running"] is False
        started = docker_operation(config, "start", runner=runner)
        assert started.exit_code == 0, deployment_diagnostic(started.message)
        assert request("/uploads/existing.txt") == (200, existing.read_bytes())
        restarted = docker_operation(config, "restart", runner=runner)
        assert restarted.exit_code == 0, deployment_diagnostic(restarted.message)

        removed = docker_operation(config, "uninstall", runner=runner)
        assert removed.exit_code == 0, deployment_diagnostic(removed.message)
        assert existing.exists()
        resumed = deploy_docker(output, runner=runner)
        assert resumed.exit_code == 0, deployment_diagnostic(resumed.message)
        assert resumed.password is None
        assert (output / "secrets/xferry_auth").read_bytes() == secret
        assert request("/uploads/existing.txt") == (200, existing.read_bytes())
    finally:
        if project:
            runner.run(
                (
                    "docker",
                    "compose",
                    "-p",
                    project,
                    "-f",
                    str(output / "compose.yaml"),
                    "down",
                    "--volumes",
                    "--remove-orphans",
                )
            )
