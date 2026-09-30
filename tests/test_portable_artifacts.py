"""Failure-boundary tests for installed portable application acceptance."""

from __future__ import annotations

import hashlib
import os
import subprocess
import sys
from pathlib import Path

import pytest

from tools import verify_python_artifacts as verifier


def test_portable_wheel_digest_mismatch_fails_before_any_install(tmp_path: Path) -> None:
    wheel = tmp_path / "xferry.whl"
    wheel.write_bytes(b"changed in transfer")
    root = tmp_path / "fresh"
    with pytest.raises(verifier.ArtifactValidationError, match="SHA256"):
        verifier.portable_smoke(
            wheel=wheel,
            wheel_sha256="0" * 64,
            constraints=tmp_path / "constraints.txt",
            fresh_root=root,
            workspace=tmp_path / "checkout",
        )
    assert not root.exists()


def test_portable_application_rejects_checkout_and_nonempty_roots(tmp_path: Path) -> None:
    workspace = tmp_path / "checkout"
    workspace.mkdir()
    wheel = tmp_path / "xferry.whl"
    wheel.write_bytes(b"same candidate")
    common = {
        "wheel": wheel,
        "wheel_sha256": hashlib.sha256(wheel.read_bytes()).hexdigest(),
        "constraints": tmp_path / "constraints.txt",
        "workspace": workspace,
    }
    with pytest.raises(verifier.ArtifactValidationError, match="outside the checkout"):
        verifier.portable_smoke(**common, fresh_root=workspace / "app")
    occupied = tmp_path / "occupied"
    occupied.mkdir()
    sentinel = occupied / "user-file"
    sentinel.write_text("preserve me")
    with pytest.raises(verifier.ArtifactValidationError, match="must start empty"):
        verifier.portable_smoke(**common, fresh_root=occupied)
    assert sentinel.read_text() == "preserve me"


def test_probe_environment_drops_source_injection_and_ambient_pytest_options(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for key in ("PYTHONPATH", "PYTHONHOME", "PYTHONOPTIMIZE", "PIP_CONSTRAINT", "PYTEST_ADDOPTS"):
        monkeypatch.setenv(key, "poison")
    env = verifier._probe_environment(workspace=tmp_path / "checkout", venv_dir=tmp_path / "app")
    for key in ("PYTHONPATH", "PYTHONHOME", "PYTHONOPTIMIZE", "PIP_CONSTRAINT", "PYTEST_ADDOPTS"):
        assert key not in env
    assert env["XFERRY_PROBE_VENV"] == str(tmp_path / "app")


def test_import_probe_rejects_foreign_package_even_outside_checkout(tmp_path: Path) -> None:
    venv = tmp_path / "app"
    subprocess.run([sys.executable, "-m", "venv", "--without-pip", str(venv)], check=True)
    foreign = tmp_path / "foreign"
    foreign.mkdir()
    for name in ("acme", "cryptography", "josepy"):
        (foreign / f"{name}.py").write_text("")
    (foreign / "OpenSSL.py").write_text("SSL = object()\n")
    (foreign / "xferry.py").write_text("class XFerryServer: pass\n")
    python, _ = verifier._venv_commands(venv)
    env = {
        **os.environ,
        "PYTHONPATH": str(foreign),
        "GITHUB_WORKSPACE": str(tmp_path / "checkout"),
        "XFERRY_PROBE_VENV": str(venv),
    }
    result = subprocess.run(
        [str(python), "-c", verifier._IMPORT_PROBE],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert result.returncode != 0
    assert "AssertionError" in result.stderr
    assert str(foreign / "xferry.py") in result.stderr


def test_probe_command_timeout_is_a_verification_failure(tmp_path: Path) -> None:
    with pytest.raises(verifier.ArtifactValidationError, match="exceeded"):
        verifier._run_checked(
            (sys.executable, "-c", "import time; time.sleep(30)"), cwd=tmp_path, timeout=0.05
        )


def test_portable_test_staging_cannot_copy_the_source_package(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = Path(__file__).resolve().parents[1]
    calls = []
    monkeypatch.setattr(
        verifier, "_run_checked", lambda *args, **kwargs: calls.append((args, kwargs))
    )
    verifier._portable_tests(venv_dir=tmp_path / "app", probe_dir=tmp_path, workspace=workspace)
    test_root = tmp_path / "portable-tests"
    assert not (test_root / "xferry").exists()
    assert not (test_root / "tools").exists()
    assert (test_root / "tests/server_factory.py").is_file()
    assert (test_root / "pyproject.toml").is_file()
    assert len(calls) == 1
    command = calls[0][0][0]
    assert command[1:3] == ("-I", "-c")
    assert command[3].count(verifier._IMPORT_PROBE) == 2
    assert calls[0][1]["cwd"] == test_root


def test_lifecycle_failure_always_stops_the_started_process(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Process:
        stopped = False
        waited = False

        def poll(self):
            return None

        def terminate(self):
            self.stopped = True

        def wait(self, *, timeout):
            self.waited = True

    process = Process()
    monkeypatch.setattr(verifier.subprocess, "Popen", lambda *args, **kwargs: process)

    def fail_health(*args, **kwargs):
        assert kwargs["timeout"] == 15
        raise verifier.ArtifactValidationError("health exceeded its deadline")

    monkeypatch.setattr(verifier, "_run_checked", fail_health)
    with pytest.raises(verifier.ArtifactValidationError, match="health exceeded"):
        verifier._server_lifecycle_smoke(
            venv_dir=tmp_path / "app", probe_dir=tmp_path, workspace=tmp_path / "checkout"
        )
    assert process.stopped and process.waited


@pytest.mark.parametrize("poll_sequence", [(None, 3, 3), (None, None, 3)])
def test_lifecycle_does_not_accept_a_spontaneous_exit_after_health(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    poll_sequence: tuple[int | None, ...],
) -> None:
    class Process:
        polls = iter(poll_sequence)

        def poll(self):
            return next(self.polls)

        def wait(self, *, timeout):
            pass

    monkeypatch.setattr(verifier.subprocess, "Popen", lambda *args, **kwargs: Process())
    monkeypatch.setattr(verifier, "_run_checked", lambda *args, **kwargs: None)
    with pytest.raises(verifier.ArtifactValidationError, match="exited after health"):
        verifier._server_lifecycle_smoke(
            venv_dir=tmp_path / "app", probe_dir=tmp_path, workspace=tmp_path / "checkout"
        )


@pytest.mark.parametrize("legacy", [False, True])
def test_health_probe_accepts_canonical_operational_fields_and_rejects_legacy(legacy: bool) -> None:
    import json
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer

    payload = {
        "health": "ready",
        "supported_methods": ["PING", "NOTE", "SMUGGLE"],
        "server": "XFerry/0.1.0",
        "timestamp": "example",
        "metrics": {},
    }
    if legacy:
        payload["status"] = "pong"

    class Handler(BaseHTTPRequestHandler):
        def do_PING(self):
            body = json.dumps(payload).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    with HTTPServer(("127.0.0.1", 0), Handler) as server:
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            result = subprocess.run(
                [
                    sys.executable,
                    "-I",
                    "-c",
                    verifier._HEALTH_PROBE,
                    str(server.server_port),
                    "0.5",
                ],
                capture_output=True,
                text=True,
                timeout=3,
                check=False,
            )
            assert (result.returncode == 0) is not legacy
        finally:
            server.shutdown()
            thread.join(timeout=2)


def test_health_probe_rejects_a_response_completed_after_its_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import http.client
    import time

    clock = [0.0]

    class Response:
        status = 200

        def read(self, size):
            clock[0] = 30.0
            return b'{"health":"ready","supported_methods":["PING","NOTE","SMUGGLE"]}'

    class Connection:
        def __init__(self, *args, **kwargs):
            pass

        def request(self, *args, **kwargs):
            pass

        def getresponse(self):
            return Response()

        def close(self):
            pass

    monkeypatch.setattr(http.client, "HTTPConnection", Connection)
    monkeypatch.setattr(time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(time, "sleep", lambda delay: None)
    monkeypatch.setattr(sys, "argv", ["probe", "8000", "14"])
    with pytest.raises(SystemExit, match="not ready before deadline"):
        exec(verifier._HEALTH_PROBE, {})


def test_health_subprocess_has_a_total_timeout_for_trickling_responses(tmp_path: Path) -> None:
    import threading
    import time
    from http.server import BaseHTTPRequestHandler, HTTPServer

    class Handler(BaseHTTPRequestHandler):
        def do_PING(self):
            self.send_response(200)
            self.send_header("Content-Length", "100")
            self.end_headers()
            try:
                for _ in range(100):
                    self.wfile.write(b" ")
                    self.wfile.flush()
                    time.sleep(0.03)
            except (BrokenPipeError, ConnectionResetError):
                pass

        def log_message(self, *args):
            pass

    with HTTPServer(("127.0.0.1", 0), Handler) as server:
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with pytest.raises(verifier.ArtifactValidationError, match="exceeded"):
                verifier._run_checked(
                    (
                        sys.executable,
                        "-I",
                        "-c",
                        verifier._HEALTH_PROBE,
                        str(server.server_port),
                        "14",
                    ),
                    cwd=tmp_path,
                    timeout=0.25,
                )
        finally:
            server.shutdown()
            thread.join(timeout=2)
