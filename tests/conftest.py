"""Pytest fixtures for XFerryServer tests."""

import socket
import tempfile
from pathlib import Path

import pytest

from xferry.http import HTTPRequest
from xferry.request_admission import (
    RequestAdmissionConfig,
    RequestAdmissionContext,
    RequestAdmissionPolicy,
)

# Local Codex stage-runner tests are intentionally ignored by Git and are not part
# of the project/CI test contract.
collect_ignore = [Path(__file__).with_name("test_close_plan_stages.py")]


@pytest.fixture
def temp_dir():
    """Create a temporary directory for test files."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def sample_file(temp_dir: Path) -> Path:
    """Create a sample file for testing."""
    file_path = temp_dir / "test_file.txt"
    file_path.write_text("Hello, World!")
    return file_path


@pytest.fixture
def upload_dir(temp_dir: Path) -> Path:
    """Create an uploads directory for testing."""
    uploads = temp_dir / "uploads"
    uploads.mkdir(exist_ok=True)
    return uploads


def find_free_port() -> int:
    """Reserve an ephemeral local port and return it."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def make_request(
    method: str = "GET",
    path: str = "/",
    headers: dict[str, str] | None = None,
    body: bytes = b"",
    *,
    http_version: str = "HTTP/1.1",
    default_host: str | None = "example.test",
) -> HTTPRequest:
    """Build and test-admit a minimal HTTPRequest with an explicit authority."""
    header_lines = [f"{method} {path} {http_version}"]
    supplied_host = next(
        (value for key, value in (headers or {}).items() if key.lower() == "host"),
        None,
    )
    if supplied_host is None and default_host is not None:
        header_lines.append(f"Host: {default_host}")
    if headers:
        for k, v in headers.items():
            header_lines.append(f"{k}: {v}")
    if body:
        header_lines.append(f"Content-Length: {len(body)}")
    raw = "\r\n".join(header_lines).encode() + b"\r\n\r\n" + body
    request = HTTPRequest(raw)
    host_value = supplied_host or default_host
    config_host = host_value or "example.test"
    if host_value is not None:
        if config_host.startswith("[") and "]" in config_host:
            config_host = config_host[1 : config_host.index("]")]
        elif config_host.count(":") == 1:
            config_host = config_host.partition(":")[0]
    policy = RequestAdmissionPolicy.from_config(
        RequestAdmissionConfig(
            bind_host=config_host,
            server_port=8080,
            tls_enabled=False,
            allowed_hosts=(config_host,),
        )
    )
    admitted = policy.admit(request)
    if isinstance(admitted, RequestAdmissionContext):
        request.set_admission_context(admitted)
    return request
