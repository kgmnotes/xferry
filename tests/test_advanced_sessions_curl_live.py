"""Live curl proof for the public Advanced Sessions journey."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from tests.test_server_live import _LiveServer

CREATE_BODY = '{"prefix":"/advanced","decoder":"auto","diagnostic_headers":true}'
UPLOAD_BODY = '{"data":"aGVsbG8=","encoding":"base64","encryption":"none","name":"hello.txt"}'
TEST_CREDENTIALS = "operator:password"


def _curl_quote(value: str) -> str:
    """Return one curl-config string value without putting it in process argv."""
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _write_body(path: Path, body: str) -> None:
    path.write_text(body, encoding="utf-8")


def _curl_config(
    *,
    url: str,
    method: str,
    headers: tuple[str, ...] = (),
    body_path: Path | None = None,
    header_dump_path: Path | None = None,
    user: str | None = None,
) -> str:
    """Build a stdin-only curl configuration for a local request."""
    lines = [
        f"url = {_curl_quote(url)}",
        f"request = {_curl_quote(method)}",
    ]
    lines.extend(f"header = {_curl_quote(header)}" for header in headers)
    if body_path is not None:
        lines.append(f"data-binary = {_curl_quote('@' + str(body_path))}")
    if header_dump_path is not None:
        lines.append(f"dump-header = {_curl_quote(str(header_dump_path))}")
    if user is not None:
        lines.append(f"user = {_curl_quote(user)}")
    return "\n".join(lines) + "\n"


def _run_curl(
    curl: str,
    config: str,
    *,
    sensitive_values: tuple[str, ...] = (),
) -> subprocess.CompletedProcess[str]:
    """Run curl with secrets in stdin config rather than its process arguments."""
    argv = [
        curl,
        "--silent",
        "--show-error",
        "--fail-with-body",
        "--config",
        "-",
    ]
    result = subprocess.run(
        argv,
        input=config,
        text=True,
        capture_output=True,
        check=False,
        shell=False,
    )
    argv_text = "\0".join(result.args)
    assert all(value not in argv_text for value in sensitive_values)
    return result


def _assert_success(result: subprocess.CompletedProcess[str]) -> dict[str, object]:
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert isinstance(payload, dict)
    return payload


def _assert_create_response(
    result: subprocess.CompletedProcess[str],
    header_dump_path: Path,
) -> str:
    response = _assert_success(result)
    metadata = response["advanced_session"]
    assert isinstance(metadata, dict)
    token = metadata["token"]
    assert isinstance(token, str)
    assert re.fullmatch(r"[A-Za-z0-9_-]{43}", token)
    assert "cache-control: no-store" in header_dump_path.read_text(encoding="iso-8859-1").lower()
    return token


def _exercise_curl_journey(
    tmp_path: Path,
    live: _LiveServer,
    curl: str,
    *,
    credentials: str | None = None,
) -> None:
    """Create, upload through an unregistered method, revoke, then reject reuse."""
    base_url = f"http://127.0.0.1:{live.port}"
    create_body_path = tmp_path / "create.json"
    upload_body_path = tmp_path / "upload.json"
    create_headers_path = tmp_path / "create.headers"
    _write_body(create_body_path, CREATE_BODY)
    _write_body(upload_body_path, UPLOAD_BODY)

    create = _run_curl(
        curl,
        _curl_config(
            url=f"{base_url}/_xferry/advanced-sessions",
            method="POST",
            headers=("Content-Type: application/json",),
            body_path=create_body_path,
            header_dump_path=create_headers_path,
            user=credentials,
        ),
        sensitive_values=tuple(value for value in (credentials,) if value is not None),
    )
    token = _assert_create_response(create, create_headers_path)

    upload = _run_curl(
        curl,
        _curl_config(
            url=f"{base_url}/advanced/upload",
            method="SYNCDATA",
            headers=(
                f"X-XFerry-Advanced-Session: {token}",
                "Content-Type: application/json",
            ),
            body_path=upload_body_path,
            user=credentials,
        ),
        sensitive_values=tuple(value for value in (credentials, token) if value is not None),
    )
    upload_response = _assert_success(upload)
    upload_details = upload_response["upload"]
    assert isinstance(upload_details, dict)
    assert upload_details["kind"] == "advanced"
    assert upload_details["encryption"] == "none"
    assert not {"token", "key", "hmac"} & set(upload_response)
    assert (tmp_path / "uploads" / "hello.txt").read_bytes() == b"hello"

    revoke = _run_curl(
        curl,
        _curl_config(
            url=f"{base_url}/_xferry/advanced-sessions/current",
            method="DELETE",
            headers=(f"X-XFerry-Advanced-Session: {token}",),
            user=credentials,
        ),
        sensitive_values=tuple(value for value in (credentials, token) if value is not None),
    )
    assert _assert_success(revoke) == {"advanced_session": {"revoked": True}}

    reused = _run_curl(
        curl,
        _curl_config(
            url=f"{base_url}/advanced/upload",
            method="SYNCDATA",
            headers=(
                f"X-XFerry-Advanced-Session: {token}",
                "Content-Type: application/json",
            ),
            body_path=upload_body_path,
            user=credentials,
        ),
        sensitive_values=tuple(value for value in (credentials, token) if value is not None),
    )
    assert reused.returncode != 0
    assert json.loads(reused.stdout)["error"]["code"] == "advanced_session_not_found"


def test_curl_advanced_session_journey_stays_on_direct_loopback(tmp_path: Path) -> None:
    """Catches a broken no-auth loopback create/use/revoke public journey."""
    curl = shutil.which("curl")
    if curl is None:
        pytest.skip("curl is required for the local Advanced Sessions journey")

    with _LiveServer(tmp_path) as live:
        _exercise_curl_journey(tmp_path, live, curl)


def test_curl_advanced_session_journey_keeps_basic_auth_out_of_argv(tmp_path: Path) -> None:
    """Catches a Basic Auth journey that leaks credentials or tokens to argv."""
    curl = shutil.which("curl")
    if curl is None:
        pytest.skip("curl is required for the local Advanced Sessions journey")

    with _LiveServer(tmp_path, auth=TEST_CREDENTIALS) as live:
        unauthenticated = _run_curl(
            curl,
            _curl_config(
                url=f"http://127.0.0.1:{live.port}/_xferry/advanced-sessions",
                method="POST",
                headers=("Content-Type: application/json",),
            ),
        )
        assert unauthenticated.returncode != 0
        assert json.loads(unauthenticated.stdout)["error"]["code"] == "authentication_required"
        _exercise_curl_journey(tmp_path, live, curl, credentials=TEST_CREDENTIALS)
