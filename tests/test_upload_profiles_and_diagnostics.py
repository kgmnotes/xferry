"""Behavioral coverage for Basic upload profiles and shared diagnostics."""

from __future__ import annotations

import base64
import hashlib
import json
import threading
from dataclasses import asdict, fields
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import quote

import pytest

import xferry.handlers.advanced_payload as advanced_payload
from tests.conftest import make_request
from xferry.advanced_sessions import (
    AdvancedSession,
    AdvancedSessionDispatch,
    AdvancedSessionPrincipal,
)
from xferry.handlers import HandlerMixin
from xferry.handlers.upload_diagnostics import UploadDiagnostics, add_upload_diagnostics
from xferry.http import HTTPRequest, error_response, json_response
from xferry.security.crypto import compute_hmac, xor_encrypt
from xferry.storage import UploadStorageQuotaExceeded

DIAGNOSTIC_KEYS = {
    "dispatch",
    "route_source",
    "route_revision",
    "profile",
    "carrier",
    "filename_source",
    "normalized_filename",
    "collision_renamed",
    "request_body_size",
    "payload_size",
    "file_content_type",
    "sha256",
}
EXPECTED_UPLOAD_DIAGNOSTIC_FIELDS = {
    "dispatch",
    "profile",
    "carrier",
    "filename_source",
    "normalized_filename",
    "collision_renamed",
    "request_body_size",
    "payload_size",
    "file_content_type",
    "sha256",
}
REMOVED_ROUTING_MODEL_ATTRIBUTES = {
    "route_source",
    "route_revision",
    "snapshot",
    "revision",
}
MIRROR_HEADERS = {
    "X-XFerry-Handler",
    "X-Upload-Profile",
    "X-File-Name-Source",
    "X-File-SHA256",
    "X-Request-Body-Size",
    "X-XFerry-Route-Revision",
}
FORBIDDEN_DIAGNOSTIC_HEADERS = MIRROR_HEADERS - {"X-XFerry-Handler"}
LEGACY_SUCCESS_KEYS = {
    "success",
    "filename",
    "size",
    "size_human",
    "path",
    "uploaded_at",
    "content_type",
}
LEGACY_UPLOAD_HEADERS = {
    "X-Upload-Status",
    "X-File-Name",
    "X-File-Size",
    "X-File-Path",
    "X-Upload-Profile",
    "X-File-Name-Source",
    "X-File-SHA256",
    "X-Request-Body-Size",
    "X-XFerry-Route-Revision",
}
LEGACY_REJECTION_CASES = (
    ("header", "X-D", "X-D"),
    ("header", "X-D-0", "X-D-0"),
    ("header", "X-E", "X-E"),
    ("header", "X-K", "X-K"),
    ("header", "X-Kb64", "X-Kb64"),
    ("header", "X-N", "X-N"),
    ("header", "X-H", "X-H"),
    ("header", "X-Encoding", "X-Encoding"),
    ("header", "X-HTTP-Method-Override", "X-HTTP-Method-Override"),
    ("header", "X-Payload-In-Path", "X-Payload-In-Path"),
    ("query", "d", "data"),
    ("query", "d0", "data"),
    ("query", "d-0", "data"),
    ("query", "d_0", "data"),
    ("query", "data0", "data"),
    ("query", "data-0", "data"),
    ("query", "e", "encryption"),
    ("query", "k", "key"),
    ("query", "kb64", "key_is_base64"),
    ("query", "n", "name"),
    ("query", "h", "hmac"),
    ("query", "enc", "encoding"),
    ("query", "_method", "method_override"),
    ("query", "path_payload", "path_payload"),
    ("query", "path_filename", "path_filename"),
    ("cookie", "xf_d", "xf_d"),
    ("cookie", "xf_data", "xf_data"),
    ("cookie", "xf_e", "xf_e"),
    ("cookie", "xf_k", "xf_k"),
    ("cookie", "xf_kb64", "xf_kb64"),
    ("cookie", "xf_n", "xf_n"),
    ("cookie", "xf_name", "xf_name"),
    ("cookie", "xf_h", "xf_h"),
    ("cookie", "xf_hmac", "xf_hmac"),
    ("cookie", "xf_encoding", "xf_encoding"),
    ("cookie", "xf_enc", "xf_enc"),
    ("cookie", "xf_method", "xf_method"),
)
STATIC_GUARD_LEGACY_TOKENS = (
    "X-D",
    "X-E",
    "X-K",
    "X-Kb64",
    "X-N",
    "X-H",
    "X-Encoding",
    "X-HTTP-Method-Override",
    "X-Payload-In-Path",
    "xf_d",
    "xf_data",
    "xf_e",
    "xf_k",
    "xf_kb64",
    "xf_n",
    "xf_name",
    "xf_h",
    "xf_hmac",
    "xf_enc",
    "xf_method",
    "path_payload",
    "path_filename",
)


class UploadServer(HandlerMixin):
    """Minimal real handler composition for upload diagnostics tests."""

    def __init__(self, root_dir: Path, upload_dir: Path) -> None:
        self.root_dir = root_dir
        self.upload_dir = upload_dir
        self.notes_dir = root_dir / "notes"
        self.notes_dir.mkdir(exist_ok=True)
        self.cors_origin = "https://ui.example"
        self.cors_origins = ("https://ui.example",)
        self.sandbox_mode = False
        self.opsec_mode = False
        self._temp_smuggle_files: set[str] = set()
        self._smuggle_lock = threading.Lock()
        self._notes_lock = threading.Lock()
        self._ecdh_manager = None
        self.method_handlers = self.build_method_handlers()


@pytest.fixture
def upload_server(temp_dir: Path, upload_dir: Path) -> UploadServer:
    return UploadServer(temp_dir, upload_dir)


def _bind_advanced_session_dispatch(
    request,
    *,
    prefix: str = "/advanced",
    decoder: str = "auto",
    diagnostic_headers: bool = False,
    owner: str | None = None,
):
    now = datetime(2026, 8, 14, 12, 0, tzinfo=timezone.utc)
    principal = (
        AdvancedSessionPrincipal("basic", owner)
        if owner is not None
        else AdvancedSessionPrincipal("no_auth", None)
    )
    request.advanced_session_dispatch = AdvancedSessionDispatch(
        session=AdvancedSession(
            prefix=prefix,
            decoder=decoder,
            diagnostic_headers=diagnostic_headers,
            created_at=now,
            expires_at=now + timedelta(hours=1),
            last_activity_at=now,
        ),
        principal=principal,
        direct_peer=None,
    )
    request.advanced_session_admission_prepared = True
    return request


def test_upload_diagnostics_and_dispatch_expose_only_current_routing_surface() -> None:
    """Catches removed routing metadata resurfacing through model introspection."""
    diagnostic_values: dict[str, object] = {
        "dispatch": "advanced",
        "route_source": "removed-route-source",
        "route_revision": 37,
        "profile": "json",
        "carrier": "body",
        "filename_source": "body",
        "normalized_filename": "diagnostic.bin",
        "collision_renamed": False,
        "request_body_size": 64,
        "payload_size": 12,
        "file_content_type": "application/octet-stream",
        "sha256": "not-exposed",
    }
    field_names = {field.name for field in fields(UploadDiagnostics)}
    diagnostics = UploadDiagnostics(**{name: diagnostic_values[name] for name in field_names})
    request = _bind_advanced_session_dispatch(make_request("POST", "/advanced"))
    dispatch = request.advanced_session_dispatch
    assert isinstance(dispatch, AdvancedSessionDispatch)

    violations: list[str] = []
    serialized_keys = set(asdict(diagnostics))
    if serialized_keys != EXPECTED_UPLOAD_DIAGNOSTIC_FIELDS:
        violations.append(f"UploadDiagnostics serialization keys: {sorted(serialized_keys)!r}")
    for model in (diagnostics, dispatch):
        exposed = sorted(name for name in REMOVED_ROUTING_MODEL_ATTRIBUTES if hasattr(model, name))
        if exposed:
            violations.append(f"{type(model).__name__} attributes: {exposed!r}")

    assert dict(dispatch) == {
        "prefix": "/advanced",
        "decoder": "auto",
        "diagnostic_headers": False,
    }
    with pytest.raises(TypeError):
        asdict(dispatch)
    assert not violations, "\n".join(violations)


def _multipart(
    payload: bytes,
    *,
    field_name: str = "artifact",
    filename: str = "part.bin",
    content_type: str = "application/custom",
    scalar: bool = True,
    encoded_field: bool = False,
    advanced_metadata: bool = False,
) -> tuple[str, bytes]:
    boundary = "xferry-profile-test"
    parts: list[bytes] = []
    if scalar:
        parts.append(b'Content-Disposition: form-data; name="note"\r\n\r\nignored')
    if encoded_field:
        parts.append(
            b'Content-Disposition: form-data; name="data"\r\n\r\n' + base64.b64encode(payload)
        )
        parts.append(b'Content-Disposition: form-data; name="encoding"\r\n\r\nbase64')
        parts.append(b'Content-Disposition: form-data; name="encryption"\r\n\r\nnone')
        parts.append(b'Content-Disposition: form-data; name="name"\r\n\r\nencoded.bin')
    else:
        parts.append(
            (
                f'Content-Disposition: form-data; name="{field_name}"; '
                f'filename="{filename}"\r\n'
                f"Content-Type: {content_type}\r\n\r\n"
            ).encode()
            + payload
        )
        if advanced_metadata:
            parts.append(b'Content-Disposition: form-data; name="encryption"\r\n\r\nnone')
    body = b"".join(b"--" + boundary.encode() + b"\r\n" + part + b"\r\n" for part in parts)
    body += b"--" + boundary.encode() + b"--\r\n"
    return f"multipart/form-data; boundary={boundary}", body


def _json(response) -> dict[str, object]:
    value = json.loads(response.body)
    assert isinstance(value, dict)
    return value


def _assert_no_legacy_basic_upload_surface(response, body: dict[str, object]) -> None:
    assert LEGACY_SUCCESS_KEYS.isdisjoint(body)
    assert DIAGNOSTIC_KEYS.isdisjoint(body)
    assert LEGACY_UPLOAD_HEADERS.isdisjoint(response.headers)


def _assert_canonical_basic_success(
    response,
    *,
    name: str,
    payload: bytes,
    content_type: str,
    profile: str,
    carrier: str,
    filename_source: str,
    request_body_size: int,
    collision_renamed: bool,
) -> dict[str, object]:
    body = _json(response)

    assert response.status_code == 201
    _assert_no_legacy_basic_upload_surface(response, body)
    assert set(body) == {"file", "upload"}
    assert body["file"] == {
        "name": name,
        "path": f"/uploads/{name}",
        "size_bytes": len(payload),
        "size_human": f"{float(len(payload)):.1f} B",
        "content_type": content_type,
        "uploaded_at": body["file"]["uploaded_at"],
        "sha256": hashlib.sha256(payload).hexdigest(),
    }
    assert body["upload"] == {
        "kind": "basic",
        "profile": profile,
        "carrier": carrier,
        "filename_source": filename_source,
        "normalized_name": name,
        "collision_renamed": collision_renamed,
        "request_body_size": request_body_size,
        "payload_size": len(payload),
    }
    assert body["file"]["uploaded_at"].endswith("+00:00")
    assert len(body["file"]["sha256"]) == 64
    assert body["file"]["sha256"].islower()
    return body


def _assert_canonical_error(
    response,
    *,
    status: int,
    code: str,
    field: str,
    details: dict[str, object] | None = None,
) -> dict[str, object]:
    body = _json(response)

    assert response.status_code == status
    assert set(body) == {"error"}
    assert body["error"]["code"] == code
    assert body["error"]["field"] == field
    if details is not None:
        assert body["error"]["details"] == details
    _assert_no_legacy_basic_upload_surface(response, body)
    assert MIRROR_HEADERS.isdisjoint(response.headers)
    return body


def _forbid_advanced_touch(
    upload_server: UploadServer,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_touch(_request: HTTPRequest) -> None:
        pytest.fail("Advanced rejection must not touch session idle activity")

    monkeypatch.setattr(upload_server, "_touch_advanced_session_dispatch", fail_touch)


def _b64(payload: bytes) -> str:
    return base64.b64encode(payload).decode("ascii")


def _b64url(payload: bytes) -> str:
    return base64.urlsafe_b64encode(payload).decode("ascii").rstrip("=")


def _assert_advanced_success(
    response,
    upload_dir: Path,
    *,
    name: str,
    payload: bytes,
    profile: str,
    carrier: str,
    filename_source: str,
    request_body_size: int,
    encoding: str,
    encryption: str = "none",
    content_type: str = "application/octet-stream",
) -> dict[str, object]:
    body = _json(response)

    assert response.status_code == 201
    assert set(body) == {"file", "upload"}
    file_body = body["file"]
    assert isinstance(file_body, dict)
    uploaded_at = file_body.get("uploaded_at")
    assert isinstance(uploaded_at, str)
    assert uploaded_at.endswith("+00:00")
    assert datetime.fromisoformat(uploaded_at).tzinfo is not None
    sha256 = file_body.get("sha256")
    assert isinstance(sha256, str)
    assert len(sha256) == 64
    assert all(char in "0123456789abcdef" for char in sha256)
    assert file_body == {
        "name": name,
        "path": f"/uploads/{name}",
        "size_bytes": len(payload),
        "size_human": f"{float(len(payload)):.1f} B",
        "content_type": content_type,
        "uploaded_at": uploaded_at,
        "sha256": hashlib.sha256(payload).hexdigest(),
    }
    assert body["upload"] == {
        "kind": "advanced",
        "profile": profile,
        "carrier": carrier,
        "filename_source": filename_source,
        "normalized_name": name,
        "collision_renamed": False,
        "request_body_size": request_body_size,
        "payload_size": len(payload),
        "encoding": encoding,
        "encryption": encryption,
        "method_override": None,
    }
    assert (upload_dir / name).read_bytes() == payload
    return body


def _canonical_json_payload(
    payload: bytes,
    *,
    name: str = "advanced.bin",
    encryption: str = "none",
    encoding: str = "base64",
    key: str | None = None,
    hmac_value: str | None = None,
) -> bytes:
    data: dict[str, object] = {
        "data": _b64(payload) if encoding == "base64" else payload.decode("utf-8"),
        "encoding": encoding,
        "encryption": encryption,
        "name": name,
    }
    if key is not None:
        data["key"] = key
    if hmac_value is not None:
        data["hmac"] = hmac_value
    return json.dumps(data, separators=(",", ":")).encode("utf-8")


def _raw_header_request(raw_values: dict[str, str]) -> HTTPRequest:
    lines = ["POST /advanced HTTP/1.1"]
    lines.extend(f"{name}:{raw_value}" for name, raw_value in raw_values.items())
    return HTTPRequest("\r\n".join(lines).encode("ascii") + b"\r\n\r\n")


def _xor_header_values() -> dict[str, str]:
    key = "header-key"
    ciphertext = xor_encrypt(b"header exact syntax", key)
    return {
        "X-XFerry-Data": _b64(ciphertext),
        "X-XFerry-Encoding": "base64",
        "X-XFerry-Encryption": "xor",
        "X-XFerry-Key": key,
        "X-XFerry-HMAC": compute_hmac(ciphertext, key),
        "X-XFerry-Name": "header-exact.bin",
    }


def _raw_canonical_header_values() -> dict[str, str]:
    return {name: f" {value}" for name, value in _xor_header_values().items()}


def test_basic_multipart_uses_single_file_part_and_reports_envelope_sizes(
    upload_server: UploadServer,
    upload_dir: Path,
) -> None:
    """Catches Basic storing the multipart envelope or requiring field name `file`."""
    payload = b"\x00multipart payload\xff"
    content_type, body = _multipart(payload)
    request = make_request(
        "POST",
        "/uploads",
        headers={"Content-Type": content_type},
        body=body,
    )

    response = upload_server._dispatch_handler(request)

    _assert_canonical_basic_success(
        response,
        name="part.bin",
        payload=payload,
        content_type="application/custom",
        profile="multipart",
        carrier="multipart",
        filename_source="part",
        request_body_size=len(body),
        collision_renamed=False,
    )
    assert (upload_dir / "part.bin").read_bytes() == payload


def test_basic_raw_header_success_returns_canonical_file_and_upload_contract(
    upload_server: UploadServer,
    upload_dir: Path,
) -> None:
    payload = b"hello"
    response = upload_server._dispatch_handler(
        make_request(
            "POST",
            "/uploads",
            headers={
                "Content-Type": "text/plain",
                "X-File-Name": "hello.txt",
            },
            body=payload,
        )
    )

    _assert_canonical_basic_success(
        response,
        name="hello.txt",
        payload=payload,
        content_type="text/plain",
        profile="raw_header",
        carrier="body",
        filename_source="header",
        request_body_size=len(payload),
        collision_renamed=False,
    )
    assert (upload_dir / "hello.txt").read_bytes() == payload


def test_basic_raw_url_success_uses_url_profile_and_source(
    upload_server: UploadServer,
    upload_dir: Path,
) -> None:
    payload = b"url bytes"
    response = upload_server._dispatch_handler(
        make_request(
            "PUT",
            "/uploads/url-name.bin",
            headers={"Content-Type": "application/octet-stream"},
            body=payload,
        )
    )

    _assert_canonical_basic_success(
        response,
        name="url-name.bin",
        payload=payload,
        content_type="application/octet-stream",
        profile="raw_url",
        carrier="body",
        filename_source="url",
        request_body_size=len(payload),
        collision_renamed=False,
    )
    assert (upload_dir / "url-name.bin").read_bytes() == payload


def test_basic_multipart_success_uses_part_profile_and_source(
    upload_server: UploadServer,
    upload_dir: Path,
) -> None:
    payload = b"multipart bytes"
    content_type, body = _multipart(payload, filename="part.txt", content_type="text/custom")
    response = upload_server._dispatch_handler(
        make_request(
            "PATCH",
            "/uploads",
            headers={"Content-Type": content_type},
            body=body,
        )
    )

    _assert_canonical_basic_success(
        response,
        name="part.txt",
        payload=payload,
        content_type="text/custom",
        profile="multipart",
        carrier="multipart",
        filename_source="part",
        request_body_size=len(body),
        collision_renamed=False,
    )
    assert (upload_dir / "part.txt").read_bytes() == payload


def test_basic_generated_name_and_collision_return_canonical_upload_metadata(
    upload_server: UploadServer,
    upload_dir: Path,
) -> None:
    generated_payload = b"generated body"
    generated = upload_server._dispatch_handler(make_request("NONE", "/", body=generated_payload))
    generated_body = _json(generated)

    assert generated.status_code == 201
    _assert_no_legacy_basic_upload_surface(generated, generated_body)
    assert set(generated_body) == {"file", "upload"}
    generated_name = generated_body["file"]["name"]
    assert isinstance(generated_name, str)
    assert generated_name.startswith("upload_")
    assert generated_body["upload"] == {
        "kind": "basic",
        "profile": "raw_url",
        "carrier": "body",
        "filename_source": "generated",
        "normalized_name": generated_name,
        "collision_renamed": False,
        "request_body_size": len(generated_payload),
        "payload_size": len(generated_payload),
    }
    assert (upload_dir / generated_name).read_bytes() == generated_payload

    (upload_dir / "duplicate.txt").write_bytes(b"existing")
    collision_payload = b"replacement"
    collision = upload_server._dispatch_handler(
        make_request(
            "POST",
            "/uploads",
            headers={"X-File-Name": "duplicate.txt"},
            body=collision_payload,
        )
    )
    collision_body = _json(collision)

    assert collision.status_code == 201
    _assert_no_legacy_basic_upload_surface(collision, collision_body)
    collision_name = collision_body["file"]["name"]
    assert collision_name != "duplicate.txt"
    assert collision_body["file"]["path"] == f"/uploads/{collision_name}"
    assert collision_body["file"]["sha256"] == hashlib.sha256(collision_payload).hexdigest()
    assert collision_body["upload"] == {
        "kind": "basic",
        "profile": "raw_header",
        "carrier": "body",
        "filename_source": "header",
        "normalized_name": collision_name,
        "collision_renamed": True,
        "request_body_size": len(collision_payload),
        "payload_size": len(collision_payload),
    }
    assert (upload_dir / "duplicate.txt").read_bytes() == b"existing"
    assert (upload_dir / str(collision_name)).read_bytes() == collision_payload


def test_basic_empty_payload_returns_exact_canonical_error_envelope(
    upload_server: UploadServer,
    upload_dir: Path,
) -> None:
    response = upload_server._dispatch_handler(
        make_request(
            "POST",
            "/uploads",
            headers={"X-File-Name": "empty.txt"},
            body=b"",
        )
    )

    _assert_canonical_error(
        response,
        status=400,
        code="empty_payload",
        field="file",
        details={"upload_kind": "basic"},
    )
    assert not (upload_dir / "empty.txt").exists()


def test_basic_invalid_multipart_returns_canonical_invalid_field_error(
    upload_server: UploadServer,
    upload_dir: Path,
) -> None:
    response = upload_server._dispatch_handler(
        make_request(
            "POST",
            "/uploads",
            headers={"Content-Type": "multipart/form-data; boundary=missing"},
            body=b"malformed",
        )
    )

    _assert_canonical_error(
        response,
        status=400,
        code="invalid_field",
        field="file",
    )
    assert list(upload_dir.iterdir()) == []


def test_basic_quota_error_returns_bounded_canonical_507(
    upload_server: UploadServer,
    upload_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    secret = "do-not-echo-this-quota-secret"

    def reject_publish(file_path: Path, data: bytes):
        raise UploadStorageQuotaExceeded(
            f"Upload storage quota exceeded: {secret}",
            status_code=507,
        )

    monkeypatch.setattr(upload_server._get_upload_storage(), "publish_bytes", reject_publish)

    response = upload_server._dispatch_handler(
        make_request(
            "POST",
            "/uploads",
            headers={"X-File-Name": "quota.txt"},
            body=b"blocked",
        )
    )
    rendered = response.body.decode()
    body = _assert_canonical_error(
        response,
        status=507,
        code="storage_quota_exceeded",
        field="file",
    )

    assert body["error"]["details"].get("scope") == "uploads"
    assert set(body["error"]["details"]) <= {
        "scope",
        "reason",
        "limit_bytes",
        "current_bytes",
        "attempted_bytes",
        "limit_files",
        "current_files",
    }
    assert secret not in rendered
    assert f"Upload storage quota exceeded: {secret}" not in rendered
    assert secret not in caplog.text
    assert list(upload_dir.iterdir()) == []


def test_basic_unexpected_storage_exception_returns_500_without_exception_echo(
    upload_server: UploadServer,
    upload_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    secret = "forced-secret-from-storage"

    def fail_publish(file_path: Path, data: bytes):
        raise RuntimeError(secret)

    monkeypatch.setattr(upload_server._get_upload_storage(), "publish_bytes", fail_publish)

    response = upload_server._dispatch_handler(
        make_request(
            "PUT",
            "/uploads",
            headers={"X-File-Name": "boom.txt"},
            body=b"boom",
        )
    )
    rendered = response.body.decode()

    _assert_canonical_error(
        response,
        status=500,
        code="internal_error",
        field="file",
    )
    assert secret not in rendered
    assert "RuntimeError" not in rendered
    assert secret not in caplog.text
    assert list(upload_dir.iterdir()) == []


def test_advanced_missing_payload_keeps_the_exact_error_envelope_after_diagnostics(
    upload_server: UploadServer,
) -> None:
    """Catches Advanced diagnostics flattening a missing-payload envelope."""
    response = upload_server.handle_advanced_upload(
        _bind_advanced_session_dispatch(
            make_request("POST", "/advanced"),
            diagnostic_headers=True,
        )
    )

    assert response.status_code == 400
    assert _json(response) == {
        "error": {
            "code": "missing_field",
            "message": "Advanced upload payload is required",
            "field": "data",
            "details": {},
        }
    }
    assert response.headers["X-XFerry-Handler"] == "advanced"
    assert DIAGNOSTIC_KEYS.isdisjoint(_json(response))


def test_advanced_metadata_only_does_not_create_a_carrier(
    upload_server: UploadServer,
    upload_dir: Path,
) -> None:
    """Catches canonical metadata headers being treated as payload candidates."""
    response = upload_server.handle_advanced_upload(
        _bind_advanced_session_dispatch(
            make_request(
                "POST",
                "/advanced",
                headers={
                    "X-XFerry-Encryption": "none",
                    "X-XFerry-Name": "metadata-only.bin",
                },
            )
        )
    )

    _assert_canonical_error(response, status=400, code="missing_field", field="data")
    assert list(upload_dir.iterdir()) == []


def test_advanced_legacy_header_alias_is_invalid_and_never_published(
    upload_server: UploadServer,
    upload_dir: Path,
) -> None:
    """Catches `X-D` compatibility fallback being accepted as a carrier."""
    response = upload_server.handle_advanced_upload(
        _bind_advanced_session_dispatch(
            make_request(
                "POST",
                "/advanced",
                headers={
                    "X-D": _b64(b"legacy"),
                    "X-N": "legacy.bin",
                },
            )
        )
    )

    _assert_canonical_error(response, status=400, code="invalid_field", field="X-D")
    assert list(upload_dir.iterdir()) == []


@pytest.mark.parametrize(("carrier", "legacy_name", "expected_field"), LEGACY_REJECTION_CASES)
def test_advanced_legacy_rejection_only_entries_are_never_accepted(
    upload_server: UploadServer,
    upload_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
    carrier: str,
    legacy_name: str,
    expected_field: str,
) -> None:
    """Catches rejection-only legacy names becoming accepted aliases."""
    _forbid_advanced_touch(upload_server, monkeypatch)
    if carrier == "header":
        request = make_request(
            "POST",
            "/advanced",
            headers={legacy_name: _b64(b"legacy")},
        )
    elif carrier == "query":
        request = make_request("POST", f"/advanced?{legacy_name}=legacy")
    else:
        request = make_request("POST", "/advanced", headers={"Cookie": f"{legacy_name}=legacy"})

    response = upload_server.handle_advanced_upload(_bind_advanced_session_dispatch(request))

    _assert_canonical_error(
        response,
        status=400,
        code="invalid_field",
        field=expected_field,
    )
    assert list(upload_dir.iterdir()) == []


def test_advanced_legacy_rejection_literals_are_static_guarded_in_runtime_parser() -> None:
    """Catches obfuscated legacy aliases or accepted-alias tables in production."""
    table = getattr(advanced_payload, "_LEGACY_ADVANCED_REJECTION_ONLY_FIELDS", None)
    assert table is not None

    production_source = Path("xferry/handlers/advanced_payload.py").read_text(encoding="utf-8")
    declaration_start = production_source.index("_LEGACY_ADVANCED_REJECTION_ONLY_FIELDS")
    declaration_end = production_source.index("_HEADER_LEGACY_REJECTIONS", declaration_start)
    outside_declaration = (
        production_source[:declaration_start] + production_source[declaration_end:]
    )

    for token in STATIC_GUARD_LEGACY_TOKENS:
        assert token in production_source
        assert token not in outside_declaration
    assert '"+ "' not in production_source
    assert '" + "' not in production_source
    assert "' + '" not in production_source


@pytest.mark.parametrize(
    ("header_name", "expected_field"),
    [
        ("X-XFerry-Data", "X-XFerry-Data"),
        ("X-XFerry-Encoding", "X-XFerry-Encoding"),
        ("X-XFerry-Encryption", "X-XFerry-Encryption"),
        ("X-XFerry-Key", "X-XFerry-Key"),
        ("X-XFerry-HMAC", "X-XFerry-HMAC"),
    ],
)
def test_advanced_canonical_header_values_reject_ows_padding_before_publication(
    upload_server: UploadServer,
    upload_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
    header_name: str,
    expected_field: str,
) -> None:
    """Catches normalized header values accepting padded non-canonical syntax."""
    _forbid_advanced_touch(upload_server, monkeypatch)
    canonical_values = _xor_header_values()
    raw_values = _raw_canonical_header_values()
    raw_values[header_name] = f"  {canonical_values[header_name]} "

    response = upload_server.handle_advanced_upload(
        _bind_advanced_session_dispatch(_raw_header_request(raw_values))
    )

    _assert_canonical_error(
        response,
        status=400,
        code="invalid_field",
        field=expected_field,
    )
    assert list(upload_dir.iterdir()) == []


@pytest.mark.parametrize(
    ("cookie_name", "expected_field"),
    [
        ("xferry_data", "xferry_data"),
        ("xferry_encoding", "xferry_encoding"),
        ("xferry_encryption", "xferry_encryption"),
        ("xferry_key", "xferry_key"),
        ("xferry_hmac", "xferry_hmac"),
    ],
)
def test_advanced_canonical_cookie_values_reject_padding_without_stripping(
    upload_server: UploadServer,
    upload_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
    cookie_name: str,
    expected_field: str,
) -> None:
    """Catches xferry_* cookie values being stripped before canonical validation."""
    _forbid_advanced_touch(upload_server, monkeypatch)
    key = "cookie-key"
    ciphertext = xor_encrypt(b"cookie exact syntax", key)
    cookie_values = {
        "xferry_data": quote(_b64(ciphertext), safe=""),
        "xferry_encoding": "base64",
        "xferry_encryption": "xor",
        "xferry_key": key,
        "xferry_hmac": compute_hmac(ciphertext, key),
        "xferry_name": "cookie-exact.bin",
    }
    cookie_values[cookie_name] = f"{cookie_values[cookie_name]} "
    cookie_header = "; ".join(f"{name}={value}" for name, value in cookie_values.items())

    response = upload_server.handle_advanced_upload(
        _bind_advanced_session_dispatch(
            make_request("POST", "/advanced", headers={"Cookie": cookie_header})
        )
    )

    _assert_canonical_error(
        response,
        status=400,
        code="invalid_field",
        field=expected_field,
    )
    assert list(upload_dir.iterdir()) == []


def test_advanced_hmac_mismatch_redacts_crypto_fields_from_exact_error_envelope(
    upload_server: UploadServer,
    upload_dir: Path,
) -> None:
    """Catches HMAC mismatch restoring aliases, echoing secrets, or writing files."""
    key = "advanced-key-secret"
    hmac_value = "0" * 64
    response = upload_server.handle_advanced_upload(
        _bind_advanced_session_dispatch(
            make_request(
                "POST",
                "/advanced",
                headers={"Content-Type": "application/json"},
                body=_canonical_json_payload(
                    b"ciphertext",
                    encryption="xor",
                    key=key,
                    hmac_value=hmac_value,
                ),
            ),
            decoder="json",
        )
    )
    rendered = response.body.decode("utf-8")

    assert _json(response) == {
        "error": {
            "code": "hmac_mismatch",
            "message": "Advanced upload integrity check failed",
            "field": "hmac",
            "details": {},
        }
    }
    assert key not in rendered
    assert hmac_value not in rendered
    assert DIAGNOSTIC_KEYS.isdisjoint(_json(response))
    assert list(upload_dir.iterdir()) == []


def test_advanced_quota_error_redacts_exception_text_from_response_and_logs(
    upload_server: UploadServer,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Catches quota accounting text leaking through Advanced error logs."""
    secret = "advanced-quota-accounting-secret"

    def reject_publish(file_path: Path, data: bytes) -> None:
        raise UploadStorageQuotaExceeded(secret, status_code=507)

    monkeypatch.setattr(upload_server._get_upload_storage(), "publish_bytes", reject_publish)
    response = upload_server.handle_advanced_upload(
        _bind_advanced_session_dispatch(
            make_request(
                "POST",
                "/advanced",
                headers={"Content-Type": "application/json"},
                body=_canonical_json_payload(b"blocked", name="quota.bin"),
            ),
            decoder="json",
        )
    )
    rendered = response.body.decode("utf-8")

    assert _json(response) == {
        "error": {
            "code": "storage_quota_exceeded",
            "message": "Upload storage quota exceeded",
            "field": "file",
            "details": {"scope": "uploads"},
        }
    }
    assert secret not in rendered
    assert secret not in caplog.text
    assert DIAGNOSTIC_KEYS.isdisjoint(_json(response))


def test_advanced_write_failure_redacts_exception_text_from_response_and_logs(
    upload_server: UploadServer,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Catches arbitrary storage failures leaking paths or secrets through logs."""
    secret = "advanced-write-path-secret"

    def fail_publish(file_path: Path, data: bytes) -> None:
        raise RuntimeError(secret)

    monkeypatch.setattr(upload_server._get_upload_storage(), "publish_bytes", fail_publish)
    response = upload_server.handle_advanced_upload(
        _bind_advanced_session_dispatch(
            make_request(
                "POST",
                "/advanced",
                headers={"Content-Type": "application/json"},
                body=_canonical_json_payload(b"blocked", name="boom.bin"),
            ),
            decoder="json",
        )
    )
    rendered = response.body.decode("utf-8")

    assert _json(response) == {
        "error": {
            "code": "internal_error",
            "message": "Advanced upload failed",
            "field": "file",
            "details": {},
        }
    }
    assert secret not in rendered
    assert secret not in caplog.text
    assert DIAGNOSTIC_KEYS.isdisjoint(_json(response))


def test_basic_upload_diagnostics_preserves_canonical_error_without_flattening() -> None:
    response = error_response(
        400,
        "empty_payload",
        "Upload payload is empty",
        field="file",
        details={"upload_kind": "basic"},
    )
    response.set_header("X-Existing-Header", "keep-me")
    original_body = response.body
    original_headers = response.headers.copy()
    original_headers_object = response.headers
    diagnostics = UploadDiagnostics(
        dispatch="basic",
        profile="raw_header",
        carrier="body",
        filename_source="header",
        normalized_filename="empty.txt",
        collision_renamed=None,
        request_body_size=0,
        payload_size=None,
        file_content_type="text/plain",
        sha256=None,
    )
    result_response = add_upload_diagnostics(response, diagnostics, None)
    body = _json(result_response)

    assert result_response is response
    assert result_response.body == original_body
    assert result_response.headers is original_headers_object
    assert result_response.headers == original_headers
    assert body == {
        "error": {
            "code": "empty_payload",
            "message": "Upload payload is empty",
            "field": "file",
            "details": {"upload_kind": "basic"},
        }
    }
    assert DIAGNOSTIC_KEYS.isdisjoint(body)
    assert MIRROR_HEADERS.isdisjoint(result_response.headers)


def test_advanced_upload_diagnostics_preserves_canonical_body_and_adds_only_handler_header() -> (
    None
):
    """Catches Advanced diagnostics rewriting the canonical upload representation."""
    response = json_response(
        {
            "file": {"name": "advanced.txt", "path": "/uploads/advanced.txt"},
            "upload": {"kind": "advanced", "encryption": "none"},
        },
        status=201,
    )
    response.set_header("X-Existing-Header", "keep-me")
    original_body = response.body
    original_headers = response.headers.copy()
    diagnostics = UploadDiagnostics(
        dispatch="advanced",
        profile="base64",
        carrier="body",
        filename_source="body",
        normalized_filename="advanced.txt",
        collision_renamed=False,
        request_body_size=16,
        payload_size=12,
        file_content_type="application/octet-stream",
        sha256="not-exposed",
    )
    request = _bind_advanced_session_dispatch(
        make_request("POST", "/advanced"),
        decoder="base64",
        diagnostic_headers=True,
    )
    dispatch = request.advanced_session_dispatch
    assert isinstance(dispatch, AdvancedSessionDispatch)

    result_response = add_upload_diagnostics(response, diagnostics, dispatch)

    assert result_response is response
    assert result_response.body == original_body
    assert result_response.headers["X-Existing-Header"] == original_headers["X-Existing-Header"]
    assert _json(result_response) == {
        "file": {"name": "advanced.txt", "path": "/uploads/advanced.txt"},
        "upload": {"kind": "advanced", "encryption": "none"},
    }
    assert result_response.headers["X-XFerry-Handler"] == "advanced"
    assert FORBIDDEN_DIAGNOSTIC_HEADERS.isdisjoint(result_response.headers)


@pytest.mark.parametrize(
    ("path", "headers", "expected_name", "expected_source", "expected_profile"),
    [
        ("/uploads", {}, "uploads", "url", "raw_url"),
        (
            "/uploads",
            {"X-File-Name": "header.bin"},
            "header.bin",
            "header",
            "raw_header",
        ),
        ("/uploads/url.bin", {}, "url.bin", "url", "raw_url"),
        (
            "/uploads/url.bin",
            {"X-File-Name": "header.bin"},
            "header.bin",
            "header",
            "raw_header",
        ),
        ("/", {}, None, "generated", "raw_url"),
    ],
)
def test_basic_raw_filename_precedence_and_legacy_uploads_name(
    upload_server: UploadServer,
    upload_dir: Path,
    path: str,
    headers: dict[str, str],
    expected_name: str | None,
    expected_source: str,
    expected_profile: str,
) -> None:
    """Catches `/uploads` being treated as an unconditional collection."""
    payload = b"raw bytes"
    response = upload_server._dispatch_handler(
        make_request("PUT", path, headers=headers, body=payload)
    )
    result = _json(response)
    upload = result["upload"]

    stored_name = str(upload["normalized_name"])
    if expected_name is not None:
        assert stored_name == expected_name
    else:
        assert stored_name.startswith("upload_")
    assert (upload_dir / stored_name).read_bytes() == payload
    assert upload["filename_source"] == expected_source
    assert upload["profile"] == expected_profile
    assert upload["carrier"] == "body"


def test_basic_multipart_header_filename_wins_and_collision_is_diagnostic(
    upload_server: UploadServer,
    upload_dir: Path,
) -> None:
    """Catches part filename overriding the header or hiding collision renames."""
    (upload_dir / "chosen.bin").write_bytes(b"old")
    content_type, body = _multipart(b"new")

    response = upload_server._dispatch_handler(
        make_request(
            "PATCH",
            "/uploads/url.bin",
            headers={
                "Content-Type": content_type,
                "X-File-Name": "chosen.bin",
            },
            body=body,
        )
    )
    result = _json(response)
    upload = result["upload"]

    assert upload["filename_source"] == "header"
    assert upload["normalized_name"] != "chosen.bin"
    assert upload["collision_renamed"] is True
    assert (upload_dir / str(upload["normalized_name"])).read_bytes() == b"new"


def test_basic_multipart_error_is_json_with_safe_diagnostics(
    upload_server: UploadServer,
) -> None:
    """Catches upload errors losing diagnostics or echoing confidential metadata."""
    secret = "do-not-return-this-key"
    response = upload_server._dispatch_handler(
        make_request(
            "POST",
            "/uploads",
            headers={
                "Content-Type": "multipart/form-data; boundary=missing",
                "Cookie": "private=do-not-return-this-cookie",
                "X-K": secret,
            },
            body=b"malformed",
        )
    )
    rendered = response.body.decode()

    _assert_canonical_error(
        response,
        status=400,
        code="invalid_field",
        field="file",
    )
    assert secret not in rendered
    assert "do-not-return-this-cookie" not in rendered


def test_basic_upload_diagnostic_header_mirrors_and_cors_exposure_are_removed(
    upload_server: UploadServer,
) -> None:
    """Catches Basic upload reintroducing legacy diagnostic mirror headers."""
    disabled = upload_server._dispatch_handler(
        make_request("NONE", "/", headers={"X-File-Name": "off.bin"}, body=b"off")
    )
    disabled.build(cors_origin="https://ui.example")
    assert MIRROR_HEADERS.isdisjoint(disabled.headers)
    disabled_exposed = set(disabled.headers["Access-Control-Expose-Headers"].split(", "))
    assert MIRROR_HEADERS.isdisjoint(disabled_exposed)

    enabled = upload_server._dispatch_handler(
        make_request("NONE", "/", headers={"X-File-Name": "on.bin"}, body=b"on")
    )
    enabled.build(cors_origin="https://ui.example")

    assert MIRROR_HEADERS.isdisjoint(enabled.headers)
    enabled_exposed = set(enabled.headers["Access-Control-Expose-Headers"].split(", "))
    assert MIRROR_HEADERS.isdisjoint(enabled_exposed)


def test_advanced_raw_body_uses_canonical_metadata_headers(
    upload_server: UploadServer,
    upload_dir: Path,
) -> None:
    """Catches raw/text bodies ignoring canonical metadata or decoding as JSON."""
    payload = b'{"data":"wrong","name":"wrong.bin"}'

    request = _bind_advanced_session_dispatch(
        make_request(
            "POST",
            "/advanced/literal.bin",
            headers={
                "Content-Type": "application/octet-stream",
                "X-XFerry-Encryption": "none",
                "X-XFerry-Name": "literal.bin",
            },
            body=payload,
        )
    )
    response = upload_server.handle_advanced_upload(request)

    _assert_advanced_success(
        response,
        upload_dir,
        name="literal.bin",
        payload=payload,
        profile="raw",
        carrier="body",
        filename_source="header",
        request_body_size=len(request.body),
        encoding="raw",
    )


def test_advanced_upload_diagnostics_redact_session_authority_from_outputs(
    upload_server: UploadServer,
    upload_dir: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Catches diagnostic body, headers, or logs exposing session authority material."""
    caplog.set_level("DEBUG", logger="xferry")

    response = upload_server.handle_advanced_upload(
        _bind_advanced_session_dispatch(
            make_request(
                "POST",
                "/advanced/redacted.bin",
                headers={
                    "Authorization": "Basic SensitiveAuthorization",
                    "Content-Type": "application/octet-stream",
                    "Forwarded": "for=SensitiveForwardedPeer",
                    "X-Forwarded-For": "SensitiveForwardedPeer",
                    "X-XFerry-Encryption": "none",
                    "X-XFerry-Name": "redacted.bin",
                },
                body=b"diagnostic redaction",
            ),
            diagnostic_headers=True,
            owner="SensitiveOwner",
        )
    )
    response.build(cors_origin="https://ui.example")
    rendered = json.dumps(_json(response), sort_keys=True) + repr(response.headers) + caplog.text

    assert response.status_code == 201
    assert (upload_dir / "redacted.bin").read_bytes() == b"diagnostic redaction"
    for sensitive in (
        "SensitiveOwner",
        "SensitiveAuthorization",
        "SensitiveForwardedPeer",
    ):
        assert sensitive not in rendered


def test_advanced_structured_body_rejects_external_metadata_headers(
    upload_server: UploadServer,
    upload_dir: Path,
) -> None:
    """Catches cross-carrier metadata overlay on JSON/form/XML/multipart bodies."""
    response = upload_server.handle_advanced_upload(
        _bind_advanced_session_dispatch(
            make_request(
                "POST",
                "/advanced",
                headers={
                    "Content-Type": "application/json",
                    "X-XFerry-Name": "overlay.bin",
                },
                body=_canonical_json_payload(b"json", name="body.bin"),
            ),
            decoder="json",
        )
    )

    _assert_canonical_error(
        response,
        status=400,
        code="invalid_field",
        field="X-XFerry-Name",
    )
    assert list(upload_dir.iterdir()) == []


def test_unknown_method_without_session_no_longer_uses_legacy_fallback(
    upload_server: UploadServer,
    upload_dir: Path,
) -> None:
    """Catches a no-header custom method using body sniffing for Advanced."""
    body = json.dumps(
        {
            "d": base64.b64encode(b"legacy fallback").decode(),
            "n": "legacy-fallback.bin",
        }
    ).encode()

    response = upload_server._dispatch_handler(
        make_request(
            "XUPLOAD",
            "/legacy",
            headers={"Content-Type": "application/json"},
            body=body,
        )
    )
    assert response.status_code == 405
    assert not (upload_dir / "legacy-fallback.bin").exists()


def test_advanced_json_canonical_success_requires_explicit_none_encryption(
    upload_server: UploadServer,
    upload_dir: Path,
) -> None:
    """Catches implicit encryption defaults or legacy `d/e/n` aliases."""
    payload = b"canonical json"
    body = _canonical_json_payload(payload, name="json.bin")
    response = upload_server.handle_advanced_upload(
        _bind_advanced_session_dispatch(
            make_request(
                "POST",
                "/advanced",
                headers={"Content-Type": "application/json"},
                body=body,
            ),
            decoder="json",
        )
    )

    _assert_advanced_success(
        response,
        upload_dir,
        name="json.bin",
        payload=payload,
        profile="json",
        carrier="body",
        filename_source="body",
        request_body_size=len(body),
        encoding="base64",
    )


def test_advanced_json_rejects_omitted_encryption_instead_of_defaulting_none(
    upload_server: UploadServer,
    upload_dir: Path,
) -> None:
    """Catches the old implicit `none` diagnostic default for encoded carriers."""
    body = json.dumps(
        {
            "data": _b64(b"missing encryption"),
            "encoding": "base64",
            "name": "implicit-none.bin",
        },
        separators=(",", ":"),
    ).encode("utf-8")

    response = upload_server.handle_advanced_upload(
        _bind_advanced_session_dispatch(
            make_request(
                "POST",
                "/advanced",
                headers={"Content-Type": "application/json"},
                body=body,
            ),
            decoder="json",
        )
    )

    _assert_canonical_error(response, status=400, code="missing_field", field="encryption")
    assert list(upload_dir.iterdir()) == []


def test_advanced_json_duplicate_member_is_invalid_field(
    upload_server: UploadServer,
    upload_dir: Path,
) -> None:
    """Catches `json.loads()` last-value behavior hiding duplicate members."""
    response = upload_server.handle_advanced_upload(
        _bind_advanced_session_dispatch(
            make_request(
                "POST",
                "/advanced",
                headers={"Content-Type": "application/json"},
                body=(
                    b'{"data":"Zmlyc3Q=","data":"c2Vjb25k",'
                    b'"encoding":"base64","encryption":"none","name":"dup.bin"}'
                ),
            ),
            decoder="json",
        )
    )

    _assert_canonical_error(response, status=400, code="invalid_field", field="data")
    assert list(upload_dir.iterdir()) == []


def test_advanced_body_and_header_payload_candidates_are_ambiguous_before_parse(
    upload_server: UploadServer,
    upload_dir: Path,
) -> None:
    """Catches a malformed selected body falling through to header data."""
    response = upload_server.handle_advanced_upload(
        _bind_advanced_session_dispatch(
            make_request(
                "POST",
                "/advanced",
                headers={
                    "Content-Type": "application/json",
                    "X-XFerry-Data": _b64(b"header"),
                    "X-XFerry-Encoding": "base64",
                    "X-XFerry-Encryption": "none",
                },
                body=b"{",
            ),
            decoder="json",
        )
    )

    _assert_canonical_error(
        response,
        status=400,
        code="ambiguous_payload",
        field="data",
        details={"carriers": ["body", "headers"]},
    )
    assert list(upload_dir.iterdir()) == []


@pytest.mark.parametrize(
    ("carrier", "name"),
    [
        ("headers", "header.bin"),
        ("query", "query.bin"),
        ("cookies", "cookie.bin"),
        ("path", "path.bin"),
    ],
)
def test_advanced_canonical_non_body_carriers_publish_without_overlay(
    upload_server: UploadServer,
    upload_dir: Path,
    carrier: str,
    name: str,
) -> None:
    """Catches carrier precedence, default encodings, and cross-carrier metadata."""
    payload = f"{carrier} payload".encode("ascii")
    encoded = _b64(payload)
    path = "/advanced"
    headers: dict[str, str] = {}
    expected_encoding = "base64"
    if carrier == "headers":
        headers = {
            "X-XFerry-Data": encoded,
            "X-XFerry-Encoding": "base64",
            "X-XFerry-Encryption": "none",
            "X-XFerry-Name": name,
        }
    elif carrier == "query":
        path += f"?data={quote(encoded, safe='')}&encoding=base64&encryption=none&name={name}"
    elif carrier == "cookies":
        headers = {
            "Cookie": (
                f"xferry_data={quote(encoded, safe='')}; "
                f"xferry_encoding=base64; xferry_encryption=none; xferry_name={name}"
            )
        }
    else:
        encoded_path = _b64url(payload)
        path += f"/_payload/{name}/{encoded_path}?encryption=none"
        expected_encoding = "base64url"

    response = upload_server.handle_advanced_upload(
        _bind_advanced_session_dispatch(
            make_request("POST", path, headers=headers),
        )
    )

    _assert_advanced_success(
        response,
        upload_dir,
        name=name,
        payload=payload,
        profile="header" if carrier == "headers" else carrier,
        carrier=carrier,
        filename_source=(
            "path" if carrier == "path" else carrier[:-1] if carrier.endswith("s") else carrier
        ),
        request_body_size=0,
        encoding=expected_encoding,
    )


def test_advanced_header_chunks_must_be_contiguous_and_in_wire_order(
    upload_server: UploadServer,
    upload_dir: Path,
) -> None:
    """Catches dict-style header parsing sorting or filling chunk gaps."""
    raw = (
        b"POST /advanced HTTP/1.1\r\n"
        b"X-XFerry-Data-1: bG8=\r\n"
        b"X-XFerry-Data-0: aGVs\r\n"
        b"X-XFerry-Encoding: base64\r\n"
        b"X-XFerry-Encryption: none\r\n"
        b"\r\n"
    )
    response = upload_server.handle_advanced_upload(
        _bind_advanced_session_dispatch(HTTPRequest(raw))
    )

    _assert_canonical_error(response, status=400, code="invalid_field", field="data")
    assert list(upload_dir.iterdir()) == []


def test_advanced_fixed_decoder_mismatched_content_type_is_415(
    upload_server: UploadServer,
    upload_dir: Path,
) -> None:
    """Catches fixed decoder mode sniffing or coercing a conflicting media type."""
    response = upload_server.handle_advanced_upload(
        _bind_advanced_session_dispatch(
            make_request(
                "POST",
                "/advanced",
                headers={"Content-Type": "text/plain"},
                body=_canonical_json_payload(b"json", name="json.bin"),
            ),
            decoder="json",
        )
    )

    body = _assert_canonical_error(
        response,
        status=415,
        code="unsupported_media_type",
        field="Content-Type",
    )
    assert "application/json" in body["error"]["details"]["supported"]
    assert list(upload_dir.iterdir()) == []


def test_advanced_form_body_invalid_utf8_returns_canonical_validation_error(
    upload_server: UploadServer,
    upload_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Catches UnicodeDecodeError escaping the Advanced error envelope."""
    _forbid_advanced_touch(upload_server, monkeypatch)

    response = upload_server.handle_advanced_upload(
        _bind_advanced_session_dispatch(
            make_request(
                "POST",
                "/advanced",
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                body=b"data=abc\xff&encoding=raw&encryption=none",
            ),
            decoder="form",
        )
    )
    rendered = response.body.decode("utf-8")

    _assert_canonical_error(response, status=400, code="invalid_field", field="data")
    assert "UnicodeDecodeError" not in rendered
    assert "abc" not in rendered
    assert list(upload_dir.iterdir()) == []


@pytest.mark.parametrize(
    "body",
    [
        b"<upload><!--hidden--><data>eG1s</data><encoding>base64</encoding>"
        b"<encryption>none</encryption></upload>",
        b"<upload><?hidden value?><data>eG1s</data><encoding>base64</encoding>"
        b"<encryption>none</encryption></upload>",
        b"<upload>mixed<data>eG1s</data><encoding>base64</encoding>"
        b"<encryption>none</encryption></upload>",
        b'<!DOCTYPE upload [<!ENTITY x "hidden">]><upload><data>&x;</data>'
        b"<encoding>base64</encoding><encryption>none</encryption></upload>",
        b"<upload><data>eG1s</data><encoding>base64</encoding>",
    ],
)
def test_advanced_xml_closed_grammar_rejects_noncanonical_payload_tree(
    upload_server: UploadServer,
    upload_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
    body: bytes,
) -> None:
    """Catches XML comments/PIs/mixed content/DTD/malformed input being accepted."""
    _forbid_advanced_touch(upload_server, monkeypatch)

    response = upload_server.handle_advanced_upload(
        _bind_advanced_session_dispatch(
            make_request(
                "POST",
                "/advanced",
                headers={"Content-Type": "application/xml"},
                body=body,
            ),
            decoder="xml",
        )
    )

    _assert_canonical_error(response, status=400, code="invalid_field", field="data")
    assert list(upload_dir.iterdir()) == []


@pytest.mark.parametrize(
    "body",
    [
        b'<!DOCTYPE upload [<!ENTITY replacement "eG1s">]><upload><data>&replacement;</data>'
        b"<encoding>base64</encoding><encryption>none</encryption></upload>",
        b'<!DOCTYPE upload SYSTEM "https://invalid.example/payload.dtd"><upload><data>eG1s</data>'
        b"<encoding>base64</encoding><encryption>none</encryption></upload>",
        b'<!DOCTYPE upload [<!ENTITY remote SYSTEM "https://invalid.example/payload.txt">]>'
        b"<upload><data>&remote;</data><encoding>base64</encoding><encryption>none</encryption>"
        b"</upload>",
        b"<!--noncanonical--><upload><data>eG1s</data><encoding>base64</encoding>"
        b"<encryption>none</encryption></upload>",
        b"<?noncanonical ignored?><upload><data>eG1s</data><encoding>base64</encoding>"
        b"<encryption>none</encryption></upload>",
    ],
    ids=["internal-entity", "external-dtd", "external-entity", "leading-comment", "leading-pi"],
)
def test_advanced_xml_rejects_unsafe_or_noncanonical_prolog_constructs(
    upload_server: UploadServer,
    upload_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
    body: bytes,
) -> None:
    """Catches an XML parser accepting DTDs, entities, or prolog comments/PIs."""
    _forbid_advanced_touch(upload_server, monkeypatch)

    response = upload_server.handle_advanced_upload(
        _bind_advanced_session_dispatch(
            make_request(
                "POST",
                "/advanced",
                headers={"Content-Type": "application/xml"},
                body=body,
            ),
            decoder="xml",
        )
    )

    _assert_canonical_error(response, status=400, code="invalid_field", field="data")
    assert list(upload_dir.iterdir()) == []


def test_advanced_multipart_binary_and_encoded_field_are_distinct(
    upload_server: UploadServer,
    upload_dir: Path,
) -> None:
    """Catches a binary file part being base64-decoded as scalar data, or vice versa."""
    binary_type, binary_body = _multipart(
        b"binary-data",
        field_name="file",
        filename="binary.bin",
        scalar=False,
        advanced_metadata=True,
    )
    encoded_type, encoded_body = _multipart(b"encoded-data", scalar=False, encoded_field=True)

    binary = upload_server.handle_advanced_upload(
        _bind_advanced_session_dispatch(
            make_request(
                "POST",
                "/advanced",
                headers={"Content-Type": binary_type},
                body=binary_body,
            ),
            decoder="multipart",
        )
    )
    encoded = upload_server.handle_advanced_upload(
        _bind_advanced_session_dispatch(
            make_request(
                "POST",
                "/advanced",
                headers={"Content-Type": encoded_type},
                body=encoded_body,
            ),
            decoder="multipart",
        )
    )

    _assert_advanced_success(
        binary,
        upload_dir,
        name="binary.bin",
        payload=b"binary-data",
        profile="multipart-binary",
        carrier="body",
        filename_source="part",
        request_body_size=len(binary_body),
        encoding="raw",
        content_type="application/custom",
    )
    _assert_advanced_success(
        encoded,
        upload_dir,
        name="encoded.bin",
        payload=b"encoded-data",
        profile="multipart-encoded",
        carrier="body",
        filename_source="body",
        request_body_size=len(encoded_body),
        encoding="base64",
    )


def test_advanced_multipart_rejects_ambiguous_payload_candidates(
    upload_server: UploadServer,
    upload_dir: Path,
) -> None:
    """Catches Advanced silently preferring a file part or encoded field."""
    content_type, body = _multipart(
        b"file-data",
        field_name="file",
        filename="file.bin",
        scalar=False,
        advanced_metadata=True,
    )
    boundary = b"--xferry-profile-test"
    body = body.replace(
        boundary + b"--\r\n",
        boundary
        + b'\r\nContent-Disposition: form-data; name="data"\r\n\r\n'
        + _b64(b"field").encode("ascii")
        + b"\r\n"
        + boundary
        + b"--\r\n",
    )

    response = upload_server.handle_advanced_upload(
        _bind_advanced_session_dispatch(
            make_request(
                "POST",
                "/advanced",
                headers={"Content-Type": content_type},
                body=body,
            ),
            decoder="multipart",
        )
    )

    _assert_canonical_error(response, status=400, code="invalid_field", field="data")
    assert list(upload_dir.iterdir()) == []


def test_advanced_sha256_covers_final_decrypted_payload(
    upload_server: UploadServer,
    upload_dir: Path,
) -> None:
    """Catches diagnostics hashing the encoded or encrypted envelope."""
    from xferry.security.crypto import xor_encrypt

    plaintext = b"final plaintext"
    key = "key"
    encrypted = xor_encrypt(plaintext, key)

    response = upload_server.handle_advanced_upload(
        _bind_advanced_session_dispatch(
            make_request(
                "POST",
                "/advanced",
                headers={"Content-Type": "application/json"},
                body=_canonical_json_payload(
                    encrypted,
                    encryption="xor",
                    key=key,
                    name="decrypted.bin",
                ),
            ),
            decoder="json",
        )
    )
    result = _json(response)

    assert response.status_code == 201
    assert (upload_dir / "decrypted.bin").read_bytes() == plaintext
    assert result["upload"]["payload_size"] == len(plaintext)
    assert result["upload"]["request_body_size"] > len(encrypted)
    assert result["file"]["sha256"] == hashlib.sha256(plaintext).hexdigest()


def test_core_dispatch_does_not_publish_advanced_diagnostic_headers(
    upload_server: UploadServer,
    upload_dir: Path,
) -> None:
    """Catches a Basic handler publishing Advanced-only diagnostic headers."""
    selected_handler = upload_server.method_handlers["POST"]

    def delegate_to_selected_handler(request):
        return selected_handler(request)

    upload_server.method_handlers.register("POST", delegate_to_selected_handler)

    response = upload_server._dispatch_handler(
        make_request(
            "POST",
            "/uploads/core-dispatch.bin",
            headers={"Content-Type": "application/octet-stream"},
            body=b"core dispatch",
        )
    )
    result = _json(response)

    assert response.status_code == 201
    assert (upload_dir / "core-dispatch.bin").read_bytes() == b"core dispatch"
    assert result["upload"]["profile"] == "raw_url"
    assert result["upload"]["normalized_name"] == "core-dispatch.bin"
    assert MIRROR_HEADERS.isdisjoint(response.headers)
