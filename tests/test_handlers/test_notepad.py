"""Tests for the Secure Notepad (NOTE method) handler."""

import base64
import json
import logging
import threading
from pathlib import Path

import pytest

from tests.conftest import make_request
from xferry.handlers import HandlerMixin
from xferry.notepad_service import NotepadServiceError, NoteStoragePolicy, max_note_data_b64_chars
from xferry.security.keys import HAS_ECDH, ECDHKeyManager, session_fingerprint

_VALID_ENCRYPTED_BLOB = b"n" * 12 + b"t" * 16


class NotepadStubServer(HandlerMixin):
    """Minimal concrete class with all handler mixins for notepad testing."""

    def __init__(self, root_dir: Path, upload_dir: Path, **kwargs):
        self.root_dir = root_dir
        self.upload_dir = upload_dir
        self.notes_dir = root_dir / "notes"
        self.notes_dir.mkdir(exist_ok=True)
        self.sandbox_mode = kwargs.get("sandbox", False)
        self.opsec_mode = kwargs.get("opsec", False)
        self._temp_smuggle_files: set[str] = set()
        self._smuggle_lock = threading.Lock()
        self._notes_lock = threading.Lock()

        # ECDH key manager (v2)
        self._ecdh_manager = None
        if HAS_ECDH:
            self._ecdh_manager = ECDHKeyManager()
        self.method_handlers = self.build_method_handlers()


@pytest.fixture
def server(temp_dir, upload_dir):
    return NotepadStubServer(temp_dir, upload_dir)


def _make_note_payload(
    title: str = "Test Note",
    data: bytes = _VALID_ENCRYPTED_BLOB,
    note_id: str = "",
    create_if_missing: bool = False,
    session_id: str | None = None,
) -> bytes:
    """Build a NOTE save payload."""
    payload: dict = {
        "title": title,
        "data": base64.b64encode(data).decode(),
    }
    if note_id:
        payload["id"] = note_id
    if create_if_missing:
        payload["create_if_missing"] = True
    if session_id is not None:
        payload["session_id"] = session_id
    return json.dumps(payload).encode()


def _response_json(response) -> dict[str, object]:
    """Decode a JSON response object for exact HTTP contract assertions."""
    payload = json.loads(response.body)
    assert isinstance(payload, dict)
    return payload


def _assert_note_metadata(
    value: object,
    *,
    title: str,
    size_bytes: int,
    note_id: str | None = None,
) -> dict[str, object]:
    """Assert the canonical NOTE HTTP metadata object and return it."""
    assert isinstance(value, dict)
    assert set(value) == {
        "id",
        "title",
        "created_at",
        "updated_at",
        "size_bytes",
    }
    assert isinstance(value["id"], str)
    assert len(value["id"]) == 32
    if note_id is not None:
        assert value["id"] == note_id
    assert value["title"] == title
    assert isinstance(value["created_at"], str)
    assert isinstance(value["updated_at"], str)
    assert value["size_bytes"] == size_bytes
    return value


def _assert_canonical_error(
    response,
    *,
    status: int,
    code: str,
    message: str,
    field: str | None,
    details: dict[str, object],
) -> None:
    """Assert the exact shared XFerry error envelope."""
    assert response.status_code == status
    assert _response_json(response) == {
        "error": {
            "code": code,
            "message": message,
            "field": field,
            "details": details,
        }
    }


@pytest.mark.skipif(not HAS_ECDH, reason="cryptography not installed")
class TestStage008CanonicalHTTPContract:
    @pytest.mark.parametrize(
        ("target", "field"),
        [
            ("/notes", "action"),
            ("/notes/", "path"),
            ("/notes?list", "list"),
            ("/notes?action=list&action=clear", "action"),
            ("/notes?action=list&extra=value", "extra"),
            ("/notes?%61ction=list", "action"),
            ("/notes?action=%6cist", "action"),
            ("/notes?xaction=list", "xaction"),
            ("/notes?action=load", "action"),
            ("/notes/key?extra=value", "extra"),
            ("/notes/exchange?action=list", "action"),
            ("/notes/key/", "path"),
            (f"/notes/{'a' * 32}", "action"),
            (f"/notes/{'a' * 32}?delete", "delete"),
            (f"/notes/{'a' * 32}?action=load&extra=value", "extra"),
        ],
    )
    def test_rejects_noncanonical_route_query_grammar(self, server, target, field):
        response = server.handle_note(make_request("NOTE", target))

        assert response.status_code == 400
        assert _response_json(response)["error"]["field"] == field

    def test_exchange_requires_snake_case_and_exact_keys(self, server):
        client = ECDHKeyManager()
        client_key = base64.b64encode(client.get_public_key_raw()).decode("ascii")

        accepted = server.handle_note(
            make_request(
                "NOTE",
                "/notes/exchange",
                body=json.dumps({"client_public_key": client_key}).encode(),
            )
        )
        legacy = server.handle_note(
            make_request(
                "NOTE",
                "/notes/exchange",
                body=json.dumps({"clientPublicKey": client_key}).encode(),
            )
        )
        extra = server.handle_note(
            make_request(
                "NOTE",
                "/notes/exchange",
                body=json.dumps({"client_public_key": client_key, "extra": True}).encode(),
            )
        )

        assert accepted.status_code == 200
        assert legacy.status_code == 400
        assert _response_json(legacy)["error"]["field"] == "clientPublicKey"
        assert extra.status_code == 400
        assert _response_json(extra)["error"]["field"] == "extra"

    @pytest.mark.parametrize("note_id", ["a", "A" * 32, "a" * 31, "a" * 33])
    def test_rejects_every_noncanonical_note_id(self, server, note_id):
        response = server.handle_note(make_request("NOTE", f"/notes/{note_id}?action=load"))

        assert response.status_code == 400
        assert _response_json(response)["error"]["field"] == "id"

    def test_save_rejects_title_instead_of_truncating(self, server):
        response = server.handle_note(
            make_request(
                "NOTE",
                "/notes?action=save",
                body=_make_note_payload("x" * 201, _VALID_ENCRYPTED_BLOB),
            )
        )

        assert response.status_code == 400
        assert _response_json(response)["error"]["field"] == "title"
        assert list(server.notes_dir.iterdir()) == []

    def test_save_accepts_exact_200_unicode_scalar_title_boundary(self, server):
        title = "🔒" * 200

        response = server.handle_note(
            make_request(
                "NOTE",
                "/notes?action=save",
                body=_make_note_payload(title, _VALID_ENCRYPTED_BLOB),
            )
        )

        assert response.status_code == 201
        assert _response_json(response)["note"]["title"] == title

    @pytest.mark.parametrize("blob_size", [0, 1, 27])
    def test_save_rejects_ciphertext_below_nonce_tag_minimum(
        self,
        server,
        blob_size,
    ):
        response = server.handle_note(
            make_request(
                "NOTE",
                "/notes?action=save",
                body=_make_note_payload("Too short", b"x" * blob_size),
            )
        )

        assert response.status_code == 400
        error = _response_json(response)["error"]
        assert error["code"] == ("empty_payload" if blob_size == 0 else "invalid_field")
        assert error["field"] == "data"
        assert list(server.notes_dir.iterdir()) == []

    def test_save_accepts_exact_snake_case_keys_and_ignores_unknown_session(self, server):
        note_id = "c" * 32
        response = server.handle_note(
            make_request(
                "NOTE",
                "/notes?action=save",
                body=json.dumps(
                    {
                        "title": "Canonical",
                        "data": base64.b64encode(_VALID_ENCRYPTED_BLOB).decode(),
                        "id": note_id,
                        "create_if_missing": True,
                        "session_id": "d" * 32,
                    }
                ).encode(),
            )
        )

        assert response.status_code == 201
        payload = _response_json(response)
        assert payload["note"]["id"] == note_id
        assert "session_id" not in json.dumps(payload)

    @pytest.mark.parametrize(
        ("field", "value"),
        [
            ("create_if_missing", "true"),
            ("session_id", "short"),
            ("session_id", None),
            ("id", "short"),
            ("extra", True),
            ("createIfMissing", True),
            ("sessionId", "a" * 32),
        ],
    )
    def test_save_rejects_invalid_types_legacy_names_and_extras(
        self,
        server,
        field,
        value,
    ):
        payload = {
            "title": "Invalid",
            "data": base64.b64encode(_VALID_ENCRYPTED_BLOB).decode(),
            field: value,
        }

        response = server.handle_note(
            make_request(
                "NOTE",
                "/notes?action=save",
                body=json.dumps(payload).encode(),
            )
        )

        assert response.status_code == 400
        assert _response_json(response)["error"]["field"] == field


# ── Canonical NOTE HTTP contract tests ───────────────────────────────


@pytest.mark.skipif(not HAS_ECDH, reason="cryptography not installed")
class TestCanonicalNotepadHTTPSuccess:
    def test_key_uses_exact_canonical_shape(self, server):
        response = server.handle_note(make_request("NOTE", "/notes/key"))

        assert response.status_code == 200
        data = _response_json(response)
        assert set(data) == {"key"}
        assert data["key"] == {
            "available": True,
            "algorithm": "ecdh_p256_hkdf_sha256_aes_256_gcm",
            "public_key": base64.b64encode(server._ecdh_manager.get_public_key_raw()).decode(
                "ascii"
            ),
            "public_key_encoding": "x9_62_uncompressed_base64",
        }

    def test_exchange_uses_exact_canonical_shape(self, server):
        client = ECDHKeyManager()
        client_public_key = base64.b64encode(client.get_public_key_raw()).decode("ascii")

        response = server.handle_note(
            make_request(
                "NOTE",
                "/notes/exchange",
                body=json.dumps({"client_public_key": client_public_key}).encode(),
            )
        )

        assert response.status_code == 200
        data = _response_json(response)
        assert set(data) == {"session", "server_public_key"}
        assert isinstance(data["session"], dict)
        assert set(data["session"]) == {"id", "ttl_seconds"}
        assert isinstance(data["session"]["id"], str)
        assert len(data["session"]["id"]) == 32
        assert data["session"]["ttl_seconds"] == 3600
        assert data["server_public_key"] == base64.b64encode(
            server._ecdh_manager.get_public_key_raw()
        ).decode("ascii")

    def test_create_uses_exact_canonical_shape(self, server):
        response = server.handle_note(
            make_request(
                "NOTE",
                "/notes?action=save",
                body=_make_note_payload("Created", _VALID_ENCRYPTED_BLOB),
            )
        )

        assert response.status_code == 201
        data = _response_json(response)
        assert set(data) == {"note", "created"}
        assert data["created"] is True
        _assert_note_metadata(data["note"], title="Created", size_bytes=28)

    def test_update_uses_exact_canonical_shape(self, server):
        created = _response_json(
            server.handle_note(
                make_request(
                    "NOTE",
                    "/notes?action=save",
                    body=_make_note_payload("Original", _VALID_ENCRYPTED_BLOB),
                )
            )
        )
        note_id = created["note"]["id"]

        response = server.handle_note(
            make_request(
                "NOTE",
                "/notes?action=save",
                body=_make_note_payload("Updated", b"u" * 28, note_id=str(note_id)),
            )
        )

        assert response.status_code == 200
        data = _response_json(response)
        assert set(data) == {"note", "created"}
        assert data["created"] is False
        _assert_note_metadata(
            data["note"],
            title="Updated",
            size_bytes=28,
            note_id=str(note_id),
        )

    def test_list_uses_exact_canonical_shape(self, server):
        server.note_storage_policy = NoteStoragePolicy(
            max_total_bytes=None,
            max_note_count=None,
            max_listed_notes=2,
        )
        created = _response_json(
            server.handle_note(
                make_request(
                    "NOTE",
                    "/notes?action=save",
                    body=_make_note_payload("Listed", _VALID_ENCRYPTED_BLOB),
                )
            )
        )

        response = server.handle_note(make_request("NOTE", "/notes?action=list"))

        assert response.status_code == 200
        data = _response_json(response)
        assert set(data) == {"notes", "page"}
        assert data["page"] == {
            "limit": 2,
            "returned_items": 1,
            "truncated": False,
        }
        assert isinstance(data["notes"], list)
        assert len(data["notes"]) == 1
        _assert_note_metadata(
            data["notes"][0],
            title="Listed",
            size_bytes=28,
            note_id=str(created["note"]["id"]),
        )

    def test_load_uses_exact_canonical_shape(self, server):
        created = _response_json(
            server.handle_note(
                make_request(
                    "NOTE",
                    "/notes?action=save",
                    body=_make_note_payload("Loaded", _VALID_ENCRYPTED_BLOB),
                )
            )
        )
        note_id = str(created["note"]["id"])

        response = server.handle_note(make_request("NOTE", f"/notes/{note_id}?action=load"))

        assert response.status_code == 200
        data = _response_json(response)
        assert set(data) == {"note", "data"}
        _assert_note_metadata(
            data["note"],
            title="Loaded",
            size_bytes=28,
            note_id=note_id,
        )
        assert data["data"] == base64.b64encode(_VALID_ENCRYPTED_BLOB).decode("ascii")

    def test_delete_uses_exact_canonical_shape(self, server):
        created = _response_json(
            server.handle_note(
                make_request(
                    "NOTE",
                    "/notes?action=save",
                    body=_make_note_payload("Deleted", _VALID_ENCRYPTED_BLOB),
                )
            )
        )
        note_id = str(created["note"]["id"])

        response = server.handle_note(make_request("NOTE", f"/notes/{note_id}?action=delete"))

        assert response.status_code == 200
        assert _response_json(response) == {"deleted_note": {"id": note_id}}

    def test_clear_uses_exact_canonical_shape(self, server):
        server.handle_note(
            make_request(
                "NOTE",
                "/notes?action=save",
                body=_make_note_payload("Cleared", _VALID_ENCRYPTED_BLOB),
            )
        )

        response = server.handle_note(make_request("NOTE", "/notes?action=clear"))

        assert response.status_code == 200
        assert _response_json(response) == {
            "cleared_notes": {
                "path": "/notes",
                "deleted_files": 2,
                "deleted_dirs": 0,
                "preserved": [],
            }
        }


class TestCanonicalNotepadHTTPErrors:
    @pytest.mark.parametrize(
        ("target", "body"),
        [
            ("/notes/key", b""),
            ("/notes/exchange", json.dumps({"client_public_key": "unused"}).encode()),
            ("/notes?action=list", b""),
            ("/notes?action=save", _make_note_payload()),
            ("/notes/" + ("a" * 32) + "?action=load", b""),
            ("/notes/" + ("a" * 32) + "?action=delete", b""),
            ("/notes?action=clear", b""),
        ],
    )
    def test_crypto_unavailable_uses_exact_canonical_error(
        self,
        temp_dir,
        upload_dir,
        target,
        body,
    ):
        server = NotepadStubServer(temp_dir, upload_dir)
        server._ecdh_manager = None

        response = server.handle_note(make_request("NOTE", target, body=body))

        _assert_canonical_error(
            response,
            status=501,
            code="feature_unavailable",
            message="Secure Notepad crypto is unavailable",
            field=None,
            details={"feature": "note", "dependency": "cryptography"},
        )

    @pytest.mark.parametrize("body", [b"not-json", b"\xff"])
    def test_malformed_save_json_uses_canonical_error(self, server, body):
        response = server.handle_note(make_request("NOTE", "/notes?action=save", body=body))

        _assert_canonical_error(
            response,
            status=400,
            code="malformed_json",
            message="Invalid JSON body",
            field=None,
            details={},
        )

    def test_non_object_exchange_json_uses_canonical_error(self, server):
        response = server.handle_note(make_request("NOTE", "/notes/exchange", body=b"[]"))

        _assert_canonical_error(
            response,
            status=400,
            code="invalid_json_type",
            message="Expected JSON object",
            field=None,
            details={"expected": "object"},
        )

    @pytest.mark.parametrize(
        ("payload", "field"),
        [({"data": "eA=="}, "title"), ({"title": "x"}, "data")],
    )
    def test_missing_save_field_uses_canonical_error(self, server, payload, field):
        response = server.handle_note(
            make_request("NOTE", "/notes?action=save", body=json.dumps(payload).encode())
        )

        _assert_canonical_error(
            response,
            status=400,
            code="missing_field",
            message="Missing required field",
            field=field,
            details={},
        )

    def test_invalid_save_data_uses_canonical_error(self, server):
        response = server.handle_note(
            make_request(
                "NOTE",
                "/notes?action=save",
                body=json.dumps({"title": "Bad", "data": "not-base64!"}).encode(),
            )
        )

        _assert_canonical_error(
            response,
            status=400,
            code="invalid_field",
            message="Invalid base64 in 'data'",
            field="data",
            details={"encoding": "base64"},
        )

    def test_invalid_note_id_uses_canonical_error(self, server):
        response = server.handle_note(make_request("NOTE", "/notes/not-hex"))

        _assert_canonical_error(
            response,
            status=400,
            code="invalid_field",
            message="Invalid note ID",
            field="id",
            details={"format": "32 lowercase hexadecimal characters"},
        )

    def test_invalid_notepad_path_uses_canonical_error(self, server):
        response = server.handle_note(make_request("NOTE", "/other/path"))

        _assert_canonical_error(
            response,
            status=400,
            code="invalid_path",
            message="Invalid notepad path",
            field="path",
            details={"access_scope": "notes"},
        )

    def test_missing_note_uses_canonical_error(self, server):
        response = server.handle_note(make_request("NOTE", "/notes/" + ("a" * 32) + "?action=load"))

        _assert_canonical_error(
            response,
            status=404,
            code="resource_not_found",
            message="Note not found",
            field="id",
            details={"resource": "note"},
        )

    def test_payload_too_large_uses_canonical_error(self, server, monkeypatch):
        monkeypatch.setattr("xferry.notepad_service.MAX_NOTE_ENCRYPTED_BLOB_BYTES", 28)

        response = server.handle_note(
            make_request(
                "NOTE",
                "/notes?action=save",
                body=_make_note_payload("Too Large", b"x" * 29),
            )
        )

        assert response.status_code == 413
        error = _response_json(response)["error"]
        assert error["code"] == "payload_too_large"
        assert error["field"] == "data"
        assert error["details"] == {
            "scope": "note",
            "limit_bytes": 28,
            "actual_bytes": 29,
        }
        assert "28 bytes" in error["message"]

    def test_storage_quota_uses_canonical_error(self, server):
        server.note_storage_policy = NoteStoragePolicy(
            max_total_bytes=4,
            max_note_count=10,
            max_listed_notes=10,
        )

        response = server.handle_note(
            make_request(
                "NOTE",
                "/notes?action=save",
                body=_make_note_payload("Too Large", _VALID_ENCRYPTED_BLOB),
            )
        )

        _assert_canonical_error(
            response,
            status=507,
            code="storage_quota_exceeded",
            message="Notepad storage quota exceeded",
            field="data",
            details={"scope": "notes", "reason": "bytes"},
        )

    def test_clear_failure_uses_canonical_error(self, server, monkeypatch):
        service = server._get_notepad_service()

        def fail_clear():
            raise NotepadServiceError(
                500,
                "Failed to clear notes",
                code="clear_failed",
                details={
                    "path": "/notes",
                    "deleted_files": 1,
                    "deleted_dirs": 0,
                    "preserved": [".gitkeep"],
                    "failures": [{"name": "locked.enc", "reason": "permission_denied"}],
                },
            )

        monkeypatch.setattr(service, "clear_notes", fail_clear)

        response = server.handle_note(make_request("NOTE", "/notes?action=clear"))

        _assert_canonical_error(
            response,
            status=500,
            code="clear_failed",
            message="Failed to clear notes",
            field=None,
            details={
                "path": "/notes",
                "deleted_files": 1,
                "deleted_dirs": 0,
                "preserved": [".gitkeep"],
                "failures": [{"name": "locked.enc", "reason": "permission_denied"}],
            },
        )


# ── Save tests ─────────────────────────────────────────────────────


class TestNotepadSave:
    def test_create_new_note(self, server):
        body = _make_note_payload("My Note", b"\x01salt1234567890xxnonce12bytesciphertext_tag16")
        req = make_request("NOTE", "/notes?action=save", body=body)
        resp = server.handle_note(req)
        assert resp.status_code == 201
        data = json.loads(resp.body)
        assert data["created"] is True
        assert len(data["note"]["id"]) == 32
        assert data["note"]["title"] == "My Note"

    def test_update_existing_note(self, server):
        # Create first
        body = _make_note_payload("Original")
        req = make_request("NOTE", "/notes?action=save", body=body)
        resp = server.handle_note(req)
        note_id = json.loads(resp.body)["note"]["id"]

        # Update
        body = _make_note_payload("Updated", b"u" * 28, note_id=note_id)
        req = make_request("NOTE", "/notes?action=save", body=body)
        resp = server.handle_note(req)
        assert resp.status_code == 200
        data = json.loads(resp.body)
        assert data["created"] is False
        assert data["note"]["id"] == note_id
        assert data["note"]["title"] == "Updated"

    def test_update_nonexistent_note_returns_404(self, server):
        body = _make_note_payload("Ghost", note_id="a" * 32)
        req = make_request("NOTE", "/notes?action=save", body=body)
        resp = server.handle_note(req)
        assert resp.status_code == 404

    def test_create_if_missing_with_client_note_id_is_idempotent(self, server):
        note_id = "b" * 32
        body = _make_note_payload(
            "Client ID",
            b"f" * 28,
            note_id=note_id,
            create_if_missing=True,
        )
        resp = server.handle_note(make_request("NOTE", "/notes?action=save", body=body))
        assert resp.status_code == 201
        data = json.loads(resp.body)
        assert data["created"] is True
        assert data["note"]["id"] == note_id

        retry_body = _make_note_payload(
            "Client ID Retry",
            b"r" * 28,
            note_id=note_id,
            create_if_missing=True,
        )
        retry_resp = server.handle_note(make_request("NOTE", "/notes?action=save", body=retry_body))
        assert retry_resp.status_code == 200
        retry_data = json.loads(retry_resp.body)
        assert retry_data["created"] is False
        assert retry_data["note"]["id"] == note_id
        assert retry_data["note"]["title"] == "Client ID Retry"

        notes_dir = server.notes_dir
        assert [path.name for path in notes_dir.glob("*.enc")] == [f"{note_id}.enc"]
        assert (notes_dir / f"{note_id}.enc").read_bytes() == b"r" * 28

    def test_save_empty_body_returns_400(self, server):
        req = make_request("NOTE", "/notes?action=save")
        resp = server.handle_note(req)
        assert resp.status_code == 400
        assert json.loads(resp.body)["error"]["code"] == "malformed_json"

    def test_save_invalid_json_returns_400(self, server):
        req = make_request("NOTE", "/notes?action=save", body=b"not json{{{")
        resp = server.handle_note(req)
        assert resp.status_code == 400

    def test_save_json_array_returns_400(self, server):
        req = make_request("NOTE", "/notes?action=save", body=b"[]")
        resp = server.handle_note(req)
        assert resp.status_code == 400

    def test_save_missing_title_returns_400(self, server):
        payload = json.dumps({"data": base64.b64encode(b"x").decode()}).encode()
        req = make_request("NOTE", "/notes?action=save", body=payload)
        resp = server.handle_note(req)
        assert resp.status_code == 400

    def test_save_missing_data_returns_400(self, server):
        payload = json.dumps({"title": "No Data"}).encode()
        req = make_request("NOTE", "/notes?action=save", body=payload)
        resp = server.handle_note(req)
        assert resp.status_code == 400

    def test_save_invalid_base64_returns_400(self, server):
        payload = json.dumps({"title": "Bad", "data": "not!!!base64"}).encode()
        req = make_request("NOTE", "/notes?action=save", body=payload)
        resp = server.handle_note(req)
        assert resp.status_code == 400

    def test_save_empty_encrypted_data_returns_400(self, server):
        payload = json.dumps({"title": "Empty", "data": base64.b64encode(b"").decode()}).encode()
        req = make_request("NOTE", "/notes?action=save", body=payload)
        resp = server.handle_note(req)
        assert resp.status_code == 400

    def test_save_rejects_oversized_encoded_data(self, server, monkeypatch):
        monkeypatch.setattr("xferry.notepad_service.MAX_NOTE_ENCRYPTED_BLOB_BYTES", 28)
        encoded_limit = max_note_data_b64_chars()
        payload = json.dumps(
            {
                "title": "Too Large",
                "data": "A" * (encoded_limit + 4),
            }
        ).encode()

        resp = server.handle_note(make_request("NOTE", "/notes?action=save", body=payload))

        assert resp.status_code == 413
        data = json.loads(resp.body)
        assert data["error"]["code"] == "payload_too_large"
        assert "Encrypted note data exceeds" in data["error"]["message"]
        assert list(server.notes_dir.iterdir()) == []

    def test_save_rejects_oversized_decoded_data_without_writing(self, server, monkeypatch):
        monkeypatch.setattr("xferry.notepad_service.MAX_NOTE_ENCRYPTED_BLOB_BYTES", 28)
        body = _make_note_payload("Too Large", b"x" * 29)

        resp = server.handle_note(make_request("NOTE", "/notes?action=save", body=body))

        assert resp.status_code == 413
        data = json.loads(resp.body)
        assert data["error"]["code"] == "payload_too_large"
        assert "28 bytes" in data["error"]["message"]
        assert list(server.notes_dir.iterdir()) == []

    def test_update_rejects_oversized_decoded_data_without_replacing_existing_note(
        self,
        server,
        monkeypatch,
    ):
        create = server.handle_note(
            make_request(
                "NOTE",
                "/notes?action=save",
                body=_make_note_payload("Original", _VALID_ENCRYPTED_BLOB),
            )
        )
        note_id = json.loads(create.body)["note"]["id"]
        enc_path = server.notes_dir / f"{note_id}.enc"
        meta_path = server.notes_dir / f"{note_id}.meta.json"
        original_meta = meta_path.read_text(encoding="utf-8")

        monkeypatch.setattr("xferry.notepad_service.MAX_NOTE_ENCRYPTED_BLOB_BYTES", 28)
        update = _make_note_payload("Too Large", b"x" * 29, note_id=note_id)

        resp = server.handle_note(make_request("NOTE", "/notes?action=save", body=update))

        assert resp.status_code == 413
        assert enc_path.read_bytes() == _VALID_ENCRYPTED_BLOB
        assert meta_path.read_text(encoding="utf-8") == original_meta

    def test_save_boundary_payload_can_load(self, server, monkeypatch):
        monkeypatch.setattr("xferry.notepad_service.MAX_NOTE_ENCRYPTED_BLOB_BYTES", 28)
        body = _make_note_payload("Boundary", _VALID_ENCRYPTED_BLOB)

        save_resp = server.handle_note(make_request("NOTE", "/notes?action=save", body=body))

        assert save_resp.status_code == 201
        saved = json.loads(save_resp.body)
        assert saved["note"]["size_bytes"] == 28

        load_resp = server.handle_note(
            make_request("NOTE", f"/notes/{saved['note']['id']}?action=load")
        )
        loaded = json.loads(load_resp.body)
        assert loaded["note"]["size_bytes"] == 28
        assert base64.b64decode(loaded["data"]) == _VALID_ENCRYPTED_BLOB

    def test_title_over_200_is_rejected(self, server):
        long_title = "x" * 300
        body = _make_note_payload(long_title)
        req = make_request("NOTE", "/notes?action=save", body=body)
        resp = server.handle_note(req)
        assert resp.status_code == 400
        assert json.loads(resp.body)["error"]["field"] == "title"
        assert list(server.notes_dir.iterdir()) == []

    def test_files_written_to_disk(self, server):
        body = _make_note_payload("Disk Test", _VALID_ENCRYPTED_BLOB)
        req = make_request("NOTE", "/notes?action=save", body=body)
        resp = server.handle_note(req)
        note_id = json.loads(resp.body)["note"]["id"]

        notes_dir = server.notes_dir
        enc_path = notes_dir / f"{note_id}.enc"
        meta_path = notes_dir / f"{note_id}.meta.json"
        assert enc_path.exists()
        assert meta_path.exists()
        assert enc_path.read_bytes() == _VALID_ENCRYPTED_BLOB
        assert not (server.upload_dir / "notes").exists()

        meta = json.loads(meta_path.read_text())
        assert meta["title"] == "Disk Test"

    def test_failed_update_keeps_existing_ciphertext_metadata_pair(self, server, monkeypatch):
        body = _make_note_payload("Original", b"o" * 28)
        resp = server.handle_note(make_request("NOTE", "/notes?action=save", body=body))
        note_id = json.loads(resp.body)["note"]["id"]
        enc_path = server.notes_dir / f"{note_id}.enc"
        meta_path = server.notes_dir / f"{note_id}.meta.json"
        original_meta = meta_path.read_text(encoding="utf-8")

        original_replace = Path.replace

        def fail_new_metadata_replace(self: Path, target: Path) -> Path:
            if Path(target) == meta_path and ".meta." in self.name and ".backup." not in self.name:
                raise OSError("injected metadata replacement failure")
            return original_replace(self, target)

        monkeypatch.setattr(Path, "replace", fail_new_metadata_replace)

        update = _make_note_payload("Updated", b"u" * 28, note_id=note_id)
        failed = server.handle_note(make_request("NOTE", "/notes?action=save", body=update))

        assert failed.status_code == 500
        assert enc_path.read_bytes() == b"o" * 28
        assert meta_path.read_text(encoding="utf-8") == original_meta
        assert sorted(path.name for path in server.notes_dir.iterdir()) == [
            f"{note_id}.enc",
            f"{note_id}.meta.json",
        ]

    def test_failed_create_does_not_leave_ciphertext_without_metadata(
        self,
        server,
        monkeypatch,
    ):
        note_id = "d" * 32
        enc_path = server.notes_dir / f"{note_id}.enc"
        meta_path = server.notes_dir / f"{note_id}.meta.json"
        original_replace = Path.replace

        def fail_new_metadata_replace(self: Path, target: Path) -> Path:
            if Path(target) == meta_path and ".meta." in self.name:
                raise OSError("injected metadata replacement failure")
            return original_replace(self, target)

        monkeypatch.setattr(Path, "replace", fail_new_metadata_replace)

        body = _make_note_payload(
            "New Note",
            b"n" * 28,
            note_id=note_id,
            create_if_missing=True,
        )
        failed = server.handle_note(make_request("NOTE", "/notes?action=save", body=body))

        assert failed.status_code == 500
        assert not enc_path.exists()
        assert not meta_path.exists()
        assert list(server.notes_dir.iterdir()) == []

    def test_create_rejects_note_count_quota_without_partial_state(self, server):
        server.note_storage_policy = NoteStoragePolicy(
            max_total_bytes=None,
            max_note_count=1,
            max_listed_notes=1,
        )
        first = server.handle_note(
            make_request(
                "NOTE",
                "/notes?action=save",
                body=_make_note_payload("First", b"f" * 28),
            )
        )
        first_id = json.loads(first.body)["note"]["id"]

        second = server.handle_note(
            make_request(
                "NOTE",
                "/notes?action=save",
                body=_make_note_payload("Second", b"s" * 28),
            )
        )

        assert second.status_code == 507
        data = json.loads(second.body)
        assert data["error"] == {
            "code": "storage_quota_exceeded",
            "message": "Notepad storage quota exceeded",
            "field": "data",
            "details": {"scope": "notes", "reason": "notes"},
        }
        assert sorted(path.name for path in server.notes_dir.iterdir()) == [
            f"{first_id}.enc",
            f"{first_id}.meta.json",
        ]

    def test_create_rejects_note_byte_quota_without_partial_state(self, server):
        server.note_storage_policy = NoteStoragePolicy(
            max_total_bytes=27,
            max_note_count=10,
            max_listed_notes=10,
        )

        response = server.handle_note(
            make_request(
                "NOTE",
                "/notes?action=save",
                body=_make_note_payload("Too Large", _VALID_ENCRYPTED_BLOB),
            )
        )

        assert response.status_code == 507
        data = json.loads(response.body)
        assert data["error"] == {
            "code": "storage_quota_exceeded",
            "message": "Notepad storage quota exceeded",
            "field": "data",
            "details": {"scope": "notes", "reason": "bytes"},
        }
        assert list(server.notes_dir.iterdir()) == []

    def test_update_rejects_note_byte_quota_without_replacing_existing_note(self, server):
        server.note_storage_policy = NoteStoragePolicy(
            max_total_bytes=28,
            max_note_count=10,
            max_listed_notes=10,
        )
        created = server.handle_note(
            make_request(
                "NOTE",
                "/notes?action=save",
                body=_make_note_payload("Original", _VALID_ENCRYPTED_BLOB),
            )
        )
        note_id = json.loads(created.body)["note"]["id"]
        enc_path = server.notes_dir / f"{note_id}.enc"
        meta_path = server.notes_dir / f"{note_id}.meta.json"
        original_meta = meta_path.read_text(encoding="utf-8")

        response = server.handle_note(
            make_request(
                "NOTE",
                "/notes?action=save",
                body=_make_note_payload("Too Large", b"x" * 29, note_id=note_id),
            )
        )

        assert response.status_code == 507
        assert enc_path.read_bytes() == _VALID_ENCRYPTED_BLOB
        assert meta_path.read_text(encoding="utf-8") == original_meta


# ── List tests ─────────────────────────────────────────────────────


class TestNotepadList:
    def test_list_empty(self, server):
        req = make_request("NOTE", "/notes?action=list")
        resp = server.handle_note(req)
        assert resp.status_code == 200
        data = json.loads(resp.body)
        assert data["notes"] == []
        assert data["page"]["returned_items"] == 0

    def test_list_returns_notes_sorted_by_updated(self, server):
        # Create two notes
        body1 = _make_note_payload("First")
        req1 = make_request("NOTE", "/notes?action=save", body=body1)
        resp1 = server.handle_note(req1)
        json.loads(resp1.body)["note"]["id"]

        body2 = _make_note_payload("Second")
        req2 = make_request("NOTE", "/notes?action=save", body=body2)
        server.handle_note(req2)

        req = make_request("NOTE", "/notes?action=list")
        resp = server.handle_note(req)
        data = json.loads(resp.body)
        assert data["page"]["returned_items"] == 2
        # Most recent first
        titles = [n["title"] for n in data["notes"]]
        assert titles[0] == "Second"

    def test_collection_without_action_is_rejected(self, server):
        req = make_request("NOTE", "/notes")
        resp = server.handle_note(req)
        assert resp.status_code == 400
        assert json.loads(resp.body)["error"]["field"] == "action"

    def test_list_is_bounded_by_policy_limit(self, server, monkeypatch):
        server.note_storage_policy = NoteStoragePolicy(
            max_total_bytes=None,
            max_note_count=None,
            max_listed_notes=2,
        )
        for suffix in ("a", "b", "c"):
            note_id = suffix * 32
            (server.notes_dir / f"{note_id}.enc").write_bytes(suffix.encode())

        service = server._get_notepad_service()
        original_note_record = service._note_record
        note_record_calls: list[str] = []

        def tracked_note_record(note_id: str, enc_path: Path):
            note_record_calls.append(note_id)
            if len(note_record_calls) > 2:
                pytest.fail("bounded list should not build summaries past the limit")
            return original_note_record(note_id, enc_path)

        monkeypatch.setattr(service, "_note_record", tracked_note_record)

        resp = server.handle_note(make_request("NOTE", "/notes?action=list"))

        assert resp.status_code == 200
        data = json.loads(resp.body)
        assert data["page"] == {
            "limit": 2,
            "returned_items": 2,
            "truncated": True,
        }
        assert len(note_record_calls) == 2


# ── Load tests ─────────────────────────────────────────────────────


class TestNotepadLoad:
    def test_load_existing_note(self, server):
        body = _make_note_payload("Load Me", _VALID_ENCRYPTED_BLOB)
        req = make_request("NOTE", "/notes?action=save", body=body)
        resp = server.handle_note(req)
        note_id = json.loads(resp.body)["note"]["id"]

        req = make_request("NOTE", f"/notes/{note_id}?action=load")
        resp = server.handle_note(req)
        assert resp.status_code == 200
        data = json.loads(resp.body)
        assert data["note"]["id"] == note_id
        assert data["note"]["title"] == "Load Me"
        # Verify data round-trips through base64
        assert base64.b64decode(data["data"]) == _VALID_ENCRYPTED_BLOB

    def test_load_missing_returns_404(self, server):
        req = make_request("NOTE", "/notes/deadbeef12345678deadbeef12345678?action=load")
        resp = server.handle_note(req)
        assert resp.status_code == 404


# ── Delete tests ───────────────────────────────────────────────────


class TestNotepadDelete:
    def test_delete_existing_note(self, server):
        body = _make_note_payload("Delete Me")
        req = make_request("NOTE", "/notes?action=save", body=body)
        resp = server.handle_note(req)
        note_id = json.loads(resp.body)["note"]["id"]

        req = make_request("NOTE", f"/notes/{note_id}?action=delete")
        resp = server.handle_note(req)
        assert resp.status_code == 200
        data = json.loads(resp.body)
        assert data == {"deleted_note": {"id": note_id}}

        # Files should be gone
        notes_dir = server.notes_dir
        assert not (notes_dir / f"{note_id}.enc").exists()
        assert not (notes_dir / f"{note_id}.meta.json").exists()

    def test_delete_missing_returns_404(self, server):
        req = make_request("NOTE", "/notes/deadbeef12345678deadbeef12345678?action=delete")
        resp = server.handle_note(req)
        assert resp.status_code == 404

    def test_delete_removes_from_list(self, server):
        body = _make_note_payload("Temporary")
        req = make_request("NOTE", "/notes?action=save", body=body)
        resp = server.handle_note(req)
        note_id = json.loads(resp.body)["note"]["id"]

        # Delete
        req = make_request("NOTE", f"/notes/{note_id}?action=delete")
        server.handle_note(req)

        # List should be empty
        req = make_request("NOTE", "/notes?action=list")
        resp = server.handle_note(req)
        data = json.loads(resp.body)
        assert data["page"]["returned_items"] == 0


class TestNotepadClear:
    def test_clear_notes_removes_notes_without_touching_uploads(self, server):
        upload_file = server.upload_dir / "download.txt"
        upload_file.write_text("keep", encoding="utf-8")

        first = server.handle_note(
            make_request(
                "NOTE",
                "/notes?action=save",
                body=_make_note_payload("First", b"f" * 28),
            )
        )
        second = server.handle_note(
            make_request(
                "NOTE",
                "/notes?action=save",
                body=_make_note_payload("Second", b"s" * 28),
            )
        )
        assert json.loads(first.body)["created"] is True
        assert json.loads(second.body)["created"] is True

        req = make_request("NOTE", "/notes?action=clear")
        resp = server.handle_note(req)

        assert resp.status_code == 200
        data = json.loads(resp.body)
        assert data["cleared_notes"] == {
            "path": "/notes",
            "deleted_files": 4,
            "deleted_dirs": 0,
            "preserved": [],
        }
        assert upload_file.exists()
        assert list(server.notes_dir.iterdir()) == []

        list_resp = server.handle_note(make_request("NOTE", "/notes?action=list"))
        assert json.loads(list_resp.body)["page"]["returned_items"] == 0

    def test_clear_notes_preserves_hidden_files(self, server):
        hidden = server.notes_dir / ".gitkeep"
        hidden.write_text("", encoding="utf-8")
        visible = server.notes_dir / "visible.tmp"
        visible.write_text("remove", encoding="utf-8")

        resp = server.handle_note(make_request("NOTE", "/notes?action=clear"))

        assert resp.status_code == 200
        data = json.loads(resp.body)
        assert data["cleared_notes"]["deleted_files"] == 1
        assert data["cleared_notes"]["preserved"] == [".gitkeep"]
        assert hidden.exists()
        assert not visible.exists()

    def test_partial_clear_failure_preserves_counters_and_bounded_reason(
        self,
        server,
        monkeypatch,
    ):
        removable = server.notes_dir / "deleted.enc"
        locked = server.notes_dir / "locked.enc"
        hidden = server.notes_dir / ".gitkeep"
        removable.write_bytes(_VALID_ENCRYPTED_BLOB)
        locked.write_bytes(_VALID_ENCRYPTED_BLOB)
        hidden.write_text("", encoding="utf-8")
        original_unlink = Path.unlink

        def guarded_unlink(path: Path, *args, **kwargs):
            if path == locked:
                raise PermissionError("secret OS detail")
            return original_unlink(path, *args, **kwargs)

        monkeypatch.setattr(Path, "unlink", guarded_unlink)

        response = server.handle_note(make_request("NOTE", "/notes?action=clear"))

        _assert_canonical_error(
            response,
            status=500,
            code="clear_failed",
            message="Failed to clear notes",
            field=None,
            details={
                "path": "/notes",
                "deleted_files": 1,
                "deleted_dirs": 0,
                "preserved": [".gitkeep"],
                "failures": [{"name": "locked.enc", "reason": "permission_denied"}],
            },
        )
        assert not removable.exists()
        assert locked.exists()
        assert "secret OS detail" not in response.body.decode("utf-8")


# ── Security tests ─────────────────────────────────────────────────


class TestNotepadSecurity:
    def test_invalid_hex_id_rejected(self, server):
        req = make_request("NOTE", "/notes/not-hex-at-all!!")
        resp = server.handle_note(req)
        assert resp.status_code == 400

    def test_path_traversal_in_id_rejected(self, server):
        req = make_request("NOTE", "/notes/../../etc/passwd")
        resp = server.handle_note(req)
        assert resp.status_code == 400

    def test_too_long_id_rejected(self, server):
        long_id = "a" * 33  # max 32
        req = make_request("NOTE", f"/notes/{long_id}")
        resp = server.handle_note(req)
        assert resp.status_code == 400

    def test_traversal_in_save_id_rejected(self, server):
        payload = json.dumps(
            {
                "id": "../../../etc/passwd",
                "title": "Evil",
                "data": base64.b64encode(b"x").decode(),
            }
        ).encode()
        req = make_request("NOTE", "/notes?action=save", body=payload)
        resp = server.handle_note(req)
        assert resp.status_code == 400

    def test_invalid_path_returns_400(self, server):
        req = make_request("NOTE", "/other/path")
        resp = server.handle_note(req)
        assert resp.status_code == 400


# ── ECDH key exchange tests ───────────────────────────────────────


@pytest.mark.skipif(not HAS_ECDH, reason="cryptography not installed")
class TestECDHKeyExchange:
    def test_get_key_returns_public_key(self, server):
        req = make_request("NOTE", "/notes/key")
        resp = server.handle_note(req)
        assert resp.status_code == 200
        data = json.loads(resp.body)
        assert data["key"]["available"] is True
        raw = base64.b64decode(data["key"]["public_key"])
        assert len(raw) == 65
        assert raw[0] == 0x04  # uncompressed point

    def test_get_key_stable(self, server):
        """Same server returns same public key."""
        req1 = make_request("NOTE", "/notes/key")
        resp1 = server.handle_note(req1)
        req2 = make_request("NOTE", "/notes/key")
        resp2 = server.handle_note(req2)
        assert (
            json.loads(resp1.body)["key"]["public_key"]
            == json.loads(resp2.body)["key"]["public_key"]
        )

    def test_exchange_returns_session_id(self, server):
        # Generate a client key
        client = ECDHKeyManager()
        client_pub_b64 = base64.b64encode(client.get_public_key_raw()).decode()

        body = json.dumps({"client_public_key": client_pub_b64}).encode()
        req = make_request("NOTE", "/notes/exchange", body=body)
        resp = server.handle_note(req)
        assert resp.status_code == 200
        data = json.loads(resp.body)
        assert len(data["session"]["id"]) == 32
        assert data["session"]["ttl_seconds"] == 3600
        assert "server_public_key" in data

    def test_exchange_missing_key_returns_400(self, server):
        body = json.dumps({}).encode()
        req = make_request("NOTE", "/notes/exchange", body=body)
        resp = server.handle_note(req)
        assert resp.status_code == 400

    def test_exchange_invalid_key_length_returns_400(self, server):
        body = json.dumps(
            {
                "client_public_key": base64.b64encode(b"tooshort").decode(),
            }
        ).encode()
        req = make_request("NOTE", "/notes/exchange", body=body)
        resp = server.handle_note(req)
        assert resp.status_code == 400

    def test_exchange_invalid_json_returns_400(self, server):
        req = make_request("NOTE", "/notes/exchange", body=b"not json")
        resp = server.handle_note(req)
        assert resp.status_code == 400

    def test_exchange_json_array_returns_400(self, server):
        req = make_request("NOTE", "/notes/exchange", body=b"[]")
        resp = server.handle_note(req)
        assert resp.status_code == 400

    def test_exchange_no_body_returns_400(self, server):
        req = make_request("NOTE", "/notes/exchange")
        resp = server.handle_note(req)
        # Empty body → JSON decode error
        assert resp.status_code == 400


class TestECDHKeyExchangeNoEcdh:
    def test_get_key_without_ecdh_manager(self, temp_dir, upload_dir):
        """Server without ECDH manager reports canonical feature unavailability."""
        srv = NotepadStubServer(temp_dir, upload_dir)
        srv._ecdh_manager = None

        req = make_request("NOTE", "/notes/key")
        resp = srv.handle_note(req)
        _assert_canonical_error(
            resp,
            status=501,
            code="feature_unavailable",
            message="Secure Notepad crypto is unavailable",
            field=None,
            details={"feature": "note", "dependency": "cryptography"},
        )

    def test_exchange_without_ecdh_manager(self, temp_dir, upload_dir):
        """Server without ECDH manager returns 501."""
        srv = NotepadStubServer(temp_dir, upload_dir)
        srv._ecdh_manager = None

        body = json.dumps({"client_public_key": "anything"}).encode()
        req = make_request("NOTE", "/notes/exchange", body=body)
        resp = srv.handle_note(req)
        assert resp.status_code == 501


class TestNotepadRequiresCrypto:
    def test_list_without_ecdh_manager_returns_501(self, temp_dir, upload_dir):
        srv = NotepadStubServer(temp_dir, upload_dir)
        srv._ecdh_manager = None

        req = make_request("NOTE", "/notes?action=list")
        resp = srv.handle_note(req)

        assert resp.status_code == 501

    def test_save_without_ecdh_manager_returns_501(self, temp_dir, upload_dir):
        srv = NotepadStubServer(temp_dir, upload_dir)
        srv._ecdh_manager = None

        req = make_request("NOTE", "/notes?action=save", body=_make_note_payload())
        resp = srv.handle_note(req)

        assert resp.status_code == 501

    def test_load_without_ecdh_manager_returns_501(self, temp_dir, upload_dir):
        srv = NotepadStubServer(temp_dir, upload_dir)
        srv._ecdh_manager = None

        req = make_request("NOTE", "/notes/" + ("a" * 32) + "?action=load")
        resp = srv.handle_note(req)

        assert resp.status_code == 501

    def test_delete_without_ecdh_manager_returns_501(self, temp_dir, upload_dir):
        srv = NotepadStubServer(temp_dir, upload_dir)
        srv._ecdh_manager = None

        req = make_request("NOTE", "/notes/" + ("a" * 32) + "?action=delete")
        resp = srv.handle_note(req)

        assert resp.status_code == 501

    def test_clear_without_ecdh_manager_returns_501(self, temp_dir, upload_dir):
        srv = NotepadStubServer(temp_dir, upload_dir)
        srv._ecdh_manager = None

        req = make_request("NOTE", "/notes?action=clear")
        resp = srv.handle_note(req)

        assert resp.status_code == 501


# ── Save with session header tests ────────────────────────────────


@pytest.mark.skipif(not HAS_ECDH, reason="cryptography not installed")
class TestNotepadSaveWithSession:
    def test_save_with_session_id_body_field(self, server):
        """A live audit-only session body field marks metadata without being echoed."""
        # Set up a session
        client = ECDHKeyManager()
        client_pub_b64 = base64.b64encode(client.get_public_key_raw()).decode()
        exchange_body = json.dumps({"client_public_key": client_pub_b64}).encode()
        exchange_req = make_request("NOTE", "/notes/exchange", body=exchange_body)
        exchange_resp = server.handle_note(exchange_req)
        session_id = json.loads(exchange_resp.body)["session"]["id"]

        body = _make_note_payload(
            "Session Note",
            _VALID_ENCRYPTED_BLOB,
            session_id=session_id,
        )
        req = make_request(
            "NOTE",
            "/notes?action=save",
            body=body,
        )
        resp = server.handle_note(req)
        assert resp.status_code == 201
        data = json.loads(resp.body)
        assert data["created"] is True

        # Verify meta has session flag
        notes_dir = server.notes_dir
        meta_path = notes_dir / f"{data['note']['id']}.meta.json"
        meta = json.loads(meta_path.read_text())
        assert meta.get("session") is True
        assert session_id not in json.dumps(data)

    def test_save_without_session_still_works(self, server):
        """Save without session header still works."""
        body = _make_note_payload("No Session", _VALID_ENCRYPTED_BLOB)
        req = make_request("NOTE", "/notes?action=save", body=body)
        resp = server.handle_note(req)
        assert resp.status_code == 201

    def test_save_with_unknown_session_body_field_is_ignored(self, server, caplog):
        caplog.set_level(logging.DEBUG, logger="xferry")
        unknown_session_id = "deadbeefdeadbeefdeadbeefdeadbeef"
        body = _make_note_payload(
            "Unknown Session",
            _VALID_ENCRYPTED_BLOB,
            session_id=unknown_session_id,
        )
        req = make_request(
            "NOTE",
            "/notes?action=save",
            body=body,
        )
        resp = server.handle_note(req)

        assert resp.status_code == 201
        data = json.loads(resp.body)

        notes_dir = server.notes_dir
        meta_path = notes_dir / f"{data['note']['id']}.meta.json"
        meta = json.loads(meta_path.read_text())
        assert "session" not in meta
        assert "Ignoring unknown or expired note session" in caplog.text
        assert session_fingerprint(unknown_session_id) in caplog.text
        assert unknown_session_id not in caplog.text

    def test_legacy_session_header_is_not_an_alias(self, server):
        body = _make_note_payload("Header Ignored", _VALID_ENCRYPTED_BLOB)
        response = server.handle_note(
            make_request(
                "NOTE",
                "/notes?action=save",
                body=body,
                headers={"X-Session-Id": "a" * 32},
            )
        )

        assert response.status_code == 201
        note_id = json.loads(response.body)["note"]["id"]
        metadata = json.loads(
            (server.notes_dir / f"{note_id}.meta.json").read_text(encoding="utf-8")
        )
        assert "session" not in metadata


class TestNotepadCorruptMetadata:
    def test_list_skips_non_object_metadata(self, server):
        notes_dir = server.notes_dir
        (notes_dir / "broken.meta.json").write_text("[]")

        req = make_request("NOTE", "/notes?action=list")
        resp = server.handle_note(req)

        assert resp.status_code == 200
        data = json.loads(resp.body)
        assert data["notes"] == []
        assert data["page"]["returned_items"] == 0

    def test_list_includes_note_when_metadata_is_corrupt(self, server):
        note_id = "b" * 32
        notes_dir = server.notes_dir
        (notes_dir / f"{note_id}.enc").write_bytes(b"ciphertext")
        (notes_dir / f"{note_id}.meta.json").write_text("[]")

        req = make_request("NOTE", "/notes?action=list")
        resp = server.handle_note(req)

        assert resp.status_code == 200
        data = json.loads(resp.body)
        assert data["page"]["returned_items"] == 1
        assert data["notes"][0]["id"] == note_id
        assert data["notes"][0]["title"] == ""
        assert data["notes"][0]["size_bytes"] == len(b"ciphertext")

    def test_load_with_non_object_metadata_falls_back(self, server):
        note_id = "a" * 32
        notes_dir = server.notes_dir
        (notes_dir / f"{note_id}.enc").write_bytes(b"ciphertext")
        (notes_dir / f"{note_id}.meta.json").write_text("[]")

        req = make_request("NOTE", f"/notes/{note_id}?action=load")
        resp = server.handle_note(req)

        assert resp.status_code == 200
        data = json.loads(resp.body)
        assert data["note"]["id"] == note_id
        assert data["note"]["title"] == ""

    def test_update_rewrites_corrupt_metadata_sidecar(self, server):
        note_id = "c" * 32
        notes_dir = server.notes_dir
        (notes_dir / f"{note_id}.enc").write_bytes(b"old")
        (notes_dir / f"{note_id}.meta.json").write_text("{not json")

        req = make_request(
            "NOTE",
            "/notes?action=save",
            body=_make_note_payload("Recovered", b"r" * 28, note_id=note_id),
        )
        resp = server.handle_note(req)

        assert resp.status_code == 200
        meta = json.loads((notes_dir / f"{note_id}.meta.json").read_text())
        assert meta["id"] == note_id
        assert meta["title"] == "Recovered"
        assert meta["size"] == 28
