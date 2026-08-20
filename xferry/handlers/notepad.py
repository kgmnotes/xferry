"""Canonical Secure Notepad HTTP and WebSocket domain handlers.

The server stores opaque nonce+ciphertext+tag blobs with small metadata
sidecars; it never receives note plaintext. HTTP exposes only the exact key,
exchange, collection-action, and item-action routes. WebSocket requests use
``action``/``request_id``/``input`` frames and wrap these same domain results.
ECDH session IDs remain optional audit context rather than authorization.
"""

import base64
import binascii
import json
import logging
import re
import socket
import threading

from ..http import HTTPRequest, HTTPResponse, json_response
from ..notepad_service import (
    NotepadService,
    NotepadServiceError,
    NoteResult,
    NoteStoragePolicy,
    SaveNoteRequest,
    is_valid_note_id,
    serialize_note_result,
)
from ..websocket import build_ws_frame
from .base import BaseHandler

logger = logging.getLogger("xferry")

_NOTE_CRYPTO_UNAVAILABLE_MESSAGE = "Secure Notepad crypto is unavailable"
_NOTE_ID_FORMAT = "32 lowercase hexadecimal characters"
_NOTE_REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_NOTE_COLLECTION_ACTIONS = ("list", "save", "clear")
_NOTE_ITEM_ACTIONS = ("load", "delete")
_NOTE_WS_ACTIONS = (*_NOTE_COLLECTION_ACTIONS[:2], *_NOTE_ITEM_ACTIONS, "clear")
_NOTE_SAVE_FIELDS = {
    "title",
    "data",
    "id",
    "create_if_missing",
    "session_id",
}


class NotepadHandlersMixin(BaseHandler):
    """Mixin for encrypted NOTE CRUD and ECDH operations.

    NOTE session IDs are short-lived, audit-only state. They confirm that a
    client recently completed an ECDH exchange, but they are not authorization
    tokens and they are not required to load or decrypt stored note blobs.
    """

    # Set by XFerryServer.__init__
    _notes_lock: threading.Lock
    _notepad_service: NotepadService | None
    note_storage_policy: NoteStoragePolicy

    # ── public entry point ────────────────────────────────────────

    def handle_note(self, request: HTTPRequest) -> HTTPResponse:
        """Dispatch only the seven canonical NOTE HTTP routes."""
        if request.raw_path != request.path:
            return self._note_invalid_path()

        if request.path == "/notes/key":
            query_error = self._note_reject_query(request)
            return query_error or self._note_get_key()

        if request.path == "/notes/exchange":
            query_error = self._note_reject_query(request)
            return query_error or self._note_exchange(request)

        action: str | None = None
        note_id: str | None = None
        if request.path == "/notes":
            action, query_error = self._note_action_query(
                request,
                allowed=_NOTE_COLLECTION_ACTIONS,
            )
            if query_error is not None:
                return query_error
        elif request.path.startswith("/notes/"):
            note_id = request.path.removeprefix("/notes/")
            if not note_id or "/" in note_id:
                return self._note_invalid_path()
            if not is_valid_note_id(note_id):
                return self._note_error_response(self._note_invalid_id_error())
            action, query_error = self._note_action_query(
                request,
                allowed=_NOTE_ITEM_ACTIONS,
            )
            if query_error is not None:
                return query_error
        else:
            return self._note_invalid_path()

        if self._ecdh_manager is None:
            return self._note_crypto_required()

        if action == "list":
            return self._note_list()
        if action == "save":
            return self._note_save(request)
        if action == "clear":
            return self._note_clear()
        if action == "load" and note_id is not None:
            return self._note_load(note_id)
        if action == "delete" and note_id is not None:
            return self._note_delete(note_id)
        return self._note_invalid_path()

    def _note_invalid_path(self) -> HTTPResponse:
        """Return the canonical NOTE path rejection."""
        return self._error_response(
            400,
            "Invalid notepad path",
            code="invalid_path",
            field="path",
            details={"access_scope": "notes"},
        )

    def _note_reject_query(self, request: HTTPRequest) -> HTTPResponse | None:
        """Reject every query on an exact key or exchange route."""
        if not request.query_string and not request.query_occurrences:
            return None
        field = request.query_occurrences[0][0] if request.query_occurrences else "query"
        return self._note_error_response(
            self._note_invalid_field_error(field, "Unexpected NOTE query field")
        )

    def _note_action_query(
        self,
        request: HTTPRequest,
        *,
        allowed: tuple[str, ...],
    ) -> tuple[str | None, HTTPResponse | None]:
        """Parse one exact, raw ``action=<value>`` query occurrence."""
        occurrences = request.query_occurrences
        if not occurrences:
            return None, self._note_error_response(self._note_missing_field_error("action"))

        unknown_key = next((key for key, _value in occurrences if key != "action"), None)
        if unknown_key is not None:
            return None, self._note_error_response(
                self._note_invalid_field_error(unknown_key, "Unexpected NOTE query field")
            )
        if len(occurrences) != 1:
            return None, self._note_error_response(
                self._note_invalid_field_error("action", "Duplicate NOTE action")
            )

        _key, action = occurrences[0]
        if request.query_string != f"action={action}" or action not in allowed:
            return None, self._note_error_response(
                self._note_invalid_field_error(
                    "action",
                    "Invalid NOTE action",
                    details={"allowed": list(allowed)},
                )
            )
        return action, None

    def _note_crypto_required(self) -> HTTPResponse:
        """Return the NOTE feature-unavailable response."""
        return self._error_response(
            501,
            _NOTE_CRYPTO_UNAVAILABLE_MESSAGE,
            code="feature_unavailable",
            details={"feature": "note", "dependency": "cryptography"},
        )

    # ── ECDH key exchange ─────────────────────────────────────────

    def _note_get_key(self) -> HTTPResponse:
        """Return the server's ECDH public key (base64 of raw 65 bytes)."""
        mgr = self._ecdh_manager
        if mgr is None:
            return self._note_crypto_required()
        return json_response(
            {
                "key": {
                    "available": True,
                    "algorithm": "ecdh_p256_hkdf_sha256_aes_256_gcm",
                    "public_key": base64.b64encode(mgr.get_public_key_raw()).decode("ascii"),
                    "public_key_encoding": "x9_62_uncompressed_base64",
                }
            }
        )

    def _note_exchange(self, request: HTTPRequest) -> HTTPResponse:
        """Perform ECDH key exchange: receive client pubkey, return session."""
        mgr = self._ecdh_manager
        if mgr is None:
            return self._note_crypto_required()

        payload, error = self._note_load_json_object(request.body)
        if error:
            return error
        assert payload is not None

        unknown_field = self._note_first_unknown_field(payload, {"client_public_key"})
        if unknown_field is not None:
            return self._note_error_response(
                self._note_invalid_field_error(
                    unknown_field,
                    "Unexpected NOTE exchange field",
                )
            )
        if "client_public_key" not in payload:
            return self._note_error_response(self._note_missing_field_error("client_public_key"))
        client_key_b64 = payload.get("client_public_key")
        if not isinstance(client_key_b64, str) or not client_key_b64:
            return self._note_error_response(
                self._note_invalid_field_error(
                    "client_public_key",
                    "Invalid client public key",
                    details={
                        "expected_encoding": "x9_62_uncompressed_base64",
                    },
                )
            )

        try:
            client_pub_raw = base64.b64decode(client_key_b64, validate=True)
        except (ValueError, binascii.Error):
            return self._note_error_response(
                self._note_invalid_field_error(
                    "client_public_key",
                    "Invalid client public key",
                    details={
                        "expected_encoding": "x9_62_uncompressed_base64",
                    },
                )
            )

        if len(client_pub_raw) != 65:
            return self._note_error_response(
                self._note_invalid_field_error(
                    "client_public_key",
                    "Invalid client public key",
                    details={
                        "expected_encoding": "x9_62_uncompressed_base64",
                    },
                )
            )

        try:
            session_id, _key = mgr.derive_session(client_pub_raw)
        except Exception as e:
            logger.error("ECDH exchange failed: %s", e)
            return self._note_error_response(
                self._note_invalid_field_error(
                    "client_public_key",
                    "Invalid client public key",
                    details={
                        "expected_encoding": "x9_62_uncompressed_base64",
                    },
                )
            )

        server_pub_b64 = base64.b64encode(
            mgr.get_public_key_raw(),
        ).decode("ascii")

        return json_response(
            {
                "session": {
                    "id": session_id,
                    "ttl_seconds": int(mgr.session_ttl_seconds),
                },
                "server_public_key": server_pub_b64,
            }
        )

    # ── internal helpers ──────────────────────────────────────────

    def _get_notepad_service(self) -> NotepadService:
        """Return the lazily created note-domain service."""
        service = getattr(self, "_notepad_service", None)
        if service is None:
            session_exists = (
                self._note_session_is_active if self._ecdh_manager is not None else None
            )
            service = NotepadService(
                self.notes_dir,
                self._notes_lock,
                session_exists=session_exists,
                storage_policy=getattr(self, "note_storage_policy", NoteStoragePolicy()),
                metrics=self._get_metrics_collector(),
            )
            self._notepad_service = service
        return service

    def _note_session_is_active(self, session_id: str) -> bool:
        """Return ``True`` when *session_id* is still active in the ECDH manager."""
        mgr = self._ecdh_manager
        return mgr is not None and mgr.get_session_key(session_id) is not None

    def _note_load_json_object(
        self,
        body: bytes,
    ) -> tuple[dict[str, object] | None, HTTPResponse | None]:
        """Decode a NOTE JSON body into an object with canonical errors."""
        try:
            payload = json.loads(body.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return None, self._error_response(
                400,
                "Invalid JSON body",
                code="malformed_json",
            )

        payload_obj = self._coerce_json_object(payload)
        if payload_obj is None:
            return None, self._error_response(
                400,
                "Expected JSON object",
                code="invalid_json_type",
                details={"expected": "object"},
            )
        return payload_obj, None

    @staticmethod
    def _note_missing_field_error(field: str) -> NotepadServiceError:
        """Build the canonical error for a required NOTE input field."""
        return NotepadServiceError(
            400,
            "Missing required field",
            code="missing_field",
            field=field,
        )

    @staticmethod
    def _note_invalid_field_error(
        field: str,
        message: str,
        *,
        details: dict[str, object] | None = None,
    ) -> NotepadServiceError:
        """Build the canonical error for an invalid NOTE input field."""
        return NotepadServiceError(
            400,
            message,
            code="invalid_field",
            field=field,
            details=details,
        )

    @staticmethod
    def _note_invalid_id_error() -> NotepadServiceError:
        """Build the canonical invalid stored-note identifier error."""
        return NotepadServiceError(
            400,
            "Invalid note ID",
            code="invalid_field",
            field="id",
            details={"format": _NOTE_ID_FORMAT},
        )

    @staticmethod
    def _note_first_unknown_field(
        payload: dict[str, object],
        allowed: set[str],
    ) -> str | None:
        """Return the first unknown JSON field in wire insertion order."""
        return next((field for field in payload if field not in allowed), None)

    def _note_error_response(
        self,
        error: NotepadServiceError,
    ) -> HTTPResponse:
        """Render the same canonical domain error used by WebSocket."""
        return self._error_response(
            error.status_code,
            error.message,
            code=error.code,
            field=error.field,
            details=error.details,
        )

    @staticmethod
    def _note_result_response(result: NoteResult, status: int = 200) -> HTTPResponse:
        """Render one canonical NOTE domain result as an HTTP body."""
        return json_response(serialize_note_result(result), status)

    def _note_parse_save_request(
        self,
        payload: dict[str, object],
    ) -> tuple[SaveNoteRequest | None, NotepadServiceError | None]:
        """Validate the exact save object shared by HTTP and WebSocket."""
        unknown_field = self._note_first_unknown_field(payload, _NOTE_SAVE_FIELDS)
        if unknown_field is not None:
            return None, self._note_invalid_field_error(
                unknown_field,
                "Unexpected NOTE save field",
            )
        if "title" not in payload:
            return None, self._note_missing_field_error("title")
        if "data" not in payload:
            return None, self._note_missing_field_error("data")

        title = payload["title"]
        data_b64 = payload["data"]
        if not isinstance(title, str):
            return None, self._note_invalid_field_error("title", "Invalid note title")
        if not isinstance(data_b64, str):
            return None, self._note_invalid_field_error(
                "data",
                "Invalid encrypted note data",
            )

        note_id = payload.get("id", "")
        if not isinstance(note_id, str) or ("id" in payload and not is_valid_note_id(note_id)):
            return None, self._note_invalid_id_error()

        create_if_missing = payload.get("create_if_missing", False)
        if not isinstance(create_if_missing, bool):
            return None, self._note_invalid_field_error(
                "create_if_missing",
                "create_if_missing must be a boolean",
            )

        session_id_value = payload.get("session_id")
        if "session_id" in payload and (
            not isinstance(session_id_value, str) or not is_valid_note_id(session_id_value)
        ):
            return None, self._note_invalid_field_error(
                "session_id",
                "Invalid note session ID",
                details={"format": _NOTE_ID_FORMAT},
            )
        session_id = session_id_value if isinstance(session_id_value, str) else None

        return (
            SaveNoteRequest(
                title=title,
                data_b64=data_b64,
                note_id=note_id,
                session_id=session_id,
                create_if_missing=create_if_missing,
            ),
            None,
        )

    def _note_save(self, request: HTTPRequest) -> HTTPResponse:
        """Save (create or update) a note."""
        payload, error = self._note_load_json_object(request.body)
        if error:
            return error
        assert payload is not None

        save_request, validation_error = self._note_parse_save_request(payload)
        if validation_error is not None:
            return self._note_error_response(validation_error)
        assert save_request is not None
        try:
            result = self._get_notepad_service().save_note(save_request)
        except NotepadServiceError as exc:
            return self._note_error_response(exc)
        return self._note_result_response(result, 201 if result.created else 200)

    def _note_list(self) -> HTTPResponse:
        """List all notes sorted by updated_at descending.

        The encrypted blob is the source of truth; malformed sidecars fall back
        to filename- and filesystem-derived metadata instead of hiding the note.
        """
        try:
            result = self._get_notepad_service().list_notes()
        except NotepadServiceError as exc:
            return self._note_error_response(exc)
        return self._note_result_response(result)

    def _note_load(self, note_id: str) -> HTTPResponse:
        """Load a single note (encrypted blob + metadata)."""
        try:
            result = self._get_notepad_service().load_note(note_id)
        except NotepadServiceError as exc:
            return self._note_error_response(exc)
        return self._note_result_response(result)

    def _note_delete(self, note_id: str) -> HTTPResponse:
        """Delete a note (both .enc and .meta.json)."""
        try:
            result = self._get_notepad_service().delete_note(note_id)
        except NotepadServiceError as exc:
            return self._note_error_response(exc)
        return self._note_result_response(result)

    def _note_clear(self) -> HTTPResponse:
        """Clear all notes from the separate notes/ directory."""
        try:
            result = self._get_notepad_service().clear_notes()
        except NotepadServiceError as exc:
            return self._note_error_response(exc)
        return self._note_result_response(result)

    def _handle_ws_message(self, sock: socket.socket, payload: bytes) -> None:
        """Process one exact canonical NOTE WebSocket application frame."""
        try:
            msg = json.loads(payload.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            self._ws_send_error(
                sock,
                action=None,
                request_id=None,
                error=NotepadServiceError(
                    400,
                    "Invalid JSON body",
                    code="malformed_json",
                ),
            )
            return

        msg_obj = self._coerce_json_object(msg)
        if msg_obj is None:
            self._ws_send_error(
                sock,
                action=None,
                request_id=None,
                error=NotepadServiceError(
                    400,
                    "Expected JSON object",
                    code="invalid_json_type",
                    details={"expected": "object"},
                ),
            )
            return

        action_value = msg_obj.get("action")
        action = (
            action_value
            if isinstance(action_value, str) and action_value in _NOTE_WS_ACTIONS
            else None
        )
        request_id_value = msg_obj.get("request_id")
        request_id = (
            request_id_value
            if isinstance(request_id_value, str)
            and _NOTE_REQUEST_ID_RE.fullmatch(request_id_value) is not None
            else None
        )

        unknown_field = self._note_first_unknown_field(
            msg_obj,
            {"action", "request_id", "input"},
        )
        if unknown_field is not None:
            self._ws_send_error(
                sock,
                action=action,
                request_id=request_id,
                error=self._note_invalid_field_error(
                    unknown_field,
                    "Unexpected NOTE WebSocket field",
                ),
            )
            return

        if "action" not in msg_obj:
            error = self._note_missing_field_error("action")
        elif action is None:
            error = self._note_invalid_field_error(
                "action",
                "Invalid NOTE action",
                details={"allowed": list(_NOTE_WS_ACTIONS)},
            )
        elif "request_id" not in msg_obj:
            error = self._note_missing_field_error("request_id")
        elif request_id is None:
            error = self._note_invalid_field_error(
                "request_id",
                "Invalid NOTE request ID",
                details={"format": "[A-Za-z0-9._:-]{1,128}"},
            )
        elif "input" not in msg_obj:
            error = self._note_missing_field_error("input")
        else:
            error = None

        if error is not None:
            self._ws_send_error(
                sock,
                action=action,
                request_id=request_id,
                error=error,
            )
            return

        input_value = msg_obj["input"]
        input_obj = self._coerce_json_object(input_value)
        if input_obj is None:
            self._ws_send_error(
                sock,
                action=action,
                request_id=request_id,
                error=self._note_invalid_field_error(
                    "input",
                    "NOTE input must be an object",
                    details={"expected": "object"},
                ),
            )
            return

        assert action is not None
        assert request_id is not None
        try:
            result = self._note_ws_operation(action, input_obj)
        except NotepadServiceError as exc:
            self._ws_send_error(
                sock,
                action=action,
                request_id=request_id,
                error=exc,
            )
            return

        if not self._ws_send_json(
            sock,
            {
                "action": action,
                "request_id": request_id,
                "result": serialize_note_result(result),
            },
        ):
            raise ConnectionError("WebSocket JSON send failed")

    def _note_ws_operation(
        self,
        action: str,
        input_obj: dict[str, object],
    ) -> NoteResult:
        """Validate action input and run the shared NOTE domain service."""
        service = self._get_notepad_service()
        if action in {"list", "clear"}:
            unknown_field = self._note_first_unknown_field(input_obj, set())
            if unknown_field is not None:
                raise self._note_invalid_field_error(
                    unknown_field,
                    f"{action} input must be empty",
                )
            return service.list_notes() if action == "list" else service.clear_notes()

        if action == "save":
            save_request, validation_error = self._note_parse_save_request(input_obj)
            if validation_error is not None:
                raise validation_error
            assert save_request is not None
            return service.save_note(save_request)

        unknown_field = self._note_first_unknown_field(input_obj, {"id"})
        if unknown_field is not None:
            raise self._note_invalid_field_error(
                unknown_field,
                f"Unexpected NOTE {action} field",
            )
        if "id" not in input_obj:
            raise self._note_missing_field_error("id")
        note_id = input_obj["id"]
        if not isinstance(note_id, str) or not is_valid_note_id(note_id):
            raise self._note_invalid_id_error()
        return service.load_note(note_id) if action == "load" else service.delete_note(note_id)

    def _ws_send_error(
        self,
        sock: socket.socket,
        *,
        action: str | None,
        request_id: str | None,
        error: NotepadServiceError,
    ) -> None:
        """Send an application error with stable top-level correlation."""
        if not self._ws_send_json(
            sock,
            {
                "action": action,
                "request_id": request_id,
                "error": error.to_dict(),
            },
        ):
            raise ConnectionError("WebSocket JSON send failed")

    @staticmethod
    def _ws_send_json(sock: socket.socket, data: dict[str, object]) -> bool:
        """Send a JSON message over WebSocket."""
        frame = build_ws_frame(json.dumps(data).encode("utf-8"))
        try:
            sock.sendall(frame)
        except Exception as exc:
            logger.warning("WebSocket JSON send failed: %s", exc)
            return False
        return True
