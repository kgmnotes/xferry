"""Tests for WebSocket message handlers (_handle_ws_message, _ws_handle_save, etc.)."""

import base64
import json
import logging
import struct
import threading
from pathlib import Path

import pytest

from tests.conftest import make_request
from tests.server_factory import make_server
from xferry.handlers import HandlerMixin, NotepadHandlersMixin
from xferry.notepad_service import NoteStoragePolicy, max_note_data_b64_chars
from xferry.security.keys import HAS_ECDH
from xferry.websocket import _MAX_FRAME_SIZE, WS_CLOSE, WS_TEXT, build_ws_frame, parse_ws_frame


def _make_masked_ws_frame(opcode: int, payload: bytes) -> bytes:
    mask_key = b"\x37\x38\x39\x30"
    masked = bytearray(len(payload))
    for index, value in enumerate(payload):
        masked[index] = value ^ mask_key[index % 4]

    header = bytearray((0x80 | opcode,))
    length = len(payload)
    if length < 126:
        header.append(0x80 | length)
    elif length < 65536:
        header.append(0x80 | 126)
        header.extend(struct.pack("!H", length))
    else:
        header.append(0x80 | 127)
        header.extend(struct.pack("!Q", length))
    header.extend(mask_key)
    return bytes(header) + bytes(masked)


class _MockSocket:
    """Captures sendall() calls for WebSocket frame inspection."""

    def __init__(self):
        self.sent: list[bytes] = []

    def sendall(self, data: bytes) -> None:
        self.sent.append(data)

    def get_json_messages(self) -> list[dict]:
        """Parse all sent WS frames as JSON messages."""
        messages = []
        for raw in self.sent:
            frame = parse_ws_frame(raw)
            if frame is None:
                continue
            _opcode, payload, _consumed = frame
            try:
                messages.append(json.loads(payload.decode("utf-8")))
            except (json.JSONDecodeError, UnicodeDecodeError):
                pass
        return messages

    @property
    def last_json(self) -> dict:
        msgs = self.get_json_messages()
        assert msgs, "No JSON messages were sent"
        return msgs[-1]


class _FailingSocket:
    def sendall(self, _data: bytes) -> None:
        raise OSError("send failed")


class _WebSocketLoopSocket(_MockSocket):
    def __init__(self, recv_items: list[bytes | BaseException]):
        super().__init__()
        self._recv_items = list(recv_items)
        self.timeouts: list[float] = []

    def settimeout(self, value: float) -> None:
        self.timeouts.append(value)

    def recv(self, _size: int) -> bytes:
        if not self._recv_items:
            return b""
        item = self._recv_items.pop(0)
        if isinstance(item, BaseException):
            raise item
        return item


class WSServerStub(HandlerMixin):
    """Minimal server with notepad + WS message handling."""

    _handle_ws_message = NotepadHandlersMixin._handle_ws_message
    _ws_send_json = staticmethod(NotepadHandlersMixin._ws_send_json)

    def __init__(self, root_dir: Path, upload_dir: Path):
        self.root_dir = root_dir
        self.upload_dir = upload_dir
        self.notes_dir = root_dir / "notes"
        self.notes_dir.mkdir(exist_ok=True)
        self.sandbox_mode = False
        self.opsec_mode = False
        self._temp_smuggle_files: set[str] = set()
        self._smuggle_lock = threading.Lock()
        self._notes_lock = threading.Lock()

        self._ecdh_manager = None
        if HAS_ECDH:
            from xferry.security.keys import ECDHKeyManager

            self._ecdh_manager = ECDHKeyManager()
        self.method_handlers = self.build_method_handlers()

    def get_metrics(self):
        return {
            "uptime_seconds": 0,
            "total_requests": 0,
            "total_errors": 0,
            "client_errors": 0,
            "server_errors": 0,
            "bytes_sent": 0,
            "status_counts": {},
        }


@pytest.fixture
def ws_server(temp_dir, upload_dir):
    (temp_dir / "index.html").write_text("<html>ok</html>")
    return WSServerStub(temp_dir, upload_dir)


@pytest.fixture
def mock_socket():
    return _MockSocket()


_VALID_ENCRYPTED_BLOB = b"n" * 12 + b"t" * 16


def _ws_payload(
    action: str,
    *,
    request_id: str = "request-1",
    input_value: object | None = None,
) -> bytes:
    """Build one canonical NOTE WebSocket request frame payload."""
    return json.dumps(
        {
            "action": action,
            "request_id": request_id,
            "input": {} if input_value is None else input_value,
        }
    ).encode()


class TestStage008CanonicalWebSocketContract:
    def test_success_wraps_the_same_domain_result_as_http(self, ws_server, mock_socket):
        body = json.dumps(
            {
                "title": "Parity",
                "data": base64.b64encode(_VALID_ENCRYPTED_BLOB).decode(),
            }
        ).encode()
        http_response = ws_server.handle_note(make_request("NOTE", "/notes?action=save", body=body))

        ws_server._handle_ws_message(
            mock_socket,
            json.dumps(
                {
                    "action": "load",
                    "request_id": "load-1",
                    "input": {"id": json.loads(http_response.body)["note"]["id"]},
                }
            ).encode(),
        )

        message = mock_socket.last_json
        http_load = ws_server.handle_note(
            make_request(
                "NOTE",
                f"/notes/{message['result']['note']['id']}?action=load",
            )
        )
        assert set(message) == {"action", "request_id", "result"}
        assert message["action"] == "load"
        assert message["request_id"] == "load-1"
        assert message["result"] == json.loads(http_load.body)

    def test_error_keeps_correlation_and_matches_http_nested_error(
        self,
        ws_server,
        mock_socket,
    ):
        note_id = "a" * 32
        http_response = ws_server.handle_note(make_request("NOTE", f"/notes/{note_id}?action=load"))

        ws_server._handle_ws_message(
            mock_socket,
            json.dumps(
                {
                    "action": "load",
                    "request_id": "load-missing",
                    "input": {"id": note_id},
                }
            ).encode(),
        )

        assert mock_socket.last_json == {
            "action": "load",
            "request_id": "load-missing",
            "error": json.loads(http_response.body)["error"],
        }

    @pytest.mark.parametrize(
        "frame",
        [
            {"type": "list", "request_id": "legacy", "input": {}},
            {"action": "list", "opId": "legacy", "input": {}},
            {"action": "load", "request_id": "legacy", "input": {"noteId": "a" * 32}},
            {
                "action": "save",
                "request_id": "legacy",
                "input": {
                    "title": "Legacy",
                    "data": base64.b64encode(_VALID_ENCRYPTED_BLOB).decode(),
                    "createIfMissing": True,
                },
            },
        ],
    )
    def test_rejects_legacy_and_extra_fields(self, ws_server, mock_socket, frame):
        ws_server._handle_ws_message(mock_socket, json.dumps(frame).encode())

        message = mock_socket.last_json
        assert set(message) == {"action", "request_id", "error"}
        assert message["error"]["code"] in {"missing_field", "invalid_field"}
        assert "status" not in message
        assert "type" not in message

    @pytest.mark.parametrize(
        "request_id",
        [None, "", "contains space", "a" * 129, 123],
    )
    def test_rejects_missing_or_invalid_request_id(
        self,
        ws_server,
        mock_socket,
        request_id,
    ):
        frame = {"action": "list", "input": {}}
        if request_id is not None:
            frame["request_id"] = request_id

        ws_server._handle_ws_message(mock_socket, json.dumps(frame).encode())

        message = mock_socket.last_json
        assert message["action"] == "list"
        assert message["request_id"] is None
        assert message["error"]["field"] == "request_id"

    @pytest.mark.parametrize(
        ("frame", "action", "request_id", "field"),
        [
            ({"request_id": "missing-action", "input": {}}, None, "missing-action", "action"),
            ({"action": "list", "request_id": "missing-input"}, "list", "missing-input", "input"),
            (
                {"action": "list", "request_id": "bad-input", "input": []},
                "list",
                "bad-input",
                "input",
            ),
            (
                {"action": "clear", "request_id": "extra-input", "input": {"extra": 1}},
                "clear",
                "extra-input",
                "extra",
            ),
        ],
    )
    def test_rejects_missing_invalid_and_extra_frame_members(
        self,
        ws_server,
        mock_socket,
        frame,
        action,
        request_id,
        field,
    ):
        ws_server._handle_ws_message(mock_socket, json.dumps(frame).encode())

        assert mock_socket.last_json["action"] == action
        assert mock_socket.last_json["request_id"] == request_id
        assert mock_socket.last_json["error"]["field"] == field

    @pytest.mark.parametrize("request_id", ["x", "a" * 128, "A-Z_0.9:ok"])
    def test_accepts_request_id_grammar_boundaries(
        self,
        ws_server,
        mock_socket,
        request_id,
    ):
        ws_server._handle_ws_message(
            mock_socket,
            _ws_payload("list", request_id=request_id),
        )

        assert mock_socket.last_json["request_id"] == request_id
        assert "result" in mock_socket.last_json


# ── Invalid input tests ───────────────────────────────────────────


class TestWSClientMasking:
    def test_binary_frame_closes_unsupported_data_without_dispatch(
        self,
        temp_dir,
        monkeypatch,
    ):
        (temp_dir / "index.html").write_text("<html>ok</html>")
        server = make_server(root_dir=str(temp_dir), quiet=True)
        handled_payloads: list[bytes] = []
        monkeypatch.setattr(
            server,
            "_handle_ws_message",
            lambda _sock, payload: handled_payloads.append(payload),
        )
        server.running = True
        sock = _WebSocketLoopSocket([_make_masked_ws_frame(0x02, b'{"type":"list"}')])
        request = make_request(
            "GET",
            "/notes/ws",
            headers={"Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ=="},
        )

        server._handle_notepad_ws(sock, request)

        assert handled_payloads == []
        assert b"HTTP/1.1 101 Switching Protocols" in sock.sent[0]
        close_frame = parse_ws_frame(sock.sent[-1])
        assert close_frame is not None
        assert close_frame[0] == WS_CLOSE
        assert struct.unpack("!H", close_frame[1][:2])[0] == 1003
        assert close_frame[1][2:] == b"Binary frames are not supported"

    def test_unmasked_frame_closes_protocol_error_without_dispatch(
        self,
        temp_dir,
        monkeypatch,
    ):
        (temp_dir / "index.html").write_text("<html>ok</html>")
        server = make_server(root_dir=str(temp_dir), quiet=True)
        handled_payloads: list[bytes] = []
        monkeypatch.setattr(
            server,
            "_handle_ws_message",
            lambda _sock, payload: handled_payloads.append(payload),
        )
        server.running = True
        sock = _WebSocketLoopSocket(
            [build_ws_frame(json.dumps({"type": "list"}).encode(), opcode=WS_TEXT)]
        )
        request = make_request(
            "GET",
            "/notes/ws",
            headers={"Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ=="},
        )

        server._handle_notepad_ws(sock, request)

        assert handled_payloads == []
        assert b"HTTP/1.1 101 Switching Protocols" in sock.sent[0]
        assert len(sock.sent) == 2
        protocol_close = parse_ws_frame(sock.sent[1])
        assert protocol_close is not None
        assert protocol_close[0] == WS_CLOSE
        assert struct.unpack("!H", protocol_close[1][:2])[0] == 1002
        assert protocol_close[1][2:] == b"Protocol error"

    def test_incomplete_frame_idle_timeout_closes_without_dispatch(
        self,
        temp_dir,
        monkeypatch,
    ):
        (temp_dir / "index.html").write_text("<html>ok</html>")
        server = make_server(
            root_dir=str(temp_dir),
            quiet=True,
            websocket_frame_idle_timeout=0.01,
        )
        handled_payloads: list[bytes] = []
        monkeypatch.setattr(
            server,
            "_handle_ws_message",
            lambda _sock, payload: handled_payloads.append(payload),
        )
        monotonic_values = iter([0.0, 0.02])
        monkeypatch.setattr("xferry.server.time.monotonic", lambda: next(monotonic_values))
        server.running = True

        partial_frame = (
            b"\x81\xff" + struct.pack("!Q", _MAX_FRAME_SIZE) + b"\x37\x38\x39\x30" + b"partial"
        )
        sock = _WebSocketLoopSocket([partial_frame, TimeoutError()])
        request = make_request(
            "GET",
            "/notes/ws",
            headers={"Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ=="},
        )

        server._handle_notepad_ws(sock, request)

        assert handled_payloads == []
        assert b"HTTP/1.1 101 Switching Protocols" in sock.sent[0]
        assert sock.timeouts == [60.0, 0.01]
        close_frame = parse_ws_frame(sock.sent[-1])
        assert close_frame is not None
        assert close_frame[0] == WS_CLOSE
        assert struct.unpack("!H", close_frame[1][:2])[0] == 1002
        assert close_frame[1][2:] == b"Incomplete frame timeout"

    def test_internal_message_error_closes_1011_and_logs_failure(
        self,
        temp_dir,
        monkeypatch,
        caplog,
    ):
        (temp_dir / "index.html").write_text("<html>ok</html>")
        server = make_server(root_dir=str(temp_dir), quiet=True)

        def fail_message(_sock: object, _payload: bytes) -> None:
            raise RuntimeError("boom")

        monkeypatch.setattr(server, "_handle_ws_message", fail_message)
        server.running = True
        sock = _WebSocketLoopSocket([_make_masked_ws_frame(WS_TEXT, b'{"type":"list"}')])
        request = make_request(
            "GET",
            "/notes/ws",
            headers={"Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ=="},
        )

        with caplog.at_level(logging.ERROR, logger="xferry"):
            server._handle_notepad_ws(sock, request)

        assert b"HTTP/1.1 101 Switching Protocols" in sock.sent[0]
        close_frame = parse_ws_frame(sock.sent[-1])
        assert close_frame is not None
        assert close_frame[0] == WS_CLOSE
        assert struct.unpack("!H", close_frame[1][:2])[0] == 1011
        assert close_frame[1][2:] == b"Internal error"
        assert server.get_metrics()["websocket"]["errors"] == 1
        assert any(record.levelno == logging.ERROR for record in caplog.records)
        assert "WS connection failed" in caplog.text


class TestWSInvalidInput:
    def test_invalid_json_returns_error(self, ws_server, mock_socket):
        ws_server._handle_ws_message(mock_socket, b"not json{{{")
        assert mock_socket.last_json == {
            "action": None,
            "request_id": None,
            "error": {
                "code": "malformed_json",
                "message": "Invalid JSON body",
                "field": None,
                "details": {},
            },
        }

    def test_json_array_returns_object_error(self, ws_server, mock_socket):
        ws_server._handle_ws_message(mock_socket, b"[]")
        assert mock_socket.last_json["action"] is None
        assert mock_socket.last_json["request_id"] is None
        assert mock_socket.last_json["error"]["code"] == "invalid_json_type"
        assert mock_socket.last_json["error"]["details"] == {"expected": "object"}

    def test_legacy_type_returns_invalid_field(self, ws_server, mock_socket):
        payload = json.dumps({"type": "bogus"}).encode()
        ws_server._handle_ws_message(mock_socket, payload)
        assert mock_socket.last_json["action"] is None
        assert mock_socket.last_json["request_id"] is None
        assert mock_socket.last_json["error"]["code"] == "invalid_field"
        assert mock_socket.last_json["error"]["field"] == "type"

    def test_non_string_action_returns_correlated_error(self, ws_server, mock_socket):
        payload = json.dumps({"action": 123, "request_id": "bad-action", "input": {}}).encode()
        ws_server._handle_ws_message(mock_socket, payload)
        assert mock_socket.last_json["action"] is None
        assert mock_socket.last_json["request_id"] == "bad-action"
        assert mock_socket.last_json["error"]["field"] == "action"

    def test_empty_payload_returns_error(self, ws_server, mock_socket):
        ws_server._handle_ws_message(mock_socket, b"")
        assert mock_socket.last_json["error"]["code"] == "malformed_json"


# ── List tests ────────────────────────────────────────────────────


class TestWSList:
    def test_list_empty(self, ws_server, mock_socket):
        ws_server._handle_ws_message(mock_socket, _ws_payload("list"))
        msg = mock_socket.last_json
        assert set(msg) == {"action", "request_id", "result"}
        assert msg["action"] == "list"
        assert msg["request_id"] == "request-1"
        assert msg["result"] == {
            "notes": [],
            "page": {"limit": 1000, "returned_items": 0, "truncated": False},
        }


# ── Save tests ────────────────────────────────────────────────────


class TestWSSave:
    def test_save_creates_note(self, ws_server, mock_socket):
        ws_server._handle_ws_message(
            mock_socket,
            _ws_payload(
                "save",
                request_id="save-create",
                input_value={
                    "title": "WS Note",
                    "data": base64.b64encode(_VALID_ENCRYPTED_BLOB).decode(),
                },
            ),
        )
        msg = mock_socket.last_json
        assert msg["action"] == "save"
        assert msg["request_id"] == "save-create"
        assert msg["result"]["created"] is True
        assert len(msg["result"]["note"]["id"]) == 32

    def test_save_echoes_request_id_and_client_note_id_retry_is_idempotent(
        self,
        ws_server,
        mock_socket,
    ):
        note_id = "c" * 32
        ws_server._handle_ws_message(
            mock_socket,
            _ws_payload(
                "save",
                request_id="save-op-1",
                input_value={
                    "id": note_id,
                    "create_if_missing": True,
                    "title": "WS Client ID",
                    "data": base64.b64encode(b"f" * 28).decode(),
                },
            ),
        )
        msg = mock_socket.last_json
        assert msg["request_id"] == "save-op-1"
        assert msg["result"]["created"] is True
        assert msg["result"]["note"]["id"] == note_id

        ws_server._handle_ws_message(
            mock_socket,
            _ws_payload(
                "save",
                request_id="save-op-2",
                input_value={
                    "id": note_id,
                    "create_if_missing": True,
                    "title": "WS Client ID Retry",
                    "data": base64.b64encode(b"r" * 28).decode(),
                },
            ),
        )
        retry_msg = mock_socket.last_json
        assert retry_msg["request_id"] == "save-op-2"
        assert retry_msg["result"]["created"] is False
        assert retry_msg["result"]["note"]["id"] == note_id
        assert retry_msg["result"]["note"]["title"] == "WS Client ID Retry"

        enc_files = sorted(path.name for path in ws_server.notes_dir.glob("*.enc"))
        assert enc_files == [f"{note_id}.enc"]
        assert (ws_server.notes_dir / f"{note_id}.enc").read_bytes() == b"r" * 28

    def test_save_nonexistent_note_id_without_create_if_missing_returns_404(
        self,
        ws_server,
        mock_socket,
    ):
        ws_server._handle_ws_message(
            mock_socket,
            _ws_payload(
                "save",
                request_id="update-op-1",
                input_value={
                    "id": "d" * 32,
                    "title": "Missing",
                    "data": base64.b64encode(_VALID_ENCRYPTED_BLOB).decode(),
                },
            ),
        )
        msg = mock_socket.last_json
        assert msg["action"] == "save"
        assert msg["request_id"] == "update-op-1"
        assert msg["error"] == {
            "code": "resource_not_found",
            "message": "Note not found",
            "field": "id",
            "details": {"resource": "note"},
        }
        assert "status" not in msg

    def test_save_oversized_encoded_data_returns_saved_error(
        self,
        ws_server,
        mock_socket,
        monkeypatch,
    ):
        monkeypatch.setattr("xferry.notepad_service.MAX_NOTE_ENCRYPTED_BLOB_BYTES", 28)
        ws_server._handle_ws_message(
            mock_socket,
            _ws_payload(
                "save",
                request_id="too-large-encoded",
                input_value={
                    "title": "Too Large",
                    "data": "A" * (max_note_data_b64_chars() + 4),
                },
            ),
        )

        msg = mock_socket.last_json
        assert msg["request_id"] == "too-large-encoded"
        assert msg["error"]["code"] == "payload_too_large"
        assert msg["error"]["details"]["limit_bytes"] == 28
        assert list(ws_server.notes_dir.iterdir()) == []

    def test_save_oversized_decoded_data_returns_saved_error(
        self,
        ws_server,
        mock_socket,
        monkeypatch,
    ):
        monkeypatch.setattr("xferry.notepad_service.MAX_NOTE_ENCRYPTED_BLOB_BYTES", 28)
        ws_server._handle_ws_message(
            mock_socket,
            _ws_payload(
                "save",
                request_id="too-large-decoded",
                input_value={
                    "title": "Too Large",
                    "data": base64.b64encode(b"x" * 29).decode(),
                },
            ),
        )

        msg = mock_socket.last_json
        assert msg["request_id"] == "too-large-decoded"
        assert msg["error"]["code"] == "payload_too_large"
        assert msg["error"]["details"] == {
            "scope": "note",
            "limit_bytes": 28,
            "actual_bytes": 29,
        }
        assert list(ws_server.notes_dir.iterdir()) == []

    def test_save_boundary_payload_can_load(self, ws_server, mock_socket, monkeypatch):
        monkeypatch.setattr("xferry.notepad_service.MAX_NOTE_ENCRYPTED_BLOB_BYTES", 28)
        save_payload = _ws_payload(
            "save",
            request_id="boundary-save",
            input_value={
                "title": "Boundary",
                "data": base64.b64encode(_VALID_ENCRYPTED_BLOB).decode(),
            },
        )
        assert len(save_payload) < _MAX_FRAME_SIZE

        ws_server._handle_ws_message(mock_socket, save_payload)
        save_msg = mock_socket.last_json
        note_id = save_msg["result"]["note"]["id"]
        assert save_msg["result"]["note"]["size_bytes"] == 28

        load_payload = _ws_payload(
            "load",
            request_id="boundary-load",
            input_value={"id": note_id},
        )
        ws_server._handle_ws_message(mock_socket, load_payload)
        load_msg = mock_socket.last_json
        assert load_msg["result"]["note"]["size_bytes"] == 28
        assert base64.b64decode(load_msg["result"]["data"]) == _VALID_ENCRYPTED_BLOB

    def test_save_then_list_shows_note(self, ws_server, mock_socket):
        save_payload = _ws_payload(
            "save",
            request_id="listed-save",
            input_value={
                "title": "Listed",
                "data": base64.b64encode(_VALID_ENCRYPTED_BLOB).decode(),
            },
        )
        ws_server._handle_ws_message(mock_socket, save_payload)

        list_payload = _ws_payload("list", request_id="listed-list")
        ws_server._handle_ws_message(mock_socket, list_payload)
        msg = mock_socket.last_json
        assert msg["result"]["page"]["returned_items"] == 1
        assert msg["result"]["notes"][0]["title"] == "Listed"

    def test_save_rejects_note_count_quota_with_stable_error(self, ws_server, mock_socket):
        ws_server.note_storage_policy = NoteStoragePolicy(
            max_total_bytes=None,
            max_note_count=1,
            max_listed_notes=1,
        )
        first_payload = _ws_payload(
            "save",
            request_id="quota-first",
            input_value={
                "title": "First",
                "data": base64.b64encode(b"f" * 28).decode(),
            },
        )
        ws_server._handle_ws_message(mock_socket, first_payload)
        first_id = mock_socket.last_json["result"]["note"]["id"]

        second_payload = _ws_payload(
            "save",
            request_id="quota-op-1",
            input_value={
                "title": "Second",
                "data": base64.b64encode(b"s" * 28).decode(),
            },
        )
        ws_server._handle_ws_message(mock_socket, second_payload)

        msg = mock_socket.last_json
        assert msg["request_id"] == "quota-op-1"
        assert msg["error"] == {
            "code": "storage_quota_exceeded",
            "message": "Notepad storage quota exceeded",
            "field": "data",
            "details": {"scope": "notes", "reason": "notes"},
        }
        assert sorted(path.name for path in ws_server.notes_dir.iterdir()) == [
            f"{first_id}.enc",
            f"{first_id}.meta.json",
        ]


# ── Load tests ────────────────────────────────────────────────────


class TestWSLoad:
    def test_load_existing_note(self, ws_server, mock_socket):
        save_payload = _ws_payload(
            "save",
            request_id="load-save",
            input_value={
                "title": "Load Test",
                "data": base64.b64encode(_VALID_ENCRYPTED_BLOB).decode(),
            },
        )
        ws_server._handle_ws_message(mock_socket, save_payload)
        note_id = mock_socket.last_json["result"]["note"]["id"]

        load_payload = _ws_payload(
            "load",
            request_id="load-existing",
            input_value={"id": note_id},
        )
        ws_server._handle_ws_message(mock_socket, load_payload)
        msg = mock_socket.last_json
        assert msg["action"] == "load"
        assert msg["request_id"] == "load-existing"
        assert msg["result"]["note"]["id"] == note_id
        assert base64.b64decode(msg["result"]["data"]) == _VALID_ENCRYPTED_BLOB

    def test_load_invalid_id_returns_error(self, ws_server, mock_socket):
        payload = _ws_payload("load", input_value={"id": "ZZZZ!!!"})
        ws_server._handle_ws_message(mock_socket, payload)
        msg = mock_socket.last_json
        assert msg["error"]["code"] == "invalid_field"
        assert msg["error"]["field"] == "id"

    def test_load_missing_id_returns_error(self, ws_server, mock_socket):
        payload = _ws_payload("load")
        ws_server._handle_ws_message(mock_socket, payload)
        msg = mock_socket.last_json
        assert msg["error"]["code"] == "missing_field"
        assert msg["error"]["field"] == "id"

    def test_load_nonexistent_returns_404(self, ws_server, mock_socket):
        payload = _ws_payload("load", input_value={"id": "a" * 32})
        ws_server._handle_ws_message(mock_socket, payload)
        msg = mock_socket.last_json
        assert msg["error"]["code"] == "resource_not_found"
        assert msg["error"]["details"] == {"resource": "note"}
        assert "status" not in msg


# ── Delete tests ──────────────────────────────────────────────────


class TestWSDelete:
    def test_delete_existing_note(self, ws_server, mock_socket, upload_dir):
        save_payload = _ws_payload(
            "save",
            request_id="delete-save",
            input_value={
                "title": "Del Test",
                "data": base64.b64encode(_VALID_ENCRYPTED_BLOB).decode(),
            },
        )
        ws_server._handle_ws_message(mock_socket, save_payload)
        note_id = mock_socket.last_json["result"]["note"]["id"]

        del_payload = _ws_payload(
            "delete",
            request_id="delete-existing",
            input_value={"id": note_id},
        )
        ws_server._handle_ws_message(mock_socket, del_payload)
        msg = mock_socket.last_json
        assert msg == {
            "action": "delete",
            "request_id": "delete-existing",
            "result": {"deleted_note": {"id": note_id}},
        }

        list_payload = _ws_payload("list", request_id="delete-list")
        ws_server._handle_ws_message(mock_socket, list_payload)
        assert mock_socket.last_json["result"]["page"]["returned_items"] == 0

    def test_delete_invalid_id_returns_error(self, ws_server, mock_socket):
        payload = _ws_payload("delete", input_value={"id": "!@#$"})
        ws_server._handle_ws_message(mock_socket, payload)
        assert mock_socket.last_json["error"]["field"] == "id"

    def test_delete_empty_id_returns_error(self, ws_server, mock_socket):
        payload = _ws_payload("delete", input_value={"id": ""})
        ws_server._handle_ws_message(mock_socket, payload)
        assert mock_socket.last_json["error"]["field"] == "id"


class TestNoteTransportContracts:
    def test_http_and_ws_save_use_canonical_domain_shape(self, ws_server, mock_socket):
        http_body = json.dumps(
            {
                "title": "HTTP Save",
                "data": base64.b64encode(_VALID_ENCRYPTED_BLOB).decode(),
            }
        ).encode()
        http_resp = ws_server.handle_note(
            make_request("NOTE", "/notes?action=save", body=http_body)
        )
        http_data = json.loads(http_resp.body)

        ws_payload = _ws_payload(
            "save",
            request_id="save-parity",
            input_value={
                "title": "WS Save",
                "data": base64.b64encode(_VALID_ENCRYPTED_BLOB).decode(),
            },
        )
        ws_server._handle_ws_message(mock_socket, ws_payload)
        ws_data = mock_socket.last_json

        assert set(http_data) == {"note", "created"}
        assert set(ws_data) == {"action", "request_id", "result"}
        assert set(ws_data["result"]) == set(http_data)
        assert set(ws_data["result"]["note"]) == set(http_data["note"])
        assert ws_data["result"]["note"]["size_bytes"] == 28

    def test_http_and_ws_list_results_are_identical(self, ws_server, mock_socket):
        save_body = json.dumps(
            {
                "title": "Parity Note",
                "data": base64.b64encode(_VALID_ENCRYPTED_BLOB).decode(),
            }
        ).encode()
        ws_server.handle_note(make_request("NOTE", "/notes?action=save", body=save_body))

        http_resp = ws_server.handle_note(make_request("NOTE", "/notes?action=list"))
        http_data = json.loads(http_resp.body)

        ws_server._handle_ws_message(
            mock_socket,
            _ws_payload("list", request_id="list-parity"),
        )
        ws_data = mock_socket.last_json

        assert ws_data["result"] == http_data

    def test_http_and_ws_load_results_are_identical(self, ws_server, mock_socket):
        save_body = json.dumps(
            {
                "title": "Load Parity",
                "data": base64.b64encode(_VALID_ENCRYPTED_BLOB).decode(),
            }
        ).encode()
        save_resp = ws_server.handle_note(
            make_request("NOTE", "/notes?action=save", body=save_body)
        )
        note_id = json.loads(save_resp.body)["note"]["id"]

        http_resp = ws_server.handle_note(make_request("NOTE", f"/notes/{note_id}?action=load"))
        http_data = json.loads(http_resp.body)

        ws_server._handle_ws_message(
            mock_socket,
            _ws_payload(
                "load",
                request_id="load-parity",
                input_value={"id": note_id},
            ),
        )
        ws_data = mock_socket.last_json

        assert ws_data["result"] == http_data

    def test_http_and_ws_clear_results_are_identical(self, ws_server, mock_socket):
        save_body = json.dumps(
            {
                "title": "Clear Parity",
                "data": base64.b64encode(_VALID_ENCRYPTED_BLOB).decode(),
            }
        ).encode()
        ws_server.handle_note(make_request("NOTE", "/notes?action=save", body=save_body))

        http_resp = ws_server.handle_note(make_request("NOTE", "/notes?action=clear"))
        http_data = json.loads(http_resp.body)

        ws_server.handle_note(make_request("NOTE", "/notes?action=save", body=save_body))
        ws_server._handle_ws_message(
            mock_socket,
            _ws_payload("clear", request_id="clear-parity"),
        )
        ws_data = mock_socket.last_json

        assert ws_data["result"] == http_data


class TestWSHelpers:
    def test_ws_send_json_reports_socket_send_failures(self, caplog) -> None:
        with caplog.at_level(logging.WARNING, logger="xferry"):
            sent = NotepadHandlersMixin._ws_send_json(
                _FailingSocket(),
                {"action": "list", "request_id": "noop", "result": {}},
            )

        assert sent is False
        assert "WebSocket JSON send failed" in caplog.text

    def test_side_effecting_save_surfaces_send_failure(
        self,
        ws_server,
        caplog,
    ):
        payload = _ws_payload(
            "save",
            request_id="save-send-failure",
            input_value={
                "title": "Sentinel",
                "data": base64.b64encode(_VALID_ENCRYPTED_BLOB).decode(),
            },
        )

        with caplog.at_level(logging.WARNING, logger="xferry"):
            with pytest.raises(ConnectionError, match="WebSocket JSON send failed"):
                ws_server._handle_ws_message(_FailingSocket(), payload)

        assert sorted(path.suffix for path in ws_server.notes_dir.iterdir()) == [
            ".enc",
            ".json",
        ]
        assert "WebSocket JSON send failed" in caplog.text

    def test_side_effecting_delete_surfaces_send_failure(
        self,
        ws_server,
        mock_socket,
        caplog,
    ):
        save_payload = _ws_payload(
            "save",
            request_id="delete-send-setup",
            input_value={
                "title": "Delete",
                "data": base64.b64encode(_VALID_ENCRYPTED_BLOB).decode(),
            },
        )
        ws_server._handle_ws_message(mock_socket, save_payload)
        note_id = mock_socket.last_json["result"]["note"]["id"]

        with caplog.at_level(logging.WARNING, logger="xferry"):
            with pytest.raises(ConnectionError, match="WebSocket JSON send failed"):
                ws_server._handle_ws_message(
                    _FailingSocket(),
                    _ws_payload(
                        "delete",
                        request_id="delete-send-failure",
                        input_value={"id": note_id},
                    ),
                )

        assert not (ws_server.notes_dir / f"{note_id}.enc").exists()
        assert "WebSocket JSON send failed" in caplog.text

    def test_side_effecting_clear_surfaces_send_failure(
        self,
        ws_server,
        mock_socket,
        caplog,
    ):
        save_payload = _ws_payload(
            "save",
            request_id="clear-send-setup",
            input_value={
                "title": "Clear",
                "data": base64.b64encode(_VALID_ENCRYPTED_BLOB).decode(),
            },
        )
        ws_server._handle_ws_message(mock_socket, save_payload)
        note_id = mock_socket.last_json["result"]["note"]["id"]

        with caplog.at_level(logging.WARNING, logger="xferry"):
            with pytest.raises(ConnectionError, match="WebSocket JSON send failed"):
                ws_server._handle_ws_message(
                    _FailingSocket(),
                    _ws_payload("clear", request_id="clear-send-failure"),
                )

        assert not (ws_server.notes_dir / f"{note_id}.enc").exists()
        assert "WebSocket JSON send failed" in caplog.text
