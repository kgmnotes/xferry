"""Tests for xferry.http.io.receive_request and header framing guards."""

from __future__ import annotations

import socket
import threading
import time

import pytest

import xferry.http.io as http_io
from xferry.http.io import (
    DEFAULT_MAX_HEADER_SIZE,
    BodyMemoryBudget,
    _has_transfer_encoding,
    _parse_content_length,
    receive_request,
    receive_request_result,
)
from xferry.http.request import HTTPRequest


class TestParseContentLength:
    def test_returns_zero_when_header_absent(self) -> None:
        assert _parse_content_length("Host: x\r\nConnection: close") == 0

    def test_returns_parsed_value(self) -> None:
        assert _parse_content_length("Host: x\r\nContent-Length: 42") == 42

    def test_rejects_negative_value(self) -> None:
        assert _parse_content_length("Content-Length: -1") is None

    def test_rejects_non_integer(self) -> None:
        assert _parse_content_length("Content-Length: abc") is None

    def test_rejects_conflicting_values(self) -> None:
        """Duplicate Content-Length with different values is an HTTP smuggling vector."""
        assert _parse_content_length("Content-Length: 10\r\nContent-Length: 20") is None

    def test_accepts_duplicate_same_value(self) -> None:
        """Duplicate but identical Content-Length is permitted by RFC 7230."""
        assert _parse_content_length("Content-Length: 10\r\nContent-Length: 10") == 10

    def test_case_insensitive(self) -> None:
        assert _parse_content_length("content-length: 5") == 5
        assert _parse_content_length("CONTENT-LENGTH: 7") == 7


class TestTransferEncodingDetection:
    def test_detects_transfer_encoding(self) -> None:
        headers = "Host: x\r\nTransfer-Encoding: chunked\r\nConnection: close"
        assert _has_transfer_encoding(headers) is True

    def test_case_insensitive(self) -> None:
        headers = "Host: x\r\nTRANSFER-ENCODING: chunked"
        assert _has_transfer_encoding(headers) is True

    def test_absent_header_returns_false(self) -> None:
        headers = "Host: x\r\nContent-Length: 0"
        assert _has_transfer_encoding(headers) is False


@pytest.fixture
def socket_pair() -> tuple[socket.socket, socket.socket]:
    server, client = socket.socketpair()
    yield server, client
    server.close()
    client.close()


class SizeRespectingSocket:
    def __init__(self, data: bytes) -> None:
        self._data = bytearray(data)
        self.recv_calls = 0
        self.recv_sizes: list[int] = []
        self.timeouts: list[float | None] = []

    def settimeout(self, timeout: float | None) -> None:
        self.timeouts.append(timeout)

    def recv(self, size: int) -> bytes:
        self.recv_calls += 1
        self.recv_sizes.append(size)
        if not self._data:
            return b""
        chunk = bytes(self._data[:size])
        del self._data[:size]
        return chunk


class ScriptedSocket:
    def __init__(self, chunks: list[bytes | BaseException]) -> None:
        self._chunks = list(chunks)
        self.recv_calls = 0
        self.timeouts: list[float | None] = []

    def settimeout(self, timeout: float | None) -> None:
        self.timeouts.append(timeout)

    def recv(self, _size: int) -> bytes:
        self.recv_calls += 1
        if not self._chunks:
            return b""
        item = self._chunks.pop(0)
        if isinstance(item, BaseException):
            raise item
        return item


class TestReceiveRequest:
    def test_equal_duplicate_content_lengths_remain_observable_after_receive(self) -> None:
        """The permitted framing case must not collapse duplicate Content-Length headers."""
        request = b"POST /upload HTTP/1.1\r\nContent-Length: 3\r\ncontent-length: 3\r\n\r\nabc"
        sock = SizeRespectingSocket(request)

        received = receive_request(sock, max_upload_size=1024)
        parsed = HTTPRequest(received)

        assert parsed.get_header_values("CONTENT-LENGTH") == ("3", "3")

    def test_reads_simple_get_request(
        self,
        socket_pair: tuple[socket.socket, socket.socket],
    ) -> None:
        server, client = socket_pair
        request = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"
        client.sendall(request)

        result = receive_request(server, max_upload_size=1024 * 1024)
        assert result == request

    def test_reads_request_with_body(
        self,
        socket_pair: tuple[socket.socket, socket.socket],
    ) -> None:
        server, client = socket_pair
        body = b"a=1&b=2"
        request = (
            f"POST /form HTTP/1.1\r\nHost: x\r\nContent-Length: {len(body)}\r\n\r\n"
        ).encode() + body
        client.sendall(request)

        result = receive_request(server, max_upload_size=1024 * 1024)
        assert result == request

    def test_rejects_header_over_configured_limit_before_body_recv(self) -> None:
        max_header_size = 32
        request = (
            b"GET / HTTP/1.1\r\nX-Pad: "
            + (b"A" * 128)
            + b"\r\n\r\n"
            + b"body-that-must-not-be-read"
        )
        sock = SizeRespectingSocket(request)
        reasons: list[str] = []

        result = receive_request(
            sock,
            max_upload_size=1024 * 1024,
            max_header_size=max_header_size,
            on_reject=reasons.append,
        )

        assert result == b""
        assert sock.recv_calls == 1
        assert sock.recv_sizes == [max_header_size + len(b"\r\n\r\n")]
        assert reasons == ["header_too_large"]

    def test_accepts_header_at_configured_limit(self) -> None:
        max_header_size = 48
        prefix = b"GET / HTTP/1.1\r\nX-Pad: "
        suffix = b"\r\n"
        padding = b"A" * (max_header_size - len(prefix) - len(suffix))
        request = prefix + padding + suffix + b"\r\n"
        sock = SizeRespectingSocket(request)

        result = receive_request(
            sock,
            max_upload_size=1024 * 1024,
            max_header_size=max_header_size,
        )

        assert result == request

    def test_accepts_max_header_with_body_at_upload_cap(self) -> None:
        body = b"A" * 32
        prefix = f"POST / HTTP/1.1\r\nContent-Length: {len(body)}\r\nX-Pad: ".encode()
        suffix = b"\r\n"
        padding = b"A" * (DEFAULT_MAX_HEADER_SIZE - len(prefix) - len(suffix))
        request = prefix + padding + suffix + b"\r\n" + body
        sock = SizeRespectingSocket(request)
        reasons: list[str] = []

        result = receive_request(
            sock,
            max_upload_size=len(body),
            max_header_size=DEFAULT_MAX_HEADER_SIZE,
            on_reject=reasons.append,
        )

        assert result == request
        assert reasons == []

    def test_header_cap_does_not_limit_body_size(
        self,
        socket_pair: tuple[socket.socket, socket.socket],
    ) -> None:
        server, client = socket_pair
        body = b"A" * 128
        header = f"POST / HTTP/1.1\r\nContent-Length: {len(body)}\r\n\r\n".encode()
        request = header + body
        client.sendall(request)

        result = receive_request(
            server,
            max_upload_size=256,
            max_header_size=len(header) + 8,
        )

        assert result == request

    def test_declared_body_cap_is_independent_from_header_cap(self) -> None:
        request = b"POST / HTTP/1.1\r\nContent-Length: 9\r\n\r\n"
        sock = SizeRespectingSocket(request)
        reasons: list[str] = []

        result = receive_request(
            sock,
            max_upload_size=8,
            max_header_size=1024,
            on_reject=reasons.append,
        )

        assert result == b""
        assert sock.recv_calls == 1
        assert reasons == ["body_too_large"]

    def test_body_memory_budget_reserves_until_caller_releases(self) -> None:
        body = b"hello"
        request = b"POST / HTTP/1.1\r\nContent-Length: 5\r\n\r\n" + body
        budget = BodyMemoryBudget(8)
        sock = SizeRespectingSocket(request)

        result = receive_request_result(
            sock,
            max_upload_size=1024,
            body_memory_budget=budget,
        )

        assert result.data == request
        assert budget.snapshot()["current_bytes"] == len(body)
        assert budget.snapshot()["peak_bytes"] == len(body)

        result.release_body_reservation()
        result.release_body_reservation()
        assert budget.snapshot()["current_bytes"] == 0

    def test_body_memory_budget_rejects_before_reading_body(self) -> None:
        header = b"POST / HTTP/1.1\r\nContent-Length: 10\r\n\r\n"
        sock = ScriptedSocket([header, b"0123456789"])
        budget = BodyMemoryBudget(5)
        reasons: list[str] = []

        result = receive_request_result(
            sock,
            max_upload_size=1024,
            body_memory_budget=budget,
            on_reject=reasons.append,
        )

        assert result.data == b""
        assert result.rejection_reason == "body_memory_budget_exceeded"
        assert sock.recv_calls == 1
        assert reasons == ["body_memory_budget_exceeded"]
        assert budget.snapshot() == {
            "max_bytes": 5,
            "current_bytes": 0,
            "peak_bytes": 0,
            "rejected": 1,
        }

    def test_body_memory_budget_released_on_incomplete_body(self) -> None:
        header = b"POST / HTTP/1.1\r\nContent-Length: 10\r\n\r\n"
        sock = ScriptedSocket([header, b"12345", b""])
        budget = BodyMemoryBudget(10)
        reasons: list[str] = []

        result = receive_request_result(
            sock,
            max_upload_size=1024,
            body_memory_budget=budget,
            on_reject=reasons.append,
        )

        assert result.data == b""
        assert result.rejection_reason == "body_incomplete"
        assert reasons == ["body_incomplete"]
        assert budget.snapshot()["current_bytes"] == 0

    def test_body_memory_budget_released_when_recv_raises_after_reservation(self) -> None:
        header = b"POST / HTTP/1.1\r\nContent-Length: 10\r\n\r\n"
        sock = ScriptedSocket([header, ConnectionResetError("reset")])
        budget = BodyMemoryBudget(10)

        with pytest.raises(ConnectionResetError):
            receive_request_result(
                sock,
                max_upload_size=1024,
                body_memory_budget=budget,
            )

        assert budget.snapshot()["current_bytes"] == 0
        assert budget.snapshot()["peak_bytes"] == 10

    def test_body_idle_timeout_rejects_stalled_body(
        self,
        socket_pair: tuple[socket.socket, socket.socket],
    ) -> None:
        server, client = socket_pair
        client.sendall(b"POST /slow HTTP/1.1\r\nContent-Length: 10\r\n\r\nx")
        reasons: list[str] = []

        start = time.monotonic()
        result = receive_request(
            server,
            max_upload_size=1024,
            body_idle_timeout=0.05,
            on_reject=reasons.append,
        )
        elapsed = time.monotonic() - start

        assert result == b""
        assert elapsed < 1.0
        assert reasons == ["body_idle_timeout"]

    def test_body_total_timeout_rejects_when_idle_timeout_disabled(
        self,
        socket_pair: tuple[socket.socket, socket.socket],
    ) -> None:
        server, client = socket_pair
        client.sendall(b"POST /slow HTTP/1.1\r\nContent-Length: 10\r\n\r\nx")
        reasons: list[str] = []

        start = time.monotonic()
        result = receive_request(
            server,
            max_upload_size=1024,
            body_idle_timeout=None,
            body_timeout=0.05,
            on_reject=reasons.append,
        )
        elapsed = time.monotonic() - start

        assert result == b""
        assert elapsed < 1.0
        assert reasons == ["body_timeout"]

    def test_body_rate_rejects_trickle_when_idle_and_total_timeout_disabled(
        self,
        socket_pair: tuple[socket.socket, socket.socket],
    ) -> None:
        server, client = socket_pair
        client.sendall(b"POST /slow HTTP/1.1\r\nContent-Length: 10\r\n\r\nx")
        reasons: list[str] = []

        result = receive_request(
            server,
            max_upload_size=1024,
            body_idle_timeout=None,
            body_timeout=None,
            body_min_rate_bytes_per_second=100_000.0,
            on_reject=reasons.append,
        )

        assert result == b""
        assert reasons == ["body_rate_too_slow"]

    def test_disabled_body_thresholds_clear_inherited_socket_timeout(self) -> None:
        header = b"POST / HTTP/1.1\r\nContent-Length: 10\r\n\r\n"
        sock = ScriptedSocket([header, b""])

        result = receive_request_result(
            sock,
            max_upload_size=1024,
            body_idle_timeout=None,
            body_timeout=None,
            body_min_rate_bytes_per_second=0,
        )

        assert result.data == b""
        assert result.rejection_reason == "body_incomplete"
        assert sock.timeouts[-1] is None

    def test_total_timeout_retry_does_not_fall_back_to_idle_timeout(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        sock = ScriptedSocket([b"POST / HTTP/1.1\r\nContent-Length: 10\r\n\r\nx", TimeoutError()])
        reasons: list[str] = []
        timeline = iter([0.0, 0.0, 0.0, 0.049, 0.049, 0.051])

        monkeypatch.setattr(http_io.time, "monotonic", lambda: next(timeline))

        result = receive_request_result(
            sock,
            max_upload_size=1024,
            body_idle_timeout=None,
            body_timeout=0.05,
            on_reject=reasons.append,
        )

        assert result.data == b""
        assert result.rejection_reason == "body_timeout"
        assert reasons == ["body_timeout"]

    def test_slow_but_valid_body_can_be_allowed_by_config(
        self,
        socket_pair: tuple[socket.socket, socket.socket],
    ) -> None:
        server, client = socket_pair
        header = b"POST /slow HTTP/1.1\r\nContent-Length: 4\r\n\r\n"
        request = header + b"slow"

        def sender() -> None:
            client.sendall(header + b"s")
            time.sleep(0.05)
            client.sendall(b"low")

        thread = threading.Thread(target=sender)
        thread.start()

        result = receive_request(
            server,
            max_upload_size=1024,
            body_idle_timeout=0.5,
            body_timeout=2.0,
        )
        thread.join(timeout=1.0)

        assert result == request

    def test_body_memory_budget_released_on_idle_timeout(self) -> None:
        header = b"POST / HTTP/1.1\r\nContent-Length: 10\r\n\r\n"
        sock = ScriptedSocket([header, TimeoutError()])
        budget = BodyMemoryBudget(10)
        reasons: list[str] = []

        result = receive_request_result(
            sock,
            max_upload_size=1024,
            body_idle_timeout=0.5,
            body_memory_budget=budget,
            on_reject=reasons.append,
        )

        assert result.data == b""
        assert result.rejection_reason == "body_idle_timeout"
        assert reasons == ["body_idle_timeout"]
        assert budget.snapshot()["current_bytes"] == 0

    def test_rejects_request_exceeding_size_limit(
        self,
        socket_pair: tuple[socket.socket, socket.socket],
    ) -> None:
        server, client = socket_pair
        body = b"A" * (200 * 1024)  # 200 KB
        request = (
            f"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: {len(body)}\r\n\r\n"
        ).encode() + body

        # Send in a background thread so we don't deadlock on the buffer
        def sender() -> None:
            try:
                client.sendall(request)
            except OSError:
                pass

        t = threading.Thread(target=sender)
        t.start()

        result = receive_request(server, max_upload_size=64 * 1024)
        t.join(timeout=2)

        assert result == b""

    def test_rejects_conflicting_content_length(
        self,
        socket_pair: tuple[socket.socket, socket.socket],
    ) -> None:
        server, client = socket_pair
        request = (
            b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\nContent-Length: 10\r\n\r\nhello"
        )
        client.sendall(request)

        result = receive_request(server, max_upload_size=1024 * 1024)
        assert result == b""

    def test_rejects_transfer_encoding_without_content_length(
        self,
        socket_pair: tuple[socket.socket, socket.socket],
    ) -> None:
        server, client = socket_pair
        request = (
            b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n"
            b"5\r\nhello\r\n0\r\n\r\n"
        )
        client.sendall(request)

        result = receive_request(server, max_upload_size=1024 * 1024)
        assert result == b""

    def test_rejects_transfer_encoding_with_content_length(
        self,
        socket_pair: tuple[socket.socket, socket.socket],
    ) -> None:
        server, client = socket_pair
        request = (
            b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n"
            b"Transfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n"
        )
        client.sendall(request)

        result = receive_request(server, max_upload_size=1024 * 1024)
        assert result == b""

    def test_timeout_when_no_data(
        self,
        socket_pair: tuple[socket.socket, socket.socket],
    ) -> None:
        server, _client = socket_pair
        # Don't send anything; receiver should time out and return empty
        start = time.monotonic()
        result = receive_request(server, max_upload_size=1024 * 1024, idle_timeout=0.1)
        elapsed = time.monotonic() - start

        assert result == b""
        assert elapsed < 2.0  # quick timeout, not the 30 s header budget
