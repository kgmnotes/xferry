"""Tests for Content-Length request smuggling prevention.

The server's _receive_request method rejects requests with:
- Multiple different Content-Length header values
- Negative Content-Length values

These checks prevent HTTP request smuggling attacks where
a proxy and backend disagree on request boundaries.
"""

import socket
import threading
import time

from tests.conftest import find_free_port
from tests.server_factory import make_server
from xferry.http.io import receive_request


class SingleRecvSocket:
    """Socket test double that fails if receive_request asks for a body."""

    def __init__(self, first_chunk: bytes):
        self.first_chunk = first_chunk
        self.recv_calls = 0
        self.timeouts: list[float | None] = []

    def settimeout(self, timeout: float | None) -> None:
        self.timeouts.append(timeout)

    def recv(self, _size: int) -> bytes:
        self.recv_calls += 1
        if self.recv_calls == 1:
            return self.first_chunk
        raise AssertionError("receive_request read body after oversized Content-Length")


def _start_server(port: int):
    """Start a server on localhost for testing."""
    server = make_server(
        host="127.0.0.1",
        port=port,
        root_dir="/tmp",
        quiet=True,
    )
    t = threading.Thread(target=server.start, daemon=True)
    t.start()
    # Wait for server to bind
    for _ in range(50):
        time.sleep(0.05)
        if server.running:
            break
    return server


def _send_raw(port: int, raw: bytes, timeout: float = 2.0) -> bytes:
    """Send raw bytes to the server and return the response."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect(("127.0.0.1", port))
        sock.sendall(raw)
        chunks = []
        while True:
            try:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                chunks.append(chunk)
            except TimeoutError:
                break
        return b"".join(chunks)
    finally:
        sock.close()


class TestContentLengthSmuggling:
    """Verify Content-Length smuggling vectors are blocked."""

    def test_oversized_declared_body_rejected_before_body_recv(self):
        """Declared oversized body should be dropped after headers, before body allocation."""
        raw = b"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 1048577\r\n\r\n"
        sock = SingleRecvSocket(raw)

        response = receive_request(sock, max_upload_size=1024 * 1024)

        assert response == b""
        assert sock.recv_calls == 1

    def test_duplicate_different_content_lengths_rejected(self):
        """Two different Content-Length values should be rejected (empty response)."""
        port = find_free_port()
        server = _start_server(port)
        try:
            raw = (
                b"GET / HTTP/1.1\r\n"
                b"Host: localhost\r\n"
                b"Content-Length: 5\r\n"
                b"Content-Length: 10\r\n"
                b"\r\n"
                b"hello"
            )
            response = _send_raw(port, raw)
            # Server should drop the connection (return empty bytes from
            # _receive_request), so no HTTP response is sent back
            assert response == b""
        finally:
            server.stop()

    def test_negative_content_length_rejected(self):
        """Negative Content-Length should be rejected."""
        port = find_free_port()
        server = _start_server(port)
        try:
            raw = b"GET / HTTP/1.1\r\nHost: localhost\r\nContent-Length: -1\r\n\r\n"
            response = _send_raw(port, raw)
            assert response == b""
        finally:
            server.stop()

    def test_duplicate_same_content_length_accepted(self):
        """Duplicate identical Content-Length values should be accepted."""
        port = find_free_port()
        server = _start_server(port)
        try:
            raw = (
                b"PING / HTTP/1.1\r\n"
                b"Host: localhost\r\n"
                b"Content-Length: 0\r\n"
                b"Content-Length: 0\r\n"
                b"\r\n"
            )
            response = _send_raw(port, raw)
            # Should get a valid HTTP response (PING returns 200)
            assert b"HTTP/1.1 200" in response
        finally:
            server.stop()

    def test_normal_single_content_length_accepted(self):
        """Normal request with single Content-Length should work fine."""
        port = find_free_port()
        server = _start_server(port)
        try:
            raw = b"PING / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n"
            response = _send_raw(port, raw)
            assert b"HTTP/1.1 200" in response
        finally:
            server.stop()

    def test_transfer_encoding_chunked_rejected(self):
        """Transfer-Encoding is unsupported and should be dropped."""
        port = find_free_port()
        server = _start_server(port)
        try:
            raw = (
                b"POST / HTTP/1.1\r\n"
                b"Host: localhost\r\n"
                b"Transfer-Encoding: chunked\r\n"
                b"X-File-Name: te.bin\r\n"
                b"\r\n"
                b"5\r\nhello\r\n0\r\n\r\n"
            )
            response = _send_raw(port, raw)
            assert response == b""
        finally:
            server.stop()

    def test_transfer_encoding_with_content_length_rejected(self):
        """Transfer-Encoding plus Content-Length must also be dropped."""
        port = find_free_port()
        server = _start_server(port)
        try:
            raw = (
                b"POST / HTTP/1.1\r\n"
                b"Host: localhost\r\n"
                b"Content-Length: 5\r\n"
                b"Transfer-Encoding: chunked\r\n"
                b"X-File-Name: te-cl.bin\r\n"
                b"\r\n"
                b"5\r\nhello\r\n0\r\n\r\n"
            )
            response = _send_raw(port, raw)
            assert response == b""
        finally:
            server.stop()
