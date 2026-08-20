"""Tests for HTTP request parsing."""

from xferry.http.request import HTTPRequest


class TestHTTPRequest:
    """Tests for HTTPRequest class."""

    def test_parse_simple_get_request(self):
        """Test parsing a simple GET request."""
        raw = b"GET /index.html HTTP/1.1\r\nHost: localhost\r\n\r\n"
        request = HTTPRequest(raw)

        assert request.method == "GET"
        assert request.path == "/index.html"
        assert request.http_version == "HTTP/1.1"
        assert request.headers.get("host") == "localhost"

    def test_parse_post_request_with_body(self):
        """Test parsing a POST request with body."""
        raw = (
            b"POST /upload HTTP/1.1\r\n"
            b"Host: localhost\r\n"
            b"Content-Length: 13\r\n"
            b"Content-Type: text/plain\r\n"
            b"\r\n"
            b"Hello, World!"
        )
        request = HTTPRequest(raw)

        assert request.method == "POST"
        assert request.path == "/upload"
        assert request.content_length == 13
        assert request.body == b"Hello, World!"

    def test_parse_url_encoded_path(self):
        """Test parsing URL-encoded paths."""
        raw = b"GET /file%20with%20spaces.txt HTTP/1.1\r\nHost: localhost\r\n\r\n"
        request = HTTPRequest(raw)

        assert request.path == "/file with spaces.txt"

    def test_get_header_case_insensitive(self):
        """Test that header lookup is case-insensitive."""
        raw = b"GET / HTTP/1.1\r\nContent-Type: application/json\r\n\r\n"
        request = HTTPRequest(raw)

        assert request.get_header("content-type") == "application/json"
        assert request.get_header("Content-Type") == "application/json"
        assert request.get_header("CONTENT-TYPE") == "application/json"

    def test_get_header_with_default(self):
        """Test header lookup with default value."""
        raw = b"GET / HTTP/1.1\r\n\r\n"
        request = HTTPRequest(raw)

        assert request.get_header("x-custom", "default") == "default"

    def test_content_type_default(self):
        """Test default content type."""
        raw = b"GET / HTTP/1.1\r\n\r\n"
        request = HTTPRequest(raw)

        assert request.content_type == "application/octet-stream"

    def test_query_params_parsed(self):
        """Test query string parameters are parsed."""
        raw = b"GET /dir?offset=10&limit=50 HTTP/1.1\r\n\r\n"
        request = HTTPRequest(raw)

        assert request.path == "/dir"
        assert request.query_params["offset"] == "10"
        assert request.query_params["limit"] == "50"

    def test_query_params_empty(self):
        """Test missing query string yields empty dict."""
        raw = b"GET /plain HTTP/1.1\r\n\r\n"
        request = HTTPRequest(raw)

        assert request.query_params == {}

    def test_preserves_duplicate_headers_in_wire_order_without_changing_legacy_lookup(self):
        """Duplicate security headers must remain distinguishable after parsing."""
        raw = (
            b"GET / HTTP/1.1\r\nX-Session: first\r\nx-session: second\r\nX-Session: second\r\n\r\n"
        )

        request = HTTPRequest(raw)

        assert request.header_occurrences == (
            ("X-Session", "first"),
            ("x-session", "second"),
            ("X-Session", "second"),
        )
        assert request.get_header_values("X-SESSION") == ("first", "second", "second")
        assert request.headers["x-session"] == "second"

    def test_preserves_raw_header_values_and_obs_fold_for_security_validation(self):
        """Security-sensitive consumers must see padding and folded continuations."""
        raw = b"GET / HTTP/1.1\r\nX-Session:  padded \r\n\tfolded\r\n\r\n"

        request = HTTPRequest(raw)

        assert request.get_header_values("X-Session") == ("padded folded",)
        assert request.get_raw_header_values("X-Session") == ("  padded \r\n\tfolded",)
        assert request.headers["x-session"] == "padded folded"

    def test_preserves_duplicate_and_blank_decoded_query_occurrences(self):
        """Session inputs must retain ordered duplicates that legacy params discard."""
        request = HTTPRequest(b"GET /search?tag=one&empty=&tag=two&flag HTTP/1.1\r\n\r\n")

        assert request.query_occurrences == (
            ("tag", "one"),
            ("empty", ""),
            ("tag", "two"),
            ("flag", ""),
        )
        assert request.query_params == {"tag": "two"}

    def test_preserves_raw_target_and_path_before_percent_decoding(self):
        """Routing keeps its decoded path while security checks can inspect exact spelling."""
        request = HTTPRequest(b"GET /a%2525/%2F?token=%252F&flag= HTTP/1.1\r\n\r\n")

        assert request.raw_target == "/a%2525/%2F?token=%252F&flag="
        assert request.raw_path == "/a%2525/%2F"
        assert request.path == "/a%25//"
        assert request.query_string == "token=%252F&flag="

    def test_missing_http_version_marks_request_invalid(self):
        """Malformed request lines are not treated as dispatchable requests."""
        raw = b"GET /plain\r\nHost: localhost\r\n\r\n"
        request = HTTPRequest(raw)

        assert request.is_valid is False
        assert request.parse_error == "Malformed request line"
        assert request.method == ""
        assert request.path == ""

    def test_extra_request_line_spaces_mark_request_invalid(self):
        """Request-line spacing must not shift method/path/version fields."""
        raw = b"GET  /plain HTTP/1.1\r\nHost: localhost\r\n\r\n"
        request = HTTPRequest(raw)

        assert request.is_valid is False
        assert request.parse_error == "Malformed request line"
        assert request.method == ""
        assert request.path == ""

    def test_invalid_http_version_marks_request_invalid(self):
        """Invalid HTTP versions are rejected by parser validity state."""
        raw = b"GET /plain NOTHTTP\r\nHost: localhost\r\n\r\n"
        request = HTTPRequest(raw)

        assert request.is_valid is False
        assert request.parse_error == "Invalid HTTP version"

    def test_request_target_whitespace_marks_request_invalid(self):
        """Literal whitespace in request-target must not be normalized into a path."""
        raw = b"GET /\t HTTP/1.1\r\nHost: localhost\r\n\r\n"
        request = HTTPRequest(raw)

        assert request.is_valid is False
        assert request.parse_error == "Invalid request target"
        assert request.path == ""

    def test_repr(self):
        """Test string representation."""
        raw = b"GET /test HTTP/1.1\r\n\r\n"
        request = HTTPRequest(raw)

        assert "GET" in repr(request)
        assert "/test" in repr(request)
