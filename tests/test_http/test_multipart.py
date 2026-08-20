"""Strict multipart/form-data parsing behavior for upload handlers."""

import pytest

from xferry.http.multipart import MultipartError, parse_single_file_multipart


def _multipart(
    *parts: bytes,
    boundary: str = "xferry-test",
    close: bool = True,
) -> bytes:
    body = bytearray()
    for part in parts:
        body.extend(f"--{boundary}\r\n".encode())
        body.extend(part)
        body.extend(b"\r\n")
    if close:
        body.extend(f"--{boundary}--\r\n".encode())
    return bytes(body)


def test_accepts_valid_multipart_content_type_header() -> None:
    """Catches header validation applying MIME body invariants to the field value."""
    body = _multipart(
        b'Content-Disposition: form-data; name="file"; filename="x.bin"\r\n\r\nx',
    )

    part = parse_single_file_multipart(
        "multipart/form-data; boundary=xferry-test",
        body,
    )

    assert part.payload == b"x"


def test_parses_one_file_part_and_ignores_scalar_parts() -> None:
    """Catches scalar fields being treated as payload candidates."""
    body = _multipart(
        b'Content-Disposition: form-data; name="note"\r\n\r\nignored',
        (
            b'Content-Disposition: form-data; name="artifact"; filename="sample.bin"\r\n'
            b"Content-Type: application/custom\r\n"
            b"Content-Transfer-Encoding: binary\r\n\r\n"
            b"\x00payload\xff"
        ),
    )

    part = parse_single_file_multipart(
        "multipart/form-data; boundary=xferry-test",
        body,
    )

    assert part.field_name == "artifact"
    assert part.filename == "sample.bin"
    assert part.content_type == "application/custom"
    assert part.payload == b"\x00payload\xff"


@pytest.mark.parametrize("transfer_encoding", [None, "binary", "8bit", "BINARY"])
def test_accepts_only_identity_file_transfer_encodings(
    transfer_encoding: str | None,
) -> None:
    """Catches identity encodings being decoded or rejected."""
    transfer_header = (
        b""
        if transfer_encoding is None
        else f"Content-Transfer-Encoding: {transfer_encoding}\r\n".encode()
    )
    body = _multipart(
        b'Content-Disposition: form-data; name="file"; filename="x.bin"\r\n'
        + transfer_header
        + b"\r\nraw-data"
    )

    part = parse_single_file_multipart(
        "multipart/form-data; boundary=xferry-test",
        body,
    )

    assert part.payload == b"raw-data"


@pytest.mark.parametrize(
    ("content_type", "body"),
    [
        ("multipart/form-data", b"anything"),
        (
            "multipart/form-data; boundary=xferry-test",
            _multipart(
                b'Content-Disposition: form-data; name="note"\r\n\r\nscalar',
            ),
        ),
        (
            "multipart/form-data; boundary=xferry-test",
            _multipart(
                b'Content-Disposition: form-data; name="a"; filename="a.bin"\r\n\r\na',
                b'Content-Disposition: form-data; name="b"; filename="b.bin"\r\n\r\nb',
            ),
        ),
        (
            "multipart/form-data; boundary=xferry-test",
            _multipart(
                b'Content-Disposition: form-data; name="file"; filename="x.bin"\r\n'
                b"Content-Type: multipart/mixed; boundary=inner\r\n\r\n"
                b"--inner--",
            ),
        ),
        (
            "multipart/form-data; boundary=xferry-test",
            _multipart(
                b'Content-Disposition: form-data; name="file"; filename="x.bin"\r\n'
                b"Content-Transfer-Encoding: base64\r\n\r\n"
                b"cmF3",
            ),
        ),
        (
            "multipart/form-data; boundary=xferry-test",
            _multipart(
                b'Content-Disposition: form-data; name="file"; filename="x.bin"\r\n\r\nx',
                close=False,
            ),
        ),
        (
            "multipart/form-data; boundary=xferry-test",
            _multipart(
                b'Content-Disposition form-data; name="file"; filename="x.bin"\r\n\r\nx',
            ),
        ),
    ],
)
def test_rejects_invalid_or_ambiguous_multipart(
    content_type: str,
    body: bytes,
) -> None:
    """Catches malformed, nested, missing, and multiple file candidates."""
    with pytest.raises(MultipartError):
        parse_single_file_multipart(content_type, body)


def test_rejects_empty_file_payload() -> None:
    """Catches a syntactically valid file part with no bytes."""
    body = _multipart(
        b'Content-Disposition: form-data; name="file"; filename="empty.bin"\r\n\r\n',
    )

    with pytest.raises(MultipartError, match="empty"):
        parse_single_file_multipart(
            "multipart/form-data; boundary=xferry-test",
            body,
        )


def test_rejects_boundary_longer_than_multipart_standard_allows() -> None:
    """Catches an invalid oversized boundary being accepted as a valid envelope."""
    boundary = "x" * 71
    body = _multipart(
        b'Content-Disposition: form-data; name="file"; filename="x.bin"\r\n\r\nx',
        boundary=boundary,
    )

    with pytest.raises(MultipartError, match="boundary"):
        parse_single_file_multipart(
            f"multipart/form-data; boundary={boundary}",
            body,
        )


@pytest.mark.parametrize(
    "content_type",
    [
        "multipart/form-data; boundary=xferry-test; boundary=other",
        'multipart/form-data; boundary="xferry-test',
        (
            "multipart/form-data; boundary=xferry-test\r\n"
            "Content-Type: multipart/form-data; boundary=other"
        ),
    ],
)
def test_rejects_malformed_or_ambiguous_content_type(content_type: str) -> None:
    """Catches malformed parameters or a second injected Content-Type being ignored."""
    body = _multipart(
        b'Content-Disposition: form-data; name="file"; filename="x.bin"\r\n\r\nx',
    )

    with pytest.raises(MultipartError, match="Invalid multipart Content-Type"):
        parse_single_file_multipart(content_type, body)


@pytest.mark.parametrize(
    "duplicate_headers",
    [
        (
            b'Content-Disposition: form-data; name="file"; filename="x.bin"\r\n'
            b'Content-Disposition: form-data; name="other"; filename="other.bin"\r\n'
        ),
        (
            b'Content-Disposition: form-data; name="file"; filename="x.bin"\r\n'
            b"Content-Type: application/octet-stream\r\n"
            b"Content-Type: text/plain\r\n"
        ),
        (
            b'Content-Disposition: form-data; name="file"; filename="x.bin"\r\n'
            b"Content-Transfer-Encoding: binary\r\n"
            b"Content-Transfer-Encoding: base64\r\n"
        ),
    ],
)
def test_rejects_duplicate_multipart_singleton_headers(
    duplicate_headers: bytes,
) -> None:
    """Catches a later malformed/unsupported singleton header being ignored."""
    body = _multipart(duplicate_headers + b"\r\npayload")

    with pytest.raises(MultipartError, match="Duplicate multipart"):
        parse_single_file_multipart(
            "multipart/form-data; boundary=xferry-test",
            body,
        )
