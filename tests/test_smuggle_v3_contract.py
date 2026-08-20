"""Contracts for the decomposed SMUGGLE backend."""

from __future__ import annotations

import importlib.util
import json
import os
from concurrent.futures import ThreadPoolExecutor

import pytest

import xferry
import xferry.utils
from tests.conftest import make_request
from tests.server_factory import make_server
from xferry.smuggle import (
    SafeSmuggleBuilderConfig,
    SmuggleArtifactStore,
    SmuggleRequestError,
    SmuggleTempPolicy,
    SmuggleTempQuotaExceeded,
    parse_smuggle_query,
    parse_smuggle_request,
)
from xferry.smuggle.policy import build_smuggle_capabilities


@pytest.mark.parametrize(
    ("kwargs", "field"),
    [
        ({"mode": "CONSTRUCTOR"}, "mode"),
        ({"encryption": "XOR"}, "encryption"),
        ({"payload_encoding": "b64"}, "payload_encoding"),
        ({"trigger_method": "pageshow", "trigger_event": "onpageshow"}, "trigger_method"),
        ({"trigger_method": "BUTTON", "trigger_event": "onauxclick"}, "trigger_method"),
        ({"trigger_method": "button", "trigger_event": "Aux_Click"}, "trigger_event"),
        ({"page_template": "npf-rar-archive-help"}, "page_template"),
        ({"title": "x" * 121}, "title"),
        ({"show_notice": "true"}, "show_notice"),
        ({"delay_ms": True}, "delay_ms"),
    ],
)
def test_direct_builder_rejects_noncanonical_or_unbounded_values(
    kwargs: dict[str, object],
    field: str,
) -> None:
    """Removing builder validation would reopen a parser-bypass path."""
    with pytest.raises(SmuggleRequestError) as exc_info:
        SafeSmuggleBuilderConfig(**kwargs)  # type: ignore[arg-type]

    assert exc_info.value.field == field


@pytest.mark.parametrize("field", ["preset", "cta_label", "delay_ms"])
def test_constructor_rejects_explicit_simple_only_fields(field: str) -> None:
    """Constructor metadata must not report options its renderer ignores."""
    values = {
        "mode": "constructor",
        "preset": "direct",
        "cta_label": "Download",
        "delay_ms": "0",
    }

    with pytest.raises(SmuggleRequestError) as exc_info:
        parse_smuggle_query({"mode": values["mode"], field: values[field]})

    assert exc_info.value.code == "invalid_smuggle_configuration"
    assert exc_info.value.field == field


def test_legacy_smuggling_renderer_is_not_importable_or_public() -> None:
    """Reintroducing the old utility would restore aliases and implicit mode selection."""
    assert importlib.util.find_spec("xferry.utils.smuggling") is None
    assert "generate_smuggling_html" not in xferry.__all__
    assert "generate_smuggling_html" not in xferry.utils.__all__
    assert not hasattr(xferry, "generate_smuggling_html")
    assert not hasattr(xferry.utils, "generate_smuggling_html")


def test_capabilities_have_one_canonical_vocabulary() -> None:
    capabilities = build_smuggle_capabilities()

    assert capabilities["schema_version"] == 1
    assert capabilities["modes"] == ["simple", "constructor"]
    assert capabilities["encryption_modes"] == ["none", "xor", "aes"]
    assert capabilities["defaults"]["payload_encoding"] == "base64"
    assert "b64" not in capabilities["payload_encodings"]
    assert "pageshow" not in capabilities["trigger_events"]
    assert "npf-rar-archive-help" not in capabilities["page_templates"]


@pytest.mark.parametrize(
    ("query", "field"),
    [
        ({"encrypt": "1"}, "encrypt"),
        ({"use_constructor": "1"}, "use_constructor"),
        ({"mode": "constructor", "payload_encoding": "b64"}, "payload_encoding"),
        ({"mode": "CONSTRUCTOR"}, "mode"),
        ({"encryption": "XOR"}, "encryption"),
        ({"show_notice": "true"}, "show_notice"),
        ({"mode": "constructor", "null_byte": "False"}, "null_byte"),
        ({"mode": "constructor", "trigger_method": "pageshow"}, "trigger_method"),
        (
            {"mode": "constructor", "page_template": "npf-rar-archive-help"},
            "page_template",
        ),
    ],
)
def test_parser_rejects_removed_aliases_and_permissive_tokens(
    query: dict[str, str],
    field: str,
) -> None:
    with pytest.raises(SmuggleRequestError) as exc_info:
        parse_smuggle_query(query)

    assert exc_info.value.field == field


def test_constructor_option_never_selects_constructor_implicitly() -> None:
    with pytest.raises(SmuggleRequestError) as exc_info:
        parse_smuggle_query({"payload_encoding": "hex"})

    assert exc_info.value.code == "invalid_smuggle_configuration"
    assert exc_info.value.field == "mode"


def test_duplicate_query_parameter_is_rejected() -> None:
    request = make_request(
        "SMUGGLE",
        "/uploads/source.bin?encryption=xor&encryption=aes",
    )

    with pytest.raises(SmuggleRequestError) as exc_info:
        parse_smuggle_request(request)

    assert exc_info.value.code == "duplicate_smuggle_parameter"
    assert exc_info.value.field == "encryption"


@pytest.mark.parametrize("mode", ["simple", "constructor"])
@pytest.mark.parametrize("encryption", ["none", "xor", "aes"])
def test_http_handler_supports_canonical_mode_and_encryption_matrix(
    tmp_path,
    mode: str,
    encryption: str,
) -> None:
    (tmp_path / "index.html").write_text("<html>ok</html>", encoding="utf-8")
    server = make_server(root_dir=str(tmp_path), quiet=True)
    (server.upload_dir / "source.bin").write_bytes(b"payload")

    response = server.handle_smuggle(
        make_request(
            "SMUGGLE",
            f"/uploads/source.bin?mode={mode}&encryption={encryption}",
        )
    )

    assert response.status_code == 200
    body = json.loads(response.body)
    builder = body["builder"]
    assert builder["schema_version"] == 1
    assert builder["mode"] == mode
    assert builder["encryption"] == encryption
    assert "legacy" not in builder.values()
    if encryption == "none":
        assert "password" not in builder
    else:
        assert isinstance(builder["password"], str)
        assert len(builder["password"]) == 7


@pytest.mark.parametrize(
    ("output_format", "expected_content_type"),
    [
        ("html", "text/html; charset=utf-8"),
        ("htm", "text/html; charset=utf-8"),
        ("shtml", "text/html; charset=utf-8"),
        ("shtm", "text/html; charset=utf-8"),
        ("xhtml", "application/xhtml+xml; charset=utf-8"),
        ("xht", "application/xhtml+xml; charset=utf-8"),
        ("xhtm", "application/xhtml+xml; charset=utf-8"),
        ("xml", "application/xml; charset=utf-8"),
        ("svg", "image/svg+xml; charset=utf-8"),
    ],
)
def test_smuggle_artifact_metadata_matches_get_content_type(
    tmp_path,
    output_format: str,
    expected_content_type: str,
) -> None:
    """A duplicate serving map must not drift from creation metadata."""
    (tmp_path / "index.html").write_text("<html>ok</html>", encoding="utf-8")
    server = make_server(root_dir=str(tmp_path), quiet=True)
    (server.upload_dir / "source.bin").write_bytes(b"payload")

    creation_response = server.handle_smuggle(
        make_request(
            "SMUGGLE",
            f"/uploads/source.bin?mode=constructor&output_format={output_format}",
        )
    )

    assert creation_response.status_code == 200
    creation_body = json.loads(creation_response.body)
    artifact_response = server.handle_get(make_request("GET", creation_body["artifact"]["url"]))

    assert artifact_response.status_code == 200
    assert creation_body["artifact"]["content_type"] == expected_content_type
    assert artifact_response.headers["Content-Type"] == expected_content_type
    assert artifact_response.stream_cleanup is not None
    artifact_response.stream_cleanup()


def test_ping_exposes_the_server_policy_projection(tmp_path) -> None:
    (tmp_path / "index.html").write_text("<html>ok</html>", encoding="utf-8")
    server = make_server(root_dir=str(tmp_path), quiet=True)

    response = server.handle_ping(make_request("PING", "/"))

    assert response.status_code == 200
    body = json.loads(response.body)
    assert body["smuggle_capabilities"] == server.get_smuggle_capabilities()
    assert body["smuggle_capabilities"]["schema_version"] == 1


def test_claimed_artifact_is_not_pruned_to_make_quota_room(tmp_path) -> None:
    tokens = iter(("0000000000000001", "0000000000000002"))
    store = SmuggleArtifactStore(
        tmp_path,
        SmuggleTempPolicy(
            max_age_seconds=None,
            max_file_count=1,
            max_total_bytes=None,
        ),
        token_factory=lambda _size: next(tokens),
    )
    first = store.write(b"first", ".html")
    assert store.claim(first)

    with pytest.raises(SmuggleTempQuotaExceeded):
        store.write(b"second", ".html")

    assert first.read_bytes() == b"first"
    assert store.contains(first)
    store.release(first)


def test_age_cleanup_does_not_delete_claimed_artifact(tmp_path) -> None:
    store = SmuggleArtifactStore(
        tmp_path,
        SmuggleTempPolicy(
            max_age_seconds=10,
            max_file_count=None,
            max_total_bytes=None,
        ),
        token_factory=lambda _size: "0000000000000001",
        clock=lambda: 100.0,
    )
    artifact = store.write(b"claimed", ".html")
    os.utime(artifact, (1.0, 1.0))
    assert store.claim(artifact)

    assert store.cleanup() == 0
    assert artifact.read_bytes() == b"claimed"
    store.release(artifact)


def test_two_concurrent_gets_claim_a_one_shot_artifact_once(tmp_path) -> None:
    (tmp_path / "index.html").write_text("<html>ok</html>", encoding="utf-8")
    server = make_server(root_dir=str(tmp_path), quiet=True)
    artifact = server._write_smuggle_temp_artifact(b"artifact", ".html")
    request = make_request("GET", f"/uploads/{artifact.name}")

    with ThreadPoolExecutor(max_workers=2) as executor:
        responses = list(executor.map(lambda _index: server.handle_get(request), range(2)))

    assert sorted(response.status_code for response in responses) == [200, 404]
    winner = next(response for response in responses if response.status_code == 200)
    assert winner.stream_path == artifact
    assert winner.stream_cleanup is not None
    winner.stream_cleanup()
    assert not artifact.exists()
    assert not server.handler_context.smuggle_temp.snapshot()


def test_server_startup_removes_only_regular_generated_artifacts(tmp_path) -> None:
    (tmp_path / "index.html").write_text("<html>ok</html>", encoding="utf-8")
    uploads = tmp_path / "uploads"
    uploads.mkdir()
    stale = uploads / "smuggle_0123456789abcdef.html"
    stale.write_bytes(b"stale")
    ordinary = uploads / "keep.html"
    ordinary.write_bytes(b"ordinary")
    target = tmp_path / "outside.html"
    target.write_bytes(b"outside")
    symlink = uploads / "smuggle_fedcba9876543210.html"
    symlink.symlink_to(target)

    make_server(root_dir=str(tmp_path), quiet=True)

    assert not stale.exists()
    assert ordinary.read_bytes() == b"ordinary"
    assert symlink.is_symlink()
    assert target.read_bytes() == b"outside"
