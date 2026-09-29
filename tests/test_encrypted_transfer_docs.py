"""Public documentation contract for encrypted streaming transfers."""

from __future__ import annotations

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]


def _read(path: str) -> str:
    return (REPO_ROOT / path).read_text(encoding="utf-8")


def test_api_documents_exact_euf_v1_wire_and_error_contract() -> None:
    api = _read("API.md")

    assert "## Encrypted Streaming Transfers (EUF v1)" in api
    for route in (
        "GET /_xferry/encrypted-uploads",
        "PUT /_xferry/encrypted-uploads/{id}",
        "GET /_xferry/encrypted-uploads/{id}",
        "DELETE /_xferry/encrypted-uploads/{id}",
        "PUT /_xferry/encrypted-uploads/{id}/chunks/{index}",
        "POST /_xferry/encrypted-uploads/{id}/complete",
        "GET /_xferry/encrypted-files",
        "GET /_xferry/encrypted-files/{id}",
        "DELETE /_xferry/encrypted-files/{id}",
        "GET /_xferry/encrypted-files/{id}/data",
        "POST /_xferry/encrypted-files/{id}/decrypt",
    ):
        assert route in api

    for field in (
        "`version`",
        "`plaintext_size`",
        "`ciphertext_size`",
        "`chunk_size`",
        "`chunk_count`",
        "`salt`",
        "`nonce_prefix`",
        "`encrypted_metadata`",
        "`received_chunks`",
        "`resume_mac`",
        "`content_key`",
    ):
        assert field in api

    for protocol_literal in (
        "PBKDF2-HMAC-SHA256",
        "600,000",
        "HKDF-SHA256",
        "xferry-euf-v1/content",
        "xferry-euf-v1/resume",
        "AES-256-GCM",
        "8 MiB",
        "XFERRY-EUF1-META\\0",
        "XFERRY-EUF1-CHUNK\\0",
        "XFERRY-EUF1-RESUME\\0",
        "unpadded base64url",
        "X-XFerry-Chunk-MAC",
    ):
        assert protocol_literal in api

    for error_code in (
        "resource_not_found",
        "method_not_allowed",
        "unsupported_media_type",
        "malformed_json",
        "missing_field",
        "invalid_field",
        "payload_too_large",
        "storage_quota_exceeded",
        "encrypted_file_conflict",
        "encrypted_chunk_conflict",
        "encrypted_file_incomplete",
        "server_decryption_forbidden",
        "decryption_failed",
    ):
        assert f"`{error_code}`" in api

    assert '"enabled": false' in api
    assert '"parallel_chunks": 2' in api
    assert '"browser_decryption": true' in api
    assert '"server_decryption": true' in api


def test_operations_document_configuration_recovery_and_resource_smoke() -> None:
    operations = _read("docs/operations.md")

    for snippet in (
        "encrypted_uploads = true",
        "encrypted_upload_max_size_mb = 2048",
        "encrypted_upload_incomplete_ttl_seconds = 86400",
        "uploads/.xferry-encrypted/",
        ".xferry/encrypted-uploads/",
        "partial -> committing -> complete",
        "XFERRY_RUN_2GIB_SMOKE=1",
        "peak_rss_bytes",
    ):
        assert snippet in operations
    assert "disabled by default" in operations
    assert "ciphertext" in operations
    assert "plaintext" in operations


def test_frontend_and_threat_model_document_key_boundaries() -> None:
    frontend = _read("docs/frontend-contract.md")
    threat_model = _read("docs/threat-model.md")

    for snippet in (
        "encrypted-transfer-crypto.js",
        "encrypted-transfer.js",
        "File System Access API",
        "IndexedDB",
        "K_content",
        "K_resume",
        "two chunks",
    ):
        assert snippet in frontend
    assert "passwords, keys, salts, encrypted metadata, or filenames" in frontend

    for snippet in (
        "client-encrypted file ciphertext",
        "malicious or compromised xferry host",
        "one-shot server decryption",
        "TLS or a direct loopback peer",
        "compromised browser",
    ):
        assert snippet in threat_model
    assert "does not know the password or content key by default" in threat_model


def test_encrypted_transfer_adr_navigation_and_changelog_are_current() -> None:
    adr = _read("docs/ADR/ADR-011-encrypted-streaming-transfers.md")
    adr_index = _read("docs/ADR/README.md")
    mkdocs = _read("mkdocs.yml")
    changelog = _read("CHANGELOG.md")

    assert "# ADR-011: Client-encrypted streaming transfers" in adr
    assert "**Status:** accepted" in adr
    for snippet in (
        "EUF v1",
        "8 MiB",
        "parallelism of two",
        "disabled by default",
        "server-side decryption",
    ):
        assert snippet in adr
    assert "ADR-011" in adr_index
    assert "ADR/ADR-011-encrypted-streaming-transfers.md" in mkdocs
    assert "resumable client-encrypted streaming transfers" in changelog


def test_generated_api_and_changelog_mirrors_are_synchronized() -> None:
    assert _read("docs/api.md") == (
        "<!-- Generated from ../API.md by tools/sync_docs.py. "
        "Edit API.md and rerun the sync tool. -->\n\n"
        + _read("API.md").replace("(docs/ADR/", "(ADR/")
    )
    assert _read("docs/changelog.md") == (
        "<!-- Generated from ../CHANGELOG.md by tools/sync_docs.py. "
        "Edit CHANGELOG.md and rerun the sync tool. -->\n\n" + _read("CHANGELOG.md")
    )
