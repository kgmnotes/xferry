"""Minimal Secure Notepad client for the current NOTE API.

Usage:
    python examples/notepad_client.py --url http://127.0.0.1:8080 \
                                      --title "Example Note" \
                                      --text "Hello secret world"

Optional:
    --note-id <hex>    Create or update one stable, retry-safe note identity.

Requires `cryptography`, which is installed with the default `xferry` package.
"""

from __future__ import annotations

import argparse
import base64
import http.client
import json
import os
import re
import sys
from urllib.parse import urlsplit

try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
except ImportError:
    print("This example requires 'cryptography'. Install or repair the xferry environment.")
    sys.exit(1)


_NOTE_ID_RE = re.compile(r"^[0-9a-f]{32}$")
_NOTEPAD_HKDF_SALT = b"\x00" * 32
_NOTEPAD_HKDF_INFO = b"notepad-e2e-key"


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64d(text: str) -> bytes:
    return base64.b64decode(text, validate=True)


def _decode_response_object(raw: bytes, request_path: str) -> dict[str, object]:
    if not raw:
        raise RuntimeError(f"NOTE {request_path} returned an empty JSON response")
    try:
        result = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"NOTE {request_path} returned invalid JSON") from exc
    if not isinstance(result, dict):
        raise RuntimeError(f"NOTE {request_path} returned a non-object JSON response")
    return result


def _note_request(
    base_url: str,
    path: str,
    *,
    payload: dict[str, object] | None = None,
    headers: dict[str, str] | None = None,
) -> dict[str, object]:
    parsed = urlsplit(base_url.rstrip("/"))
    if parsed.scheme not in ("http", "https"):
        raise RuntimeError("URL must use http:// or https://")
    if not parsed.hostname:
        raise RuntimeError("URL must include a hostname")

    data = None
    request_headers: dict[str, str] = {}
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        request_headers["Content-Type"] = "application/json"
    if headers:
        request_headers.update(headers)

    conn_cls = (
        http.client.HTTPSConnection if parsed.scheme == "https" else http.client.HTTPConnection
    )
    conn = conn_cls(parsed.hostname, parsed.port, timeout=10)
    request_path = f"{parsed.path.rstrip('/')}{path}" if parsed.path else path

    try:
        conn.request("NOTE", request_path, body=data, headers=request_headers)
        resp = conn.getresponse()
        raw = resp.read()
    finally:
        conn.close()

    result = _decode_response_object(raw, request_path)
    if resp.status >= 400:
        error = result.get("error")
        if not isinstance(error, dict):
            raise RuntimeError(
                f"NOTE {request_path} failed: HTTP {resp.status} invalid error envelope"
            )
        code = error.get("code")
        message = error.get("message")
        if not isinstance(code, str) or not isinstance(message, str):
            raise RuntimeError(
                f"NOTE {request_path} failed: HTTP {resp.status} invalid error envelope"
            )
        raise RuntimeError(f"NOTE {request_path} failed: HTTP {resp.status} {code}: {message}")

    return result


def fetch_server_public_key(url: str) -> bytes:
    payload = _note_request(url, "/notes/key")
    key = payload.get("key")
    if not isinstance(key, dict) or key.get("available") is not True:
        raise RuntimeError("Server reports that ECDH is unavailable")
    public_key = key.get("public_key")
    if not isinstance(public_key, str) or not public_key:
        raise RuntimeError("Server did not return a usable public key")
    return _b64d(public_key)


def exchange_session(
    url: str,
    client_pub_raw: bytes,
) -> tuple[str, bytes]:
    payload = _note_request(
        url,
        "/notes/exchange",
        payload={"client_public_key": _b64(client_pub_raw)},
    )
    session = payload.get("session")
    session_id = session.get("id") if isinstance(session, dict) else None
    server_public_key = payload.get("server_public_key")
    if not isinstance(session_id, str) or _NOTE_ID_RE.fullmatch(session_id) is None:
        raise RuntimeError("Server did not return a session ID")
    if not isinstance(server_public_key, str) or not server_public_key:
        raise RuntimeError("Server did not return an exchange public key")
    return session_id, _b64d(server_public_key)


def derive_shared_key(server_pub_raw: bytes, client_priv: ec.EllipticCurvePrivateKey) -> bytes:
    server_pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), server_pub_raw)
    shared = client_priv.exchange(ec.ECDH(), server_pub)
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=_NOTEPAD_HKDF_SALT,
        info=_NOTEPAD_HKDF_INFO,
    ).derive(shared)


def encrypt_note(text: str, key: bytes) -> bytes:
    nonce = os.urandom(12)
    ciphertext = AESGCM(key).encrypt(nonce, text.encode("utf-8"), associated_data=None)
    return nonce + ciphertext


def decrypt_note(blob: bytes, key: bytes) -> str:
    if len(blob) < 12 + 16:
        raise RuntimeError("Encrypted note is too short to contain nonce + tag")
    nonce = blob[:12]
    ciphertext = blob[12:]
    plaintext = AESGCM(key).decrypt(nonce, ciphertext, associated_data=None)
    return plaintext.decode("utf-8")


def save_note(
    url: str,
    *,
    title: str,
    text: str,
    key: bytes,
    session_id: str,
    note_id: str | None,
) -> dict[str, object]:
    encrypted_blob = encrypt_note(text, key)
    body: dict[str, object] = {
        "title": title,
        "data": _b64(encrypted_blob),
    }
    if note_id:
        body["id"] = note_id
        body["create_if_missing"] = True
    body["session_id"] = session_id
    return _note_request(url, "/notes?action=save", payload=body)


def load_note(url: str, note_id: str) -> dict[str, object]:
    return _note_request(url, f"/notes/{note_id}?action=load")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--url", required=True, help="Base server URL, for example http://127.0.0.1:8080"
    )
    parser.add_argument("--title", default="Example Note", help="Note title to save")
    parser.add_argument("--text", required=True, help="Plaintext note content to encrypt and save")
    parser.add_argument(
        "--note-id",
        help="Optional 32-lowercase-hex stable ID to create or update idempotently",
    )
    args = parser.parse_args()

    if args.note_id and _NOTE_ID_RE.fullmatch(args.note_id) is None:
        parser.error("--note-id must be exactly 32 lowercase hex characters")

    advertised_server_key = fetch_server_public_key(args.url)
    client_priv = ec.generate_private_key(ec.SECP256R1())
    client_pub_raw = client_priv.public_key().public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint,
    )

    session_id, exchanged_server_key = exchange_session(args.url, client_pub_raw)
    if exchanged_server_key != advertised_server_key:
        raise RuntimeError("Server public key changed between /notes/key and /notes/exchange")

    shared_key = derive_shared_key(exchanged_server_key, client_priv)
    saved = save_note(
        args.url,
        title=args.title,
        text=args.text,
        key=shared_key,
        session_id=session_id,
        note_id=args.note_id,
    )

    saved_note = saved.get("note")
    saved_note_id = saved_note.get("id") if isinstance(saved_note, dict) else None
    if not isinstance(saved_note_id, str) or _NOTE_ID_RE.fullmatch(saved_note_id) is None:
        raise RuntimeError(f"Unexpected save response: {saved!r}")

    loaded = load_note(args.url, saved_note_id)
    loaded_note = loaded.get("note")
    encrypted_data = loaded.get("data")
    loaded_note_id = loaded_note.get("id") if isinstance(loaded_note, dict) else None
    if (
        not isinstance(loaded_note, dict)
        or loaded_note_id != saved_note_id
        or not isinstance(encrypted_data, str)
        or not encrypted_data
    ):
        raise RuntimeError(f"Unexpected load response: {loaded!r}")

    decrypted_text = decrypt_note(_b64d(encrypted_data), shared_key)

    print(f"Saved note: {saved_note_id}")
    print(f"Title: {loaded_note.get('title', args.title)}")
    print(f"Decrypted text: {decrypted_text}")


if __name__ == "__main__":
    main()
