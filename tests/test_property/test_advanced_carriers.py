"""Property-style coverage for canonical Advanced upload carriers."""

from __future__ import annotations

import base64
import hashlib
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from tests.conftest import make_request
from xferry.advanced_sessions import (
    AdvancedSession,
    AdvancedSessionDispatch,
    AdvancedSessionPrincipal,
)
from xferry.handlers import HandlerMixin


class PropertyUploadServer(HandlerMixin):
    """Minimal real handler composition for Advanced carrier properties."""

    def __init__(self, root_dir: Path, upload_dir: Path) -> None:
        self.root_dir = root_dir
        self.upload_dir = upload_dir
        self.notes_dir = root_dir / "notes"
        self.notes_dir.mkdir(exist_ok=True)
        self.cors_origin = None
        self.cors_origins = ()
        self.sandbox_mode = False
        self.opsec_mode = False
        self._temp_smuggle_files: set[str] = set()
        self._smuggle_lock = threading.Lock()
        self._notes_lock = threading.Lock()
        self._ecdh_manager = None
        self.method_handlers = self.build_method_handlers()


def _bind_dispatch(request):
    now = datetime(2026, 8, 14, 12, 0, tzinfo=timezone.utc)
    request.advanced_session_dispatch = AdvancedSessionDispatch(
        session=AdvancedSession(
            prefix="/advanced",
            decoder="auto",
            diagnostic_headers=False,
            created_at=now,
            expires_at=now + timedelta(hours=1),
            last_activity_at=now,
        ),
        principal=AdvancedSessionPrincipal("no_auth", None),
        direct_peer=None,
    )
    request.advanced_session_admission_prepared = True
    return request


@given(
    payload=st.binary(min_size=1, max_size=96),
    chunk_size=st.integers(min_value=1, max_value=12),
)
@settings(
    max_examples=30,
    suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture],
    deadline=None,
)
def test_header_chunks_roundtrip_arbitrary_bytes_in_wire_order(
    temp_dir: Path,
    upload_dir: Path,
    payload: bytes,
    chunk_size: int,
) -> None:
    """Catches chunk concatenation using dict order, default encodings, or aliases."""
    server = PropertyUploadServer(temp_dir, upload_dir)
    encoded = base64.b64encode(payload).decode("ascii")
    chunks = [encoded[index : index + chunk_size] for index in range(0, len(encoded), chunk_size)]
    name = f"chunk-{hashlib.sha256(payload).hexdigest()[:16]}-{chunk_size}.bin"
    headers = {
        "X-XFerry-Encoding": "base64",
        "X-XFerry-Encryption": "none",
        "X-XFerry-Name": name,
    }
    headers.update({f"X-XFerry-Data-{index}": chunk for index, chunk in enumerate(chunks)})

    response = server.handle_advanced_upload(
        _bind_dispatch(make_request("POST", "/advanced", headers=headers))
    )

    assert response.status_code == 201
    assert (upload_dir / name).read_bytes() == payload
