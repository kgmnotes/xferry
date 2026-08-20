"""Workspace performance baselines for upload, INFO, Notepad, receive, and WS slots."""

from __future__ import annotations

import base64
import importlib.util
import itertools
import json
import threading
from pathlib import Path

import pytest

from tests.conftest import make_request
from tests.server_factory import make_server
from xferry.handlers import HandlerMixin
from xferry.http.io import BodyMemoryBudget, receive_request_result
from xferry.notepad_service import (
    DEFAULT_MAX_NOTES,
    NotepadService,
    NoteStoragePolicy,
    SaveNoteRequest,
)
from xferry.storage import UploadStoragePolicy, UploadStorageService

pytestmark = pytest.mark.skipif(
    importlib.util.find_spec("pytest_benchmark") is None,
    reason="pytest-benchmark is required for benchmarks",
)

LARGE_SCAN_CARDINALITIES = (1_000, 10_000)
NOTE_LIMIT_COUNT = DEFAULT_MAX_NOTES
WEBSOCKET_SLOT_COUNT = 64
BENCHMARK_ROUNDS = 20
LARGE_SCAN_ROUNDS = 5


class _BenchmarkHandlerServer(HandlerMixin):
    """Minimal in-process handler host for INFO benchmarks."""

    def __init__(self, root_dir: Path, upload_dir: Path) -> None:
        self.root_dir = root_dir
        self.upload_dir = upload_dir
        self.upload_storage = UploadStorageService(upload_dir)
        self.notes_dir = root_dir / "notes"
        self.notes_dir.mkdir(exist_ok=True)
        self.cors_origin = None
        self.sandbox_mode = False
        self.opsec_mode = False
        self._temp_smuggle_files: set[str] = set()
        self._smuggle_lock = threading.Lock()
        self._notes_lock = threading.Lock()
        self._ecdh_manager = None
        self.method_handlers = self.build_method_handlers()

    def get_metrics(self) -> dict[str, object]:
        return {
            "uptime_seconds": 0,
            "total_requests": 0,
            "total_errors": 0,
            "client_errors": 0,
            "server_errors": 0,
            "bytes_sent": 0,
            "status_counts": {},
        }


class _ChunkedSocket:
    """Small recv-compatible test double that returns a request in body chunks."""

    def __init__(self, chunks: list[bytes]) -> None:
        self._chunks = list(chunks)
        self.timeouts: list[float | None] = []

    def settimeout(self, timeout: float | None) -> None:
        self.timeouts.append(timeout)

    def recv(self, size: int) -> bytes:
        if not self._chunks:
            return b""
        chunk = self._chunks.pop(0)
        if len(chunk) <= size:
            return chunk
        self._chunks.insert(0, chunk[size:])
        return chunk[:size]


def _populate_upload_files(upload_dir: Path, count: int, *, size: int = 16) -> None:
    payload = b"u" * size
    for index in range(count):
        (upload_dir / f"existing-{index:04d}.bin").write_bytes(payload)


def _write_note_pair(notes_dir: Path, index: int, *, size: int = 16) -> str:
    note_id = f"{index:032x}"
    timestamp = f"2026-06-15T00:{index % 60:02d}:00+00:00"
    (notes_dir / f"{note_id}.enc").write_bytes(b"n" * size)
    (notes_dir / f"{note_id}.meta.json").write_text(
        json.dumps(
            {
                "id": note_id,
                "title": f"Benchmark {index}",
                "created_at": timestamp,
                "updated_at": timestamp,
                "size": size,
            }
        ),
        encoding="utf-8",
    )
    return note_id


@pytest.mark.parametrize(
    "file_count",
    LARGE_SCAN_CARDINALITIES,
    ids=("1k-files", "10k-files"),
)
def test_upload_quota_scan_with_aggregate_limits(
    benchmark,
    tmp_path: Path,
    file_count: int,
) -> None:
    upload_dir = tmp_path / "uploads"
    upload_dir.mkdir()
    _populate_upload_files(upload_dir, file_count)
    service = UploadStorageService(
        upload_dir,
        UploadStoragePolicy(max_total_bytes=1024 * 1024, max_file_count=20_000),
    )

    benchmark.pedantic(
        service._check_accepts,
        args=(32,),
        kwargs={"require_free_for_size": True},
        rounds=LARGE_SCAN_ROUNDS,
        iterations=1,
    )


def test_upload_publish_no_limit_policy(benchmark, tmp_path: Path) -> None:
    upload_dir = tmp_path / "uploads"
    upload_dir.mkdir()
    service = UploadStorageService(upload_dir, UploadStoragePolicy())
    counter = itertools.count()
    payload = b"x" * 4096

    def publish_once() -> str:
        path = service.publish_bytes(upload_dir / f"published-{next(counter):04d}.bin", payload)
        try:
            assert path.read_bytes() == payload
            return path.name
        finally:
            path.unlink(missing_ok=True)

    result = benchmark.pedantic(publish_once, rounds=BENCHMARK_ROUNDS, iterations=1)
    assert result.startswith("published-")


@pytest.mark.parametrize(
    "file_count",
    LARGE_SCAN_CARDINALITIES,
    ids=("1k-files", "10k-files"),
)
def test_info_large_directory_listing(
    benchmark,
    tmp_path: Path,
    file_count: int,
) -> None:
    upload_dir = tmp_path / "uploads"
    upload_dir.mkdir()
    _populate_upload_files(upload_dir, file_count)
    server = _BenchmarkHandlerServer(tmp_path, upload_dir)
    request = make_request("INFO", "/uploads?offset=128&limit=64")

    def handle_info() -> int:
        response = server.handle_info(request)
        assert response.status_code == 200
        data = json.loads(response.body)
        assert data["page"]["total_items"] == file_count
        return len(data["contents"])

    result = benchmark.pedantic(handle_info, rounds=LARGE_SCAN_ROUNDS, iterations=1)
    assert result == 64


def test_notepad_save_near_count_limit(benchmark, tmp_path: Path) -> None:
    notes_dir = tmp_path / "notes"
    notes_dir.mkdir()
    for index in range(NOTE_LIMIT_COUNT - 1):
        _write_note_pair(notes_dir, index)

    service = NotepadService(
        notes_dir,
        threading.Lock(),
        storage_policy=NoteStoragePolicy(
            max_total_bytes=1024 * 1024,
            max_note_count=NOTE_LIMIT_COUNT,
            max_listed_notes=NOTE_LIMIT_COUNT,
        ),
    )
    counter = itertools.count(NOTE_LIMIT_COUNT)
    data_b64 = base64.b64encode(bytes(range(28))).decode("ascii")

    def save_once() -> str:
        note_id = f"{next(counter):032x}"
        result = service.save_note(
            SaveNoteRequest(
                title="Benchmark save",
                data_b64=data_b64,
                note_id=note_id,
                create_if_missing=True,
            )
        )
        try:
            assert result.created is True
            return result.note.note_id
        finally:
            (notes_dir / f"{note_id}.enc").unlink(missing_ok=True)
            (notes_dir / f"{note_id}.meta.json").unlink(missing_ok=True)

    note_id = benchmark.pedantic(save_once, rounds=BENCHMARK_ROUNDS, iterations=1)
    assert len(note_id) == 32


def test_notepad_list_near_limit(benchmark, tmp_path: Path) -> None:
    notes_dir = tmp_path / "notes"
    notes_dir.mkdir()
    for index in range(NOTE_LIMIT_COUNT):
        _write_note_pair(notes_dir, index)

    service = NotepadService(
        notes_dir,
        threading.Lock(),
        storage_policy=NoteStoragePolicy(
            max_total_bytes=1024 * 1024,
            max_note_count=NOTE_LIMIT_COUNT,
            max_listed_notes=NOTE_LIMIT_COUNT,
        ),
    )

    def list_notes() -> tuple[int, bool]:
        result = service.list_notes()
        return len(result.notes), result.truncated

    result = benchmark.pedantic(list_notes, rounds=BENCHMARK_ROUNDS, iterations=1)
    assert result == (NOTE_LIMIT_COUNT, False)


def test_chunked_request_receive_loop(benchmark) -> None:
    body = b"r" * 2048
    header = f"POST /upload HTTP/1.1\r\nContent-Length: {len(body)}\r\n\r\n".encode()
    chunks = [header, *[body[index : index + 32] for index in range(0, len(body), 32)]]

    def receive_chunked_body() -> int:
        result = receive_request_result(
            _ChunkedSocket(chunks),
            max_upload_size=len(body),
            body_memory_budget=BodyMemoryBudget(len(body)),
            body_idle_timeout=1.0,
            body_timeout=5.0,
        )
        try:
            assert result.data == header + body
            return len(result.data)
        finally:
            result.release_body_reservation()

    received = benchmark.pedantic(
        receive_chunked_body,
        rounds=BENCHMARK_ROUNDS,
        iterations=1,
    )
    assert received == len(header) + len(body)


def test_websocket_slot_saturation(benchmark, tmp_path: Path) -> None:
    (tmp_path / "index.html").write_text("<html>ok</html>", encoding="utf-8")
    server = make_server(
        root_dir=str(tmp_path),
        quiet=True,
        max_workers=WEBSOCKET_SLOT_COUNT * 2,
        max_websocket_connections=WEBSOCKET_SLOT_COUNT,
    )

    def saturate_slots() -> tuple[int, bool]:
        acquired = 0
        try:
            for _index in range(WEBSOCKET_SLOT_COUNT):
                if server._try_acquire_websocket_slot():
                    acquired += 1
            extra_slot = server._try_acquire_websocket_slot()
            return acquired, extra_slot
        finally:
            for _index in range(acquired):
                server._release_websocket_slot()

    result = benchmark.pedantic(saturate_slots, rounds=BENCHMARK_ROUNDS, iterations=1)
    assert result == (WEBSOCKET_SLOT_COUNT, False)
