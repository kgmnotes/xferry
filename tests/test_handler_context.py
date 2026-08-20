"""Focused ownership and concurrency checks for the built-in handler context."""

from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import fields
from pathlib import Path

from tests.server_factory import make_server
from xferry.handlers.base import BaseHandler
from xferry.handlers.context import HandlerRuntimeContext, SmuggleTempCoordinator
from xferry.metrics import MetricsCollector
from xferry.storage import UploadStorageService

REPO_ROOT = Path(__file__).resolve().parents[1]


def test_handler_runtime_context_has_only_documented_dependencies(tmp_path: Path) -> None:
    upload_dir = tmp_path / "uploads"
    upload_dir.mkdir()
    storage = UploadStorageService(upload_dir)
    metrics = MetricsCollector()
    context = HandlerRuntimeContext(
        upload_dir=upload_dir,
        upload_storage=storage,
        metrics=metrics,
        smuggle_temp=SmuggleTempCoordinator(),
    )

    assert [field.name for field in fields(HandlerRuntimeContext)] == [
        "upload_dir",
        "upload_storage",
        "metrics",
        "smuggle_temp",
    ]
    assert context.upload_dir is upload_dir
    assert context.upload_storage is storage
    assert context.metrics is metrics
    assert {name for name in dir(context.smuggle_temp) if not name.startswith("_")} == {
        "contains",
        "discard",
        "remove_all_registered",
        "snapshot",
        "transaction",
    }


def test_coordinator_wraps_existing_server_state_without_copying_it(tmp_path: Path) -> None:
    lock = threading.Lock()
    registered_paths: set[str] = set()
    coordinator = SmuggleTempCoordinator(lock=lock, paths=registered_paths)
    artifact = tmp_path / "smuggle_0123456789abcdef.html"

    with coordinator.transaction() as registry:
        registry.add(artifact)

    assert registered_paths == {str(artifact)}
    registered_paths.add(str(tmp_path / "smuggle_fedcba9876543210.svg"))
    assert coordinator.contains(artifact)
    assert coordinator.snapshot() == frozenset(registered_paths)


def test_coordinator_serializes_parallel_registry_updates(tmp_path: Path) -> None:
    coordinator = SmuggleTempCoordinator()
    paths = [tmp_path / f"smuggle_{index:016x}.html" for index in range(128)]

    def register(path: Path) -> None:
        with coordinator.transaction() as registry:
            registry.add(path)

    with ThreadPoolExecutor(max_workers=16) as executor:
        list(executor.map(register, paths))

    assert coordinator.snapshot() == frozenset(str(path) for path in paths)

    with ThreadPoolExecutor(max_workers=16) as executor:
        list(executor.map(coordinator.discard, paths))

    assert coordinator.snapshot() == frozenset()


def test_coordinator_shutdown_cleanup_unlinks_and_forgets_registered_files(
    tmp_path: Path,
) -> None:
    coordinator = SmuggleTempCoordinator()
    paths = [
        tmp_path / "smuggle_0123456789abcdef.html",
        tmp_path / "smuggle_fedcba9876543210.svg",
    ]
    for path in paths:
        path.write_text("artifact", encoding="utf-8")
        with coordinator.transaction() as registry:
            registry.add(path)

    assert coordinator.remove_all_registered() == 2
    assert coordinator.snapshot() == frozenset()
    assert all(not path.exists() for path in paths)


def test_server_smuggle_creation_and_cleanup_remain_serialized(tmp_path: Path) -> None:
    server = make_server(root_dir=str(tmp_path), quiet=True)

    with ThreadPoolExecutor(max_workers=8) as executor:
        paths = list(
            executor.map(
                lambda index: server._write_smuggle_temp_artifact(
                    f"artifact-{index}".encode(),
                    ".html",
                ),
                range(32),
            )
        )

    assert len(set(paths)) == 32
    assert server.handler_context.smuggle_temp.snapshot() == frozenset(str(path) for path in paths)
    assert all(path.exists() for path in paths)
    assert server.cleanup_smuggle_temp_artifacts(remove_all=True) == 32
    assert server.handler_context.smuggle_temp.snapshot() == frozenset()
    assert all(not path.exists() for path in paths)


def test_base_handler_fallback_reuses_legacy_stub_objects(tmp_path: Path) -> None:
    class StubHandler(BaseHandler):
        pass

    handler = StubHandler()
    handler.root_dir = tmp_path
    handler.upload_dir = tmp_path / "uploads"
    handler.upload_dir.mkdir()
    handler.notes_dir = tmp_path / "notes"
    handler.notes_dir.mkdir()
    handler._metrics = MetricsCollector()
    handler._smuggle_lock = threading.Lock()
    handler._temp_smuggle_files = set()

    context = handler._get_handler_context()
    artifact = handler.upload_dir / "smuggle_0123456789abcdef.html"
    handler._temp_smuggle_files.add(str(artifact))

    assert context.upload_dir is handler.upload_dir
    assert context.upload_storage is handler._get_upload_storage()
    assert context.metrics is handler._metrics
    assert context.smuggle_temp.contains(artifact)
    assert handler._get_handler_context() is context


def test_files_and_smuggle_handlers_do_not_reach_server_temp_fields() -> None:
    files_source = (REPO_ROOT / "xferry" / "handlers" / "files.py").read_text(encoding="utf-8")
    smuggle_source = (REPO_ROOT / "xferry" / "handlers" / "smuggle.py").read_text(encoding="utf-8")
    server_source = (REPO_ROOT / "xferry" / "server.py").read_text(encoding="utf-8")

    for source in (files_source, smuggle_source):
        assert "_smuggle_lock" not in source
        assert "_temp_smuggle_files" not in source

    assert "HandlerRuntimeContext(" in server_source
    assert "SmuggleTempCoordinator(" in server_source
    assert "self.get_smuggle_temp_usage()" in server_source
    assert "self.handler_context.smuggle_temp.remove_all_registered()" in server_source
