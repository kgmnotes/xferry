"""Certificate lifetime scheduling and portable ACME cache serialization."""

from __future__ import annotations

import datetime as dt
import hashlib
import importlib
import json
import os
import stat
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from cryptography import x509

UTC = dt.timezone.utc


def certificate_schedule(payload: bytes) -> tuple[str, dt.datetime, dt.datetime]:
    """Return fingerprint, fallback renewal time and expiry for any cert lifetime."""
    cert = x509.load_pem_x509_certificate(payload)
    start, end = cert.not_valid_before_utc, cert.not_valid_after_utc
    lifetime = end - start
    window = (
        lifetime / 2
        if lifetime < dt.timedelta(days=10)
        else min(dt.timedelta(days=30), lifetime / 3)
    )
    return hashlib.sha256(payload).hexdigest(), end - window, end


def load_schedule(path: Path, fingerprint: str) -> dict[str, object]:
    """Read bounded, non-secret state; a different certificate resets the schedule."""
    try:
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > 4096:
            return {}
        value = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(value, dict) and value.get("fingerprint") == fingerprint:
            return value
    except (OSError, ValueError):
        pass
    return {}


@contextmanager
def acme_cache_lock(root: Path, stop: threading.Event | None = None) -> Iterator[None]:
    """Serialize account and certificate writers across processes, with cancellation."""
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(root / ".acme.lock", flags, 0o600)
    event = stop or threading.Event()
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise RuntimeError("unsafe ACME cache lock")
        if os.name == "nt":  # pragma: no cover - native Windows CI
            msvcrt = importlib.import_module("msvcrt")

            if info.st_size == 0:
                os.write(descriptor, b"\0")
            while True:
                os.lseek(descriptor, 0, os.SEEK_SET)
                try:
                    msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)
                    break
                except OSError:
                    if event.wait(0.1):
                        raise InterruptedError("certificate renewal stopped") from None
        else:
            import fcntl

            while True:
                try:
                    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if event.wait(0.1):
                        raise InterruptedError("certificate renewal stopped") from None
        if event.is_set():
            raise InterruptedError("certificate renewal stopped")
        yield
    finally:
        os.close(descriptor)
