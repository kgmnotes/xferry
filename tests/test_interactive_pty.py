"""Exercise the real CLI and terminal keyboard over a narrow SSH-style PTY."""

from __future__ import annotations

import os
import select
import struct
import subprocess
import sys
import time
from pathlib import Path

import pytest

from xferry.settings import load_settings_text

pytestmark = pytest.mark.skipif(os.name != "posix", reason="requires a POSIX PTY")


@pytest.mark.parametrize(
    ("width", "save", "field"),
    [(80, True, "files_dir"), (60, False, "files_dir"), (80, True, "max_size_mb")],
)
def test_real_config_keyboard_save_or_discard(
    tmp_path: Path, width: int, save: bool, field: str
) -> None:
    import fcntl
    import pty
    import termios

    config = tmp_path / "profile.ini"
    before = (
        f"[server]\nconfig_version = 1\naccess = private\n"
        f"files_dir = {tmp_path / 'initial'}\n[limits]\nmax_size_mb = 100\n"
    )
    config.write_text(before)
    folder = tmp_path / "shared files"
    master, slave = pty.openpty()
    fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 24, width, 0, 0))
    environment = {**os.environ, "TERM": "xterm-256color", "XDG_DATA_HOME": str(tmp_path / "data")}
    environment.pop("NO_COLOR", None)
    child = subprocess.Popen(
        [sys.executable, "-m", "xferry", "--lang", "en", "config", "--config", str(config)],
        stdin=slave,
        stdout=slave,
        stderr=slave,
        env=environment,
    )
    os.close(slave)
    pending = bytearray()
    transcript = bytearray()

    def expect(text: str) -> None:
        token = text.encode()
        deadline = time.monotonic() + 15
        while token not in pending:
            if time.monotonic() >= deadline:
                pytest.fail(f"Waiting for {text!r}: {transcript[-4000:].decode(errors='replace')}")
            if select.select([master], [], [], 0.1)[0]:
                try:
                    chunk = os.read(master, 65536)
                except OSError:
                    chunk = b""
                if not chunk:
                    pytest.fail(
                        f"CLI exited before {text!r}: {transcript.decode(errors='replace')}"
                    )
                pending.extend(chunk)
                transcript.extend(chunk)
        end = pending.index(token) + len(token)
        del pending[:end]

    try:
        expect("Change a setting")
        # Common fields are visible first; familiar numbered selection also works.
        os.write(master, b"\r" if field == "files_dir" else b"2\r")
        expect(f"{field}:")
        value = str(folder) if field == "files_dir" else "25"
        # Typing a replacement must not append it to the current/default value.
        os.write(master, value.encode() + b"\r")
        expect("Change a setting")
        assert config.read_text() == before
        if save:
            os.write(master, b"9\r")
            expect("Save this configuration?")
            # Confirmation defaults to No; explicitly select Yes.
            os.write(master, b"\x1b[A\r")
        else:
            os.write(master, b"\x1b")
        assert child.wait(timeout=15) == 0
        if save:
            settings = load_settings_text(config.read_text())
            assert getattr(settings, field) == (str(folder) if field == "files_dir" else 25)
        else:
            assert config.read_text() == before
    finally:
        if child.poll() is None:
            child.kill()
            child.wait(timeout=5)
        os.close(master)
