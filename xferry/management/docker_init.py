"""One-shot container initialization; never receives a Docker socket."""

from __future__ import annotations

import argparse
import os
import tempfile
from pathlib import Path


def initialize(secret_source: Path, secret_target: Path, files: Path, host_uid: int) -> None:
    if not files.is_dir() or files.is_symlink():
        raise ValueError("host files directory must be a real directory")
    # Directory access is granted by the host controller with an ownership
    # receipt. This one-shot container only copies protected credentials.
    credentials = secret_source.read_bytes()
    lines = credentials.decode("utf-8").splitlines()
    if len(lines) != 1 or ":" not in lines[0] or "\x00" in lines[0]:
        raise ValueError("invalid auth file")
    secret_target.parent.mkdir(parents=True, exist_ok=True)
    os.chown(secret_target.parent, 10001, 10001)
    secret_target.parent.chmod(0o700)
    fd, temporary = tempfile.mkstemp(prefix=".auth-", dir=secret_target.parent)
    try:
        os.fchmod(fd, 0o400)
        os.fchown(fd, 10001, 10001)
        with os.fdopen(fd, "wb") as stream:
            stream.write(credentials)
            stream.flush()
            os.fsync(stream.fileno())
        Path(temporary).replace(secret_target)
    finally:
        Path(temporary).unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host-uid", type=int, required=True)
    args = parser.parse_args()
    try:
        initialize(
            Path("/source/auth"), Path("/secrets/xferry_auth"), Path("/host-files"), args.host_uid
        )
    except (OSError, ValueError, UnicodeError):
        print(
            "XFerry initialization failed: check files-directory access/ACL support "
            "and auth permissions."
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
