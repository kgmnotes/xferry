"""One-shot container initialization; never receives a Docker socket."""

from __future__ import annotations

import argparse
import os
import stat
import struct
import tempfile
from pathlib import Path

_ACL_USER_OBJ = 1
_ACL_USER = 2
_ACL_GROUP_OBJ = 4
_ACL_MASK = 16
_ACL_OTHER = 32
_UNDEFINED = 0xFFFFFFFF


def _grant_directory_acl(path: Path, runtime_uid: int, host_uid: int) -> None:
    """Grant only named access; retain existing ownership and ACL entries."""
    mode = path.stat().st_mode
    for attribute in ("system.posix_acl_access", "system.posix_acl_default"):
        try:
            raw = os.getxattr(path, attribute)
        except OSError:
            raw = b""
        if raw:
            if len(raw) < 4 or struct.unpack_from("<I", raw)[0] != 2 or (len(raw) - 4) % 8:
                raise ValueError("unsupported directory ACL")
            entries = [struct.unpack_from("<HHI", raw, i) for i in range(4, len(raw), 8)]
        else:
            entries = [
                (_ACL_USER_OBJ, (mode >> 6) & 7, _UNDEFINED),
                (_ACL_GROUP_OBJ, (mode >> 3) & 7, _UNDEFINED),
                (_ACL_OTHER, mode & 7, _UNDEFINED),
            ]
        owner = path.stat().st_uid
        previous_mask = next((entry[1] for entry in entries if entry[0] == _ACL_MASK), 7)
        # Raising the mask must not activate permissions previously masked off for
        # unrelated named users/groups or the owning group.
        entries = [
            (
                tag,
                permission & previous_mask if tag in {_ACL_USER, _ACL_GROUP_OBJ, 8} else permission,
                identity,
            )
            for tag, permission, identity in entries
        ]
        named = {runtime_uid}
        if attribute.endswith("default"):
            named.add(host_uid)
        if owner == runtime_uid:
            entries = [
                (tag, 7 if tag == _ACL_USER_OBJ else permission, identity)
                for tag, permission, identity in entries
            ]
        for uid in named if attribute.endswith("default") else named - {owner}:
            entries = [
                entry for entry in entries if not (entry[0] == _ACL_USER and entry[2] == uid)
            ]
            entries.append((_ACL_USER, 7, uid))
        entries = [entry for entry in entries if entry[0] != _ACL_MASK]
        entries.append((_ACL_MASK, 7, _UNDEFINED))
        entries.sort(key=lambda entry: (entry[0], entry[2]))
        os.setxattr(
            path,
            attribute,
            struct.pack("<I", 2) + b"".join(struct.pack("<HHI", *entry) for entry in entries),
        )


def initialize(secret_source: Path, secret_target: Path, files: Path, host_uid: int) -> None:
    if not files.is_dir() or files.is_symlink():
        raise ValueError("host files directory must be a real directory")
    # Linux bind mounts need a precise ACL when host and container users differ.
    # Docker Desktop filesystems may already grant access and lack Linux ACLs.
    metadata = files.stat()
    mode = stat.S_IMODE(metadata.st_mode)
    permissions = (
        (mode >> 6) & 7
        if metadata.st_uid == 10001
        else ((mode >> 3) & 7 if metadata.st_gid == 10001 else mode & 7)
    )
    if permissions != 7:
        _grant_directory_acl(files, 10001, host_uid)
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
