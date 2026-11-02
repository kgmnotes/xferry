"""Conditional ownership cleanup and reversible, non-recursive ACL grants."""

from __future__ import annotations

import base64
import errno
import os
import stat
import struct
from pathlib import Path

_ACCESS = "system.posix_acl_access"
_DEFAULT = "system.posix_acl_default"
_UNDEFINED = 0xFFFFFFFF


def _get(descriptor: int, name: str) -> bytes | None:
    try:
        return os.getxattr(descriptor, name)
    except OSError as error:
        if error.errno in {errno.ENODATA, getattr(errno, "ENOATTR", errno.ENODATA)}:
            return None
        raise


def _encode(value: bytes | None) -> str | None:
    return base64.b64encode(value).decode() if value is not None else None


def _set(descriptor: int, name: str, value: bytes | None) -> None:
    if value is not None:
        os.setxattr(descriptor, name, value)
    else:
        try:
            os.removexattr(descriptor, name)
        except OSError as error:
            if error.errno != errno.ENODATA:
                raise


def _grant(value: bytes | None, mode: int, uid: int, *, owner_uid: int | None = None) -> bytes:
    if value is None:
        entries = [
            (1, (mode >> 6) & 7, _UNDEFINED),
            (4, (mode >> 3) & 7, _UNDEFINED),
            (32, mode & 7, _UNDEFINED),
        ]
    else:
        if len(value) < 4 or (len(value) - 4) % 8 or struct.unpack_from("<I", value)[0] != 2:
            raise ValueError("unsupported POSIX ACL format")
        entries = [struct.unpack_from("<HHI", value, index) for index in range(4, len(value), 8)]
    mask = next((permission for tag, permission, _ in entries if tag == 16), 7)
    # Expanding the mask must not increase effective rights for existing entries.
    result = [
        (tag, permission & mask if tag in {2, 4, 8} else permission, identity)
        for tag, permission, identity in entries
        if tag != 16 and not (tag == 2 and identity == uid)
    ]
    if owner_uid == uid:
        result = [
            (tag, 7 if tag == 1 else permission, identity) for tag, permission, identity in result
        ]
    else:
        result.append((2, 7, uid))
    result.append((16, 7, _UNDEFINED))
    result.sort(key=lambda entry: (entry[0], entry[2]))
    return struct.pack("<I", 2) + b"".join(struct.pack("<HHI", *entry) for entry in result)


def grant_directory_access(path: Path, uid: int) -> dict[str, object] | None:
    """Grant only this directory and inheritance, preserving ownership/content.

    Receipt includes inode and exact before/after ACLs. Rollback and purge restore
    only if the directory and both ACLs still match the grant we made.
    """
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        metadata = os.fstat(descriptor)
        if metadata.st_uid == uid and metadata.st_mode & stat.S_IRWXU == stat.S_IRWXU:
            return None
        before = {name: _get(descriptor, name) for name in (_ACCESS, _DEFAULT)}
        after = {
            name: _grant(
                value, metadata.st_mode, uid, owner_uid=metadata.st_uid if name == _ACCESS else None
            )
            for name, value in before.items()
        }
        if metadata.st_uid != uid:
            after[_DEFAULT] = _grant(after[_DEFAULT], metadata.st_mode, metadata.st_uid)
        if all(before[name] == value for name, value in after.items()):
            return None
        try:
            for name, value in after.items():
                _set(descriptor, name, value)
        except OSError as error:
            for name, original_value in before.items():
                _set(descriptor, name, original_value)
            raise ValueError(
                f"cannot grant files folder access using POSIX ACLs: {error.strerror}"
            ) from error
        return {
            "path": str(path),
            "uid": metadata.st_uid,
            "gid": metadata.st_gid,
            "device": metadata.st_dev,
            "inode": metadata.st_ino,
            "mode": stat.S_IMODE(metadata.st_mode),
            "before": {name: _encode(value) for name, value in before.items()},
            "after": {name: _encode(_get(descriptor, name)) for name in after},
        }
    finally:
        os.close(descriptor)


def restore_directory_access(receipt: dict[str, object]) -> bool:
    path = Path(str(receipt["path"]))
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError:
        return False
    try:
        metadata = os.fstat(descriptor)
        if any(
            getattr(metadata, field) != receipt[key]
            for field, key in (
                ("st_dev", "device"),
                ("st_ino", "inode"),
                ("st_uid", "uid"),
                ("st_gid", "gid"),
            )
        ):
            return False
        before, after = receipt["before"], receipt["after"]
        if not isinstance(before, dict) or not isinstance(after, dict):
            return False
        if any(_encode(_get(descriptor, name)) != after.get(name) for name in (_ACCESS, _DEFAULT)):
            return False
        for name in (_ACCESS, _DEFAULT):
            value = before.get(name)
            _set(descriptor, name, base64.b64decode(value) if value is not None else None)
        os.fchmod(descriptor, int(str(receipt["mode"])))
        return True
    except (OSError, ValueError, KeyError):
        return False
    finally:
        os.close(descriptor)
