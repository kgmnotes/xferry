"""Host file-directory mapping for a sandboxed managed service."""

from __future__ import annotations

import json
import os
import struct
from collections.abc import Sequence
from importlib import resources
from pathlib import Path

from .model import ManagedLayout
from .system import FilesystemTransaction


def deployment_metadata_path(layout: ManagedLayout) -> Path:
    return layout.config_file.parent / "deployment.json"


def managed_files_path(layout: ManagedLayout) -> Path:
    """Return the host path; legacy installations retain their actual uploads."""
    metadata = deployment_metadata_path(layout)
    if metadata.exists():
        if metadata.is_symlink() or metadata.stat().st_size > 65536:
            raise ValueError("unsafe deployment metadata")
        document = json.loads(metadata.read_text(encoding="utf-8"))
        if (
            not isinstance(document, dict)
            or document.get("schema") != 1
            or document.get("kind") != "managed"
            or not isinstance(document.get("files_dir"), str)
        ):
            raise ValueError("unsupported deployment metadata")
        return _safe_files_path(Path(document["files_dir"]))
    if layout.config_file.exists():
        from xferry.settings import load_settings_file

        settings = load_settings_file(layout.config_file, state_dir=layout.data_root)
        return Path(settings.files_dir or Path(settings.root_dir) / "uploads").resolve()
    return layout.data_root / "files"


def _safe_files_path(path: Path) -> Path:
    if not str(path).strip() or any(c in str(path) for c in ("\n", "\r", "\x00")):
        raise ValueError("invalid files directory")
    result = path.expanduser().resolve()
    if result == Path(result.anchor):
        raise ValueError("the filesystem root cannot be the files directory")
    return result


def render_managed_unit(layout: ManagedLayout, host: Path) -> bytes:
    """Map a host folder outside masked /home without opening all of /home."""
    source = _safe_files_path(host)
    text = resources.files("xferry.management").joinpath("data/xferry.service").read_text()
    if source != (layout.data_root / "files").resolve():

        def escape(value: Path) -> str:
            # Unit specifiers and whitespace must remain literal path bytes.
            return (
                str(value)
                .replace("%", "%%")
                .replace("\\", "\\x5c")
                .replace(" ", "\\x20")
                .replace(":", "\\x3a")
                .replace('"', "\\x22")
                .replace("\t", "\\x09")
            )

        binding = f"BindPaths={escape(source)}:{escape(layout.data_root / 'files')}\n"
        text = text.replace(
            "ReadWritePaths=/var/lib/xferry\n", "ReadWritePaths=/var/lib/xferry\n" + binding
        )
    return text.encode("utf-8")


def stage_managed_files_folder(
    layout: ManagedLayout,
    host: Path,
    transaction: FilesystemTransaction,
    uid: int,
    gid: int,
    private_files: Sequence[Path] = (),
) -> None:
    """Stage mapping and new folders; never change existing folder ownership."""
    source = _safe_files_path(host)
    for private in (
        layout.config_file.parent,
        layout.data_root / "notes",
        layout.acme_root,
        layout.release_root,
    ):
        protected = private.resolve()
        if protected.is_relative_to(source) or source.is_relative_to(protected):
            raise ValueError("files directory would expose private XFerry state")
    if any(path.expanduser().resolve().is_relative_to(source) for path in private_files):
        raise ValueError("files directory would expose an authentication or TLS file")
    if source.exists():
        if not source.is_dir():
            raise ValueError("files directory is not a directory")
        metadata = source.stat()
        access = (
            (metadata.st_mode >> 6) & 7
            if metadata.st_uid == uid
            else ((metadata.st_mode >> 3) & 7 if metadata.st_gid == gid else metadata.st_mode & 7)
        )
        # Account for named ACL grants without changing the existing directory.
        if hasattr(os, "getxattr"):
            try:
                acl = os.getxattr(source, "system.posix_acl_access")
                if struct.unpack_from("<I", acl)[0] == 2:
                    entries = [struct.unpack_from("<HHI", acl, i) for i in range(4, len(acl), 8)]
                    mask = next((entry[1] for entry in entries if entry[0] == 16), 7)
                    named = next(
                        (entry[1] for entry in entries if entry[0] == 2 and entry[2] == uid), None
                    )
                    if metadata.st_uid == uid:
                        access = next(entry[1] for entry in entries if entry[0] == 1)
                    elif named is not None:
                        access = named & mask
                    else:
                        groups = [
                            entry[1]
                            for entry in entries
                            if (entry[0] == 4 and metadata.st_gid == gid)
                            or (entry[0] == 8 and entry[2] == gid)
                        ]
                        if groups:
                            access = 0
                            for permission in groups:
                                access |= permission & mask
                        else:
                            access = next(entry[1] for entry in entries if entry[0] == 32)
            except (OSError, struct.error):
                pass
        if access & 7 != 7:
            raise ValueError(
                "files directory needs read/write/search access for xferry; "
                "grant access with setfacl -m u:xferry:rwx,d:u:xferry:rwx PATH "
                "or choose a new dedicated directory"
            )
    else:
        transaction.ensure_retained_directory(source, mode=0o750, uid=uid, gid=gid)
    transaction.retain_directory(source)
    transaction.retain_directory(layout.data_root / ".xferry/encrypted-uploads")
    destination = layout.data_root / "files"
    if not destination.exists():
        transaction.ensure_retained_directory(destination, mode=0o750, uid=uid, gid=gid)
    body = json.dumps(
        {
            "schema": 1,
            "kind": "managed",
            "files_dir": str(source),
            "state_dir": str(layout.data_root),
        },
        indent=2,
    )
    transaction.atomic_write(
        deployment_metadata_path(layout), (body + "\n").encode(), mode=0o640, uid=0, gid=gid
    )
    transaction.atomic_write(
        layout.unit_file, render_managed_unit(layout, source), mode=0o644, uid=0, gid=0
    )
