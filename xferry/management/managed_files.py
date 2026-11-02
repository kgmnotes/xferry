"""Host file-directory mapping for a sandboxed managed service."""

from __future__ import annotations

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
        from .deployment import load_manifest

        spec = load_manifest(metadata)
        if spec.backend != "native":
            raise ValueError("expected native deployment metadata")
        return _safe_files_path(spec.files_dir)
    if layout.config_file.exists():
        from xferry.settings import load_settings_file

        settings = load_settings_file(layout.config_file, state_dir=layout.data_root)
        return Path(
            settings.files_dir or Path(settings.state_dir or layout.data_root) / "files"
        ).resolve()
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
) -> tuple[dict[str, object], ...]:
    """Stage mapping and new folders; never change existing folder ownership."""
    source = _safe_files_path(host)
    receipts: list[dict[str, object]] = []
    for private in (
        layout.config_file.parent,
        layout.data_root / "notes",
        layout.data_root / ".xferry",
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
        from .ownership import grant_directory_access, restore_directory_access

        receipt = grant_directory_access(source, uid)
        if receipt is not None:
            transaction.on_rollback(lambda: restore_directory_access(receipt))
            receipts.append(receipt)
    else:
        transaction.ensure_retained_directory(source, mode=0o750, uid=uid, gid=gid)
    transaction.retain_directory(source)
    transaction.retain_directory(layout.data_root / ".xferry/encrypted-uploads")
    destination = layout.data_root / "files"
    if not destination.exists():
        transaction.ensure_retained_directory(destination, mode=0o750, uid=uid, gid=gid)
    transaction.atomic_write(
        layout.unit_file, render_managed_unit(layout, source), mode=0o644, uid=0, gid=0
    )
    return tuple(receipts)
