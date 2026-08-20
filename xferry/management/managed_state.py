"""Read-only unsupported and ambiguous managed-state detection."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from dataclasses import dataclass
from enum import Enum
from itertools import islice
from pathlib import Path

from .model import ManagedLayout
from .versions import is_canonical_release_version, is_supported_release_version

UNSUPPORTED_MANAGED_STATE_CODE = "unsupported-managed-state"
UNSUPPORTED_MANAGED_STATE_INSTRUCTIONS = (
    "Unsupported or ambiguous XFerry managed state was detected and preserved; "
    "no changes were made. "
    "Back up the existing XFerry configuration and data. "
    "Remove the managed state with its original tooling. "
    "Then install XFerry in a clean environment."
)
_MAX_RELEASE_ENTRIES = 128
_MAX_MANIFEST_BYTES = 64 * 1024
_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")


class _ReleaseState(Enum):
    ABSENT = "absent"
    VALID_SUPPORTED = "valid_supported"
    BLOCKED = "blocked"


@dataclass(frozen=True)
class _DescriptorCapabilities:
    directory_open_flags: int
    file_open_flags: int
    effective_uid: int


@dataclass(frozen=True)
class _Manifest:
    version: str
    executable_size: int
    executable_sha256: str


@dataclass(frozen=True)
class _OwnedEntryWitness:
    retained_path: Path
    descriptor: int
    directory_metadata: os.stat_result
    absent_name: str | None
    leaf_name: str | None
    leaf_metadata: os.stat_result | None
    cli_target: Path | None


def _validate_layout_paths(layout: ManagedLayout) -> None:
    for path in (
        layout.release_root,
        layout.config_file,
        layout.auth_file,
        layout.data_root,
        layout.lock_file,
        layout.unit_file,
        layout.cli_link,
    ):
        _validated_path_components(path, allow_current_directory=False)


def _validated_path_components(
    path: Path,
    *,
    allow_current_directory: bool,
) -> tuple[str, ...]:
    parts = path.parts
    if path.is_absolute():
        if not parts or parts[0] != path.anchor:
            raise ValueError("invalid absolute path")
        components = parts[1:]
    else:
        components = parts
    if (not components and not allow_current_directory) or any(
        component in {"", ".", ".."} for component in components
    ):
        raise ValueError("unsafe lexical path component")
    return components


def _descriptor_capabilities() -> _DescriptorCapabilities | None:
    read_only = getattr(os, "O_RDONLY", None)
    close_on_exec = getattr(os, "O_CLOEXEC", None)
    directory_only = getattr(os, "O_DIRECTORY", None)
    no_follow = getattr(os, "O_NOFOLLOW", None)
    nonblocking = getattr(os, "O_NONBLOCK", None)
    effective_uid_function = getattr(os, "geteuid", None)
    open_function = getattr(os, "open", None)
    stat_function = getattr(os, "stat", None)
    readlink_function = getattr(os, "readlink", None)
    scandir_function = getattr(os, "scandir", None)
    fstat_function = getattr(os, "fstat", None)
    fdopen_function = getattr(os, "fdopen", None)
    close_function = getattr(os, "close", None)
    if (
        not isinstance(read_only, int)
        or not isinstance(close_on_exec, int)
        or not isinstance(directory_only, int)
        or not isinstance(no_follow, int)
        or not isinstance(nonblocking, int)
        or not callable(effective_uid_function)
        or not callable(open_function)
        or not callable(stat_function)
        or not callable(readlink_function)
        or not callable(scandir_function)
        or not callable(fstat_function)
        or not callable(fdopen_function)
        or not callable(close_function)
    ):
        return None

    try:
        if (
            open_function not in getattr(os, "supports_dir_fd", ())
            or stat_function not in getattr(os, "supports_dir_fd", ())
            or readlink_function not in getattr(os, "supports_dir_fd", ())
            or scandir_function not in getattr(os, "supports_fd", ())
            or stat_function not in getattr(os, "supports_follow_symlinks", ())
        ):
            return None
        effective_uid = effective_uid_function()
    except (OSError, TypeError, ValueError):
        return None
    if not isinstance(effective_uid, int) or isinstance(effective_uid, bool) or effective_uid < 0:
        return None
    return _DescriptorCapabilities(
        directory_open_flags=read_only | close_on_exec | directory_only | no_follow,
        file_open_flags=read_only | close_on_exec | no_follow | nonblocking,
        effective_uid=effective_uid,
    )


def has_unsupported_managed_state(layout: ManagedLayout) -> bool:
    """Return whether setup must preserve unsupported or ambiguous managed state."""
    try:
        _validate_layout_paths(layout)
        capabilities = _descriptor_capabilities()
        if capabilities is None:
            return True
        release_state = _release_state(layout, capabilities)
        if release_state is _ReleaseState.BLOCKED:
            return True
        return not _owned_state_is_safe(
            layout,
            capabilities,
            allow_expected_entries=release_state is _ReleaseState.VALID_SUPPORTED,
        )
    except Exception:
        return True


def _release_state(
    layout: ManagedLayout,
    capabilities: _DescriptorCapabilities,
) -> _ReleaseState:
    try:
        root_parent_descriptor, root_descriptor = _open_release_root(
            layout.release_root,
            capabilities,
        )
    except FileNotFoundError:
        if _protected_absence_is_stable(layout.release_root, capabilities):
            return _ReleaseState.ABSENT
        return _ReleaseState.BLOCKED
    except (OSError, ValueError):
        return _ReleaseState.BLOCKED

    try:
        if not _protected_directory_entry_matches(
            root_parent_descriptor,
            layout.release_root.name,
            root_descriptor,
            capabilities.effective_uid,
        ):
            return _ReleaseState.BLOCKED
        releases_descriptor = os.open(
            "releases",
            capabilities.directory_open_flags,
            dir_fd=root_descriptor,
        )
        try:
            if not _trusted_directory(
                os.fstat(releases_descriptor),
                capabilities.effective_uid,
            ):
                return _ReleaseState.BLOCKED
            current_metadata = _stat_at("current", dir_fd=root_descriptor)
            if not stat.S_ISLNK(current_metadata.st_mode):
                return _ReleaseState.BLOCKED

            with os.scandir(releases_descriptor) as iterator:
                entries = list(islice(iterator, _MAX_RELEASE_ENTRIES + 1))
            if not entries or len(entries) > _MAX_RELEASE_ENTRIES:
                return _ReleaseState.BLOCKED

            versions: set[str] = set()
            release_identities: dict[str, os.stat_result] = {}
            for entry in entries:
                entry_metadata = entry.stat(follow_symlinks=False)
                if not stat.S_ISDIR(entry_metadata.st_mode):
                    return _ReleaseState.BLOCKED
                version = entry.name
                if not is_supported_release_version(version):
                    return _ReleaseState.BLOCKED
                release_descriptor = os.open(
                    version,
                    capabilities.directory_open_flags,
                    dir_fd=releases_descriptor,
                )
                try:
                    release_metadata = os.fstat(release_descriptor)
                    if not _same_identity(
                        entry_metadata,
                        release_metadata,
                    ) or not _trusted_directory(
                        release_metadata,
                        capabilities.effective_uid,
                    ):
                        return _ReleaseState.BLOCKED
                    manifest, manifest_metadata = _read_manifest(
                        "xferry-release.json",
                        dir_fd=release_descriptor,
                        capabilities=capabilities,
                    )
                    executable_metadata = _valid_executable(
                        "xferry",
                        manifest,
                        dir_fd=release_descriptor,
                        capabilities=capabilities,
                    )
                    if manifest.version != version or executable_metadata is None:
                        return _ReleaseState.BLOCKED
                    if not _entry_matches(
                        release_descriptor,
                        "xferry-release.json",
                        manifest_metadata,
                    ) or not _entry_matches(
                        release_descriptor,
                        "xferry",
                        executable_metadata,
                    ):
                        return _ReleaseState.BLOCKED
                    if not _directory_entry_matches(
                        releases_descriptor,
                        version,
                        release_descriptor,
                    ):
                        return _ReleaseState.BLOCKED
                finally:
                    os.close(release_descriptor)
                versions.add(version)
                release_identities[version] = release_metadata

            for version, release_metadata in release_identities.items():
                current_release = _stat_at(version, dir_fd=releases_descriptor)
                if not stat.S_ISDIR(current_release.st_mode) or not _same_identity(
                    current_release,
                    release_metadata,
                ):
                    return _ReleaseState.BLOCKED

            target = Path(_readlink_at("current", dir_fd=root_descriptor))
            current_after = _stat_at("current", dir_fd=root_descriptor)
            if not _same_identity(current_metadata, current_after):
                return _ReleaseState.BLOCKED
            if target.is_absolute() or len(target.parts) != 2 or target.parts[0] != "releases":
                return _ReleaseState.BLOCKED
            if target.parts[1] not in versions:
                return _ReleaseState.BLOCKED
            if not _directory_entry_matches(root_descriptor, "releases", releases_descriptor):
                return _ReleaseState.BLOCKED
            if not _path_matches_directory(
                layout.release_root,
                root_descriptor,
                capabilities,
            ):
                return _ReleaseState.BLOCKED
            if not _protected_directory_entry_matches(
                root_parent_descriptor,
                layout.release_root.name,
                root_descriptor,
                capabilities.effective_uid,
            ):
                return _ReleaseState.BLOCKED
        finally:
            os.close(releases_descriptor)
    except (OSError, ValueError):
        return _ReleaseState.BLOCKED
    finally:
        try:
            os.close(root_descriptor)
        finally:
            os.close(root_parent_descriptor)
    return _ReleaseState.VALID_SUPPORTED


def _read_manifest(
    path: str,
    *,
    dir_fd: int,
    capabilities: _DescriptorCapabilities,
) -> tuple[_Manifest, os.stat_result]:
    payload, metadata = _read_bounded_regular_file(
        path,
        _MAX_MANIFEST_BYTES,
        dir_fd=dir_fd,
        capabilities=capabilities,
    )
    document = json.loads(payload, object_pairs_hook=_reject_duplicate_keys)
    if not isinstance(document, dict) or set(document) != {
        "schema_version",
        "version",
        "tag",
        "platform",
        "executable",
    }:
        raise ValueError
    version = document["version"]
    executable = document["executable"]
    if (
        document["schema_version"] != 1
        or not isinstance(version, str)
        or not is_canonical_release_version(version)
        or document["tag"] != f"v{version}"
        or document["platform"] != "linux-x86_64"
        or not isinstance(executable, dict)
        or set(executable) != {"name", "size", "sha256"}
    ):
        raise ValueError
    executable_size = executable["size"]
    if (
        executable["name"] != f"xferry-{version}-linux-x86_64"
        or not isinstance(executable_size, int)
        or isinstance(executable_size, bool)
        or executable_size < 1
        or not isinstance(executable["sha256"], str)
        or _SHA256_RE.fullmatch(executable["sha256"]) is None
    ):
        raise ValueError
    return (
        _Manifest(
            version=version,
            executable_size=executable_size,
            executable_sha256=executable["sha256"],
        ),
        metadata,
    )


def _read_bounded_regular_file(
    path: str,
    maximum: int,
    *,
    dir_fd: int,
    capabilities: _DescriptorCapabilities,
) -> tuple[bytes, os.stat_result]:
    descriptor = os.open(
        path,
        capabilities.file_open_flags,
        dir_fd=dir_fd,
    )
    try:
        metadata_before = os.fstat(descriptor)
        if (
            not _trusted_regular_file(metadata_before, capabilities.effective_uid)
            or not 0 < metadata_before.st_size <= maximum
        ):
            raise ValueError
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            payload = stream.read(maximum + 1)
        metadata_after = os.fstat(descriptor)
        if (
            len(payload) > maximum
            or not _same_file_metadata(metadata_before, metadata_after)
            or not _trusted_regular_file(metadata_after, capabilities.effective_uid)
        ):
            raise ValueError
        return payload, metadata_after
    finally:
        os.close(descriptor)


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError
        result[key] = value
    return result


def _valid_executable(
    path: str,
    manifest: _Manifest,
    *,
    dir_fd: int,
    capabilities: _DescriptorCapabilities,
) -> os.stat_result | None:
    try:
        descriptor = os.open(
            path,
            capabilities.file_open_flags,
            dir_fd=dir_fd,
        )
    except OSError:
        return None
    try:
        metadata_before = os.fstat(descriptor)
        if (
            not _trusted_regular_file(metadata_before, capabilities.effective_uid)
            or metadata_before.st_size != manifest.executable_size
            or metadata_before.st_mode & 0o111 == 0
        ):
            return None
        digest = hashlib.sha256()
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        metadata_after = os.fstat(descriptor)
        if (
            digest.hexdigest() != manifest.executable_sha256
            or not _same_file_metadata(metadata_before, metadata_after)
            or not _trusted_regular_file(metadata_after, capabilities.effective_uid)
        ):
            return None
        return metadata_after
    except OSError:
        return None
    finally:
        os.close(descriptor)


def _owned_state_is_safe(
    layout: ManagedLayout,
    capabilities: _DescriptorCapabilities,
    *,
    allow_expected_entries: bool,
) -> bool:
    expected_entries = (
        (layout.config_file, "file", None),
        (layout.auth_file, "file", None),
        (layout.data_root, "directory", None),
        (layout.unit_file, "file", None),
        (layout.cli_link, "symlink", Path("/opt/xferry/current/xferry")),
    )
    witnesses: list[_OwnedEntryWitness] = []
    safe = False
    try:
        for path, expected_kind, expected_target in expected_entries:
            witnesses.append(
                _inspect_owned_entry(
                    path,
                    expected_kind,
                    expected_target,
                    allow_expected_entry=allow_expected_entries,
                    capabilities=capabilities,
                )
            )
        safe = True
        for witness in witnesses:
            safe = _owned_entry_witness_is_valid(witness, capabilities) and safe
    except Exception:
        safe = False
    finally:
        for witness in witnesses:
            try:
                os.close(witness.descriptor)
            except OSError:
                safe = False
    return safe


def _inspect_owned_entry(
    path: Path,
    expected_kind: str,
    expected_target: Path | None,
    *,
    allow_expected_entry: bool,
    capabilities: _DescriptorCapabilities,
) -> _OwnedEntryWitness:
    _validated_path_components(path, allow_current_directory=False)
    descriptor, retained_path, directory_metadata, missing_name = (
        _open_trusted_directory_or_missing(path.parent, capabilities)
    )
    try:
        if missing_name is not None:
            return _protected_absence_witness(
                retained_path,
                descriptor,
                directory_metadata,
                missing_name,
            )

        parent_before = os.fstat(descriptor)
        if not _same_directory_metadata(directory_metadata, parent_before):
            raise ValueError("managed parent changed during inspection")
        try:
            leaf_metadata = _stat_at(path.name, dir_fd=descriptor)
        except FileNotFoundError:
            return _protected_absence_witness(
                retained_path,
                descriptor,
                parent_before,
                path.name,
            )

        if (
            not allow_expected_entry
            or not _entry_is_protected(
                parent_before,
                leaf_metadata,
                capabilities.effective_uid,
            )
            or _metadata_kind(leaf_metadata) != expected_kind
        ):
            raise ValueError("unsafe managed entry")
        cli_target = None
        if expected_target is not None:
            cli_target = Path(_readlink_at(path.name, dir_fd=descriptor))
            if cli_target != expected_target:
                raise ValueError("unexpected managed CLI target")
        leaf_after = _stat_at(path.name, dir_fd=descriptor)
        parent_after = os.fstat(descriptor)
        if (
            not _same_directory_metadata(parent_before, parent_after)
            or not _same_identity(leaf_metadata, leaf_after)
            or not _entry_is_protected(
                parent_after,
                leaf_after,
                capabilities.effective_uid,
            )
        ):
            raise ValueError("managed entry changed during inspection")
        return _OwnedEntryWitness(
            retained_path=retained_path,
            descriptor=descriptor,
            directory_metadata=parent_after,
            absent_name=None,
            leaf_name=path.name,
            leaf_metadata=leaf_after,
            cli_target=cli_target,
        )
    except Exception:
        os.close(descriptor)
        raise


def _inspect_protected_absence(
    path: Path,
    capabilities: _DescriptorCapabilities,
) -> _OwnedEntryWitness:
    _validated_path_components(path, allow_current_directory=False)
    descriptor, retained_path, directory_metadata, missing_name = (
        _open_trusted_directory_or_missing(path.parent, capabilities)
    )
    try:
        if missing_name is not None:
            return _protected_absence_witness(
                retained_path,
                descriptor,
                directory_metadata,
                missing_name,
            )
        parent_before = os.fstat(descriptor)
        if not _same_directory_metadata(directory_metadata, parent_before):
            raise ValueError("absent entry parent changed during inspection")
        try:
            _stat_at(path.name, dir_fd=descriptor)
        except FileNotFoundError:
            return _protected_absence_witness(
                retained_path,
                descriptor,
                parent_before,
                path.name,
            )
        raise ValueError("expected absent entry is present")
    except Exception:
        os.close(descriptor)
        raise


def _protected_absence_witness(
    retained_path: Path,
    descriptor: int,
    directory_metadata: os.stat_result,
    absent_name: str,
) -> _OwnedEntryWitness:
    if directory_metadata.st_mode & 0o022:
        raise ValueError("replaceable entry absence")
    return _OwnedEntryWitness(
        retained_path=retained_path,
        descriptor=descriptor,
        directory_metadata=directory_metadata,
        absent_name=absent_name,
        leaf_name=None,
        leaf_metadata=None,
        cli_target=None,
    )


def _protected_absence_is_stable(
    path: Path,
    capabilities: _DescriptorCapabilities,
) -> bool:
    witness: _OwnedEntryWitness | None = None
    safe = False
    try:
        witness = _inspect_protected_absence(path, capabilities)
        safe = _owned_entry_witness_is_valid(witness, capabilities)
    except Exception:
        safe = False
    finally:
        if witness is not None:
            try:
                os.close(witness.descriptor)
            except OSError:
                safe = False
    return safe


def _owned_entry_witness_is_valid(
    witness: _OwnedEntryWitness,
    capabilities: _DescriptorCapabilities,
) -> bool:
    try:
        parent_before = os.fstat(witness.descriptor)
        if not _same_directory_metadata(
            witness.directory_metadata, parent_before
        ) or not _trusted_ancestor_directory(
            parent_before,
            capabilities.effective_uid,
        ):
            return False
        reopened = _open_trusted_directory(witness.retained_path, capabilities)
        try:
            if not _same_directory_metadata(os.fstat(reopened), parent_before):
                return False
        finally:
            os.close(reopened)

        if witness.absent_name is not None:
            if parent_before.st_mode & 0o022:
                return False
            try:
                _stat_at(witness.absent_name, dir_fd=witness.descriptor)
            except FileNotFoundError:
                pass
            else:
                return False
        else:
            if witness.leaf_name is None or witness.leaf_metadata is None:
                return False
            current = _stat_at(witness.leaf_name, dir_fd=witness.descriptor)
            if not _same_identity(current, witness.leaf_metadata) or not _entry_is_protected(
                parent_before,
                current,
                capabilities.effective_uid,
            ):
                return False
            if witness.cli_target is not None:
                target = Path(_readlink_at(witness.leaf_name, dir_fd=witness.descriptor))
                current_after = _stat_at(witness.leaf_name, dir_fd=witness.descriptor)
                if target != witness.cli_target or not _same_identity(current, current_after):
                    return False
        parent_after = os.fstat(witness.descriptor)
        return _same_directory_metadata(parent_before, parent_after)
    except (OSError, ValueError):
        return False


def _open_release_root(
    path: Path,
    capabilities: _DescriptorCapabilities,
) -> tuple[int, int]:
    _validated_path_components(path, allow_current_directory=False)
    parent_descriptor = _open_trusted_directory(path.parent, capabilities)
    try:
        root_descriptor = os.open(
            path.name,
            capabilities.directory_open_flags,
            dir_fd=parent_descriptor,
        )
    except Exception:
        os.close(parent_descriptor)
        raise
    return parent_descriptor, root_descriptor


def _open_trusted_directory(
    path: Path,
    capabilities: _DescriptorCapabilities,
) -> int:
    descriptor, _retained_path, _metadata, missing_name = _open_trusted_directory_or_missing(
        path, capabilities
    )
    if missing_name is not None:
        os.close(descriptor)
        raise FileNotFoundError(missing_name)
    return descriptor


def _open_trusted_directory_or_missing(
    path: Path,
    capabilities: _DescriptorCapabilities,
) -> tuple[int, Path, os.stat_result, str | None]:
    components = _validated_path_components(path, allow_current_directory=True)
    if path.is_absolute():
        descriptor = os.open(path.anchor, capabilities.directory_open_flags)
        retained_path = Path(path.anchor)
    else:
        descriptor = os.open(".", capabilities.directory_open_flags)
        retained_path = Path()
    try:
        metadata = os.fstat(descriptor)
        if not _trusted_ancestor_directory(metadata, capabilities.effective_uid):
            raise ValueError("unsafe directory ancestor")
        for component in components:
            if component in {"", ".", ".."}:
                raise ValueError("unsafe directory component")
            parent_before = os.fstat(descriptor)
            try:
                entry_metadata = _stat_at(component, dir_fd=descriptor)
            except FileNotFoundError:
                parent_after = os.fstat(descriptor)
                if (
                    not _same_directory_metadata(parent_before, parent_after)
                    or parent_after.st_mode & 0o022
                ):
                    raise ValueError("replaceable directory absence") from None
                return descriptor, retained_path, parent_after, component
            if not _directory_entry_is_protected(
                parent_before,
                entry_metadata,
                capabilities.effective_uid,
            ):
                raise ValueError("replaceable directory entry")
            child_descriptor = os.open(
                component,
                capabilities.directory_open_flags,
                dir_fd=descriptor,
            )
            try:
                opened_metadata = os.fstat(child_descriptor)
                parent_after = os.fstat(descriptor)
                if (
                    not _same_directory_metadata(parent_before, parent_after)
                    or not _same_directory_metadata(entry_metadata, opened_metadata)
                    or not _directory_entry_is_protected(
                        parent_after,
                        opened_metadata,
                        capabilities.effective_uid,
                    )
                    or not _trusted_ancestor_directory(
                        opened_metadata,
                        capabilities.effective_uid,
                    )
                ):
                    raise ValueError("directory changed during traversal")
            except Exception:
                os.close(child_descriptor)
                raise
            parent_descriptor = descriptor
            descriptor = child_descriptor
            os.close(parent_descriptor)
            retained_path /= component
        return descriptor, retained_path, os.fstat(descriptor), None
    except Exception:
        os.close(descriptor)
        raise


def _same_identity(left: os.stat_result, right: os.stat_result) -> bool:
    return (left.st_dev, left.st_ino, stat.S_IFMT(left.st_mode)) == (
        right.st_dev,
        right.st_ino,
        stat.S_IFMT(right.st_mode),
    )


def _metadata_kind(metadata: os.stat_result) -> str:
    if stat.S_ISREG(metadata.st_mode):
        return "file"
    if stat.S_ISDIR(metadata.st_mode):
        return "directory"
    if stat.S_ISLNK(metadata.st_mode):
        return "symlink"
    return "unsafe"


def _metadata_owner_is_trusted(metadata: os.stat_result, effective_uid: int) -> bool:
    return metadata.st_uid in {0, effective_uid}


def _trusted_directory(metadata: os.stat_result, effective_uid: int) -> bool:
    return (
        stat.S_ISDIR(metadata.st_mode)
        and _metadata_owner_is_trusted(metadata, effective_uid)
        and metadata.st_mode & 0o022 == 0
    )


def _trusted_ancestor_directory(metadata: os.stat_result, effective_uid: int) -> bool:
    write_access_is_protected = (
        metadata.st_mode & 0o022 == 0 or metadata.st_mode & stat.S_ISVTX != 0
    )
    return (
        stat.S_ISDIR(metadata.st_mode)
        and _metadata_owner_is_trusted(metadata, effective_uid)
        and write_access_is_protected
    )


def _entry_is_protected(
    parent: os.stat_result,
    entry: os.stat_result,
    effective_uid: int,
) -> bool:
    if not _trusted_ancestor_directory(parent, effective_uid):
        return False
    if parent.st_mode & 0o022 == 0:
        return True
    return parent.st_mode & stat.S_ISVTX != 0 and _metadata_owner_is_trusted(entry, effective_uid)


def _directory_entry_is_protected(
    parent: os.stat_result,
    entry: os.stat_result,
    effective_uid: int,
) -> bool:
    return stat.S_ISDIR(entry.st_mode) and _entry_is_protected(
        parent,
        entry,
        effective_uid,
    )


def _same_directory_metadata(left: os.stat_result, right: os.stat_result) -> bool:
    return _same_identity(left, right) and (
        left.st_mode,
        left.st_uid,
        left.st_gid,
    ) == (
        right.st_mode,
        right.st_uid,
        right.st_gid,
    )


def _trusted_regular_file(metadata: os.stat_result, effective_uid: int) -> bool:
    return (
        stat.S_ISREG(metadata.st_mode)
        and _metadata_owner_is_trusted(metadata, effective_uid)
        and metadata.st_mode & 0o022 == 0
    )


def _same_file_metadata(left: os.stat_result, right: os.stat_result) -> bool:
    return _same_identity(left, right) and (
        left.st_mode,
        left.st_uid,
        left.st_gid,
        left.st_nlink,
        left.st_size,
        left.st_mtime_ns,
        left.st_ctime_ns,
    ) == (
        right.st_mode,
        right.st_uid,
        right.st_gid,
        right.st_nlink,
        right.st_size,
        right.st_mtime_ns,
        right.st_ctime_ns,
    )


def _directory_entry_matches(parent_fd: int, name: str, descriptor: int) -> bool:
    try:
        current = _stat_at(name, dir_fd=parent_fd)
        opened = os.fstat(descriptor)
    except OSError:
        return False
    return stat.S_ISDIR(current.st_mode) and _same_identity(current, opened)


def _protected_directory_entry_matches(
    parent_fd: int,
    name: str,
    descriptor: int,
    effective_uid: int,
) -> bool:
    try:
        parent_before = os.fstat(parent_fd)
        current = _stat_at(name, dir_fd=parent_fd)
        opened = os.fstat(descriptor)
        parent_after = os.fstat(parent_fd)
    except OSError:
        return False
    return (
        _same_directory_metadata(parent_before, parent_after)
        and _directory_entry_is_protected(parent_before, current, effective_uid)
        and _directory_entry_is_protected(parent_after, current, effective_uid)
        and _same_directory_metadata(current, opened)
        and _trusted_directory(opened, effective_uid)
    )


def _entry_matches(
    parent_fd: int,
    name: str,
    expected: os.stat_result,
) -> bool:
    try:
        current = _stat_at(name, dir_fd=parent_fd)
    except OSError:
        return False
    return _same_file_metadata(current, expected)


def _path_matches_directory(
    path: Path,
    descriptor: int,
    capabilities: _DescriptorCapabilities,
) -> bool:
    try:
        reopened = _open_trusted_directory(path, capabilities)
    except (OSError, ValueError):
        return False
    try:
        return _same_directory_metadata(os.fstat(reopened), os.fstat(descriptor))
    finally:
        os.close(reopened)


def _stat_at(name: str, *, dir_fd: int) -> os.stat_result:
    return os.stat(name, dir_fd=dir_fd, follow_symlinks=False)  # noqa: PTH116


def _readlink_at(name: str, *, dir_fd: int) -> str:
    return os.readlink(name, dir_fd=dir_fd)  # noqa: PTH115
