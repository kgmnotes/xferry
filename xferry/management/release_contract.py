"""Canonical platform, artifact, and release-manifest contracts."""

from __future__ import annotations

import json
import platform as host_platform
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, NoReturn, TypeAlias, TypedDict, TypeGuard

from .versions import is_canonical_release_version

MANIFEST_NAME = "xferry-release.json"
INSTALLED_EXECUTABLE_NAME = "xferry"
MAX_MANIFEST_BYTES = 64 * 1024
MAX_ARTIFACT_DIGESTS = 128
MAX_SIGNING_KEY_IDS = 1

PlatformId: TypeAlias = Literal["linux-x86_64", "linux-aarch64"]
LINUX_X86_64: PlatformId = "linux-x86_64"
LINUX_AARCH64: PlatformId = "linux-aarch64"
SUPPORTED_PLATFORM_IDS: tuple[PlatformId, ...] = (LINUX_X86_64, LINUX_AARCH64)

_MACHINE_ALIASES: dict[PlatformId, tuple[str, ...]] = {
    LINUX_X86_64: ("amd64", "x86_64"),
    LINUX_AARCH64: ("aarch64", "arm64"),
}
_PLATFORM_BY_MACHINE: dict[str, PlatformId] = {
    alias: platform_id for platform_id, aliases in _MACHINE_ALIASES.items() for alias in aliases
}
_CANONICAL_MACHINE: dict[PlatformId, str] = {
    LINUX_X86_64: "x86_64",
    LINUX_AARCH64: "aarch64",
}
_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
_SOURCE_COMMIT_RE = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
_WORKFLOW_RUN_RE = re.compile(r"(?:local|[1-9][0-9]*)\Z")
_ASSET_NAME_RE = re.compile(r"[0-9A-Za-z][0-9A-Za-z._+-]{0,254}\Z")
_SIGNING_KEY_ID_RE = re.compile(r"(?:[a-z0-9]|[a-z0-9][a-z0-9._-]{0,62}[a-z0-9])\Z")


class _CommonManifestFields(TypedDict):
    version: str
    tag: str
    platform: PlatformId
    executable_name: str
    executable_size: int
    executable_sha256: str


def normalize_machine(machine: str) -> str:
    """Normalize a host architecture alias without claiming unknown support."""
    normalized = machine.casefold()
    platform_id = _PLATFORM_BY_MACHINE.get(normalized)
    if platform_id is None:
        return normalized
    return _CANONICAL_MACHINE[platform_id]


def platform_id_for_host(system: str, machine: str) -> PlatformId | None:
    """Return the canonical platform ID for a modeled Linux host."""
    if system.casefold() != "linux":
        return None
    return _PLATFORM_BY_MACHINE.get(machine.casefold())


def current_platform_id() -> str:
    """Return a canonical local ID when known and a stable unsupported ID otherwise."""
    system = host_platform.system()
    machine = host_platform.machine()
    known = platform_id_for_host(system, machine)
    if known is not None:
        return known
    return f"{system.casefold()}-{normalize_machine(machine)}"


def require_platform_id(value: object) -> PlatformId:
    """Return a known canonical platform ID or reject the value."""
    if value == LINUX_X86_64:
        return LINUX_X86_64
    if value == LINUX_AARCH64:
        return LINUX_AARCH64
    raise ValueError("unknown release platform")


def machine_aliases(platform_id: PlatformId) -> tuple[str, ...]:
    """Return every accepted machine spelling for a canonical platform."""
    return _MACHINE_ALIASES[require_platform_id(platform_id)]


def platform_display_name(platform_id: PlatformId) -> str:
    """Return a stable human-readable platform description."""
    selected = require_platform_id(platform_id)
    return f"Linux {_CANONICAL_MACHINE[selected]}"


def artifact_name(version: str, platform_id: PlatformId) -> str:
    """Return the deterministic downloadable SCIE name for one release."""
    if not is_canonical_release_version(version):
        raise ValueError("invalid release version")
    selected = require_platform_id(platform_id)
    return f"xferry-{version}-{selected}"


def is_safe_artifact_name(value: object) -> TypeGuard[str]:
    """Return whether a value is a bounded portable basename."""
    return (
        isinstance(value, str)
        and _ASSET_NAME_RE.fullmatch(value) is not None
        and value not in {".", ".."}
        and Path(value).name == value
        and "/" not in value
        and "\\" not in value
        and "\x00" not in value
    )


def require_source_commit(value: object) -> str:
    """Return a canonical full source commit or reject it."""
    if not isinstance(value, str) or _SOURCE_COMMIT_RE.fullmatch(value) is None:
        raise ValueError("invalid source commit")
    return value


def require_workflow_run(value: object) -> str:
    """Return a positive workflow run ID or the deterministic local marker."""
    if not isinstance(value, str) or _WORKFLOW_RUN_RE.fullmatch(value) is None:
        raise ValueError("invalid workflow run")
    return value


def require_signing_key_id(value: object) -> str:
    """Return a bounded, portable release-signing key identifier."""
    if not isinstance(value, str) or _SIGNING_KEY_ID_RE.fullmatch(value) is None:
        raise ValueError("invalid signing key ID")
    return value


def _is_sha256(value: object) -> TypeGuard[str]:
    return isinstance(value, str) and _SHA256_RE.fullmatch(value) is not None


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate manifest key")
        result[key] = value
    return result


def _reject_json_constant(_value: str) -> NoReturn:
    raise ValueError("non-finite JSON value")


@dataclass(frozen=True)
class ReleaseManifest:
    """Validated release metadata shared by builders and managed consumers."""

    schema_version: int
    version: str
    tag: str
    platform: PlatformId
    executable_name: str
    executable_size: int
    executable_sha256: str
    source_commit: str | None = None
    workflow_run: str | None = None
    artifact_digests: tuple[tuple[str, str], ...] = ()
    signing_scheme: str | None = None
    signing_key_ids: tuple[str, ...] = ()

    @classmethod
    def create_v2(
        cls,
        *,
        version: str,
        platform: PlatformId,
        executable_size: int,
        executable_sha256: str,
        source_commit: str,
        workflow_run: str,
        artifact_digests: Mapping[str, str] | None = None,
        signing_key_ids: Sequence[str] = (),
    ) -> ReleaseManifest:
        """Create a strict v2 manifest ready for unsigned testing or detached signing."""
        selected_platform = require_platform_id(platform)
        name = artifact_name(version, selected_platform)
        digests = {name: executable_sha256} if artifact_digests is None else dict(artifact_digests)
        selected_key_ids = list(signing_key_ids)
        document: dict[str, object] = {
            "schema_version": 2,
            "version": version,
            "tag": f"v{version}",
            "platform": selected_platform,
            "executable": {
                "name": name,
                "size": executable_size,
                "sha256": executable_sha256,
            },
            "source": {
                "commit": source_commit,
                "workflow_run": workflow_run,
            },
            "artifact_digests": digests,
            "signing": {
                "scheme": "ed25519" if selected_key_ids else "unsigned",
                "key_ids": selected_key_ids,
            },
        }
        return cls._parse_document(document, require_v2=True)

    @classmethod
    def parse(cls, payload: bytes) -> ReleaseManifest:
        """Read a strict installed v1 or v2 manifest."""
        return cls._parse_payload(payload, require_v2=False)

    @classmethod
    def parse_new(cls, payload: bytes) -> ReleaseManifest:
        """Read a strict v2 manifest for a newly downloaded release."""
        return cls._parse_payload(payload, require_v2=True)

    @classmethod
    def _parse_payload(cls, payload: bytes, *, require_v2: bool) -> ReleaseManifest:
        try:
            if not isinstance(payload, bytes) or not 0 < len(payload) <= MAX_MANIFEST_BYTES:
                raise ValueError
            document = json.loads(
                payload.decode("utf-8"),
                object_pairs_hook=_reject_duplicate_keys,
                parse_constant=_reject_json_constant,
            )
            return cls._parse_document(document, require_v2=require_v2)
        except (UnicodeError, json.JSONDecodeError, KeyError, TypeError, ValueError):
            raise ValueError("invalid release manifest") from None

    @classmethod
    def _parse_document(
        cls,
        document: object,
        *,
        require_v2: bool,
    ) -> ReleaseManifest:
        if not isinstance(document, dict):
            raise ValueError
        schema_version = document.get("schema_version")
        if isinstance(schema_version, bool) or schema_version not in {1, 2}:
            raise ValueError
        if require_v2 and schema_version != 2:
            raise ValueError
        if schema_version == 1:
            return cls._parse_v1(document)
        return cls._parse_v2(document)

    @classmethod
    def _parse_v1(cls, document: dict[object, object]) -> ReleaseManifest:
        if set(document) != {
            "schema_version",
            "version",
            "tag",
            "platform",
            "executable",
        }:
            raise ValueError
        common = cls._parse_common(document)
        return cls(
            schema_version=1,
            **common,
            artifact_digests=((common["executable_name"], common["executable_sha256"]),),
        )

    @classmethod
    def _parse_v2(cls, document: dict[object, object]) -> ReleaseManifest:
        if set(document) != {
            "schema_version",
            "version",
            "tag",
            "platform",
            "executable",
            "source",
            "artifact_digests",
            "signing",
        }:
            raise ValueError
        common = cls._parse_common(document)
        source = document["source"]
        digest_document = document["artifact_digests"]
        signing = document["signing"]
        if not isinstance(source, dict) or set(source) != {"commit", "workflow_run"}:
            raise ValueError
        source_commit = source["commit"]
        workflow_run = source["workflow_run"]
        source_commit = require_source_commit(source["commit"])
        workflow_run = require_workflow_run(source["workflow_run"])
        if (
            not isinstance(digest_document, dict)
            or not digest_document
            or len(digest_document) > MAX_ARTIFACT_DIGESTS
        ):
            raise ValueError
        digests: list[tuple[str, str]] = []
        for name, digest in digest_document.items():
            if not is_safe_artifact_name(name) or not _is_sha256(digest):
                raise ValueError
            digests.append((name, digest))
        digest_map = dict(digests)
        if digest_map.get(common["executable_name"]) != common["executable_sha256"]:
            raise ValueError
        if not isinstance(signing, dict) or set(signing) != {"scheme", "key_ids"}:
            raise ValueError
        scheme = signing["scheme"]
        raw_key_ids = signing["key_ids"]
        if not isinstance(raw_key_ids, list):
            raise ValueError
        key_ids = tuple(require_signing_key_id(key_id) for key_id in raw_key_ids)
        if len(key_ids) != len(set(key_ids)) or tuple(sorted(key_ids)) != key_ids:
            raise ValueError
        if scheme == "unsigned":
            if key_ids:
                raise ValueError
        elif scheme == "ed25519":
            if not 0 < len(key_ids) <= MAX_SIGNING_KEY_IDS:
                raise ValueError
        else:
            raise ValueError
        return cls(
            schema_version=2,
            **common,
            source_commit=source_commit,
            workflow_run=workflow_run,
            artifact_digests=tuple(sorted(digests)),
            signing_scheme=scheme,
            signing_key_ids=key_ids,
        )

    @staticmethod
    def _parse_common(document: dict[object, object]) -> _CommonManifestFields:
        version = document["version"]
        tag = document["tag"]
        if not is_canonical_release_version(version) or tag != f"v{version}":
            raise ValueError
        platform_id = require_platform_id(document["platform"])
        executable = document["executable"]
        if not isinstance(executable, dict) or set(executable) != {"name", "size", "sha256"}:
            raise ValueError
        name = executable["name"]
        size = executable["size"]
        sha256 = executable["sha256"]
        if (
            not is_safe_artifact_name(name)
            or name != artifact_name(version, platform_id)
            or not isinstance(size, int)
            or isinstance(size, bool)
            or size < 1
            or not _is_sha256(sha256)
        ):
            raise ValueError
        return {
            "version": version,
            "tag": tag,
            "platform": platform_id,
            "executable_name": name,
            "executable_size": size,
            "executable_sha256": sha256,
        }

    def to_bytes(self) -> bytes:
        """Serialize this validated manifest in its canonical field order."""
        document: dict[str, object] = {
            "schema_version": self.schema_version,
            "version": self.version,
            "tag": self.tag,
            "platform": self.platform,
            "executable": {
                "name": self.executable_name,
                "size": self.executable_size,
                "sha256": self.executable_sha256,
            },
        }
        if self.schema_version == 2:
            document.update(
                {
                    "source": {
                        "commit": self.source_commit,
                        "workflow_run": self.workflow_run,
                    },
                    "artifact_digests": dict(self.artifact_digests),
                    "signing": {
                        "scheme": self.signing_scheme,
                        "key_ids": list(self.signing_key_ids),
                    },
                }
            )
        return (json.dumps(document, indent=2) + "\n").encode("utf-8")
