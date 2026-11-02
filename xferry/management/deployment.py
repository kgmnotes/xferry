"""Versioned deployment identity and ownership, independent of runtime state."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import uuid
from collections.abc import Mapping
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Literal

Backend = Literal["native", "docker"]
StateName = Literal["absent", "incomplete", "stopped", "running", "retained", "broken"]
MANIFEST_SCHEMA = 2


@dataclass(frozen=True)
class Credentials:
    username: str
    password: str = field(repr=False)
    url: str


@dataclass(frozen=True)
class OwnedResource:
    path: str
    kind: str = "file"
    sha256: str | None = None
    uid: int | None = None
    gid: int | None = None
    device: int | None = None
    inode: int | None = None
    size: int | None = None
    modified_ns: int | None = None
    mode: int | None = None


@dataclass(frozen=True)
class OwnershipReceipt:
    resources: tuple[OwnedResource, ...] = ()
    acl: tuple[dict[str, object], ...] = ()
    accounts: tuple[str, ...] = ()


@dataclass(frozen=True)
class DeploymentSpec:
    instance_id: str
    backend: Backend
    profile: Path
    files_dir: Path
    state_dir: Path
    artifact: Mapping[str, object]
    ownership: OwnershipReceipt = field(default_factory=OwnershipReceipt)
    backend_options: Mapping[str, object] = field(default_factory=dict)
    schema: int = MANIFEST_SCHEMA

    @classmethod
    def new(
        cls,
        backend: Backend,
        profile: Path,
        files_dir: Path,
        state_dir: Path,
        artifact: Mapping[str, object],
        *,
        ownership: OwnershipReceipt | None = None,
        backend_options: Mapping[str, object] | None = None,
    ) -> DeploymentSpec:
        return cls(
            str(uuid.uuid4()),
            backend,
            profile,
            files_dir,
            state_dir,
            artifact,
            ownership or OwnershipReceipt(),
            backend_options or {},
        )

    def to_json(self) -> dict[str, object]:
        result = asdict(self)
        for name in ("profile", "files_dir", "state_dir"):
            result[name] = str(getattr(self, name))
        result["artifact"] = dict(self.artifact)
        result["backend_options"] = dict(self.backend_options)
        return result


@dataclass(frozen=True)
class ObservedState:
    state: StateName
    instance_id: str | None = None
    backend: Backend | None = None
    health: str = "not_checked"
    detail: str = ""
    running: bool = False
    config: str = "unknown"
    enabled: str = "unknown"

    def to_json(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class OperationPlan:
    action: str
    instance_id: str | None = None
    steps: tuple[str, ...] = ()
    retains: tuple[str, ...] = ()


@dataclass(frozen=True)
class OperationResult:
    exit_code: int
    message: str
    details: Mapping[str, object] = field(default_factory=dict)
    credentials: Credentials | None = field(default=None, repr=False)
    url: str | None = None
    plan: OperationPlan | None = None
    state: ObservedState | None = None

    @property
    def code(self) -> str | None:
        code = self.details.get("code")
        return code if isinstance(code, str) else None

    @property
    def detail(self) -> str:
        return str(self.details.get("detail", ""))

    @property
    def next_actions(self) -> tuple[str, ...]:
        actions = self.details.get("next_actions", ())
        return (
            tuple(action for action in actions if isinstance(action, str))
            if isinstance(actions, (tuple, list))
            else ()
        )

    def to_json(self) -> dict[str, object]:
        # Secrets go through the explicit credentials renderer only.
        return {
            "exit_code": self.exit_code,
            "message": self.message,
            "details": dict(self.details),
            "url": self.url,
            "plan": asdict(self.plan) if self.plan else None,
            "state": self.state.to_json() if self.state else None,
        }


def read_document(path: Path, *, maximum: int = 1024 * 1024) -> dict[str, object]:
    """Read a bounded regular file through a no-follow descriptor."""
    descriptor = os.open(
        path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    )
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_size > maximum
        ):
            raise ValueError("deployment metadata must be a bounded regular file with one link")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            data = stream.read(maximum + 1)
        if len(data) > maximum:
            raise ValueError("deployment metadata is too large")
        document = json.loads(data)
        if not isinstance(document, dict):
            raise ValueError("deployment metadata must be an object")
        return document
    finally:
        os.close(descriptor)


def _absolute(value: object) -> Path:
    if not isinstance(value, str) or not value or any(c in value for c in "\x00\r\n"):
        raise ValueError("deployment paths must be absolute paths")
    path = Path(value)
    if not path.is_absolute() or ".." in path.parts:
        raise ValueError("deployment paths must be absolute paths without parent traversal")
    return path


def load_manifest(path: Path) -> DeploymentSpec:
    document = read_document(path)
    if document.get("schema") != MANIFEST_SCHEMA:
        raise ValueError("unsupported deployment schema; existing state was not changed")
    backend, identity = document.get("backend"), document.get("instance_id")
    if backend not in {"native", "docker"} or not isinstance(identity, str):
        raise ValueError("invalid deployment identity")
    try:
        if str(uuid.UUID(identity)) != identity:
            raise ValueError
    except ValueError:
        raise ValueError("invalid deployment instance ID") from None
    artifact, options = document.get("artifact"), document.get("backend_options", {})
    if not isinstance(artifact, dict) or not isinstance(options, dict):
        raise ValueError("invalid deployment artifact or backend options")
    if backend == "docker":
        image = artifact.get("image")
        if not isinstance(image, str) or not re.fullmatch(
            r"[a-z0-9][a-z0-9._:/-]*@sha256:[0-9a-f]{64}", image
        ):
            raise ValueError("Docker deployment must pin its actual image digest")
        project = options.get("project")
        if not isinstance(project, str) or not re.fullmatch(r"xferry-[a-z0-9_-]{1,57}", project):
            raise ValueError("invalid Docker project identity")
        storage = options.get("state_storage")
        expected_storage = {
            "kind": "docker_volume",
            "name": project + "_xferry-data",
            "runtime_root": "/data",
        }
        if storage is not None and storage != expected_storage:
            raise ValueError("Docker state volume identity disagrees with its project")
    elif not isinstance(artifact.get("version"), str) or not re.fullmatch(
        r"[0-9a-f]{64}", str(artifact.get("sha256", ""))
    ):
        raise ValueError("native deployment must record its exact artifact version and SHA256")
    receipt = document.get("ownership", {})
    if not isinstance(receipt, dict):
        raise ValueError("invalid ownership receipt")
    resources = []
    try:
        for resource in receipt.get("resources", []):
            if not isinstance(resource, dict):
                raise ValueError("invalid resource receipt")
            _absolute(resource.get("path"))
            resources.append(OwnedResource(**resource))
        acl, accounts = receipt.get("acl", []), receipt.get("accounts", [])
        if not isinstance(acl, list) or not all(isinstance(x, dict) for x in acl):
            raise ValueError("invalid ACL receipt")
        if not isinstance(accounts, list) or not all(isinstance(x, str) for x in accounts):
            raise ValueError("invalid account receipt")
    except TypeError:
        raise ValueError("invalid ownership receipt") from None
    return DeploymentSpec(
        identity,
        backend,
        _absolute(document.get("profile")),
        _absolute(document.get("files_dir")),
        _absolute(document.get("state_dir")),
        artifact,
        OwnershipReceipt(tuple(resources), tuple(acl), tuple(accounts)),
        options,
    )


def write_manifest(path: Path, spec: DeploymentSpec) -> None:
    from .docker_deploy import _atomic_write

    _atomic_write(
        path,
        (json.dumps(spec.to_json(), indent=2) + "\n").encode(),
        0o644 if spec.backend == "native" else 0o600,
    )


def resource_receipt(path: Path, *, kind: str = "file") -> OwnedResource:
    metadata = path.lstat()
    if kind in {"file", "secret"} and (
        not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1
    ):
        raise ValueError("owned deployment files must be regular files with one link")
    digest = hashlib.sha256(path.read_bytes()).hexdigest() if kind == "file" else None
    return OwnedResource(
        str(path.absolute()),
        kind,
        digest,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
        stat.S_IMODE(metadata.st_mode),
    )


def resource_unchanged(resource: OwnedResource) -> bool:
    path = Path(resource.path)
    try:
        metadata = path.lstat()
        if metadata.st_uid != resource.uid or metadata.st_gid != resource.gid:
            return False
        if resource.mode is not None and stat.S_IMODE(metadata.st_mode) != resource.mode:
            return False
        if resource.kind == "file":
            return (
                stat.S_ISREG(metadata.st_mode)
                and metadata.st_nlink == 1
                and hashlib.sha256(path.read_bytes()).hexdigest() == resource.sha256
            )
        if resource.kind == "secret":
            return (
                stat.S_ISREG(metadata.st_mode)
                and metadata.st_nlink == 1
                and metadata.st_dev == resource.device
                and metadata.st_ino == resource.inode
                and metadata.st_size == resource.size
                and metadata.st_mtime_ns == resource.modified_ns
            )
        return (
            stat.S_ISDIR(metadata.st_mode)
            and metadata.st_dev == resource.device
            and metadata.st_ino == resource.inode
        )
    except OSError:
        return False
