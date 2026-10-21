"""Create, verify, and safely transfer the exact unsigned release candidate files."""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import re
import stat
import sys
import tarfile
import zipfile
from collections.abc import Sequence
from email.parser import BytesParser
from pathlib import Path, PurePosixPath
from tempfile import TemporaryDirectory
from typing import NoReturn, TypedDict

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tools.check_release_preflight import version_from_tag  # noqa: E402
from xferry.management.release_contract import (  # noqa: E402
    SUPPORTED_PLATFORM_IDS,
    ReleaseManifest,
    artifact_name,
    release_manifest_asset_name,
    require_workflow_run,
)
from xferry.management.versions import is_supported_release_version  # noqa: E402

INVENTORY_NAME = "candidate-inventory.json"
_SHA_RE = re.compile(r"[0-9a-f]{64}\Z")
_COMMIT_RE = re.compile(r"[0-9a-f]{40}\Z")
_DIGEST_RE = re.compile(r"sha256:([0-9a-f]{64})\Z")
_MAX_JSON_BYTES = 16 * 1024 * 1024
_INDEX_TYPES = {
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
}
_MANIFEST_TYPES = {
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
}
_CONFIG_TYPES = {
    "application/vnd.oci.image.config.v1+json",
    "application/vnd.docker.container.image.v1+json",
}
_LAYER_TYPES = {
    "application/vnd.oci.image.layer.v1.tar",
    "application/vnd.oci.image.layer.v1.tar+gzip",
    "application/vnd.oci.image.layer.v1.tar+zstd",
    "application/vnd.docker.image.rootfs.diff.tar",
    "application/vnd.docker.image.rootfs.diff.tar.gzip",
}
_ATTESTATION_TYPE = "application/vnd.in-toto+json"
_ATTESTATION_MANIFEST_TYPE = "application/vnd.docker.attestation.manifest.v1+json"
_EMPTY_CONFIG_TYPE = "application/vnd.oci.empty.v1+json"
_SBOM_PREDICATES = {"https://spdx.dev/Document", "https://cyclonedx.org/bom"}
_PROVENANCE_PREDICATES = {
    "https://slsa.dev/provenance/v0.2",
    "https://slsa.dev/provenance/v1",
}


class FileRecord(TypedDict):
    """The promoted bytes and permissions bound by the candidate inventory."""

    size: int
    sha256: str
    mode: int


def _canonical(document: object) -> bytes:
    return (json.dumps(document, sort_keys=True, indent=2, allow_nan=False) + "\n").encode()


def _duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    document: dict[str, object] = {}
    for key, value in pairs:
        if key in document:
            raise ValueError("duplicate JSON key")
        document[key] = value
    return document


def _invalid_constant(_value: str) -> NoReturn:
    raise ValueError("non-finite JSON value")


def _json(path: Path) -> dict[str, object]:
    if path.stat().st_size > _MAX_JSON_BYTES:
        raise ValueError(f"JSON metadata is too large: {path.name}")
    document = json.loads(
        path.read_bytes(), object_pairs_hook=_duplicate_keys, parse_constant=_invalid_constant
    )
    if not isinstance(document, dict):
        raise ValueError("JSON metadata must be an object")
    return document


def _sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _require_sha(value: str) -> str:
    if _SHA_RE.fullmatch(value) is None:
        raise ValueError("expected SHA256 must be 64 lowercase hexadecimal characters")
    return value


def _identity(tag: str, source_commit: str, workflow_run: str) -> str:
    version = version_from_tag(tag)
    if not is_supported_release_version(version):
        raise ValueError("candidate version is outside the supported release line")
    if _COMMIT_RE.fullmatch(source_commit) is None:
        raise ValueError("source commit must be exactly 40 lowercase hexadecimal characters")
    require_workflow_run(workflow_run)
    return version


def _safe_path(name: str, *, directory: bool = False) -> str:
    if directory and name.endswith("/"):
        name = name[:-1]
    parts = name.split("/")
    if (
        not name
        or name.startswith("/")
        or "\\" in name
        or ":" in name
        or any(ord(character) < 32 or ord(character) == 127 for character in name)
        or any(part in {"", ".", ".."} for part in parts)
        or PurePosixPath(name).as_posix() != name
    ):
        raise ValueError(f"unsafe candidate path: {name!r}")
    return name


def _scan(root: Path) -> tuple[dict[str, FileRecord], set[str]]:
    if root.is_symlink() or not root.is_dir():
        raise ValueError("candidate root must be a real directory")
    files: dict[str, FileRecord] = {}
    directories: set[str] = set()
    for path in sorted(root.rglob("*")):
        relative = _safe_path(path.relative_to(root).as_posix())
        metadata = path.lstat()
        mode = stat.S_IMODE(metadata.st_mode)
        if mode & ~0o777:
            raise ValueError(f"special permission bits are not allowed: {relative}")
        if stat.S_ISDIR(metadata.st_mode):
            directories.add(relative)
        elif stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1:
            files[relative] = {"size": metadata.st_size, "sha256": _sha(path), "mode": mode}
        else:
            raise ValueError(f"candidate must contain regular files and directories: {relative}")
    return files, directories


def _metadata(payload: bytes, version: str) -> None:
    document = BytesParser().parsebytes(payload)
    if document.get_all("Name") != ["xferry"] or document.get_all("Version") != [version]:
        raise ValueError("Python archive metadata does not match the requested release identity")


def _python(root: Path, version: str) -> None:
    wheel = root / f"python/xferry-{version}-py3-none-any.whl"
    with zipfile.ZipFile(wheel) as archive:
        members = archive.infolist()
        names = [_safe_path(member.filename, directory=member.is_dir()) for member in members]
        if len(names) != len(set(names)):
            raise ValueError("duplicate wheel archive path")
        for member in members:
            file_type = stat.S_IFMT(member.external_attr >> 16)
            if file_type not in {0, stat.S_IFREG, stat.S_IFDIR}:
                raise ValueError("unsafe wheel archive member")
        metadata = [member for member in members if member.filename.endswith(".dist-info/METADATA")]
        expected = f"xferry-{version}.dist-info/METADATA"
        if len(metadata) != 1 or metadata[0].filename != expected:
            raise ValueError("wheel metadata filename does not match requested release")
        if metadata[0].file_size > _MAX_JSON_BYTES:
            raise ValueError("wheel metadata is too large")
        _metadata(archive.read(metadata[0]), version)
        if archive.testzip() is not None:
            raise ValueError("wheel content CRC mismatch")
    sdist = root / f"python/xferry-{version}.tar.gz"
    with tarfile.open(sdist, "r:gz") as archive:
        members = archive.getmembers()
        names = [_safe_path(member.name, directory=member.isdir()) for member in members]
        if len(names) != len(set(names)):
            raise ValueError("duplicate sdist archive path")
        if any(not member.isfile() and not member.isdir() for member in members):
            raise ValueError("unsafe sdist archive member")
        if any(
            not name.startswith(f"xferry-{version}/")
            for name in names
            if name != f"xferry-{version}"
        ):
            raise ValueError("sdist root does not match requested release")
        metadata = [member for member in members if member.name == f"xferry-{version}/PKG-INFO"]
        if len(metadata) != 1 or metadata[0].size > _MAX_JSON_BYTES:
            raise ValueError("sdist must contain one bounded root PKG-INFO")
        stream = archive.extractfile(metadata[0])
        if stream is None:
            raise ValueError("sdist PKG-INFO is not a regular file")
        with stream:
            _metadata(stream.read(), version)
    sbom = _json(root / "python/xferry-dependency-sbom.cdx.json")
    if sbom.get("bomFormat") != "CycloneDX" or not isinstance(sbom.get("specVersion"), str):
        raise ValueError("Python dependency SBOM must be a CycloneDX JSON document")


def _scie(
    root: Path, files: dict[str, FileRecord], version: str, source_commit: str, workflow_run: str
) -> None:
    for platform in SUPPORTED_PLATFORM_IDS:
        directory = root / f"scie-{platform}"
        name = artifact_name(version, platform)
        executable = files[f"scie-{platform}/{name}"]
        payload = (directory / "xferry-release.json").read_bytes()
        manifest = ReleaseManifest.parse_new(payload)
        if (
            manifest.to_bytes() != payload
            or manifest.version != version
            or manifest.platform != platform
            or manifest.source_commit != source_commit
            or manifest.workflow_run != workflow_run
            or manifest.executable_name != name
            or manifest.executable_size != executable["size"]
            or manifest.executable_sha256 != executable["sha256"]
            or manifest.signing_scheme != "unsigned"
            or manifest.signing_key_ids
        ):
            raise ValueError("SCIE manifest does not match the unsigned candidate identity")
        _installer(directory / "install.sh", manifest, payload)
        digests = dict(manifest.artifact_digests)
        if set(digests) - {name, "install.sh"}:
            raise ValueError("SCIE manifest names an unexpected candidate artifact")
        for digest_name, digest in digests.items():
            if files[f"scie-{platform}/{digest_name}"]["sha256"] != digest:
                raise ValueError("SCIE artifact digest mismatch")
        if (directory / "SHA256SUMS").read_bytes() != f"{executable['sha256']}  {name}\n".encode():
            raise ValueError("SCIE checksums must match the exact executable name and digest")
        if (
            not executable["mode"] & 0o111
            or not files[f"scie-{platform}/install.sh"]["mode"] & 0o111
        ):
            raise ValueError("SCIE executable and installer must retain executable permissions")


def _installer(path: Path, manifest: ReleaseManifest, manifest_payload: bytes) -> None:
    if path.stat().st_size > _MAX_JSON_BYTES:
        raise ValueError("SCIE installer is too large")
    payload = path.read_text(encoding="utf-8")
    fields = {
        "version": manifest.version,
        "platform_id": manifest.platform,
        "artifact_name": manifest.executable_name,
        "artifact_size": str(manifest.executable_size),
        "artifact_sha256": manifest.executable_sha256,
        "manifest_signature_required": "false",
        "hosted_signature_required": "true",
        "hosted_manifest_name": release_manifest_asset_name(manifest.platform),
        "supported_release_major": manifest.version.split(".", 1)[0],
    }
    if not payload.startswith("#!/bin/sh\n") or any(
        re.findall(rf"^{name}='([^'\n]*)'$", payload, re.MULTILINE) != [value]
        for name, value in fields.items()
    ):
        raise ValueError("SCIE installer fields must match the unsigned release manifest")
    embedded = re.findall(
        r"^cat > \"\$candidate_release/xferry-release.json\" <<'XFERRY_CANDIDATE_MANIFEST'\n"
        r"(.*?)\nXFERRY_CANDIDATE_MANIFEST$",
        payload,
        re.MULTILINE | re.DOTALL,
    )
    if len(embedded) != 1 or (embedded[0] + "\n").encode() != manifest_payload:
        raise ValueError("SCIE installer must embed the exact canonical release manifest")


class _OCI:
    """Validate all reachable OCI content, including nested Buildx attestations."""

    def __init__(
        self, root: Path, files: dict[str, FileRecord], version: str, source_commit: str
    ) -> None:
        self.root = root
        self.files = files
        self.version = version
        self.source_commit = source_commit
        self.used: set[str] = set()
        self.visiting: set[str] = set()
        self.platforms: dict[str, str] = {}
        self.attestations: dict[str, set[str]] = {}
        self.descriptors = 0

    def _descriptor(self, descriptor: object) -> tuple[dict[str, object], str, Path]:
        if not isinstance(descriptor, dict):
            raise ValueError("OCI descriptor must be an object")
        digest = descriptor.get("digest")
        size = descriptor.get("size")
        media_type = descriptor.get("mediaType")
        if (
            not isinstance(digest, str)
            or _DIGEST_RE.fullmatch(digest) is None
            or not isinstance(size, int)
            or isinstance(size, bool)
            or size < 0
            or not isinstance(media_type, str)
            or "urls" in descriptor
        ):
            raise ValueError("OCI descriptor requires local SHA256 content and an exact size")
        relative = f"oci/blobs/sha256/{digest[7:]}"
        record = self.files.get(relative)
        if record is None or record["size"] != size or record["sha256"] != digest[7:]:
            raise ValueError("OCI blob digest or size mismatch")
        if "data" in descriptor:
            encoded = descriptor["data"]
            if not isinstance(encoded, str) or len(encoded) > 2 * _MAX_JSON_BYTES:
                raise ValueError("OCI embedded data must be bounded base64 content")
            try:
                embedded = base64.b64decode(encoded, validate=True)
            except (binascii.Error, ValueError) as error:
                raise ValueError("OCI embedded data is not valid base64") from error
            if len(embedded) != size or hashlib.sha256(embedded).hexdigest() != digest[7:]:
                raise ValueError("OCI embedded data must match its local blob digest and size")
        self.used.add(relative)
        self.descriptors += 1
        if self.descriptors > 10000:
            raise ValueError("too many OCI descriptors")
        return descriptor, media_type, self.root / relative

    def _node(self, descriptor: object, depth: int = 0) -> None:
        selected, media_type, path = self._descriptor(descriptor)
        digest = str(selected["digest"])
        if depth > 32 or digest in self.visiting:
            raise ValueError("cyclic or excessively nested OCI layout")
        self.visiting.add(digest)
        document = _json(path)
        if type(document.get("schemaVersion")) is not int or document["schemaVersion"] != 2:
            raise ValueError("OCI document must use schemaVersion 2")
        if "mediaType" in document and document["mediaType"] != media_type:
            raise ValueError("OCI document media type does not match its descriptor")
        if "subject" in document:
            self._descriptor(document["subject"])
        if media_type in _INDEX_TYPES:
            before = set(self.platforms)
            self._index(document, depth + 1)
            claimed = selected.get("platform")
            if claimed is not None and (
                not isinstance(claimed, dict)
                or claimed.get("os") != "linux"
                or not isinstance(claimed.get("architecture"), str)
                or claimed.get("architecture") not in {"amd64", "arm64"}
                or set(self.platforms) - before != {f"linux/{claimed['architecture']}"}
            ):
                raise ValueError("OCI nested index platform does not match its runnable images")
        elif media_type in _MANIFEST_TYPES:
            self._manifest(document, selected, digest)
        else:
            raise ValueError("OCI index must reference image indexes or manifests")
        self.visiting.remove(digest)

    def _index(self, document: dict[str, object], depth: int) -> None:
        manifests = document.get("manifests")
        if not isinstance(manifests, list) or not manifests:
            raise ValueError("OCI index must contain image descriptors")
        for descriptor in manifests:
            self._node(descriptor, depth)

    def _manifest(
        self, document: dict[str, object], descriptor: dict[str, object], digest: str
    ) -> None:
        _config, config_type, config_path = self._descriptor(document.get("config"))
        if config_type not in _CONFIG_TYPES | {_EMPTY_CONFIG_TYPE}:
            raise ValueError("OCI image must reference an image config")
        config = _json(config_path)
        os_name, architecture = config.get("os"), config.get("architecture")
        platform = descriptor.get("platform")
        if config_type == _EMPTY_CONFIG_TYPE:
            if (
                config != {}
                or document.get("artifactType") != _ATTESTATION_MANIFEST_TYPE
                or not isinstance(platform, dict)
                or (platform.get("os"), platform.get("architecture")) != ("unknown", "unknown")
            ):
                raise ValueError(
                    "empty OCI config is allowed only for unknown/unknown attestations"
                )
            os_name, architecture = "unknown", "unknown"
        if platform is not None:
            if not isinstance(platform, dict) or (
                platform.get("os"),
                platform.get("architecture"),
            ) != (os_name, architecture):
                raise ValueError("OCI descriptor platform does not match image config")
        layers = document.get("layers")
        if not isinstance(layers, list) or not layers:
            raise ValueError("OCI image must contain layers")
        if (os_name, architecture) == ("unknown", "unknown"):
            self._attestation(layers, descriptor, document.get("subject"))
            return
        if (
            not isinstance(architecture, str)
            or os_name != "linux"
            or architecture not in {"amd64", "arm64"}
        ):
            raise ValueError("OCI candidate contains an unsupported runnable platform")
        if "subject" in document or "artifactType" in document:
            raise ValueError("runnable OCI image must not be an attestation artifact")
        identity = f"linux/{architecture}"
        if identity in self.platforms:
            raise ValueError("OCI candidate contains a duplicate runnable platform")
        settings = config.get("config")
        labels = settings.get("Labels") if isinstance(settings, dict) else None
        if not isinstance(labels, dict) or (
            labels.get("org.opencontainers.image.version") != self.version
            or labels.get("org.opencontainers.image.revision") != self.source_commit
        ):
            raise ValueError("OCI image labels do not match release version and source commit")
        for layer in layers:
            _selected, layer_type, _path = self._descriptor(layer)
            if layer_type not in _LAYER_TYPES:
                raise ValueError("runnable OCI image contains an unexpected layer type")
        self.platforms[identity] = digest

    def _attestation(
        self, layers: list[object], descriptor: dict[str, object], subject: object
    ) -> None:
        annotations = descriptor.get("annotations")
        if not isinstance(annotations, dict) or (
            annotations.get("vnd.docker.reference.type") != "attestation-manifest"
        ):
            raise ValueError("unknown/unknown OCI content must be a Buildx attestation")
        reference = annotations.get("vnd.docker.reference.digest")
        if not isinstance(reference, str) or _DIGEST_RE.fullmatch(reference) is None:
            raise ValueError("OCI attestation must identify its platform manifest")
        if subject is not None:
            selected, subject_type, _path = self._descriptor(subject)
            if selected["digest"] != reference or subject_type not in _MANIFEST_TYPES:
                raise ValueError(
                    "OCI attestation subject must match its platform manifest reference"
                )
        predicates = self.attestations.setdefault(reference, set())
        for layer in layers:
            _selected, layer_type, path = self._descriptor(layer)
            if layer_type != _ATTESTATION_TYPE:
                raise ValueError("OCI attestations require in-toto JSON layers")
            statement = _json(path)
            if (
                not isinstance(statement.get("_type"), str)
                or statement["_type"]
                not in {"https://in-toto.io/Statement/v0.1", "https://in-toto.io/Statement/v1"}
                or not isinstance(statement.get("predicateType"), str)
            ):
                raise ValueError("OCI attestation layer must be an in-toto statement")
            subjects = statement.get("subject")
            if not isinstance(subjects, list):
                raise ValueError("in-toto attestation subjects must be an array")
            bound_subject = any(
                isinstance(entry, dict)
                and isinstance(entry.get("digest"), dict)
                and entry["digest"].get("sha256") == reference[7:]
                for entry in subjects
            )
            if (subjects and not bound_subject) or (subject is None and not bound_subject):
                raise ValueError("in-toto subjects must bind the referenced platform image digest")
            predicate = statement.get("predicate")
            if not isinstance(predicate, dict) or not predicate:
                raise ValueError("OCI attestation must contain a nonempty predicate object")
            predicate_type = str(statement["predicateType"])
            if predicate_type == "https://spdx.dev/Document" and (
                not isinstance(predicate.get("spdxVersion"), str)
                or not str(predicate["spdxVersion"]).startswith("SPDX-")
                or not isinstance(predicate.get("packages"), list)
                or not predicate["packages"]
            ):
                raise ValueError("SPDX attestation must contain an SPDX version and packages")
            if predicate_type == "https://cyclonedx.org/bom" and (
                predicate.get("bomFormat") != "CycloneDX"
                or not isinstance(predicate.get("components"), list)
                or not predicate["components"]
            ):
                raise ValueError("CycloneDX attestation must contain dependency components")
            if predicate_type == "https://slsa.dev/provenance/v0.2":
                builder = predicate.get("builder")
                if (
                    not isinstance(predicate.get("buildType"), str)
                    or not str(predicate["buildType"]).strip()
                    or not isinstance(builder, dict)
                    or not isinstance(builder.get("id"), str)
                    or not str(builder["id"]).strip()
                ):
                    raise ValueError("SLSA v0.2 provenance requires buildType and builder.id")
            if predicate_type == "https://slsa.dev/provenance/v1":
                definition = predicate.get("buildDefinition")
                details = predicate.get("runDetails")
                builder = details.get("builder") if isinstance(details, dict) else None
                if (
                    not isinstance(definition, dict)
                    or not definition
                    or not isinstance(details, dict)
                    or not details
                    or not isinstance(definition.get("buildType"), str)
                    or not str(definition["buildType"]).strip()
                    or not isinstance(builder, dict)
                    or not isinstance(builder.get("id"), str)
                ):
                    raise ValueError("SLSA v1 provenance requires buildDefinition and runDetails")
            predicates.add(predicate_type)

    def verify(self) -> dict[str, object]:
        layout = _json(self.root / "oci/oci-layout")
        if layout != {"imageLayoutVersion": "1.0.0"}:
            raise ValueError("OCI layout must have imageLayoutVersion 1.0.0")
        index = _json(self.root / "oci/index.json")
        if type(index.get("schemaVersion")) is not int or index["schemaVersion"] != 2:
            raise ValueError("OCI index must use schemaVersion 2")
        if "mediaType" in index and (
            not isinstance(index["mediaType"], str) or index["mediaType"] not in _INDEX_TYPES
        ):
            raise ValueError("OCI root must be an image index")
        self._index(index, 0)
        if set(self.platforms) != {"linux/amd64", "linux/arm64"}:
            raise ValueError("OCI candidate requires exactly linux/amd64 and linux/arm64")
        if set(self.attestations) != set(self.platforms.values()):
            raise ValueError("OCI attestations must reference every runnable platform manifest")
        for predicates in self.attestations.values():
            if not predicates & _SBOM_PREDICATES or not predicates & _PROVENANCE_PREDICATES:
                raise ValueError("every OCI platform requires SBOM and provenance attestations")
        blobs = {name for name in self.files if name.startswith("oci/blobs/")}
        if self.used != blobs:
            raise ValueError("OCI layout contains unreferenced or missing blob content")
        digest = str(self.files["oci/index.json"]["sha256"])
        return {
            "root_digest": f"sha256:{digest}",
            "index_sha256": digest,
            "platform_manifests": dict(sorted(self.platforms.items())),
        }


def _document(
    root: Path, tag: str, source_commit: str, workflow_run: str, *, include_inventory: bool
) -> dict[str, object]:
    version = _identity(tag, source_commit, workflow_run)
    files, directories = _scan(root)
    expected = {
        f"python/xferry-{version}-py3-none-any.whl",
        f"python/xferry-{version}.tar.gz",
        "python/xferry-dependency-sbom.cdx.json",
        "oci/oci-layout",
        "oci/index.json",
    }
    for platform in SUPPORTED_PLATFORM_IDS:
        expected.update(
            f"scie-{platform}/{name}"
            for name in (
                artifact_name(version, platform),
                "install.sh",
                "xferry-release.json",
                "SHA256SUMS",
            )
        )
    if include_inventory:
        expected.add(INVENTORY_NAME)
    blobs = {name for name in files if re.fullmatch(r"oci/blobs/sha256/[0-9a-f]{64}", name)}
    if set(files) != expected | blobs:
        raise ValueError("candidate files do not match the exact Python/SCIE/OCI layout")
    if directories != {
        "python",
        "oci",
        "oci/blobs",
        "oci/blobs/sha256",
        *(f"scie-{platform}" for platform in SUPPORTED_PLATFORM_IDS),
    }:
        raise ValueError("candidate contains missing or unexpected directories")
    if include_inventory:
        del files[INVENTORY_NAME]
    _python(root, version)
    _scie(root, files, version, source_commit, workflow_run)
    oci = _OCI(root, files, version, source_commit).verify()
    return {
        "schema_version": 1,
        "version": version,
        "tag": tag,
        "source_commit": source_commit,
        "workflow_run": workflow_run,
        "files": files,
        "oci": oci,
    }


def create_inventory(root: Path, tag: str, source_commit: str, workflow_run: str) -> str:
    """Validate the full candidate and write one immutable canonical inventory."""
    root = Path(root)
    document = _document(root, tag, source_commit, workflow_run, include_inventory=False)
    payload = _canonical(document)
    with (root / INVENTORY_NAME).open("xb") as stream:
        stream.write(payload)
    return hashlib.sha256(payload).hexdigest()


def verify_inventory(
    root: Path,
    tag: str,
    source_commit: str,
    workflow_run: str,
    *,
    expected_sha256: str | None = None,
) -> str:
    """Revalidate every candidate byte and identity against the canonical inventory."""
    root = Path(root)
    path = root / INVENTORY_NAME
    if path.is_symlink() or not path.is_file():
        raise ValueError("candidate inventory must be a regular file")
    digest = _sha(path)
    if expected_sha256 is not None and digest != _require_sha(expected_sha256):
        raise ValueError("candidate inventory SHA256 does not match the producer digest")
    inventory = _json(path)
    payload = path.read_bytes()
    if _canonical(inventory) != payload:
        raise ValueError("candidate inventory must use canonical sorted JSON bytes")
    actual = _document(root, tag, source_commit, workflow_run, include_inventory=True)
    if payload != _canonical(actual):
        raise ValueError("candidate inventory does not match candidate bytes or requested identity")
    return digest


def normalize_oci_export(root: Path) -> None:
    """Remove BuildKit's empty local-content-store ingest directory, if present."""
    root = Path(root)
    oci = root / "oci"
    if root.is_symlink() or not root.is_dir() or oci.is_symlink() or not oci.is_dir():
        raise ValueError("OCI candidate root and OCI directory must be real directories")
    ingest = oci / "ingest"
    if ingest.is_symlink():
        raise ValueError("OCI ingest path must be an empty directory")
    if not ingest.exists():
        return
    if not ingest.is_dir():
        raise ValueError("OCI ingest path must be an empty directory")
    try:
        ingest.rmdir()
    except OSError as error:
        raise ValueError("OCI ingest path must be an empty directory") from error


def pack_candidate(root: Path, archive: Path) -> str:
    """Write a new deterministic tar archive preserving regular permission bits."""
    root, archive = Path(root), Path(archive)
    if archive.resolve().is_relative_to(root.resolve()):
        raise ValueError("candidate archive must be outside its input root")
    files, directories = _scan(root)
    with archive.open("xb") as stream:
        try:
            with tarfile.open(fileobj=stream, mode="w", format=tarfile.PAX_FORMAT) as output:
                for name in sorted(set(files) | directories):
                    path = root / name
                    info = tarfile.TarInfo(name)
                    info.mode = stat.S_IMODE(path.stat().st_mode)
                    if name in directories:
                        info.type = tarfile.DIRTYPE
                        output.addfile(info)
                    else:
                        info.size = path.stat().st_size
                        with path.open("rb") as contents:
                            output.addfile(info, contents)
        except BaseException:
            archive.unlink()
            raise
    return _sha(archive)


def unpack_candidate(archive: Path, expected_sha256: str, root: Path) -> None:
    """Authenticate an archive before parsing, then extract validated regular members."""
    archive, root = Path(archive), Path(root)
    if archive.is_symlink() or not archive.is_file():
        raise ValueError("candidate archive must be a regular file")
    if _sha(archive) != _require_sha(expected_sha256):
        raise ValueError("candidate archive SHA256 does not match the producer digest")
    if root.is_symlink() or (root.exists() and (not root.is_dir() or any(root.iterdir()))):
        raise ValueError("candidate extraction root must be new or empty")
    with tarfile.open(archive, "r:*") as source:
        members = source.getmembers()
        paths: dict[str, tarfile.TarInfo] = {}
        for member in members:
            name = _safe_path(member.name, directory=member.isdir())
            if name in paths or member.mode & ~0o777 or member.size < 0:
                raise ValueError("duplicate archive path or unsafe member permissions/size")
            if not member.isfile() and not member.isdir():
                raise ValueError("archive must contain only regular files and directories")
            if member.isdir() and member.size:
                raise ValueError("archive directory must not carry content")
            paths[name] = member
        for name in paths:
            for parent in PurePosixPath(name).parents:
                if str(parent) in paths and not paths[str(parent)].isdir():
                    raise ValueError("archive file is also used as a parent directory")
        root.parent.mkdir(parents=True, exist_ok=True)
        with TemporaryDirectory(prefix=".candidate-unpack-", dir=root.parent) as temporary:
            target = Path(temporary) / "candidate"
            target.mkdir()
            for name, member in sorted(paths.items()):
                output = target / name
                if member.isdir():
                    output.mkdir(parents=True, exist_ok=True)
                else:
                    output.parent.mkdir(parents=True, exist_ok=True)
                    contents = source.extractfile(member)
                    if contents is None:
                        raise ValueError("archive regular file has no content")
                    with contents, output.open("xb") as stream:
                        while chunk := contents.read(1024 * 1024):
                            stream.write(chunk)
                    if output.stat().st_size != member.size:
                        raise ValueError("archive file size mismatch")
                    output.chmod(member.mode)
            for name, member in sorted(paths.items(), reverse=True):
                if member.isdir():
                    (target / name).chmod(member.mode)
            if root.is_symlink() or (root.exists() and (not root.is_dir() or any(root.iterdir()))):
                raise ValueError("candidate extraction root changed during verification")
            target.replace(root)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    for command in ("create", "verify"):
        selected = subparsers.add_parser(command)
        selected.add_argument("--candidate-dir", dest="root", type=Path, required=True)
        selected.add_argument("--tag", required=True)
        selected.add_argument("--source-commit", required=True)
        selected.add_argument("--workflow-run", required=True)
        if command == "verify":
            selected.add_argument("--expected-sha256")
    pack = subparsers.add_parser("pack")
    pack.add_argument("--candidate-dir", dest="root", type=Path, required=True)
    pack.add_argument("--archive", type=Path, required=True)
    unpack = subparsers.add_parser("unpack")
    unpack.add_argument("--archive", type=Path, required=True)
    unpack.add_argument("--expected-sha256", required=True)
    unpack.add_argument("--candidate-dir", dest="root", type=Path, required=True)
    normalize = subparsers.add_parser("normalize-oci")
    normalize.add_argument("--candidate-dir", dest="root", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "normalize-oci":
            normalize_oci_export(args.root)
        elif args.command == "pack":
            print(pack_candidate(args.root, args.archive))
        elif args.command == "unpack":
            unpack_candidate(args.archive, args.expected_sha256, args.root)
        elif args.command == "create":
            print(create_inventory(args.root, args.tag, args.source_commit, args.workflow_run))
        else:
            print(
                verify_inventory(
                    args.root,
                    args.tag,
                    args.source_commit,
                    args.workflow_run,
                    expected_sha256=args.expected_sha256,
                )
            )
    except (OSError, UnicodeError, ValueError, tarfile.TarError, zipfile.BadZipFile) as error:
        print(f"candidate {args.command} failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
