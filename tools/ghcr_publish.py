"""Verify and stage the fixed STAGE-009 OCI candidate for GHCR promotion."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tools.candidate_inventory import unpack_candidate, verify_inventory  # noqa: E402

IDENTITY_FILE = REPO_ROOT / "packaging/ghcr-candidate.json"
IMAGE_NAME = "ghcr.io/kgmnotes/xferry"
RECEIPT_NAME = "ghcr-candidate-receipt.json"
_INDEX_TYPES = {
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
}
_MANIFEST_TYPES = {
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
}
_SBOM_PREDICATES = {"https://spdx.dev/Document", "https://cyclonedx.org/bom"}
_PROVENANCE_PREDICATES = {
    "https://slsa.dev/provenance/v0.2",
    "https://slsa.dev/provenance/v1",
}


def _json(path: Path) -> dict[str, Any]:
    document = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        raise ValueError(f"JSON document must be an object: {path}")
    return document


def _write_json(path: Path, document: Mapping[str, Any]) -> None:
    path.write_text(json.dumps(document, sort_keys=True, indent=2) + "\n", encoding="utf-8")


def _sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _descriptor_path(oci: Path, descriptor: Mapping[str, Any]) -> Path:
    digest = descriptor.get("digest")
    size = descriptor.get("size")
    if not isinstance(digest, str) or not digest.startswith("sha256:"):
        raise ValueError("OCI descriptor is missing a SHA256 digest")
    path = oci / "blobs" / "sha256" / digest[7:]
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"OCI descriptor blob is missing: {digest}")
    if not isinstance(size, int) or path.stat().st_size != size or _sha(path) != digest[7:]:
        raise ValueError(f"OCI descriptor digest or size mismatch: {digest}")
    return path


def _read_descriptor(oci: Path, descriptor: Mapping[str, Any]) -> dict[str, Any]:
    return _json(_descriptor_path(oci, descriptor))


def _platform_key(platform: object) -> str | None:
    if not isinstance(platform, dict):
        return None
    os_name = platform.get("os")
    architecture = platform.get("architecture")
    if os_name == "linux" and architecture in {"amd64", "arm64"}:
        return f"linux/{architecture}"
    return None


def _collect_index(
    oci: Path,
    document: Mapping[str, Any],
    *,
    platforms: dict[str, str],
    attestation_predicates: dict[str, set[str]],
    attestation_manifests: dict[str, set[str]],
) -> None:
    manifests = document.get("manifests")
    if not isinstance(manifests, list) or not manifests:
        raise ValueError("OCI index must contain manifests")
    for descriptor in manifests:
        if not isinstance(descriptor, dict):
            raise ValueError("OCI descriptor must be an object")
        media_type = descriptor.get("mediaType")
        platform = descriptor.get("platform")
        platform_key = _platform_key(platform)
        if platform_key is not None:
            if media_type not in _MANIFEST_TYPES:
                raise ValueError("runnable platform descriptor must reference an image manifest")
            platforms[platform_key] = str(descriptor["digest"])
            _read_descriptor(oci, descriptor)
            continue
        if isinstance(platform, dict) and (platform.get("os"), platform.get("architecture")) == (
            "unknown",
            "unknown",
        ):
            _collect_attestation(
                oci,
                descriptor,
                attestation_predicates,
                attestation_manifests,
            )
            continue
        if media_type in _INDEX_TYPES:
            _collect_index(
                oci,
                _read_descriptor(oci, descriptor),
                platforms=platforms,
                attestation_predicates=attestation_predicates,
                attestation_manifests=attestation_manifests,
            )
            continue
        raise ValueError("OCI registry graph contains an unsupported descriptor")


def _collect_attestation(
    oci: Path,
    descriptor: Mapping[str, Any],
    attestation_predicates: dict[str, set[str]],
    attestation_manifests: dict[str, set[str]],
) -> None:
    annotations = descriptor.get("annotations")
    reference = (
        annotations.get("vnd.docker.reference.digest") if isinstance(annotations, dict) else None
    )
    descriptor_digest = descriptor.get("digest")
    if (
        descriptor.get("mediaType") not in _MANIFEST_TYPES
        or not isinstance(reference, str)
        or not reference.startswith("sha256:")
        or not isinstance(descriptor_digest, str)
        or not descriptor_digest.startswith("sha256:")
    ):
        raise ValueError("unknown platform descriptor is not a Buildx attestation")
    manifest = _read_descriptor(oci, descriptor)
    layers = manifest.get("layers")
    if not isinstance(layers, list) or not layers:
        raise ValueError("OCI attestation manifest must contain in-toto layers")
    attestation_manifests.setdefault(reference, set()).add(descriptor_digest)
    predicates = attestation_predicates.setdefault(reference, set())
    for layer in layers:
        if not isinstance(layer, dict):
            raise ValueError("OCI attestation layer descriptor must be an object")
        statement = _json(_descriptor_path(oci, layer))
        predicate_type = statement.get("predicateType")
        if not isinstance(predicate_type, str):
            raise ValueError("OCI attestation layer is missing predicateType")
        predicates.add(predicate_type)


def summarize_oci_layout(oci: Path) -> dict[str, Any]:
    """Return the registry-relevant identity of a local OCI layout."""
    oci = Path(oci)
    layout = _json(oci / "oci-layout")
    if layout != {"imageLayoutVersion": "1.0.0"}:
        raise ValueError("OCI layout must use imageLayoutVersion 1.0.0")
    root_path = oci / "index.json"
    root = _json(root_path)
    layout_root_digest = f"sha256:{_sha(root_path)}"
    root_manifests = root.get("manifests")
    if (
        isinstance(root_manifests, list)
        and len(root_manifests) == 1
        and isinstance(root_manifests[0], dict)
        and root_manifests[0].get("mediaType") in _INDEX_TYPES
        and root_manifests[0].get("platform") is None
    ):
        publish_digest = str(root_manifests[0]["digest"])
        selected = _read_descriptor(oci, root_manifests[0])
    else:
        publish_digest = layout_root_digest
        selected = root
    platforms: dict[str, str] = {}
    attestation_predicates: dict[str, set[str]] = {}
    attestation_manifests: dict[str, set[str]] = {}
    _collect_index(
        oci,
        selected,
        platforms=platforms,
        attestation_predicates=attestation_predicates,
        attestation_manifests=attestation_manifests,
    )
    if set(platforms) != {"linux/amd64", "linux/arm64"}:
        raise ValueError("GHCR candidate requires exactly linux/amd64 and linux/arm64")
    if set(attestation_predicates) != set(platforms.values()) or set(attestation_manifests) != set(
        platforms.values()
    ):
        raise ValueError("OCI attestation manifests must reference every platform manifest")
    for manifest_digest, predicates in attestation_predicates.items():
        if not predicates & _SBOM_PREDICATES or not predicates & _PROVENANCE_PREDICATES:
            raise ValueError(f"OCI attestation predicates are incomplete for {manifest_digest}")
    return {
        "layout_root_digest": layout_root_digest,
        "publish_digest": publish_digest,
        "platform_manifests": dict(sorted(platforms.items())),
        "attestation_predicates": {
            key: sorted(value) for key, value in sorted(attestation_predicates.items())
        },
        "attestation_manifests": {
            key: sorted(value) for key, value in sorted(attestation_manifests.items())
        },
    }


def verify_api_identity(
    identity: Mapping[str, Any], artifact: Mapping[str, Any], run: Mapping[str, Any]
) -> None:
    """Reject foreign, expired, rerun, or unsuccessful producer artifacts."""
    expected_artifact = {
        "id": identity["artifact_id"],
        "name": identity["artifact_name"],
        "digest": "sha256:" + str(identity["artifact_sha256"]),
        "size_in_bytes": identity["artifact_size"],
        "expired": False,
    }
    expected_run = {
        "id": identity["workflow_run"],
        "run_attempt": 1,
        "head_sha": identity["source_commit"],
        "event": "workflow_dispatch",
        "path": ".github/workflows/release.yml",
        "status": "completed",
        "conclusion": "success",
    }
    producer = artifact.get("workflow_run", {})
    repository = run.get("repository", {})
    if (
        any(artifact.get(key) != value for key, value in expected_artifact.items())
        or any(run.get(key) != value for key, value in expected_run.items())
        or not isinstance(producer, dict)
        or producer.get("id") != identity["workflow_run"]
        or producer.get("head_sha") != identity["source_commit"]
        or producer.get("repository_id") != identity["repository_id"]
        or not isinstance(repository, dict)
        or repository.get("id") != identity["repository_id"]
        or repository.get("full_name") != identity["repository"]
    ):
        raise ValueError("GitHub candidate API identity differs from STAGE-009")


def prepare_oci_candidate(
    identity: Mapping[str, Any],
    archive: Path,
    candidate_dir: Path,
    oci_dir: Path,
    receipt_path: Path,
) -> dict[str, Any]:
    """Authenticate the release candidate and stage only its OCI graph for GHCR."""
    if oci_dir.exists() or receipt_path.exists():
        raise ValueError("GHCR OCI staging outputs must be new")
    unpack_candidate(archive, str(identity["archive_sha256"]), candidate_dir)
    verify_inventory(
        candidate_dir,
        str(identity["tag"]),
        str(identity["source_commit"]),
        str(identity["workflow_run"]),
        expected_sha256=str(identity["inventory_sha256"]),
    )
    inventory = _json(candidate_dir / "candidate-inventory.json")
    if (
        inventory.get("tag") != identity["tag"]
        or inventory.get("version") != identity["version"]
        or inventory.get("source_commit") != identity["source_commit"]
        or str(inventory.get("workflow_run")) != str(identity["workflow_run"])
    ):
        raise ValueError("candidate inventory identity differs from GHCR identity")
    source_oci = candidate_dir / "oci"
    oci_summary = summarize_oci_layout(source_oci)
    if oci_summary["platform_manifests"] != inventory["oci"]["platform_manifests"]:
        raise ValueError("candidate OCI platform manifest digests differ from inventory")
    shutil.copytree(source_oci, oci_dir)
    receipt = {
        "schema_version": 1,
        "image": identity["image"],
        "tag": identity["tag"],
        "version": identity["version"],
        "source_commit": identity["source_commit"],
        "workflow_run": identity["workflow_run"],
        "candidate": {
            "artifact_id": identity["artifact_id"],
            "archive_sha256": identity["archive_sha256"],
            "inventory_sha256": identity["inventory_sha256"],
        },
        "oci": oci_summary,
    }
    _write_json(receipt_path, receipt)
    return receipt


def verify_registry_layout(receipt: Mapping[str, Any], registry_oci: Path) -> None:
    """Verify a registry-pulled OCI layout still matches the staged candidate receipt."""
    actual = summarize_oci_layout(registry_oci)
    expected = receipt["oci"]
    if actual["platform_manifests"] != expected["platform_manifests"]:
        raise ValueError("registry platform manifest digests differ from staged GHCR candidate")
    if actual["attestation_manifests"] != expected["attestation_manifests"]:
        raise ValueError("registry attestation manifest digests differ from staged GHCR candidate")
    if actual["attestation_predicates"] != expected["attestation_predicates"]:
        raise ValueError("registry attestation predicates differ from staged GHCR candidate")
    if actual["publish_digest"] != expected["publish_digest"]:
        raise ValueError("registry publish digest differs from staged GHCR candidate")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    identity_parser = subparsers.add_parser("identity")
    identity_parser.add_argument("--artifact-metadata", type=Path, required=True)
    identity_parser.add_argument("--run-metadata", type=Path, required=True)
    prepare_parser = subparsers.add_parser("prepare")
    prepare_parser.add_argument("--artifact-metadata", type=Path, required=True)
    prepare_parser.add_argument("--run-metadata", type=Path, required=True)
    prepare_parser.add_argument("--archive", type=Path, required=True)
    prepare_parser.add_argument("--candidate-dir", type=Path, required=True)
    prepare_parser.add_argument("--oci-dir", type=Path, required=True)
    prepare_parser.add_argument("--receipt", type=Path, required=True)
    verify_parser = subparsers.add_parser("verify-registry-layout")
    verify_parser.add_argument("--receipt", type=Path, required=True)
    verify_parser.add_argument("--registry-oci-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    identity = _json(IDENTITY_FILE)
    try:
        if args.command in {"identity", "prepare"}:
            verify_api_identity(
                identity,
                _json(args.artifact_metadata),
                _json(args.run_metadata),
            )
            if args.command == "prepare":
                prepare_oci_candidate(
                    identity,
                    args.archive,
                    args.candidate_dir,
                    args.oci_dir,
                    args.receipt,
                )
        else:
            verify_registry_layout(_json(args.receipt), args.registry_oci_dir)
    except (KeyError, OSError, TypeError, ValueError) as error:
        print(f"GHCR {args.command} failed: {error}", file=sys.stderr)
        return 1
    print(f"GHCR {args.command}: exact STAGE-009 OCI identity verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
