"""Assemble, sign, and verify fixed STAGE-009 GitHub Release rehearsal assets."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import stat
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tools.candidate_inventory import unpack_candidate, verify_inventory  # noqa: E402
from tools.sign_release_metadata import (  # noqa: E402
    _load_private_key,
    _read_private_key_path,
    sign_installer,
    sign_manifest,
)
from xferry.management.release_contract import (  # noqa: E402
    SUPPORTED_PLATFORM_IDS,
    PlatformId,
    ReleaseManifest,
    artifact_name,
)
from xferry.management.release_trust import (  # noqa: E402
    DEFAULT_RELEASE_KEY_RING,
    INSTALLER_SIGNATURE_TYPE,
    ReleaseKeyRing,
    ReleaseTrustError,
    verify_detached_signature,
    verify_signed_manifest,
)

IDENTITY_FILE = REPO_ROOT / "packaging/github-release-candidate.json"
ASSET_INVENTORY_NAME = "github-release-assets.json"
_CANDIDATE_INVENTORY_NAME = "candidate-inventory.json"
_ARCHIVE_NAME = "release-candidate.tar"
_SCHEMA_VERSION = 1


def _canonical(document: object) -> bytes:
    return (json.dumps(document, sort_keys=True, indent=2, allow_nan=False) + "\n").encode()


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _asset_record(path: Path, *, generated: bool) -> dict[str, object]:
    metadata = path.stat()
    return {
        "size": metadata.st_size,
        "sha256": _sha256(path),
        "mode": stat.S_IMODE(metadata.st_mode),
        "generated": generated,
    }


def _candidate_aliases(identity: Mapping[str, object]) -> dict[str, Path]:
    version = str(identity["version"])
    aliases = {
        f"xferry-{version}-py3-none-any.whl": Path("python") / f"xferry-{version}-py3-none-any.whl",
        f"xferry-{version}.tar.gz": Path("python") / f"xferry-{version}.tar.gz",
        "xferry-dependency-sbom.cdx.json": Path("python") / "xferry-dependency-sbom.cdx.json",
    }
    for platform in SUPPORTED_PLATFORM_IDS:
        executable_name = artifact_name(version, platform)
        aliases[executable_name] = Path(f"scie-{platform}") / executable_name
        aliases[f"install-{platform}.sh"] = Path(f"scie-{platform}") / "install.sh"
        aliases[f"SHA256SUMS-{platform}"] = Path(f"scie-{platform}") / "SHA256SUMS"
    return aliases


def _unsigned_asset_names(identity: Mapping[str, object]) -> set[str]:
    return set(_candidate_aliases(identity)) | {
        _ARCHIVE_NAME,
        _CANDIDATE_INVENTORY_NAME,
        ASSET_INVENTORY_NAME,
    }


def _signed_asset_names(identity: Mapping[str, object]) -> set[str]:
    names = _unsigned_asset_names(identity)
    for platform in SUPPORTED_PLATFORM_IDS:
        manifest_name = f"xferry-release-{platform}.json"
        names.update(
            {
                manifest_name,
                f"{manifest_name}.sig",
                f"install-{platform}.sh.sig",
            }
        )
    return names


def _require_new_directory(path: Path) -> None:
    if path.is_symlink() or (path.exists() and (not path.is_dir() or any(path.iterdir()))):
        raise ValueError(f"output directory must be new or empty: {path}")
    path.mkdir(parents=True, exist_ok=True)


def _copy_asset(source: Path, destination: Path, *, mode: int | None = None) -> None:
    if source.is_symlink() or not source.is_file():
        raise ValueError(f"release asset source must be a regular file: {source}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination)
    selected_mode = stat.S_IMODE(source.stat().st_mode) if mode is None else mode
    destination.chmod(selected_mode)
    if source.read_bytes() != destination.read_bytes():
        raise ValueError(f"release asset copy changed bytes: {destination.name}")


def _read_json(path: Path) -> dict[str, Any]:
    document = json.loads(path.read_bytes())
    if not isinstance(document, dict):
        raise ValueError(f"JSON document must be an object: {path.name}")
    return document


def _require_asset_set(assets_dir: Path, expected: set[str]) -> None:
    actual = {path.name for path in assets_dir.iterdir() if path.is_file()}
    if actual != expected:
        raise ValueError("GitHub Release asset set contains missing or unexpected files")
    if any(path.is_symlink() for path in assets_dir.iterdir()):
        raise ValueError("GitHub Release asset set must not contain symlinks")


def _identity_summary(identity: Mapping[str, object]) -> dict[str, object]:
    return {
        "repository": identity["repository"],
        "repository_id": identity["repository_id"],
        "version": identity["version"],
        "tag": identity["tag"],
        "release_tag": identity["release_tag"],
        "source_commit": identity["source_commit"],
        "workflow_run": identity["workflow_run"],
        "artifact_id": identity["artifact_id"],
        "artifact_name": identity["artifact_name"],
        "archive_sha256": identity["archive_sha256"],
        "inventory_sha256": identity["inventory_sha256"],
    }


def _require_inventory_identity(
    document: Mapping[str, object], identity: Mapping[str, object]
) -> None:
    expected = _identity_summary(identity)
    if any(document.get(key) != value for key, value in expected.items()):
        raise ValueError("GitHub Release asset inventory identity differs from STAGE-009")


def _verify_asset_records(
    document: Mapping[str, object], assets_dir: Path, names: set[str]
) -> None:
    assets = document.get("assets")
    expected_record_names = names - {ASSET_INVENTORY_NAME}
    if not isinstance(assets, dict) or set(assets) != expected_record_names:
        raise ValueError("GitHub Release asset inventory does not match the expected asset set")
    for name, record in assets.items():
        if not isinstance(record, dict):
            raise ValueError("GitHub Release asset record must be an object")
        path = assets_dir / name
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"GitHub Release asset is not a regular file: {name}")
        if path.stat().st_size != record.get("size") or _sha256(path) != record.get("sha256"):
            raise ValueError(f"prepared GitHub Release asset digest differs from inventory: {name}")


def verify_api_identity(identity: dict, artifact: dict, run: dict) -> None:
    """Reject foreign, expired, rerun, or unsuccessful producer artifacts."""
    expected_artifact = {
        "id": identity["artifact_id"],
        "name": identity["artifact_name"],
        "digest": "sha256:" + identity["artifact_sha256"],
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
        or producer.get("id") != identity["workflow_run"]
        or producer.get("head_sha") != identity["source_commit"]
        or producer.get("repository_id") != identity["repository_id"]
        or repository.get("id") != identity["repository_id"]
        or repository.get("full_name") != identity["repository"]
    ):
        raise ValueError("GitHub Release candidate API identity differs from STAGE-009")


def _verified_candidate_inventory(identity: dict, candidate_dir: Path) -> dict[str, Any]:
    verify_inventory(
        candidate_dir,
        identity["tag"],
        identity["source_commit"],
        str(identity["workflow_run"]),
        expected_sha256=identity["inventory_sha256"],
    )
    inventory = _read_json(candidate_dir / _CANDIDATE_INVENTORY_NAME)
    if inventory.get("version") != identity["version"]:
        raise ValueError("candidate inventory version differs from STAGE-009 identity")
    return inventory


def _extract_verified_candidate(identity: Mapping[str, object], archive: Path, root: Path) -> Path:
    candidate = root / "candidate"
    unpack_candidate(archive, str(identity["archive_sha256"]), candidate)
    verify_inventory(
        candidate,
        str(identity["tag"]),
        str(identity["source_commit"]),
        str(identity["workflow_run"]),
        expected_sha256=str(identity["inventory_sha256"]),
    )
    return candidate


def _verify_candidate_aliases(identity: Mapping[str, object], assets_dir: Path) -> None:
    archive = assets_dir / _ARCHIVE_NAME
    inventory = assets_dir / _CANDIDATE_INVENTORY_NAME
    if archive.is_symlink() or inventory.is_symlink():
        raise ValueError("candidate archive and inventory must be regular release assets")
    if _sha256(archive) != identity["archive_sha256"]:
        raise ValueError("candidate archive digest differs from STAGE-009 identity")
    if _sha256(inventory) != identity["inventory_sha256"]:
        raise ValueError("candidate inventory digest differs from STAGE-009 identity")
    with TemporaryDirectory(prefix="xferry-release-candidate-") as temporary:
        candidate = _extract_verified_candidate(identity, archive, Path(temporary))
        if inventory.read_bytes() != (candidate / _CANDIDATE_INVENTORY_NAME).read_bytes():
            raise ValueError("candidate inventory asset differs from the verified archive")
        for asset_name, candidate_relative in _candidate_aliases(identity).items():
            asset_path = assets_dir / asset_name
            candidate_path = candidate / candidate_relative
            if asset_path.is_symlink() or not asset_path.is_file():
                raise ValueError(f"candidate release alias is missing: {asset_name}")
            if asset_path.read_bytes() != candidate_path.read_bytes():
                raise ValueError(f"candidate release alias differs from STAGE-009: {asset_name}")


def _verify_prepared_unsigned_assets(identity: Mapping[str, object], unsigned_dir: Path) -> dict:
    names = _unsigned_asset_names(identity)
    _require_asset_set(unsigned_dir, names)
    document = _read_json(unsigned_dir / ASSET_INVENTORY_NAME)
    if document.get("schema_version") != _SCHEMA_VERSION or document.get("phase") != "unsigned":
        raise ValueError("prepared asset inventory is not an unsigned STAGE-012 document")
    _require_inventory_identity(document, identity)
    _verify_asset_records(document, unsigned_dir, names)
    _verify_candidate_aliases(identity, unsigned_dir)
    return document


def prepare_unsigned_assets(
    identity: dict,
    artifact: dict,
    run: dict,
    archive: Path,
    candidate_dir: Path,
    unsigned_dir: Path,
) -> None:
    """Authenticate the whole STAGE-009 candidate and stage exact release asset bytes."""
    verify_api_identity(identity, artifact, run)
    unpack_candidate(archive, identity["archive_sha256"], candidate_dir)
    inventory = _verified_candidate_inventory(identity, candidate_dir)
    files = inventory["files"]
    _require_new_directory(unsigned_dir)

    copied: dict[str, bool] = {}
    _copy_asset(archive, unsigned_dir / _ARCHIVE_NAME, mode=0o644)
    copied[_ARCHIVE_NAME] = False
    _copy_asset(
        candidate_dir / _CANDIDATE_INVENTORY_NAME,
        unsigned_dir / _CANDIDATE_INVENTORY_NAME,
        mode=0o644,
    )
    copied[_CANDIDATE_INVENTORY_NAME] = False

    version = str(identity["version"])
    for name in (
        f"xferry-{version}-py3-none-any.whl",
        f"xferry-{version}.tar.gz",
        "xferry-dependency-sbom.cdx.json",
    ):
        relative = f"python/{name}"
        if relative not in files:
            raise ValueError(f"candidate inventory does not contain {relative}")
        _copy_asset(candidate_dir / relative, unsigned_dir / name, mode=0o644)
        copied[name] = False

    for platform in SUPPORTED_PLATFORM_IDS:
        source_dir = candidate_dir / f"scie-{platform}"
        executable_name = artifact_name(version, platform)
        for relative_name in (executable_name, "install.sh", "SHA256SUMS"):
            relative = f"scie-{platform}/{relative_name}"
            if relative not in files:
                raise ValueError(f"candidate inventory does not contain {relative}")
        _copy_asset(
            source_dir / executable_name,
            unsigned_dir / executable_name,
            mode=0o755,
        )
        copied[executable_name] = False
        installer_name = f"install-{platform}.sh"
        _copy_asset(source_dir / "install.sh", unsigned_dir / installer_name, mode=0o755)
        copied[installer_name] = False
        checksums_name = f"SHA256SUMS-{platform}"
        _copy_asset(source_dir / "SHA256SUMS", unsigned_dir / checksums_name, mode=0o644)
        copied[checksums_name] = False

    document = {
        "schema_version": _SCHEMA_VERSION,
        "phase": "unsigned",
        **_identity_summary(identity),
        "assets": {
            name: _asset_record(unsigned_dir / name, generated=generated)
            for name, generated in sorted(copied.items())
        },
    }
    (unsigned_dir / ASSET_INVENTORY_NAME).write_bytes(_canonical(document))
    (unsigned_dir / ASSET_INVENTORY_NAME).chmod(0o644)


def _copy_unsigned_payload(unsigned_dir: Path, signed_dir: Path) -> dict[str, bool]:
    copied: dict[str, bool] = {}
    for source in sorted(unsigned_dir.iterdir(), key=lambda path: path.name):
        if source.name == ASSET_INVENTORY_NAME:
            continue
        if source.is_symlink() or not source.is_file():
            raise ValueError("prepared asset directory must contain only regular asset files")
        target = signed_dir / source.name
        _copy_asset(source, target)
        copied[target.name] = False
    return copied


def _write_signed_platform_assets(
    signed_dir: Path,
    *,
    identity: Mapping[str, object],
    key_id: str,
    private_key: Ed25519PrivateKey,
    platform: PlatformId,
) -> dict[str, bool]:
    version = str(identity["version"])
    workflow_run = str(identity["workflow_run"])
    executable = signed_dir / artifact_name(version, platform)
    installer_name = f"install-{platform}.sh"
    checksums_name = f"SHA256SUMS-{platform}"
    installer = signed_dir / installer_name
    checksums = signed_dir / checksums_name
    if any(path.is_symlink() or not path.is_file() for path in (executable, installer, checksums)):
        raise ValueError(f"prepared assets are incomplete for {platform}")

    artifact_digests = {
        executable.name: _sha256(executable),
        installer_name: _sha256(installer),
        checksums_name: _sha256(checksums),
    }
    manifest = ReleaseManifest.create_v2(
        version=version,
        platform=platform,
        executable_size=executable.stat().st_size,
        executable_sha256=artifact_digests[executable.name],
        source_commit=str(identity["source_commit"]),
        workflow_run=workflow_run,
        artifact_digests=artifact_digests,
        signing_key_ids=(key_id,),
    )
    manifest_name = f"xferry-release-{platform}.json"
    manifest_path = signed_dir / manifest_name
    manifest_path.write_bytes(manifest.to_bytes())
    manifest_path.chmod(0o644)

    (signed_dir / f"{manifest_name}.sig").write_bytes(
        sign_manifest(manifest_path.read_bytes(), key_id=key_id, private_key=private_key)
    )
    (signed_dir / f"{manifest_name}.sig").chmod(0o644)
    (signed_dir / f"{installer_name}.sig").write_bytes(
        sign_installer(installer.read_bytes(), key_id=key_id, private_key=private_key)
    )
    (signed_dir / f"{installer_name}.sig").chmod(0o644)
    return {
        manifest_name: True,
        f"{manifest_name}.sig": True,
        f"{installer_name}.sig": True,
    }


def sign_prepared_assets(
    unsigned_dir: Path,
    signed_dir: Path,
    *,
    key_id: str,
    private_key: Path,
    identity: dict | None = None,
) -> None:
    """Sign staged assets inside the protected environment without granting publish rights."""
    fixed_identity = _load_identity() if identity is None else identity
    _verify_prepared_unsigned_assets(fixed_identity, unsigned_dir)
    signer = _load_private_key(_read_private_key_path(private_key))
    _require_new_directory(signed_dir)
    generated = _copy_unsigned_payload(unsigned_dir, signed_dir)
    for platform in SUPPORTED_PLATFORM_IDS:
        generated.update(
            _write_signed_platform_assets(
                signed_dir,
                identity=fixed_identity,
                key_id=key_id,
                private_key=signer,
                platform=platform,
            )
        )

    assets = {
        path.name: _asset_record(path, generated=generated[path.name])
        for path in sorted(signed_dir.iterdir(), key=lambda candidate: candidate.name)
        if path.is_file()
    }
    document = {
        "schema_version": _SCHEMA_VERSION,
        "phase": "signed",
        **_identity_summary(fixed_identity),
        "signing_key_id": key_id,
        "assets": assets,
    }
    (signed_dir / ASSET_INVENTORY_NAME).write_bytes(_canonical(document))
    (signed_dir / ASSET_INVENTORY_NAME).chmod(0o644)


def _verify_asset_inventory(identity: Mapping[str, object], assets_dir: Path) -> dict[str, Any]:
    names = _signed_asset_names(identity)
    _require_asset_set(assets_dir, names)
    document = _read_json(assets_dir / ASSET_INVENTORY_NAME)
    if document.get("schema_version") != _SCHEMA_VERSION or document.get("phase") != "signed":
        raise ValueError("GitHub Release asset inventory is not a signed STAGE-012 document")
    _require_inventory_identity(document, identity)
    _verify_asset_records(document, assets_dir, names)
    _verify_candidate_aliases(identity, assets_dir)
    return document


def _verify_platform_assets(
    identity: Mapping[str, object],
    assets_dir: Path,
    *,
    key_ring: ReleaseKeyRing,
    platform: PlatformId,
) -> None:
    manifest_name = f"xferry-release-{platform}.json"
    installer_name = f"install-{platform}.sh"
    manifest_payload = (assets_dir / manifest_name).read_bytes()
    manifest = verify_signed_manifest(
        manifest_payload,
        (assets_dir / f"{manifest_name}.sig").read_bytes(),
        key_ring=key_ring,
    )
    if (
        manifest.version != identity["version"]
        or manifest.platform != platform
        or manifest.source_commit != identity["source_commit"]
        or manifest.workflow_run != str(identity["workflow_run"])
    ):
        raise ValueError(f"signed release manifest identity differs for {platform}")
    digest_map = dict(manifest.artifact_digests)
    for name, digest in digest_map.items():
        path = assets_dir / name
        if path.is_symlink() or not path.is_file() or _sha256(path) != digest:
            raise ValueError(f"signed manifest asset digest differs for {platform}: {name}")
    if digest_map.get(installer_name) != _sha256(assets_dir / installer_name):
        raise ValueError(f"installer digest is missing from signed manifest for {platform}")
    verify_detached_signature(
        (assets_dir / installer_name).read_bytes(),
        (assets_dir / f"{installer_name}.sig").read_bytes(),
        payload_type=INSTALLER_SIGNATURE_TYPE,
        key_ring=key_ring,
    )


def verify_downloaded_assets(
    identity: dict,
    assets_dir: Path,
    *,
    key_ring: ReleaseKeyRing = DEFAULT_RELEASE_KEY_RING,
) -> None:
    """Verify downloaded draft Release assets without consulting mutable GitHub state."""
    _verify_asset_inventory(identity, assets_dir)
    for platform in SUPPORTED_PLATFORM_IDS:
        _verify_platform_assets(identity, assets_dir, key_ring=key_ring, platform=platform)


def verify_tamper_is_rejected(
    assets_dir: Path,
    *,
    identity: dict | None = None,
    key_ring: ReleaseKeyRing = DEFAULT_RELEASE_KEY_RING,
) -> None:
    """Prove at least one byte mutation is rejected while leaving input assets untouched."""
    fixed_identity = _load_identity() if identity is None else identity
    verify_downloaded_assets(fixed_identity, assets_dir, key_ring=key_ring)
    with TemporaryDirectory(prefix="xferry-release-tamper-") as temporary:
        tampered = Path(temporary) / "assets"
        shutil.copytree(assets_dir, tampered)
        target = tampered / "install-linux-x86_64.sh"
        target.write_bytes(target.read_bytes() + b"# tamper\n")
        try:
            verify_downloaded_assets(fixed_identity, tampered, key_ring=key_ring)
        except (ValueError, ReleaseTrustError):
            return
    raise ValueError("tampered GitHub Release assets were accepted")


def _load_identity(path: Path = IDENTITY_FILE) -> dict:
    return _read_json(path)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--identity-file", type=Path, default=IDENTITY_FILE)
    subparsers = parser.add_subparsers(dest="command", required=True)

    identity_parser = subparsers.add_parser("identity")
    identity_parser.add_argument("--artifact-metadata", type=Path, required=True)
    identity_parser.add_argument("--run-metadata", type=Path, required=True)

    prepare_parser = subparsers.add_parser("prepare")
    prepare_parser.add_argument("--artifact-metadata", type=Path, required=True)
    prepare_parser.add_argument("--run-metadata", type=Path, required=True)
    prepare_parser.add_argument("--archive", type=Path, required=True)
    prepare_parser.add_argument("--candidate-dir", type=Path, required=True)
    prepare_parser.add_argument("--unsigned-dir", type=Path, required=True)

    sign_parser = subparsers.add_parser("sign")
    sign_parser.add_argument("--unsigned-dir", type=Path, required=True)
    sign_parser.add_argument("--signed-dir", type=Path, required=True)
    sign_parser.add_argument("--key-id", required=True)
    sign_parser.add_argument("--private-key", type=Path, required=True)

    verify_parser = subparsers.add_parser("verify")
    verify_parser.add_argument("--assets-dir", type=Path, required=True)

    tamper_parser = subparsers.add_parser("verify-tamper")
    tamper_parser.add_argument("--assets-dir", type=Path, required=True)

    args = parser.parse_args(argv)
    identity = _load_identity(args.identity_file)
    try:
        if args.command == "identity":
            verify_api_identity(
                identity,
                _read_json(args.artifact_metadata),
                _read_json(args.run_metadata),
            )
        elif args.command == "prepare":
            prepare_unsigned_assets(
                identity,
                _read_json(args.artifact_metadata),
                _read_json(args.run_metadata),
                args.archive,
                args.candidate_dir,
                args.unsigned_dir,
            )
        elif args.command == "sign":
            sign_prepared_assets(
                args.unsigned_dir,
                args.signed_dir,
                key_id=args.key_id,
                private_key=args.private_key,
                identity=identity,
            )
        elif args.command == "verify":
            verify_downloaded_assets(identity, args.assets_dir)
        else:
            verify_tamper_is_rejected(args.assets_dir, identity=identity)
    except (OSError, ValueError, ReleaseTrustError) as error:
        print(str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
