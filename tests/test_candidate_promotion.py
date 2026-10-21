"""Offline candidate identity and producer/consumer archive contracts."""

from __future__ import annotations

import hashlib
import io
import json
import stat
import subprocess
import sys
import tarfile
import zipfile
from collections.abc import Callable
from pathlib import Path

import pytest

from tools.candidate_inventory import (
    INVENTORY_NAME,
    create_inventory,
    pack_candidate,
    unpack_candidate,
    verify_inventory,
)
from tools.check_release_preflight import check_source
from xferry.management.release_contract import (
    SUPPORTED_PLATFORM_IDS,
    ReleaseManifest,
    artifact_name,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
TAG = "v0.1.0"
VERSION = "0.1.0"
COMMIT = "a" * 40
RUN = "123456"
OCI_INDEX = "application/vnd.oci.image.index.v1+json"
OCI_MANIFEST = "application/vnd.oci.image.manifest.v1+json"
OCI_CONFIG = "application/vnd.oci.image.config.v1+json"


def _sha(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _json(document: object) -> bytes:
    return json.dumps(document, sort_keys=True, separators=(",", ":")).encode()


def _source(root: Path, *, version: str = VERSION, changelog: str | None = None) -> Path:
    (root / "xferry").mkdir(parents=True)
    (root / "xferry/config.py").write_text(
        f'raise RuntimeError("source preflight must not import")\n__version__ = "{version}"\n',
        encoding="utf-8",
    )
    (root / "CHANGELOG.md").write_text(
        changelog or f"# Changelog\n\n## [{version}] - 2026-09-30\n\n- Release.\n",
        encoding="utf-8",
    )
    return root


def _blob(root: Path, payload: bytes, media_type: str) -> dict[str, object]:
    digest = _sha(payload)
    (root / "oci/blobs/sha256" / digest).write_bytes(payload)
    return {"mediaType": media_type, "digest": f"sha256:{digest}", "size": len(payload)}


def _image(root: Path, arch: str) -> dict[str, object]:
    config = _blob(
        root,
        _json(
            {
                "architecture": arch,
                "os": "linux",
                "config": {
                    "Labels": {
                        "org.opencontainers.image.version": VERSION,
                        "org.opencontainers.image.revision": COMMIT,
                    }
                },
            }
        ),
        OCI_CONFIG,
    )
    layer = _blob(root, f"layer-{arch}".encode(), "application/vnd.oci.image.layer.v1.tar")
    manifest = _blob(
        root,
        _json({"schemaVersion": 2, "mediaType": OCI_MANIFEST, "config": config, "layers": [layer]}),
        OCI_MANIFEST,
    )
    manifest["platform"] = {"os": "linux", "architecture": arch}
    return manifest


def _candidate(
    root: Path,
    *,
    nested: bool = True,
    attestations: bool = True,
    empty_attestation_config: bool = False,
) -> Path:
    for directory in ("python", "oci/blobs/sha256", *(f"scie-{p}" for p in SUPPORTED_PLATFORM_IDS)):
        (root / directory).mkdir(parents=True)
    metadata = f"Metadata-Version: 2.4\nName: xferry\nVersion: {VERSION}\n\n".encode()
    with zipfile.ZipFile(root / f"python/xferry-{VERSION}-py3-none-any.whl", "w") as wheel:
        wheel.writestr(f"xferry-{VERSION}.dist-info/METADATA", metadata)
        wheel.writestr("xferry/config.py", f'__version__ = "{VERSION}"\n')
    with tarfile.open(root / f"python/xferry-{VERSION}.tar.gz", "w:gz") as sdist:
        member = tarfile.TarInfo(f"xferry-{VERSION}/PKG-INFO")
        member.size = len(metadata)
        sdist.addfile(member, io.BytesIO(metadata))
    (root / "python/xferry-dependency-sbom.cdx.json").write_bytes(
        _json({"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1})
    )
    for platform in SUPPORTED_PLATFORM_IDS:
        directory = root / f"scie-{platform}"
        executable = directory / artifact_name(VERSION, platform)
        executable.write_bytes(f"scie-{platform}".encode())
        executable.chmod(0o755)
        manifest = ReleaseManifest.create_v2(
            version=VERSION,
            platform=platform,
            executable_size=executable.stat().st_size,
            executable_sha256=_sha(executable.read_bytes()),
            source_commit=COMMIT,
            workflow_run=RUN,
        )
        (directory / "xferry-release.json").write_bytes(manifest.to_bytes())
        (directory / "install.sh").write_text(
            "#!/bin/sh\n"
            f"version='{VERSION}'\nplatform_id='{platform}'\n"
            f"artifact_name='{executable.name}'\nartifact_size='{executable.stat().st_size}'\n"
            f"artifact_sha256='{manifest.executable_sha256}'\nmanifest_signature_required='false'\n"
            "hosted_signature_required='true'\n"
            f"hosted_manifest_name='xferry-release-{platform}.json'\n"
            "supported_release_major='0'\n"
            "cat > \"$candidate_release/xferry-release.json\" <<'XFERRY_CANDIDATE_MANIFEST'\n"
            + manifest.to_bytes().decode()
            + "XFERRY_CANDIDATE_MANIFEST\n",
            encoding="utf-8",
        )
        (directory / "install.sh").chmod(0o755)
        (directory / "SHA256SUMS").write_text(
            f"{manifest.executable_sha256}  {executable.name}\n", encoding="utf-8"
        )
    manifests = [_image(root, arch) for arch in ("amd64", "arm64")]
    if attestations:
        config = _blob(
            root,
            _json({} if empty_attestation_config else {"architecture": "unknown", "os": "unknown"}),
            "application/vnd.oci.empty.v1+json" if empty_attestation_config else OCI_CONFIG,
        )
        if empty_attestation_config:
            config["data"] = "e30="
        for image in list(manifests):
            layers = [
                _blob(
                    root,
                    _json(
                        {
                            "_type": "https://in-toto.io/Statement/v0.1",
                            "predicateType": predicate,
                            "subject": []
                            if empty_attestation_config
                            else [
                                {"name": "xferry", "digest": {"sha256": str(image["digest"])[7:]}}
                            ],
                            "predicate": {
                                "spdxVersion": "SPDX-2.3",
                                "packages": [{"name": "xferry", "versionInfo": VERSION}],
                            }
                            if predicate == "https://spdx.dev/Document"
                            else {
                                "buildType": "xferry/test",
                                "builder": {"id": "offline"},
                            },
                        }
                    ),
                    "application/vnd.in-toto+json",
                )
                for predicate in ("https://spdx.dev/Document", "https://slsa.dev/provenance/v0.2")
            ]
            document = {"schemaVersion": 2, "config": config, "layers": layers}
            if empty_attestation_config:
                document["artifactType"] = "application/vnd.docker.attestation.manifest.v1+json"
                document["subject"] = {key: image[key] for key in ("mediaType", "digest", "size")}
            attestation = _blob(root, _json(document), OCI_MANIFEST)
            attestation["platform"] = {"os": "unknown", "architecture": "unknown"}
            attestation["annotations"] = {
                "vnd.docker.reference.type": "attestation-manifest",
                "vnd.docker.reference.digest": image["digest"],
            }
            manifests.append(attestation)
    index = {"schemaVersion": 2, "mediaType": OCI_INDEX, "manifests": manifests}
    if nested:
        descriptor = _blob(root, _json(index), OCI_INDEX)
        index = {"schemaVersion": 2, "manifests": [descriptor]}
    (root / "oci/index.json").write_bytes(_json(index))
    (root / "oci/oci-layout").write_bytes(_json({"imageLayoutVersion": "1.0.0"}))
    return root


def test_source_preflight_reads_literal_without_importing(tmp_path: Path) -> None:
    assert check_source(_source(tmp_path), TAG) == VERSION


def test_candidate_full_layout_round_trip_preserves_every_byte_and_mode(tmp_path: Path) -> None:
    root = _candidate(tmp_path / "producer")
    inventory_sha = create_inventory(root, TAG, COMMIT, RUN)
    inventory = json.loads((root / INVENTORY_NAME).read_bytes())
    assert inventory["version"] == VERSION
    assert inventory["source_commit"] == COMMIT
    assert set(inventory["oci"]["platform_manifests"]) == {"linux/amd64", "linux/arm64"}
    assert (
        inventory["oci"]["root_digest"] == f"sha256:{_sha((root / 'oci/index.json').read_bytes())}"
    )
    assert verify_inventory(root, TAG, COMMIT, RUN, expected_sha256=inventory_sha) == inventory_sha
    archive = tmp_path / "candidate.tar"
    archive_sha = pack_candidate(root, archive)
    downloaded = tmp_path / "downloaded"
    unpack_candidate(archive, archive_sha, downloaded)
    assert (
        verify_inventory(downloaded, TAG, COMMIT, RUN, expected_sha256=inventory_sha)
        == inventory_sha
    )
    for source in root.rglob("*"):
        copy = downloaded / source.relative_to(root)
        assert stat.S_IMODE(copy.stat().st_mode) == stat.S_IMODE(source.stat().st_mode)
        if source.is_file():
            assert copy.read_bytes() == source.read_bytes()


def test_candidate_supports_current_buildx_empty_attestation_config_and_subject(
    tmp_path: Path,
) -> None:
    root = _candidate(tmp_path, empty_attestation_config=True)
    digest = create_inventory(root, TAG, COMMIT, RUN)
    assert verify_inventory(root, TAG, COMMIT, RUN, expected_sha256=digest) == digest


def test_normalize_oci_export_removes_empty_buildx_ingest_before_inventory(
    tmp_path: Path,
) -> None:
    root = _candidate(tmp_path / "candidate")
    ingest = root / "oci/ingest"
    ingest.mkdir()
    command = [
        sys.executable,
        "-I",
        "-S",
        str(REPO_ROOT / "tools/candidate_inventory.py"),
        "normalize-oci",
        "--candidate-dir",
        str(root),
    ]

    normalized = subprocess.run(command, capture_output=True, text=True, check=False)

    assert normalized.returncode == 0, normalized.stderr
    assert not ingest.exists()
    digest = create_inventory(root, TAG, COMMIT, RUN)
    assert verify_inventory(root, TAG, COMMIT, RUN, expected_sha256=digest) == digest


@pytest.mark.parametrize("shape", ["file", "nonempty", "nested"])
def test_normalize_oci_export_rejects_nonempty_or_non_directory_ingest(
    tmp_path: Path,
    shape: str,
) -> None:
    root = _candidate(tmp_path / "candidate")
    ingest = root / "oci/ingest"
    if shape == "file":
        ingest.write_bytes(b"unexpected staged content")
    elif shape == "nonempty":
        ingest.mkdir()
        (ingest / "data").write_bytes(b"incomplete export")
    else:
        (ingest / "nested").mkdir(parents=True)
    command = [
        sys.executable,
        "-I",
        "-S",
        str(REPO_ROOT / "tools/candidate_inventory.py"),
        "normalize-oci",
        "--candidate-dir",
        str(root),
    ]

    rejected = subprocess.run(command, capture_output=True, text=True, check=False)

    assert rejected.returncode == 1
    assert "OCI ingest path must be an empty directory" in rejected.stderr
    assert ingest.exists()


@pytest.mark.parametrize("symlinked_parent", ["candidate", "oci"])
def test_normalize_oci_export_rejects_symlinked_parent_without_external_deletion(
    tmp_path: Path,
    symlinked_parent: str,
) -> None:
    if symlinked_parent == "candidate":
        outside = _candidate(tmp_path / "outside-candidate")
        ingest = outside / "oci/ingest"
        ingest.mkdir()
        root = tmp_path / "candidate"
        root.symlink_to(outside, target_is_directory=True)
    else:
        root = _candidate(tmp_path / "candidate")
        outside = tmp_path / "outside-oci"
        (root / "oci").rename(outside)
        ingest = outside / "ingest"
        ingest.mkdir()
        (root / "oci").symlink_to(outside, target_is_directory=True)
    command = [
        sys.executable,
        "-I",
        "-S",
        str(REPO_ROOT / "tools/candidate_inventory.py"),
        "normalize-oci",
        "--candidate-dir",
        str(root),
    ]

    rejected = subprocess.run(command, capture_output=True, text=True, check=False)

    assert rejected.returncode == 1
    assert "OCI candidate root and OCI directory must be real directories" in rejected.stderr
    assert ingest.is_dir()
    assert list(ingest.iterdir()) == []


def test_source_and_inventory_cli_work_in_isolated_mode(tmp_path: Path) -> None:
    source = _source(tmp_path / "source")
    root = _candidate(tmp_path / "candidate")
    result = subprocess.run(
        [
            sys.executable,
            "-I",
            "-S",
            str(REPO_ROOT / "tools/check_release_preflight.py"),
            "--workspace",
            str(source),
            "--tag",
            TAG,
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == VERSION
    command = [sys.executable, "-I", "-S", str(REPO_ROOT / "tools/candidate_inventory.py")]
    arguments = [
        "--candidate-dir",
        str(root),
        "--tag",
        TAG,
        "--source-commit",
        COMMIT,
        "--workflow-run",
        RUN,
    ]
    created = subprocess.run(command + ["create"] + arguments, capture_output=True, text=True)
    assert created.returncode == 0, created.stderr
    verified = subprocess.run(
        command + ["verify"] + arguments + ["--expected-sha256", created.stdout.strip()],
        capture_output=True,
        text=True,
    )
    assert verified.returncode == 0, verified.stderr
    assert verified.stdout == created.stdout


@pytest.mark.parametrize(
    "tag",
    [
        "0.1.0",
        "v00.1.0",
        "v0.01.0",
        "v0.1.00",
        "v0.1",
        "v0.1.0-rc.1",
        "v0.1.0+build.1",
        "v0.1.0\n",
        " v0.1.0",
        "V0.1.0",
        "v0.2.0",
    ],
)
def test_source_preflight_rejects_malformed_or_mismatched_tag(tmp_path: Path, tag: str) -> None:
    with pytest.raises(ValueError):
        check_source(_source(tmp_path), tag)


@pytest.mark.parametrize(
    "changelog",
    [
        "# Changelog\n",
        "## [0.1.0]\n",
        "## [0.1.0] - 2026-02-30\n",
        "## [0.1.0] - 2026-9-30\n",
        "## [0.1.0] - 2026-09-30\n## [0.1.0] - 2026-09-29\n",
        "## [0.2.0] - 2026-09-30\n## [0.1.0] - 2026-09-29\n",
        "## [0.1.0-rc.1] - 2026-09-30\n## [0.1.0] - 2026-09-29\n",
        "## [Unreleased]\n## [Unreleased]\n## [0.1.0] - 2026-09-30\n",
    ],
)
def test_source_preflight_rejects_ambiguous_or_undated_changelog(
    tmp_path: Path,
    changelog: str,
) -> None:
    with pytest.raises(ValueError):
        check_source(_source(tmp_path, changelog=changelog), TAG)


def test_source_preflight_allows_unreleased_before_current_release(tmp_path: Path) -> None:
    source = _source(
        tmp_path,
        changelog="## [Unreleased]\n\n## [0.1.0] - 2026-09-30\n\n## [0.0.9] - 2026-09-29\n",
    )
    assert check_source(source, TAG) == VERSION


@pytest.mark.parametrize(
    "source_code",
    [
        '__version__ = "0." + "1.0"',
        '__version__ = "0.1.0"\n__version__ = "0.1.0"',
        '__version__ = "0.1.0"\n__version__ += "-rc.1"',
        'if True:\n    __version__ = "0.1.0"',
        '__version__ = "0.1.0-rc.1"',
        '__version__ = "00.1.0"',
        "__version__ = 1",
        "__version__ = ",
    ],
)
def test_source_preflight_requires_one_top_level_final_version_literal(
    tmp_path: Path,
    source_code: str,
) -> None:
    source = _source(tmp_path)
    (source / "xferry/config.py").write_text(source_code, encoding="utf-8")
    with pytest.raises(ValueError):
        check_source(source, TAG)


@pytest.mark.parametrize(
    ("tag", "commit", "run"),
    [
        ("v1.0.0", COMMIT, RUN),
        ("v00.1.0", COMMIT, RUN),
        (TAG, "a" * 39, RUN),
        (TAG, "a" * 64, RUN),
        (TAG, "A" * 40, RUN),
        (TAG, COMMIT, "0"),
        (TAG, COMMIT, "0123"),
        (TAG, COMMIT, "run-123"),
    ],
)
def test_inventory_rejects_invalid_requested_identity(
    tmp_path: Path,
    tag: str,
    commit: str,
    run: str,
) -> None:
    root = _candidate(tmp_path)
    with pytest.raises(ValueError):
        create_inventory(root, tag, commit, run)
    assert not (root / INVENTORY_NAME).exists()


@pytest.mark.parametrize(
    "missing",
    ["python/xferry-dependency-sbom.cdx.json", "oci/oci-layout", "scie-linux-aarch64/install.sh"],
)
def test_inventory_requires_every_component_file(tmp_path: Path, missing: str) -> None:
    root = _candidate(tmp_path)
    (root / missing).unlink()
    with pytest.raises(ValueError, match="exact.*layout"):
        create_inventory(root, TAG, COMMIT, RUN)


@pytest.mark.parametrize("extra", ["unexpected", "python/foreign.whl", "oci/signature.sig"])
def test_inventory_rejects_unexpected_files(tmp_path: Path, extra: str) -> None:
    root = _candidate(tmp_path)
    (root / extra).write_bytes(b"extra")
    with pytest.raises(ValueError, match="exact.*layout"):
        create_inventory(root, TAG, COMMIT, RUN)


def test_inventory_rejects_unexpected_empty_directory(tmp_path: Path) -> None:
    root = _candidate(tmp_path)
    (root / "extra").mkdir()
    with pytest.raises(ValueError, match="unexpected directories"):
        create_inventory(root, TAG, COMMIT, RUN)


@pytest.mark.parametrize("directory", [False, True])
def test_inventory_and_pack_reject_symlinks(tmp_path: Path, directory: bool) -> None:
    root = _candidate(tmp_path / "candidate")
    target = tmp_path / "outside"
    if directory:
        target.mkdir()
    else:
        target.write_bytes(b"outside")
    (root / "unsafe-link").symlink_to(target, target_is_directory=directory)
    with pytest.raises(ValueError, match="regular files"):
        create_inventory(root, TAG, COMMIT, RUN)
    with pytest.raises(ValueError, match="regular files"):
        pack_candidate(root, tmp_path / "unsafe.tar")
    assert not (tmp_path / "unsafe.tar").exists()


@pytest.mark.parametrize(
    "artifact", ["python/xferry-0.1.0-py3-none-any.whl", "python/xferry-0.1.0.tar.gz"]
)
def test_inventory_rejects_foreign_python_metadata_in_correctly_named_archive(
    tmp_path: Path,
    artifact: str,
) -> None:
    root = _candidate(tmp_path)
    archive = root / artifact
    metadata = b"Metadata-Version: 2.4\nName: xferry\nVersion: 0.2.0\n\n"
    if artifact.endswith(".whl"):
        with zipfile.ZipFile(archive, "w") as wheel:
            wheel.writestr(f"xferry-{VERSION}.dist-info/METADATA", metadata)
    else:
        with tarfile.open(archive, "w:gz") as sdist:
            member = tarfile.TarInfo(f"xferry-{VERSION}/PKG-INFO")
            member.size = len(metadata)
            sdist.addfile(member, io.BytesIO(metadata))
    with pytest.raises(ValueError, match="metadata.*identity"):
        create_inventory(root, TAG, COMMIT, RUN)


def test_inventory_rejects_nonmatching_wheel_dist_info_filename(tmp_path: Path) -> None:
    root = _candidate(tmp_path)
    with zipfile.ZipFile(root / f"python/xferry-{VERSION}-py3-none-any.whl", "w") as wheel:
        wheel.writestr("xferry-0.2.0.dist-info/METADATA", f"Name: xferry\nVersion: {VERSION}\n\n")
    with pytest.raises(ValueError, match="metadata filename"):
        create_inventory(root, TAG, COMMIT, RUN)


@pytest.mark.parametrize(
    "mutation",
    ["source", "run", "signed", "platform", "version", "noncanonical", "checksum", "execute"],
)
def test_inventory_rejects_inconsistent_or_signed_scie_manifest(
    tmp_path: Path, mutation: str
) -> None:
    root = _candidate(tmp_path)
    directory = root / "scie-linux-x86_64"
    path = directory / "xferry-release.json"
    document = json.loads(path.read_bytes())
    if mutation == "source":
        document["source"]["commit"] = "b" * 40
    elif mutation == "run":
        document["source"]["workflow_run"] = "123457"
    elif mutation == "signed":
        document["signing"] = {"scheme": "ed25519", "key_ids": ["production"]}
    elif mutation == "platform":
        document["platform"] = "linux-aarch64"
    elif mutation == "version":
        document["version"] = "0.2.0"
        document["tag"] = "v0.2.0"
    elif mutation == "checksum":
        (directory / "SHA256SUMS").write_bytes(b"0" * 64 + b"  other\n")
    elif mutation == "execute":
        (directory / "install.sh").chmod(0o644)
    if mutation == "noncanonical":
        path.write_bytes(_json(document))
    else:
        path.write_bytes((json.dumps(document, indent=2) + "\n").encode())
    with pytest.raises(ValueError):
        create_inventory(root, TAG, COMMIT, RUN)


def _replace_blob(root: Path, descriptor: dict[str, object], document: object) -> None:
    old_path = root / "oci/blobs/sha256" / str(descriptor["digest"])[7:]
    replacement = _blob(root, _json(document), str(descriptor["mediaType"]))
    if replacement["digest"] != descriptor["digest"]:
        old_path.unlink()
    descriptor.update(replacement)


def _edit_image(root: Path, mutate: Callable[[dict[str, object]], None]) -> None:
    index_path = root / "oci/index.json"
    index = json.loads(index_path.read_bytes())
    descriptor = index["manifests"][0]
    original_digest = descriptor["digest"]
    manifest_path = root / "oci/blobs/sha256" / original_digest[7:]
    manifest = json.loads(manifest_path.read_bytes())
    config_descriptor = manifest["config"]
    config_path = root / "oci/blobs/sha256" / config_descriptor["digest"][7:]
    config = json.loads(config_path.read_bytes())
    mutate(config)
    _replace_blob(root, config_descriptor, config)
    _replace_blob(root, descriptor, manifest)
    for entry in index["manifests"]:
        annotations = entry.get("annotations", {})
        if annotations.get("vnd.docker.reference.digest") == original_digest:
            annotations["vnd.docker.reference.digest"] = descriptor["digest"]
    index_path.write_bytes(_json(index))


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("architecture", "arm64"),
        ("architecture", "riscv64"),
        ("architecture", []),
        ("os", "windows"),
        ("os", {}),
        ("org.opencontainers.image.version", "0.2.0"),
        ("org.opencontainers.image.revision", "b" * 40),
    ],
)
def test_inventory_checks_actual_oci_config_identity(
    tmp_path: Path, field: str, value: object
) -> None:
    root = _candidate(tmp_path, nested=False)

    def mutate(config: dict[str, object]) -> None:
        if field.startswith("org."):
            config["config"]["Labels"][field] = value
        else:
            config[field] = value

    _edit_image(root, mutate)
    with pytest.raises(ValueError):
        create_inventory(root, TAG, COMMIT, RUN)


@pytest.mark.parametrize("mutation", ["digest", "size", "urls", "missing", "duplicate", "unknown"])
def test_inventory_rejects_bad_oci_descriptors_or_platform_set(
    tmp_path: Path, mutation: str
) -> None:
    root = _candidate(tmp_path, nested=False)
    path = root / "oci/index.json"
    document = json.loads(path.read_bytes())
    descriptor = document["manifests"][0]
    if mutation == "digest":
        descriptor["digest"] = "sha256:" + "0" * 64
    elif mutation == "size":
        descriptor["size"] += 1
    elif mutation == "urls":
        descriptor["urls"] = ["https://example.invalid/image"]
    elif mutation == "missing":
        document["manifests"].pop(1)
    elif mutation == "duplicate":
        document["manifests"].insert(1, descriptor.copy())
    else:
        descriptor["platform"] = {"os": "unknown", "architecture": "unknown"}
    path.write_bytes(_json(document))
    with pytest.raises(ValueError):
        create_inventory(root, TAG, COMMIT, RUN)


def test_inventory_rejects_unreferenced_oci_blob(tmp_path: Path) -> None:
    root = _candidate(tmp_path)
    _blob(root, b"extra unattached content", "unused")
    with pytest.raises(ValueError, match="unreferenced"):
        create_inventory(root, TAG, COMMIT, RUN)


def test_inventory_requires_attestations_for_each_actual_oci_platform(tmp_path: Path) -> None:
    root = _candidate(tmp_path, nested=False)
    path = root / "oci/index.json"
    index = json.loads(path.read_bytes())
    index["manifests"].pop(2)
    path.write_bytes(_json(index))
    with pytest.raises(ValueError, match="attestations.*every runnable"):
        create_inventory(root, TAG, COMMIT, RUN)


@pytest.mark.parametrize(
    "predicate", ["https://spdx.dev/Document", "https://slsa.dev/provenance/v0.2"]
)
def test_inventory_requires_both_sbom_and_provenance_per_oci_platform(
    tmp_path: Path,
    predicate: str,
) -> None:
    root = _candidate(tmp_path, nested=False)
    index_path = root / "oci/index.json"
    index = json.loads(index_path.read_bytes())
    descriptor = index["manifests"][2]
    manifest_path = root / "oci/blobs/sha256" / descriptor["digest"][7:]
    manifest = json.loads(manifest_path.read_bytes())
    manifest["layers"] = [
        layer
        for layer in manifest["layers"]
        if json.loads((root / "oci/blobs/sha256" / layer["digest"][7:]).read_bytes())[
            "predicateType"
        ]
        != predicate
    ]
    replacement = _blob(root, _json(manifest), OCI_MANIFEST)
    descriptor.update(replacement)
    index_path.write_bytes(_json(index))
    with pytest.raises(ValueError, match="SBOM and provenance"):
        create_inventory(root, TAG, COMMIT, RUN)


@pytest.mark.parametrize("tamper", ["file", "mode", "inventory", "noncanonical", "extra"])
def test_downloaded_inventory_rejects_every_kind_of_tamper(tmp_path: Path, tamper: str) -> None:
    root = _candidate(tmp_path)
    digest = create_inventory(root, TAG, COMMIT, RUN)
    path = root / INVENTORY_NAME
    if tamper == "file":
        (root / "scie-linux-x86_64/install.sh").write_bytes(b"#!/bin/sh\nexit 1\n")
    elif tamper == "mode":
        (root / "python/xferry-dependency-sbom.cdx.json").chmod(0o600)
    elif tamper == "extra":
        (root / "other").write_bytes(b"extra")
    else:
        document = json.loads(path.read_bytes())
        if tamper == "inventory":
            document["source_commit"] = "b" * 40
            path.write_bytes((json.dumps(document, sort_keys=True, indent=2) + "\n").encode())
        else:
            path.write_bytes(_json(document))
    with pytest.raises(ValueError):
        verify_inventory(root, TAG, COMMIT, RUN, expected_sha256=digest)


def test_inventory_rejects_self_consistent_replacement_without_producer_digest(
    tmp_path: Path,
) -> None:
    root = _candidate(tmp_path)
    digest = create_inventory(root, TAG, COMMIT, RUN)
    (root / INVENTORY_NAME).unlink()
    installer = root / "scie-linux-x86_64/install.sh"
    installer.write_bytes(installer.read_bytes() + b"# replacement candidate\n")
    replacement = create_inventory(root, TAG, COMMIT, RUN)
    assert replacement != digest
    assert verify_inventory(root, TAG, COMMIT, RUN) == replacement
    with pytest.raises(ValueError, match="producer digest"):
        verify_inventory(root, TAG, COMMIT, RUN, expected_sha256=digest)


def _tar(path: Path, members: list[tarfile.TarInfo]) -> str:
    with tarfile.open(path, "w") as archive:
        for member in members:
            archive.addfile(member, io.BytesIO(b"x" * member.size))
    return _sha(path.read_bytes())


@pytest.mark.parametrize(
    "name",
    [
        "../escape",
        "/absolute",
        "a/../escape",
        "a/./file",
        "a//file",
        "./file",
        "C:/escape",
        "a\\escape",
        "a\nfile",
    ],
)
def test_unpack_rejects_unsafe_member_paths_before_creating_root(tmp_path: Path, name: str) -> None:
    archive = tmp_path / "unsafe.tar"
    member = tarfile.TarInfo(name)
    member.size = 1
    digest = _tar(archive, [member])
    target = tmp_path / "output"
    with pytest.raises(ValueError, match="unsafe candidate path"):
        unpack_candidate(archive, digest, target)
    assert not target.exists()
    assert not (tmp_path / "escape").exists()


@pytest.mark.parametrize(
    "kind", [tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.FIFOTYPE, tarfile.CHRTYPE, tarfile.BLKTYPE]
)
def test_unpack_rejects_links_and_special_members(tmp_path: Path, kind: bytes) -> None:
    archive = tmp_path / "unsafe.tar"
    member = tarfile.TarInfo("unsafe")
    member.type = kind
    member.linkname = "../escape"
    digest = _tar(archive, [member])
    target = tmp_path / "output"
    with pytest.raises(ValueError, match="only regular"):
        unpack_candidate(archive, digest, target)
    assert not target.exists()


@pytest.mark.parametrize("abuse", ["duplicate", "file-parent", "setuid"])
def test_unpack_rejects_conflicting_or_unsafe_archive_members(tmp_path: Path, abuse: str) -> None:
    archive = tmp_path / "unsafe.tar"
    first = tarfile.TarInfo("file")
    second = tarfile.TarInfo("file/child" if abuse == "file-parent" else "file")
    if abuse == "setuid":
        first.mode = 0o4755
        members = [first]
    else:
        members = [first, second]
    digest = _tar(archive, members)
    with pytest.raises(ValueError):
        unpack_candidate(archive, digest, tmp_path / "output")
    assert not (tmp_path / "output").exists()


def test_unpack_authenticates_digest_before_tar_parsing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    archive = tmp_path / "malformed.tar"
    archive.write_bytes(b"not a tar archive")

    def forbidden_parse(*args: object, **kwargs: object) -> None:
        raise AssertionError("unauthenticated archive was parsed")

    monkeypatch.setattr(tarfile, "open", forbidden_parse)
    with pytest.raises(ValueError, match="producer digest"):
        unpack_candidate(archive, "0" * 64, tmp_path / "output")
    assert not (tmp_path / "output").exists()


def test_pack_and_unpack_refuse_overwrites_and_preserve_existing_data(tmp_path: Path) -> None:
    root = tmp_path / "component"
    root.mkdir()
    (root / "file").write_bytes(b"source")
    archive = tmp_path / "component.tar"
    digest = pack_candidate(root, archive)
    original = archive.read_bytes()
    with pytest.raises(FileExistsError):
        pack_candidate(root, archive)
    assert archive.read_bytes() == original
    output = tmp_path / "output"
    output.mkdir()
    preserved = output / "preserved"
    preserved.write_bytes(b"keep me")
    with pytest.raises(ValueError, match="new or empty"):
        unpack_candidate(archive, digest, output)
    assert preserved.read_bytes() == b"keep me"
    preserved.unlink()
    unpack_candidate(archive, digest, output)
    assert (output / "file").read_bytes() == b"source"


def test_pack_is_deterministic_and_handles_component_layout(tmp_path: Path) -> None:
    root = tmp_path / "component"
    root.mkdir()
    payload = root / "xferry"
    payload.write_bytes(b"executable")
    payload.chmod(0o755)
    first, second = tmp_path / "first.tar", tmp_path / "second.tar"
    assert pack_candidate(root, first) == pack_candidate(root, second)
    assert first.read_bytes() == second.read_bytes()
    with pytest.raises(ValueError, match="outside"):
        pack_candidate(root, root / "recursive.tar")


def test_pack_unpack_cli_and_bad_digest_exit_status(tmp_path: Path) -> None:
    root = tmp_path / "component"
    root.mkdir()
    (root / "file").write_bytes(b"candidate")
    archive = tmp_path / "component.tar"
    command = [sys.executable, "-I", "-S", str(REPO_ROOT / "tools/candidate_inventory.py")]
    packed = subprocess.run(
        command + ["pack", "--candidate-dir", str(root), "--archive", str(archive)],
        text=True,
        capture_output=True,
    )
    assert packed.returncode == 0, packed.stderr
    output = tmp_path / "output"
    unpack_arguments = [
        "unpack",
        "--candidate-dir",
        str(output),
        "--archive",
        str(archive),
        "--expected-sha256",
    ]
    rejected = subprocess.run(
        command + unpack_arguments + ["0" * 64], text=True, capture_output=True
    )
    assert rejected.returncode == 1
    assert "producer digest" in rejected.stderr
    assert not output.exists()
    unpacked = subprocess.run(
        command + unpack_arguments + [packed.stdout.strip()], text=True, capture_output=True
    )
    assert unpacked.returncode == 0, unpacked.stderr
    assert (output / "file").read_bytes() == b"candidate"


def test_source_preflight_rejects_unsupported_major_even_when_source_and_changelog_match(
    tmp_path: Path,
) -> None:
    with pytest.raises(ValueError, match="supported source release line"):
        check_source(_source(tmp_path, version="1.0.0"), "v1.0.0")


@pytest.mark.parametrize(
    ("before", "after"),
    [
        ("version='0.1.0'", "version='0.2.0'"),
        ("platform_id='linux-x86_64'", "platform_id='linux-aarch64'"),
        ("artifact_name='xferry-0.1.0-linux-x86_64'", "artifact_name='other'"),
        ("artifact_size='17'", "artifact_size='18'"),
        ("manifest_signature_required='false'", "manifest_signature_required='true'"),
        ("hosted_signature_required='true'", "hosted_signature_required='false'"),
        (
            "hosted_manifest_name='xferry-release-linux-x86_64.json'",
            "hosted_manifest_name='xferry-release-linux-aarch64.json'",
        ),
        ("supported_release_major='0'", "supported_release_major='1'"),
        ('"workflow_run": "123456"', '"workflow_run": "123457"'),
    ],
)
def test_inventory_rejects_installer_fields_or_embedded_manifest_mismatch(
    tmp_path: Path,
    before: str,
    after: str,
) -> None:
    root = _candidate(tmp_path)
    path = root / "scie-linux-x86_64/install.sh"
    payload = path.read_text(encoding="utf-8")
    assert before in payload
    path.write_text(payload.replace(before, after, 1), encoding="utf-8")
    with pytest.raises(ValueError, match="SCIE installer"):
        create_inventory(root, TAG, COMMIT, RUN)


@pytest.mark.parametrize("mutation", ["wrong-subject", "embedded-data", "config", "artifact-type"])
def test_inventory_rejects_current_buildx_attestation_subject_or_empty_config_tamper(
    tmp_path: Path,
    mutation: str,
) -> None:
    root = _candidate(tmp_path, nested=False, empty_attestation_config=True)
    index_path = root / "oci/index.json"
    index = json.loads(index_path.read_bytes())
    descriptor = index["manifests"][2]
    manifest = json.loads((root / "oci/blobs/sha256" / descriptor["digest"][7:]).read_bytes())
    if mutation == "wrong-subject":
        manifest["subject"] = {
            key: index["manifests"][1][key] for key in ("mediaType", "digest", "size")
        }
    elif mutation == "embedded-data":
        manifest["config"]["data"] = "W10="
    elif mutation == "config":
        manifest["config"] = _blob(
            root, _json({"not": "empty"}), "application/vnd.oci.empty.v1+json"
        )
    else:
        del manifest["artifactType"]
    descriptor.update(_blob(root, _json(manifest), OCI_MANIFEST))
    index_path.write_bytes(_json(index))
    with pytest.raises(ValueError):
        create_inventory(root, TAG, COMMIT, RUN)


@pytest.mark.parametrize("mutation", ["subject", "absent-subject", "predicate", "spdx", "type"])
def test_inventory_rejects_unbound_or_empty_in_toto_evidence(tmp_path: Path, mutation: str) -> None:
    root = _candidate(tmp_path, nested=False)
    index_path = root / "oci/index.json"
    index = json.loads(index_path.read_bytes())
    descriptor = index["manifests"][2]
    manifest = json.loads((root / "oci/blobs/sha256" / descriptor["digest"][7:]).read_bytes())
    layer = manifest["layers"][0]
    statement = json.loads((root / "oci/blobs/sha256" / layer["digest"][7:]).read_bytes())
    if mutation == "subject":
        statement["subject"][0]["digest"]["sha256"] = "0" * 64
    elif mutation == "absent-subject":
        statement["subject"] = []
    elif mutation == "predicate":
        statement["predicate"] = {}
    elif mutation == "spdx":
        statement["predicate"] = {"spdxVersion": "SPDX-2.3", "packages": []}
    else:
        statement["_type"] = []
    layer.update(_blob(root, _json(statement), "application/vnd.in-toto+json"))
    descriptor.update(_blob(root, _json(manifest), OCI_MANIFEST))
    index_path.write_bytes(_json(index))
    with pytest.raises(ValueError):
        create_inventory(root, TAG, COMMIT, RUN)


def test_inventory_rejects_noncanonical_json_without_an_expected_digest(tmp_path: Path) -> None:
    root = _candidate(tmp_path)
    create_inventory(root, TAG, COMMIT, RUN)
    path = root / INVENTORY_NAME
    path.write_bytes(_json(json.loads(path.read_bytes())))
    with pytest.raises(ValueError, match="canonical sorted JSON"):
        verify_inventory(root, TAG, COMMIT, RUN)


def _rewrite_provenance(root: Path, predicate_type: str, predicate: object) -> None:
    """Replace provenance and all referencing digests, leaving a self-consistent OCI closure."""
    index_path = root / "oci/index.json"
    index = json.loads(index_path.read_bytes())
    for descriptor in index["manifests"][2:]:
        manifest = json.loads((root / "oci/blobs/sha256" / descriptor["digest"][7:]).read_bytes())
        layer = manifest["layers"][1]
        statement = json.loads((root / "oci/blobs/sha256" / layer["digest"][7:]).read_bytes())
        statement["predicateType"] = predicate_type
        statement["predicate"] = predicate
        _replace_blob(root, layer, statement)
        _replace_blob(root, descriptor, manifest)
    index_path.write_bytes(_json(index))


@pytest.mark.parametrize("version", ["v0.2", "v1"])
def test_inventory_rejects_junk_slsa_predicate_in_digest_consistent_oci_layout(
    tmp_path: Path,
    version: str,
) -> None:
    root = _candidate(tmp_path, nested=False)
    _rewrite_provenance(root, f"https://slsa.dev/provenance/{version}", {"junk": True})
    with pytest.raises(ValueError, match="SLSA"):
        create_inventory(root, TAG, COMMIT, RUN)


@pytest.mark.parametrize(
    ("version", "predicate"),
    [
        ("v0.2", {"buildType": "", "builder": {"id": "offline"}}),
        ("v0.2", {"buildType": "xferry/test", "builder": {"id": ""}}),
        ("v0.2", {"buildType": "xferry/test", "builder": {"id": 1}}),
        ("v1", {"buildDefinition": {}, "runDetails": {"builder": {"id": ""}}}),
        ("v1", {"buildDefinition": {"buildType": 1}, "runDetails": {"builder": {"id": ""}}}),
        ("v1", {"buildDefinition": {"buildType": "xferry/test"}, "runDetails": {}}),
        (
            "v1",
            {"buildDefinition": {"buildType": "xferry/test"}, "runDetails": {"builder": {"id": 1}}},
        ),
    ],
)
def test_inventory_requires_minimal_slsa_provenance_structure(
    tmp_path: Path,
    version: str,
    predicate: dict[str, object],
) -> None:
    root = _candidate(tmp_path, nested=False)
    _rewrite_provenance(root, f"https://slsa.dev/provenance/{version}", predicate)
    with pytest.raises(ValueError, match="SLSA"):
        create_inventory(root, TAG, COMMIT, RUN)


@pytest.mark.parametrize(
    ("version", "predicate"),
    [
        ("v0.2", {"buildType": "xferry/test", "builder": {"id": "offline"}}),
        (
            "v1",
            {
                "buildDefinition": {"buildType": "https://github.com/moby/buildkit"},
                "runDetails": {"builder": {"id": ""}},
            },
        ),
    ],
)
def test_inventory_accepts_old_slsa_and_current_buildx_empty_builder_id(
    tmp_path: Path,
    version: str,
    predicate: dict[str, object],
) -> None:
    root = _candidate(tmp_path, nested=False)
    _rewrite_provenance(root, f"https://slsa.dev/provenance/{version}", predicate)
    digest = create_inventory(root, TAG, COMMIT, RUN)
    assert verify_inventory(root, TAG, COMMIT, RUN, expected_sha256=digest) == digest
