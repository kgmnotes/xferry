"""Derive exact production channel identities from one authenticated candidate."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any, NoReturn

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tools.candidate_inventory import (  # noqa: E402
    INVENTORY_NAME,
    unpack_candidate,
    verify_inventory,
)
from tools.check_release_preflight import version_from_tag  # noqa: E402

PRODUCTION_REPOSITORY = "kgmnotes/xferry"
PRODUCTION_WORKFLOW_PATH = ".github/workflows/release-production.yml"
GHCR_IMAGE = "ghcr.io/kgmnotes/xferry"
TESTPYPI_IDENTITY_NAME = "testpypi-candidate.json"
GHCR_IDENTITY_NAME = "ghcr-candidate.json"
GITHUB_RELEASE_IDENTITY_NAME = "github-release-candidate.json"

_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
_DIGEST_RE = re.compile(r"sha256:([0-9a-f]{64})\Z")
_COMMIT_RE = re.compile(r"[0-9a-f]{40}\Z")
_MAX_JSON_BYTES = 16 * 1024 * 1024


def _canonical(document: object) -> bytes:
    return (json.dumps(document, sort_keys=True, indent=2, allow_nan=False) + "\n").encode()


def _write_canonical(path: Path, document: object) -> None:
    with path.open("xb") as stream:
        stream.write(_canonical(document))


def _duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    document: dict[str, object] = {}
    for key, value in pairs:
        if key in document:
            raise ValueError("duplicate JSON key")
        document[key] = value
    return document


def _invalid_constant(_value: str) -> NoReturn:
    raise ValueError("non-finite JSON value")


def _read_json(path: Path) -> dict[str, Any]:
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"JSON metadata must be a regular file: {path.name}")
    if path.stat().st_size > _MAX_JSON_BYTES:
        raise ValueError(f"JSON metadata is too large: {path.name}")
    document = json.loads(
        path.read_bytes(), object_pairs_hook=_duplicate_keys, parse_constant=_invalid_constant
    )
    if not isinstance(document, dict):
        raise ValueError(f"JSON metadata must be an object: {path.name}")
    return document


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _require_sha256(value: str, label: str) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise ValueError(f"{label} must be 64 lowercase hexadecimal characters")
    return value


def _positive_integer(value: object) -> bool:
    return type(value) is int and value > 0


def _branch_matches_tag(value: object, tag: str) -> bool:
    """GitHub may expose a tag run's head_branch as the tag or as null."""
    return value is None or value == tag


def _repository_identity(value: object, repository: str) -> int | None:
    if not isinstance(value, Mapping):
        return None
    repository_id = value.get("id")
    if not _positive_integer(repository_id) or value.get("full_name") != repository:
        return None
    return int(repository_id)


def verify_api_identity(
    artifact: Mapping[str, Any],
    run: Mapping[str, Any],
    *,
    artifact_id: int,
    repository: str,
    tag: str,
    source_commit: str,
    workflow_run: int,
) -> dict[str, object]:
    """Bind GitHub API metadata to the exact in-progress production tag run."""
    if repository != PRODUCTION_REPOSITORY:
        raise ValueError(f"production repository must be exactly {PRODUCTION_REPOSITORY}")
    version_from_tag(tag)
    if _COMMIT_RE.fullmatch(source_commit) is None:
        raise ValueError("source commit must be exactly 40 lowercase hexadecimal characters")
    if not _positive_integer(artifact_id) or not _positive_integer(workflow_run):
        raise ValueError("GitHub artifact and workflow run identity must use positive integers")

    run_attempt = run.get("run_attempt")
    repository_id = _repository_identity(run.get("repository"), repository)
    head_repository_id = _repository_identity(run.get("head_repository"), repository)
    if (
        run.get("id") != workflow_run
        or not _positive_integer(run_attempt)
        or run.get("head_sha") != source_commit
        or not _branch_matches_tag(run.get("head_branch"), tag)
        or run.get("event") != "push"
        or run.get("path") != PRODUCTION_WORKFLOW_PATH
        or run.get("status") != "in_progress"
        or run.get("conclusion") is not None
        or repository_id is None
        or head_repository_id != repository_id
    ):
        raise ValueError("GitHub production run API identity does not match the requested tag")

    artifact_name = artifact.get("name")
    name_match = (
        re.fullmatch(rf"release-candidate-{workflow_run}-([1-9][0-9]*)", artifact_name)
        if isinstance(artifact_name, str)
        else None
    )
    artifact_attempt = int(name_match.group(1)) if name_match is not None else None
    artifact_digest = artifact.get("digest")
    digest_match = (
        _DIGEST_RE.fullmatch(artifact_digest) if isinstance(artifact_digest, str) else None
    )
    producer = artifact.get("workflow_run")
    if (
        artifact.get("id") != artifact_id
        or name_match is None
        or artifact_attempt is None
        or artifact_attempt > int(run_attempt)
        or digest_match is None
        or not _positive_integer(artifact.get("size_in_bytes"))
        or artifact.get("expired") is not False
        or not isinstance(producer, Mapping)
        or producer.get("id") != workflow_run
        or producer.get("head_sha") != source_commit
        or not _branch_matches_tag(producer.get("head_branch"), tag)
        or producer.get("repository_id") != repository_id
        or producer.get("head_repository_id") != repository_id
    ):
        raise ValueError("GitHub candidate artifact API identity does not match the production run")

    return {
        "repository": repository,
        "repository_id": repository_id,
        "artifact_id": artifact_id,
        "artifact_name": artifact_name,
        "artifact_sha256": digest_match.group(1),
        "artifact_size": artifact["size_in_bytes"],
        "producer_event": "push",
        "producer_workflow_path": PRODUCTION_WORKFLOW_PATH,
        "producer_run_attempt": run_attempt,
        "producer_status": "in_progress",
        "producer_conclusion": None,
    }


def _distribution_record(path: Path, inventory_record: object) -> dict[str, object]:
    if path.is_symlink() or not path.is_file() or not isinstance(inventory_record, Mapping):
        raise ValueError(f"candidate distribution is not an inventoried regular file: {path.name}")
    record: dict[str, object] = {"sha256": _sha256(path), "size": path.stat().st_size}
    if any(inventory_record.get(key) != value for key, value in record.items()):
        raise ValueError(f"candidate distribution differs from its inventory: {path.name}")
    return record


def _verified_candidate(
    archive: Path,
    *,
    archive_sha256: str,
    inventory_sha256: str,
    tag: str,
    source_commit: str,
    workflow_run: int,
    extraction_dir: Path,
) -> tuple[str, dict[str, dict[str, object]]]:
    version = version_from_tag(tag)
    unpack_candidate(archive, _require_sha256(archive_sha256, "archive SHA256"), extraction_dir)
    actual_inventory_sha256 = verify_inventory(
        extraction_dir,
        tag,
        source_commit,
        str(workflow_run),
        expected_sha256=_require_sha256(inventory_sha256, "inventory SHA256"),
    )
    inventory = _read_json(extraction_dir / INVENTORY_NAME)
    if (
        actual_inventory_sha256 != inventory_sha256
        or inventory.get("tag") != tag
        or inventory.get("version") != version
        or inventory.get("source_commit") != source_commit
        or inventory.get("workflow_run") != str(workflow_run)
    ):
        raise ValueError("candidate inventory identity differs from the production request")
    files = inventory.get("files")
    if not isinstance(files, Mapping):
        raise ValueError("candidate inventory files must be an object")
    distributions: dict[str, dict[str, object]] = {}
    for name in (f"xferry-{version}-py3-none-any.whl", f"xferry-{version}.tar.gz"):
        relative = f"python/{name}"
        distributions[name] = _distribution_record(extraction_dir / relative, files.get(relative))
    return version, distributions


def _write_identity_directory(output_dir: Path, documents: Mapping[str, object]) -> None:
    output_dir = Path(output_dir)
    if output_dir.is_symlink() or output_dir.exists():
        raise ValueError("production identity output directory must be new")
    output_dir.parent.mkdir(parents=True, exist_ok=True)
    with TemporaryDirectory(prefix=f".{output_dir.name}.", dir=output_dir.parent) as temporary:
        temporary_dir = Path(temporary)
        for name in sorted(documents):
            _write_canonical(temporary_dir / name, documents[name])
        if output_dir.is_symlink() or output_dir.exists():
            raise ValueError("production identity output directory must remain new")
        temporary_dir.rename(output_dir)


def prepare_release_identities(
    artifact: Mapping[str, Any],
    run: Mapping[str, Any],
    *,
    artifact_id: int,
    repository: str,
    tag: str,
    source_commit: str,
    workflow_run: int,
    archive: Path,
    archive_sha256: str,
    inventory_sha256: str,
    output_dir: Path,
) -> dict[str, Path]:
    """Verify one candidate and atomically materialize all channel identity files."""
    output_dir = Path(output_dir)
    if output_dir.is_symlink() or output_dir.exists():
        raise ValueError("production identity output directory must be new")
    api = verify_api_identity(
        artifact,
        run,
        artifact_id=artifact_id,
        repository=repository,
        tag=tag,
        source_commit=source_commit,
        workflow_run=workflow_run,
    )
    with TemporaryDirectory(prefix="xferry-production-candidate-") as temporary:
        version, distributions = _verified_candidate(
            Path(archive),
            archive_sha256=archive_sha256,
            inventory_sha256=inventory_sha256,
            tag=tag,
            source_commit=source_commit,
            workflow_run=workflow_run,
            extraction_dir=Path(temporary) / "candidate",
        )

    common = {
        **api,
        "version": version,
        "tag": tag,
        "source_commit": source_commit,
        "workflow_run": workflow_run,
        "archive_sha256": archive_sha256,
        "inventory_sha256": inventory_sha256,
    }
    documents = {
        TESTPYPI_IDENTITY_NAME: {**common, "distributions": distributions},
        GHCR_IDENTITY_NAME: {**common, "image": GHCR_IMAGE},
        GITHUB_RELEASE_IDENTITY_NAME: {**common, "release_tag": tag},
    }
    _write_identity_directory(output_dir, documents)
    return {name: output_dir / name for name in documents}


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    prepare = subparsers.add_parser("prepare")
    prepare.add_argument("--artifact-metadata", type=Path, required=True)
    prepare.add_argument("--run-metadata", type=Path, required=True)
    prepare.add_argument("--artifact-id", type=int, required=True)
    prepare.add_argument("--repository", required=True)
    prepare.add_argument("--tag", required=True)
    prepare.add_argument("--source-commit", required=True)
    prepare.add_argument("--workflow-run", type=int, required=True)
    prepare.add_argument("--archive", type=Path, required=True)
    prepare.add_argument("--archive-sha256", required=True)
    prepare.add_argument("--inventory-sha256", required=True)
    prepare.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        paths = prepare_release_identities(
            _read_json(args.artifact_metadata),
            _read_json(args.run_metadata),
            artifact_id=args.artifact_id,
            repository=args.repository,
            tag=args.tag,
            source_commit=args.source_commit,
            workflow_run=args.workflow_run,
            archive=args.archive,
            archive_sha256=args.archive_sha256,
            inventory_sha256=args.inventory_sha256,
            output_dir=args.output_dir,
        )
    except (KeyError, OSError, TypeError, UnicodeError, ValueError) as error:
        print(f"production identity preparation failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps({name: str(path) for name, path in sorted(paths.items())}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
