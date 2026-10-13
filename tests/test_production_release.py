"""Production promotion derives channel identities from one authenticated candidate."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from tests.test_candidate_promotion import COMMIT, RUN, TAG, VERSION, _candidate
from tools import production_release
from tools.candidate_inventory import create_inventory, pack_candidate

REPOSITORY = "kgmnotes/xferry"
REPOSITORY_ID = 1_341_230_685
ARTIFACT_ID = 12_345_678_901
WORKFLOW_PATH = ".github/workflows/release-production.yml"


def _canonical(document: object) -> bytes:
    return (json.dumps(document, sort_keys=True, indent=2, allow_nan=False) + "\n").encode()


def _prepared_candidate(tmp_path: Path) -> tuple[Path, str, str]:
    candidate = _candidate(tmp_path / "candidate")
    inventory_sha256 = create_inventory(candidate, TAG, COMMIT, RUN)
    archive = tmp_path / "release-candidate.tar"
    archive_sha256 = pack_candidate(candidate, archive)
    return archive, archive_sha256, inventory_sha256


def _metadata(
    *, archive_sha256: str, artifact_attempt: int = 2, run_attempt: int = 3
) -> tuple[dict, dict]:
    artifact_digest = hashlib.sha256(b"GitHub artifact envelope").hexdigest()
    artifact = {
        "id": ARTIFACT_ID,
        "name": f"release-candidate-{RUN}-{artifact_attempt}",
        "digest": f"sha256:{artifact_digest}",
        "expired": False,
        "size_in_bytes": 765_432_100,
        "workflow_run": {
            "id": int(RUN),
            "head_branch": TAG,
            "head_sha": COMMIT,
            "repository_id": REPOSITORY_ID,
            "head_repository_id": REPOSITORY_ID,
        },
    }
    run = {
        "id": int(RUN),
        "run_attempt": run_attempt,
        "head_sha": COMMIT,
        "head_branch": TAG,
        "event": "push",
        "path": WORKFLOW_PATH,
        "status": "in_progress",
        "conclusion": None,
        "repository": {"id": REPOSITORY_ID, "full_name": REPOSITORY},
        "head_repository": {"id": REPOSITORY_ID, "full_name": REPOSITORY},
    }
    assert archive_sha256 != artifact_digest
    return artifact, run


def _prepare(
    tmp_path: Path,
    artifact: dict,
    run: dict,
    archive: Path,
    archive_sha256: str,
    inventory_sha256: str,
) -> Path:
    output = tmp_path / "identities"
    production_release.prepare_release_identities(
        artifact,
        run,
        artifact_id=ARTIFACT_ID,
        repository=REPOSITORY,
        tag=TAG,
        source_commit=COMMIT,
        workflow_run=int(RUN),
        archive=archive,
        archive_sha256=archive_sha256,
        inventory_sha256=inventory_sha256,
        output_dir=output,
    )
    return output


def _cli_arguments(
    artifact_path: Path,
    run_path: Path,
    archive: Path,
    archive_sha256: str,
    inventory_sha256: str,
    output: Path,
) -> list[str]:
    return [
        "prepare",
        "--artifact-metadata",
        str(artifact_path),
        "--run-metadata",
        str(run_path),
        "--artifact-id",
        str(ARTIFACT_ID),
        "--repository",
        REPOSITORY,
        "--tag",
        TAG,
        "--source-commit",
        COMMIT,
        "--workflow-run",
        RUN,
        "--archive",
        str(archive),
        "--archive-sha256",
        archive_sha256,
        "--inventory-sha256",
        inventory_sha256,
        "--output-dir",
        str(output),
    ]


def test_prepare_writes_three_canonical_compatible_identities(tmp_path: Path) -> None:
    archive, archive_sha256, inventory_sha256 = _prepared_candidate(tmp_path)
    artifact, run = _metadata(archive_sha256=archive_sha256)

    output = _prepare(tmp_path, artifact, run, archive, archive_sha256, inventory_sha256)

    expected_names = {
        "testpypi-candidate.json",
        "ghcr-candidate.json",
        "github-release-candidate.json",
    }
    assert {path.name for path in output.iterdir()} == expected_names
    documents = {path.name: json.loads(path.read_bytes()) for path in output.iterdir()}
    for path in output.iterdir():
        assert path.read_bytes() == _canonical(documents[path.name])

    common = {
        "repository": REPOSITORY,
        "repository_id": REPOSITORY_ID,
        "version": VERSION,
        "tag": TAG,
        "source_commit": COMMIT,
        "workflow_run": int(RUN),
        "artifact_id": ARTIFACT_ID,
        "artifact_name": f"release-candidate-{RUN}-2",
        "artifact_sha256": artifact["digest"].removeprefix("sha256:"),
        "artifact_size": artifact["size_in_bytes"],
        "archive_sha256": archive_sha256,
        "inventory_sha256": inventory_sha256,
        "producer_event": "push",
        "producer_workflow_path": WORKFLOW_PATH,
        "producer_run_attempt": 3,
        "producer_status": "in_progress",
        "producer_conclusion": None,
    }
    for document in documents.values():
        for key, value in common.items():
            assert document[key] == value

    wheel = archive.parent / "candidate" / f"python/xferry-{VERSION}-py3-none-any.whl"
    sdist = archive.parent / "candidate" / f"python/xferry-{VERSION}.tar.gz"
    assert documents["testpypi-candidate.json"]["distributions"] == {
        wheel.name: {
            "sha256": hashlib.sha256(wheel.read_bytes()).hexdigest(),
            "size": wheel.stat().st_size,
        },
        sdist.name: {
            "sha256": hashlib.sha256(sdist.read_bytes()).hexdigest(),
            "size": sdist.stat().st_size,
        },
    }
    assert documents["ghcr-candidate.json"]["image"] == "ghcr.io/kgmnotes/xferry"
    assert documents["github-release-candidate.json"]["release_tag"] == TAG


def test_cli_prepares_the_same_identity_set(tmp_path: Path) -> None:
    archive, archive_sha256, inventory_sha256 = _prepared_candidate(tmp_path)
    artifact, run = _metadata(archive_sha256=archive_sha256)
    artifact_path = tmp_path / "artifact.json"
    run_path = tmp_path / "run.json"
    artifact_path.write_bytes(_canonical(artifact))
    run_path.write_bytes(_canonical(run))
    output = tmp_path / "identities"

    result = production_release.main(
        _cli_arguments(
            artifact_path,
            run_path,
            archive,
            archive_sha256,
            inventory_sha256,
            output,
        )
    )

    assert result == 0
    assert {path.name for path in output.iterdir()} == {
        "testpypi-candidate.json",
        "ghcr-candidate.json",
        "github-release-candidate.json",
    }


@pytest.mark.parametrize(
    ("target", "path", "value"),
    [
        ("artifact", ("id",), ARTIFACT_ID + 1),
        ("artifact", ("name",), f"release-candidate-{RUN}-4"),
        ("artifact", ("name",), f"release-candidate-{RUN}-0"),
        ("artifact", ("digest",), "sha256:" + "A" * 64),
        ("artifact", ("size_in_bytes",), 0),
        ("artifact", ("expired",), True),
        ("artifact", ("workflow_run", "id"), int(RUN) + 1),
        ("artifact", ("workflow_run", "head_sha"), "b" * 40),
        ("artifact", ("workflow_run", "head_branch"), "main"),
        ("artifact", ("workflow_run", "repository_id"), REPOSITORY_ID + 1),
        ("artifact", ("workflow_run", "head_repository_id"), REPOSITORY_ID + 1),
        ("run", ("id",), int(RUN) + 1),
        ("run", ("run_attempt",), 0),
        ("run", ("head_sha",), "b" * 40),
        ("run", ("head_branch",), "main"),
        ("run", ("event",), "workflow_dispatch"),
        ("run", ("path",), ".github/workflows/release.yml"),
        ("run", ("status",), "completed"),
        ("run", ("conclusion",), "success"),
        ("run", ("repository", "id"), REPOSITORY_ID + 1),
        ("run", ("repository", "full_name"), "attacker/xferry"),
        ("run", ("head_repository", "id"), REPOSITORY_ID + 1),
        ("run", ("head_repository", "full_name"), "attacker/xferry"),
    ],
)
def test_api_identity_substitutions_are_rejected_before_output(
    tmp_path: Path, target: str, path: tuple[str, ...], value: object
) -> None:
    archive, archive_sha256, inventory_sha256 = _prepared_candidate(tmp_path)
    artifact, run = _metadata(archive_sha256=archive_sha256)
    document = artifact if target == "artifact" else run
    selected = document
    for key in path[:-1]:
        selected = selected[key]
    selected[path[-1]] = value

    with pytest.raises(ValueError, match="identity"):
        _prepare(tmp_path, artifact, run, archive, archive_sha256, inventory_sha256)

    assert not (tmp_path / "identities").exists()


def test_null_tag_branch_is_accepted_for_github_tag_api_variance(tmp_path: Path) -> None:
    archive, archive_sha256, inventory_sha256 = _prepared_candidate(tmp_path)
    artifact, run = _metadata(archive_sha256=archive_sha256)
    artifact["workflow_run"]["head_branch"] = None
    run["head_branch"] = None

    assert _prepare(tmp_path, artifact, run, archive, archive_sha256, inventory_sha256).is_dir()


@pytest.mark.parametrize(
    ("argument", "replacement", "message"),
    [
        ("repository", "attacker/xferry", "repository"),
        ("tag", "v01.0.0", "tag"),
        ("source_commit", "B" * 40, "commit"),
        ("workflow_run", int(RUN) + 1, "identity"),
        ("artifact_id", ARTIFACT_ID + 1, "identity"),
        ("archive_sha256", "0" * 64, "SHA256"),
        ("inventory_sha256", "0" * 64, "inventory"),
    ],
)
def test_requested_or_candidate_identity_substitution_is_rejected(
    tmp_path: Path, argument: str, replacement: object, message: str
) -> None:
    archive, archive_sha256, inventory_sha256 = _prepared_candidate(tmp_path)
    artifact, run = _metadata(archive_sha256=archive_sha256)
    arguments = {
        "artifact_id": ARTIFACT_ID,
        "repository": REPOSITORY,
        "tag": TAG,
        "source_commit": COMMIT,
        "workflow_run": int(RUN),
        "archive": archive,
        "archive_sha256": archive_sha256,
        "inventory_sha256": inventory_sha256,
        "output_dir": tmp_path / "identities",
    }
    arguments[argument] = replacement

    with pytest.raises(ValueError, match=message):
        production_release.prepare_release_identities(artifact, run, **arguments)

    assert not (tmp_path / "identities").exists()


def test_existing_output_directory_is_never_reused(tmp_path: Path) -> None:
    archive, archive_sha256, inventory_sha256 = _prepared_candidate(tmp_path)
    artifact, run = _metadata(archive_sha256=archive_sha256)
    output = tmp_path / "identities"
    output.mkdir()
    sentinel = output / "do-not-overwrite"
    sentinel.write_text("retained", encoding="utf-8")

    with pytest.raises(ValueError, match="new"):
        _prepare(tmp_path, artifact, run, archive, archive_sha256, inventory_sha256)

    assert sentinel.read_text(encoding="utf-8") == "retained"


def test_cli_rejects_duplicate_metadata_keys_without_output(tmp_path: Path) -> None:
    archive, archive_sha256, inventory_sha256 = _prepared_candidate(tmp_path)
    artifact, run = _metadata(archive_sha256=archive_sha256)
    artifact_path = tmp_path / "artifact.json"
    run_path = tmp_path / "run.json"
    artifact_payload = json.dumps(artifact)
    artifact_path.write_text(artifact_payload[:-1] + ', "id": 1}', encoding="utf-8")
    run_path.write_text(json.dumps(run), encoding="utf-8")
    output = tmp_path / "identities"

    result = production_release.main(
        _cli_arguments(
            artifact_path,
            run_path,
            archive,
            archive_sha256,
            inventory_sha256,
            output,
        )
    )

    assert result == 1
    assert not output.exists()


def test_failure_never_leaves_partial_identity_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    archive, archive_sha256, inventory_sha256 = _prepared_candidate(tmp_path)
    artifact, run = _metadata(archive_sha256=archive_sha256)
    real_write = production_release._write_canonical
    calls = 0

    def fail_second_write(path: Path, document: object) -> None:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("simulated disk failure")
        real_write(path, document)

    monkeypatch.setattr(production_release, "_write_canonical", fail_second_write)

    with pytest.raises(OSError, match="disk failure"):
        _prepare(tmp_path, artifact, run, archive, archive_sha256, inventory_sha256)

    assert not (tmp_path / "identities").exists()
