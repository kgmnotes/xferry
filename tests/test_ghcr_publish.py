"""GHCR staging promotion preserves the exact STAGE-009 OCI candidate."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import textwrap
from pathlib import Path

import pytest

from tests.test_candidate_promotion import COMMIT, RUN, TAG, _candidate
from tools.candidate_inventory import create_inventory, pack_candidate
from tools.check_stale_docs import (
    find_release_policy_issues,
    ghcr_workflow_policy_findings,
)
from tools.ghcr_publish import (
    IMAGE_NAME,
    prepare_oci_candidate,
    verify_registry_layout,
)

REPO_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def ghcr_identity() -> dict:
    return json.loads((REPO_ROOT / "packaging/ghcr-candidate.json").read_text())


def _metadata(identity: dict) -> tuple[dict, dict]:
    artifact = {
        "id": identity["artifact_id"],
        "name": identity["artifact_name"],
        "digest": "sha256:" + identity["artifact_sha256"],
        "expired": False,
        "size_in_bytes": identity["artifact_size"],
        "workflow_run": {
            "id": identity["workflow_run"],
            "head_sha": identity["source_commit"],
            "repository_id": identity["repository_id"],
        },
    }
    run = {
        "id": identity["workflow_run"],
        "run_attempt": 1,
        "head_sha": identity["source_commit"],
        "event": "workflow_dispatch",
        "path": ".github/workflows/release.yml",
        "status": "completed",
        "conclusion": "success",
        "repository": {"id": identity["repository_id"], "full_name": identity["repository"]},
    }
    return artifact, run


def _identity_for(candidate: Path, inventory_sha: str, archive_sha: str) -> dict:
    inventory = json.loads((candidate / "candidate-inventory.json").read_text())
    return {
        "repository": "kgmnotes/xferry",
        "repository_id": 1341230685,
        "version": inventory["version"],
        "tag": inventory["tag"],
        "source_commit": inventory["source_commit"],
        "workflow_run": int(inventory["workflow_run"]),
        "artifact_id": 11095067140,
        "artifact_name": "release-candidate-36712344792-1",
        "artifact_sha256": "0" * 64,
        "artifact_size": 123,
        "archive_sha256": archive_sha,
        "inventory_sha256": inventory_sha,
        "image": IMAGE_NAME,
    }


def _prepared_candidate(tmp_path: Path) -> tuple[Path, dict]:
    candidate = _candidate(tmp_path / "candidate")
    inventory_sha = create_inventory(candidate, TAG, COMMIT, RUN)
    archive = tmp_path / "release-candidate.tar"
    archive_sha = pack_candidate(candidate, archive)
    return archive, _identity_for(candidate, inventory_sha, archive_sha)


def _workflow_named_step(workflow: str, name: str) -> str:
    lines = workflow.splitlines()
    marker = f"      - name: {name}"
    start = lines.index(marker)
    end = len(lines)
    for index in range(start + 1, len(lines)):
        line = lines[index]
        if line.startswith("      - name: ") or (
            len(line) - len(line.lstrip()) == 2 and line.endswith(":")
        ):
            end = index
            break
    return "\n".join(lines[start:end])


def _workflow_run_script(workflow: str, step_name: str) -> str:
    step = _workflow_named_step(workflow, step_name)
    marker = "        run: |\n"
    assert marker in step
    return textwrap.dedent(step.split(marker, maxsplit=1)[1])


def _digest(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _write_fake_skopeo(bin_dir: Path) -> Path:
    fake = bin_dir / "skopeo"
    fake.write_text(
        """#!/usr/bin/env python3
import os
import sys
from pathlib import Path

log = Path(os.environ["FAKE_SKOPEO_LOG"])
state = Path(os.environ["FAKE_SKOPEO_STATE"])
arguments = " ".join(sys.argv[1:])
previous = log.read_text() if log.exists() else ""
log.write_text(previous + arguments + "\\n")
scenario = os.environ["FAKE_SKOPEO_SCENARIO"]

def fail(message: str) -> None:
    print(message, file=sys.stderr)
    raise SystemExit(1)

if sys.argv[1:2] == ["login"]:
    raise SystemExit(0)
if sys.argv[1:2] == ["copy"]:
    state.write_text("copied", encoding="utf-8")
    raise SystemExit(0)
if sys.argv[1:3] == ["inspect", "--raw"]:
    target = sys.argv[-1]
    if target.endswith(":latest"):
        if os.environ.get("FAKE_LATEST") == "present":
            sys.stdout.buffer.write(os.environ["FAKE_LATEST_RAW"].encode())
            raise SystemExit(0)
        if os.environ.get("FAKE_LATEST") == "api404":
            fail("GET https://ghcr.io/token returned 404 unauthorized")
        fail("manifest unknown: latest")
    if state.exists():
        sys.stdout.buffer.write(os.environ["FAKE_POST_COPY_RAW"].encode())
        raise SystemExit(0)
    if scenario == "absent":
        fail("manifest unknown: v0.1.0")
    if scenario == "equal":
        sys.stdout.buffer.write(os.environ["FAKE_EXISTING_RAW"].encode())
        raise SystemExit(0)
    if scenario == "conflict":
        sys.stdout.buffer.write(b"conflicting-index")
        raise SystemExit(0)
    if scenario == "auth":
        fail("unauthorized: authentication required")
    if scenario == "timeout":
        fail("dial tcp: i/o timeout")
    if scenario == "server":
        fail("500 Internal Server Error")
fail("unexpected skopeo invocation: " + " ".join(sys.argv[1:]))
""",
        encoding="utf-8",
    )
    fake.chmod(0o755)
    return fake


def _run_publish_shell(
    tmp_path: Path, scenario: str, *, latest: str = "absent"
) -> subprocess.CompletedProcess[str]:
    workflow = (REPO_ROOT / ".github/workflows/ghcr.yml").read_text()
    script = _workflow_run_script(workflow, "Promote exact OCI graph to GHCR")
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    _write_fake_skopeo(fake_bin)
    existing_raw = b"existing-index"
    post_copy_raw = b"published-index"
    expected_raw = existing_raw if scenario == "equal" else post_copy_raw
    environment = {
        **os.environ,
        "PATH": str(fake_bin) + os.pathsep + os.environ["PATH"],
        "FAKE_SKOPEO_LOG": str(tmp_path / "skopeo.log"),
        "FAKE_SKOPEO_STATE": str(tmp_path / "copied.state"),
        "FAKE_SKOPEO_SCENARIO": scenario,
        "FAKE_EXISTING_RAW": existing_raw.decode(),
        "FAKE_POST_COPY_RAW": post_copy_raw.decode(),
        "FAKE_LATEST": latest,
        "FAKE_LATEST_RAW": "latest-index",
        "GHCR_IMAGE": IMAGE_NAME,
        "GHCR_TAG": "v0.1.0",
        "GH_TOKEN": "token",
        "EXPECTED_DIGEST": _digest(expected_raw),
        "GITHUB_ACTOR": "kgmnotes",
        "GITHUB_OUTPUT": str(tmp_path / "github-output"),
    }
    (tmp_path / "staged" / "oci").mkdir(parents=True)
    return subprocess.run(
        ["bash", "-c", script],
        cwd=tmp_path,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )


def _run_refuse_latest_shell(tmp_path: Path, *, latest: str) -> subprocess.CompletedProcess[str]:
    workflow = (REPO_ROOT / ".github/workflows/ghcr.yml").read_text()
    script = _workflow_run_script(workflow, "Refuse mutable latest tag")
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    _write_fake_skopeo(fake_bin)
    environment = {
        **os.environ,
        "PATH": str(fake_bin) + os.pathsep + os.environ["PATH"],
        "FAKE_SKOPEO_LOG": str(tmp_path / "skopeo.log"),
        "FAKE_SKOPEO_STATE": str(tmp_path / "copied.state"),
        "FAKE_SKOPEO_SCENARIO": "absent",
        "FAKE_LATEST": latest,
        "FAKE_LATEST_RAW": "latest-index",
        "GHCR_IMAGE": IMAGE_NAME,
    }
    return subprocess.run(
        ["bash", "-c", script],
        cwd=tmp_path,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )


def test_ghcr_candidate_identity_tracks_the_fixed_stage009_artifact(
    ghcr_identity: dict,
) -> None:
    """Catches GHCR staging drifting to a different producer than TestPyPI."""
    testpypi_identity = json.loads((REPO_ROOT / "packaging/testpypi-candidate.json").read_text())

    for field in (
        "repository",
        "repository_id",
        "version",
        "tag",
        "source_commit",
        "workflow_run",
        "artifact_id",
        "artifact_name",
        "artifact_sha256",
        "artifact_size",
        "archive_sha256",
        "inventory_sha256",
    ):
        assert ghcr_identity[field] == testpypi_identity[field]
    assert ghcr_identity["image"] == IMAGE_NAME


def test_prepare_oci_candidate_records_publish_digest_platforms_and_attestations(
    tmp_path: Path,
) -> None:
    """Catches staging copying bytes without preserving the publishable OCI graph."""
    archive, identity = _prepared_candidate(tmp_path)

    receipt = prepare_oci_candidate(
        identity,
        archive,
        tmp_path / "promoted",
        tmp_path / "staged-oci",
        tmp_path / "ghcr-receipt.json",
    )

    assert (tmp_path / "staged-oci/index.json").is_file()
    assert receipt["image"] == IMAGE_NAME
    assert receipt["tag"] == TAG
    assert receipt["oci"]["layout_root_digest"].startswith("sha256:")
    assert receipt["oci"]["publish_digest"].startswith("sha256:")
    assert receipt["oci"]["publish_digest"] != receipt["oci"]["layout_root_digest"]
    assert set(receipt["oci"]["platform_manifests"]) == {"linux/amd64", "linux/arm64"}
    for predicates in receipt["oci"]["attestation_predicates"].values():
        assert "https://spdx.dev/Document" in predicates
        assert "https://slsa.dev/provenance/v0.2" in predicates


def test_prepare_oci_candidate_stops_before_writing_on_bad_archive_identity(
    tmp_path: Path,
) -> None:
    """Catches extraction or staging before the artifact SHA is authenticated."""
    archive = tmp_path / "release-candidate.tar"
    archive.write_bytes(b"foreign")
    identity = {
        "tag": TAG,
        "version": "0.1.0",
        "source_commit": COMMIT,
        "workflow_run": int(RUN),
        "archive_sha256": "a" * 64,
        "inventory_sha256": "b" * 64,
        "image": IMAGE_NAME,
    }

    with pytest.raises(ValueError, match="SHA256"):
        prepare_oci_candidate(
            identity,
            archive,
            tmp_path / "promoted",
            tmp_path / "staged-oci",
            tmp_path / "ghcr-receipt.json",
        )

    assert not (tmp_path / "promoted").exists()
    assert not (tmp_path / "staged-oci").exists()
    assert not (tmp_path / "ghcr-receipt.json").exists()


def test_registry_layout_verification_rejects_missing_attestation_predicates(
    tmp_path: Path,
) -> None:
    """Catches a registry copy that loses SBOM/provenance attachment manifests."""
    archive, identity = _prepared_candidate(tmp_path)
    receipt = prepare_oci_candidate(
        identity,
        archive,
        tmp_path / "promoted",
        tmp_path / "staged-oci",
        tmp_path / "ghcr-receipt.json",
    )
    registry_oci = tmp_path / "registry-oci"
    shutil.copytree(tmp_path / "staged-oci", registry_oci)
    verify_registry_layout(receipt, registry_oci)

    index = json.loads((registry_oci / "index.json").read_text())
    nested_digest = index["manifests"][0]["digest"][7:]
    nested = json.loads((registry_oci / "blobs/sha256" / nested_digest).read_text())
    nested["manifests"] = [
        item
        for item in nested["manifests"]
        if item.get("platform", {}).get("architecture") != "unknown"
    ]
    replacement = json.dumps(nested, sort_keys=True, separators=(",", ":")).encode()
    replacement_digest = hashlib.sha256(replacement).hexdigest()
    (registry_oci / "blobs/sha256" / replacement_digest).write_bytes(replacement)
    old_path = registry_oci / "blobs/sha256" / nested_digest
    if replacement_digest != nested_digest:
        old_path.unlink()
    index["manifests"][0].update(
        digest=f"sha256:{replacement_digest}",
        size=len(replacement),
    )
    (registry_oci / "index.json").write_text(
        json.dumps(index, sort_keys=True, separators=(",", ":"))
    )

    with pytest.raises(ValueError, match="attestation"):
        verify_registry_layout(receipt, registry_oci)


def test_registry_layout_verification_rejects_changed_attestation_manifest_digest(
    tmp_path: Path,
) -> None:
    """Catches a registry copy changing SBOM/provenance bytes under the same predicates."""
    archive, identity = _prepared_candidate(tmp_path)
    receipt = prepare_oci_candidate(
        identity,
        archive,
        tmp_path / "promoted",
        tmp_path / "staged-oci",
        tmp_path / "ghcr-receipt.json",
    )
    registry_oci = tmp_path / "registry-oci"
    shutil.copytree(tmp_path / "staged-oci", registry_oci)
    index = json.loads((registry_oci / "index.json").read_text())
    nested_descriptor = index["manifests"][0]
    nested = json.loads(
        (registry_oci / "blobs/sha256" / nested_descriptor["digest"][7:]).read_text()
    )
    attestation_descriptor = next(
        item
        for item in nested["manifests"]
        if item.get("platform", {}).get("architecture") == "unknown"
    )
    attestation = json.loads(
        (registry_oci / "blobs/sha256" / attestation_descriptor["digest"][7:]).read_text()
    )
    layer = attestation["layers"][0]
    statement_path = registry_oci / "blobs/sha256" / layer["digest"][7:]
    statement = json.loads(statement_path.read_text())
    statement["predicate"]["name"] = "changed-but-same-predicate-type"
    statement_payload = json.dumps(statement, sort_keys=True, separators=(",", ":")).encode()
    statement_digest = hashlib.sha256(statement_payload).hexdigest()
    (registry_oci / "blobs/sha256" / statement_digest).write_bytes(statement_payload)
    statement_path.unlink()
    layer.update(digest=f"sha256:{statement_digest}", size=len(statement_payload))
    attestation_payload = json.dumps(attestation, sort_keys=True, separators=(",", ":")).encode()
    attestation_digest = hashlib.sha256(attestation_payload).hexdigest()
    (registry_oci / "blobs/sha256" / attestation_digest).write_bytes(attestation_payload)
    (registry_oci / "blobs/sha256" / attestation_descriptor["digest"][7:]).unlink()
    attestation_descriptor.update(
        digest=f"sha256:{attestation_digest}", size=len(attestation_payload)
    )
    nested_payload = json.dumps(nested, sort_keys=True, separators=(",", ":")).encode()
    nested_digest = hashlib.sha256(nested_payload).hexdigest()
    (registry_oci / "blobs/sha256" / nested_digest).write_bytes(nested_payload)
    (registry_oci / "blobs/sha256" / nested_descriptor["digest"][7:]).unlink()
    nested_descriptor.update(digest=f"sha256:{nested_digest}", size=len(nested_payload))
    (registry_oci / "index.json").write_text(
        json.dumps(index, sort_keys=True, separators=(",", ":"))
    )

    with pytest.raises(ValueError, match="attestation manifest"):
        verify_registry_layout(receipt, registry_oci)


@pytest.mark.parametrize(
    ("scenario", "should_pass", "should_copy"),
    [
        ("absent", True, True),
        ("equal", True, False),
        ("conflict", False, False),
        ("auth", False, False),
        ("timeout", False, False),
        ("server", False, False),
    ],
)
def test_publish_shell_distinguishes_absent_equal_conflict_and_transient_failures(
    tmp_path: Path, scenario: str, should_pass: bool, should_copy: bool
) -> None:
    """Catches auth/rate-limit/server inspect failures being treated as tag absence."""
    completed = _run_publish_shell(tmp_path, scenario)
    log = (tmp_path / "skopeo.log").read_text()

    assert (completed.returncode == 0) is should_pass, completed.stderr
    assert ("copy --all --preserve-digests" in log) is should_copy


def test_publish_shell_refuses_latest_before_first_copy(tmp_path: Path) -> None:
    """Catches the mutable latest guard running only after the first registry write."""
    completed = _run_publish_shell(tmp_path, "absent", latest="present")
    log = (tmp_path / "skopeo.log").read_text().splitlines()

    assert completed.returncode != 0
    assert not any("copy --all --preserve-digests" in line for line in log)


def test_publish_shell_does_not_treat_unrelated_404_as_manifest_absence(
    tmp_path: Path,
) -> None:
    """Catches auth/proxy/API 404 responses opening the registry write boundary."""
    completed = _run_publish_shell(tmp_path, "absent", latest="api404")
    log = (tmp_path / "skopeo.log").read_text().splitlines()

    assert completed.returncode != 0
    assert not any("copy --all --preserve-digests" in line for line in log)


def test_final_latest_guard_does_not_treat_unrelated_404_as_manifest_absence(
    tmp_path: Path,
) -> None:
    """Catches an unrelated 404 bypassing the independent final latest guard."""
    completed = _run_refuse_latest_shell(tmp_path, latest="api404")

    assert completed.returncode != 0


def test_registry_verification_creates_oci_parent_before_skopeo_copy(
    tmp_path: Path,
) -> None:
    """Catches Skopeo rejecting an OCI destination whose parent is absent."""
    workflow = (REPO_ROOT / ".github/workflows/ghcr.yml").read_text()
    script = _workflow_run_script(
        workflow, "Copy registry graph and verify digests, SBOM, and provenance"
    )
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    (fake_bin / "sudo").write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    (fake_bin / "skopeo").write_text(
        """#!/bin/sh
if [ "$1" = "login" ]; then
  cat >/dev/null
  exit 0
fi
if [ "$1" = "copy" ]; then
  test -d registry || exit 97
  mkdir -p registry/oci
  exit 0
fi
exit 98
""",
        encoding="utf-8",
    )
    (fake_bin / "python").write_text(
        """#!/bin/sh
test "$1" = "tools/ghcr_publish.py"
test "$2" = "verify-registry-layout"
test -d registry/oci
""",
        encoding="utf-8",
    )
    for executable in fake_bin.iterdir():
        executable.chmod(0o755)

    completed = subprocess.run(
        ["bash", "-c", script],
        cwd=tmp_path,
        env={
            **os.environ,
            "PATH": f"{fake_bin}{os.pathsep}{os.environ['PATH']}",
            "GH_TOKEN": "test-token",
            "GITHUB_ACTOR": "kgmnotes",
            "GHCR_DIGEST": "sha256:" + "a" * 64,
        },
        text=True,
        capture_output=True,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr


@pytest.mark.parametrize(
    ("before", "after"),
    [
        ("workflow_dispatch:", "push:"),
        ("environment: ghcr-staging", "environment: production"),
        ("packages: write", "contents: write"),
        ("skopeo copy --all --preserve-digests", "docker build --push"),
        ("GHCR_IMAGE: ghcr.io/kgmnotes/xferry", "GHCR_IMAGE: ghcr.io/kgmnotes/other"),
        ("GHCR_TAG: v0.1.0", "GHCR_TAG: v0.1.1"),
        (
            'test "$existing_digest" = "$EXPECTED_DIGEST"',
            "true # skipped existing digest equality",
        ),
        (
            'test "$registry_digest" = "$EXPECTED_DIGEST"',
            "true # skipped registry digest equality",
        ),
        (
            "test \"$(uname -m)\" = '${{ matrix.machine }}'",
            "uname -m >/dev/null",
        ),
        (
            "skopeo=1.13.3+ds1-2ubuntu0.24.04.3",
            "skopeo",
        ),
        (
            'skopeo copy --all --preserve-digests "docker://ghcr.io/kgmnotes/xferry@${GHCR_DIGEST}"',
            'skopeo copy --all "docker://ghcr.io/kgmnotes/xferry@${GHCR_DIGEST}"',
        ),
        ("mkdir -p registry", "true # skipped registry destination setup"),
        ("refs/heads/codex/stage-011-ghcr-rehearsal-v2", "refs/heads/main"),
        ("artifact-ids: 11095067140", "artifact-ids: 1"),
        ("Refuse mutable latest tag", "Publish mutable latest tag"),
    ],
)
def test_ghcr_staging_policy_rejects_boundary_regressions(before: str, after: str) -> None:
    workflow = (REPO_ROOT / ".github/workflows/ghcr.yml").read_text()
    assert ghcr_workflow_policy_findings(workflow) == []
    assert before in workflow

    assert ghcr_workflow_policy_findings(workflow.replace(before, after, 1))


def test_ghcr_staging_policy_is_included_in_repository_guard(tmp_path: Path) -> None:
    path = Path(".github/workflows/ghcr.yml")
    (tmp_path / path).parent.mkdir(parents=True)
    workflow = (REPO_ROOT / path).read_text()
    (tmp_path / path).write_text(workflow.replace("packages: write", "contents: write", 1))

    assert find_release_policy_issues(tmp_path, targets=(path.as_posix(),))


def test_ghcr_publish_job_does_not_checkout_or_execute_repository_code() -> None:
    workflow = (REPO_ROOT / ".github/workflows/ghcr.yml").read_text()
    publish = workflow.split("\n  publish:", maxsplit=1)[1].split("\n  registry-verify:", 1)[0]

    assert "actions/checkout@" not in publish
    assert "tools/ghcr_publish.py" not in publish
    assert "docker/login-action" not in publish
    assert "${{ secrets." not in publish
