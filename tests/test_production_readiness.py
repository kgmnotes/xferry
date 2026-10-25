"""Real archive/receipt validation with an explicitly mocked external Sigstore CLI."""

from __future__ import annotations

import copy
import hashlib
import io
import json
import stat
import subprocess
import urllib.request
import zipfile
from pathlib import Path
from typing import Any

import pytest

from tests.test_managed_public_matrix import _result as _public_result
from tests.test_managed_public_matrix import signed as _signed_fixture
from tests.test_managed_systemd_matrix import SOURCE, _architecture
from tools import production_readiness as readiness

signed = _signed_fixture
RUN = 123
ATTEMPT = 1
TAG = "v0.2.0"


def _document() -> dict[str, Any]:
    return {
        "schema": 1,
        "scope": "native-systemd-ten-pair-fixture-matrix",
        "status": "passed",
        "sourceCommit": SOURCE,
        "workflowRun": str(RUN),
        "workflowAttempt": ATTEMPT,
        "publicReleaseEvidence": False,
        "pairCount": 10,
        "architectures": [_architecture("linux-aarch64"), _architecture("linux-x86_64")],
    }


def _verified(
    body: bytes,
    *,
    source_commit: str = SOURCE,
    workflow_run: int = RUN,
    workflow_attempt: int = ATTEMPT,
    signer_name: str = "managed-systemd-matrix.yml",
    subject_name: str = "systemd-matrix-verified.json",
) -> list[dict[str, Any]]:
    reference = f"refs/tags/{TAG}"
    base = f"https://github.com/{readiness.REPOSITORY}"
    signer = f"{base}/.github/workflows/{signer_name}@{reference}"
    config = f"{base}/{readiness.PRODUCTION_WORKFLOW}@{reference}"
    invocation = f"{base}/actions/runs/{workflow_run}/attempts/{workflow_attempt}"
    return [
        {
            "verificationResult": {
                "signature": {
                    "certificate": {
                        "issuer": readiness.ISSUER,
                        "subjectAlternativeName": signer,
                        "buildSignerURI": signer,
                        "buildSignerDigest": source_commit,
                        "sourceRepositoryURI": base,
                        "sourceRepositoryIdentifier": str(readiness.REPOSITORY_ID),
                        "sourceRepositoryOwnerIdentifier": str(readiness.OWNER_ID),
                        "sourceRepositoryDigest": source_commit,
                        "sourceRepositoryRef": reference,
                        "buildConfigURI": config,
                        "buildConfigDigest": source_commit,
                        "buildTrigger": "push",
                        "runnerEnvironment": "github-hosted",
                        "runInvocationURI": invocation,
                    }
                },
                "statement": {
                    "_type": "https://in-toto.io/Statement/v1",
                    "predicateType": "https://slsa.dev/provenance/v1",
                    "subject": [
                        {
                            "name": subject_name,
                            "digest": {"sha256": hashlib.sha256(body).hexdigest()},
                        }
                    ],
                    "predicate": {
                        "runDetails": {
                            "metadata": {
                                "invocationId": invocation,
                            }
                        }
                    },
                },
            }
        }
    ]


def _pack(tmp_path: Path, entries: list[tuple[str | zipfile.ZipInfo, bytes]]) -> Path:
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        for name, body in entries:
            archive.writestr(name, body)
    path = tmp_path / "receipt.zip"
    path.write_bytes(stream.getvalue())
    return path


def _metadata(path: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    artifact = {
        "id": 456,
        "name": f"systemd-matrix-verified-{RUN}-{ATTEMPT}",
        "expired": False,
        "size_in_bytes": path.stat().st_size,
        "digest": "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest(),
        "workflow_run": {
            "id": RUN,
            "head_sha": SOURCE,
            "head_branch": TAG,
            "repository_id": readiness.REPOSITORY_ID,
            "head_repository_id": readiness.REPOSITORY_ID,
        },
    }
    repository = {"id": readiness.REPOSITORY_ID, "full_name": readiness.REPOSITORY}
    run = {
        "id": RUN,
        "run_attempt": ATTEMPT,
        "head_sha": SOURCE,
        "head_branch": TAG,
        "event": "push",
        "path": readiness.PRODUCTION_WORKFLOW,
        "repository": dict(repository),
        "head_repository": dict(repository),
        "status": "in_progress",
        "conclusion": None,
    }
    return artifact, run


@pytest.fixture
def evidence(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    document = _document()
    body = readiness._canonical(document)
    path = _pack(
        tmp_path,
        [("systemd-matrix-verified.json", body), ("attestation.json", b'{"unitTestOnly":true}')],
    )
    artifact, run = _metadata(path)
    state: dict[str, Any] = {"verified": _verified(body), "calls": []}

    def cli(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        assert kwargs["stderr"] == subprocess.DEVNULL and kwargs["timeout"] == 120
        state["calls"].append(tuple(argv))
        if argv == ["gh", "--version"]:
            output = f"gh version {readiness.CLI_VERSION} (unit-test-only)\n".encode()
        else:
            assert argv[:3] == ["gh", "attestation", "verify"]
            output = json.dumps(state["verified"]).encode()
        return subprocess.CompletedProcess(argv, 0, output, b"")

    monkeypatch.setattr(readiness.subprocess, "run", cli)
    return {
        "kind": "native",
        "archive": path,
        "artifact": artifact,
        "run": run,
        "artifact_id": 456,
        "source_commit": SOURCE,
        "tag": TAG,
        "workflow_run": RUN,
        "workflow_attempt": ATTEMPT,
        "document": document,
        "body": body,
        "state": state,
    }


def _arguments(evidence: dict[str, Any]) -> dict[str, Any]:
    return {
        key: value for key, value in evidence.items() if key not in {"document", "body", "state"}
    }


def test_exact_native_archive_is_replayed_without_becoming_public(evidence: dict[str, Any]) -> None:
    result = readiness.verify_evidence_archive(**_arguments(evidence))
    assert result == evidence["document"] and result["publicReleaseEvidence"] is False
    argv = evidence["state"]["calls"][1]
    for flag, value in (
        ("--repo", readiness.REPOSITORY),
        ("--source-digest", SOURCE),
        ("--signer-digest", SOURCE),
        ("--source-ref", f"refs/tags/{TAG}"),
        ("--cert-oidc-issuer", readiness.ISSUER),
    ):
        assert argv[argv.index(flag) + 1] == value
    assert "--bundle" in argv and "--deny-self-hosted-runners" in argv


@pytest.mark.parametrize(
    ("target", "field", "value"),
    [
        ("run", "head_sha", "b" * 40),
        ("run", "event", "workflow_dispatch"),
        ("run", "path", ".github/workflows/other.yml"),
        ("run", "head_branch", "main"),
        ("run", "id", True),
        ("run", "run_attempt", 2),
        ("run", "conclusion", "failure"),
        ("artifact", "id", True),
        ("artifact", "expired", True),
        ("artifact", "name", "systemd-matrix-verified-123-2"),
        ("artifact", "digest", "sha256:" + "0" * 64),
        ("artifact", "size_in_bytes", True),
    ],
)
def test_api_identity_and_archive_substitutions_fail_before_crypto(
    evidence: dict[str, Any],
    target: str,
    field: str,
    value: Any,
) -> None:
    evidence[target][field] = value
    with pytest.raises(ValueError):
        readiness.verify_evidence_archive(**_arguments(evidence))
    assert evidence["state"]["calls"] == []


@pytest.mark.parametrize(
    "field",
    [
        "issuer",
        "subjectAlternativeName",
        "buildSignerURI",
        "buildSignerDigest",
        "sourceRepositoryURI",
        "sourceRepositoryIdentifier",
        "sourceRepositoryOwnerIdentifier",
        "sourceRepositoryDigest",
        "sourceRepositoryRef",
        "buildConfigURI",
        "buildConfigDigest",
        "buildTrigger",
        "runnerEnvironment",
        "runInvocationURI",
    ],
)
def test_oidc_identity_is_bound_in_the_certificate_not_user_predicate(
    evidence: dict[str, Any],
    field: str,
) -> None:
    certificate = evidence["state"]["verified"][0]["verificationResult"]["signature"]["certificate"]
    certificate[field] = "wrong-identity"
    with pytest.raises(ValueError, match="certificate identity"):
        readiness.verify_evidence_archive(**_arguments(evidence))


@pytest.mark.parametrize("change", ["empty", "subject", "predicate", "repo-id-type", "schema"])
def test_verified_output_requires_exact_subject_and_schema(
    evidence: dict[str, Any], change: str
) -> None:
    verified = evidence["state"]["verified"]
    if change == "empty":
        evidence["state"]["verified"] = []
    elif change == "subject":
        verified[0]["verificationResult"]["statement"]["subject"][0]["digest"]["sha256"] = "f" * 64
    elif change == "predicate":
        verified[0]["verificationResult"]["statement"]["predicateType"] = "untrusted"
    elif change == "repo-id-type":
        verified[0]["verificationResult"]["signature"]["certificate"][
            "sourceRepositoryIdentifier"
        ] = readiness.REPOSITORY_ID
    else:
        evidence["state"]["verified"] = [{}]
    with pytest.raises(ValueError):
        readiness.verify_evidence_archive(**_arguments(evidence))


@pytest.mark.parametrize(
    "mutation", ["missing-pair", "wrong-helper", "public-flag", "wrong-attempt"]
)
def test_signed_but_incomplete_or_relabelled_fixture_receipt_is_rejected(
    evidence: dict[str, Any],
    mutation: str,
) -> None:
    document = copy.deepcopy(evidence["document"])
    if mutation == "missing-pair":
        document["architectures"][0]["receipts"].pop()
    elif mutation == "wrong-helper":
        document["architectures"][0]["helpers"]["matrixSha"] = "0" * 64
    elif mutation == "public-flag":
        document["publicReleaseEvidence"] = True
    else:
        document["workflowAttempt"] = 2
    body = readiness._canonical(document)
    path = _pack(
        evidence["archive"].parent,
        [("systemd-matrix-verified.json", body), ("attestation.json", b"{}")],
    )
    evidence["artifact"], _ = _metadata(path)
    evidence["state"]["verified"] = _verified(body)
    with pytest.raises((ValueError, RuntimeError)):
        readiness.verify_evidence_archive(**_arguments(evidence))


@pytest.mark.parametrize(
    "unsafe", ["duplicate", "traversal", "symlink", "fifo", "extra", "json-duplicate", "nan"]
)
def test_evidence_archive_rejects_unsafe_members_before_sigstore(
    evidence: dict[str, Any],
    unsafe: str,
) -> None:
    body = evidence["body"]
    entries: list[tuple[str | zipfile.ZipInfo, bytes]] = [
        ("systemd-matrix-verified.json", body),
        ("attestation.json", b"{}"),
    ]
    if unsafe == "duplicate":
        entries.append(entries[0])
    elif unsafe == "traversal":
        entries[0] = ("../systemd-matrix-verified.json", body)
    elif unsafe in {"symlink", "fifo"}:
        entry = zipfile.ZipInfo("systemd-matrix-verified.json")
        entry.create_system = 3
        entry.external_attr = (
            (stat.S_IFLNK if unsafe == "symlink" else stat.S_IFIFO) | 0o600
        ) << 16
        entries[0] = (entry, body)
    elif unsafe == "extra":
        entries.append(("private.pem", b"not-a-key"))
    elif unsafe == "json-duplicate":
        entries[0] = ("systemd-matrix-verified.json", b'{"status":"failed","status":"passed"}')
    else:
        entries[0] = ("systemd-matrix-verified.json", b'{"untrusted":NaN}')
    path = _pack(evidence["archive"].parent, entries)
    evidence["artifact"], _ = _metadata(path)
    with pytest.raises(ValueError):
        readiness.verify_evidence_archive(**_arguments(evidence))
    assert evidence["state"]["calls"] == []


def test_unavailable_or_failed_crypto_has_no_metadata_only_fallback(
    evidence: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def failed(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        return subprocess.CompletedProcess(argv, 1, b"", b"untrusted diagnostic")

    monkeypatch.setattr(readiness.subprocess, "run", failed)
    with pytest.raises(ValueError, match="cryptographic"):
        readiness.verify_evidence_archive(**_arguments(evidence))


def test_optional_expected_subject_digest_cannot_be_ignored(evidence: dict[str, Any]) -> None:
    with pytest.raises(ValueError, match="subject digest"):
        readiness.verify_evidence_archive(**_arguments(evidence), evidence_sha256="0" * 64)
    assert evidence["state"]["calls"] == []


def test_bundle_redirect_drops_auth_and_rejects_untrusted_hosts() -> None:
    handler = readiness._EvidenceRedirect()
    request = urllib.request.Request(
        "https://api.github.com/repos/kgmnotes/xferry/actions/artifacts/1/zip",
        headers={"Authorization": "Bearer unit-test-only"},
    )
    redirected = handler.redirect_request(
        request,
        None,
        302,
        "Found",
        {},
        "https://example.blob.core.windows.net/evidence.zip?sig=unit-only",
    )
    assert redirected is not None and not redirected.has_header("Authorization")
    for target in (
        "http://example.blob.core.windows.net/a",
        "https://evil.example/a",
        "https://api.github.com@evil.example/a",
        "https://api.github.com:444/a",
    ):
        with pytest.raises(ValueError):
            handler.redirect_request(request, None, 302, "Found", {}, target)


@pytest.mark.parametrize("mutation", [None, "plan-hash", "wrong-target", "fixture-substitution"])
def test_public_archive_binds_signed_public_plan_and_full_ten_pair_receipt(
    evidence: dict[str, Any],
    signed: Any,
    mutation: str | None,
) -> None:
    plan, _, _ = signed
    result = _public_result(plan)
    if mutation == "plan-hash":
        result["planSha256"] = "0" * 64
    elif mutation == "wrong-target":
        result["targetTag"] = "v0.3.0"
    elif mutation == "fixture-substitution":
        result = evidence["document"]
    body = readiness._canonical(result)
    path = _pack(
        evidence["archive"].parent,
        [
            ("managed-public-verified.json", body),
            ("managed-public-plan.json", readiness._canonical(plan)),
            ("attestation.json", b"{}"),
        ],
    )
    artifact, run = _metadata(path)
    source, workflow_run, attempt = (
        plan["sourceCommit"],
        int(plan["workflowRun"]),
        plan["workflowAttempt"],
    )
    artifact["name"] = f"managed-public-verified-{workflow_run}-{attempt}"
    artifact["workflow_run"].update(id=workflow_run, head_sha=source)
    run.update(id=workflow_run, head_sha=source, run_attempt=attempt)
    evidence["state"]["verified"] = _verified(
        body,
        source_commit=source,
        workflow_run=workflow_run,
        workflow_attempt=attempt,
        signer_name="managed-public-matrix.yml",
        subject_name="managed-public-verified.json",
    )
    arguments = {
        "kind": "public",
        "artifact": artifact,
        "run": run,
        "archive": path,
        "artifact_id": 456,
        "source_commit": source,
        "tag": TAG,
        "workflow_run": workflow_run,
        "workflow_attempt": attempt,
    }
    if mutation is None:
        accepted = readiness.verify_evidence_archive(**arguments)
        assert accepted == result and accepted["publicReleaseEvidence"] is True
    else:
        with pytest.raises(ValueError, match="lifecycle receipt"):
            readiness.verify_evidence_archive(**arguments)


@pytest.mark.parametrize("payload", [b"not JSON", b"[]", b"null", b'{"id":1,"id":2}'])
def test_cli_metadata_errors_are_fixed_json_without_tracebacks(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    payload: bytes,
) -> None:
    artifact = tmp_path / "artifact.json"
    run = tmp_path / "run.json"
    artifact.write_bytes(payload)
    run.write_bytes(b"{}")
    result = readiness.main(
        [
            "verify-native",
            "--artifact-metadata",
            str(artifact),
            "--run-metadata",
            str(run),
            "--archive",
            str(tmp_path / "missing.zip"),
            "--output",
            str(tmp_path / "out.json"),
            "--artifact-id",
            "456",
            "--workflow-run",
            str(RUN),
            "--workflow-attempt",
            str(ATTEMPT),
            "--source-commit",
            SOURCE,
            "--tag",
            TAG,
            "--evidence-sha256",
            "0" * 64,
        ]
    )
    captured = capsys.readouterr()
    assert result == 1 and captured.err == ""
    assert json.loads(captured.out) == {"status": "failed", "code": "managed_evidence_invalid"}
