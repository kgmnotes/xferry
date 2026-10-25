"""Authenticate immutable native/public managed evidence before release or Pages.

Artifact metadata is not a signature. Every accepted receipt is also verified by
the pinned GitHub CLI against GitHub's Sigstore trust roots and an exact OIDC
certificate identity. Prepublication fixtures never become public evidence.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import re
import stat
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from collections.abc import Mapping, Sequence
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any, NoReturn

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tools.check_release_preflight import version_from_tag  # noqa: E402
from tools.install_attestation_cli import VERSION as CLI_VERSION  # noqa: E402

REPOSITORY = "kgmnotes/xferry"
REPOSITORY_ID = 1341230685
OWNER_ID = 316200733
PRODUCTION_WORKFLOW = ".github/workflows/release-production.yml"
ISSUER = "https://token.actions.githubusercontent.com"
MAX_ARCHIVE_BYTES = 16 * 1024 * 1024
MAX_JSON_BYTES = 4 * 1024 * 1024
_SHA = re.compile(r"[0-9a-f]{64}\Z")
_COMMIT = re.compile(r"[0-9a-f]{40}\Z")
_EVIDENCE = {
    "native": (
        "systemd-matrix-verified",
        "systemd-matrix-verified.json",
        ".github/workflows/managed-systemd-matrix.yml",
    ),
    "public": (
        "managed-public-verified",
        "managed-public-verified.json",
        ".github/workflows/managed-public-matrix.yml",
    ),
}


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def _positive(value: object) -> bool:
    return type(value) is int and value > 0


def _pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in items:
        _require(key not in result, "duplicate evidence JSON key")
        result[key] = value
    return result


def _invalid_constant(_value: str) -> NoReturn:
    raise ValueError("non-finite evidence JSON value")


def _json(payload: bytes) -> Any:
    _require(0 < len(payload) <= MAX_JSON_BYTES, "evidence JSON exceeds its bound")
    return json.loads(payload, object_pairs_hook=_pairs, parse_constant=_invalid_constant)


def _regular(path: Path, limit: int) -> bytes:
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, "rb") as stream:
            metadata = os.fstat(stream.fileno())
            _require(
                stat.S_ISREG(metadata.st_mode) and metadata.st_size <= limit,
                "evidence must be a bounded regular file",
            )
            payload = stream.read(limit + 1)
        _require(len(payload) <= limit, "evidence exceeds its bound")
        return payload
    except (OSError, ValueError):
        raise ValueError("evidence must be a bounded regular file") from None


def _canonical(document: object) -> bytes:
    return (json.dumps(document, sort_keys=True, indent=2, allow_nan=False) + "\n").encode()


def _write(path: Path, document: object) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(_canonical(document))


def _identity(
    kind: str,
    artifact: Mapping[str, Any],
    run: Mapping[str, Any],
    *,
    artifact_id: int,
    source_commit: str,
    tag: str,
    workflow_run: int,
    workflow_attempt: int,
) -> tuple[str, str]:
    _require(kind in _EVIDENCE, "unknown managed evidence phase")
    _require(
        isinstance(artifact, Mapping) and isinstance(run, Mapping),
        "evidence API metadata must be objects",
    )
    version_from_tag(tag)
    _require(
        isinstance(source_commit, str) and _COMMIT.fullmatch(source_commit) is not None,
        "invalid evidence source commit",
    )
    _require(
        all(_positive(value) for value in (artifact_id, workflow_run, workflow_attempt)),
        "invalid evidence numeric identity",
    )
    for field in ("repository", "head_repository"):
        repository = run.get(field)
        _require(
            isinstance(repository, Mapping)
            and type(repository.get("id")) is int
            and repository["id"] == REPOSITORY_ID
            and repository.get("full_name") == REPOSITORY,
            "evidence repository mismatch",
        )
    _require(
        type(run.get("id")) is int
        and run["id"] == workflow_run
        and type(run.get("run_attempt")) is int
        and run["run_attempt"] == workflow_attempt
        and run.get("head_sha") == source_commit
        and run.get("head_branch") in (None, tag)
        and run.get("event") == "push"
        and run.get("path") == PRODUCTION_WORKFLOW
        and (
            (run.get("status") == "in_progress" and run.get("conclusion") is None)
            or (run.get("status") == "completed" and run.get("conclusion") == "success")
        ),
        "evidence production run mismatch",
    )
    prefix, subject, signer = _EVIDENCE[kind]
    producer = artifact.get("workflow_run")
    digest = artifact.get("digest")
    _require(
        type(artifact.get("id")) is int
        and artifact["id"] == artifact_id
        and artifact.get("name") == f"{prefix}-{workflow_run}-{workflow_attempt}"
        and artifact.get("expired") is False
        and _positive(artifact.get("size_in_bytes"))
        and artifact["size_in_bytes"] <= MAX_ARCHIVE_BYTES
        and isinstance(digest, str)
        and digest.startswith("sha256:")
        and _SHA.fullmatch(digest.removeprefix("sha256:")) is not None
        and isinstance(producer, Mapping)
        and type(producer.get("id")) is int
        and producer["id"] == workflow_run
        and producer.get("head_sha") == source_commit
        and producer.get("head_branch") in (None, tag)
        and type(producer.get("repository_id")) is int
        and producer["repository_id"] == REPOSITORY_ID
        and type(producer.get("head_repository_id")) is int
        and producer["head_repository_id"] == REPOSITORY_ID,
        "immutable evidence artifact mismatch",
    )
    return subject, signer


def _unpack(payload: bytes, *, expected: set[str], destination: Path) -> dict[str, Any]:
    documents: dict[str, Any] = {}
    try:
        with zipfile.ZipFile(io.BytesIO(payload)) as archive:
            entries = archive.infolist()
            _require(
                len(entries) == len(expected) and {item.filename for item in entries} == expected,
                "unexpected or duplicate evidence archive members",
            )
            for item in entries:
                mode = stat.S_IFMT(item.external_attr >> 16)
                _require(
                    not item.is_dir()
                    and not item.flag_bits & 1
                    and mode in (0, stat.S_IFREG)
                    and item.file_size <= MAX_JSON_BYTES,
                    "unsafe evidence archive member",
                )
                body = archive.read(item)
                _require(len(body) == item.file_size, "evidence member size mismatch")
                documents[item.filename] = _json(body)
                with (destination / item.filename).open("xb") as stream:
                    stream.write(body)
    except (zipfile.BadZipFile, OSError, RuntimeError):
        raise ValueError("invalid evidence archive") from None
    return documents


def _cli(argv: Sequence[str]) -> bytes:
    try:
        result = subprocess.run(
            list(argv), check=False, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=120
        )
        _require(
            result.returncode == 0 and len(result.stdout) <= MAX_JSON_BYTES,
            "cryptographic attestation verification failed",
        )
        return result.stdout
    except (OSError, subprocess.TimeoutExpired):
        raise ValueError("cryptographic attestation verifier unavailable") from None


def _verify_attestation(
    subject: Path,
    bundle: Path,
    *,
    signer: str,
    source_commit: str,
    tag: str,
    workflow_run: int,
    workflow_attempt: int,
) -> None:
    version = _cli(("gh", "--version"))
    _require(
        re.match(rb"gh version " + re.escape(CLI_VERSION.encode()) + rb"(?:\s|$)", version)
        is not None,
        "pinned GitHub attestation CLI required",
    )
    reference = f"refs/tags/{tag}"
    verified = _json(
        _cli(
            (
                "gh",
                "attestation",
                "verify",
                str(subject),
                "--bundle",
                str(bundle),
                "--repo",
                REPOSITORY,
                "--signer-workflow",
                f"{REPOSITORY}/{signer}",
                "--signer-digest",
                source_commit,
                "--source-digest",
                source_commit,
                "--source-ref",
                reference,
                "--deny-self-hosted-runners",
                "--cert-oidc-issuer",
                ISSUER,
                "--format",
                "json",
            )
        )
    )
    _require(isinstance(verified, list) and 0 < len(verified) <= 16, "missing verified attestation")
    expected_signer = f"https://github.com/{REPOSITORY}/{signer}@{reference}"
    expected_config = f"https://github.com/{REPOSITORY}/{PRODUCTION_WORKFLOW}@{reference}"
    invocation = (
        f"https://github.com/{REPOSITORY}/actions/runs/{workflow_run}/attempts/{workflow_attempt}"
    )
    digest = hashlib.sha256(_regular(subject, MAX_JSON_BYTES)).hexdigest()
    for entry in verified:
        try:
            result = entry["verificationResult"]
            certificate = result["signature"]["certificate"]
            statement = result["statement"]
            expected = {
                "issuer": ISSUER,
                "subjectAlternativeName": expected_signer,
                "buildSignerURI": expected_signer,
                "buildSignerDigest": source_commit,
                "sourceRepositoryURI": f"https://github.com/{REPOSITORY}",
                "sourceRepositoryIdentifier": str(REPOSITORY_ID),
                "sourceRepositoryOwnerIdentifier": str(OWNER_ID),
                "sourceRepositoryDigest": source_commit,
                "sourceRepositoryRef": reference,
                "buildConfigURI": expected_config,
                "buildConfigDigest": source_commit,
                "buildTrigger": "push",
                "runnerEnvironment": "github-hosted",
                "runInvocationURI": invocation,
            }
            _require(
                all(
                    type(certificate.get(key)) is str and certificate[key] == value
                    for key, value in expected.items()
                ),
                "attestation certificate identity mismatch",
            )
            _require(
                statement.get("_type") == "https://in-toto.io/Statement/v1"
                and statement.get("predicateType") == "https://slsa.dev/provenance/v1"
                and statement.get("subject")
                == [{"name": subject.name, "digest": {"sha256": digest}}],
                "attested subject mismatch",
            )
        except (KeyError, TypeError, AttributeError):
            raise ValueError("invalid verified attestation schema") from None


def _native(
    document: Any, root: Path, *, source_commit: str, workflow_run: int, workflow_attempt: int
) -> dict[str, Any]:
    from tools.managed_systemd_matrix import verify_matrix

    _require(
        isinstance(document, dict)
        and isinstance(document.get("architectures"), list)
        and len(document["architectures"]) == 2,
        "incomplete native managed evidence",
    )
    inputs = root / "native"
    inputs.mkdir()
    for index, architecture in enumerate(document["architectures"]):
        directory = inputs / str(index)
        directory.mkdir()
        _write(directory / "architecture.json", architecture)
    replayed = verify_matrix(
        evidence_root=inputs,
        source_commit=source_commit,
        workflow_run=str(workflow_run),
        workflow_attempt=workflow_attempt,
        output=root / "replayed.json",
    )
    _require(
        _canonical(replayed) == _canonical(document), "native managed evidence differs from replay"
    )
    return dict(replayed)


def verify_evidence_archive(
    *,
    kind: str,
    artifact: Mapping[str, Any],
    run: Mapping[str, Any],
    archive: Path,
    artifact_id: int,
    source_commit: str,
    tag: str,
    workflow_run: int,
    workflow_attempt: int,
    evidence_sha256: str | None = None,
    output: Path | None = None,
) -> dict[str, Any]:
    """Verify API binding, exact ZIP bytes, OIDC signature and the full receipt.

    Returned native evidence deliberately has publicReleaseEvidence=False. Only
    the public phase verifies two public versions and can satisfy final/Pages.
    """
    subject, signer = _identity(
        kind,
        artifact,
        run,
        artifact_id=artifact_id,
        source_commit=source_commit,
        tag=tag,
        workflow_run=workflow_run,
        workflow_attempt=workflow_attempt,
    )
    payload = _regular(archive, MAX_ARCHIVE_BYTES)
    _require(
        len(payload) == artifact["size_in_bytes"]
        and "sha256:" + hashlib.sha256(payload).hexdigest() == artifact["digest"],
        "evidence archive digest or size mismatch",
    )
    expected = {subject, "attestation.json"}
    if kind == "public":
        expected.add("managed-public-plan.json")
    with TemporaryDirectory(prefix="xferry-managed-evidence-") as temporary:
        root = Path(temporary)
        documents = _unpack(payload, expected=expected, destination=root)
        actual_sha = hashlib.sha256(_regular(root / subject, MAX_JSON_BYTES)).hexdigest()
        if evidence_sha256 is not None:
            _require(
                isinstance(evidence_sha256, str)
                and _SHA.fullmatch(evidence_sha256) is not None
                and evidence_sha256 == actual_sha,
                "managed evidence subject digest mismatch",
            )
        _verify_attestation(
            root / subject,
            root / "attestation.json",
            signer=signer,
            source_commit=source_commit,
            tag=tag,
            workflow_run=workflow_run,
            workflow_attempt=workflow_attempt,
        )
        try:
            if kind == "native":
                result = _native(
                    documents[subject],
                    root,
                    source_commit=source_commit,
                    workflow_run=workflow_run,
                    workflow_attempt=workflow_attempt,
                )
            else:
                from tools.managed_public_matrix import validate_public_result

                result = validate_public_result(
                    documents[subject],
                    plan=documents["managed-public-plan.json"],
                    source_commit=source_commit,
                    workflow_run=str(workflow_run),
                    workflow_attempt=workflow_attempt,
                )
                _require(
                    result.get("targetTag") == tag and result.get("publicReleaseEvidence") is True,
                    "public managed target identity mismatch",
                )
        except Exception:
            raise ValueError("managed lifecycle receipt validation failed") from None
    if output is not None:
        _write(output, result)
    return result


def _download_url(url: str) -> urllib.parse.SplitResult:
    parsed = urllib.parse.urlsplit(url)
    hostname = parsed.hostname or ""
    allowed = hostname == "api.github.com" or any(
        hostname.endswith(suffix)
        for suffix in (
            ".blob.core.windows.net",
            ".actions.githubusercontent.com",
            ".githubusercontent.com",
        )
    )
    _require(
        parsed.scheme == "https"
        and allowed
        and parsed.port in (None, 443)
        and parsed.username is None
        and parsed.password is None
        and not parsed.fragment
        and not any(character in url for character in ("\\", "\r", "\n")),
        "unsafe evidence download URL",
    )
    return parsed


class _EvidenceRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self, req: urllib.request.Request, fp: Any, code: int, msg: str, headers: Any, newurl: str
    ) -> urllib.request.Request | None:
        target = _download_url(newurl)
        redirected = super().redirect_request(req, fp, code, msg, headers, newurl)
        if redirected is not None and target.hostname != "api.github.com":
            redirected.remove_header("Authorization")
        return redirected


def download_evidence_archive(artifact_id: int, path: Path, *, token: str | None = None) -> None:
    """Narrow authenticated API ZIP transport, separate from anonymous consumers."""
    _require(_positive(artifact_id), "invalid evidence artifact id")
    selected_token = (
        token
        if token is not None
        else os.environ.get("GH_TOKEN", os.environ.get("GITHUB_TOKEN", ""))
    )
    _require(
        bool(selected_token) and not any(c in selected_token for c in "\r\n"),
        "GitHub evidence API authentication required",
    )
    url = f"https://api.github.com/repos/{REPOSITORY}/actions/artifacts/{artifact_id}/zip"
    request = urllib.request.Request(
        url,
        headers={
            "Authorization": f"Bearer {selected_token}",
            "Accept": "application/vnd.github+json",
            "User-Agent": "xferry-managed-evidence",
        },
    )
    opener = urllib.request.build_opener(_EvidenceRedirect())
    try:
        with opener.open(request, timeout=30) as response, path.open("xb") as stream:
            _require(response.status == 200, "evidence download failed")
            count = 0
            while chunk := response.read(min(1024 * 1024, MAX_ARCHIVE_BYTES - count + 1)):
                count += len(chunk)
                _require(count <= MAX_ARCHIVE_BYTES, "evidence download exceeds its bound")
                stream.write(chunk)
    except (urllib.error.URLError, OSError):
        # Never expose a redirect SAS URL, API credential or transport exception.
        raise ValueError("evidence archive transport failed") from None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("verify-native", "verify-public"))
    for name in ("artifact-metadata", "run-metadata", "archive", "output"):
        parser.add_argument(f"--{name}", type=Path, required=True)
    for name in ("artifact-id", "workflow-run", "workflow-attempt"):
        parser.add_argument(f"--{name}", type=int, required=True)
    for name in ("source-commit", "tag", "evidence-sha256"):
        parser.add_argument(f"--{name}", required=True)
    options = vars(parser.parse_args(argv))
    command = options.pop("command")
    try:
        options["artifact"] = _json(_regular(options.pop("artifact_metadata"), MAX_JSON_BYTES))
        options["run"] = _json(_regular(options.pop("run_metadata"), MAX_JSON_BYTES))
        result = verify_evidence_archive(kind=command.removeprefix("verify-"), **options)
        print(
            json.dumps(
                {
                    "status": "passed",
                    "scope": result["scope"],
                    "publicReleaseEvidence": result["publicReleaseEvidence"],
                }
            )
        )
        return 0
    except (ValueError, OSError):
        print(json.dumps({"status": "failed", "code": "managed_evidence_invalid"}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
