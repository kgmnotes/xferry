"""Permit Pages only after an accepted production run and verified public channels."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Mapping, Sequence
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any, NoReturn

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tools import github_release_assets, production_readiness  # noqa: E402
from tools.candidate_inventory import unpack_candidate, verify_inventory  # noqa: E402
from tools.check_release_preflight import (  # noqa: E402
    _source_version,
    check_source,
    version_from_tag,
)
from tools.ghcr_publish import summarize_oci_layout  # noqa: E402
from tools.production_release_state import (  # noqa: E402
    APIResponse,
    GitHubReleaseAPI,
    ReleaseAPI,
    _next_page,
)
from xferry.management.release_contract import (  # noqa: E402
    MAX_MANIFEST_BYTES,
    MAX_SIGNATURE_BYTES,
    SUPPORTED_PLATFORM_IDS,
    release_manifest_asset_name,
)
from xferry.management.release_trust import (  # noqa: E402
    DEFAULT_RELEASE_KEY_RING,
    ReleaseKeyRing,
    verify_signed_manifest,
)

REPOSITORY = "kgmnotes/xferry"
WORKFLOW_PATH = ".github/workflows/release-production.yml"
MAX_JSON_BYTES = 16 * 1024 * 1024
MAX_ASSET_BYTES = 2 * 1024 * 1024 * 1024
MAX_TOTAL_ASSET_BYTES = 8 * 1024 * 1024 * 1024
MAX_PAGES = 1_000
PAGE_SIZE = 100
_COMMIT_RE = re.compile(r"[0-9a-f]{40}\Z")
_SHA_RE = re.compile(r"[0-9a-f]{64}\Z")
_INDEX_TYPES = {
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
}
_MANIFEST_TYPES = {
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
}
_PUBLIC_HOSTS = {
    "api.github.com",
    "github.com",
    "release-assets.githubusercontent.com",
    "objects.githubusercontent.com",
    "pypi.org",
    "files.pythonhosted.org",
    "ghcr.io",
}
_DOCS_FILES = {
    "README.md",
    "API.md",
    "SECURITY.md",
    "CHANGELOG.md",
    "CONTRIBUTING.md",
    "mkdocs.yml",
}
REQUIRED_JOBS = frozenset(
    {
        "preflight",
        "prepare-candidate",
        "production-readiness",
        "sign-assets",
        "create-draft-release",
        "publish-pypi",
        "publish-ghcr",
        "publish-github-release",
        "verify-pypi-identity",
        "post-release",
        "final-gate",
        "post-managed / Prepare immutable public managed plan",
        "post-managed / Public managed lifecycle (linux-x86_64, native)",
        "post-managed / Public managed lifecycle (linux-aarch64, native)",
        "post-managed / Verify and attest public managed matrix",
    }
    | {
        f"Public pipx ({os_name}, Python {version})"
        for os_name in ("ubuntu-latest", "macos-15", "windows-latest")
        for version in ("3.10", "3.12", "3.14")
    }
    | {f"Public GHCR ({arch}, native)" for arch in ("amd64", "arm64")}
)


def _positive_id(value: object, label: str) -> int:
    if type(value) is not int or value <= 0:
        raise ValueError(f"{label} must be a positive integer")
    return value


def _duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate public metadata JSON key")
        result[key] = value
    return result


def _invalid_constant(_value: str) -> NoReturn:
    raise ValueError("non-finite public metadata JSON value")


def _json(payload: bytes) -> dict[str, Any]:
    if not 0 < len(payload) <= MAX_JSON_BYTES:
        raise ValueError("public JSON metadata exceeds its size bound")
    document = json.loads(
        payload,
        object_pairs_hook=_duplicate_keys,
        parse_constant=_invalid_constant,
    )
    if not isinstance(document, dict):
        raise ValueError("public JSON metadata must be an object")
    return document


def _public_url(url: str) -> urllib.parse.SplitResult:
    parsed = urllib.parse.urlsplit(url)
    if (
        parsed.scheme != "https"
        or parsed.hostname not in _PUBLIC_HOSTS
        or parsed.username is not None
        or parsed.password is not None
        or parsed.port not in (None, 443)
        or parsed.fragment
        or any(character in url for character in ("\\", "\r", "\n"))
    ):
        raise ValueError("public download URL must use an allowed HTTPS host")
    return parsed


class _HTTPSRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> urllib.request.Request | None:
        target = _public_url(newurl)
        if (
            req.has_header("Authorization")
            and target.hostname != urllib.parse.urlsplit(req.full_url).hostname
        ):
            raise ValueError("anonymous registry token must not cross hosts")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class PublicHTTP:
    """Anonymous HTTPS only; the only permitted token is GHCR's anonymous pull token."""

    def __init__(self) -> None:
        self._opener = urllib.request.build_opener(_HTTPSRedirect())

    def _open(self, url: str, headers: Mapping[str, str] | None = None) -> Any:
        parsed = _public_url(url)
        selected = dict(headers or {})
        if any(key.lower() == "authorization" for key in selected) and parsed.hostname != "ghcr.io":
            raise ValueError("public channel downloads must not use GitHub authentication")
        request = urllib.request.Request(
            url,
            headers={"User-Agent": "xferry-publication-gate", **selected},
        )
        try:
            return self._opener.open(request, timeout=30)
        except urllib.error.HTTPError as error:
            raise ValueError(f"public channel unavailable (HTTP {error.code})") from None
        except urllib.error.URLError:
            raise ValueError("public channel unavailable (transport failure)") from None

    def get(self, url: str, headers: Mapping[str, str] | None = None) -> tuple[bytes, str | None]:
        with self._open(url, headers) as response:
            if response.status != 200:
                raise ValueError("public metadata did not return HTTP 200")
            raw = response.read(MAX_JSON_BYTES + 1)
            link = response.headers.get("Link")
        if len(raw) > MAX_JSON_BYTES:
            raise ValueError("public metadata exceeds its size bound")
        return raw, link

    def download(self, url: str, path: Path, *, size: int, sha256: str | None = None) -> None:
        if type(size) is not int or not 0 < size <= MAX_ASSET_BYTES:
            raise ValueError("public asset size is outside its bound")
        digest = hashlib.sha256()
        count = 0
        with self._open(url) as response, path.open("xb") as output:
            if response.status != 200:
                raise ValueError("public asset did not return HTTP 200")
            while chunk := response.read(min(1024 * 1024, size - count + 1)):
                count += len(chunk)
                if count > size:
                    raise ValueError("public asset exceeds its declared size")
                digest.update(chunk)
                output.write(chunk)
        if count != size or (sha256 is not None and digest.hexdigest() != sha256):
            raise ValueError("public asset size or SHA256 differs from signed records")


class AnonymousGitHubAPI:
    def __init__(self, public: PublicHTTP) -> None:
        self._public = public

    def request(
        self,
        method: str,
        endpoint: str,
        payload: Mapping[str, object] | None = None,
    ) -> APIResponse:
        if (
            method != "GET"
            or payload is not None
            or not endpoint.startswith(f"repos/{REPOSITORY}/")
        ):
            raise ValueError("anonymous GitHub metadata must be read-only and repository-scoped")
        raw, link = self._public.get(
            f"https://api.github.com/{endpoint}",
            {"Accept": "application/vnd.github+json"},
        )
        document = json.loads(
            raw,
            object_pairs_hook=_duplicate_keys,
            parse_constant=_invalid_constant,
        )
        return APIResponse(document, link)


def verify_production_run(
    api: ReleaseAPI,
    production_run: int,
    *,
    expected_tag: str | None = None,
) -> dict[str, Any]:
    _positive_id(production_run, "production run")
    run = api.request("GET", f"repos/{REPOSITORY}/actions/runs/{production_run}").document
    if not isinstance(run, dict):
        raise ValueError("production run metadata must be an object")
    repository, head_repository, tag = (
        run.get("repository"),
        run.get("head_repository"),
        run.get("head_branch"),
    )
    if expected_tag is not None:
        version_from_tag(expected_tag)
        if tag is not None and tag != expected_tag:
            raise ValueError("production run tag differs from the documentation source version")
        tag = expected_tag
    if not isinstance(tag, str):
        raise ValueError(
            "production run must identify its tag or use a source-derived expected tag"
        )
    version_from_tag(tag)
    if (
        run.get("id") != production_run
        or run.get("path") != WORKFLOW_PATH
        or run.get("event") != "push"
        or run.get("status") != "completed"
        or run.get("conclusion") != "success"
        or not isinstance(run.get("head_sha"), str)
        or _COMMIT_RE.fullmatch(run["head_sha"]) is None
        or not isinstance(repository, dict)
        or repository.get("full_name") != REPOSITORY
        or not isinstance(head_repository, dict)
        or head_repository.get("full_name") != REPOSITORY
        or repository.get("id") != head_repository.get("id")
    ):
        raise ValueError("production run is not an exact successful production repository tag run")
    _positive_id(run.get("id"), "production run ID")
    _positive_id(repository.get("id"), "production repository ID")
    attempt = _positive_id(run.get("run_attempt"), "production run attempt")
    endpoint = f"repos/{REPOSITORY}/actions/runs/{production_run}/attempts/{attempt}/jobs"
    jobs: list[dict[str, Any]] = []
    total: int | None = None
    for page in range(1, MAX_PAGES + 1):
        response = api.request("GET", f"{endpoint}?per_page={PAGE_SIZE}&page={page}")
        document = response.document
        if not isinstance(document, dict) or not isinstance(document.get("jobs"), list):
            raise ValueError("production jobs pagination metadata is invalid")
        page_total = document.get("total_count")
        if (
            type(page_total) is not int
            or page_total < 0
            or (total is not None and total != page_total)
        ):
            raise ValueError("production jobs pagination total is invalid or changed")
        total = page_total
        batch = document["jobs"]
        if len(batch) > PAGE_SIZE or any(not isinstance(job, dict) for job in batch):
            raise ValueError("production jobs pagination page is invalid")
        has_next = _next_page(response.link, endpoint, page)
        if has_next and len(batch) != PAGE_SIZE:
            raise ValueError("production jobs pagination has a truncated page")
        jobs.extend(batch)
        if not has_next and len(batch) < PAGE_SIZE:
            break
    else:
        raise ValueError("production jobs pagination exceeds its bound")
    if total != len(jobs):
        raise ValueError("production jobs pagination omitted jobs")
    seen_ids: set[int] = set()
    required: set[str] = set()
    for job in jobs:
        job_id = _positive_id(job.get("id"), "production job ID")
        if (
            job_id in seen_ids
            or job.get("run_id") != production_run
            or job.get("run_attempt") != attempt
            or job.get("head_sha") != run["head_sha"]
        ):
            raise ValueError("production job belongs to a duplicate or different run attempt")
        seen_ids.add(job_id)
        name = job.get("name")
        if not isinstance(name, str):
            raise ValueError("production job name is invalid")
        if name in REQUIRED_JOBS:
            if (
                name in required
                or job.get("status") != "completed"
                or job.get("conclusion") != "success"
            ):
                raise ValueError("required consumer or final gate did not succeed exactly once")
            required.add(name)
    if required != REQUIRED_JOBS:
        raise ValueError("required production consumer or final gate jobs are missing")
    return {**run, "head_branch": tag}


def verify_public_managed_evidence(
    api: ReleaseAPI,
    run: Mapping[str, Any],
    destination: Path,
    *,
    tag: str,
) -> dict[str, object]:
    """Require this completed attempt's immutable, OIDC-authenticated public matrix.

    Artifact transport is separate from the anonymous public-channel client;
    GitHub API authentication must never be added to that client's host policy.
    """
    version_from_tag(tag)
    if run.get("status") != "completed" or run.get("conclusion") != "success":
        raise ValueError("Pages requires a completed successful public managed production run")
    run_id = _positive_id(run.get("id"), "managed production run")
    attempt = _positive_id(run.get("run_attempt"), "managed production attempt")
    expected_name = f"managed-public-verified-{run_id}-{attempt}"
    endpoint = f"repos/{REPOSITORY}/actions/runs/{run_id}/artifacts"
    selected: list[dict[str, Any]] = []
    seen: set[int] = set()
    total: int | None = None
    for page in range(1, MAX_PAGES + 1):
        response = api.request("GET", f"{endpoint}?per_page={PAGE_SIZE}&page={page}")
        document = response.document
        if not isinstance(document, dict) or not isinstance(document.get("artifacts"), list):
            raise ValueError("managed evidence artifacts pagination metadata is invalid")
        page_total = document.get("total_count")
        if (
            type(page_total) is not int
            or not 0 <= page_total <= MAX_PAGES * PAGE_SIZE
            or (total is not None and total != page_total)
        ):
            raise ValueError("managed evidence artifacts pagination total is invalid or changed")
        total = page_total
        batch = document["artifacts"]
        if len(batch) > PAGE_SIZE or any(not isinstance(item, dict) for item in batch):
            raise ValueError("managed evidence artifacts pagination page is invalid")
        has_next = _next_page(response.link, endpoint, page)
        if has_next and len(batch) != PAGE_SIZE:
            raise ValueError("managed evidence artifacts pagination has a truncated page")
        for artifact in batch:
            artifact_id = _positive_id(artifact.get("id"), "managed evidence artifact ID")
            if artifact_id in seen:
                raise ValueError("managed evidence artifacts pagination duplicated an artifact")
            seen.add(artifact_id)
            if artifact.get("name") == expected_name:
                selected.append(artifact)
        if not has_next and len(batch) < PAGE_SIZE:
            break
    else:
        raise ValueError("managed evidence artifacts pagination exceeds its bound")
    if total != len(seen):
        raise ValueError("managed evidence artifacts pagination omitted artifacts")
    if len(selected) != 1:
        raise ValueError("this production attempt must have exactly one public managed artifact")

    artifact_id = _positive_id(selected[0].get("id"), "managed evidence artifact ID")
    artifact = api.request("GET", f"repos/{REPOSITORY}/actions/artifacts/{artifact_id}").document
    identity_fields = ("id", "name", "digest", "size_in_bytes", "expired")
    if not isinstance(artifact, dict) or any(
        artifact.get(field) != selected[0].get(field) for field in identity_fields
    ):
        raise ValueError("managed evidence artifact identity changed before download")
    digest, size = artifact.get("digest"), artifact.get("size_in_bytes")
    producer = artifact.get("workflow_run")
    repository = run.get("repository")
    if (
        artifact.get("expired") is not False
        or not isinstance(digest, str)
        or not digest.startswith("sha256:")
        or _SHA_RE.fullmatch(digest.removeprefix("sha256:")) is None
        or type(size) is not int
        or not 0 < size <= production_readiness.MAX_ARCHIVE_BYTES
        or not isinstance(producer, dict)
        or not isinstance(repository, dict)
        or producer.get("id") != run_id
        or producer.get("head_sha") != run.get("head_sha")
        or producer.get("head_branch") not in (None, tag)
        or producer.get("repository_id") != repository.get("id")
        or producer.get("head_repository_id") != repository.get("id")
    ):
        raise ValueError("public managed artifact is expired, foreign or malformed")

    destination.mkdir(parents=True, exist_ok=False)
    archive = destination / "managed-public.zip"
    production_readiness.download_evidence_archive(
        artifact_id, archive, token=os.environ.get("GH_TOKEN")
    )
    evidence = production_readiness.verify_evidence_archive(
        kind="public",
        artifact=artifact,
        run=run,
        archive=archive,
        artifact_id=artifact_id,
        evidence_sha256=None,
        source_commit=run["head_sha"],
        tag=tag,
        workflow_run=run_id,
        workflow_attempt=attempt,
    )
    if (
        not isinstance(evidence, dict)
        or evidence.get("scope") != "native-systemd-public-matrix"
        or evidence.get("status") != "passed"
        or evidence.get("publicReleaseEvidence") is not True
        or evidence.get("sourceCommit") != run["head_sha"]
        or evidence.get("workflowRun") != str(run_id)
        or type(evidence.get("workflowAttempt")) is not int
        or evidence["workflowAttempt"] != attempt
        or evidence.get("targetTag") != tag
        or type(evidence.get("pairCount")) is not int
        or evidence["pairCount"] != 10
    ):
        raise ValueError("Pages requires authenticated full public managed lifecycle evidence")
    previous_tag = evidence.get("previousTag")
    if not isinstance(previous_tag, str):
        raise ValueError("public managed lifecycle requires a distinct public predecessor")
    previous = tuple(map(int, version_from_tag(previous_tag).split(".")))
    current = tuple(map(int, version_from_tag(tag).split(".")))
    if previous >= current:
        raise ValueError("public managed lifecycle requires a distinct earlier public predecessor")
    return {
        "artifact_id": artifact_id,
        "artifact_zip_sha256": digest.removeprefix("sha256:"),
        "target_tag": tag,
        "previous_tag": previous_tag,
        "pair_count": 10,
    }


def _docs_path(path: object) -> bool:
    return isinstance(path, str) and (
        path in _DOCS_FILES
        or (
            path.startswith("docs/")
            and all(part not in {"", ".", ".."} for part in path.split("/"))
            and "\\" not in path
        )
    )


def verify_source(api: ReleaseAPI, run: Mapping[str, Any], documentation_commit: str) -> None:
    if _COMMIT_RE.fullmatch(documentation_commit) is None:
        raise ValueError("documentation source must be a full lowercase commit SHA")
    source = run["head_sha"]
    main = api.request("GET", f"repos/{REPOSITORY}/git/ref/heads/main").document
    if (
        not isinstance(main, dict)
        or not isinstance(main.get("object"), dict)
        or main.get("ref") != "refs/heads/main"
        or main["object"].get("type") != "commit"
        or main["object"].get("sha") != documentation_commit
    ):
        raise ValueError("documentation source is not the current main commit")
    reference = api.request(
        "GET",
        f"repos/{REPOSITORY}/git/ref/tags/{run['head_branch']}",
    ).document
    if not isinstance(reference, dict) or reference.get("ref") != f"refs/tags/{run['head_branch']}":
        raise ValueError("production tag reference is missing")
    target = reference.get("object")
    for _ in range(4):
        if (
            not isinstance(target, dict)
            or not isinstance(target.get("sha"), str)
            or _COMMIT_RE.fullmatch(target["sha"]) is None
        ):
            raise ValueError("production tag reference identity is invalid")
        if target.get("type") == "commit":
            if target["sha"] != source:
                raise ValueError("production tag no longer identifies its accepted source")
            break
        if target.get("type") != "tag":
            raise ValueError("production tag target is not a commit or annotated tag")
        annotated = api.request("GET", f"repos/{REPOSITORY}/git/tags/{target['sha']}").document
        if not isinstance(annotated, dict) or annotated.get("sha") != target["sha"]:
            raise ValueError("annotated production tag metadata is inconsistent")
        target = annotated.get("object")
    else:
        raise ValueError("production tag nesting exceeds its bound")
    if source == documentation_commit:
        return
    compare = api.request(
        "GET",
        f"repos/{REPOSITORY}/compare/{source}...{documentation_commit}",
    ).document
    if not isinstance(compare, dict):
        raise ValueError("documentation/source comparison metadata is invalid")
    files, commits = compare.get("files"), compare.get("commits")
    if (
        compare.get("status") != "ahead"
        or compare.get("behind_by") != 0
        or not isinstance(compare.get("base_commit"), dict)
        or compare["base_commit"].get("sha") != source
        or not isinstance(compare.get("merge_base_commit"), dict)
        or compare["merge_base_commit"].get("sha") != source
        or type(compare.get("total_commits")) is not int
        or not 0 < compare["total_commits"] <= 250
        or not isinstance(commits, list)
        or len(commits) != compare["total_commits"]
        or not isinstance(commits[-1], dict)
        or commits[-1].get("sha") != documentation_commit
        or not isinstance(files, list)
        or not 0 < len(files) < 300
        or compare.get("ahead_by") != compare["total_commits"]
    ):
        raise ValueError("documentation is not a completely enumerated accepted source descendant")
    if any(
        not isinstance(record, dict)
        or not _docs_path(record.get("filename"))
        or ("previous_filename" in record and not _docs_path(record["previous_filename"]))
        for record in files
    ):
        raise ValueError("documentation descendant includes changes outside its whitelist")


def _public_assets(api: ReleaseAPI, release_id: int) -> list[dict[str, Any]]:
    endpoint = f"repos/{REPOSITORY}/releases/{release_id}/assets"
    result: list[dict[str, Any]] = []
    for page in range(1, MAX_PAGES + 1):
        response = api.request("GET", f"{endpoint}?per_page={PAGE_SIZE}&page={page}")
        if not isinstance(response.document, list) or len(response.document) > PAGE_SIZE:
            raise ValueError("public release assets pagination is invalid")
        has_next = _next_page(response.link, endpoint, page)
        if has_next and len(response.document) != PAGE_SIZE:
            raise ValueError("public release assets pagination is truncated")
        result.extend(response.document)
        if not has_next and len(response.document) < PAGE_SIZE:
            return result
    raise ValueError("public release assets pagination exceeds its bound")


def _verify_cross_channel_signatures(
    identity: dict[str, Any],
    assets: Path,
    key_ring: ReleaseKeyRing,
) -> None:
    version = identity["version"]
    required = {
        "release-candidate.tar",
        "candidate-inventory.json",
        f"xferry-{version}-py3-none-any.whl",
        f"xferry-{version}.tar.gz",
    }
    for platform in SUPPORTED_PLATFORM_IDS:
        name = release_manifest_asset_name(platform)
        manifest = verify_signed_manifest(
            (assets / name).read_bytes(),
            (assets / f"{name}.sig").read_bytes(),
            key_ring=key_ring,
        )
        digests = dict(manifest.artifact_digests)
        if any(digests.get(name) != _sha256(assets / name) for name in required):
            raise ValueError("signed release manifest does not authenticate all channel candidates")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _asset_size_limit(name: str) -> int:
    if name.endswith(".sig"):
        return MAX_SIGNATURE_BYTES
    if name.startswith("xferry-release-") and name.endswith(".json"):
        return MAX_MANIFEST_BYTES
    if name.endswith(".json") or name.startswith(("install-", "SHA256SUMS-")):
        return MAX_JSON_BYTES
    return MAX_ASSET_BYTES


def verify_public_release(
    public: PublicHTTP,
    run: dict[str, Any],
    assets: Path,
    *,
    key_ring: ReleaseKeyRing = DEFAULT_RELEASE_KEY_RING,
) -> tuple[dict[str, Any], dict[str, Any]]:
    tag = run["head_branch"]
    api = AnonymousGitHubAPI(public)
    release = api.request("GET", f"repos/{REPOSITORY}/releases/tags/{tag}").document
    if (
        not isinstance(release, dict)
        or release.get("tag_name") != tag
        or release.get("draft") is not False
        or release.get("prerelease") is not False
        or not isinstance(release.get("published_at"), str)
        or not release["published_at"]
        or release.get("target_commitish") != run["head_sha"]
    ):
        raise ValueError("public GitHub Release is not the published final accepted source")
    release_id = _positive_id(release.get("id"), "public release ID")
    version = version_from_tag(tag)
    expected = github_release_assets._signed_asset_names({"version": version})
    metadata = _public_assets(api, release_id)
    records: dict[str, dict[str, Any]] = {}
    seen_ids: set[int] = set()
    total = 0
    for record in metadata:
        if not isinstance(record, dict):
            raise ValueError("public release asset metadata is invalid")
        asset_id = _positive_id(record.get("id"), "public asset ID")
        name, size, url = (
            record.get("name"),
            record.get("size"),
            record.get("browser_download_url"),
        )
        if (
            not isinstance(name, str)
            or name not in expected
            or name in records
            or asset_id in seen_ids
            or type(size) is not int
            or not 0 < size <= MAX_ASSET_BYTES
            or size > _asset_size_limit(name)
            or record.get("state") != "uploaded"
            or not isinstance(url, str)
            or url != f"https://github.com/{REPOSITORY}/releases/download/{tag}/{name}"
        ):
            raise ValueError("public release asset name, size, identity, or URL differs")
        total += size
        seen_ids.add(asset_id)
        records[name] = record
    if set(records) != expected or total > MAX_TOTAL_ASSET_BYTES:
        raise ValueError("public release asset set is incomplete, unexpected, or oversized")
    assets.mkdir()
    for name, record in sorted(records.items()):
        public.download(record["browser_download_url"], assets / name, size=record["size"])
    inventory = _json((assets / github_release_assets.ASSET_INVENTORY_NAME).read_bytes())
    fields = (
        "repository",
        "repository_id",
        "version",
        "tag",
        "release_tag",
        "source_commit",
        "workflow_run",
        "artifact_id",
        "artifact_name",
        "archive_sha256",
        "inventory_sha256",
    )
    if not all(field in inventory for field in fields):
        raise ValueError("public release inventory identity is incomplete")
    identity = {field: inventory[field] for field in fields}
    if (
        identity["repository"] != REPOSITORY
        or identity["repository_id"] != run["repository"]["id"]
        or identity["version"] != version
        or identity["tag"] != tag
        or identity["release_tag"] != tag
        or identity["source_commit"] != run["head_sha"]
        or identity["workflow_run"] != run["id"]
        or not isinstance(identity["archive_sha256"], str)
        or _SHA_RE.fullmatch(identity["archive_sha256"]) is None
        or not isinstance(identity["inventory_sha256"], str)
        or _SHA_RE.fullmatch(identity["inventory_sha256"]) is None
    ):
        raise ValueError("public release inventory source/run differs from the accepted run")
    _positive_id(identity["artifact_id"], "public candidate artifact ID")
    match = re.fullmatch(
        rf"release-candidate-{run['id']}-([1-9][0-9]*)",
        str(identity["artifact_name"]),
    )
    if match is None or int(match[1]) > run["run_attempt"]:
        raise ValueError("public candidate artifact differs from its production run")
    # Authenticate the archive before the existing verifier parses or extracts it.
    _verify_cross_channel_signatures(identity, assets, key_ring)
    github_release_assets.verify_downloaded_assets(identity, assets, key_ring=key_ring)
    return identity, release


def verify_public_pypi(
    public: PublicHTTP,
    identity: dict[str, Any],
    assets: Path,
    output: Path,
) -> None:
    version = identity["version"]
    document = _json(public.get(f"https://pypi.org/pypi/xferry/{version}/json")[0])
    info, urls = document.get("info"), document.get("urls")
    expected = {
        f"xferry-{version}-py3-none-any.whl": "bdist_wheel",
        f"xferry-{version}.tar.gz": "sdist",
    }
    if (
        not isinstance(info, dict)
        or info.get("name") != "xferry"
        or info.get("version") != version
        or not isinstance(urls, list)
        or len(urls) != len(expected)
    ):
        raise ValueError("public PyPI project version or files differ from the signed release")
    output.mkdir()
    seen: set[str] = set()
    for record in urls:
        if not isinstance(record, dict) or not isinstance(record.get("filename"), str):
            raise ValueError("public PyPI file metadata is invalid")
        name = record["filename"]
        if name not in expected or name in seen:
            raise ValueError("public PyPI has duplicate or unexpected distributions")
        seen.add(name)
        path = assets / name
        digest = _sha256(path)
        url = record.get("url")
        parsed = _public_url(url) if isinstance(url, str) else None
        if (
            record.get("packagetype") != expected[name]
            or record.get("yanked") is not False
            or record.get("size") != path.stat().st_size
            or not isinstance(record.get("digests"), dict)
            or record["digests"].get("sha256") != digest
            or parsed is None
            or parsed.hostname != "files.pythonhosted.org"
            or urllib.parse.unquote(parsed.path.rsplit("/", 1)[-1]) != name
        ):
            raise ValueError(
                "public PyPI digest, size, yank state, or URL differs from signed bytes"
            )
        public.download(str(url), output / name, size=path.stat().st_size, sha256=digest)


def _registry_platforms(
    public: PublicHTTP,
    raw: bytes,
    headers: Mapping[str, str],
    depth: int = 0,
) -> dict[str, str]:
    if depth > 4:
        raise ValueError("public registry index nesting exceeds its bound")
    document = _json(raw)
    descriptors = document.get("manifests")
    if not isinstance(descriptors, list) or not 0 < len(descriptors) <= 64:
        raise ValueError("public registry index is invalid or oversized")
    platforms: dict[str, str] = {}
    for descriptor in descriptors:
        if not isinstance(descriptor, dict):
            raise ValueError("public registry manifest descriptor is invalid")
        digest, platform, media_type = (
            descriptor.get("digest"),
            descriptor.get("platform"),
            descriptor.get("mediaType"),
        )
        if (
            not isinstance(digest, str)
            or not digest.startswith("sha256:")
            or _SHA_RE.fullmatch(digest[7:]) is None
        ):
            raise ValueError("public registry manifest descriptor digest is invalid")
        if (
            isinstance(platform, dict)
            and platform.get("os") == "linux"
            and platform.get("architecture") in {"amd64", "arm64"}
        ):
            name = f"linux/{platform['architecture']}"
            if media_type not in _MANIFEST_TYPES or name in platforms:
                raise ValueError(
                    "public registry native platform descriptor is invalid or repeated"
                )
            platforms[name] = digest
        elif isinstance(platform, dict) and (platform.get("os"), platform.get("architecture")) == (
            "unknown",
            "unknown",
        ):
            if media_type not in _MANIFEST_TYPES:
                raise ValueError("public registry attestation descriptor is invalid")
        elif media_type in _INDEX_TYPES:
            child = public.get(
                f"https://ghcr.io/v2/kgmnotes/xferry/manifests/{digest}",
                headers,
            )[0]
            if f"sha256:{hashlib.sha256(child).hexdigest()}" != digest or len(
                child
            ) != descriptor.get("size"):
                raise ValueError("public registry nested index size or digest differs")
            nested = _registry_platforms(public, child, headers, depth + 1)
            if platforms.keys() & nested.keys():
                raise ValueError("public registry native platform is repeated")
            platforms.update(nested)
        else:
            raise ValueError("public registry contains an unsupported native platform")
    return platforms


def verify_public_ghcr(
    public: PublicHTTP,
    identity: dict[str, Any],
    assets: Path,
    candidate: Path,
) -> str:
    unpack_candidate(assets / "release-candidate.tar", identity["archive_sha256"], candidate)
    verify_inventory(
        candidate,
        identity["tag"],
        identity["source_commit"],
        str(identity["workflow_run"]),
        expected_sha256=identity["inventory_sha256"],
    )
    summary = summarize_oci_layout(candidate / "oci")
    digest = summary["publish_digest"]
    if (
        not isinstance(digest, str)
        or not digest.startswith("sha256:")
        or _SHA_RE.fullmatch(digest[7:]) is None
    ):
        raise ValueError("authenticated candidate OCI digest is invalid")
    query = urllib.parse.urlencode(
        {"service": "ghcr.io", "scope": "repository:kgmnotes/xferry:pull"}
    )
    token = _json(public.get(f"https://ghcr.io/token?{query}")[0]).get("token")
    if not isinstance(token, str) or not token or any(character.isspace() for character in token):
        raise ValueError("public GHCR did not issue an anonymous pull token")
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": ", ".join(sorted(_INDEX_TYPES | _MANIFEST_TYPES)),
    }
    for reference in (digest, identity["tag"]):
        raw = public.get(f"https://ghcr.io/v2/kgmnotes/xferry/manifests/{reference}", headers)[0]
        if f"sha256:{hashlib.sha256(raw).hexdigest()}" != digest:
            raise ValueError(
                "public GHCR immutable digest or tag differs from the signed candidate"
            )
        if _registry_platforms(public, raw, headers) != summary["platform_manifests"]:
            raise ValueError(
                "public GHCR native platform manifests differ from the signed candidate"
            )
    return digest


def verify_publication(
    api: ReleaseAPI,
    public: PublicHTTP,
    *,
    production_run: int,
    documentation_commit: str,
    workspace: Path = REPO_ROOT,
    key_ring: ReleaseKeyRing = DEFAULT_RELEASE_KEY_RING,
) -> dict[str, object]:
    expected_tag = f"v{_source_version(workspace)}"
    run = verify_production_run(api, production_run, expected_tag=expected_tag)
    check_source(workspace, run["head_branch"])
    verify_source(api, run, documentation_commit)
    with TemporaryDirectory(prefix="xferry-pages-publication-") as temporary:
        root = Path(temporary)
        managed = verify_public_managed_evidence(api, run, root / "managed", tag=expected_tag)
        identity, release = verify_public_release(public, run, root / "assets", key_ring=key_ring)
        verify_public_pypi(public, identity, root / "assets", root / "pypi")
        ghcr_digest = verify_public_ghcr(public, identity, root / "assets", root / "candidate")
    rechecked = verify_production_run(api, production_run, expected_tag=expected_tag)
    if any(
        rechecked.get(key) != run.get(key) for key in ("run_attempt", "head_sha", "head_branch")
    ):
        raise ValueError("accepted production run changed during public channel verification")
    verify_source(api, rechecked, documentation_commit)
    return {
        "repository": REPOSITORY,
        "production_run": production_run,
        "production_attempt": run["run_attempt"],
        "tag": run["head_branch"],
        "source_commit": run["head_sha"],
        "documentation_commit": documentation_commit,
        "release_id": release["id"],
        "ghcr_digest": ghcr_digest,
        "public_channels_verified": ["github-release", "pypi", "ghcr"],
        "public_managed_verified": True,
        "managed_evidence": managed,
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--production-run", type=int, required=True)
    parser.add_argument("--documentation-commit", required=True)
    parser.add_argument("--workspace", type=Path, default=REPO_ROOT)
    args = parser.parse_args(argv)
    try:
        receipt = verify_publication(
            GitHubReleaseAPI(os.environ.get("GH_TOKEN", "")),
            PublicHTTP(),
            production_run=args.production_run,
            documentation_commit=args.documentation_commit,
            workspace=args.workspace,
        )
    except (OSError, UnicodeError, ValueError) as error:
        print(f"Pages publication rejected: {error}", file=sys.stderr)
        return 1
    print(json.dumps(receipt, sort_keys=True, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
