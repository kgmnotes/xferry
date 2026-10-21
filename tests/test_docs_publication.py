"""Pages requires the latest accepted run and anonymously verified signed public bytes."""

from __future__ import annotations

import copy
import hashlib
import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest

from tests.test_github_release_assets import (
    COMMIT,
    RUN,
    TAG,
    VERSION,
    _identity,
    _metadata,
    _private_key,
)
from tools import docs_publication as gate
from tools import github_release_assets
from tools.production_release_state import APIResponse
from xferry.management.release_contract import SUPPORTED_PLATFORM_IDS, release_manifest_asset_name
from xferry.management.release_trust import ReleaseKeyRing

ROOT = f"repos/{gate.REPOSITORY}"
RUN_ID = int(RUN)
ATTEMPT = 2
RUN_ENDPOINT = f"{ROOT}/actions/runs/{RUN_ID}"
JOBS_ENDPOINT = f"{RUN_ENDPOINT}/attempts/{ATTEMPT}/jobs?per_page=100&page=1"
RELEASE_ID = 321


def _json(document: object) -> bytes:
    return json.dumps(document).encode()


def _run(**changes: object) -> dict[str, Any]:
    repository = {"id": 1341230685, "full_name": gate.REPOSITORY}
    return {
        "id": RUN_ID,
        "path": gate.WORKFLOW_PATH,
        "head_branch": TAG,
        "head_sha": COMMIT,
        "event": "push",
        "status": "completed",
        "conclusion": "success",
        "run_attempt": ATTEMPT,
        "repository": repository,
        "head_repository": repository.copy(),
        **changes,
    }


def _jobs() -> list[dict[str, Any]]:
    return [
        {
            "id": index,
            "run_id": RUN_ID,
            "run_attempt": ATTEMPT,
            "name": name,
            "head_sha": COMMIT,
            "status": "completed",
            "conclusion": "success",
        }
        for index, name in enumerate(sorted(gate.REQUIRED_JOBS), 1)
    ]


class FakeAPI:
    def __init__(self, documents: dict[str, object] | None = None) -> None:
        self.documents = {
            RUN_ENDPOINT: _run(),
            JOBS_ENDPOINT: {"total_count": len(_jobs()), "jobs": _jobs()},
            f"{ROOT}/git/ref/heads/main": {
                "ref": "refs/heads/main",
                "object": {"type": "commit", "sha": COMMIT},
            },
            f"{ROOT}/git/ref/tags/{TAG}": {
                "ref": f"refs/tags/{TAG}",
                "object": {"type": "commit", "sha": COMMIT},
            },
            **(documents or {}),
        }
        self.calls: list[str] = []

    def request(
        self,
        method: str,
        endpoint: str,
        payload: Mapping[str, object] | None = None,
    ) -> APIResponse:
        assert method == "GET" and payload is None
        self.calls.append(endpoint)
        response = copy.deepcopy(self.documents[endpoint])
        if isinstance(response, Exception):
            raise response
        return response if isinstance(response, APIResponse) else APIResponse(response)


class FakePublic(gate.PublicHTTP):
    def __init__(self, documents: dict[str, bytes], files: dict[str, bytes]) -> None:
        self.documents, self.files = documents, files
        self.calls: list[tuple[str, Mapping[str, str] | None]] = []

    def get(self, url: str, headers: Mapping[str, str] | None = None) -> tuple[bytes, str | None]:
        self.calls.append((url, headers))
        assert not headers or "Authorization" not in headers or url.startswith("https://ghcr.io/")
        return self.documents[url], None

    def download(self, url: str, path: Path, *, size: int, sha256: str | None = None) -> None:
        self.calls.append((url, None))
        raw = self.files[url]
        if len(raw) != size or (sha256 is not None and hashlib.sha256(raw).hexdigest() != sha256):
            raise ValueError("public asset size or SHA256 differs from signed records")
        path.write_bytes(raw)


@pytest.fixture
def public_release(tmp_path: Path) -> tuple[FakePublic, dict, Path, ReleaseKeyRing]:
    identity, candidate, archive = _identity(tmp_path)
    identity["release_tag"] = TAG
    artifact, producer = _metadata(identity)
    unsigned, signed = tmp_path / "unsigned", tmp_path / "signed"
    github_release_assets.prepare_unsigned_assets(
        identity,
        artifact,
        producer,
        archive,
        candidate_dir=tmp_path / "unpacked",
        unsigned_dir=unsigned,
    )
    key_path = tmp_path / "test-key.pem"
    key_id, key_ring = _private_key(key_path)
    github_release_assets.sign_prepared_assets(
        unsigned,
        signed,
        key_id=key_id,
        private_key=key_path,
        identity=identity,
    )
    release = {
        "id": RELEASE_ID,
        "tag_name": TAG,
        "draft": False,
        "prerelease": False,
        "target_commitish": COMMIT,
        "published_at": "2026-10-13T00:00:00Z",
    }
    release_url = f"https://github.com/{gate.REPOSITORY}/releases/download/{TAG}/"
    files = {release_url + path.name: path.read_bytes() for path in signed.iterdir()}
    asset_metadata = [
        {
            "id": index,
            "name": url.rsplit("/", 1)[-1],
            "state": "uploaded",
            "size": len(raw),
            "browser_download_url": url,
        }
        for index, (url, raw) in enumerate(sorted(files.items()), 1)
    ]
    pypi_files = []
    for name, kind in (
        (f"xferry-{VERSION}-py3-none-any.whl", "bdist_wheel"),
        (f"xferry-{VERSION}.tar.gz", "sdist"),
    ):
        raw = (signed / name).read_bytes()
        url = f"https://files.pythonhosted.org/packages/example/{name}"
        files[url] = raw
        pypi_files.append(
            {
                "filename": name,
                "packagetype": kind,
                "size": len(raw),
                "yanked": False,
                "digests": {"sha256": hashlib.sha256(raw).hexdigest()},
                "url": url,
            }
        )
    index = (candidate / "oci/index.json").read_bytes()
    digest = f"sha256:{hashlib.sha256(index).hexdigest()}"
    documents = {
        f"https://api.github.com/{ROOT}/releases/tags/{TAG}": _json(release),
        f"https://api.github.com/{ROOT}/releases/{RELEASE_ID}/assets?per_page=100&page=1": _json(
            asset_metadata
        ),
        f"https://pypi.org/pypi/xferry/{VERSION}/json": _json(
            {
                "info": {"name": "xferry", "version": VERSION},
                "urls": pypi_files,
            }
        ),
        "https://ghcr.io/token?service=ghcr.io&scope=repository%3Akgmnotes%2Fxferry%3Apull": _json(
            {"token": "anonymous-token"}
        ),
        f"https://ghcr.io/v2/kgmnotes/xferry/manifests/{digest}": index,
        f"https://ghcr.io/v2/kgmnotes/xferry/manifests/{TAG}": index,
    }
    workspace = tmp_path / "workspace"
    (workspace / "xferry").mkdir(parents=True)
    (workspace / "xferry/config.py").write_text(f'__version__ = "{VERSION}"\n')
    (workspace / "CHANGELOG.md").write_text(f"## [{VERSION}] - 2026-10-13\n")
    return FakePublic(documents, files), identity, workspace, key_ring


def test_latest_successful_run_and_all_public_channels_permit_pages(public_release) -> None:
    public, _identity_document, workspace, key_ring = public_release
    receipt = gate.verify_publication(
        FakeAPI(),
        public,
        production_run=RUN_ID,
        documentation_commit=COMMIT,
        workspace=workspace,
        key_ring=key_ring,
    )
    assert receipt["production_attempt"] == ATTEMPT
    assert receipt["release_id"] == RELEASE_ID
    assert receipt["public_channels_verified"] == ["github-release", "pypi", "ghcr"]
    assert any(url.startswith("https://files.pythonhosted.org/") for url, _ in public.calls)
    assert all(
        headers["Authorization"] == "Bearer anonymous-token"
        for _, headers in public.calls
        if headers and "Authorization" in headers
    )


def test_null_tag_run_requires_source_version_and_a_matching_real_tag_ref(public_release) -> None:
    public, _identity_document, workspace, key_ring = public_release
    api = FakeAPI({RUN_ENDPOINT: _run(head_branch=None)})
    receipt = gate.verify_publication(
        api,
        public,
        production_run=RUN_ID,
        documentation_commit=COMMIT,
        workspace=workspace,
        key_ring=key_ring,
    )
    assert receipt["tag"] == TAG
    assert f"{ROOT}/git/ref/tags/{TAG}" in api.calls
    with pytest.raises(ValueError, match="expected tag"):
        gate.verify_production_run(FakeAPI({RUN_ENDPOINT: _run(head_branch=None)}), RUN_ID)
    with pytest.raises(ValueError, match="differs"):
        gate.verify_production_run(
            FakeAPI({RUN_ENDPOINT: _run(head_branch="v0.2.0")}),
            RUN_ID,
            expected_tag=TAG,
        )


@pytest.mark.parametrize(
    "changes",
    [
        {"conclusion": "failure"},
        {"status": "in_progress"},
        {"event": "workflow_dispatch"},
        {"path": ".github/workflows/release.yml"},
        {"head_branch": "main"},
        {"id": RUN_ID + 1},
        {"repository": {"id": 1341230685, "full_name": "attacker/xferry"}},
        {"head_repository": {"id": 99, "full_name": gate.REPOSITORY}},
        {"run_attempt": True},
        {"head_sha": "short"},
    ],
)
def test_wrong_or_unsuccessful_producer_is_rejected_before_public_access(changes: dict) -> None:
    api = FakeAPI({RUN_ENDPOINT: _run(**changes)})
    with pytest.raises(ValueError):
        gate.verify_production_run(api, RUN_ID)
    assert api.calls == [RUN_ENDPOINT]


@pytest.mark.parametrize(
    "field,value",
    [
        ("conclusion", "skipped"),
        ("conclusion", "failure"),
        ("status", "in_progress"),
        ("run_attempt", 1),
        ("run_id", RUN_ID + 1),
        ("head_sha", "b" * 40),
    ],
)
def test_required_consumers_cannot_be_skipped_or_reused_from_an_older_attempt(field, value) -> None:
    jobs = _jobs()
    jobs[0][field] = value
    with pytest.raises(ValueError):
        gate.verify_production_run(
            FakeAPI({JOBS_ENDPOINT: {"total_count": len(jobs), "jobs": jobs}}),
            RUN_ID,
        )


def test_missing_or_duplicate_final_gate_is_rejected() -> None:
    jobs = [job for job in _jobs() if job["name"] != "final-gate"]
    for selected in (jobs, [*_jobs(), {**_jobs()[-1], "id": 999}]):
        with pytest.raises(ValueError):
            gate.verify_production_run(
                FakeAPI({JOBS_ENDPOINT: {"total_count": len(selected), "jobs": selected}}),
                RUN_ID,
            )


def test_jobs_pagination_requires_all_pages_and_exact_total() -> None:
    extra = [{**_jobs()[0], "id": 1000 + index, "name": f"Other {index}"} for index in range(100)]
    second = JOBS_ENDPOINT.replace("&page=1", "&page=2")
    total = 100 + len(_jobs())
    documents = {
        JOBS_ENDPOINT: APIResponse(
            {"total_count": total, "jobs": extra},
            f'<https://api.github.com/{second}>; rel="next"',
        ),
        second: {"total_count": total, "jobs": _jobs()},
    }
    api = FakeAPI(documents)
    assert gate.verify_production_run(api, RUN_ID)["id"] == RUN_ID
    assert second in api.calls
    documents[second] = {"total_count": total, "jobs": _jobs()[:-1]}
    with pytest.raises(ValueError, match="omitted"):
        gate.verify_production_run(FakeAPI(documents), RUN_ID)


@pytest.mark.parametrize(
    "link",
    [
        "broken",
        '<https://evil.example/jobs?page=2>; rel="next"',
        f'<https://api.github.com/{JOBS_ENDPOINT}>; rel="next"',
    ],
)
def test_jobs_pagination_transport_or_identity_failure_is_not_ignored(link: str) -> None:
    api = FakeAPI(
        {JOBS_ENDPOINT: APIResponse({"total_count": len(_jobs()), "jobs": _jobs()}, link)}
    )
    with pytest.raises(ValueError, match="pagination"):
        gate.verify_production_run(api, RUN_ID)


def _descendant_api(files: list[dict], **changes: object) -> tuple[FakeAPI, str]:
    docs_commit = "b" * 40
    compare = {
        "status": "ahead",
        "ahead_by": 1,
        "behind_by": 0,
        "total_commits": 1,
        "base_commit": {"sha": COMMIT},
        "merge_base_commit": {"sha": COMMIT},
        "commits": [{"sha": docs_commit}],
        "files": files,
        **changes,
    }
    return FakeAPI(
        {
            f"{ROOT}/git/ref/heads/main": {
                "ref": "refs/heads/main",
                "object": {"type": "commit", "sha": docs_commit},
            },
            f"{ROOT}/compare/{COMMIT}...{docs_commit}": compare,
        }
    ), docs_commit


def test_docs_only_descendant_can_update_the_accepted_release_documentation() -> None:
    api, commit = _descendant_api(
        [
            {"filename": "docs/quick-start.md"},
            {"filename": "README.md"},
            {"filename": "docs/new.md", "previous_filename": "docs/old.md"},
        ]
    )
    gate.verify_source(api, _run(), commit)


@pytest.mark.parametrize(
    "files,changes",
    [
        ([{"filename": "xferry/config.py"}], {}),
        ([{"filename": "docs/code.py", "previous_filename": "tools/installer.py"}], {}),
        ([{"filename": "docs/../xferry/config.py"}], {}),
        ([{"filename": "docs/quick-start.md"}], {"status": "diverged", "behind_by": 1}),
        ([{"filename": "docs/quick-start.md"}], {"merge_base_commit": {"sha": "c" * 40}}),
        ([{"filename": "docs/quick-start.md"}], {"total_commits": 251}),
        ([{"filename": f"docs/{index}.md"} for index in range(300)], {}),
    ],
)
def test_source_regression_code_changes_or_truncated_comparison_reject_pages(
    files, changes
) -> None:
    api, commit = _descendant_api(files, **changes)
    with pytest.raises(ValueError):
        gate.verify_source(api, _run(), commit)


def test_moved_tag_and_stale_main_are_rejected() -> None:
    for endpoint in (f"{ROOT}/git/ref/heads/main", f"{ROOT}/git/ref/tags/{TAG}"):
        with pytest.raises(ValueError):
            gate.verify_source(
                FakeAPI({endpoint: {"object": {"type": "commit", "sha": "b" * 40}}}),
                _run(),
                COMMIT,
            )


@pytest.mark.parametrize(
    "changes",
    [
        {"draft": True},
        {"prerelease": True},
        {"tag_name": "v0.2.0"},
        {"target_commitish": "b" * 40},
        {"published_at": None},
        {"id": True},
    ],
)
def test_unpublished_or_wrong_release_rejects_pages(
    public_release, changes: dict, tmp_path
) -> None:
    public, _identity_document, _workspace, key_ring = public_release
    url = f"https://api.github.com/{ROOT}/releases/tags/{TAG}"
    public.documents[url] = _json({**json.loads(public.documents[url]), **changes})
    with pytest.raises(ValueError):
        gate.verify_public_release(public, _run(), tmp_path / "downloads", key_ring=key_ring)
    assert not any("/releases/download/" in url for url, _ in public.calls)


def test_tampered_signed_release_bytes_reject_before_archive_extraction(
    public_release, tmp_path
) -> None:
    public, _identity_document, _workspace, key_ring = public_release
    url = f"https://github.com/{gate.REPOSITORY}/releases/download/{TAG}/release-candidate.tar"
    raw = public.files[url]
    public.files[url] = b"x" + raw[1:]
    with pytest.raises(ValueError, match="authenticate"):
        gate.verify_public_release(public, _run(), tmp_path / "downloads", key_ring=key_ring)


def test_unsigned_cross_channel_digests_cannot_authorize_pages(public_release, tmp_path) -> None:
    public, identity, _workspace, key_ring = public_release
    # Remove only archive coverage and re-sign with this fixture's throwaway key.
    from tools.sign_release_metadata import _load_private_key, sign_manifest

    signer = _load_private_key((tmp_path / "test-key.pem").read_bytes())
    for platform in SUPPORTED_PLATFORM_IDS:
        name = release_manifest_asset_name(platform)
        url = f"https://github.com/{gate.REPOSITORY}/releases/download/{TAG}/{name}"
        manifest = json.loads(public.files[url])
        manifest["artifact_digests"].pop("release-candidate.tar")
        raw = (json.dumps(manifest, indent=2) + "\n").encode()
        public.files[url] = raw
        public.files[f"{url}.sig"] = sign_manifest(
            raw, key_id="test-release-2026", private_key=signer
        )
    metadata_url = f"https://api.github.com/{ROOT}/releases/{RELEASE_ID}/assets?per_page=100&page=1"
    metadata = json.loads(public.documents[metadata_url])
    for record in metadata:
        record["size"] = len(public.files[record["browser_download_url"]])
    public.documents[metadata_url] = _json(metadata)
    with pytest.raises(ValueError, match="authenticate"):
        gate.verify_public_release(public, _run(), tmp_path / "downloads", key_ring=key_ring)
    assert identity["tag"] == TAG


@pytest.mark.parametrize(
    "field,value",
    [
        ("yanked", True),
        ("size", 1),
        ("digests", {"sha256": "a" * 64}),
        ("url", "http://files.pythonhosted.org/wheel.whl"),
    ],
)
def test_public_pypi_yank_or_digest_substitution_rejects_pages(
    public_release, field, value, tmp_path
) -> None:
    public, identity, _workspace, _key_ring = public_release
    url = f"https://pypi.org/pypi/xferry/{VERSION}/json"
    document = json.loads(public.documents[url])
    document["urls"][0][field] = value
    public.documents[url] = _json(document)
    with pytest.raises(ValueError):
        gate.verify_public_pypi(public, identity, tmp_path / "signed", tmp_path / "pypi-downloads")


def test_public_pypi_actual_download_must_match_metadata(public_release, tmp_path) -> None:
    public, identity, _workspace, _key_ring = public_release
    url = f"https://files.pythonhosted.org/packages/example/xferry-{VERSION}-py3-none-any.whl"
    public.files[url] = b"x" + public.files[url][1:]
    with pytest.raises(ValueError, match="SHA256"):
        gate.verify_public_pypi(public, identity, tmp_path / "signed", tmp_path / "pypi-downloads")


@pytest.mark.parametrize("reference", ["digest", "tag"])
def test_public_ghcr_tag_or_immutable_digest_substitution_rejects_pages(
    public_release, tmp_path, reference
) -> None:
    public, identity, _workspace, _key_ring = public_release
    prefix = "https://ghcr.io/v2/kgmnotes/xferry/manifests/"
    url = next(url for url in public.documents if url.startswith(f"{prefix}sha256:"))
    if reference == "tag":
        url = prefix + TAG
    public.documents[url] = _json({"schemaVersion": 2, "manifests": []})
    with pytest.raises(ValueError, match="signed candidate"):
        gate.verify_public_ghcr(public, identity, tmp_path / "signed", tmp_path / "ghcr-candidate")


@pytest.mark.parametrize(
    "url",
    [
        "http://github.com/kgmnotes/xferry",
        "https://evil.example/release",
        "https://user:password@github.com/release",
        "https://github.com:444/release",
    ],
)
def test_anonymous_download_transport_rejects_insecure_or_foreign_targets(url: str) -> None:
    with pytest.raises(ValueError):
        gate._public_url(url)


def test_public_metadata_rejects_duplicate_or_nonfinite_json() -> None:
    for raw in (b'{"tag": "v0.1.0", "tag": "v0.2.0"}', b'{"size": NaN}'):
        with pytest.raises(ValueError):
            gate._json(raw)
