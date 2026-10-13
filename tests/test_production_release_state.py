"""Authenticated draft lookup fails closed and subsequent operations bind numeric IDs."""

from __future__ import annotations

import copy
import io
import json
import urllib.error
from collections.abc import Mapping
from pathlib import Path
from typing import Any, NoReturn

import pytest

from tools import production_release_state as state

REPOSITORY = "kgmnotes/xferry"
TAG = "v1.2.3"
COMMIT = "a" * 40
RELEASE_ID = 321
ROOT = f"repos/{REPOSITORY}"
LIST = f"{ROOT}/releases?per_page=100&page=1"
RELEASE = f"{ROOT}/releases/{RELEASE_ID}"
ASSETS = f"{RELEASE}/assets?per_page=100&page=1"
NOTES = "Immutable preliminary notes.\n"
FINAL_NOTES = "Immutable final notes.\n"


def _release(**changes: object) -> dict[str, Any]:
    return {
        "id": RELEASE_ID,
        "tag_name": TAG,
        "target_commitish": COMMIT,
        "draft": True,
        "prerelease": False,
        "body": NOTES,
        **changes,
    }


def _asset(**changes: object) -> dict[str, object]:
    return {
        "id": 678,
        "name": "SHA256SUMS",
        "state": "uploaded",
        "size": 123,
        **changes,
    }


class FakeAPI:
    def __init__(self, steps: list[tuple[str, str, object]]) -> None:
        self.steps = list(steps)
        self.calls: list[tuple[str, str, Mapping[str, object] | None]] = []

    def request(
        self, method: str, endpoint: str, payload: Mapping[str, object] | None = None
    ) -> state.APIResponse:
        self.calls.append((method, endpoint, payload))
        assert self.steps, f"unexpected API request: {method} {endpoint}"
        expected_method, expected_endpoint, response = self.steps.pop(0)
        assert (method, endpoint) == (expected_method, expected_endpoint)
        if isinstance(response, Exception):
            raise response
        if isinstance(response, state.APIResponse):
            return response
        return state.APIResponse(copy.deepcopy(response))


def _read_steps(release: dict, assets: list | None = None) -> list[tuple[str, str, object]]:
    return [("GET", RELEASE, release), ("GET", ASSETS, [_asset()] if assets is None else assets)]


def test_lookup_reads_later_authenticated_page_containing_draft() -> None:
    first = [_release(id=index + 1, tag_name=f"v0.0.{index}", draft=False) for index in range(100)]
    next_endpoint = f"{ROOT}/releases?per_page=100&page=2"
    api = FakeAPI(
        [
            (
                "GET",
                LIST,
                state.APIResponse(first, f'<{state.API_BASE}{next_endpoint}>; rel="next"'),
            ),
            ("GET", next_endpoint, [_release()]),
        ]
    )
    assert state.find_release(api, REPOSITORY, TAG) == _release()
    assert api.steps == []
    assert all("/releases/tags/" not in endpoint for _, endpoint, _ in api.calls)


def test_full_final_page_requires_absence_probe_even_without_link() -> None:
    first = [_release(id=index + 1, tag_name=f"v0.0.{index}") for index in range(100)]
    api = FakeAPI(
        [
            ("GET", LIST, first),
            ("GET", f"{ROOT}/releases?per_page=100&page=2", []),
        ]
    )
    assert state.find_release(api, REPOSITORY, TAG) is None
    assert len(api.calls) == 2


@pytest.mark.parametrize(
    "document",
    [
        {"message": "rate limit exceeded"},
        [None],
        [_release(id=True)],
        [_release(id="321")],
        [_release(id=0)],
        [_release(draft="true")],
        [_release(prerelease=None)],
        [_release(tag_name="")],
        [_release(), _release(id=999)],
        [_release(), _release(tag_name="v9.9.9")],
    ],
)
def test_lookup_rejects_malformed_or_ambiguous_releases_without_mutation(document: object) -> None:
    api = FakeAPI([("GET", LIST, document)])
    with pytest.raises(ValueError):
        state.ensure_draft(api, repository=REPOSITORY, tag=TAG, source_commit=COMMIT, notes=NOTES)
    assert all(method == "GET" for method, _, _ in api.calls)


@pytest.mark.parametrize(
    "link",
    [
        "malformed",
        '<https://evil.example/releases>; rel="next"',
        f'<{state.API_BASE}{LIST}>; rel="next"',
        f'<{state.API_BASE}{ROOT}/releases?per_page=100&page=3>; rel="next"',
        (
            f'<{state.API_BASE}{ROOT}/releases?per_page=100&page=2>; rel="next", '
            f'<{state.API_BASE}{ROOT}/releases?per_page=100&page=2>; rel="next"'
        ),
    ],
)
def test_lookup_rejects_pagination_ambiguity_before_create(link: str) -> None:
    api = FakeAPI([("GET", LIST, state.APIResponse([], link))])
    with pytest.raises(ValueError, match="pagination"):
        state.ensure_draft(api, repository=REPOSITORY, tag=TAG, source_commit=COMMIT, notes=NOTES)
    assert len(api.calls) == 1


def test_later_listing_failure_never_becomes_absence_or_create() -> None:
    first = [_release(id=index + 1, tag_name=f"v0.0.{index}") for index in range(100)]
    api = FakeAPI(
        [
            ("GET", LIST, first),
            ("GET", f"{ROOT}/releases?per_page=100&page=2", ValueError("HTTP 403")),
        ]
    )
    with pytest.raises(ValueError, match="403"):
        state.ensure_draft(api, repository=REPOSITORY, tag=TAG, source_commit=COMMIT, notes=NOTES)
    assert all(method == "GET" for method, _, _ in api.calls)


def test_pagination_limit_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(state, "MAX_PAGES", 1)
    api = FakeAPI([("GET", LIST, [_release(id=index + 1) for index in range(100)])])
    with pytest.raises(ValueError, match="page limit"):
        state.find_release(api, REPOSITORY, TAG)


def test_create_binds_post_response_numeric_id_and_reads_draft_by_id() -> None:
    api = FakeAPI(
        [
            ("GET", LIST, []),
            (
                "GET",
                f"{ROOT}/git/ref/tags/{TAG}",
                {
                    "ref": f"refs/tags/{TAG}",
                    "object": {"type": "commit", "sha": COMMIT},
                },
            ),
            ("POST", f"{ROOT}/releases", _release()),
            *_read_steps(_release(), []),
        ]
    )
    release = state.ensure_draft(
        api, repository=REPOSITORY, tag=TAG, source_commit=COMMIT, notes=NOTES
    )
    assert release == {**_release(), "assets": []}
    post = next(payload for method, _, payload in api.calls if method == "POST")
    assert post == {
        "tag_name": TAG,
        "target_commitish": COMMIT,
        "name": f"xferry {TAG}",
        "body": NOTES,
        "draft": True,
        "prerelease": False,
        "make_latest": "false",
    }
    assert api.steps == []


def test_existing_draft_resumes_same_numeric_id_without_post() -> None:
    api = FakeAPI([("GET", LIST, [_release()]), *_read_steps(_release())])
    release = state.ensure_draft(
        api, repository=REPOSITORY, tag=TAG, source_commit=COMMIT, notes=NOTES
    )
    assert release["id"] == RELEASE_ID
    assert release["assets"] == [_asset()]
    assert all(method == "GET" for method, _, _ in api.calls)


@pytest.mark.parametrize(
    "changes",
    [
        {"draft": False},
        {"prerelease": True},
        {"body": "different notes"},
        {"target_commitish": "b" * 40},
    ],
)
def test_existing_release_state_or_notes_mismatch_cannot_be_resumed(changes: dict) -> None:
    api = FakeAPI([("GET", LIST, [_release(**changes)])])
    with pytest.raises(ValueError):
        state.ensure_draft(api, repository=REPOSITORY, tag=TAG, source_commit=COMMIT, notes=NOTES)
    assert len(api.calls) == 1


def test_create_requires_verified_tag_source_commit() -> None:
    api = FakeAPI(
        [
            ("GET", LIST, []),
            (
                "GET",
                f"{ROOT}/git/ref/tags/{TAG}",
                {
                    "ref": f"refs/tags/{TAG}",
                    "object": {"type": "commit", "sha": "b" * 40},
                },
            ),
        ]
    )
    with pytest.raises(ValueError, match="bound source"):
        state.ensure_draft(api, repository=REPOSITORY, tag=TAG, source_commit=COMMIT, notes=NOTES)
    assert all(method == "GET" for method, _, _ in api.calls)


def test_annotated_tag_is_resolved_before_creation() -> None:
    tag_sha = "c" * 40
    api = FakeAPI(
        [
            ("GET", LIST, []),
            (
                "GET",
                f"{ROOT}/git/ref/tags/{TAG}",
                {
                    "ref": f"refs/tags/{TAG}",
                    "object": {"type": "tag", "sha": tag_sha},
                },
            ),
            (
                "GET",
                f"{ROOT}/git/tags/{tag_sha}",
                {
                    "sha": tag_sha,
                    "object": {"type": "commit", "sha": COMMIT},
                },
            ),
            ("POST", f"{ROOT}/releases", _release()),
            *_read_steps(_release(), []),
        ]
    )
    assert (
        state.ensure_draft(api, repository=REPOSITORY, tag=TAG, source_commit=COMMIT, notes=NOTES)[
            "id"
        ]
        == RELEASE_ID
    )
    assert api.steps == []


@pytest.mark.parametrize(
    "changes",
    [
        {"id": RELEASE_ID + 1},
        {"tag_name": "v1.2.4"},
        {"draft": "false"},
        {"target_commitish": "main"},
        {"prerelease": True},
    ],
)
def test_bound_get_cannot_switch_numeric_identity_or_state(changes: dict) -> None:
    api = FakeAPI([("GET", RELEASE, _release(**changes))])
    with pytest.raises(ValueError):
        state.read_release(
            api,
            repository=REPOSITORY,
            release_id=RELEASE_ID,
            tag=TAG,
            source_commit=COMMIT,
            state="draft",
        )


@pytest.mark.parametrize(
    "assets",
    [
        [_asset(id=True)],
        [_asset(id="678")],
        [_asset(name="../SHA256SUMS")],
        [_asset(name="-option")],
        [_asset(state="starter")],
        [_asset(size=0)],
        [_asset(size=True)],
        [_asset(), _asset(id=679)],
        [_asset(), _asset(name="other")],
    ],
)
def test_bound_asset_listing_rejects_invalid_or_ambiguous_identity(assets: list) -> None:
    api = FakeAPI(_read_steps(_release(), assets))
    with pytest.raises(ValueError, match="asset"):
        state.read_release(
            api,
            repository=REPOSITORY,
            release_id=RELEASE_ID,
            tag=TAG,
            source_commit=COMMIT,
            state="draft",
        )


def test_expose_patches_only_bound_numeric_id_and_rechecks_public_notes_assets() -> None:
    published = _release(draft=False, body=FINAL_NOTES)
    api = FakeAPI(
        [
            *_read_steps(_release()),
            ("PATCH", RELEASE, published),
            *_read_steps(published),
        ]
    )
    result = state.expose_release(
        api,
        repository=REPOSITORY,
        release_id=RELEASE_ID,
        tag=TAG,
        source_commit=COMMIT,
        notes=FINAL_NOTES,
    )
    assert result == {**published, "assets": [_asset()]}
    assert next(payload for method, _, payload in api.calls if method == "PATCH") == {
        "body": FINAL_NOTES,
        "draft": False,
        "make_latest": "false",
    }
    assert api.steps == []


def test_already_published_release_is_read_only_and_requires_identical_final_notes() -> None:
    published = _release(draft=False, body=FINAL_NOTES)
    api = FakeAPI([*_read_steps(published), *_read_steps(published)])
    assert (
        state.expose_release(
            api,
            repository=REPOSITORY,
            release_id=RELEASE_ID,
            tag=TAG,
            source_commit=COMMIT,
            notes=FINAL_NOTES,
        )["draft"]
        is False
    )
    assert all(method == "GET" for method, _, _ in api.calls)
    wrong = FakeAPI(_read_steps(_release(draft=False, body="wrong")))
    with pytest.raises(ValueError, match="final immutable notes"):
        state.expose_release(
            wrong,
            repository=REPOSITORY,
            release_id=RELEASE_ID,
            tag=TAG,
            source_commit=COMMIT,
            notes=FINAL_NOTES,
        )
    assert all(method == "GET" for method, _, _ in wrong.calls)


def test_exposure_rejects_asset_replacement_even_with_same_name_and_size() -> None:
    published = _release(draft=False, body=FINAL_NOTES)
    api = FakeAPI(
        [
            *_read_steps(_release()),
            ("PATCH", RELEASE, published),
            *_read_steps(published, [_asset(id=999)]),
        ]
    )
    with pytest.raises(ValueError, match="asset identities changed"):
        state.expose_release(
            api,
            repository=REPOSITORY,
            release_id=RELEASE_ID,
            tag=TAG,
            source_commit=COMMIT,
            notes=FINAL_NOTES,
        )


@pytest.mark.parametrize("status", [403, 404, 429, 500])
def test_http_errors_never_become_absence(status: int, monkeypatch: pytest.MonkeyPatch) -> None:
    class Opener:
        def open(self, request: Any, timeout: int) -> NoReturn:
            raise urllib.error.HTTPError(request.full_url, status, "failure", {}, None)

    monkeypatch.setattr(state.urllib.request, "build_opener", lambda *_args: Opener())
    api = state.GitHubReleaseAPI("fake-token")
    with pytest.raises(ValueError, match=f"HTTP {status}"):
        state.ensure_draft(api, repository=REPOSITORY, tag=TAG, source_commit=COMMIT, notes=NOTES)


@pytest.mark.parametrize("raw", [b"not JSON", b'{"id":1,"id":2}', b'{"id":NaN}'])
def test_transport_rejects_malformed_json(raw: bytes, monkeypatch: pytest.MonkeyPatch) -> None:
    class Response(io.BytesIO):
        status = 200
        headers: dict[str, str] = {}

    class Opener:
        def open(self, request: Any, timeout: int) -> Response:
            assert request.full_url == f"{state.API_BASE}{LIST}"
            assert request.get_header("Authorization") == "Bearer fake-token"
            assert timeout == 30
            return Response(raw)

    monkeypatch.setattr(state.urllib.request, "build_opener", lambda *_args: Opener())
    with pytest.raises(ValueError, match="invalid JSON"):
        state.GitHubReleaseAPI("fake-token").request("GET", LIST)


def test_transport_never_redirects_authentication() -> None:
    request = state.urllib.request.Request(f"{state.API_BASE}{LIST}")
    assert (
        state._NoRedirect().redirect_request(
            request, None, 302, "found", {}, "https://evil.example/"
        )
        is None
    )


def test_cli_exports_only_numeric_bound_id_and_state_document(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    api = FakeAPI([("GET", LIST, [_release()]), *_read_steps(_release())])
    monkeypatch.setenv("GH_TOKEN", "fake-token")
    monkeypatch.setattr(state, "GitHubReleaseAPI", lambda _token: api)
    notes = tmp_path / "notes.md"
    notes.write_text(NOTES)
    output = tmp_path / "release.json"
    assert (
        state.main(
            [
                "draft",
                "--repository",
                REPOSITORY,
                "--tag",
                TAG,
                "--source-commit",
                COMMIT,
                "--notes-file",
                str(notes),
                "--output",
                str(output),
            ]
        )
        == 0
    )
    assert capsys.readouterr().out == f"{RELEASE_ID}\n"
    assert json.loads(output.read_text()) == {**_release(), "assets": [_asset()]}


def test_cli_listing_failure_creates_no_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    api = FakeAPI([("GET", LIST, ValueError("HTTP 403"))])
    monkeypatch.setenv("GH_TOKEN", "fake-token")
    monkeypatch.setattr(state, "GitHubReleaseAPI", lambda _token: api)
    notes = tmp_path / "notes.md"
    notes.write_text(NOTES)
    output = tmp_path / "release.json"
    assert (
        state.main(
            [
                "draft",
                "--repository",
                REPOSITORY,
                "--tag",
                TAG,
                "--source-commit",
                COMMIT,
                "--notes-file",
                str(notes),
                "--output",
                str(output),
            ]
        )
        == 1
    )
    assert not output.exists()
    result = capsys.readouterr()
    assert result.out == ""
    assert "HTTP 403" in result.err
