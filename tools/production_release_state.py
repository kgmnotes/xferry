"""Resolve authenticated production drafts and publish only their bound release ID."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.request
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, NoReturn, Protocol

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tools.check_release_preflight import version_from_tag  # noqa: E402

PRODUCTION_REPOSITORY = "kgmnotes/xferry"
API_BASE = "https://api.github.com/"
PAGE_SIZE = 100
MAX_PAGES = 1_000
MAX_RESPONSE_BYTES = 16 * 1024 * 1024
_COMMIT_RE = re.compile(r"[0-9a-f]{40}\Z")
_ASSET_NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*\Z")
_LINK_RE = re.compile(r'<([^<>]+)>;\s*rel="([a-z]+)"\Z')


@dataclass(frozen=True)
class APIResponse:
    document: object
    link: str | None = None


class ReleaseAPI(Protocol):
    def request(
        self, method: str, endpoint: str, payload: Mapping[str, object] | None = None
    ) -> APIResponse: ...


def _duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    document: dict[str, object] = {}
    for key, value in pairs:
        if key in document:
            raise ValueError("duplicate GitHub API JSON key")
        document[key] = value
    return document


def _invalid_constant(_value: str) -> NoReturn:
    raise ValueError("non-finite GitHub API JSON value")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> None:
        return None


class GitHubReleaseAPI:
    """JSON-only transport; authentication is never forwarded through a redirect."""

    def __init__(self, token: str) -> None:
        if not token or any(character.isspace() for character in token):
            raise ValueError("an authenticated GitHub token is required")
        self._token = token
        self._opener = urllib.request.build_opener(_NoRedirect())

    def request(
        self, method: str, endpoint: str, payload: Mapping[str, object] | None = None
    ) -> APIResponse:
        if not endpoint.startswith(f"repos/{PRODUCTION_REPOSITORY}/") or any(
            character in endpoint for character in ("#", "\\", "\r", "\n")
        ):
            raise ValueError("GitHub API endpoint is outside the production repository")
        body = json.dumps(dict(payload), allow_nan=False).encode() if payload is not None else None
        request = urllib.request.Request(
            API_BASE + endpoint,
            data=body,
            method=method,
            headers={
                "Authorization": f"Bearer {self._token}",
                "Accept": "application/vnd.github+json",
                "Content-Type": "application/json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )
        try:
            with self._opener.open(request, timeout=30) as response:
                expected_status = 201 if method == "POST" else 200
                if response.status != expected_status:
                    raise ValueError(f"unexpected GitHub API status: {response.status}")
                raw = response.read(MAX_RESPONSE_BYTES + 1)
                link = response.headers.get("Link")
        except urllib.error.HTTPError as error:
            raise ValueError(
                f"unable to establish GitHub release state (HTTP {error.code})"
            ) from None
        except urllib.error.URLError:
            raise ValueError(
                "unable to establish GitHub release state (transport failure)"
            ) from None
        if len(raw) > MAX_RESPONSE_BYTES:
            raise ValueError("GitHub release API response is too large")
        try:
            document = json.loads(
                raw, object_pairs_hook=_duplicate_keys, parse_constant=_invalid_constant
            )
        except (UnicodeError, ValueError) as error:
            raise ValueError("GitHub release API response is invalid JSON") from error
        return APIResponse(document, link)


def _positive_id(value: object, label: str) -> int:
    if type(value) is not int or value <= 0:
        raise ValueError(f"{label} must be a positive numeric GitHub ID")
    return value


def _scope(repository: str, tag: str, source_commit: str) -> None:
    if repository != PRODUCTION_REPOSITORY:
        raise ValueError("release repository is not the production repository")
    version_from_tag(tag)
    if _COMMIT_RE.fullmatch(source_commit) is None:
        raise ValueError("release source must be a full lowercase commit SHA")


def _release(document: object) -> dict[str, Any]:
    if not isinstance(document, dict):
        raise ValueError("GitHub release must be an object")
    _positive_id(document.get("id"), "release ID")
    if not isinstance(document.get("tag_name"), str) or not document["tag_name"]:
        raise ValueError("GitHub release tag must be a nonempty string")
    if type(document.get("draft")) is not bool or type(document.get("prerelease")) is not bool:
        raise ValueError("GitHub release draft and prerelease states must be booleans")
    return document


def _next_page(link: str | None, endpoint: str, page: int) -> bool:
    if link is None:
        return False
    relations: dict[str, str] = {}
    for item in link.split(","):
        match = _LINK_RE.fullmatch(item.strip())
        if match is None or match[2] in relations:
            raise ValueError("GitHub release pagination Link is malformed or ambiguous")
        relations[match[2]] = match[1]
    next_url = relations.get("next")
    if next_url is None:
        return False
    expected = f"{API_BASE}{endpoint}?per_page={PAGE_SIZE}&page={page + 1}"
    if next_url != expected:
        raise ValueError("GitHub release pagination escaped its exact next page")
    return True


def _pages(api: ReleaseAPI, endpoint: str) -> list[object]:
    """Read every page before treating absence as authoritative; never swallow errors."""
    documents: list[object] = []
    for page in range(1, MAX_PAGES + 1):
        response = api.request("GET", f"{endpoint}?per_page={PAGE_SIZE}&page={page}")
        if not isinstance(response.document, list) or len(response.document) > PAGE_SIZE:
            raise ValueError("GitHub release pagination page must be a bounded array")
        has_next = _next_page(response.link, endpoint, page)
        if has_next and len(response.document) != PAGE_SIZE:
            raise ValueError("GitHub release pagination has a truncated non-final page")
        documents.extend(response.document)
        if not has_next and len(response.document) < PAGE_SIZE:
            return documents
        # A full page without a Link still requires an explicit final-page probe.
    raise ValueError("GitHub release pagination exceeded the bounded page limit")


def find_release(api: ReleaseAPI, repository: str, tag: str) -> dict[str, Any] | None:
    """Authenticated release listings include drafts; the by-tag endpoint does not."""
    if repository != PRODUCTION_REPOSITORY:
        raise ValueError("release repository is not the production repository")
    version_from_tag(tag)
    documents = _pages(api, f"repos/{repository}/releases")
    matches: list[dict[str, Any]] = []
    seen: set[int] = set()
    for document in documents:
        release = _release(document)
        release_id = _positive_id(release["id"], "release ID")
        if release_id in seen:
            raise ValueError("GitHub release listing repeats a numeric ID across pages")
        seen.add(release_id)
        if release["tag_name"] == tag:
            matches.append(release)
    if len(matches) > 1:
        raise ValueError("GitHub release tag is ambiguous in authenticated listings")
    return matches[0] if matches else None


def _assets(api: ReleaseAPI, repository: str, release_id: int) -> list[dict[str, Any]]:
    documents = _pages(api, f"repos/{repository}/releases/{release_id}/assets")
    result: list[dict[str, Any]] = []
    seen_ids: set[int] = set()
    seen_names: set[str] = set()
    for document in documents:
        if not isinstance(document, dict):
            raise ValueError("GitHub release asset must be an object")
        asset_id = _positive_id(document.get("id"), "asset ID")
        name = document.get("name")
        size = document.get("size")
        if (
            not isinstance(name, str)
            or _ASSET_NAME_RE.fullmatch(name) is None
            or type(size) is not int
            or size <= 0
            or document.get("state") != "uploaded"
            or asset_id in seen_ids
            or name in seen_names
        ):
            raise ValueError("GitHub release asset identity, size, or upload state is invalid")
        seen_ids.add(asset_id)
        seen_names.add(name)
        result.append(document)
    return result


def _bound_release(
    document: object,
    *,
    release_id: int,
    tag: str,
    source_commit: str,
    state: str,
    notes: str | None,
) -> dict[str, Any]:
    release = _release(document)
    if (
        release["id"] != release_id
        or release["tag_name"] != tag
        or release["prerelease"] is not False
        or release.get("target_commitish") != source_commit
        or (state == "draft" and release["draft"] is not True)
        or (state == "published" and release["draft"] is not False)
    ):
        raise ValueError(
            "numeric GitHub release identity or state differs from the bound candidate"
        )
    if notes is not None and release.get("body") != notes:
        label = "preliminary" if state == "draft" else "final"
        destination = "existing draft" if state == "draft" else "public Release"
        raise ValueError(f"{label} immutable notes differ from {destination} body")
    return release


def read_release(
    api: ReleaseAPI,
    *,
    repository: str,
    release_id: int,
    tag: str,
    source_commit: str,
    state: str,
    notes: str | None = None,
) -> dict[str, Any]:
    _scope(repository, tag, source_commit)
    _positive_id(release_id, "release ID")
    if state not in {"draft", "published", "either"}:
        raise ValueError("release state must be draft, published, or either")
    response = api.request("GET", f"repos/{repository}/releases/{release_id}")
    release = _bound_release(
        response.document,
        release_id=release_id,
        tag=tag,
        source_commit=source_commit,
        state=state,
        notes=notes,
    )
    release = dict(release)
    release["assets"] = _assets(api, repository, release_id)
    return release


def _verify_tag(api: ReleaseAPI, repository: str, tag: str, source_commit: str) -> None:
    response = api.request("GET", f"repos/{repository}/git/ref/tags/{tag}")
    document = response.document
    if not isinstance(document, dict) or document.get("ref") != f"refs/tags/{tag}":
        raise ValueError("the exact production tag could not be verified before draft creation")
    target = document.get("object")
    for _ in range(16):
        if not isinstance(target, dict):
            raise ValueError("production tag target is malformed")
        sha = target.get("sha")
        if not isinstance(sha, str) or _COMMIT_RE.fullmatch(sha) is None:
            raise ValueError("production tag target is not a full commit or tag SHA")
        if target.get("type") == "commit":
            if sha != source_commit:
                raise ValueError("production tag does not target the bound source commit")
            return
        if target.get("type") != "tag":
            raise ValueError("production tag does not resolve to a commit")
        document = api.request("GET", f"repos/{repository}/git/tags/{sha}").document
        if not isinstance(document, dict) or document.get("sha") != sha:
            raise ValueError("annotated production tag identity is malformed")
        target = document.get("object")
    raise ValueError("production annotated tag chain exceeds its bounded depth")


def ensure_draft(
    api: ReleaseAPI, *, repository: str, tag: str, source_commit: str, notes: str
) -> dict[str, Any]:
    _scope(repository, tag, source_commit)
    existing = find_release(api, repository, tag)
    if existing is None:
        _verify_tag(api, repository, tag, source_commit)
        response = api.request(
            "POST",
            f"repos/{repository}/releases",
            {
                "tag_name": tag,
                "target_commitish": source_commit,
                "name": f"xferry {tag}",
                "body": notes,
                "draft": True,
                "prerelease": False,
                "make_latest": "false",
            },
        )
        existing = _release(response.document)
    release_id = _positive_id(existing["id"], "release ID")
    _bound_release(
        existing,
        release_id=release_id,
        tag=tag,
        source_commit=source_commit,
        state="draft",
        notes=notes,
    )
    return read_release(
        api,
        repository=repository,
        release_id=release_id,
        tag=tag,
        source_commit=source_commit,
        state="draft",
        notes=notes,
    )


def _asset_identities(release: Mapping[str, Any]) -> set[tuple[int, str, int, str]]:
    return {
        (asset["id"], asset["name"], asset["size"], asset["state"]) for asset in release["assets"]
    }


def expose_release(
    api: ReleaseAPI,
    *,
    repository: str,
    release_id: int,
    tag: str,
    source_commit: str,
    notes: str,
) -> dict[str, Any]:
    before = read_release(
        api,
        repository=repository,
        release_id=release_id,
        tag=tag,
        source_commit=source_commit,
        state="either",
    )
    if before["draft"]:
        response = api.request(
            "PATCH",
            f"repos/{repository}/releases/{release_id}",
            {"body": notes, "draft": False, "make_latest": "false"},
        )
        _bound_release(
            response.document,
            release_id=release_id,
            tag=tag,
            source_commit=source_commit,
            state="published",
            notes=notes,
        )
    else:
        _bound_release(
            before,
            release_id=release_id,
            tag=tag,
            source_commit=source_commit,
            state="published",
            notes=notes,
        )
    published = read_release(
        api,
        repository=repository,
        release_id=release_id,
        tag=tag,
        source_commit=source_commit,
        state="published",
        notes=notes,
    )
    if _asset_identities(before) != _asset_identities(published):
        raise ValueError("GitHub release asset identities changed during publication")
    return published


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("draft", "read", "expose"))
    parser.add_argument("--repository", required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--release-id", type=int)
    parser.add_argument("--state", choices=("draft", "published", "either"), default="draft")
    parser.add_argument("--notes-file", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    if args.command != "draft" and args.release_id is None:
        parser.error("read and expose require --release-id")
    if args.command != "read" and args.notes_file is None:
        parser.error("draft and expose require --notes-file")
    try:
        api = GitHubReleaseAPI(os.environ.get("GH_TOKEN", ""))
        notes = args.notes_file.read_text(encoding="utf-8") if args.notes_file is not None else None
        common = {
            "repository": args.repository,
            "tag": args.tag,
            "source_commit": args.source_commit,
        }
        if args.command == "draft":
            assert notes is not None
            release = ensure_draft(api, **common, notes=notes)
        elif args.command == "expose":
            assert notes is not None
            release = expose_release(api, **common, release_id=args.release_id, notes=notes)
        else:
            release = read_release(
                api, **common, release_id=args.release_id, state=args.state, notes=notes
            )
        args.output.write_text(
            json.dumps(release, indent=2, sort_keys=True, allow_nan=False) + "\n", encoding="utf-8"
        )
        print(release["id"])
    except (OSError, UnicodeError, ValueError) as error:
        print(f"production release state failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
