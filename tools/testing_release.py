"""Record manual VPS acceptance and guard the final rebuild of an accepted preview."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
import urllib.request
from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tools.testing_build import REPOSITORY, TestingIdentity  # noqa: E402
from xferry.management.channels import (  # noqa: E402
    TESTING_IMAGES_NAME,
    parse_testing_images,
    release_tag,
)
from xferry.management.release_contract import (  # noqa: E402
    SUPPORTED_PLATFORM_IDS,
    release_manifest_asset_name,
    require_source_commit,
)
from xferry.management.release_trust import verify_signed_manifest  # noqa: E402

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10
    from setuptools._vendor import tomli as tomllib  # type: ignore[no-redef]

ACCEPTANCE_NAME = "testing-acceptance.json"


def fetch_asset(version: str, name: str, *, limit: int = 1024 * 1024) -> bytes:
    if "/" in name or not name or ".." in name:
        raise ValueError("invalid preview asset name")
    tag = release_tag(version, "testing")
    url = f"https://github.com/{REPOSITORY}/releases/download/{tag}/{name}"
    with urllib.request.urlopen(url, timeout=30) as response:
        payload = bytes(response.read(limit + 1))
    if not payload or len(payload) > limit:
        raise ValueError("preview metadata size exceeds its limit")
    return payload


def verify_ready(
    ready: Mapping[str, Any], manifests: Mapping[str, tuple[bytes, bytes]], catalog: bytes
) -> TestingIdentity:
    identity = TestingIdentity.create(
        ready["target_version"], ready["source_commit"], ready["workflow_run"], ready["run_attempt"]
    )
    if any(ready.get(key) != value for key, value in vars(identity).items()):
        raise ValueError("ready report identity is inconsistent")
    if ready.get("schema") != 1 or ready.get("manual_acceptance") != "pending":
        raise ValueError("ready report is not a completed testing build")
    if set(manifests) != set(SUPPORTED_PLATFORM_IDS):
        raise ValueError("both supported testing platforms are required")
    for platform, (payload, signature) in manifests.items():
        manifest = verify_signed_manifest(payload, signature, channel="testing")
        if (
            manifest.version,
            manifest.source_commit,
            manifest.build_id,
            manifest.platform,
            manifest.workflow_run,
        ) != (
            identity.version,
            identity.source_commit,
            identity.build_id,
            platform,
            identity.workflow_run,
        ):
            raise ValueError("ready report differs from signed testing identity")
        if parse_testing_images(catalog, manifest) != ready.get("image"):
            raise ValueError("ready image differs from signed testing catalog")
        digests = dict(manifest.artifact_digests)
        required = {
            TESTING_IMAGES_NAME,
            f"xferry-{identity.version}-py3-none-any.whl",
            f"xferry-{identity.version}.tar.gz",
            manifest.executable_name,
            f"install-{platform}.sh",
        }
        if not required.issubset(digests):
            raise ValueError("signed preview inventory is incomplete")
        for name in required:
            if ready.get("assets", {}).get(name, {}).get("sha256") != digests[name]:
                raise ValueError("ready asset differs from signed testing inventory")
    return identity


def verified_preview(version: str) -> tuple[TestingIdentity, dict[str, Any]]:
    report = json.loads(fetch_asset(version, "testing-ready.json"))
    if not isinstance(report, dict):
        raise ValueError("ready report must be an object")
    manifests: dict[str, tuple[bytes, bytes]] = {
        platform: (
            fetch_asset(version, release_manifest_asset_name(platform)),
            fetch_asset(version, f"{release_manifest_asset_name(platform)}.sig"),
        )
        for platform in SUPPORTED_PLATFORM_IDS
    }
    identity = verify_ready(report, manifests, fetch_asset(version, TESTING_IMAGES_NAME))
    if identity.version != version:
        raise ValueError("preview version mismatch")
    return identity, report


def acceptance_record(
    identity: TestingIdentity, ready: Mapping[str, Any], actor: str, workflow_run: str
) -> dict[str, Any]:
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]{0,38}(?:\[bot\])?", actor):
        raise ValueError("acceptance requires a GitHub actor")
    if not re.fullmatch(r"[1-9][0-9]*", workflow_run):
        raise ValueError("acceptance requires a workflow run")
    payload = (json.dumps(ready, sort_keys=True, indent=2, allow_nan=False) + "\n").encode()
    return {
        "schema": 1,
        "status": "accepted",
        "channel": "testing",
        "version": identity.version,
        "target_version": identity.target_version,
        "source_commit": identity.source_commit,
        "build_id": identity.build_id,
        "actor": actor,
        "accepted_at": datetime.now(timezone.utc).isoformat(),
        "acceptance_workflow_run": workflow_run,
        "ready_sha256": hashlib.sha256(payload).hexdigest(),
        "checks": ["clean-vps", "upgrade", "health", "persistence", "rollback"],
    }


def _git_file(workspace: Path, commit: str, name: str) -> bytes:
    return subprocess.check_output(["git", "show", f"{commit}:{name}"], cwd=workspace)


def _normalize_version_file(name: str, payload: bytes) -> bytes:
    text = payload.decode()
    if name == "xferry/config.py":
        return re.sub(r'(?m)^__version__ = "[^"]+"$', '__version__ = "VERSION"', text).encode()
    if name == "xferry/data/index.html":
        return re.sub(
            r'id="appVersion"\s+data-app-version="[^"]+">v[^<]+</p>',
            'id="appVersion" data-app-version="VERSION">vVERSION</p>',
            text,
        ).encode()
    if name == "README.md":
        return re.sub(r"version-[^-\s/]+-orange\.svg", "version-VERSION-orange.svg", text).encode()
    if name == "docs/cli-reference.md":
        version = r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
        text = re.sub(
            r"(?m)^(  --to VERSION          Signed release version to install \(default: )"
            + version
            + r"(\)\.)$",
            r"\g<1>VERSION\g<2>",
            text,
        )
        return re.sub(
            r"(?m)^(Example: xferry update --to )" + version + r"$",
            r"\g<1>VERSION",
            text,
        ).encode()
    if name == "packaging/channels.toml":
        document = tomllib.loads(text)
        document.pop("promotion", None)
        document["testing"]["target_version"] = "VERSION"
        return json.dumps(document, sort_keys=True).encode()
    raise ValueError("functional or dependency change requires another testing build")


def validate_final_diff(workspace: Path, preview_commit: str, final_commit: str) -> None:
    """A final rebuild may change only version markers, changelog and promotion metadata."""
    require_source_commit(preview_commit)
    require_source_commit(final_commit)
    subprocess.run(
        ["git", "merge-base", "--is-ancestor", preview_commit, final_commit],
        cwd=workspace,
        check=True,
    )
    names = subprocess.check_output(
        ["git", "diff", "--name-only", "-z", preview_commit, final_commit], cwd=workspace
    ).split(b"\0")
    for raw in names:
        if not raw:
            continue
        name = raw.decode()
        if name in {"CHANGELOG.md", "docs/changelog.md"}:
            continue
        before = _normalize_version_file(name, _git_file(workspace, preview_commit, name))
        after = _normalize_version_file(name, _git_file(workspace, final_commit, name))
        if before != after:
            raise ValueError(f"{name} changes behavior; test a new preview before release")


def verify_acceptance(
    record: Mapping[str, Any], identity: TestingIdentity, ready: Mapping[str, Any]
) -> None:
    expected = acceptance_record(
        identity, ready, record.get("actor", ""), record.get("acceptance_workflow_run", "")
    )
    for key in expected:
        if key != "accepted_at" and record.get(key) != expected[key]:
            raise ValueError("manual acceptance does not match the exact ready preview")
    when = datetime.fromisoformat(record.get("accepted_at", ""))
    if when.tzinfo is None or when > datetime.now(timezone.utc):
        raise ValueError("manual acceptance timestamp is invalid")


def verify_acceptance_run(
    run: Mapping[str, Any],
    jobs: Mapping[str, Any],
    identity: TestingIdentity,
    record: Mapping[str, Any],
) -> None:
    title = f"Accept {identity.version} ({identity.build_id}) from {identity.source_commit}"
    if (
        run.get("path") != ".github/workflows/testing-acceptance.yml"
        or run.get("event") != "workflow_dispatch"
        or run.get("head_branch") != "main"
        or run.get("status") != "completed"
        or run.get("conclusion") != "success"
        or run.get("display_title") != title
        or run.get("repository", {}).get("full_name") != REPOSITORY
        or run.get("actor", {}).get("login") != record["actor"]
    ):
        raise ValueError("manual acceptance was not produced by the trusted acceptance workflow")
    accepted = [job for job in jobs.get("jobs", []) if job.get("name") == "accept"]
    if len(accepted) != 1 or accepted[0].get("conclusion") != "success":
        raise ValueError("manual acceptance job did not run successfully")
    step = "Record explicit acceptance of the authenticated preview"
    if not any(
        item.get("name") == step and item.get("conclusion") == "success"
        for item in accepted[0].get("steps", [])
    ):
        raise ValueError("manual VPS confirmation was not recorded")


def promotion_preflight(workspace: Path, final_commit: str, final_version: str) -> None:
    document = tomllib.loads(_git_file(workspace, final_commit, "packaging/channels.toml").decode())
    promotion = document.get("promotion")
    if not isinstance(promotion, dict) or set(promotion) != {
        "version",
        "source_commit",
        "build_id",
    }:
        raise ValueError("set exact accepted preview in packaging/channels.toml [promotion]")
    identity, ready = verified_preview(promotion["version"])
    if (promotion["source_commit"], promotion["build_id"], final_version) != (
        identity.source_commit,
        identity.build_id,
        identity.target_version,
    ):
        raise ValueError("stable source does not match the selected testing build")
    record = json.loads(fetch_asset(identity.version, ACCEPTANCE_NAME))
    if not isinstance(record, dict):
        raise ValueError("manual acceptance receipt must be an object")
    verify_acceptance(record, identity, ready)
    run_id = record["acceptance_workflow_run"]
    run = json.loads(
        subprocess.check_output(
            ["gh", "api", f"repos/{REPOSITORY}/actions/runs/{run_id}"], text=True
        )
    )
    jobs = json.loads(
        subprocess.check_output(
            ["gh", "api", f"repos/{REPOSITORY}/actions/runs/{run_id}/jobs?per_page=100"], text=True
        )
    )
    verify_acceptance_run(run, jobs, identity, record)
    subprocess.run(
        [
            "git",
            "merge-base",
            "--is-ancestor",
            require_source_commit(run["head_sha"]),
            final_commit,
        ],
        cwd=workspace,
        check=True,
    )
    validate_final_diff(workspace, identity.source_commit, final_commit)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_subparsers(dest="action", required=True)
    accept = actions.add_parser("accept")
    accept.add_argument("--version", required=True)
    accept.add_argument("--source-commit", required=True)
    accept.add_argument("--build-id", required=True)
    accept.add_argument("--actor", required=True)
    accept.add_argument("--workflow-run", required=True)
    accept.add_argument("--output", type=Path, required=True)
    final = actions.add_parser("preflight")
    final.add_argument("--workspace", type=Path, default=REPO_ROOT)
    final.add_argument("--source-commit", required=True)
    final.add_argument("--version", required=True)
    args = parser.parse_args(argv)
    try:
        if args.action == "accept":
            identity, ready = verified_preview(args.version)
            if (identity.source_commit, identity.build_id) != (args.source_commit, args.build_id):
                raise ValueError("manual acceptance must name the exact source and build ID")
            record = acceptance_record(identity, ready, args.actor, args.workflow_run)
            args.output.write_text(json.dumps(record, indent=2) + "\n")
        else:
            promotion_preflight(args.workspace, args.source_commit, args.version)
    except (OSError, ValueError, KeyError, TypeError, subprocess.CalledProcessError) as error:
        print(f"testing release failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
