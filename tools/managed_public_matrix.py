"""Anonymous, signed two-public-version native systemd acceptance; never publishes."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import sys
import tempfile
import urllib.request
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any, NoReturn, cast
from urllib.parse import urljoin, urlsplit

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tools import managed_systemd_matrix as fixture  # noqa: E402
from xferry.management.release_contract import (  # noqa: E402
    SUPPORTED_PLATFORM_IDS,
    artifact_name,
    release_manifest_asset_name,
    require_platform_id,
    require_source_commit,
    require_workflow_run,
)
from xferry.management.release_trust import (  # noqa: E402
    DEFAULT_RELEASE_KEY_RING,
    INSTALLER_SIGNATURE_TYPE,
    ReleaseKeyRing,
    verify_detached_signature,
    verify_signed_manifest,
)

SCHEMA = 2
REPOSITORY = "kgmnotes/xferry"
API = f"https://api.github.com/repos/{REPOSITORY}"
RELEASES = f"https://github.com/{REPOSITORY}/releases/download"
PLAN_SCOPE = "managed-public-lifecycle-plan"
ARCH_SCOPE = "native-systemd-public-architecture"
RESULT_SCOPE = "native-systemd-public-matrix"
PROBE_SCOPE = "native-systemd-public-lifecycle"
_STABLE = re.compile(r"v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\Z")
_SHA = re.compile(r"[0-9a-f]{64}\Z")
_HOSTS = frozenset(
    {
        "api.github.com",
        "github.com",
        "release-assets.githubusercontent.com",
        "objects.githubusercontent.com",
        "github-releases.githubusercontent.com",
    }
)
_CODES = frozenset(
    {
        "public_baseline_required",
        "public_release_invalid",
        "public_plan_invalid",
        "public_matrix_invalid",
        "public_download_failed",
        "public_list_incomplete",
        "public_host_required",
        "public_probe_failed",
        "public_cleanup_failed",
    }
)
Fetch = Callable[[str, int], bytes]


class PublicFailure(RuntimeError):
    """Only stable, nonsecret codes cross the evidence boundary."""

    def __init__(self, code: str) -> None:
        super().__init__(code if code in _CODES else "public_matrix_invalid")


def _require(condition: bool, code: str = "public_plan_invalid") -> None:
    if not condition:
        raise PublicFailure(code)


def _object(value: object, fields: set[str]) -> dict[str, Any]:
    _require(isinstance(value, dict) and set(value) == fields)
    return dict(cast(dict[str, Any], value))


def _pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
    document: dict[str, Any] = {}
    for key, value in items:
        _require(key not in document)
        document[key] = value
    return document


def _constant(_value: str) -> NoReturn:
    raise PublicFailure("public_plan_invalid")


def _json(payload: bytes) -> Any:
    return json.loads(payload, object_pairs_hook=_pairs, parse_constant=_constant)


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def _sha(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _tag(value: object) -> tuple[int, int, int]:
    _require(isinstance(value, str) and _STABLE.fullmatch(value) is not None)
    return cast(tuple[int, int, int], tuple(map(int, cast(str, value)[1:].split("."))))


def _arguments(source: str, run: str, attempt: int) -> None:
    try:
        require_source_commit(source)
        require_workflow_run(run)
    except ValueError:
        raise PublicFailure("public_plan_invalid") from None
    _require(isinstance(run, str) and re.fullmatch(r"[1-9][0-9]*", run) is not None)
    _require(type(attempt) is int and attempt > 0)


def _url(value: str) -> None:
    parsed = urlsplit(value)
    _require(
        parsed.scheme == "https"
        and parsed.hostname in _HOSTS
        and parsed.port in (None, 443)
        and parsed.username is None
        and parsed.password is None
        and not parsed.fragment,
        "public_download_failed",
    )


class _Redirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str
    ) -> Any:
        _url(urljoin(req.full_url, newurl))
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def fetch_public(url: str, limit: int) -> bytes:
    """Credential-free HTTPS; validate redirects and bound the actual response."""
    _url(url)
    try:
        request = urllib.request.Request(url, headers={"User-Agent": "xferry-public-acceptance"})
        with urllib.request.build_opener(_Redirect()).open(request, timeout=30) as response:
            _url(response.geturl())
            payload = response.read(limit + 1)
        _require(0 < len(payload) <= limit, "public_download_failed")
        return cast(bytes, payload)
    except PublicFailure:
        raise
    except Exception:
        raise PublicFailure("public_download_failed") from None


def _decode(value: object, limit: int) -> bytes:
    _require(isinstance(value, str) and len(value) <= (limit + 2) // 3 * 4)
    try:
        payload = base64.b64decode(cast(str, value), validate=True)
    except ValueError:
        raise PublicFailure("public_plan_invalid") from None
    _require(0 < len(payload) <= limit and base64.b64encode(payload).decode() == value)
    return payload


def _record(payload: bytes) -> dict[str, Any]:
    return {"size": len(payload), "sha256": _sha(payload)}


def _helpers() -> dict[str, str]:
    return {
        "matrixSha": fixture._sha(Path(__file__)),
        "probeSha": fixture._sha(REPO_ROOT / "tools/managed_public_probe.py"),
        "commonProbeSha": fixture._sha(REPO_ROOT / "tools/managed_systemd_probe.py"),
        "containerHelperSha": fixture._sha(REPO_ROOT / "tools/managed_systemd_matrix.py"),
    }


def _verify_release(document: object, ring: ReleaseKeyRing) -> dict[str, Any]:
    result = _object(
        document, {"tag", "version", "sourceCommit", "workflowRun", "releaseId", "platforms"}
    )
    _tag(result["tag"])
    _require(result["version"] == result["tag"][1:])
    _arguments(result["sourceCommit"], result["workflowRun"], 1)
    _require(type(result["releaseId"]) is int and result["releaseId"] > 0)
    platforms = _object(result["platforms"], set(SUPPORTED_PLATFORM_IDS))
    for platform, raw in platforms.items():
        platform_id = require_platform_id(platform)
        item = _object(
            raw,
            {
                "manifestPayload",
                "manifestSignature",
                "installerPayload",
                "installerSignature",
                "assets",
            },
        )
        payload = _decode(item["manifestPayload"], 64 * 1024)
        signature = _decode(item["manifestSignature"], 4 * 1024)
        installer_signature = _decode(item["installerSignature"], 4 * 1024)
        installer_payload = _decode(item["installerPayload"], 1024 * 1024)
        manifest = verify_signed_manifest(payload, signature, key_ring=ring)
        _require(not any("rehearsal" in key for key in manifest.signing_key_ids))
        _require(
            manifest.version == result["version"]
            and manifest.tag == result["tag"]
            and manifest.platform == platform
            and manifest.source_commit == result["sourceCommit"]
            and manifest.workflow_run == result["workflowRun"]
        )
        manifest_name = release_manifest_asset_name(platform_id)
        installer = f"install-{platform}.sh"
        executable = artifact_name(result["version"], platform_id)
        expected = {
            manifest_name,
            manifest_name + ".sig",
            installer,
            installer + ".sig",
            executable,
        }
        assets = _object(item["assets"], expected)
        for name, asset in assets.items():
            record = _object(asset, {"size", "sha256"})
            cap = 256 * 1024 * 1024 if name == executable else 1024 * 1024
            _require(
                type(record["size"]) is int
                and 0 < record["size"] <= cap
                and isinstance(record["sha256"], str)
                and _SHA.fullmatch(record["sha256"]) is not None
            )
        _require(
            assets[manifest_name] == _record(payload)
            and assets[manifest_name + ".sig"] == _record(signature)
            and assets[installer] == _record(installer_payload)
            and assets[installer + ".sig"] == _record(installer_signature)
        )
        digests = dict(manifest.artifact_digests)
        _require(
            digests.get(installer) == assets[installer]["sha256"]
            and assets[executable]
            == {"size": manifest.executable_size, "sha256": manifest.executable_sha256}
        )
        signer = verify_detached_signature(
            installer_payload,
            installer_signature,
            payload_type=INSTALLER_SIGNATURE_TYPE,
            key_ring=ring,
        )
        _require(signer in manifest.signing_key_ids)
    return result


def validate_public_plan(
    document: object, *, key_ring: ReleaseKeyRing | None = None
) -> dict[str, Any]:
    """Pure offline validation; never treats fixture identities as public releases."""
    result = _object(
        document,
        {
            "schema",
            "scope",
            "repository",
            "sourceCommit",
            "workflowRun",
            "workflowAttempt",
            "targetTag",
            "previousTag",
            "helpers",
            "releases",
        },
    )
    _require(
        type(result["schema"]) is int
        and result["schema"] == SCHEMA
        and result["scope"] == PLAN_SCOPE
        and result["repository"] == REPOSITORY
    )
    _arguments(result["sourceCommit"], result["workflowRun"], result["workflowAttempt"])
    _require(_tag(result["previousTag"]) < _tag(result["targetTag"]), "public_baseline_required")
    helpers = _object(
        result["helpers"], {"matrixSha", "probeSha", "commonProbeSha", "containerHelperSha"}
    )
    _require(all(isinstance(value, str) and _SHA.fullmatch(value) for value in helpers.values()))
    releases = _object(result["releases"], {"previous", "target"})
    ring = DEFAULT_RELEASE_KEY_RING if key_ring is None else key_ring
    previous = _verify_release(releases["previous"], ring)
    target = _verify_release(releases["target"], ring)
    _require(
        previous["tag"] == result["previousTag"]
        and target["tag"] == result["targetTag"]
        and target["sourceCommit"] == result["sourceCommit"]
        and target["workflowRun"] == result["workflowRun"]
        and previous["releaseId"] != target["releaseId"]
    )
    _require(len(_canonical(result)) <= 4 * 1024 * 1024)
    return result


def _public_release(metadata: object, fetch: Fetch, ring: ReleaseKeyRing) -> dict[str, Any]:
    _require(isinstance(metadata, dict), "public_release_invalid")
    raw = cast(dict[str, Any], metadata)
    tag = raw.get("tag_name")
    _tag(tag)
    tag = cast(str, tag)
    _require(
        raw.get("draft") is False
        and raw.get("prerelease") is False
        and type(raw.get("id")) is int
        and raw["id"] > 0
        and isinstance(raw.get("assets"), list)
        and 0 < len(raw["assets"]) <= 128,
        "public_release_invalid",
    )
    assets: dict[str, Any] = {}
    for asset in raw["assets"]:
        _require(
            isinstance(asset, dict)
            and isinstance(asset.get("name"), str)
            and asset["name"] not in assets,
            "public_release_invalid",
        )
        assets[asset["name"]] = asset
    result: dict[str, Any] = {
        "tag": tag,
        "version": tag[1:],
        "releaseId": raw["id"],
        "platforms": {},
    }
    source = run = None
    for platform in SUPPORTED_PLATFORM_IDS:
        manifest_name = release_manifest_asset_name(platform)
        installer = f"install-{platform}.sh"
        executable = artifact_name(tag[1:], platform)
        required = {
            manifest_name,
            manifest_name + ".sig",
            installer,
            installer + ".sig",
            executable,
        }
        _require(required <= assets.keys(), "public_release_invalid")
        downloaded: dict[str, bytes] = {}
        for name in sorted(required - {executable}):
            payload = fetch(f"{RELEASES}/{tag}/{name}", 1024 * 1024)
            _require(len(payload) == assets[name].get("size"), "public_release_invalid")
            downloaded[name] = payload
        manifest = verify_signed_manifest(
            downloaded[manifest_name], downloaded[manifest_name + ".sig"], key_ring=ring
        )
        verify_detached_signature(
            downloaded[installer],
            downloaded[installer + ".sig"],
            payload_type=INSTALLER_SIGNATURE_TYPE,
            key_ring=ring,
        )
        if source is None:
            source, run = manifest.source_commit, manifest.workflow_run
        _require(
            source == manifest.source_commit and run == manifest.workflow_run,
            "public_release_invalid",
        )
        inventory = {name: _record(payload) for name, payload in downloaded.items()}
        _require(
            assets[executable].get("size") == manifest.executable_size, "public_release_invalid"
        )
        inventory[executable] = {
            "size": manifest.executable_size,
            "sha256": manifest.executable_sha256,
        }
        result["platforms"][platform] = {
            "manifestPayload": base64.b64encode(downloaded[manifest_name]).decode(),
            "manifestSignature": base64.b64encode(downloaded[manifest_name + ".sig"]).decode(),
            "installerPayload": base64.b64encode(downloaded[installer]).decode(),
            "installerSignature": base64.b64encode(downloaded[installer + ".sig"]).decode(),
            "assets": inventory,
        }
    result.update(sourceCommit=source, workflowRun=run)
    return _verify_release(result, ring)


def prepare_public_plan(
    *,
    target_tag: str,
    source_commit: str,
    workflow_run: str,
    workflow_attempt: int,
    fetch: Fetch = fetch_public,
    key_ring: ReleaseKeyRing | None = None,
) -> dict[str, Any]:
    """Select highest lower signed stable public release, never a latest alias."""
    _arguments(source_commit, workflow_run, workflow_attempt)
    target_version = _tag(target_tag)
    ring = DEFAULT_RELEASE_KEY_RING if key_ring is None else key_ring
    target = _public_release(
        _json(fetch(f"{API}/releases/tags/{target_tag}", 2 * 1024 * 1024)), fetch, ring
    )
    _require(target["sourceCommit"] == source_commit, "public_release_invalid")
    candidates: dict[str, dict[str, Any]] = {}
    for page in range(1, 11):
        listing = _json(fetch(f"{API}/releases?per_page=100&page={page}", 2 * 1024 * 1024))
        _require(isinstance(listing, list) and len(listing) <= 100, "public_release_invalid")
        for item in listing:
            _require(isinstance(item, dict), "public_release_invalid")
            tag = item.get("tag_name")
            if (
                isinstance(tag, str)
                and _STABLE.fullmatch(tag)
                and _tag(tag) < target_version
                and item.get("draft") is False
                and item.get("prerelease") is False
            ):
                _require(tag not in candidates, "public_release_invalid")
                candidates[tag] = item
        if len(listing) < 100:
            break
    else:
        raise PublicFailure("public_list_incomplete")
    previous = None
    for tag in sorted(candidates, key=_tag, reverse=True):
        item = candidates[tag]
        names = {asset.get("name") for asset in item.get("assets", []) if isinstance(asset, dict)}
        # Portable-only historical versions cannot establish a managed baseline.
        if not any(
            name in names
            for name in (release_manifest_asset_name(p) for p in SUPPORTED_PLATFORM_IDS)
        ):
            continue
        previous = _public_release(item, fetch, ring)
        break
    _require(previous is not None, "public_baseline_required")
    return validate_public_plan(
        {
            "schema": SCHEMA,
            "scope": PLAN_SCOPE,
            "repository": REPOSITORY,
            "sourceCommit": source_commit,
            "workflowRun": workflow_run,
            "workflowAttempt": workflow_attempt,
            "targetTag": target_tag,
            "previousTag": cast(dict[str, Any], previous)["tag"],
            "helpers": _helpers(),
            "releases": {"previous": previous, "target": target},
        },
        key_ring=ring,
    )


def _installed(plan: Mapping[str, Any], platform: str, versions: list[str]) -> dict[str, Any]:
    records: dict[str, Any] = {}
    platform_id = require_platform_id(platform)
    for role in ("previous", "target"):
        release = plan["releases"][role]
        if release["version"] not in versions:
            continue
        assets = release["platforms"][platform]["assets"]
        name = release_manifest_asset_name(platform_id)
        executable = artifact_name(release["version"], platform_id)
        records[release["version"]] = {
            "manifestSha256": assets[name]["sha256"],
            "signatureSha256": assets[name + ".sig"]["sha256"],
            "executableSha256": assets[executable]["sha256"],
            "executableSize": assets[executable]["size"],
        }
    return records


def validate_public_probe(
    document: object, *, plan: Mapping[str, Any], platform: str, distro: str, distro_version: str
) -> dict[str, Any]:
    result = _object(document, {"schema", "scope", "status", "host", "stages", "cliContracts"})
    _require(
        type(result["schema"]) is int
        and result["schema"] == SCHEMA
        and result["scope"] == PROBE_SCOPE
        and result["status"] == "passed"
    )
    host = _object(
        result["host"],
        {
            "distro",
            "distro_version",
            "machine",
            "platform",
            "pid1",
            "container",
            "effective_uid",
            "private_cgroup_namespace",
            "cgroup_namespace",
            "host_cgroup_namespace",
        },
    )
    _require(
        host["distro"] == distro
        and host["distro_version"] == distro_version
        and host["machine"] == platform.removeprefix("linux-")
        and host["platform"] == platform
        and host["pid1"] == "systemd"
        and host["container"] == "docker"
        and type(host["effective_uid"]) is int
        and host["effective_uid"] == 0
        and host["private_cgroup_namespace"] is True
        and all(
            isinstance(host[key], str) and re.fullmatch(r"cgroup:\[\d+\]", host[key])
            for key in ("cgroup_namespace", "host_cgroup_namespace")
        )
        and host["cgroup_namespace"] != host["host_cgroup_namespace"]
    )
    _require(isinstance(result["stages"], list) and len(result["stages"]) == len(fixture._PHASES))
    previous = plan["releases"]["previous"]["version"]
    target = plan["releases"]["target"]["version"]
    contracts = _object(result["cliContracts"], {"previous", "target"})
    _require(
        isinstance(contracts["previous"], str)
        and isinstance(contracts["target"], str)
        and (contracts["previous"], contracts["target"])
        in {("legacy", "legacy"), ("legacy", "canonical"), ("canonical", "canonical")}
    )
    conversion = contracts == {"previous": "legacy", "target": "canonical"}
    for raw, phase in zip(result["stages"], fixture._PHASES, strict=True):
        fields = {"phase", "status"}
        if phase != "guard":
            fields.add("service")
        if phase not in {"guard", "uninstall"}:
            fields.update({"version", "current_link", "retained_versions", "installed"})
        if phase not in {"guard", "install", "uninstall"}:
            fields.add("health")
        if phase in {"dry_run", "update", "rollback", "uninstall"}:
            fields.add("preserved")
        if phase == "doctor":
            fields.add("checks")
        if phase == "update" and conversion:
            fields.add("configuration")
        if phase == "uninstall":
            fields.add("removed")
        stage = _object(raw, fields)
        _require(stage["phase"] == phase and stage["status"] == "passed")
        if "service" in fields:
            active = phase not in {"install", "uninstall"}
            service = _object(
                stage["service"], {"active", "main_pid", "enabled", "load_state", "listener_gone"}
            )
            _require(
                service["active"] is active
                and service["enabled"] is active
                and service["listener_gone"] is (not active)
                and service["load_state"] == ("loaded" if active else "not-found")
                and type(service["main_pid"]) is int
                and (0 < service["main_pid"] < 2**31 if active else service["main_pid"] == 0)
            )
        if "version" in fields:
            version = target if phase == "update" else previous
            retained = [previous, target] if phase in {"update", "rollback"} else [previous]
            _require(
                stage["version"] == version
                and stage["current_link"] == f"releases/{version}"
                and stage["retained_versions"] == retained
                and _canonical(stage["installed"])
                == _canonical(_installed(plan, platform, retained))
            )
        if "health" in fields:
            _require(stage["health"] is True)
        preserved_fields = {"auth", "sentinel"}
        if phase != "update" or not conversion:
            preserved_fields.add("config")
        if phase in {"dry_run", "rollback"}:
            preserved_fields.add("unit")
        if phase == "update" and conversion:
            configuration = _object(
                stage["configuration"],
                {
                    "transition",
                    "values_preserved",
                    "files_path_preserved",
                    "state_path_preserved",
                    "unit_updated",
                },
            )
            _require(configuration.pop("transition") == "legacy-to-canonical")
            _require(all(value is True for value in configuration.values()))
        for key, expected in (
            ("preserved", preserved_fields),
            (
                "checks",
                set(fixture._doctor_statuses(canonical=contracts["previous"] == "canonical")),
            ),
        ):
            if key in fields:
                values = _object(stage[key], expected)
                _require(all(value is True for value in values.values()))
        if "removed" in fields:
            _require(stage["removed"] is True)
    return result


def _validate_architecture(document: object, plan: Mapping[str, Any]) -> dict[str, Any]:
    result = _object(
        document,
        {
            "schema",
            "scope",
            "sourceCommit",
            "workflowRun",
            "workflowAttempt",
            "platform",
            "planSha256",
            "helpers",
            "targetTag",
            "previousTag",
            "releases",
            "publicReleaseEvidence",
            "status",
            "receipts",
        },
    )
    _require(
        type(result["schema"]) is int
        and result["schema"] == SCHEMA
        and result["scope"] == ARCH_SCOPE
        and result["status"] == "passed"
        and result["publicReleaseEvidence"] is True
        and result["platform"] in SUPPORTED_PLATFORM_IDS
        and result["planSha256"] == _sha(_canonical(plan))
    )
    for key in (
        "sourceCommit",
        "workflowRun",
        "workflowAttempt",
        "helpers",
        "targetTag",
        "previousTag",
        "releases",
    ):
        _require(_canonical(result[key]) == _canonical(plan[key]))
    _require(isinstance(result["receipts"], list) and len(result["receipts"]) == len(fixture.PAIRS))
    seen = set()
    for raw in result["receipts"]:
        pair = _object(
            raw,
            {
                "distro",
                "distroVersion",
                "status",
                "baseImage",
                "imageId",
                "containerId",
                "lifecycle",
            },
        )
        identity = pair["distro"], pair["distroVersion"]
        _require(
            identity in fixture.PAIRS
            and identity not in seen
            and pair["status"] == "passed"
            and isinstance(pair["baseImage"], str)
            and re.fullmatch(rf"{identity[0]}@sha256:[0-9a-f]{{64}}", pair["baseImage"]) is not None
            and isinstance(pair["imageId"], str)
            and re.fullmatch(r"sha256:[0-9a-f]{64}", pair["imageId"]) is not None
            and isinstance(pair["containerId"], str)
            and _SHA.fullmatch(pair["containerId"]) is not None
        )
        seen.add(identity)
        validate_public_probe(
            pair["lifecycle"],
            plan=plan,
            platform=result["platform"],
            distro=identity[0],
            distro_version=identity[1],
        )
    _require(seen == set(fixture.PAIRS))
    return result


def validate_public_result(
    document: object, *, plan: object, source_commit: str, workflow_run: str, workflow_attempt: int
) -> dict[str, Any]:
    """Pure downstream verifier: all identities, both native architectures, all ten lifecycles."""
    checked = validate_public_plan(plan)
    _require(checked["helpers"] == _helpers())
    _arguments(source_commit, workflow_run, workflow_attempt)
    _require(
        checked["sourceCommit"] == source_commit
        and checked["workflowRun"] == workflow_run
        and checked["workflowAttempt"] == workflow_attempt
    )
    result = _object(
        document,
        {
            "schema",
            "scope",
            "sourceCommit",
            "workflowRun",
            "workflowAttempt",
            "targetTag",
            "previousTag",
            "planSha256",
            "publicReleaseEvidence",
            "status",
            "pairCount",
            "architectures",
        },
    )
    _require(
        type(result["schema"]) is int
        and result["schema"] == SCHEMA
        and result["scope"] == RESULT_SCOPE
        and result["status"] == "passed"
        and result["publicReleaseEvidence"] is True
        and type(result["pairCount"]) is int
        and result["pairCount"] == 10
        and result["planSha256"] == _sha(_canonical(checked))
    )
    for key in ("sourceCommit", "workflowRun", "workflowAttempt", "targetTag", "previousTag"):
        _require(_canonical(result[key]) == _canonical(checked[key]))
    _require(isinstance(result["architectures"], list) and len(result["architectures"]) == 2)
    arches = [_validate_architecture(item, checked) for item in result["architectures"]]
    _require({item["platform"] for item in arches} == set(SUPPORTED_PLATFORM_IDS))
    return result


def create_public_command(
    *, assets_root: Path, plan_file: Path, evidence_dir: Path, image_id: str, network: str
) -> tuple[str, ...]:
    """Use a dedicated bridge and private namespaces without host runtime mounts."""
    _require(re.fullmatch(r"sha256:[0-9a-f]{64}", image_id) is not None)
    _require(re.fullmatch(r"xferry-public-[0-9a-f]{24}", network) is not None)
    argv = [
        "docker",
        "create",
        "--privileged",
        "--cgroupns",
        "private",
        "--network",
        network,
        "--memory",
        "1024m",
        "--cpus",
        "2",
        "--pids-limit",
        "512",
        "--tmpfs",
        "/run",
        "--tmpfs",
        "/run/lock",
        "--tmpfs",
        "/tmp:rw,nosuid,nodev,noexec,mode=1777",
        "--tmpfs",
        "/var/tmp:rw,nosuid,nodev,exec,mode=1777",
        "--env",
        "container=docker",
        "--env",
        "XFERRY_SYSTEMD_REHEARSAL=1",
        "--label",
        "org.xferry.public-lifecycle=1",
    ]
    for source, target, readonly in (
        (assets_root, "/public-assets", True),
        (plan_file, "/public-plan.json", True),
        (REPO_ROOT / "tools/managed_public_probe.py", "/matrix/managed_public_probe.py", True),
        (REPO_ROOT / "tools/managed_systemd_probe.py", "/matrix/managed_systemd_probe.py", True),
        (evidence_dir, "/evidence", False),
    ):
        _require(
            source.is_absolute()
            and source.resolve() == source
            and not source.is_symlink()
            and not any(character in str(source) for character in ",\n\r")
        )
        mount = f"type=bind,src={source},dst={target}" + (",readonly" if readonly else "")
        argv.extend(("--mount", mount))
    return (*argv, image_id)


def run_public_matrix(
    *, plan: object, platform: str, evidence_root: Path, fetch: Fetch = fetch_public
) -> dict[str, Any]:
    checked = validate_public_plan(plan)
    _require(
        platform in SUPPORTED_PLATFORM_IDS
        and os.uname().sysname == "Linux"
        and os.uname().machine == platform.removeprefix("linux-"),
        "public_host_required",
    )
    _require(checked["helpers"] == _helpers())
    _require(
        fixture._command(("git", "rev-parse", "HEAD"), cwd=REPO_ROOT).strip().decode("ascii")
        == checked["sourceCommit"],
        "public_host_required",
    )
    _require(
        evidence_root.is_absolute()
        and evidence_root.resolve() == evidence_root
        and not os.path.lexists(evidence_root)
    )
    _require(
        not os.environ.get("DOCKER_HOST")
        and fixture._command(("docker", "context", "show")).strip() == b"default",
        "public_host_required",
    )
    namespace = str(Path("/proc/self/ns/cgroup").readlink())
    _require(re.fullmatch(r"cgroup:\[\d+\]", namespace) is not None, "public_host_required")
    evidence_root.mkdir(parents=True, mode=0o700)
    receipts = []
    with tempfile.TemporaryDirectory(prefix="xferry-public-matrix-") as temporary:
        root = Path(temporary).resolve()
        assets = root / "assets"
        assets.mkdir()
        plan_file = root / "public-plan.json"
        fixture._write_json(plan_file, checked)
        for release in checked["releases"].values():
            directory = assets / release["tag"]
            directory.mkdir()
            for name, record in release["platforms"][platform]["assets"].items():
                payload = fetch(f"{RELEASES}/{release['tag']}/{name}", record["size"])
                _require(_record(payload) == record, "public_release_invalid")
                (directory / name).write_bytes(payload)
            installer = f"install-{platform}.sh"
            verify_detached_signature(
                (directory / installer).read_bytes(),
                (directory / (installer + ".sig")).read_bytes(),
                payload_type=INSTALLER_SIGNATURE_TYPE,
                key_ring=DEFAULT_RELEASE_KEY_RING,
            )
        network = "xferry-public-" + os.urandom(12).hex()
        network_id = (
            fixture._command(
                (
                    "docker",
                    "network",
                    "create",
                    "--driver",
                    "bridge",
                    "--label",
                    "org.xferry.public-lifecycle=1",
                    network,
                )
            )
            .strip()
            .decode("ascii")
        )
        _require(_SHA.fullmatch(network_id) is not None)
        try:
            for distro, version in fixture.PAIRS:
                container = None
                pair: dict[str, Any] = {
                    "distro": distro,
                    "distroVersion": version,
                    "status": "failed",
                }
                try:
                    options = cast(fixture.RunOptions, argparse.Namespace(platform=platform))
                    base, image = fixture._image(options, distro, version)
                    raw = root / f"{distro}-{version}"
                    raw.mkdir()
                    container = (
                        fixture._command(
                            create_public_command(
                                assets_root=assets,
                                plan_file=plan_file,
                                evidence_dir=raw,
                                image_id=image,
                                network=network,
                            )
                        )
                        .strip()
                        .decode("ascii")
                    )
                    _require(_SHA.fullmatch(container) is not None)
                    fixture._command(("docker", "start", container))
                    fixture._wait_systemd(container, namespace)
                    fixture._command(
                        (
                            "docker",
                            "exec",
                            container,
                            "python3",
                            "/matrix/managed_public_probe.py",
                            "--plan",
                            "/public-plan.json",
                            "--assets-root",
                            "/public-assets",
                            "--evidence",
                            "/evidence/lifecycle.json",
                            "--distro",
                            distro,
                            "--distro-version",
                            version,
                            "--machine",
                            platform.removeprefix("linux-"),
                            "--platform",
                            platform,
                            "--host-cgroup-namespace",
                            namespace,
                        ),
                        timeout=1200,
                        allowed_codes=(0, 1),
                    )
                    lifecycle = validate_public_probe(
                        fixture._read_json(raw / "lifecycle.json"),
                        plan=checked,
                        platform=platform,
                        distro=distro,
                        distro_version=version,
                    )
                    _require(lifecycle["host"]["host_cgroup_namespace"] == namespace)
                    pair.update(
                        status="passed",
                        baseImage=base,
                        imageId=image,
                        containerId=container,
                        lifecycle=lifecycle,
                    )
                except Exception:
                    pair = {
                        "distro": distro,
                        "distroVersion": version,
                        "status": "failed",
                        "code": "public_probe_failed",
                    }
                finally:
                    if container is not None and _SHA.fullmatch(container):
                        try:
                            fixture._command(("docker", "rm", "--force", container), timeout=60)
                        except Exception:
                            pair = {
                                "distro": distro,
                                "distroVersion": version,
                                "status": "failed",
                                "code": "public_cleanup_failed",
                            }
                fixture._write_json(evidence_root / f"{distro}-{version}.json", pair)
                receipts.append(pair)
        finally:
            fixture._command(("docker", "network", "rm", network_id), timeout=60)
    result = {
        "schema": SCHEMA,
        "scope": ARCH_SCOPE,
        "sourceCommit": checked["sourceCommit"],
        "workflowRun": checked["workflowRun"],
        "workflowAttempt": checked["workflowAttempt"],
        "platform": platform,
        "planSha256": _sha(_canonical(checked)),
        "helpers": checked["helpers"],
        "targetTag": checked["targetTag"],
        "previousTag": checked["previousTag"],
        "releases": checked["releases"],
        "publicReleaseEvidence": True,
        "status": "passed" if all(pair["status"] == "passed" for pair in receipts) else "failed",
        "receipts": receipts,
    }
    fixture._write_json(evidence_root / "architecture.json", result)
    return result


def verify_public_matrix(
    *,
    plan: object,
    source_commit: str,
    workflow_run: str,
    workflow_attempt: int,
    evidence_root: Path,
    output: Path,
) -> dict[str, Any]:
    checked = validate_public_plan(plan)
    _require(checked["helpers"] == _helpers())
    _require(
        evidence_root.is_absolute()
        and evidence_root.resolve() == evidence_root
        and evidence_root.is_dir()
        and not evidence_root.is_symlink()
    )
    directories = sorted(evidence_root.iterdir())
    _require(len(directories) == 2)
    expected = {"architecture.json"} | {
        f"{distro}-{version}.json" for distro, version in fixture.PAIRS
    }
    architectures = []
    for directory in directories:
        _require(directory.is_dir() and not directory.is_symlink())
        members = list(directory.iterdir())
        _require(
            len(members) == len(expected)
            and {path.name for path in members} == expected
            and all(path.is_file() and not path.is_symlink() for path in members)
        )
        architecture = _validate_architecture(
            fixture._read_json(directory / "architecture.json"), checked
        )
        for receipt in architecture["receipts"]:
            filename = f"{receipt['distro']}-{receipt['distroVersion']}.json"
            standalone = fixture._read_json(directory / filename)
            _require(_canonical(standalone) == _canonical(receipt))
        architectures.append(architecture)
    result = {
        "schema": SCHEMA,
        "scope": RESULT_SCOPE,
        "sourceCommit": source_commit,
        "workflowRun": workflow_run,
        "workflowAttempt": workflow_attempt,
        "targetTag": checked["targetTag"],
        "previousTag": checked["previousTag"],
        "planSha256": _sha(_canonical(checked)),
        "publicReleaseEvidence": True,
        "status": "passed",
        "pairCount": 10,
        "architectures": architectures,
    }
    validate_public_result(
        result,
        plan=checked,
        source_commit=source_commit,
        workflow_run=workflow_run,
        workflow_attempt=workflow_attempt,
    )
    fixture._write_json(output, result)
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    prepare = commands.add_parser("prepare")
    run = commands.add_parser("run")
    verify = commands.add_parser("verify-matrix")
    prepare.add_argument("--target-tag", required=True)
    for command in (prepare, verify):
        command.add_argument("--source-commit", required=True)
        command.add_argument("--workflow-run", required=True)
        command.add_argument("--workflow-attempt", type=int, required=True)
        command.add_argument("--output", type=Path, required=True)
    for command in (run, verify):
        command.add_argument("--plan", type=Path, required=True)
        command.add_argument("--evidence-root", type=Path, required=True)
    run.add_argument("--platform", choices=SUPPORTED_PLATFORM_IDS, required=True)
    arguments = vars(parser.parse_args(argv))
    command = arguments.pop("command")
    try:
        if command == "prepare":
            output = arguments.pop("output")
            result = prepare_public_plan(**arguments)
            fixture._write_json(output, result)
        else:
            arguments["plan"] = fixture._read_json(arguments["plan"])
            result = (
                run_public_matrix(**arguments)
                if command == "run"
                else verify_public_matrix(**arguments)
            )
        print(json.dumps({"status": result.get("status", "prepared"), "scope": result["scope"]}))
        return 0 if result.get("status", "prepared") in {"passed", "prepared"} else 1
    except Exception as exc:
        code = str(exc) if isinstance(exc, PublicFailure) else "public_matrix_invalid"
        print(json.dumps({"status": "failed", "code": code}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
