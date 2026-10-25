"""Synthetic signed public-contract tests; never production/lifecycle evidence."""

from __future__ import annotations

import base64
import copy
import hashlib
import json
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from tools import managed_public_matrix as public
from xferry.management.release_contract import (
    ReleaseManifest,
    artifact_name,
    release_manifest_asset_name,
)
from xferry.management.release_trust import (
    INSTALLER_SIGNATURE_TYPE,
    MANIFEST_SIGNATURE_TYPE,
    ReleaseKeyRing,
    ReleaseTrustError,
    TrustedReleaseKey,
    create_detached_signature,
)


@pytest.fixture
def signed(
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[dict[str, Any], dict[str, bytes], dict[str, Any]]:
    # Public unit-test trust only; no production key is read or generated.
    private = Ed25519PrivateKey.from_private_bytes(b"\x19" * 32)
    key_id = "xferry-unit-public"
    ring = ReleaseKeyRing([TrustedReleaseKey(key_id, private.public_key().public_bytes_raw())])
    monkeypatch.setattr(public, "DEFAULT_RELEASE_KEY_RING", ring)
    bodies: dict[str, bytes] = {}
    metadata: dict[str, Any] = {}
    releases = {}
    for role, version, source, run, release_id in (
        ("previous", "0.1.0", "a" * 40, "111", 11),
        ("target", "0.2.0", "b" * 40, "222", 22),
    ):
        tag = "v" + version
        release: dict[str, Any] = {
            "tag": tag,
            "version": version,
            "sourceCommit": source,
            "workflowRun": run,
            "releaseId": release_id,
            "platforms": {},
        }
        assets = []
        for platform in public.SUPPORTED_PLATFORM_IDS:
            installer = b"#!/bin/sh\n# synthetic signed fixture; never executed\nexit 0\n"
            executable = f"unit executable {version} {platform}".encode()
            installer_name = f"install-{platform}.sh"
            executable_name = artifact_name(version, platform)
            manifest = ReleaseManifest.create_v2(
                version=version,
                platform=platform,
                executable_size=len(executable),
                executable_sha256=hashlib.sha256(executable).hexdigest(),
                source_commit=source,
                workflow_run=run,
                artifact_digests={
                    installer_name: hashlib.sha256(installer).hexdigest(),
                    executable_name: hashlib.sha256(executable).hexdigest(),
                },
                signing_key_ids=(key_id,),
            ).to_bytes()
            signature = create_detached_signature(
                manifest, payload_type=MANIFEST_SIGNATURE_TYPE, key_id=key_id, signer=private
            )
            installer_signature = create_detached_signature(
                installer, payload_type=INSTALLER_SIGNATURE_TYPE, key_id=key_id, signer=private
            )
            manifest_name = release_manifest_asset_name(platform)
            payloads = {
                manifest_name: manifest,
                manifest_name + ".sig": signature,
                installer_name: installer,
                installer_name + ".sig": installer_signature,
                executable_name: executable,
            }
            release["platforms"][platform] = {
                "manifestPayload": base64.b64encode(manifest).decode(),
                "manifestSignature": base64.b64encode(signature).decode(),
                "installerPayload": base64.b64encode(installer).decode(),
                "installerSignature": base64.b64encode(installer_signature).decode(),
                "assets": {name: public._record(payload) for name, payload in payloads.items()},
            }
            for name, payload in payloads.items():
                bodies[f"{public.RELEASES}/{tag}/{name}"] = payload
                assets.append({"name": name, "size": len(payload)})
        metadata[tag] = {
            "tag_name": tag,
            "id": release_id,
            "draft": False,
            "prerelease": False,
            "assets": assets,
        }
        releases[role] = release
    plan = {
        "schema": 1,
        "scope": public.PLAN_SCOPE,
        "repository": public.REPOSITORY,
        "sourceCommit": "b" * 40,
        "workflowRun": "222",
        "workflowAttempt": 2,
        "targetTag": "v0.2.0",
        "previousTag": "v0.1.0",
        "helpers": public._helpers(),
        "releases": releases,
    }
    return plan, bodies, metadata


def _lifecycle(plan: dict[str, Any], platform: str, distro: str, version: str) -> dict[str, Any]:
    stages = []
    previous = plan["releases"]["previous"]["version"]
    target = plan["releases"]["target"]["version"]
    for phase in public.fixture._PHASES:
        stage: dict[str, Any] = {"phase": phase, "status": "passed"}
        if phase != "guard":
            active = phase not in {"install", "uninstall"}
            stage["service"] = {
                "active": active,
                "enabled": active,
                "main_pid": 42 if active else 0,
                "load_state": "loaded" if active else "not-found",
                "listener_gone": not active,
            }
        if phase not in {"guard", "uninstall"}:
            retained = [previous, target] if phase in {"update", "rollback"} else [previous]
            selected = target if phase == "update" else previous
            stage.update(
                version=selected,
                current_link="releases/" + selected,
                retained_versions=retained,
                installed=public._installed(plan, platform, retained),
            )
        if phase not in {"guard", "install", "uninstall"}:
            stage["health"] = True
        if phase == "doctor":
            stage["checks"] = dict.fromkeys(
                ("platform", "installation", "configuration", "service", "network", "health"), True
            )
        if phase in {"dry_run", "update", "rollback", "uninstall"}:
            stage["preserved"] = dict.fromkeys(("config", "auth", "sentinel"), True)
        if phase == "uninstall":
            stage["removed"] = True
        stages.append(stage)
    return {
        "schema": 1,
        "scope": public.PROBE_SCOPE,
        "status": "passed",
        "stages": stages,
        "host": {
            "distro": distro,
            "distro_version": version,
            "platform": platform,
            "machine": platform.removeprefix("linux-"),
            "pid1": "systemd",
            "container": "docker",
            "effective_uid": 0,
            "private_cgroup_namespace": True,
            "cgroup_namespace": "cgroup:[2]",
            "host_cgroup_namespace": "cgroup:[1]",
        },
    }


def _result(plan: dict[str, Any]) -> dict[str, Any]:
    architectures = []
    for platform in public.SUPPORTED_PLATFORM_IDS:
        architecture = {
            "schema": 1,
            "scope": public.ARCH_SCOPE,
            "platform": platform,
            "planSha256": public._sha(public._canonical(plan)),
            "publicReleaseEvidence": True,
            "status": "passed",
            "receipts": [],
        }
        for key in (
            "sourceCommit",
            "workflowRun",
            "workflowAttempt",
            "targetTag",
            "previousTag",
            "helpers",
            "releases",
        ):
            architecture[key] = copy.deepcopy(plan[key])
        for distro, version in public.fixture.PAIRS:
            architecture["receipts"].append(
                {
                    "distro": distro,
                    "distroVersion": version,
                    "status": "passed",
                    "baseImage": distro + "@sha256:" + "c" * 64,
                    "imageId": "sha256:" + "d" * 64,
                    "containerId": "e" * 64,
                    "lifecycle": _lifecycle(plan, platform, distro, version),
                }
            )
        architectures.append(architecture)
    return {
        "schema": 1,
        "scope": public.RESULT_SCOPE,
        "sourceCommit": plan["sourceCommit"],
        "workflowRun": plan["workflowRun"],
        "workflowAttempt": plan["workflowAttempt"],
        "targetTag": plan["targetTag"],
        "previousTag": plan["previousTag"],
        "planSha256": public._sha(public._canonical(plan)),
        "publicReleaseEvidence": True,
        "status": "passed",
        "pairCount": 10,
        "architectures": architectures,
    }


def _validate(result: dict[str, Any], plan: dict[str, Any]) -> dict[str, Any]:
    return public.validate_public_result(
        result,
        plan=plan,
        source_commit=plan["sourceCommit"],
        workflow_run=plan["workflowRun"],
        workflow_attempt=plan["workflowAttempt"],
    )


def test_offline_full_public_contract_accepts_all_ten_bound_pairs(signed: Any) -> None:
    plan, _, _ = signed
    result = _result(plan)
    assert _validate(result, plan) == result
    assert sum(len(arch["receipts"]) for arch in result["architectures"]) == 10


@pytest.mark.parametrize(
    "field,value",
    [
        ("schema", True),
        ("scope", "native-systemd-ten-pair-fixture-matrix"),
        ("pairCount", 9),
        ("pairCount", True),
        ("publicReleaseEvidence", False),
        ("workflowAttempt", True),
        ("sourceCommit", "f" * 40),
        ("workflowRun", "999"),
        ("targetTag", "v9.0.0"),
        ("status", "skipped"),
    ],
)
def test_result_rejects_identity_scope_and_boolean_integer_confusion(
    signed: Any, field: str, value: Any
) -> None:
    plan, _, _ = signed
    result = _result(plan)
    result[field] = value
    with pytest.raises(public.PublicFailure):
        _validate(result, plan)


@pytest.mark.parametrize(
    "mutation",
    [
        "duplicate_arch",
        "missing_pair",
        "duplicate_pair",
        "fixture_scope",
        "same_namespace",
        "wrong_arch",
        "lost_config",
        "wrong_version",
        "wrong_digest",
        "missing_phase",
        "false_health",
    ],
)
def test_result_rejects_incomplete_or_weakened_actual_lifecycle(signed: Any, mutation: str) -> None:
    plan, _, _ = signed
    result = _result(plan)
    arch = result["architectures"][0]
    life = arch["receipts"][0]["lifecycle"]
    if mutation == "duplicate_arch":
        result["architectures"][1] = copy.deepcopy(arch)
    elif mutation == "missing_pair":
        arch["receipts"].pop()
    elif mutation == "duplicate_pair":
        arch["receipts"][1] = copy.deepcopy(arch["receipts"][0])
    elif mutation == "fixture_scope":
        life["scope"] = "native-systemd-container-fixtures"
    elif mutation == "same_namespace":
        life["host"]["cgroup_namespace"] = life["host"]["host_cgroup_namespace"]
    elif mutation == "wrong_arch":
        life["host"]["machine"] = "emulated"
    elif mutation == "lost_config":
        life["stages"][5]["preserved"]["config"] = False
    elif mutation == "wrong_version":
        life["stages"][5]["version"] = "0.1.0"
    elif mutation == "wrong_digest":
        life["stages"][5]["installed"]["0.2.0"]["executableSha256"] = "0" * 64
    elif mutation == "missing_phase":
        life["stages"].pop()
    else:
        life["stages"][5]["health"] = False
    with pytest.raises(public.PublicFailure):
        _validate(result, plan)


@pytest.mark.parametrize("tag", ["v0.2.0", "v0.3.0", "v0.1.0-rc1", "latest", "v00.1.0"])
def test_plan_requires_distinct_lower_stable_predecessor(signed: Any, tag: str) -> None:
    plan, _, _ = signed
    plan["previousTag"] = tag
    with pytest.raises(public.PublicFailure):
        public.validate_public_plan(plan)


@pytest.mark.parametrize("run", ["333", "local", "0", "000222"])
def test_plan_requires_same_positive_numeric_production_workflow_run(signed: Any, run: str) -> None:
    plan, _, _ = signed
    plan["workflowRun"] = run
    with pytest.raises(public.PublicFailure):
        public.validate_public_plan(plan)


def test_final_result_rejects_consistently_relabelled_stale_helpers(signed: Any) -> None:
    plan, _, _ = signed
    plan["helpers"]["probeSha"] = "0" * 64
    result = _result(plan)
    with pytest.raises(public.PublicFailure):
        _validate(result, plan)


@pytest.mark.parametrize(
    "mutation", [None, "standalone", "extra", "missing", "symlink", "root_extra"]
)
def test_collector_requires_one_exact_coherent_regular_receipt_set(
    signed: Any,
    tmp_path: Path,
    mutation: str | None,
) -> None:
    plan, _, _ = signed
    root = tmp_path / "downloaded"
    root.mkdir()
    for architecture in _result(plan)["architectures"]:
        directory = root / architecture["platform"]
        directory.mkdir()
        (directory / "architecture.json").write_text(json.dumps(architecture))
        for receipt in architecture["receipts"]:
            (directory / f"{receipt['distro']}-{receipt['distroVersion']}.json").write_text(
                json.dumps(receipt)
            )
    directory = root / "linux-x86_64"
    filename = directory / "ubuntu-22.04.json"
    if mutation == "standalone":
        document = json.loads(filename.read_text())
        document["status"] = "failed"
        filename.write_text(json.dumps(document))
    elif mutation == "extra":
        (directory / "unexpected.log").write_text("must not be attested")
    elif mutation == "missing":
        filename.unlink()
    elif mutation == "symlink":
        other = tmp_path / "outside.json"
        other.write_bytes(filename.read_bytes())
        filename.unlink()
        filename.symlink_to(other)
    elif mutation == "root_extra":
        (root / "unexpected.json").write_text("{}")
    arguments = {
        "plan": plan,
        "source_commit": plan["sourceCommit"],
        "workflow_run": plan["workflowRun"],
        "workflow_attempt": plan["workflowAttempt"],
        "evidence_root": root,
        "output": tmp_path / "verified.json",
    }
    if mutation is None:
        assert public.verify_public_matrix(**arguments)["pairCount"] == 10
    else:
        with pytest.raises(public.PublicFailure):
            public.verify_public_matrix(**arguments)


@pytest.mark.parametrize(
    "member", ["manifestPayload", "manifestSignature", "installerPayload", "installerSignature"]
)
def test_plan_rejects_tampered_public_signed_bytes(signed: Any, member: str) -> None:
    plan, _, _ = signed
    plan["releases"]["target"]["platforms"]["linux-x86_64"][member] = base64.b64encode(
        b"tampered"
    ).decode()
    with pytest.raises((public.PublicFailure, ReleaseTrustError)):
        public.validate_public_plan(plan)


def test_prepare_selects_highest_lower_signed_public_release_without_latest(signed: Any) -> None:
    plan, bodies, metadata = signed
    requests = []

    def fetch(url: str, limit: int) -> bytes:
        requests.append(url)
        if url == public.API + "/releases/tags/v0.2.0":
            return json.dumps(metadata["v0.2.0"]).encode()
        if url == public.API + "/releases?per_page=100&page=1":
            return json.dumps(
                [
                    metadata["v0.2.0"],
                    {"tag_name": "v0.1.9", "draft": False, "prerelease": False, "assets": []},
                    metadata["v0.1.0"],
                ]
            ).encode()
        assert len(bodies[url]) <= limit
        return bodies[url]

    result = public.prepare_public_plan(
        target_tag="v0.2.0",
        source_commit=plan["sourceCommit"],
        workflow_run=plan["workflowRun"],
        workflow_attempt=2,
        fetch=fetch,
    )
    assert result["previousTag"] == "v0.1.0"
    assert not any("latest" in url for url in requests)


def test_prepare_missing_baseline_never_produces_a_bootstrap_success(signed: Any) -> None:
    plan, bodies, metadata = signed

    def fetch(url: str, _limit: int) -> bytes:
        if url.endswith("/releases/tags/v0.2.0"):
            return json.dumps(metadata["v0.2.0"]).encode()
        if "?per_page=" in url:
            return b"[]"
        return bodies[url]

    with pytest.raises(public.PublicFailure, match="public_baseline_required"):
        public.prepare_public_plan(
            target_tag="v0.2.0",
            source_commit=plan["sourceCommit"],
            workflow_run=plan["workflowRun"],
            workflow_attempt=2,
            fetch=fetch,
        )


def test_release_asset_inventory_is_bounded_before_downloads(signed: Any) -> None:
    _, _, metadata = signed
    raw = copy.deepcopy(metadata["v0.2.0"])
    raw["assets"] = [{"name": str(number), "size": 1} for number in range(129)]
    with pytest.raises(public.PublicFailure, match="public_release_invalid"):
        public._public_release(
            raw,
            lambda *_args: pytest.fail("must not download oversized inventory"),
            public.DEFAULT_RELEASE_KEY_RING,
        )


def test_release_listing_cannot_silently_truncate_before_selecting_baseline(signed: Any) -> None:
    plan, bodies, metadata = signed

    def fetch(url: str, _limit: int) -> bytes:
        if url.endswith("/releases/tags/v0.2.0"):
            return json.dumps(metadata["v0.2.0"]).encode()
        if "?per_page=" in url:
            return json.dumps(
                [
                    {"tag_name": f"v0.0.{number}", "draft": True, "prerelease": False}
                    for number in range(100)
                ]
            ).encode()
        return bodies[url]

    with pytest.raises(public.PublicFailure, match="public_list_incomplete"):
        public.prepare_public_plan(
            target_tag="v0.2.0",
            source_commit=plan["sourceCommit"],
            workflow_run=plan["workflowRun"],
            workflow_attempt=2,
            fetch=fetch,
        )


@pytest.mark.parametrize("payload", [b'{"a":1,"a":2}', b'{"a":{"b":1,"b":2}}', b'{"a":NaN}'])
def test_ambiguous_or_nonstandard_json_is_rejected(payload: bytes) -> None:
    with pytest.raises(public.PublicFailure):
        public._json(payload)


@pytest.mark.parametrize(
    "url",
    [
        "http://github.com/a",
        "https://127.0.0.1/a",
        "https://evil.invalid/a",
        "https://secret@github.com/a",
        "https://github.com:444/a",
        "https://github.com/a#fragment",
    ],
)
def test_public_download_rejects_nonproduction_transport(url: str) -> None:
    with pytest.raises(public.PublicFailure):
        public._url(url)


def test_dedicated_public_container_keeps_host_runtime_unmounted(tmp_path: Path) -> None:
    command = public.create_public_command(
        assets_root=tmp_path,
        plan_file=tmp_path / "plan.json",
        evidence_dir=tmp_path / "evidence",
        image_id="sha256:" + "a" * 64,
        network="xferry-public-" + "b" * 24,
    )
    assert command[command.index("--network") + 1] == "xferry-public-" + "b" * 24
    assert command[command.index("--cgroupns") + 1] == "private"
    assert "/tmp:rw,nosuid,nodev,noexec,mode=1777" in command
    assert "/var/tmp:rw,nosuid,nodev,exec,mode=1777" in command
    assert not any(
        value in {"host", "/sys/fs/cgroup", "/run/systemd", "/var/run/docker.sock"}
        for value in command
    )
    assert not any(
        "fixture-tls" in value or "XFERRY_RELEASE_BASE_URL" in value for value in command
    )


@pytest.mark.parametrize("network", ["host", "bridge", "none", "xferry-public-bad/name"])
def test_public_profile_cannot_use_host_or_implicit_network(tmp_path: Path, network: str) -> None:
    with pytest.raises(public.PublicFailure):
        public.create_public_command(
            assets_root=tmp_path,
            plan_file=tmp_path / "plan.json",
            evidence_dir=tmp_path / "evidence",
            image_id="sha256:" + "a" * 64,
            network=network,
        )
