"""Pure validation/command regressions, not real container lifecycle receipts."""

from __future__ import annotations

import copy
import hashlib
import json
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from tools import managed_systemd_matrix as matrix
from tools.managed_update_rehearsal import patch_fixture_source

SOURCE = "a" * 40
BASE_TREE = "d" * 40
PUBLIC = bytes.fromhex("ab" * 32)
CONTAINER = "e" * 64
IMAGE = "sha256:" + "f" * 64


def _lifecycle(distro: str, version: str, platform: str) -> dict[str, Any]:
    stages: list[dict[str, Any]] = []
    for phase in matrix._PHASES:
        stage: dict[str, Any] = {"phase": phase, "status": "passed"}
        if phase != "guard":
            active = phase not in {"install", "uninstall"}
            stage["service"] = {
                "active": active,
                "enabled": active,
                "main_pid": 123 if active else 0,
                "load_state": "loaded" if active else "not-found",
                "listener_gone": not active,
            }
        if phase not in {"guard", "uninstall"}:
            release = "0.1.2" if phase == "update" else "0.1.1"
            stage.update(
                version=release,
                current_link=f"releases/{release}",
                retained_versions=(
                    ["0.1.1", "0.1.2"] if phase in {"update", "rollback"} else ["0.1.1"]
                ),
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
        "scope": "native-systemd-container-fixtures",
        "status": "passed",
        "host": {
            "distro": distro,
            "distro_version": version,
            "machine": platform.removeprefix("linux-"),
            "platform": platform,
            "pid1": "systemd",
            "container": "docker",
            "effective_uid": 0,
            "private_cgroup_namespace": True,
            "cgroup_namespace": "cgroup:[200]",
            "host_cgroup_namespace": "cgroup:[100]",
        },
        "stages": stages,
    }


def _architecture(platform: str) -> dict[str, Any]:
    return {
        "schema": 1,
        "scope": "native-systemd-fixture-matrix",
        "sourceCommit": SOURCE,
        "workflowRun": "123",
        "workflowAttempt": 1,
        "platform": platform,
        "fixturesSha": "1" * 64,
        "helpers": {
            "matrixSha": matrix._sha(Path(matrix.__file__)),
            "probeSha": matrix._sha(matrix.REPO_ROOT / "tools/managed_systemd_probe.py"),
        },
        "fixtureSources": {
            version: {
                "commit": "b" * 40,
                "tree": "c" * 40,
                "baseCommit": "d" * 40,
                "patchSha": "4" * 64,
            }
            for version in matrix.VERSIONS
        },
        "publicReleaseEvidence": False,
        "status": "passed",
        "receipts": [
            {
                "distro": distro,
                "distroVersion": version,
                "status": "passed",
                "baseImage": distro + "@sha256:" + "5" * 64,
                "imageId": IMAGE,
                "containerId": CONTAINER,
                "lifecycle": _lifecycle(distro, version, platform),
            }
            for distro, version in matrix.PAIRS
        ],
    }


@pytest.fixture
def fixtures(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[matrix.RunOptions, dict[str, Any], list[tuple[str, ...]], Any]:
    options = matrix.RunOptions(
        fixtures_root=tmp_path / "fixtures",
        fixture_evidence=tmp_path / "fixtures.json",
        sources_root=tmp_path / "work" / "sources",
        tls_dir=tmp_path / "tls",
        evidence_root=tmp_path / "evidence",
        source_commit=SOURCE,
        workflow_run="local",
        workflow_attempt=1,
        platform="linux-x86_64",
    )
    options.fixtures_root.mkdir()
    options.sources_root.mkdir(parents=True)
    options.tls_dir.mkdir()
    originals = {name: (matrix.REPO_ROOT / name).read_bytes() for name in matrix._PATCH_FILES}
    versions: dict[str, Any] = {}
    for index, version in enumerate(matrix.VERSIONS, 1):
        source = options.sources_root / version
        for name, payload in originals.items():
            path = source / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(payload)
        for name in ("packaging/install.sh.in", "tools/verify_release_signature.py"):
            path = source / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes((matrix.REPO_ROOT / name).read_bytes())
        patch_fixture_source(
            source,
            version=version,
            public_key_hex=PUBLIC.hex(),
            release_base_url=matrix.RELEASE_BASE_URL,
        )
        commit = "c" * 39 + str(index)
        parent = "b" * 39 + str(index)
        tree = "d" * 39 + str(index)
        hosted = options.fixtures_root / "releases" / "download" / f"v{version}"
        hosted.mkdir(parents=True)
        executable_name = matrix.artifact_name(version, "linux-x86_64")
        executable = hosted / executable_name
        executable.write_bytes(f"unit-only native fixture {version}".encode())
        manifest_name = matrix.release_manifest_asset_name("linux-x86_64")
        manifest = matrix.ReleaseManifest.create_v2(
            version=version,
            platform="linux-x86_64",
            executable_size=executable.stat().st_size,
            executable_sha256=matrix._sha(executable),
            source_commit=commit,
            workflow_run="local",
            signing_key_ids=(matrix.REHEARSAL_KEY_ID,),
        )
        manifest_payload = manifest.to_bytes()
        (hosted / manifest_name).write_bytes(manifest_payload)
        installer_name = "install-linux-x86_64.sh"
        rendered = matrix._render_installer(
            source / "packaging/install.sh.in",
            version=version,
            executable=executable,
            manifest_payload=manifest_payload.decode(),
            platform_id="linux-x86_64",
            manifest_signature_required=True,
            require_hosted_signature=True,
        )
        (hosted / installer_name).write_text(rendered)
        # Signature CLI is injected below; these bytes are not cryptographic proof.
        for name in (manifest_name, installer_name):
            (hosted / f"{name}.sig").write_bytes(b"unit-only fake signature")
        wheel = (
            options.sources_root.parent / "wheels" / version / f"xferry-{version}-py3-none-any.whl"
        )
        wheel.parent.mkdir(parents=True)
        wheel.write_bytes(b"unit-only wheel fixture")
        versions[version] = {
            "base_commit": SOURCE,
            "fixture_base_commit": parent,
            "fixture_commit": commit,
            "fixture_tree": tree,
            "patch_sha256": hashlib.sha256(f"raw patch {version}\n".encode()).hexdigest(),
            "version": version,
            "wheel_sha256": matrix._sha(wheel),
            "assets": {
                path.name: {"size": path.stat().st_size, "sha256": matrix._sha(path)}
                for path in hosted.iterdir()
            },
        }
    metadata = {
        "base_commit": SOURCE,
        "platform": options.platform,
        "release_base_url": matrix.RELEASE_BASE_URL,
        "release_key": {
            "key_id": matrix.REHEARSAL_KEY_ID,
            "public_key_sha256": hashlib.sha256(PUBLIC).hexdigest(),
        },
        "versions": versions,
        "workflow_run": "local",
    }
    options.fixture_evidence.write_text(json.dumps(metadata))
    calls: list[tuple[str, ...]] = []

    def command(argv: Any, **kwargs: Any) -> bytes:
        argv = tuple(argv)
        calls.append(argv)
        if argv[0] == sys.executable:
            assert argv[1] == "-I"
            return b""
        assert argv[:2] == ("git", "--no-pager")
        source = kwargs["cwd"]
        arguments = argv[2:]
        if source == matrix.REPO_ROOT:
            assert arguments == ("rev-parse", f"{SOURCE}^{{tree}}")
            return BASE_TREE.encode() + b"\n"
        version = source.name
        entry = metadata["versions"][version]
        if arguments[0] == "show":
            return originals[arguments[1].removeprefix("HEAD^:")]
        if arguments[0] == "status":
            return b""
        if arguments[0] == "rev-list":
            return entry["fixture_base_commit"].encode() + b"\n"
        if arguments[0] == "rev-parse":
            field = {
                "HEAD": "fixture_commit",
                "HEAD^{tree}": "fixture_tree",
                "HEAD^": "fixture_base_commit",
            }.get(arguments[1])
            return (entry[field] if field else BASE_TREE).encode() + b"\n"
        if arguments[0] == "diff":
            if "--name-only" in arguments:
                return ("\n".join(matrix._PATCH_FILES) + "\n").encode()
            return f"raw patch {version}\n".encode()
        raise AssertionError("unexpected injected validation command")

    monkeypatch.setattr(matrix, "_command", command)
    return options, metadata, calls, command


def test_fixture_validation_binds_all_sources_assets_and_four_signatures(fixtures: Any) -> None:
    options, metadata, calls, _ = fixtures
    result = matrix.validate_fixtures(options)
    assert result["fixturesSha"] == matrix._sha(options.fixture_evidence)
    assert set(result["fixtureSources"]) == {"0.1.1", "0.1.2"}
    assert set(result["helpers"]) == {"matrixSha", "probeSha"}
    signature_calls = [argv for argv in calls if argv[0] == sys.executable]
    assert len(signature_calls) == 4
    assert [argv[3] for argv in signature_calls] == ["--manifest", "--installer"] * 2
    assert all(argv[1] == "-I" and "--signature" in argv for argv in signature_calls)
    assert not any(argv[0] == "docker" for argv in calls)
    for version in matrix.VERSIONS:
        assert (
            result["fixtureSources"][version]["commit"]
            == metadata["versions"][version]["fixture_commit"]
        )


@pytest.mark.parametrize(
    "invalid",
    [
        "base",
        "run",
        "platform",
        "version",
        "release_url",
        "key",
        "fingerprint",
        "asset_extra",
        "asset_missing",
        "asset_traversal",
        "asset_size",
        "asset_sha",
        "asset_symlink",
        "file_extra",
        "patch",
        "dirty_source",
        "source_text",
        "manifest_source",
        "wheel",
        "signature",
    ],
)
def test_fixture_validation_rejects_malformed_or_unbound_inventory(
    fixtures: Any,
    monkeypatch: pytest.MonkeyPatch,
    invalid: str,
) -> None:
    options, metadata, calls, command = fixtures
    version = "0.1.1"
    entry = metadata["versions"][version]
    hosted = options.fixtures_root / "releases" / "download" / "v0.1.1"
    executable = hosted / "xferry-0.1.1-linux-x86_64"
    if invalid in {"base", "run", "platform", "release_url"}:
        key = {
            "base": "base_commit",
            "run": "workflow_run",
            "platform": "platform",
            "release_url": "release_base_url",
        }[invalid]
        metadata[key] = "untrusted sensitive value"
    elif invalid == "version":
        entry["version"] = "0.1.3"
    elif invalid == "key":
        metadata["release_key"]["key_id"] = "xferry-release-2026-09"
    elif invalid == "fingerprint":
        metadata["release_key"]["public_key_sha256"] = "0" * 64
    elif invalid == "asset_extra":
        entry["assets"]["secret.log"] = {"size": 1, "sha256": "0" * 64}
    elif invalid == "asset_missing":
        entry["assets"].pop(executable.name)
    elif invalid == "asset_traversal":
        entry["assets"]["../../secret"] = entry["assets"].pop(executable.name)
    elif invalid == "asset_size":
        entry["assets"][executable.name]["size"] = True
    elif invalid == "asset_sha":
        entry["assets"][executable.name]["sha256"] = "0" * 64
    elif invalid == "asset_symlink":
        saved = executable.read_bytes()
        executable.unlink()
        outside = options.tls_dir / "secret"
        outside.write_bytes(saved)
        executable.symlink_to(outside)
    elif invalid == "file_extra":
        (hosted / "untracked-secret.log").write_bytes(b"sensitive file")
    elif invalid == "patch":
        entry["patch_sha256"] = "0" * 64
    elif invalid == "source_text":
        path = options.sources_root / version / "xferry/config.py"
        path.write_text(path.read_text() + "\nprint('sensitive altered source')\n")
    elif invalid == "manifest_source":
        path = hosted / "xferry-release-linux-x86_64.json"
        manifest = json.loads(path.read_bytes())
        manifest["source"]["commit"] = "0" * 40
        path.write_text(json.dumps(manifest))
        entry["assets"][path.name] = {"size": path.stat().st_size, "sha256": matrix._sha(path)}
    elif invalid == "wheel":
        entry["wheel_sha256"] = "0" * 64
    elif invalid in {"signature", "dirty_source"}:

        def failing(argv: Any, **kwargs: Any) -> bytes:
            if invalid == "signature" and argv[0] == sys.executable:
                raise RuntimeError("Credentials: secret failure message")
            if invalid == "dirty_source" and "status" in argv:
                return b" M xferry/config.py\n"
            return command(argv, **kwargs)

        monkeypatch.setattr(matrix, "_command", failing)
    options.fixture_evidence.write_text(json.dumps(metadata))
    with pytest.raises(matrix.MatrixFailure) as failure:
        matrix.validate_fixtures(options)
    assert str(failure.value) in {"fixture_invalid", "source_invalid", "signature_invalid"}
    assert "sensitive" not in str(failure.value)
    assert not any(argv[0] == "docker" for argv in calls)


@pytest.mark.parametrize(
    "invalid",
    [
        "extra",
        "host",
        "namespace",
        "pid1",
        "euid",
        "phases",
        "version",
        "retained",
        "health",
        "preserved",
        "enabled",
        "pid",
    ],
)
def test_probe_receipt_validator_rejects_fabricated_or_sensitive_fields(invalid: str) -> None:
    receipt = _lifecycle("ubuntu", "24.04", "linux-x86_64")
    if invalid == "extra":
        receipt["Credentials"] = "secret token"
    elif invalid in {"host", "namespace", "pid1", "euid"}:
        key, value = {
            "host": ("distro", "debian"),
            "namespace": ("cgroup_namespace", "cgroup:[100]"),
            "pid1": ("pid1", "python"),
            "euid": ("effective_uid", False),
        }[invalid]
        receipt["host"][key] = value
    elif invalid == "phases":
        receipt["stages"].reverse()
    else:
        stage = receipt["stages"][5]
        if invalid == "version":
            stage["version"] = "0.1.1"
        elif invalid == "retained":
            stage["retained_versions"] = ["0.1.2"]
        elif invalid == "health":
            stage["health"] = 1
        elif invalid == "preserved":
            stage["preserved"]["auth"] = "sensitive hash"
        elif invalid == "enabled":
            stage["service"]["enabled"] = False
        elif invalid == "pid":
            stage["service"]["main_pid"] = True
    with pytest.raises(matrix.MatrixFailure, match="^receipt_invalid$"):
        matrix.validate_probe(
            receipt, distro="ubuntu", distro_version="24.04", platform="linux-x86_64"
        )


def test_docker_construction_has_private_namespaces_only_four_scoped_mounts(fixtures: Any) -> None:
    options, _, _, _ = fixtures
    evidence = options.evidence_root.parent / "temporary-evidence"
    evidence.mkdir()
    argv = matrix.create_command(options, IMAGE, evidence)
    text = " ".join(argv)
    assert "--privileged --cgroupns private --network none" in text
    for literal in (
        "--memory 1024m",
        "--cpus 2",
        "--pids-limit 512",
        "--tmpfs /run",
        "--tmpfs /run/lock",
        "--tmpfs /tmp:rw,nosuid,nodev,noexec,mode=1777",
        "--tmpfs /var/tmp:rw,nosuid,nodev,exec,mode=1777",
        "XFERRY_SYSTEMD_REHEARSAL=1",
    ):
        assert literal in text
    mounts = [argv[index + 1] for index, item in enumerate(argv) if item == "--mount"]
    assert len(mounts) == 4
    assert sum(item.endswith(",readonly") for item in mounts) == 3
    assert all(item.endswith(",readonly") for item in mounts if "dst=/evidence" not in item)
    assert not any(
        item in text
        for item in (
            "docker.sock",
            "--network host",
            "--pid host",
            "--cgroupns host",
            "src=/sys",
            "src=/run",
            "qemu",
        )
    )
    dockerfile = matrix.dockerfile("ubuntu@sha256:" + "1" * 64).decode()
    assert "FROM ubuntu@sha256:" in dockerfile
    for package in (
        "systemd",
        "systemd-sysv",
        "dbus",
        "python3",
        "curl",
        "ca-certificates",
        "passwd",
        "coreutils",
        "findutils",
        "mawk",
        "grep",
        "util-linux",
    ):
        assert package in dockerfile
    assert (
        "mount -o remount,ro /sys; mount --bind /proc/sys /proc/sys; "
        "mount -o remount,bind,ro /proc/sys; exec /sbin/init"
    ) in dockerfile
    assert '["/bin/sh", "-ec",' in dockerfile
    assert "|| true" not in dockerfile


def test_systemd_readiness_requires_live_manager_readonly_mounts_and_private_namespace(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    commands: list[tuple[str, ...]] = []

    def command(argv: Any, **kwargs: Any) -> bytes:
        argv = tuple(argv)
        commands.append(argv)
        if argv[1] == "inspect":
            return b"true\n"
        assert argv[:5] == ("docker", "exec", CONTAINER, "sh", "-ec")
        assert kwargs["timeout"] == 15
        shell = argv[5]
        assert 'test "$(cat /proc/1/comm)" = systemd;' in shell
        assert 'test "$(cat /run/systemd/container)" = docker;' in shell
        # Display versions may contain spaces/parentheses; only query success matters.
        assert "systemctl show --property=Version --value >/dev/null;" in shell
        for mountpoint in ("/sys", "/proc/sys"):
            assert (
                'xferry_mount_options="$(findmnt --first-only --noheadings '
                f'--mountpoint {mountpoint} --output VFS-OPTIONS)"; '
                'case ",$xferry_mount_options," in *,ro,*) ;; *) exit 1 ;; esac;'
            ) in shell
        assert shell.endswith("readlink /proc/self/ns/cgroup")
        assert "for xferry_temp_path in /tmp /var/tmp; do" in shell
        assert "for xferry_required_flag in rw nosuid nodev; do" in shell
        assert '--mountpoint "$xferry_temp_path" --output VFS-OPTIONS)' in shell
        assert "--mountpoint /var/tmp --output FSTYPE)" in shell
        assert 'test "$xferry_mount_type" = tmpfs;' in shell
        assert 'test "$xferry_staging_mode" = 0:1777;' in shell
        assert "|| true" not in shell
        return b"cgroup:[200]\n"

    monkeypatch.setattr(matrix, "_command", command)
    monkeypatch.setattr(matrix.time, "sleep", lambda _: pytest.fail("ready must not sleep"))
    matrix._wait_systemd(CONTAINER, "cgroup:[100]")
    assert len(commands) == 2


def test_systemd_readiness_retries_transient_query_failure_before_success(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    probes = 0
    inspections = 0
    sleeps: list[int] = []

    def command(argv: Any, **kwargs: Any) -> bytes:
        nonlocal probes, inspections
        if argv[1] == "inspect":
            inspections += 1
            return b"true\n"
        probes += 1
        if probes == 1:
            raise matrix.MatrixFailure("docker_failed")
        return b"cgroup:[200]\n"

    monkeypatch.setattr(matrix, "_command", command)
    monkeypatch.setattr(matrix.time, "sleep", sleeps.append)
    matrix._wait_systemd(CONTAINER, "cgroup:[100]")
    assert probes == inspections == 2
    assert sleeps == [1]


@pytest.mark.parametrize(
    ("pid1", "marker", "manager_code", "sys_options", "proc_options", "mount_code", "valid"),
    [
        ("systemd", "docker", 0, "ro,nosuid", "ro,nodev", 0, True),
        ("systemd", "docker", 0, "nodev,ro,nosuid", "nodev,ro", 0, True),
        ("other", "docker", 0, "ro", "ro", 0, False),
        ("systemd", "other", 0, "ro", "ro", 0, False),
        ("systemd", "docker", 1, "ro", "ro", 0, False),
        ("systemd", "docker", 0, "rw,nosuid", "ro", 0, False),
        ("systemd", "docker", 0, "ro", "rw,nodev", 0, False),
        ("systemd", "docker", 0, "", "ro", 0, False),
        ("systemd", "docker", 0, "ro", "", 0, False),
        # A failing findmnt must not be hidden by otherwise plausible stdout.
        ("systemd", "docker", 0, "ro", "ro", 1, False),
        ("systemd", "docker", 0, "notro", "ro", 0, False),
        ("systemd", "docker", 0, "ro", "root", 0, False),
    ],
)
def test_actual_readiness_shell_preserves_every_guard_without_parsing_display_version(
    monkeypatch: pytest.MonkeyPatch,
    pid1: str,
    marker: str,
    manager_code: int,
    sys_options: str,
    proc_options: str,
    mount_code: int,
    valid: bool,
) -> None:
    _assert_actual_readiness_shell(
        monkeypatch,
        pid1=pid1,
        marker=marker,
        manager_code=manager_code,
        sys_options=sys_options,
        proc_options=proc_options,
        mount_code=mount_code,
        valid=valid,
    )


@pytest.mark.parametrize(
    ("temporary", "staging", "filesystem", "owner_mode", "type_code", "stat_code", "valid"),
    [
        ("rw,nosuid,nodev,noexec", "rw,nosuid,nodev", "tmpfs", "0:1777", 0, 0, True),
        ("noexec,nodev,nosuid,rw", "nodev,rw,nosuid,relatime", "tmpfs", "0:1777", 0, 0, True),
        ("rw,nosuid,nodev", "rw,nosuid,nodev", "tmpfs", "0:1777", 0, 0, False),
        ("rw,nosuid,nodev,nonoexec", "rw,nosuid,nodev", "tmpfs", "0:1777", 0, 0, False),
        ("rw,nodev,noexec", "rw,nosuid,nodev", "tmpfs", "0:1777", 0, 0, False),
        ("rw,nosuid,noexec", "rw,nosuid,nodev", "tmpfs", "0:1777", 0, 0, False),
        ("ro,nosuid,nodev,noexec", "rw,nosuid,nodev", "tmpfs", "0:1777", 0, 0, False),
        ("rw,nosuid,nodev,noexec", "rw,nosuid,nodev,noexec", "tmpfs", "0:1777", 0, 0, False),
        ("rw,nosuid,nodev,noexec", "ro,nosuid,nodev", "tmpfs", "0:1777", 0, 0, False),
        ("rw,nosuid,nodev,noexec", "rw,nodev", "tmpfs", "0:1777", 0, 0, False),
        ("rw,nosuid,nodev,noexec", "rw,nosuid", "tmpfs", "0:1777", 0, 0, False),
        ("rw,nosuid,nodev,noexec", "rw,nosuid,nodevice", "tmpfs", "0:1777", 0, 0, False),
        ("rw,nosuid,nodev,noexec", "", "tmpfs", "0:1777", 0, 0, False),
        ("rw,nosuid,nodev,noexec", "rw,nosuid,nodev", "ext4", "0:1777", 0, 0, False),
        ("rw,nosuid,nodev,noexec", "rw,nosuid,nodev", "tmpfs", "0:0755", 0, 0, False),
        ("rw,nosuid,nodev,noexec", "rw,nosuid,nodev", "tmpfs", "1000:1777", 0, 0, False),
        ("rw,nosuid,nodev,noexec", "rw,nosuid,nodev", "tmpfs", "0:1777", 1, 0, False),
        ("rw,nosuid,nodev,noexec", "rw,nosuid,nodev", "tmpfs", "0:1777", 0, 1, False),
    ],
)
def test_actual_readiness_shell_requires_hardened_dedicated_exec_staging(
    monkeypatch: pytest.MonkeyPatch,
    temporary: str,
    staging: str,
    filesystem: str,
    owner_mode: str,
    type_code: int,
    stat_code: int,
    valid: bool,
) -> None:
    _assert_actual_readiness_shell(
        monkeypatch,
        temporary=temporary,
        staging=staging,
        filesystem=filesystem,
        owner_mode=owner_mode,
        type_code=type_code,
        stat_code=stat_code,
        valid=valid,
    )


def _assert_actual_readiness_shell(
    monkeypatch: pytest.MonkeyPatch,
    *,
    pid1: str = "systemd",
    marker: str = "docker",
    manager_code: int = 0,
    sys_options: str = "ro,nosuid,nodev,noexec",
    proc_options: str = "ro,nosuid,nodev,noexec",
    mount_code: int = 0,
    temporary: str = "rw,nosuid,nodev,noexec",
    staging: str = "rw,nosuid,nodev",
    filesystem: str = "tmpfs",
    owner_mode: str = "0:1777",
    type_code: int = 0,
    stat_code: int = 0,
    valid: bool = True,
) -> None:
    # Execute the actual helper's shell under fixtures, never Docker/host mounts.
    definitions = f"""
cat() {{
    case "$1" in
        /proc/1/comm) printf '%s\\n' '{pid1}' ;;
        /run/systemd/container) printf '%s\\n' '{marker}' ;;
        *) return 1 ;;
    esac
}}
systemctl() {{ printf '%s\\n' '252 (252.39-1~deb12u1)'; return {manager_code}; }}
findmnt() {{
    if test "$6" = FSTYPE; then
        printf '%s\\n' '{filesystem}'; return {type_code};
    fi
    case "$4" in
        /sys) printf '%s\\n' '{sys_options}' ;;
        /proc/sys) printf '%s\\n' '{proc_options}' ;;
        /tmp) printf '%s\\n' '{temporary}' ;;
        /var/tmp) printf '%s\\n' '{staging}' ;;
        *) return 1 ;;
    esac
    return {mount_code}
}}
stat() {{ printf '%s\\n' '{owner_mode}'; return {stat_code}; }}
readlink() {{ printf '%s\\n' 'cgroup:[200]'; }}
"""

    def command(argv: Any, **kwargs: Any) -> bytes:
        if argv[1] == "inspect":
            return b"true\n"
        completed = subprocess.run(
            ["sh", "-ec", definitions + argv[5]],
            capture_output=True,
            check=False,
            timeout=2,
        )
        if completed.returncode:
            raise matrix.MatrixFailure("docker_failed")
        return completed.stdout

    monkeypatch.setattr(matrix, "_command", command)
    monkeypatch.setattr(matrix.time, "sleep", lambda _: None)
    if valid:
        matrix._wait_systemd(CONTAINER, "cgroup:[100]")
    else:
        with pytest.raises(matrix.MatrixFailure, match="^systemd_unavailable$"):
            matrix._wait_systemd(CONTAINER, "cgroup:[100]")


@pytest.mark.parametrize(
    "output",
    [
        b"cgroup:[100]\n",  # Host namespace must never be accepted.
        b"cgroup:[200]\ncgroup:[300]\n",
        b"252 (252.39-1~deb12u1)\ncgroup:[200]\n",
        b"\ncgroup:[200]\n",
        b"cgroup:[200]\n\n",
        b" cgroup:[200]\n",
        b"cgroup:[not-a-number]\n",
        b"mnt:[200]\n",
        b"",
        b"\xff\n",
    ],
)
def test_systemd_readiness_fails_closed_on_invalid_namespace_output(
    monkeypatch: pytest.MonkeyPatch, output: bytes
) -> None:
    probes = 0
    sleeps: list[int] = []

    def command(argv: Any, **kwargs: Any) -> bytes:
        nonlocal probes
        if argv[1] == "inspect":
            return b"true\n"
        probes += 1
        return output

    monkeypatch.setattr(matrix, "_command", command)
    monkeypatch.setattr(matrix.time, "sleep", sleeps.append)
    with pytest.raises(matrix.MatrixFailure, match="^systemd_unavailable$"):
        matrix._wait_systemd(CONTAINER, "cgroup:[100]")
    assert probes == 30
    assert sleeps == [1] * 30


def test_systemd_readiness_never_accepts_a_failing_manager_or_mount_check(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    probes = 0

    def command(argv: Any, **kwargs: Any) -> bytes:
        nonlocal probes
        if argv[1] == "inspect":
            return b"true\n"
        probes += 1
        raise matrix.MatrixFailure("docker_failed")

    monkeypatch.setattr(matrix, "_command", command)
    monkeypatch.setattr(matrix.time, "sleep", lambda _: None)
    with pytest.raises(matrix.MatrixFailure, match="^systemd_unavailable$"):
        matrix._wait_systemd(CONTAINER, "cgroup:[100]")
    assert probes == 30


@pytest.mark.parametrize("state", [b"false\n", b"true\nfalse\n", b"", b"unknown\n"])
def test_systemd_readiness_stops_before_exec_when_container_is_not_running(
    monkeypatch: pytest.MonkeyPatch, state: bytes
) -> None:
    commands: list[tuple[str, ...]] = []

    def command(argv: Any, **kwargs: Any) -> bytes:
        commands.append(tuple(argv))
        return state

    monkeypatch.setattr(matrix, "_command", command)
    monkeypatch.setattr(matrix.time, "sleep", lambda _: pytest.fail("stopped must not retry"))
    with pytest.raises(matrix.MatrixFailure, match="^systemd_unavailable$"):
        matrix._wait_systemd(CONTAINER, "cgroup:[100]")
    assert commands == [("docker", "inspect", "--format", "{{.State.Running}}", CONTAINER)]


@pytest.mark.parametrize("namespace", ["", "mnt:[100]", "cgroup:[100]\nextra"])
def test_systemd_readiness_rejects_invalid_host_namespace_before_docker(
    monkeypatch: pytest.MonkeyPatch, namespace: str
) -> None:
    monkeypatch.setattr(matrix, "_command", lambda *a, **k: pytest.fail("no Docker mutation"))
    with pytest.raises(matrix.MatrixFailure, match="^systemd_unavailable$"):
        matrix._wait_systemd(CONTAINER, namespace)


@pytest.mark.parametrize("machine", ["aarch64", "arm64", "amd64"])
def test_native_guard_does_not_allow_cross_arch_emulation(
    fixtures: Any,
    monkeypatch: pytest.MonkeyPatch,
    machine: str,
) -> None:
    options, _, calls, _ = fixtures
    monkeypatch.setattr(
        matrix.os, "uname", lambda: SimpleNamespace(sysname="Linux", machine=machine)
    )
    with pytest.raises(matrix.MatrixFailure, match="^native_host_required$"):
        matrix._native_guard(options)
    assert calls == []


@pytest.mark.parametrize("bad_id", ["", "all", CONTAINER + "\n" + "1" * 64, "../../host"])
def test_pair_cleanup_never_uses_uncaptured_or_malformed_container_ids(
    fixtures: Any,
    monkeypatch: pytest.MonkeyPatch,
    bad_id: str,
) -> None:
    options, _, _, _ = fixtures
    calls: list[tuple[str, ...]] = []
    monkeypatch.setattr(matrix, "_image", lambda *args: ("ubuntu@sha256:" + "1" * 64, IMAGE))

    def command(argv: Any, **kwargs: Any) -> bytes:
        calls.append(tuple(argv))
        return bad_id.encode()

    monkeypatch.setattr(matrix, "_command", command)
    result = matrix._pair(options, "ubuntu", "24.04", "cgroup:[100]")
    assert result == {
        "distro": "ubuntu",
        "distroVersion": "24.04",
        "status": "failed",
        "code": "docker_identity_invalid",
    }
    assert not any(argv[:2] in {("docker", "rm"), ("docker", "start")} for argv in calls)


def test_pair_cleans_up_exact_owned_id_and_keeps_raw_files_outside_artifacts(
    fixtures: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    options, _, _, _ = fixtures
    commands: list[tuple[str, ...]] = []
    raw_root: Path | None = None
    monkeypatch.setattr(matrix, "_image", lambda *args: ("ubuntu@sha256:" + "1" * 64, IMAGE))
    monkeypatch.setattr(matrix, "_wait_systemd", lambda *args: None)

    def command(argv: Any, **kwargs: Any) -> bytes:
        nonlocal raw_root
        argv = tuple(argv)
        commands.append(argv)
        if argv[1] == "create":
            mount = next(item for item in argv if "dst=/evidence" in item)
            raw_root = Path(mount.split("src=", 1)[1].split(",dst=", 1)[0])
            assert not raw_root.is_relative_to(options.evidence_root)
            return CONTAINER.encode()
        if argv[1] == "exec":
            assert raw_root is not None
            (raw_root / "lifecycle.json").write_text(
                json.dumps(_lifecycle("ubuntu", "24.04", options.platform))
            )
            (raw_root / "secret.log").write_text("Credentials: non-uploadable unit secret")
            assert argv[3:5] == ("python3", "/matrix-runner.py")
        return b""

    monkeypatch.setattr(matrix, "_command", command)
    result = matrix._pair(options, "ubuntu", "24.04", "cgroup:[100]")
    assert result["status"] == "passed"
    assert commands[-1] == ("docker", "rm", "--force", CONTAINER)
    assert raw_root is not None and not raw_root.exists()
    assert "Credentials" not in json.dumps(result)


def test_pair_readiness_failure_never_starts_app_probe_and_cleans_owned_container(
    fixtures: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    options, _, _, _ = fixtures
    commands: list[tuple[str, ...]] = []
    monkeypatch.setattr(matrix, "_image", lambda *args: ("ubuntu@sha256:" + "1" * 64, IMAGE))

    def command(argv: Any, **kwargs: Any) -> bytes:
        commands.append(tuple(argv))
        return CONTAINER.encode() if argv[1] == "create" else b""

    def unavailable(container_id: str, namespace: str) -> None:
        assert container_id == CONTAINER and namespace == "cgroup:[100]"
        assert commands[-1] == ("docker", "start", CONTAINER)
        raise matrix.MatrixFailure("systemd_unavailable")

    monkeypatch.setattr(matrix, "_command", command)
    monkeypatch.setattr(matrix, "_wait_systemd", unavailable)
    assert matrix._pair(options, "ubuntu", "24.04", "cgroup:[100]") == {
        "distro": "ubuntu",
        "distroVersion": "24.04",
        "status": "failed",
        "code": "systemd_unavailable",
    }
    assert commands[-1] == ("docker", "rm", "--force", CONTAINER)
    assert not any(argv[1] == "exec" for argv in commands)


@pytest.mark.parametrize("invalid", ["base_arch", "built_arch", "os", "digest", "image_id"])
def test_docker_image_verification_is_native_and_pins_only_official_digests(
    fixtures: Any,
    monkeypatch: pytest.MonkeyPatch,
    invalid: str,
) -> None:
    options, _, _, _ = fixtures
    calls: list[tuple[str, ...]] = []

    def command(argv: Any, **kwargs: Any) -> bytes:
        argv = tuple(argv)
        calls.append(argv)
        if argv[1] == "pull":
            assert "linux/amd64" in argv
            return b""
        if argv[1] == "build":
            assert b"FROM ubuntu@sha256:" in kwargs["input_bytes"]
            return b"unsafe sensitive image identity" if invalid == "image_id" else IMAGE.encode()
        assert argv[1:3] == ("image", "inspect")
        built = argv[-1] == IMAGE
        architecture = (
            "arm64"
            if ((invalid == "base_arch" and not built) or (invalid == "built_arch" and built))
            else "amd64"
        )
        digest = (
            "untrusted/ubuntu@sha256:" if invalid == "digest" else "ubuntu@sha256:"
        ) + "1" * 64
        return json.dumps(
            [
                {
                    "Id": IMAGE,
                    "Architecture": architecture,
                    "Os": "windows" if invalid == "os" else "linux",
                    "RepoDigests": [digest],
                }
            ]
        ).encode()

    monkeypatch.setattr(matrix, "_command", command)
    with pytest.raises(matrix.MatrixFailure, match="^docker_identity_invalid$"):
        matrix._image(options, "ubuntu", "24.04")
    assert not any(argv[1] == "create" for argv in calls)


@pytest.mark.parametrize("phase", ["pull", "build"])
def test_image_failures_report_only_the_exact_fixed_substep(
    fixtures: Any, monkeypatch: pytest.MonkeyPatch, phase: str
) -> None:
    options, _, _, _ = fixtures
    calls: list[tuple[str, ...]] = []

    def command(argv: Any, **kwargs: Any) -> bytes:
        argv = tuple(argv)
        calls.append(argv)
        if argv[1] == phase:
            raise matrix.MatrixFailure("docker_failed")
        if argv[1] == "pull":
            return b""
        assert argv[1:3] == ("image", "inspect")
        return json.dumps(
            [{"Architecture": "amd64", "Os": "linux", "RepoDigests": ["ubuntu@sha256:" + "1" * 64]}]
        ).encode()

    monkeypatch.setattr(matrix, "_command", command)
    with pytest.raises(matrix.MatrixFailure, match=f"^image_{phase}_failed$"):
        matrix._image(options, "ubuntu", "22.04")
    assert not any(argv[1] in {"create", "start", "exec"} for argv in calls)


def test_pair_cleanup_failure_downgrades_pass_and_does_not_echo_error(
    fixtures: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    options, _, _, _ = fixtures
    raw_root: Path | None = None
    cleanup_ids: list[str] = []
    monkeypatch.setattr(matrix, "_image", lambda *args: ("ubuntu@sha256:" + "1" * 64, IMAGE))
    monkeypatch.setattr(matrix, "_wait_systemd", lambda *args: None)

    def command(argv: Any, **kwargs: Any) -> bytes:
        nonlocal raw_root
        if argv[1] == "create":
            mount = next(item for item in argv if "dst=/evidence" in item)
            raw_root = Path(mount.split("src=", 1)[1].split(",dst=", 1)[0])
            return CONTAINER.encode()
        if argv[1] == "exec":
            assert raw_root is not None
            (raw_root / "lifecycle.json").write_text(
                json.dumps(_lifecycle("ubuntu", "24.04", options.platform))
            )
        if argv[1] == "rm":
            cleanup_ids.append(argv[-1])
            raise OSError("sensitive cleanup diagnostic must not be returned")
        return b""

    monkeypatch.setattr(matrix, "_command", command)
    assert matrix._pair(options, "ubuntu", "24.04", "cgroup:[100]") == {
        "distro": "ubuntu",
        "distroVersion": "24.04",
        "status": "failed",
        "code": "cleanup_failed",
    }
    assert cleanup_ids == [CONTAINER]


@pytest.mark.parametrize(
    ("phase", "code", "cleanup_fails", "valid"),
    [
        ("setup", "setup_outcome_invalid", False, True),
        ("update", "health_response_invalid", False, True),
        ("setup", "setup_outcome_invalid", True, True),
        ("raw-secret-phase", "command_failed", False, False),
        ("setup", "raw-secret-error", False, False),
    ],
)
def test_failed_probe_keeps_only_fixed_phase_code_and_still_requires_cleanup(
    fixtures: Any,
    monkeypatch: pytest.MonkeyPatch,
    phase: str,
    code: str,
    cleanup_fails: bool,
    valid: bool,
) -> None:
    options, _, _, _ = fixtures
    raw_root: Path | None = None
    cleanup_ids: list[str] = []
    monkeypatch.setattr(matrix, "_image", lambda *args: ("ubuntu@sha256:" + "1" * 64, IMAGE))
    monkeypatch.setattr(matrix, "_wait_systemd", lambda *args: None)

    def command(argv: Any, **kwargs: Any) -> bytes:
        nonlocal raw_root
        if argv[1] == "create":
            mount = next(item for item in argv if "dst=/evidence" in item)
            raw_root = Path(mount.split("src=", 1)[1].split(",dst=", 1)[0])
            return CONTAINER.encode()
        if argv[1] == "exec":
            assert raw_root is not None
            (raw_root / "lifecycle.json").write_text(
                json.dumps(
                    {
                        "schema": 1,
                        "scope": "native-systemd-container-fixtures",
                        "status": "failed",
                        "failure": {"phase": phase, "code": code},
                        "stages": [{"raw": "raw-secret-output"}],
                    }
                )
            )
        if argv[1] == "rm":
            cleanup_ids.append(argv[-1])
            if cleanup_fails:
                raise OSError("raw-secret-cleanup")
        return b""

    monkeypatch.setattr(matrix, "_command", command)
    receipt = matrix._pair(options, "ubuntu", "24.04", "cgroup:[100]")
    assert receipt["status"] == "failed"
    assert receipt["code"] == (
        "cleanup_failed" if cleanup_fails else "probe_failed" if valid else "receipt_invalid"
    )
    if valid and not cleanup_fails:
        assert receipt["failure"] == {"phase": phase, "code": code}
    else:
        assert "failure" not in receipt
    assert "raw-secret" not in json.dumps(receipt)
    assert cleanup_ids == [CONTAINER]
    assert raw_root is not None and not raw_root.exists()


def test_run_matrix_collects_all_five_pair_failures_without_raw_error_output(
    fixtures: Any,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    options, _, _, _ = fixtures
    calls: list[tuple[str, str]] = []
    monkeypatch.setattr(matrix, "_native_guard", lambda _: "cgroup:[100]")
    monkeypatch.setattr(
        matrix,
        "validate_fixtures",
        lambda _: {
            "fixturesSha": "1" * 64,
            "fixtureSources": {},
            "helpers": {},
        },
    )

    def pair(_: Any, distro: str, version: str, namespace: str) -> dict[str, Any]:
        calls.append((distro, version))
        return {
            "distro": distro,
            "distroVersion": version,
            "status": "failed",
            "code": "probe_failed",
        }

    monkeypatch.setattr(matrix, "_pair", pair)
    result = matrix.run_matrix(options)
    assert calls == list(matrix.PAIRS)
    assert result["status"] == "failed"
    assert result["publicReleaseEvidence"] is False
    assert len(result["receipts"]) == 5
    assert {path.name for path in options.evidence_root.iterdir()} == {
        "architecture.json",
        *(f"{distro}-{version}.json" for distro, version in matrix.PAIRS),
    }
    assert capsys.readouterr() == ("", "")


def test_invalid_fixtures_stop_before_any_docker_call(fixtures: Any, monkeypatch: Any) -> None:
    options, metadata, calls, _ = fixtures
    metadata["base_commit"] = "0" * 40
    options.fixture_evidence.write_text(json.dumps(metadata))
    monkeypatch.setattr(matrix, "_native_guard", lambda _: "cgroup:[100]")
    with pytest.raises(matrix.MatrixFailure):
        matrix.run_matrix(options)
    assert not options.evidence_root.exists()
    assert not any(argv[0] == "docker" for argv in calls)


def _write_architectures(root: Path, architectures: list[dict[str, Any]]) -> None:
    for index, architecture in enumerate(architectures):
        directory = root / f"artifact-{index}"
        directory.mkdir(parents=True)
        (directory / "architecture.json").write_text(json.dumps(architecture))


def test_ten_pair_aggregator_requires_both_native_architecture_receipts(tmp_path: Path) -> None:
    root = tmp_path / "downloaded"
    architectures = [_architecture(platform) for platform in matrix.SUPPORTED_PLATFORM_IDS]
    _write_architectures(root, architectures)
    result = matrix.verify_matrix(
        evidence_root=root,
        source_commit=SOURCE,
        workflow_run="123",
        workflow_attempt=1,
        output=tmp_path / "verified.json",
    )
    assert result["status"] == "passed"
    assert result["publicReleaseEvidence"] is False
    assert result["pairCount"] == 10
    assert result["architectures"] == architectures


@pytest.mark.parametrize(
    "invalid",
    [
        "missing_arch",
        "duplicate_arch",
        "missing_pair",
        "duplicate_pair",
        "source",
        "run",
        "attempt",
        "public",
        "scope",
        "extra",
        "helper",
        "matched_wrong_helpers",
        "unsupported",
        "failed",
        "nested_secret",
    ],
)
def test_ten_pair_aggregator_rejects_incomplete_duplicate_or_unbound_evidence(
    tmp_path: Path,
    invalid: str,
) -> None:
    architectures = [_architecture(platform) for platform in matrix.SUPPORTED_PLATFORM_IDS]
    target = architectures[1]
    if invalid == "missing_arch":
        architectures.pop()
    elif invalid == "duplicate_arch":
        architectures[1] = copy.deepcopy(architectures[0])
    elif invalid == "missing_pair":
        target["receipts"].pop()
    elif invalid == "duplicate_pair":
        target["receipts"][1] = copy.deepcopy(target["receipts"][0])
    elif invalid == "source":
        target["sourceCommit"] = "0" * 40
    elif invalid == "run":
        target["workflowRun"] = "124"
    elif invalid == "attempt":
        target["workflowAttempt"] = 2
    elif invalid == "public":
        target["publicReleaseEvidence"] = True
    elif invalid == "scope":
        target["scope"] = "public-production-lifecycle"
    elif invalid == "extra":
        target["credentials"] = "unit secret"
    elif invalid == "helper":
        target["helpers"]["probeSha"] = "9" * 64
    elif invalid == "matched_wrong_helpers":
        for architecture in architectures:
            architecture["helpers"]["probeSha"] = "9" * 64
    elif invalid == "unsupported":
        target["receipts"][0]["distroVersion"] = "20.04"
    elif invalid == "failed":
        target["status"] = "failed"
    elif invalid == "nested_secret":
        target["receipts"][0]["lifecycle"]["stages"][2]["service"]["password"] = "unit secret"
    root = tmp_path / "downloaded"
    _write_architectures(root, architectures)
    output = tmp_path / "verified.json"
    with pytest.raises(matrix.MatrixFailure):
        matrix.verify_matrix(
            evidence_root=root,
            source_commit=SOURCE,
            workflow_run="123",
            workflow_attempt=1,
            output=output,
        )
    assert not output.exists()


def test_cli_and_command_failures_emit_only_fixed_codes(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    def fail(*args: Any, **kwargs: Any) -> None:
        raise RuntimeError("Credentials: sensitive_token Authorization: unsafe raw exception")

    monkeypatch.setattr(matrix, "verify_matrix", fail)
    exit_code = matrix.main(
        [
            "verify-matrix",
            "--evidence-root",
            str(tmp_path),
            "--source-commit",
            SOURCE,
            "--workflow-run",
            "123",
            "--workflow-attempt",
            "1",
            "--output",
            str(tmp_path / "result.json"),
        ]
    )
    assert exit_code == 1
    output = capsys.readouterr()
    assert output.err == ""
    assert json.loads(output.out) == {
        "status": "failed",
        "code": "evidence_failed",
        "publicReleaseEvidence": False,
    }
    monkeypatch.setattr(
        matrix.subprocess,
        "run",
        lambda *args, **kwargs: subprocess.CompletedProcess(
            args[0],
            1,
            stdout=b"sensitive stdout",
            stderr=b"sensitive stderr",
        ),
    )
    with pytest.raises(matrix.MatrixFailure, match="^docker_failed$"):
        matrix._command(("docker", "inspect", "example"))
    assert capsys.readouterr() == ("", "")
