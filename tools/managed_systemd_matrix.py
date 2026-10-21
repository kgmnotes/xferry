"""Native, artifact-only systemd fixture matrix with a fail-closed ten-pair verifier.

Containers have private namespaces, no network, no host runtime mounts, and only
one disposable evidence directory writable. Public release readiness is never
implied by these ephemeral 0.1.1 -> 0.1.2 fixtures.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tools.build_scie_release import _render_installer  # noqa: E402
from tools.managed_systemd_probe import _FAILURE_CODES as _PROBE_FAILURE_CODES  # noqa: E402
from xferry.management.model import SUPPORTED_MANAGED_DISTRIBUTIONS  # noqa: E402
from xferry.management.release_contract import (  # noqa: E402
    SUPPORTED_PLATFORM_IDS,
    ReleaseManifest,
    artifact_name,
    release_manifest_asset_name,
    require_platform_id,
    require_source_commit,
    require_workflow_run,
)

VERSIONS = ("0.1.1", "0.1.2")
RELEASE_BASE_URL = "https://127.0.0.1:44443/releases"
REHEARSAL_KEY_ID = "xferry-rehearsal-2026-10"
PAIRS = tuple(
    (distro, version)
    for distro, versions in SUPPORTED_MANAGED_DISTRIBUTIONS
    for version in versions
)
_DOCKER_ARCH = {"linux-x86_64": "amd64", "linux-aarch64": "arm64"}
_PHASES = ("guard", "install", "setup", "doctor", "dry_run", "update", "rollback", "uninstall")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_FULL_SHA = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
_NAMESPACE = re.compile(r"cgroup:\[\d+\]\Z")
_CODES = frozenset(
    {
        "invalid_arguments",
        "native_host_required",
        "fixture_invalid",
        "source_invalid",
        "signature_invalid",
        "docker_failed",
        "image_pull_failed",
        "image_build_failed",
        "docker_identity_invalid",
        "systemd_unavailable",
        "probe_failed",
        "receipt_invalid",
        "cleanup_failed",
        "matrix_invalid",
        "evidence_failed",
    }
)
_PATCH_FILES = (
    "xferry/config.py",
    "xferry/management/releases.py",
    "xferry/management/release_trust.py",
)


class MatrixFailure(RuntimeError):
    """Only fixed safe diagnostic codes cross the command/evidence boundary."""

    def __init__(self, code: str) -> None:
        super().__init__(code if code in _CODES else "evidence_failed")


def _require(condition: bool, code: str) -> None:
    if not condition:
        raise MatrixFailure(code)


def _object(value: object, fields: set[str], code: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise MatrixFailure(code)
    return dict(value)


def _is_sha(value: object, pattern: re.Pattern[str] = _SHA256) -> bool:
    return isinstance(value, str) and pattern.fullmatch(value) is not None


def _json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _regular(path: Path, limit: int) -> bytes:
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, "rb") as stream:
            metadata = os.fstat(stream.fileno())
            _require(
                stat.S_ISREG(metadata.st_mode) and metadata.st_size <= limit, "evidence_failed"
            )
            payload = stream.read(limit + 1)
            _require(len(payload) <= limit, "evidence_failed")
            return payload
    except MatrixFailure:
        raise
    except Exception:
        raise MatrixFailure("evidence_failed") from None


def _read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(_regular(path, 4 * 1024 * 1024), object_pairs_hook=_json_object)
        _require(isinstance(value, dict), "evidence_failed")
        return dict(value)
    except MatrixFailure:
        raise
    except Exception:
        raise MatrixFailure("evidence_failed") from None


def _sha(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, "rb") as stream:
            _require(stat.S_ISREG(os.fstat(stream.fileno()).st_mode), "fixture_invalid")
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
    except MatrixFailure:
        raise
    except Exception:
        raise MatrixFailure("fixture_invalid") from None
    return digest.hexdigest()


def _write_json(path: Path, value: Mapping[str, Any]) -> None:
    payload = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(payload)


def _command(
    argv: Sequence[str],
    *,
    cwd: Path | None = None,
    input_bytes: bytes | None = None,
    timeout: int = 600,
    allowed_codes: tuple[int, ...] = (0,),
) -> bytes:
    """Capture and suppress all process output; callers use only validated facts."""
    try:
        completed = subprocess.run(
            list(argv),
            cwd=cwd,
            input=input_bytes,
            capture_output=True,
            check=False,
            timeout=timeout,
        )
        _require(completed.returncode in allowed_codes, "docker_failed")
        _require(len(completed.stdout) <= 32 * 1024 * 1024, "docker_failed")
        return completed.stdout
    except MatrixFailure:
        raise
    except Exception:
        raise MatrixFailure("docker_failed") from None


@dataclass(frozen=True)
class RunOptions:
    fixtures_root: Path
    fixture_evidence: Path
    sources_root: Path
    tls_dir: Path
    evidence_root: Path
    source_commit: str
    workflow_run: str
    workflow_attempt: int
    platform: str


def _arguments(source_commit: str, workflow_run: str, workflow_attempt: int) -> None:
    try:
        require_source_commit(source_commit)
        require_workflow_run(workflow_run)
    except ValueError:
        raise MatrixFailure("invalid_arguments") from None
    _require(type(workflow_attempt) is int and workflow_attempt > 0, "invalid_arguments")


def _native_guard(options: RunOptions) -> str:
    _arguments(options.source_commit, options.workflow_run, options.workflow_attempt)
    _require(options.platform in SUPPORTED_PLATFORM_IDS, "invalid_arguments")
    host = os.uname()
    _require(
        host.sysname == "Linux" and host.machine == options.platform.removeprefix("linux-"),
        "native_host_required",
    )
    namespace = str(Path("/proc/self/ns/cgroup").readlink())
    _require(_NAMESPACE.fullmatch(namespace) is not None, "native_host_required")
    for path in (options.fixtures_root, options.sources_root, options.tls_dir):
        _require(
            path.is_absolute()
            and path.is_dir()
            and not path.is_symlink()
            and path.resolve() == path,
            "invalid_arguments",
        )
    _require(
        options.evidence_root.is_absolute()
        and options.evidence_root.resolve() == options.evidence_root
        and not os.path.lexists(options.evidence_root),
        "invalid_arguments",
    )
    _require(not options.tls_dir.is_relative_to(options.fixtures_root), "invalid_arguments")
    for name in ("server.crt", "server.key"):
        _require(
            not (options.tls_dir / name).is_symlink() and (options.tls_dir / name).is_file(),
            "invalid_arguments",
        )
    return namespace


def _git(source: Path, *arguments: str) -> bytes:
    try:
        return _command(("git", "--no-pager", *arguments), cwd=source)
    except Exception:
        raise MatrixFailure("source_invalid") from None


def _public_key(source: Path) -> bytes:
    try:
        module = ast.parse(_regular(source / _PATCH_FILES[2], 128 * 1024))
        assignments = [
            node
            for node in module.body
            if isinstance(node, ast.AnnAssign)
            and isinstance(node.target, ast.Name)
            and node.target.id == "EMBEDDED_RELEASE_KEYS"
        ]
        _require(len(assignments) == 1, "source_invalid")
        ring = assignments[0].value
        _require(isinstance(ring, ast.Tuple) and len(ring.elts) == 1, "source_invalid")
        assert isinstance(ring, ast.Tuple)
        key = ring.elts[0]
        _require(
            isinstance(key, ast.Call)
            and isinstance(key.func, ast.Name)
            and key.func.id == "TrustedReleaseKey"
            and not key.args,
            "source_invalid",
        )
        assert isinstance(key, ast.Call)
        keywords = {item.arg: item.value for item in key.keywords}
        _require(
            set(keywords) == {"key_id", "public_key"}
            and isinstance(keywords["key_id"], ast.Constant)
            and keywords["key_id"].value == REHEARSAL_KEY_ID,
            "source_invalid",
        )
        public = keywords["public_key"]
        _require(
            isinstance(public, ast.Call)
            and isinstance(public.func, ast.Attribute)
            and isinstance(public.func.value, ast.Name)
            and public.func.value.id == "bytes"
            and public.func.attr == "fromhex"
            and not public.keywords
            and len(public.args) == 1
            and isinstance(public.args[0], ast.Constant)
            and _is_sha(public.args[0].value),
            "source_invalid",
        )
        assert isinstance(public, ast.Call) and isinstance(public.args[0], ast.Constant)
        assert isinstance(public.args[0].value, str)
        return bytes.fromhex(public.args[0].value)
    except MatrixFailure:
        raise
    except Exception:
        raise MatrixFailure("source_invalid") from None


def _verify_patch(source: Path, version: str, public: bytes) -> None:
    originals = {
        name: _git(source, "show", f"HEAD^:{name}").decode("utf-8") for name in _PATCH_FILES
    }
    config = originals[_PATCH_FILES[0]]
    version_lines = [line for line in config.splitlines() if line.startswith("__version__ = ")]
    _require(len(version_lines) == 1, "source_invalid")
    expected_config = config.replace(version_lines[0], f'__version__ = "{version}"', 1)
    releases = originals[_PATCH_FILES[1]]
    production = 'release_base_url: str = "https://github.com/kgmnotes/xferry/releases"'
    _require(releases.count(production) == 1, "source_invalid")
    expected_releases = releases.replace(
        production, f'release_base_url: str = "{RELEASE_BASE_URL}"'
    )
    trust = originals[_PATCH_FILES[2]]
    start_marker = "EMBEDDED_RELEASE_KEYS: tuple[TrustedReleaseKey, ...] = ("
    end_marker = "\nDEFAULT_RELEASE_KEY_RING = ReleaseKeyRing(EMBEDDED_RELEASE_KEYS)"
    _require(trust.count(start_marker) == trust.count(end_marker) == 1, "source_invalid")
    start, end = trust.index(start_marker), trust.index(end_marker)
    replacement = (
        start_marker + "\n    TrustedReleaseKey(\n"
        f'        key_id="{REHEARSAL_KEY_ID}",\n'
        f'        public_key=bytes.fromhex("{public.hex()}"),\n'
        "    ),\n)"
    )
    expected = (expected_config, expected_releases, trust[:start] + replacement + trust[end:])
    for name, text in zip(_PATCH_FILES, expected, strict=True):
        _require(_regular(source / name, 512 * 1024) == text.encode(), "source_invalid")


def validate_fixtures(options: RunOptions) -> dict[str, Any]:
    """Bind exact inventory, source transforms, public trust and both signatures."""
    try:
        document = _object(
            _read_json(options.fixture_evidence),
            {
                "base_commit",
                "platform",
                "release_base_url",
                "release_key",
                "versions",
                "workflow_run",
            },
            "fixture_invalid",
        )
        _require(
            document["base_commit"] == options.source_commit
            and document["platform"] == options.platform
            and document["workflow_run"] == options.workflow_run
            and document["release_base_url"] == RELEASE_BASE_URL,
            "fixture_invalid",
        )
        key = _object(document["release_key"], {"key_id", "public_key_sha256"}, "fixture_invalid")
        _require(
            key["key_id"] == REHEARSAL_KEY_ID and _is_sha(key["public_key_sha256"]),
            "fixture_invalid",
        )
        versions = _object(document["versions"], set(VERSIONS), "fixture_invalid")
        platform = require_platform_id(options.platform)
        expected_paths = {Path("releases"), Path("releases/download")}
        sources: dict[str, Any] = {}
        original_tree = _git(REPO_ROOT, "rev-parse", f"{options.source_commit}^{{tree}}").strip()
        public_keys: list[bytes] = []
        for version in VERSIONS:
            metadata = _object(
                versions[version],
                {
                    "base_commit",
                    "fixture_base_commit",
                    "fixture_commit",
                    "fixture_tree",
                    "patch_sha256",
                    "version",
                    "wheel_sha256",
                    "assets",
                },
                "fixture_invalid",
            )
            _require(
                metadata["base_commit"] == options.source_commit
                and metadata["version"] == version
                and all(
                    _is_sha(metadata[name], _FULL_SHA)
                    for name in ("fixture_base_commit", "fixture_commit", "fixture_tree")
                )
                and _is_sha(metadata["patch_sha256"])
                and _is_sha(metadata["wheel_sha256"]),
                "fixture_invalid",
            )
            manifest_name = release_manifest_asset_name(platform)
            installer_name = f"install-{platform}.sh"
            executable_name = artifact_name(version, platform)
            assets = _object(
                metadata["assets"],
                {
                    manifest_name,
                    f"{manifest_name}.sig",
                    installer_name,
                    f"{installer_name}.sig",
                    executable_name,
                },
                "fixture_invalid",
            )
            hosted = options.fixtures_root / "releases" / "download" / f"v{version}"
            expected_paths.add(hosted.relative_to(options.fixtures_root))
            for name, raw_asset in assets.items():
                asset = _object(raw_asset, {"sha256", "size"}, "fixture_invalid")
                _require(
                    _is_sha(asset["sha256"]) and type(asset["size"]) is int and asset["size"] > 0,
                    "fixture_invalid",
                )
                path = hosted / name
                _require(
                    not path.is_symlink()
                    and path.is_file()
                    and path.stat().st_size == asset["size"]
                    and _sha(path) == asset["sha256"],
                    "fixture_invalid",
                )
                expected_paths.add(path.relative_to(options.fixtures_root))
            source = options.sources_root / version
            _require(source.is_dir() and not source.is_symlink(), "source_invalid")
            _require(
                _git(source, "rev-parse", "HEAD").strip().decode() == metadata["fixture_commit"]
                and _git(source, "rev-parse", "HEAD^{tree}").strip().decode()
                == metadata["fixture_tree"]
                and _git(source, "rev-parse", "HEAD^").strip().decode()
                == metadata["fixture_base_commit"]
                and _git(source, "rev-list", "--parents", "-n", "1", "HEAD^").strip().decode()
                == metadata["fixture_base_commit"]
                and _git(source, "rev-parse", "HEAD^^{tree}").strip() == original_tree
                and not _git(source, "status", "--porcelain", "--untracked-files=no").strip(),
                "source_invalid",
            )
            patch = _git(source, "diff", "--no-ext-diff", "--binary", "HEAD^", "HEAD")
            _require(
                hashlib.sha256(patch).hexdigest() == metadata["patch_sha256"], "source_invalid"
            )
            _require(
                set(_git(source, "diff", "--name-only", "HEAD^", "HEAD").decode().splitlines())
                == set(_PATCH_FILES),
                "source_invalid",
            )
            public = _public_key(source)
            _require(
                hashlib.sha256(public).hexdigest() == key["public_key_sha256"], "source_invalid"
            )
            public_keys.append(public)
            _verify_patch(source, version, public)
            wheel = (
                options.sources_root.parent
                / "wheels"
                / version
                / f"xferry-{version}-py3-none-any.whl"
            )
            _require(_sha(wheel) == metadata["wheel_sha256"], "fixture_invalid")
            manifest = ReleaseManifest.parse_new(_regular(hosted / manifest_name, 64 * 1024))
            _require(
                manifest.version == version
                and manifest.tag == f"v{version}"
                and manifest.platform == platform
                and manifest.source_commit == metadata["fixture_commit"]
                and manifest.workflow_run == options.workflow_run
                and manifest.executable_name == executable_name
                and manifest.executable_size == assets[executable_name]["size"]
                and manifest.executable_sha256 == assets[executable_name]["sha256"]
                and dict(manifest.artifact_digests)
                == {executable_name: assets[executable_name]["sha256"]}
                and manifest.signing_scheme == "ed25519"
                and manifest.signing_key_ids == (REHEARSAL_KEY_ID,),
                "fixture_invalid",
            )
            rendered = _render_installer(
                source / "packaging/install.sh.in",
                version=version,
                executable=hosted / executable_name,
                manifest_payload=(hosted / manifest_name).read_text(),
                platform_id=platform,
                manifest_signature_required=True,
                require_hosted_signature=True,
            )
            _require(
                _regular(hosted / installer_name, 1024 * 1024) == rendered.encode(),
                "fixture_invalid",
            )
            verifier = source / "tools/verify_release_signature.py"
            _regular(verifier, 128 * 1024)
            for kind, name in (("manifest", manifest_name), ("installer", installer_name)):
                try:
                    _command(
                        (
                            sys.executable,
                            "-I",
                            str(verifier),
                            f"--{kind}",
                            str(hosted / name),
                            "--signature",
                            str(hosted / f"{name}.sig"),
                        ),
                        cwd=source,
                    )
                except Exception:
                    raise MatrixFailure("signature_invalid") from None
            sources[version] = {
                "commit": metadata["fixture_commit"],
                "tree": metadata["fixture_tree"],
                "baseCommit": metadata["fixture_base_commit"],
                "patchSha": metadata["patch_sha256"],
            }
        actual_paths = set()
        for path in options.fixtures_root.rglob("*"):
            _require(not path.is_symlink(), "fixture_invalid")
            actual_paths.add(path.relative_to(options.fixtures_root))
        _require(
            actual_paths == expected_paths and public_keys[0] == public_keys[1], "fixture_invalid"
        )
        return {
            "fixturesSha": _sha(options.fixture_evidence),
            "fixtureSources": sources,
            "helpers": {
                "matrixSha": _sha(Path(__file__)),
                "probeSha": _sha(REPO_ROOT / "tools/managed_systemd_probe.py"),
            },
        }
    except MatrixFailure:
        raise
    except Exception:
        raise MatrixFailure("fixture_invalid") from None


def validate_probe(
    document: object,
    *,
    distro: str,
    distro_version: str,
    platform: str,
    host_namespace: str | None = None,
) -> dict[str, Any]:
    """Accept only actual passed, exact-version/private-systemd proof fields."""
    result = _object(document, {"schema", "scope", "status", "host", "stages"}, "receipt_invalid")
    _require(
        type(result["schema"]) is int
        and result["schema"] == 1
        and result["scope"] == "native-systemd-container-fixtures"
        and result["status"] == "passed",
        "receipt_invalid",
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
        "receipt_invalid",
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
        and isinstance(host["cgroup_namespace"], str)
        and isinstance(host["host_cgroup_namespace"], str)
        and _NAMESPACE.fullmatch(host["cgroup_namespace"]) is not None
        and _NAMESPACE.fullmatch(host["host_cgroup_namespace"]) is not None
        and host["cgroup_namespace"] != host["host_cgroup_namespace"]
        and (host_namespace is None or host["host_cgroup_namespace"] == host_namespace),
        "receipt_invalid",
    )
    _require(
        isinstance(result["stages"], list) and len(result["stages"]) == len(_PHASES),
        "receipt_invalid",
    )
    for raw_stage, phase in zip(result["stages"], _PHASES, strict=True):
        fields = {"phase", "status"}
        if phase != "guard":
            fields.add("service")
        if phase not in {"guard", "uninstall"}:
            fields.update(("current_link", "version", "retained_versions"))
        if phase not in {"guard", "install", "uninstall"}:
            fields.add("health")
        if phase == "doctor":
            fields.add("checks")
        if phase in {"dry_run", "update", "rollback", "uninstall"}:
            fields.add("preserved")
        if phase == "uninstall":
            fields.add("removed")
        stage = _object(raw_stage, fields, "receipt_invalid")
        _require(stage["phase"] == phase and stage["status"] == "passed", "receipt_invalid")
        if "service" in fields:
            service = _object(
                stage["service"],
                {
                    "active",
                    "main_pid",
                    "enabled",
                    "load_state",
                    "listener_gone",
                },
                "receipt_invalid",
            )
            active = phase not in {"install", "uninstall"}
            _require(
                service["active"] is active
                and service["enabled"] is active
                and service["listener_gone"] is (not active)
                and service["load_state"] == ("loaded" if active else "not-found")
                and type(service["main_pid"]) is int
                and (0 < service["main_pid"] < 2**31 if active else service["main_pid"] == 0),
                "receipt_invalid",
            )
        if "version" in fields:
            expected_version = "0.1.2" if phase == "update" else "0.1.1"
            retained = list(VERSIONS) if phase in {"update", "rollback"} else ["0.1.1"]
            _require(
                stage["version"] == expected_version
                and stage["current_link"] == f"releases/{expected_version}"
                and stage["retained_versions"] == retained,
                "receipt_invalid",
            )
        if "health" in fields:
            _require(stage["health"] is True, "receipt_invalid")
        if "preserved" in fields:
            preserved = _object(
                stage["preserved"], {"config", "auth", "sentinel"}, "receipt_invalid"
            )
            _require(all(value is True for value in preserved.values()), "receipt_invalid")
        if "checks" in fields:
            checks = _object(
                stage["checks"],
                {
                    "platform",
                    "installation",
                    "configuration",
                    "service",
                    "network",
                    "health",
                },
                "receipt_invalid",
            )
            _require(all(value is True for value in checks.values()), "receipt_invalid")
        if "removed" in fields:
            _require(stage["removed"] is True, "receipt_invalid")
    return result


def dockerfile(base_digest: str) -> bytes:
    _require(
        re.fullmatch(r"(?:ubuntu|debian)@sha256:[0-9a-f]{64}", base_digest) is not None,
        "docker_identity_invalid",
    )
    return (
        f"FROM {base_digest}\nENV container=docker DEBIAN_FRONTEND=noninteractive\n"
        "RUN apt-get update && apt-get install -y --no-install-recommends "
        "systemd systemd-sysv dbus python3 curl ca-certificates passwd "
        "coreutils findutils mawk grep mount util-linux "
        "&& rm -rf /var/lib/apt/lists/*\nSTOPSIGNAL SIGRTMIN+3\n"
        'CMD ["/bin/sh", "-ec", "mount -o remount,ro /sys; '
        "mount --bind /proc/sys /proc/sys; "
        'mount -o remount,bind,ro /proc/sys; exec /sbin/init"]\n'
    ).encode()


def create_command(options: RunOptions, image_id: str, evidence_dir: Path) -> tuple[str, ...]:
    _require(re.fullmatch(r"sha256:[0-9a-f]{64}", image_id) is not None, "docker_identity_invalid")
    mounts = (
        (options.fixtures_root, "/fixtures", True),
        (options.tls_dir, "/fixture-tls", True),
        (REPO_ROOT / "tools/managed_systemd_probe.py", "/matrix-runner.py", True),
        (evidence_dir, "/evidence", False),
    )
    argv = [
        "docker",
        "create",
        "--privileged",
        "--cgroupns",
        "private",
        "--network",
        "none",
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
        "org.xferry.systemd-rehearsal=1",
    ]
    for source, target, readonly in mounts:
        _require(
            source.is_absolute()
            and source.resolve() == source
            and not any(character in str(source) for character in ",\n\r"),
            "invalid_arguments",
        )
        mount = f"type=bind,src={source},dst={target}" + (",readonly" if readonly else "")
        argv.extend(("--mount", mount))
    argv.append(image_id)
    return tuple(argv)


def _image(options: RunOptions, distro: str, version: str) -> tuple[str, str]:
    architecture = _DOCKER_ARCH[options.platform]
    platform = f"linux/{architecture}"
    tag = f"{distro}:{version}"
    try:
        _command(("docker", "pull", "--platform", platform, tag))
    except MatrixFailure:
        raise MatrixFailure("image_pull_failed") from None
    try:
        inspected = json.loads(_command(("docker", "image", "inspect", tag)))
        _require(isinstance(inspected, list) and len(inspected) == 1, "docker_identity_invalid")
        image = inspected[0]
        _require(
            image["Architecture"] == architecture
            and image["Os"] == "linux"
            and isinstance(image["RepoDigests"], list),
            "docker_identity_invalid",
        )
        digests = []
        for digest in image["RepoDigests"]:
            if isinstance(digest, str):
                canonical = digest.removeprefix("docker.io/library/")
                if re.fullmatch(rf"{distro}@sha256:[0-9a-f]{{64}}", canonical):
                    digests.append(canonical)
        _require(len(set(digests)) == 1, "docker_identity_invalid")
        base = digests[0]
        try:
            built_id = _command(
                ("docker", "build", "--quiet", "--platform", platform, "-"),
                input_bytes=dockerfile(base),
            )
        except MatrixFailure:
            raise MatrixFailure("image_build_failed") from None
        image_id = built_id.strip().decode("ascii")
        _require(
            re.fullmatch(r"sha256:[0-9a-f]{64}", image_id) is not None, "docker_identity_invalid"
        )
        built = json.loads(_command(("docker", "image", "inspect", image_id)))
        _require(
            isinstance(built, list)
            and len(built) == 1
            and built[0]["Id"] == image_id
            and built[0]["Architecture"] == architecture
            and built[0]["Os"] == "linux",
            "docker_identity_invalid",
        )
        return base, image_id
    except MatrixFailure:
        raise
    except Exception:
        raise MatrixFailure("docker_identity_invalid") from None


def _container_running(container_id: str) -> None:
    _require(_SHA256.fullmatch(container_id) is not None, "docker_identity_invalid")
    state = _command(("docker", "inspect", "--format", "{{.State.Running}}", container_id)).strip()
    _require(state == b"true", "systemd_unavailable")


def _wait_systemd(container_id: str, host_namespace: str) -> None:
    _require(_NAMESPACE.fullmatch(host_namespace) is not None, "systemd_unavailable")
    for _ in range(30):
        _container_running(container_id)
        try:
            observed = (
                _command(
                    (
                        "docker",
                        "exec",
                        container_id,
                        "sh",
                        "-ec",
                        'test "$(cat /proc/1/comm)" = systemd; '
                        'test "$(cat /run/systemd/container)" = docker; '
                        # Query the live manager, not its distro-specific display version.
                        "systemctl show --property=Version --value >/dev/null; "
                        'xferry_mount_options="$(findmnt --first-only --noheadings '
                        '--mountpoint /sys --output VFS-OPTIONS)"; '
                        'case ",$xferry_mount_options," in *,ro,*) ;; *) exit 1 ;; esac; '
                        'xferry_mount_options="$(findmnt --first-only --noheadings '
                        '--mountpoint /proc/sys --output VFS-OPTIONS)"; '
                        'case ",$xferry_mount_options," in *,ro,*) ;; *) exit 1 ;; esac; '
                        "for xferry_temp_path in /tmp /var/tmp; do "
                        'xferry_mount_options="$(findmnt --first-only --noheadings '
                        '--mountpoint "$xferry_temp_path" --output VFS-OPTIONS)"; '
                        "for xferry_required_flag in rw nosuid nodev; do "
                        'case ",$xferry_mount_options," in *,$xferry_required_flag,*) ;; '
                        "*) exit 1 ;; esac; done; "
                        'if test "$xferry_temp_path" = /tmp; then '
                        'case ",$xferry_mount_options," in *,noexec,*) ;; *) exit 1 ;; esac; '
                        'else case ",$xferry_mount_options," in *,noexec,*) exit 1 ;; esac; '
                        "fi; done; "
                        'xferry_mount_type="$(findmnt --first-only --noheadings '
                        '--mountpoint /var/tmp --output FSTYPE)"; '
                        'test "$xferry_mount_type" = tmpfs; '
                        'xferry_staging_mode="$(stat -c "%u:%a" /var/tmp)"; '
                        'test "$xferry_staging_mode" = 0:1777; '
                        "readlink /proc/self/ns/cgroup",
                    ),
                    timeout=15,
                )
                .decode("ascii")
                .splitlines()
            )
            if (
                len(observed) == 1
                and _NAMESPACE.fullmatch(observed[0])
                and observed[0] != host_namespace
            ):
                return
        except (MatrixFailure, UnicodeDecodeError):
            pass
        time.sleep(1)
    raise MatrixFailure("systemd_unavailable")


def _pair(options: RunOptions, distro: str, version: str, host_namespace: str) -> dict[str, Any]:
    container_id: str | None = None
    receipt: dict[str, Any] = {"distro": distro, "distroVersion": version, "status": "failed"}
    try:
        base, image_id = _image(options, distro, version)
        with tempfile.TemporaryDirectory(prefix="xferry-systemd-pair-") as tmp:
            raw_evidence = Path(tmp).resolve()
            candidate = (
                _command(create_command(options, image_id, raw_evidence)).strip().decode("ascii")
            )
            _require(_SHA256.fullmatch(candidate) is not None, "docker_identity_invalid")
            container_id = candidate
            _command(("docker", "start", container_id))
            _wait_systemd(container_id, host_namespace)
            _command(
                (
                    "docker",
                    "exec",
                    container_id,
                    "python3",
                    "/matrix-runner.py",
                    "--fixtures-root",
                    "/fixtures",
                    "--tls-dir",
                    "/fixture-tls",
                    "--evidence",
                    "/evidence/lifecycle.json",
                    "--distro",
                    distro,
                    "--distro-version",
                    version,
                    "--machine",
                    options.platform.removeprefix("linux-"),
                    "--platform",
                    options.platform,
                    "--host-cgroup-namespace",
                    host_namespace,
                ),
                timeout=900,
                allowed_codes=(0, 1),
            )
            document = _read_json(raw_evidence / "lifecycle.json")
            if document.get("status") == "failed":
                failure = _object(document.get("failure"), {"phase", "code"}, "receipt_invalid")
                _require(
                    type(document.get("schema")) is int
                    and document["schema"] == 1
                    and document.get("scope") == "native-systemd-container-fixtures"
                    and isinstance(failure["phase"], str)
                    and failure["phase"] in _PHASES
                    and isinstance(failure["code"], str)
                    and failure["code"] in _PROBE_FAILURE_CODES,
                    "receipt_invalid",
                )
                # Copy only fixed phase/code identifiers, never raw failed stages/output.
                receipt.update(code="probe_failed", failure=failure)
                return receipt
            lifecycle = validate_probe(
                document,
                distro=distro,
                distro_version=version,
                platform=options.platform,
                host_namespace=host_namespace,
            )
            receipt.update(
                status="passed",
                baseImage=base,
                imageId=image_id,
                containerId=container_id,
                lifecycle=lifecycle,
            )
    except Exception as exc:
        receipt["code"] = str(exc) if isinstance(exc, MatrixFailure) else "probe_failed"
    finally:
        if container_id is not None:
            try:
                _require(_SHA256.fullmatch(container_id) is not None, "docker_identity_invalid")
                _command(("docker", "rm", "--force", container_id), timeout=60)
            except Exception:
                receipt.clear()
                receipt.update(
                    distro=distro,
                    distroVersion=version,
                    status="failed",
                    code="cleanup_failed",
                )
    return receipt


def run_matrix(options: RunOptions) -> dict[str, Any]:
    host_namespace = _native_guard(options)
    verified = validate_fixtures(options)  # No container/image call may precede this.
    options.evidence_root.mkdir(parents=True, exist_ok=False)
    receipts = []
    for distro, version in PAIRS:
        receipt = _pair(options, distro, version, host_namespace)
        _write_json(options.evidence_root / f"{distro}-{version}.json", receipt)
        receipts.append(receipt)
    result = {
        "schema": 1,
        "scope": "native-systemd-fixture-matrix",
        "sourceCommit": options.source_commit,
        "workflowRun": options.workflow_run,
        "workflowAttempt": options.workflow_attempt,
        "platform": options.platform,
        **verified,
        "publicReleaseEvidence": False,
        "status": "passed"
        if all(receipt["status"] == "passed" for receipt in receipts)
        else "failed",
        "receipts": receipts,
    }
    _write_json(options.evidence_root / "architecture.json", result)
    return result


def validate_architecture(
    document: object,
    *,
    source_commit: str,
    workflow_run: str,
    workflow_attempt: int,
) -> dict[str, Any]:
    result = _object(
        document,
        {
            "schema",
            "scope",
            "sourceCommit",
            "workflowRun",
            "workflowAttempt",
            "platform",
            "fixturesSha",
            "fixtureSources",
            "helpers",
            "publicReleaseEvidence",
            "status",
            "receipts",
        },
        "matrix_invalid",
    )
    _require(
        type(result["schema"]) is int
        and result["schema"] == 1
        and result["scope"] == "native-systemd-fixture-matrix"
        and result["sourceCommit"] == source_commit
        and result["workflowRun"] == workflow_run
        and type(result["workflowAttempt"]) is int
        and result["workflowAttempt"] == workflow_attempt
        and result["platform"] in SUPPORTED_PLATFORM_IDS
        and result["publicReleaseEvidence"] is False
        and result["status"] == "passed"
        and _is_sha(result["fixturesSha"]),
        "matrix_invalid",
    )
    helpers = _object(result["helpers"], {"matrixSha", "probeSha"}, "matrix_invalid")
    _require(all(_is_sha(value) for value in helpers.values()), "matrix_invalid")
    sources = _object(result["fixtureSources"], set(VERSIONS), "matrix_invalid")
    for source in sources.values():
        identity = _object(source, {"commit", "tree", "baseCommit", "patchSha"}, "matrix_invalid")
        _require(
            all(_is_sha(identity[name], _FULL_SHA) for name in ("commit", "tree", "baseCommit"))
            and _is_sha(identity["patchSha"]),
            "matrix_invalid",
        )
    _require(
        isinstance(result["receipts"], list) and len(result["receipts"]) == len(PAIRS),
        "matrix_invalid",
    )
    observed = set()
    for raw_receipt in result["receipts"]:
        receipt = _object(
            raw_receipt,
            {
                "distro",
                "distroVersion",
                "status",
                "baseImage",
                "imageId",
                "containerId",
                "lifecycle",
            },
            "matrix_invalid",
        )
        pair = (receipt["distro"], receipt["distroVersion"])
        _require(
            pair in PAIRS
            and pair not in observed
            and receipt["status"] == "passed"
            and isinstance(receipt["baseImage"], str)
            and re.fullmatch(rf"{pair[0]}@sha256:[0-9a-f]{{64}}", receipt["baseImage"]) is not None
            and isinstance(receipt["imageId"], str)
            and re.fullmatch(r"sha256:[0-9a-f]{64}", receipt["imageId"]) is not None
            and _is_sha(receipt["containerId"]),
            "matrix_invalid",
        )
        observed.add(pair)
        validate_probe(
            receipt["lifecycle"],
            distro=pair[0],
            distro_version=pair[1],
            platform=result["platform"],
        )
    _require(observed == set(PAIRS), "matrix_invalid")
    return result


def verify_matrix(
    *,
    evidence_root: Path,
    source_commit: str,
    workflow_run: str,
    workflow_attempt: int,
    output: Path,
) -> dict[str, Any]:
    _arguments(source_commit, workflow_run, workflow_attempt)
    files = sorted(evidence_root.rglob("architecture.json"))
    _require(len(files) == len(SUPPORTED_PLATFORM_IDS), "matrix_invalid")
    architectures = [
        validate_architecture(
            _read_json(path),
            source_commit=source_commit,
            workflow_run=workflow_run,
            workflow_attempt=workflow_attempt,
        )
        for path in files
    ]
    _require(
        {item["platform"] for item in architectures} == set(SUPPORTED_PLATFORM_IDS)
        and architectures[0]["helpers"] == architectures[1]["helpers"],
        "matrix_invalid",
    )
    _require(
        architectures[0]["helpers"]
        == {
            "matrixSha": _sha(Path(__file__)),
            "probeSha": _sha(REPO_ROOT / "tools/managed_systemd_probe.py"),
        },
        "matrix_invalid",
    )
    result = {
        "schema": 1,
        "scope": "native-systemd-ten-pair-fixture-matrix",
        "status": "passed",
        "sourceCommit": source_commit,
        "workflowRun": workflow_run,
        "workflowAttempt": workflow_attempt,
        "publicReleaseEvidence": False,
        "pairCount": len(PAIRS) * len(SUPPORTED_PLATFORM_IDS),
        "architectures": architectures,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    _write_json(output, result)
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    run = commands.add_parser("run")
    verify = commands.add_parser("verify-matrix")
    for command in (run, verify):
        for name in ("source-commit", "workflow-run"):
            command.add_argument(f"--{name}", required=True)
        command.add_argument("--workflow-attempt", type=int, required=True)
        command.add_argument("--evidence-root", type=Path, required=True)
    for name in ("fixtures-root", "fixture-evidence", "sources-root", "tls-dir"):
        run.add_argument(f"--{name}", type=Path, required=True)
    run.add_argument("--platform", choices=SUPPORTED_PLATFORM_IDS, required=True)
    verify.add_argument("--output", type=Path, required=True)
    arguments = vars(parser.parse_args(argv))
    command = arguments.pop("command")
    try:
        result = (
            run_matrix(RunOptions(**arguments)) if command == "run" else verify_matrix(**arguments)
        )
        print(
            json.dumps({key: result[key] for key in ("scope", "status", "publicReleaseEvidence")})
        )
        return 0 if result["status"] == "passed" else 1
    except Exception as exc:
        code = str(exc) if isinstance(exc, MatrixFailure) else "evidence_failed"
        print(json.dumps({"status": "failed", "code": code, "publicReleaseEvidence": False}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
