"""Release-bundle and bootstrap-installer contracts."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import zipfile
from collections.abc import Callable, Sequence
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from tools.build_scie_release import CommandRunner, ReleaseBundle, build_release_bundle
from tools.sign_release_metadata import (
    main as sign_release_metadata,
)
from tools.sign_release_metadata import (
    sign_installer,
    sign_manifest,
)
from tools.verify_release_signature import verify_installer_files
from xferry.management.health import HealthResult
from xferry.management.model import HostFacts, ManagedLayout
from xferry.management.release_contract import (
    LINUX_AARCH64,
    LINUX_X86_64,
    MAX_MANIFEST_BYTES,
    SUPPORTED_PLATFORM_IDS,
    PlatformId,
)
from xferry.management.release_trust import (
    MANIFEST_SIGNATURE_TYPE,
    MAX_SIGNATURE_BYTES,
    ReleaseKeyRing,
    TrustedReleaseKey,
    create_detached_signature,
    verify_signed_manifest,
)
from xferry.management.releases import ReleaseManager, ReleaseManifest
from xferry.management.system import CommandResult

REPO_ROOT = Path(__file__).resolve().parents[1]
TEST_SOURCE_COMMIT = "b" * 40
TEST_WORKFLOW_RUN = "654321"
TEST_INSTALLED_PAYLOAD = b"xferry-0.2.0"
TEST_INSTALLED_SHA256 = hashlib.sha256(TEST_INSTALLED_PAYLOAD).hexdigest()
UNSUPPORTED_MANAGED_STATE_INSTRUCTION_CLAUSES = (
    (
        "Unsupported or ambiguous XFerry managed state was detected and preserved; "
        "no changes were made."
    ),
    "Back up the existing XFerry configuration and data.",
    "Remove the managed state with its original tooling.",
    "Then install XFerry in a clean environment.",
)


@pytest.fixture(autouse=True)
def _stable_native_build_host(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep builder contracts deterministic on both native workflow runners."""
    monkeypatch.setattr(
        "tools.build_scie_release.current_platform_id",
        lambda: LINUX_X86_64,
    )


def test_release_builder_help_runs_when_invoked_directly_in_isolated_mode() -> None:
    """The release workflow runs this script without the checkout on sys.path."""
    result = subprocess.run(
        [
            sys.executable,
            "-I",
            "-S",
            str(REPO_ROOT / "tools" / "build_scie_release.py"),
            "--help",
        ],
        cwd=REPO_ROOT,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert "Build deterministic SCIE products" in result.stdout
    assert "--platform {linux-x86_64,linux-aarch64}" in result.stdout


class FakeRunner:
    """Command boundary that builds a fixed SCIE payload without network access."""

    def __init__(self, payload: bytes) -> None:
        self.payload = payload
        self.commands: list[tuple[tuple[str, ...], Path]] = []

    def __call__(self, command: Sequence[str], cwd: Path) -> None:
        self.commands.append((tuple(command), cwd))
        if tuple(command[:3]) == ("python", "-m", "build"):
            wheel_dir = Path(command[command.index("--outdir") + 1])
            wheel_dir.mkdir(parents=True)
            with zipfile.ZipFile(wheel_dir / "xferry-0.1.0-py3-none-any.whl", "w") as wheel:
                wheel.writestr("xferry/__init__.py", "")
        if tuple(command[:3]) == ("pex3", "lock", "create"):
            output = Path(command[command.index("-o") + 1])
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text("lock", encoding="utf-8")
        if tuple(command[:1]) == ("pex",) and "--scie" in command:
            output = Path(command[command.index("-o") + 1])
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_bytes(self.payload)
            output.chmod(0o755)


class ForbiddenWheelRunner(FakeRunner):
    """Build boundary that injects an internal file into the candidate SCIE wheel."""

    def __call__(self, command: Sequence[str], cwd: Path) -> None:
        super().__call__(command, cwd)
        if tuple(command[:3]) == ("python", "-m", "build"):
            wheel_dir = Path(command[command.index("--outdir") + 1])
            with zipfile.ZipFile(wheel_dir / "xferry-0.1.0-py3-none-any.whl", "w") as wheel:
                wheel.writestr("xferry/__init__.py", "")
                wheel.writestr("CLAU" + "DE.md", "private instructions")


class NestedForbiddenWheelRunner(FakeRunner):
    """Build boundary that injects a nested internal directory into the SCIE wheel."""

    def __call__(self, command: Sequence[str], cwd: Path) -> None:
        super().__call__(command, cwd)
        if tuple(command[:3]) == ("python", "-m", "build"):
            wheel_dir = Path(command[command.index("--outdir") + 1])
            with zipfile.ZipFile(wheel_dir / "xferry-0.1.0-py3-none-any.whl", "w") as wheel:
                wheel.writestr("xferry/__init__.py", "")
                wheel.writestr(
                    "/".join(("xferry", "implementation" + "-plan", "private.md")),
                    "private instructions",
                )


class ExtraCandidateRunner(FakeRunner):
    """Inject a second platform candidate to exercise exact-output validation."""

    def __call__(self, command: Sequence[str], cwd: Path) -> None:
        super().__call__(command, cwd)
        if tuple(command[:1]) == ("pex",) and "--scie" in command:
            output = Path(command[command.index("-o") + 1])
            output.with_name("xferry-0.1.0-linux-aarch64").write_bytes(b"unexpected")


def _render_bundle(
    tmp_path: Path,
    payload: bytes = b"scie",
    *,
    platform_id: PlatformId = LINUX_X86_64,
    signing_key_id: str | None = None,
    require_hosted_signature: bool = False,
) -> ReleaseBundle:
    return build_release_bundle(
        REPO_ROOT,
        tmp_path / "bundle",
        "0.1.0",
        FakeRunner(payload),
        platform_id=platform_id,
        source_commit=TEST_SOURCE_COMMIT,
        workflow_run=TEST_WORKFLOW_RUN,
        signing_key_id=signing_key_id,
        require_hosted_signature=require_hosted_signature,
    )


def test_release_builder_rejects_a_wheel_with_an_internal_public_surface(tmp_path: Path) -> None:
    """Catches SCIE construction accepting an internal artifact from its real wheel input."""
    with pytest.raises(RuntimeError, match="CLAU" + "DE.md"):
        build_release_bundle(
            REPO_ROOT,
            tmp_path / "bundle",
            "0.1.0",
            ForbiddenWheelRunner(b"scie"),
            platform_id=LINUX_X86_64,
        )


def test_release_builder_rejects_nested_internal_wheel_content(tmp_path: Path) -> None:
    """Catches SCIE construction accepting a nested internal path in its wheel."""
    with pytest.raises(RuntimeError, match="implementation" + "-plan"):
        build_release_bundle(
            REPO_ROOT,
            tmp_path / "bundle",
            "0.1.0",
            NestedForbiddenWheelRunner(b"scie"),
            platform_id=LINUX_X86_64,
        )


def test_release_builder_rejects_unknown_platform_before_build_or_output(tmp_path: Path) -> None:
    runner = FakeRunner(b"scie")
    output = tmp_path / "bundle"

    with pytest.raises(ValueError, match="unknown release platform"):
        build_release_bundle(
            REPO_ROOT,
            output,
            "0.1.0",
            runner,
            platform_id="linux-riscv64",  # type: ignore[arg-type]
            source_commit=TEST_SOURCE_COMMIT,
            workflow_run=TEST_WORKFLOW_RUN,
        )

    assert runner.commands == []
    assert not output.exists()


def test_release_builder_rejects_platform_mismatched_build_host_before_output(
    tmp_path: Path,
) -> None:
    runner = FakeRunner(b"scie")
    output = tmp_path / "bundle"

    with pytest.raises(RuntimeError, match="does not match build host"):
        build_release_bundle(
            REPO_ROOT,
            output,
            "0.1.0",
            runner,
            platform_id=LINUX_AARCH64,
            source_commit=TEST_SOURCE_COMMIT,
            workflow_run=TEST_WORKFLOW_RUN,
        )

    assert runner.commands == []
    assert not output.exists()


def test_release_builder_refuses_existing_output_without_mutation(tmp_path: Path) -> None:
    runner = FakeRunner(b"scie")
    output = tmp_path / "bundle"
    output.mkdir()
    sentinel = output / "preserve"
    sentinel.write_bytes(b"existing output")

    with pytest.raises(ValueError, match="must not already exist"):
        build_release_bundle(
            REPO_ROOT,
            output,
            "0.1.0",
            runner,
            platform_id=LINUX_X86_64,
            source_commit=TEST_SOURCE_COMMIT,
            workflow_run=TEST_WORKFLOW_RUN,
        )

    assert runner.commands == []
    assert sentinel.read_bytes() == b"existing output"


def test_release_builder_rejects_more_than_one_candidate_without_publishing_output(
    tmp_path: Path,
) -> None:
    output = tmp_path / "bundle"

    with pytest.raises(RuntimeError, match="exactly one SCIE executable"):
        build_release_bundle(
            REPO_ROOT,
            output,
            "0.1.0",
            ExtraCandidateRunner(b"scie"),
            platform_id=LINUX_X86_64,
            source_commit=TEST_SOURCE_COMMIT,
            workflow_run=TEST_WORKFLOW_RUN,
        )

    assert not output.exists()


def _run_installer(
    bundle: ReleaseBundle,
    tmp_path: Path,
    payload: bytes,
    *,
    os_id: str = "ubuntu",
    os_version: str = "24.04",
    machine: str = "x86_64",
    has_systemd: bool = True,
    ram_mib: int = 1024,
    prepare_root: Callable[[Path], None] | None = None,
    manifest_payload: bytes | None = None,
    signature_payload: bytes | None = None,
    require_https_transport: bool = False,
    forced_mkdir_mode: int | None = None,
) -> subprocess.CompletedProcess[str]:
    fake_bin = tmp_path / "fake-bin"
    fake_bin.mkdir(parents=True)
    tmp_path.chmod(0o755)
    (fake_bin / "id").write_text("#!/bin/sh\necho 0\n", encoding="utf-8")
    (fake_bin / "uname").write_text(
        '#!/bin/sh\ncase "$1" in -s) echo Linux ;; -m) echo "$XFERRY_TEST_MACHINE" ;; esac\n',
        encoding="utf-8",
    )
    (fake_bin / "curl").write_text(
        "#!/bin/sh\n"
        ': > "$XFERRY_TEST_CURL_MARKER"\n'
        "output=''\n"
        "url=''\n"
        "saw_proto=false\n"
        "saw_proto_redir=false\n"
        'while [ "$#" -gt 0 ]; do\n'
        '  if [ "$1" = "-o" ]; then output="$2"; shift 2; continue; fi\n'
        '  if [ "$1" = "--proto" ]; then\n'
        '    [ "$2" = "=https" ] && saw_proto=true\n'
        "    shift 2\n"
        "    continue\n"
        "  fi\n"
        '  if [ "$1" = "--proto-redir" ]; then\n'
        '    [ "$2" = "=https" ] && saw_proto_redir=true\n'
        "    shift 2\n"
        "    continue\n"
        "  fi\n"
        '  url="$1"\n'
        "  shift\n"
        "done\n"
        'if [ "$XFERRY_TEST_REQUIRE_HTTPS_TRANSPORT" = true ]; then\n'
        '  [ "$saw_proto" = true ] && [ "$saw_proto_redir" = true ] || exit 97\n'
        "fi\n"
        'case "$url" in\n'
        '  *.json.sig) cp "$XFERRY_TEST_SIGNATURE" "$output" ;;\n'
        '  *.json) cp "$XFERRY_TEST_MANIFEST" "$output" ;;\n'
        '  *) cp "$XFERRY_TEST_PAYLOAD" "$output" ;;\n'
        "esac\n",
        encoding="utf-8",
    )
    real_mktemp = shutil.which("mktemp")
    assert real_mktemp is not None
    (fake_bin / "mktemp").write_text(
        f'#!/bin/sh\n: > "$XFERRY_TEST_MKTEMP_MARKER"\nexec "{real_mktemp}" "$@"\n',
        encoding="utf-8",
    )
    if forced_mkdir_mode is not None:
        real_mkdir = shutil.which("mkdir")
        assert real_mkdir is not None
        (fake_bin / "mkdir").write_text(
            "#!/bin/sh\n"
            f'"{real_mkdir}" "$@" || exit $?\n'
            'for argument in "$@"; do\n'
            '  case "$argument" in -*) continue ;; esac\n'
            '  case "$argument" in\n'
            '    "$DESTDIR/opt/xferry/releases")\n'
            '      chmod "$XFERRY_TEST_FORCED_MKDIR_MODE" "${argument%/*}" "$argument"\n'
            "      ;;\n"
            '    *) chmod "$XFERRY_TEST_FORCED_MKDIR_MODE" "$argument" ;;\n'
            "  esac\n"
            "done\n",
            encoding="utf-8",
        )
    for tool in fake_bin.iterdir():
        tool.chmod(0o755)

    downloaded = tmp_path / "downloaded-scie"
    downloaded.write_bytes(payload)
    downloaded_manifest = tmp_path / "downloaded-manifest"
    downloaded_manifest.write_bytes(manifest_payload or bundle.manifest.read_bytes())
    downloaded_signature = tmp_path / "downloaded-signature"
    downloaded_signature.write_bytes(signature_payload or b"")
    target_root = tmp_path / "root"
    target_root.joinpath("etc").mkdir(parents=True)
    target_root.joinpath("etc/os-release").write_text(
        f'ID="{os_id}"\nVERSION_ID="{os_version}"\n',
        encoding="utf-8",
    )
    target_root.joinpath("proc").mkdir(parents=True)
    target_root.joinpath("proc/meminfo").write_text(
        f"MemTotal: {ram_mib * 1024} kB\n",
        encoding="utf-8",
    )
    if has_systemd:
        target_root.joinpath("run/systemd/system").mkdir(parents=True)
    if prepare_root is not None:
        prepare_root(target_root)
    for host_directory in (
        target_root,
        target_root / "etc",
        target_root / "proc",
        target_root / "run",
        target_root / "run/systemd",
        target_root / "run/systemd/system",
    ):
        if host_directory.exists():
            host_directory.chmod(0o755)
    environment = os.environ | {
        "DESTDIR": str(target_root),
        "PATH": f"{fake_bin}:{os.environ['PATH']}",
        "PYTHONPATH": str(REPO_ROOT),
        "XFERRY_RELEASE_BASE_URL": "https://releases.example.test/xferry",
        "XFERRY_TEST_CURL_MARKER": str(tmp_path / "curl-called"),
        "XFERRY_TEST_FORCED_MKDIR_MODE": (
            "" if forced_mkdir_mode is None else format(forced_mkdir_mode, "04o")
        ),
        "XFERRY_TEST_MKTEMP_MARKER": str(tmp_path / "mktemp-called"),
        "XFERRY_TEST_MACHINE": machine,
        "XFERRY_TEST_MANIFEST": str(downloaded_manifest),
        "XFERRY_TEST_PAYLOAD": str(downloaded),
        "XFERRY_TEST_REQUIRE_HTTPS_TRANSPORT": ("true" if require_https_transport else "false"),
        "XFERRY_TEST_SIGNATURE": str(downloaded_signature),
        "XFERRY_TEST_VERIFIER_LOG": str(tmp_path / "verifier-arguments"),
    }
    return subprocess.run(
        ["sh", str(bundle.installer)],
        cwd=tmp_path,
        env=environment,
        text=True,
        capture_output=True,
        check=False,
    )


def _seed_unsupported_managed_state(root: Path) -> dict[Path, bytes]:
    release = root / "opt/xferry/releases/4.1.0"
    release.mkdir(parents=True)
    release.joinpath("xferry").write_bytes(b"unsupported executable\n")
    release.joinpath("xferry-release.json").write_text(
        '{"schema_version":1,"version":"4.1.0"}\n',
        encoding="utf-8",
    )
    root.joinpath("opt/xferry/current").symlink_to("releases/4.1.0")
    sentinels = {
        root / "etc/xferry/xferry.ini": b"unsupported config\n",
        root / "etc/xferry/auth": b"admin:unsupported\n",
        root / "var/lib/xferry/upload.bin": b"unsupported data\n",
        root / "etc/systemd/system/xferry.service": b"unsupported unit\n",
    }
    for path, payload in sentinels.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
    cli_link = root / "usr/local/bin/xferry"
    cli_link.parent.mkdir(parents=True)
    cli_link.symlink_to("/opt/xferry/current/xferry")
    return sentinels


def _seed_valid_supported_installation(
    root: Path,
    version: str = "0.2.0",
    *,
    manifest_version: str | None = None,
    manifest_schema: int = 1,
) -> None:
    described_version = manifest_version or version
    payload = f"xferry-{version}".encode()
    release = root / "opt/xferry/releases" / version
    release.mkdir(parents=True)
    executable = release / "xferry"
    executable.write_bytes(payload)
    executable.chmod(0o755)
    if manifest_schema == 1:
        manifest_payload = (
            json.dumps(
                {
                    "schema_version": 1,
                    "version": described_version,
                    "tag": f"v{described_version}",
                    "platform": "linux-x86_64",
                    "executable": {
                        "name": f"xferry-{described_version}-linux-x86_64",
                        "size": len(payload),
                        "sha256": hashlib.sha256(payload).hexdigest(),
                    },
                },
                indent=2,
            )
            + "\n"
        )
    elif manifest_schema == 2:
        manifest_payload = (
            ReleaseManifest.create_v2(
                version=described_version,
                platform="linux-x86_64",
                executable_size=len(payload),
                executable_sha256=hashlib.sha256(payload).hexdigest(),
                source_commit=TEST_SOURCE_COMMIT,
                workflow_run=TEST_WORKFLOW_RUN,
            )
            .to_bytes()
            .decode("utf-8")
        )
    else:
        raise AssertionError(f"unexpected manifest schema: {manifest_schema}")
    release.joinpath("xferry-release.json").write_text(manifest_payload, encoding="utf-8")
    root.joinpath("opt/xferry/current").symlink_to(Path("releases") / version)
    cli_link = root / "usr/local/bin/xferry"
    cli_link.parent.mkdir(parents=True)
    cli_link.symlink_to("/opt/xferry/current/xferry")


def _v2_installed_manifest(*, include_extra_digest: bool = False) -> str:
    version = "0.2.0"
    executable_name = f"xferry-{version}-linux-x86_64"
    executable_sha256 = TEST_INSTALLED_SHA256
    artifact_digests = {executable_name: executable_sha256}
    if include_extra_digest:
        artifact_digests["install.sh"] = "0" * 64
    return (
        ReleaseManifest.create_v2(
            version=version,
            platform="linux-x86_64",
            executable_size=len(TEST_INSTALLED_PAYLOAD),
            executable_sha256=executable_sha256,
            source_commit=TEST_SOURCE_COMMIT,
            workflow_run=TEST_WORKFLOW_RUN,
            artifact_digests=artifact_digests,
        )
        .to_bytes()
        .decode("utf-8")
        .rstrip("\n")
    )


@pytest.mark.parametrize("platform_id", SUPPORTED_PLATFORM_IDS)
def test_release_bundle_writes_literal_manifest_and_checksum(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    platform_id: PlatformId,
) -> None:
    payload = b"scie-payload"
    monkeypatch.setattr("tools.build_scie_release.current_platform_id", lambda: platform_id)
    bundle = build_release_bundle(
        REPO_ROOT,
        tmp_path / "bundle",
        "0.1.0",
        FakeRunner(payload),
        platform_id=platform_id,
        source_commit=TEST_SOURCE_COMMIT,
        workflow_run=TEST_WORKFLOW_RUN,
    )

    executable_name = f"xferry-0.1.0-{platform_id}"
    executable = bundle.output_dir / executable_name
    manifest = json.loads(bundle.manifest.read_text(encoding="utf-8"))
    expected_sha256 = hashlib.sha256(payload).hexdigest()

    assert executable.read_bytes() == payload
    assert manifest == {
        "schema_version": 2,
        "version": "0.1.0",
        "tag": "v0.1.0",
        "platform": platform_id,
        "executable": {
            "name": executable_name,
            "size": 12,
            "sha256": expected_sha256,
        },
        "source": {
            "commit": TEST_SOURCE_COMMIT,
            "workflow_run": TEST_WORKFLOW_RUN,
        },
        "artifact_digests": {
            executable_name: expected_sha256,
        },
        "signing": {
            "scheme": "unsigned",
            "key_ids": [],
        },
    }
    assert bundle.manifest.read_bytes().endswith(b"\n")
    assert bundle.checksums.read_text(encoding="utf-8") == f"{expected_sha256}  {executable_name}\n"


def test_release_signer_uses_external_key_without_rebuilding_manifest_or_artifacts(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    key_id = "test-release-2026"
    bundle = _render_bundle(tmp_path / "candidate", signing_key_id=key_id)
    manifest_before = bundle.manifest.read_bytes()
    executable_before = bundle.executable.read_bytes()
    private_key = Ed25519PrivateKey.generate()
    private_key_path = tmp_path / "protected-signing-key.pem"
    private_key_path.write_bytes(
        private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    private_key_path.chmod(0o600)
    signature_path = tmp_path / "xferry-release.json.sig"

    result = sign_release_metadata(
        (
            "--manifest",
            str(bundle.manifest),
            "--signature-output",
            str(signature_path),
            "--key-id",
            key_id,
            "--private-key",
            str(private_key_path),
        )
    )

    assert result == 0
    assert capsys.readouterr() == ("", "")
    assert bundle.manifest.read_bytes() == manifest_before
    assert bundle.executable.read_bytes() == executable_before
    manifest = verify_signed_manifest(
        manifest_before,
        signature_path.read_bytes(),
        key_ring=ReleaseKeyRing(
            (
                TrustedReleaseKey(
                    key_id,
                    private_key.public_key().public_bytes_raw(),
                ),
            )
        ),
    )
    assert manifest.signing_key_ids == (key_id,)
    assert stat.S_IMODE(signature_path.stat().st_mode) == 0o644


def test_release_signer_rejects_a_world_readable_private_key(
    tmp_path: Path,
) -> None:
    bundle = _render_bundle(
        tmp_path / "candidate",
        signing_key_id="test-release-2026",
    )
    private_key_path = tmp_path / "unsafe-signing-key.pem"
    private_key_path.write_bytes(
        Ed25519PrivateKey.generate().private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    private_key_path.chmod(0o644)

    with pytest.raises(ValueError, match="must not be accessible"):
        sign_release_metadata(
            (
                "--manifest",
                str(bundle.manifest),
                "--signature-output",
                str(tmp_path / "signature"),
                "--key-id",
                "test-release-2026",
                "--private-key",
                str(private_key_path),
            )
        )

    assert not (tmp_path / "signature").exists()


def test_release_signer_accepts_an_already_protected_private_key_descriptor(
    tmp_path: Path,
) -> None:
    key_id = "test-release-2026"
    bundle = _render_bundle(tmp_path / "candidate", signing_key_id=key_id)
    private_key = Ed25519PrivateKey.generate()
    key_path = tmp_path / "external-key.pem"
    key_path.write_bytes(
        private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    signature_path = tmp_path / "manifest.sig"

    with key_path.open("rb") as private_stream:
        assert (
            sign_release_metadata(
                (
                    "--manifest",
                    str(bundle.manifest),
                    "--signature-output",
                    str(signature_path),
                    "--key-id",
                    key_id,
                    "--private-key-fd",
                    str(private_stream.fileno()),
                )
            )
            == 0
        )

    assert (
        verify_signed_manifest(
            bundle.manifest.read_bytes(),
            signature_path.read_bytes(),
            key_ring=ReleaseKeyRing(
                (
                    TrustedReleaseKey(
                        key_id,
                        private_key.public_key().public_bytes_raw(),
                    ),
                )
            ),
        ).version
        == "0.1.0"
    )


def test_installer_signature_verifies_before_privileged_execution(tmp_path: Path) -> None:
    key_id = "test-release-2026"
    private_key = Ed25519PrivateKey.generate()
    key_ring = ReleaseKeyRing(
        (
            TrustedReleaseKey(
                key_id,
                private_key.public_key().public_bytes_raw(),
            ),
        )
    )
    bundle = _render_bundle(tmp_path / "candidate")
    signature_path = tmp_path / "install.sh.sig"
    signature_path.write_bytes(
        sign_installer(
            bundle.installer.read_bytes(),
            key_id=key_id,
            private_key=private_key,
        )
    )

    verify_installer_files(bundle.installer, signature_path, key_ring=key_ring)
    bundle.installer.write_text(
        bundle.installer.read_text(encoding="utf-8") + "# tampered\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="release_signature_invalid"):
        verify_installer_files(bundle.installer, signature_path, key_ring=key_ring)


def test_signed_bundle_installer_persists_manifest_signature_for_rollback(
    tmp_path: Path,
) -> None:
    key_id = "test-release-2026"
    private_key = Ed25519PrivateKey.generate()
    payload = b"signed-scie"
    bundle = _render_bundle(
        tmp_path / "candidate",
        payload,
        signing_key_id=key_id,
    )
    signature = sign_manifest(
        bundle.manifest.read_bytes(),
        key_id=key_id,
        private_key=private_key,
    )

    result = _run_installer(
        bundle,
        tmp_path / "installed",
        payload,
        signature_payload=signature,
    )

    assert result.returncode == 0, result.stderr
    installed = tmp_path / "installed/root/opt/xferry/releases/0.1.0"
    assert installed.joinpath("xferry-release.json.sig").read_bytes() == signature
    assert stat.S_IMODE(installed.joinpath("xferry-release.json.sig").stat().st_mode) == 0o644


def _recording_verifier_scie(public_key: bytes) -> bytes:
    return f"""#!{sys.executable}
import argparse
import os
import sys
from pathlib import Path

from xferry.management.release_trust import ReleaseKeyRing, TrustedReleaseKey
from xferry.management.release_verifier import ReleaseEnvelopeError, verify_release_envelope

if sys.argv[1:2] != ["_verify-release-envelope"]:
    raise SystemExit(97)
parser = argparse.ArgumentParser()
parser.add_argument("--manifest", required=True, type=Path)
parser.add_argument("--signature", required=True, type=Path)
parser.add_argument("--executable", required=True, type=Path)
parser.add_argument("--version", required=True)
parser.add_argument("--platform", required=True)
arguments = parser.parse_args(sys.argv[2:])
Path(os.environ["XFERRY_TEST_VERIFIER_LOG"]).write_text(
    "\\n".join(sys.argv[2:]) + "\\n", encoding="utf-8"
)
try:
    verify_release_envelope(
        arguments.manifest,
        arguments.signature,
        arguments.executable,
        expected_version=arguments.version,
        expected_platform=arguments.platform,
        key_ring=ReleaseKeyRing(
            (TrustedReleaseKey("test-release-2026", bytes.fromhex("{public_key.hex()}")),)
        ),
    )
except ReleaseEnvelopeError as failure:
    print(failure.code, file=sys.stderr)
    raise SystemExit(1) from None
""".encode()


def _hosted_envelope(
    payload: bytes,
    private_key: Ed25519PrivateKey,
) -> tuple[bytes, bytes]:
    key_id = "test-release-2026"
    manifest = ReleaseManifest.create_v2(
        version="0.1.0",
        platform=LINUX_X86_64,
        executable_size=len(payload),
        executable_sha256=hashlib.sha256(payload).hexdigest(),
        source_commit=TEST_SOURCE_COMMIT,
        workflow_run=TEST_WORKFLOW_RUN,
        signing_key_ids=(key_id,),
    ).to_bytes()
    return manifest, sign_manifest(
        manifest,
        key_id=key_id,
        private_key=private_key,
    )


def test_hosted_installer_verifies_and_persists_exact_platform_envelope(tmp_path: Path) -> None:
    """Replacing the hosted signed envelope with the embedded unsigned one breaks rollback trust."""
    private_key = Ed25519PrivateKey.generate()
    payload = _recording_verifier_scie(private_key.public_key().public_bytes_raw())
    manifest, signature = _hosted_envelope(payload, private_key)
    bundle = _render_bundle(
        tmp_path / "candidate",
        payload,
        require_hosted_signature=True,
    )

    result = _run_installer(
        bundle,
        tmp_path / "installed",
        payload,
        manifest_payload=manifest,
        signature_payload=signature,
    )

    assert result.returncode == 0, result.stderr
    installed = tmp_path / "installed/root/opt/xferry/releases/0.1.0"
    assert installed.joinpath("xferry-release.json").read_bytes() == manifest
    assert installed.joinpath("xferry-release.json.sig").read_bytes() == signature
    verifier_arguments = tmp_path.joinpath("installed/verifier-arguments").read_text().splitlines()
    assert verifier_arguments[::2] == [
        "--manifest",
        "--signature",
        "--executable",
        "--version",
        "--platform",
    ]
    assert Path(verifier_arguments[1]).name == "xferry-release-linux-x86_64.json"
    assert Path(verifier_arguments[3]).name == "xferry-release-linux-x86_64.json.sig"
    assert Path(verifier_arguments[5]).name == "xferry"
    assert verifier_arguments[7] == "0.1.0"
    assert verifier_arguments[9] == "linux-x86_64"


def test_hosted_installer_verifier_failure_prevents_managed_writes(tmp_path: Path) -> None:
    """Signature rejection must stop before creating the managed release or CLI link roots."""
    private_key = Ed25519PrivateKey.generate()
    payload = _recording_verifier_scie(private_key.public_key().public_bytes_raw())
    manifest, _signature = _hosted_envelope(payload, private_key)
    bundle = _render_bundle(
        tmp_path / "candidate",
        payload,
        require_hosted_signature=True,
    )
    case_root = tmp_path / "rejected"

    result = _run_installer(
        bundle,
        case_root,
        payload,
        manifest_payload=manifest,
        signature_payload=b'{"invalid":true}\n',
    )

    assert result.returncode == 1
    assert "signed release envelope verification failed" in result.stderr
    assert not case_root.joinpath("root/opt").exists()
    assert not case_root.joinpath("root/usr").exists()


@pytest.mark.parametrize("oversized_asset", ["manifest", "signature"])
def test_hosted_installer_bounds_metadata_before_invoking_the_verifier(
    tmp_path: Path,
    oversized_asset: str,
) -> None:
    """Unauthenticated metadata must not fill root temporary storage before verification."""
    private_key = Ed25519PrivateKey.generate()
    payload = _recording_verifier_scie(private_key.public_key().public_bytes_raw())
    manifest, signature = _hosted_envelope(payload, private_key)
    if oversized_asset == "manifest":
        manifest = b"x" * (MAX_MANIFEST_BYTES + 1)
    else:
        signature = b"x" * (MAX_SIGNATURE_BYTES + 1)
    bundle = _render_bundle(
        tmp_path / "candidate",
        payload,
        require_hosted_signature=True,
    )
    case_root = tmp_path / oversized_asset

    result = _run_installer(
        bundle,
        case_root,
        payload,
        manifest_payload=manifest,
        signature_payload=signature,
    )

    assert result.returncode == 1
    assert "bounded release download failed" in result.stderr
    assert not case_root.joinpath("verifier-arguments").exists()
    assert not case_root.joinpath("root/opt").exists()
    assert not case_root.joinpath("root/usr").exists()


def test_hosted_installer_restricts_initial_and_redirect_downloads_to_https(
    tmp_path: Path,
) -> None:
    """Every executable and metadata request must reject non-HTTPS redirect targets."""
    private_key = Ed25519PrivateKey.generate()
    payload = _recording_verifier_scie(private_key.public_key().public_bytes_raw())
    manifest, signature = _hosted_envelope(payload, private_key)
    bundle = _render_bundle(
        tmp_path / "candidate",
        payload,
        require_hosted_signature=True,
    )
    case_root = tmp_path / "https-only"

    result = _run_installer(
        bundle,
        case_root,
        payload,
        manifest_payload=manifest,
        signature_payload=signature,
        require_https_transport=True,
    )

    assert result.returncode == 0, result.stderr
    assert case_root.joinpath("root/opt/xferry/current/xferry").is_file()


def test_installer_guidance_verifies_downloads_before_explicit_sudo() -> None:
    security = (REPO_ROOT / "SECURITY.md").read_text(encoding="utf-8")
    procedure = security.split("### Privileged installer verification order", maxsplit=1)[1]
    commands = procedure.split("```console", maxsplit=1)[1].split("```", maxsplit=1)[0]

    assert commands.index("--manifest xferry-release-linux-x86_64.json") < commands.index(
        "--installer install-linux-x86_64.sh"
    )
    assert commands.index("--installer install-linux-x86_64.sh") < commands.index(
        "sudo sh ./install-linux-x86_64.sh"
    )
    assert "| sudo" not in commands
    assert "curl |" not in commands


def test_installer_guidance_declares_verifier_prerequisites_before_commands() -> None:
    """Catches installer onboarding hiding its Python and checkout prerequisites."""
    security = (REPO_ROOT / "SECURITY.md").read_text(encoding="utf-8")
    procedure = security.split("### Privileged installer verification order", maxsplit=1)[1]
    introduction = procedure.split("```console", maxsplit=1)[0]

    assert "Python" in introduction
    assert "reviewed checkout" in introduction
    assert "tools/verify_release_signature.py" in introduction


def test_installer_guidance_resolves_immutable_urls_without_inherited_release_url(
    tmp_path: Path,
) -> None:
    """Catches an undefined release URL or privileged execution before verification."""
    security = (REPO_ROOT / "SECURITY.md").read_text(encoding="utf-8")
    procedure = security.split("### Privileged installer verification order", maxsplit=1)[1]
    commands = procedure.split("```console", maxsplit=1)[1].split("```", maxsplit=1)[0]
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    capture = tmp_path / "installer-argv"
    for name in ("curl", "python", "sudo"):
        executable = fake_bin / name
        executable.write_text(
            "#!/bin/sh\n"
            'printf \'%s\\t\' "${0##*/}" "$@" >> "$XFERRY_TEST_CAPTURE"\n'
            "printf '\\n' >> \"$XFERRY_TEST_CAPTURE\"\n",
            encoding="utf-8",
        )
        executable.chmod(0o755)

    result = subprocess.run(
        ["/bin/bash", "-e", "-c", commands],
        cwd=tmp_path,
        env={"PATH": str(fake_bin), "XFERRY_TEST_CAPTURE": str(capture)},
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    calls = [line.split("\t")[:-1] for line in capture.read_text().splitlines()]
    expected_names = [
        "xferry-release-linux-x86_64.json",
        "xferry-release-linux-x86_64.json.sig",
        "install-linux-x86_64.sh",
        "install-linux-x86_64.sh.sig",
    ]
    curl_prefix = [
        "curl",
        "--proto",
        "=https",
        "--proto-redir",
        "=https",
        "--fail",
        "--silent",
        "--show-error",
        "--remote-name",
    ]
    expected = [
        curl_prefix + [f"https://github.com/kgmnotes/xferry/releases/download/v0.2.0/{name}"]
        for name in expected_names
    ]
    expected += [
        [
            "python",
            "tools/verify_release_signature.py",
            "--manifest",
            "xferry-release-linux-x86_64.json",
            "--signature",
            "xferry-release-linux-x86_64.json.sig",
        ],
        [
            "python",
            "tools/verify_release_signature.py",
            "--installer",
            "install-linux-x86_64.sh",
            "--signature",
            "install-linux-x86_64.sh.sig",
        ],
        ["sudo", "sh", "./install-linux-x86_64.sh"],
    ]
    assert calls == expected


@pytest.mark.parametrize("version", ["1.0.0", "4.1.0", "99.0.0"])
def test_release_builder_rejects_other_majors_before_build_or_output(
    tmp_path: Path,
    version: str,
) -> None:
    """An unsupported release line must not create output or invoke build tools."""
    runner = FakeRunner(b"scie")
    output = tmp_path / "bundle"

    with pytest.raises(ValueError, match="supported release line"):
        build_release_bundle(
            REPO_ROOT,
            output,
            version,
            runner,
            platform_id=LINUX_X86_64,
        )

    assert runner.commands == []
    assert not output.exists()


@pytest.mark.parametrize("version", ["0.1", "0.01.0", "0.1.0.0", "0.1.00"])
def test_release_builder_rejects_noncanonical_versions_before_build_or_output(
    tmp_path: Path,
    version: str,
) -> None:
    """A noncanonical release label must not create build output or invoke build tools."""
    runner = FakeRunner(b"scie")
    output = tmp_path / "bundle"

    with pytest.raises(ValueError, match="supported release line"):
        build_release_bundle(
            REPO_ROOT,
            output,
            version,
            runner,
            platform_id=LINUX_X86_64,
        )

    assert runner.commands == []
    assert not output.exists()


@pytest.mark.parametrize(
    ("source_commit", "workflow_run"),
    [
        ("", TEST_WORKFLOW_RUN),
        ("not-a-commit", TEST_WORKFLOW_RUN),
        (TEST_SOURCE_COMMIT, ""),
        (TEST_SOURCE_COMMIT, "0"),
        (TEST_SOURCE_COMMIT, "run-123"),
    ],
)
def test_release_builder_rejects_invalid_provenance_before_build_or_output(
    tmp_path: Path,
    source_commit: str,
    workflow_run: str,
) -> None:
    """Malformed provenance must fail before a candidate can be mistaken for releasable output."""
    runner = FakeRunner(b"scie")
    output = tmp_path / "bundle"

    with pytest.raises(ValueError, match="invalid (source commit|workflow run)"):
        build_release_bundle(
            REPO_ROOT,
            output,
            "0.1.0",
            runner,
            platform_id=LINUX_X86_64,
            source_commit=source_commit,
            workflow_run=workflow_run,
        )

    assert runner.commands == []
    assert not output.exists()


@pytest.mark.parametrize("version", ["0.1.0", "0.2.0", "0.2.0-rc.1", "0.2.0+build.1"])
def test_release_builder_accepts_canonical_supported_versions(
    tmp_path: Path,
    version: str,
) -> None:
    runner = FakeRunner(b"scie")

    bundle = build_release_bundle(
        REPO_ROOT,
        tmp_path / "bundle",
        version,
        runner,
        platform_id=LINUX_X86_64,
    )

    assert bundle.executable.name == f"xferry-{version}-linux-x86_64"


@pytest.mark.parametrize("platform_id", SUPPORTED_PLATFORM_IDS)
def test_release_builder_uses_pinned_pex_lock_and_eager_cpython_scie(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    platform_id: PlatformId,
) -> None:
    monkeypatch.setattr("tools.build_scie_release.current_platform_id", lambda: platform_id)
    runner: CommandRunner = FakeRunner(b"scie")
    bundle = build_release_bundle(
        REPO_ROOT,
        tmp_path / "bundle",
        "0.1.0",
        runner,
        platform_id=platform_id,
    )
    commands = [command for command, _cwd in runner.commands]

    assert any(command[:4] == ("python", "-m", "build", "--wheel") for command in commands)
    lock_command = next(
        command for command in commands if command[:3] == ("pex3", "lock", "create")
    )
    scie_command = next(command for command in commands if "--scie" in command)
    assert "constraints/ci.txt" in lock_command
    assert "pex==2.99.0" in (REPO_ROOT / "constraints/ci.txt").read_text(encoding="utf-8")
    assert ("--scie", "eager") == tuple(scie_command[scie_command.index("--scie") :][:2])
    assert ("--scie-platform", platform_id) == tuple(
        scie_command[scie_command.index("--scie-platform") :][:2]
    )
    assert "CPython>=3.12,<3.13" in scie_command
    assert ("-c", "xferry") == tuple(scie_command[scie_command.index("-c") :][:2])
    assert bundle.executable.name == f"xferry-0.1.0-{platform_id}"


def test_release_builder_passes_the_wheel_as_a_positional_pex_requirement(tmp_path: Path) -> None:
    """PEX treats ``--requirement`` inputs as UTF-8 requirement files, not wheels."""
    runner: CommandRunner = FakeRunner(b"scie")
    _ = build_release_bundle(
        REPO_ROOT,
        tmp_path / "bundle",
        "0.1.0",
        runner,
        platform_id=LINUX_X86_64,
    )
    lock_command = next(
        command for command, _cwd in runner.commands if command[:3] == ("pex3", "lock", "create")
    )

    assert "--requirement" not in lock_command
    assert any(argument.endswith(".whl") for argument in lock_command)


def test_release_builder_consumes_the_exact_promoted_wheel_without_rebuilding(
    tmp_path: Path,
) -> None:
    wheel = tmp_path / "xferry-0.1.0-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr("xferry/__init__.py", "")
    digest = hashlib.sha256(wheel.read_bytes()).hexdigest()
    runner = FakeRunner(b"scie")
    build_release_bundle(
        REPO_ROOT,
        tmp_path / "bundle",
        "0.1.0",
        runner,
        platform_id=LINUX_X86_64,
        wheel=wheel,
        wheel_sha256=digest,
    )
    assert not any(command[:3] == ("python", "-m", "build") for command, _ in runner.commands)
    lock = next(
        command for command, _ in runner.commands if command[:3] == ("pex3", "lock", "create")
    )
    assert str(wheel.resolve()) in lock
    assert hashlib.sha256(wheel.read_bytes()).hexdigest() == digest


@pytest.mark.parametrize("case", ["digest", "name", "missing-digest", "missing-wheel"])
def test_promoted_scie_wheel_is_validated_before_build_commands(tmp_path: Path, case: str) -> None:
    wheel = tmp_path / (
        "xferry-0.2.0-py3-none-any.whl" if case == "name" else "xferry-0.1.0-py3-none-any.whl"
    )
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr("xferry/__init__.py", "")
    digest = hashlib.sha256(wheel.read_bytes()).hexdigest()
    runner = FakeRunner(b"scie")
    with pytest.raises(ValueError):
        build_release_bundle(
            REPO_ROOT,
            tmp_path / "bundle",
            "0.1.0",
            runner,
            platform_id=LINUX_X86_64,
            wheel=None if case == "missing-wheel" else wheel,
            wheel_sha256=None
            if case == "missing-digest"
            else ("0" * 64 if case == "digest" else digest),
        )
    assert runner.commands == []
    assert not (tmp_path / "bundle").exists()


def test_rendered_installer_verifies_before_installing(tmp_path: Path) -> None:
    payload = b"scie"
    bundle = _render_bundle(tmp_path, payload)
    installer = bundle.installer.read_text(encoding="utf-8")

    assert "releases/download/v0.1.0" in installer
    assert "xferry-0.1.0-linux-x86_64" in installer
    assert "supported_release_major='0'" in installer
    assert "4" in installer
    assert hashlib.sha256(payload).hexdigest() in installer

    tampered = _run_installer(bundle, tmp_path / "tampered", b"tampered")
    assert tampered.returncode != 0
    assert not (tmp_path / "tampered" / "root" / "opt" / "xferry").exists()

    wrong_hash = _run_installer(bundle, tmp_path / "wrong-hash", b"evil")
    assert wrong_hash.returncode != 0
    assert not (tmp_path / "wrong-hash" / "root" / "opt" / "xferry").exists()

    installed = _run_installer(bundle, tmp_path / "installed", payload)
    root = tmp_path / "installed" / "root"
    assert installed.returncode == 0, installed.stderr
    release_dir = root / "opt/xferry/releases/0.1.0"
    assert release_dir.joinpath("xferry").read_bytes() == payload
    assert release_dir.joinpath("xferry-release.json").read_bytes() == bundle.manifest.read_bytes()
    assert stat.S_IMODE(release_dir.stat().st_mode) == 0o755
    assert stat.S_IMODE(release_dir.joinpath("xferry").stat().st_mode) == 0o755
    assert stat.S_IMODE(release_dir.joinpath("xferry-release.json").stat().st_mode) == 0o644
    assert (root / "opt/xferry/current").readlink() == Path("releases/0.1.0")
    assert (root / "usr/local/bin/xferry").readlink() == Path("/opt/xferry/current/xferry")


def test_installer_restricts_release_directories_after_writable_mode_inheritance(
    tmp_path: Path,
) -> None:
    """A hostile parent ACL must not leave the managed release chain writable."""
    payload = b"scie"
    bundle = _render_bundle(tmp_path / "candidate", payload)

    result = _run_installer(
        bundle,
        tmp_path / "install",
        payload,
        forced_mkdir_mode=0o777,
    )

    assert result.returncode == 0, result.stderr
    release_root = tmp_path / "install/root/opt/xferry"
    assert stat.S_IMODE(release_root.stat().st_mode) == 0o755
    assert stat.S_IMODE(release_root.joinpath("releases").stat().st_mode) == 0o755


@pytest.mark.parametrize(
    ("os_id", "os_version", "platform_id", "machine"),
    [
        ("ubuntu", "22.04", LINUX_X86_64, "x86_64"),
        ("ubuntu", "24.04", LINUX_X86_64, "x86_64"),
        ("ubuntu", "26.04", LINUX_X86_64, "x86_64"),
        ("debian", "12", LINUX_X86_64, "x86_64"),
        ("debian", "13", LINUX_X86_64, "x86_64"),
        ("ubuntu", "22.04", LINUX_AARCH64, "aarch64"),
        ("ubuntu", "24.04", LINUX_AARCH64, "aarch64"),
        ("ubuntu", "26.04", LINUX_AARCH64, "aarch64"),
        ("debian", "12", LINUX_AARCH64, "aarch64"),
        ("debian", "13", LINUX_AARCH64, "aarch64"),
    ],
)
def test_installer_accepts_the_complete_managed_distro_architecture_matrix(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    os_id: str,
    os_version: str,
    platform_id: PlatformId,
    machine: str,
) -> None:
    payload = f"scie-{platform_id}".encode()
    monkeypatch.setattr("tools.build_scie_release.current_platform_id", lambda: platform_id)
    bundle = _render_bundle(
        tmp_path / "candidate",
        payload,
        platform_id=platform_id,
    )

    result = _run_installer(
        bundle,
        tmp_path / "install",
        payload,
        os_id=os_id,
        os_version=os_version,
        machine=machine,
    )

    assert result.returncode == 0, result.stderr
    installed = tmp_path / "install/root/opt/xferry/current/xferry"
    assert installed.read_bytes() == payload


@pytest.mark.parametrize(
    ("platform_id", "host_machine"),
    [
        (LINUX_X86_64, "aarch64"),
        (LINUX_AARCH64, "x86_64"),
        (LINUX_X86_64, "riscv64"),
    ],
)
def test_installer_rejects_wrong_or_unknown_platform_before_download_or_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    platform_id: PlatformId,
    host_machine: str,
) -> None:
    monkeypatch.setattr("tools.build_scie_release.current_platform_id", lambda: platform_id)
    bundle = _render_bundle(tmp_path / "candidate", platform_id=platform_id)
    case_root = tmp_path / "install"

    result = _run_installer(bundle, case_root, b"scie", machine=host_machine)

    assert result.returncode == 4
    assert not case_root.joinpath("mktemp-called").exists()
    assert not case_root.joinpath("curl-called").exists()
    assert not case_root.joinpath("root/opt").exists()
    assert not case_root.joinpath("root/usr").exists()


@pytest.mark.parametrize(
    ("original", "replacement"),
    [
        ('  "schema_version": 2,', '  "schema_version": 3,'),
        (
            '  "platform": "linux-x86_64",',
            '  "platform": "linux-aarch64",',
        ),
        (
            '    "name": "xferry-0.1.0-linux-x86_64",',
            '    "name": "xferry-0.1.0-linux-aarch64",',
        ),
    ],
    ids=("unsupported-schema", "wrong-platform", "wrong-name"),
)
def test_installer_rejects_invalid_candidate_metadata_before_destination_mutation(
    tmp_path: Path,
    original: str,
    replacement: str,
) -> None:
    payload = b"scie"
    bundle = _render_bundle(tmp_path / "candidate", payload)
    installer = bundle.installer.read_text(encoding="utf-8")
    assert installer.count(original) == 1
    bundle.installer.write_text(installer.replace(original, replacement), encoding="utf-8")
    case_root = tmp_path / "install"

    result = _run_installer(bundle, case_root, payload)

    assert result.returncode == 1
    assert "candidate manifest or executable is invalid" in result.stderr
    assert not case_root.joinpath("root/opt").exists()
    assert not case_root.joinpath("root/usr").exists()


@pytest.mark.parametrize(
    "downloaded_payload",
    [b"", b"s", b"scie-with-unexpected-trailing-bytes"],
    ids=("empty", "truncated", "corrupt"),
)
def test_installer_rejects_truncated_or_corrupt_payload_before_destination_mutation(
    tmp_path: Path,
    downloaded_payload: bytes,
) -> None:
    bundle = _render_bundle(tmp_path / "candidate", b"scie")
    case_root = tmp_path / "install"

    result = _run_installer(bundle, case_root, downloaded_payload)

    assert result.returncode == 1
    assert not case_root.joinpath("root/opt").exists()
    assert not case_root.joinpath("root/usr").exists()


def test_installer_blocks_unsupported_state_before_mktemp_download_or_mutation(
    tmp_path: Path,
) -> None:
    """Installing over unsupported state preserves sentinels and managed symlink targets."""
    payload = b"scie"
    bundle = _render_bundle(tmp_path / "bundle", payload)
    sentinels: dict[Path, bytes] = {}

    def prepare(root: Path) -> None:
        sentinels.update(_seed_unsupported_managed_state(root))

    result = _run_installer(bundle, tmp_path / "unsupported", payload, prepare_root=prepare)
    root = tmp_path / "unsupported/root"

    assert result.returncode == 1
    assert all(clause in result.stderr for clause in UNSUPPORTED_MANAGED_STATE_INSTRUCTION_CLAUSES)
    assert not tmp_path.joinpath("unsupported/mktemp-called").exists()
    assert not tmp_path.joinpath("unsupported/curl-called").exists()
    assert root.joinpath("opt/xferry/current").readlink() == Path("releases/4.1.0")
    assert root.joinpath("usr/local/bin/xferry").readlink() == Path("/opt/xferry/current/xferry")
    for path, payload_bytes in sentinels.items():
        assert path.read_bytes() == payload_bytes
    assert not root.joinpath("opt/xferry/releases/0.1.0").exists()


def test_installer_blocks_another_unsupported_release_before_any_effect(tmp_path: Path) -> None:
    payload = b"scie"
    bundle = _render_bundle(tmp_path / "bundle", payload)

    def prepare(root: Path) -> None:
        _seed_valid_supported_installation(root, "99.0.0")

    result = _run_installer(bundle, tmp_path / "unsupported-release", payload, prepare_root=prepare)
    root = tmp_path / "unsupported-release/root"

    assert result.returncode == 1
    assert all(clause in result.stderr for clause in UNSUPPORTED_MANAGED_STATE_INSTRUCTION_CLAUSES)
    assert not tmp_path.joinpath("unsupported-release/mktemp-called").exists()
    assert not tmp_path.joinpath("unsupported-release/curl-called").exists()
    assert not root.joinpath("opt/xferry/releases/0.1.0").exists()


@pytest.mark.parametrize("owned_kind", ["config", "auth", "data", "unit", "cli"])
def test_installer_blocks_unmarked_owned_state_before_mktemp_or_download(
    tmp_path: Path,
    owned_kind: str,
) -> None:
    """Any owned-state footprint is ambiguous without a valid supported release marker."""
    payload = b"scie"
    bundle = _render_bundle(tmp_path / "bundle", payload)
    sentinel: Path | None = None
    original = b"unsupported state\n"

    def prepare(root: Path) -> None:
        nonlocal sentinel
        relative = {
            "config": "etc/xferry/xferry.ini",
            "auth": "etc/xferry/auth",
            "data": "var/lib/xferry/sentinel",
            "unit": "etc/systemd/system/xferry.service",
            "cli": "usr/local/bin/xferry",
        }[owned_kind]
        sentinel = root / relative
        sentinel.parent.mkdir(parents=True, exist_ok=True)
        if owned_kind == "cli":
            sentinel.symlink_to("/unsupported/xferry")
        else:
            sentinel.write_bytes(original)

    case_root = tmp_path / f"unmarked-{owned_kind}"
    result = _run_installer(bundle, case_root, payload, prepare_root=prepare)
    root = case_root / "root"

    assert result.returncode != 0
    assert all(clause in result.stderr for clause in UNSUPPORTED_MANAGED_STATE_INSTRUCTION_CLAUSES)
    assert not case_root.joinpath("mktemp-called").exists()
    assert not case_root.joinpath("curl-called").exists()
    assert sentinel is not None
    if owned_kind == "cli":
        assert sentinel.readlink() == Path("/unsupported/xferry")
    else:
        assert sentinel.read_bytes() == original
    assert not root.joinpath("opt/xferry").exists()


@pytest.mark.parametrize("manifest_schema", [1, 2], ids=["v1-migration", "v2"])
def test_installer_allows_a_valid_same_major_managed_installation(
    tmp_path: Path,
    manifest_schema: int,
) -> None:
    """The guard must not reject an ordinary supported-line bootstrap rerun."""
    payload = b"scie"
    bundle = _render_bundle(tmp_path / "bundle", payload)

    def prepare(root: Path) -> None:
        _seed_valid_supported_installation(root, manifest_schema=manifest_schema)

    result = _run_installer(
        bundle,
        tmp_path / f"same-major-{manifest_schema}",
        payload,
        prepare_root=prepare,
    )
    case_root = tmp_path / f"same-major-{manifest_schema}"
    root = case_root / "root"

    assert result.returncode == 0, result.stderr
    assert case_root.joinpath("mktemp-called").exists()
    assert case_root.joinpath("curl-called").exists()
    assert root.joinpath("opt/xferry/current").readlink() == Path("releases/0.1.0")
    assert root.joinpath("opt/xferry/releases/0.2.0/xferry").is_file()


def test_installer_accepts_a_canonical_v2_multi_artifact_digest_set(tmp_path: Path) -> None:
    """Generated shell parsing stays aligned with the canonical expandable digest inventory."""
    payload = b"scie"
    bundle = _render_bundle(tmp_path / "bundle", payload)

    def prepare(root: Path) -> None:
        _seed_valid_supported_installation(root, manifest_schema=2)
        root.joinpath("opt/xferry/releases/0.2.0/xferry-release.json").write_text(
            _v2_installed_manifest(include_extra_digest=True) + "\n",
            encoding="utf-8",
        )

    case_root = tmp_path / "multi-digest"
    result = _run_installer(bundle, case_root, payload, prepare_root=prepare)

    assert result.returncode == 0, result.stderr
    assert case_root.joinpath("mktemp-called").exists()
    assert case_root.joinpath("curl-called").exists()


def test_installer_blocks_unsupported_manifest_hidden_under_a_supported_directory(
    tmp_path: Path,
) -> None:
    """A mismatched manifest blocks even when its directory is on the supported line."""
    payload = b"scie"
    bundle = _render_bundle(tmp_path / "bundle", payload)

    def prepare(root: Path) -> None:
        _seed_valid_supported_installation(root, "0.2.0", manifest_version="4.1.0")

    result = _run_installer(
        bundle,
        tmp_path / "unsupported-manifest",
        payload,
        prepare_root=prepare,
    )

    assert result.returncode != 0
    assert all(clause in result.stderr for clause in UNSUPPORTED_MANAGED_STATE_INSTRUCTION_CLAUSES)
    assert not tmp_path.joinpath("unsupported-manifest/mktemp-called").exists()
    assert not tmp_path.joinpath("unsupported-manifest/curl-called").exists()


@pytest.mark.parametrize(
    "manifest_payload",
    [
        pytest.param(
            """not-json
\"schema_version\": 1
\"version\": \"0.2.0\"
\"tag\": \"v0.2.0\"
\"platform\": \"linux-x86_64\"
\"name\": \"xferry-0.2.0-linux-x86_64\"""",
            id="non-json-substring-bait",
        ),
        pytest.param(
            """{
  \"schema_version\": 1,
  \"schema_version\": 1,
  \"version\": \"0.2.0\",
  \"tag\": \"v0.2.0\",
  \"platform\": \"linux-x86_64\",
  \"executable\": {
    \"name\": \"xferry-0.2.0-linux-x86_64\",
    \"size\": 12,
    \"sha256\": \"0000000000000000000000000000000000000000000000000000000000000000\"
  }
}""",
            id="duplicate-key",
        ),
        pytest.param(
            """{
  \"schema_version\": 1,
  \"version\": \"\\u0032.1.0\",
  \"tag\": \"v2.1.0\",
  \"platform\": \"linux-x86_64\",
  \"executable\": {
    \"name\": \"xferry-2.1.0-linux-x86_64\",
    \"size\": 12,
    \"sha256\": \"0000000000000000000000000000000000000000000000000000000000000000\"
  },
  \"decoy\": {
    \"version\": \"0.2.0\",
    \"tag\": \"v0.2.0\",
    \"platform\": \"linux-x86_64\",
    \"name\": \"xferry-0.2.0-linux-x86_64\"
  }
}""",
            id="nested-extra-key-decoy",
        ),
        pytest.param(
            """{
  \"schema_version\": 1,
  \"version\": \"0.2.0\",
  \"tag\": \"v0.2.0\",
  \"platform\": \"linux-x86_64\",
  \"executable\": {
    \"name\": \"xferry-0.2.0-linux-x86_64\",
    \"size\": 999,
    \"sha256\": \"0000000000000000000000000000000000000000000000000000000000000000\"
  }
}""",
            id="declared-size-mismatch",
        ),
        pytest.param(
            _v2_installed_manifest().replace(
                f'    "workflow_run": "{TEST_WORKFLOW_RUN}"',
                f'    "workflow_run": "{TEST_WORKFLOW_RUN}",',
                1,
            ),
            id="v2-trailing-source-comma",
        ),
        pytest.param(
            _v2_installed_manifest().replace(
                f'    "commit": "{TEST_SOURCE_COMMIT}",',
                f'    "commit": "{TEST_SOURCE_COMMIT}"',
                1,
            ),
            id="v2-missing-source-comma",
        ),
        pytest.param(
            _v2_installed_manifest().replace(
                f'    "xferry-0.2.0-linux-x86_64": "{TEST_INSTALLED_SHA256}"',
                f'    "xferry-0.2.0-linux-x86_64": "{TEST_INSTALLED_SHA256}",',
                1,
            ),
            id="v2-trailing-artifact-comma",
        ),
        pytest.param(
            _v2_installed_manifest(include_extra_digest=True).replace(
                f'    "install.sh": "{"0" * 64}",',
                f'    "install.sh": "{"0" * 64}"',
                1,
            ),
            id="v2-missing-artifact-comma",
        ),
    ],
)
def test_installer_blocks_ambiguous_supported_manifest_before_any_mutation(
    tmp_path: Path,
    manifest_payload: str,
) -> None:
    """Malformed or ambiguous manifests must never unlock the installer mutation boundary."""
    payload = b"scie"
    bundle = _render_bundle(tmp_path / "bundle", payload)
    original_config = b"preserve existing managed config\n"

    def prepare(root: Path) -> None:
        _seed_valid_supported_installation(root)
        root.joinpath("opt/xferry/releases/0.2.0/xferry-release.json").write_text(
            manifest_payload + "\n",
            encoding="utf-8",
        )
        config = root / "etc/xferry/xferry.ini"
        config.parent.mkdir(parents=True)
        config.write_bytes(original_config)

    case_root = tmp_path / "ambiguous-manifest"
    result = _run_installer(bundle, case_root, payload, prepare_root=prepare)
    root = case_root / "root"

    assert result.returncode != 0
    assert all(clause in result.stderr for clause in UNSUPPORTED_MANAGED_STATE_INSTRUCTION_CLAUSES)
    assert not case_root.joinpath("mktemp-called").exists()
    assert not case_root.joinpath("curl-called").exists()
    assert root.joinpath("opt/xferry/current").readlink() == Path("releases/0.2.0")
    assert root.joinpath("usr/local/bin/xferry").readlink() == Path("/opt/xferry/current/xferry")
    assert root.joinpath("etc/xferry/xferry.ini").read_bytes() == original_config
    assert root.joinpath("opt/xferry/releases/0.2.0/xferry-release.json").read_text(
        encoding="utf-8"
    ) == (manifest_payload + "\n")
    assert not root.joinpath("opt/xferry/releases/0.1.0").exists()


def test_installer_blocks_current_symlink_outside_managed_releases(tmp_path: Path) -> None:
    """The guard must inspect, not follow, an unsafe current target."""
    payload = b"scie"
    bundle = _render_bundle(tmp_path / "bundle", payload)

    def prepare(root: Path) -> None:
        _seed_valid_supported_installation(root)
        current = root / "opt/xferry/current"
        current.unlink()
        current.symlink_to(root / "outside")

    result = _run_installer(bundle, tmp_path / "unsafe-current", payload, prepare_root=prepare)

    assert result.returncode != 0
    assert all(clause in result.stderr for clause in UNSUPPORTED_MANAGED_STATE_INSTRUCTION_CLAUSES)
    assert not tmp_path.joinpath("unsafe-current/mktemp-called").exists()
    assert not tmp_path.joinpath("unsafe-current/curl-called").exists()


def test_installer_bounds_release_inventory_before_mktemp_or_download(tmp_path: Path) -> None:
    """More than 128 managed release entries is ambiguous and must fail closed."""
    payload = b"scie"
    bundle = _render_bundle(tmp_path / "bundle", payload)

    def prepare(root: Path) -> None:
        releases = root / "opt/xferry/releases"
        releases.mkdir(parents=True)
        for index in range(129):
            releases.joinpath(f"0.1.{index}").mkdir()
        root.joinpath("opt/xferry/current").symlink_to("releases/0.1.0")

    result = _run_installer(bundle, tmp_path / "bounded", payload, prepare_root=prepare)

    assert result.returncode != 0
    assert all(clause in result.stderr for clause in UNSUPPORTED_MANAGED_STATE_INSTRUCTION_CLAUSES)
    assert not tmp_path.joinpath("bounded/mktemp-called").exists()
    assert not tmp_path.joinpath("bounded/curl-called").exists()


def test_installer_rejects_unsupported_os_before_download_or_destination_mutation(
    tmp_path: Path,
) -> None:
    """The bootstrap must not download or create install paths on an unsupported distro."""
    bundle = _render_bundle(tmp_path / "bundle", b"scie")

    result = _run_installer(
        bundle,
        tmp_path / "unsupported",
        b"scie",
        os_id="ubuntu",
        os_version="20.04",
    )

    root = tmp_path / "unsupported/root"
    assert result.returncode == 4
    assert not (tmp_path / "unsupported/curl-called").exists()
    assert not root.joinpath("opt").exists()
    assert not root.joinpath("usr").exists()


def test_installer_accepts_ubuntu_2604_as_a_managed_host(tmp_path: Path) -> None:
    """The current Ubuntu LTS must reach the verified install path."""
    payload = b"scie"
    bundle = _render_bundle(tmp_path / "bundle", payload)

    result = _run_installer(
        bundle,
        tmp_path / "ubuntu-2604",
        payload,
        os_id="ubuntu",
        os_version="26.04",
    )

    root = tmp_path / "ubuntu-2604/root"
    assert result.returncode == 0, result.stderr
    assert root.joinpath("opt/xferry/current/xferry").read_bytes() == payload


def test_installer_rejects_missing_systemd_before_download_or_destination_mutation(
    tmp_path: Path,
) -> None:
    """Kernel and architecture alone are insufficient for the managed systemd workflow."""
    bundle = _render_bundle(tmp_path / "bundle", b"scie")

    result = _run_installer(
        bundle,
        tmp_path / "missing-systemd",
        b"scie",
        has_systemd=False,
    )

    root = tmp_path / "missing-systemd/root"
    assert result.returncode == 4
    assert not (tmp_path / "missing-systemd/curl-called").exists()
    assert not root.joinpath("opt").exists()
    assert not root.joinpath("usr").exists()


def test_installer_rejects_low_ram_before_download_or_destination_mutation(tmp_path: Path) -> None:
    """Hosts below 512 MiB must fail at the bootstrap boundary with stable exit 4."""
    bundle = _render_bundle(tmp_path / "bundle", b"scie")

    result = _run_installer(
        bundle,
        tmp_path / "low-ram",
        b"scie",
        ram_mib=511,
    )

    root = tmp_path / "low-ram/root"
    assert result.returncode == 4
    assert not (tmp_path / "low-ram/curl-called").exists()
    assert not root.joinpath("opt").exists()
    assert not root.joinpath("usr").exists()


class _LifecycleRunner:
    def __init__(self) -> None:
        self.commands: list[tuple[str, ...]] = []

    def run(self, argv: Sequence[str]) -> CommandResult:
        command = tuple(str(item) for item in argv)
        self.commands.append(command)
        if command == (
            "systemctl",
            "show",
            "--property=ActiveState",
            "--value",
            "xferry.service",
        ):
            return CommandResult(command, 0, stdout="active\n")
        return CommandResult(command, 0)


class _LifecycleDownloader:
    def __init__(self, assets: dict[str, bytes]) -> None:
        self.assets = assets

    def read(self, url: str, max_bytes: int) -> bytes:
        payload = self.assets[url]
        assert len(payload) <= max_bytes
        return payload

    def download(self, url: str, destination: Path, max_bytes: int) -> None:
        payload = self.assets[url]
        assert len(payload) <= max_bytes
        destination.write_bytes(payload)


def test_bootstrap_install_is_eligible_for_default_rollback_after_update(tmp_path: Path) -> None:
    """Omitting bootstrap metadata makes the first verified update impossible to roll back."""
    key_id = "test-release-2026"
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes_raw()
    key_ring = ReleaseKeyRing((TrustedReleaseKey(key_id, public_key),))
    bootstrap_payload = _recording_verifier_scie(public_key)
    bootstrap_manifest, bootstrap_signature = _hosted_envelope(
        bootstrap_payload,
        private_key,
    )
    bundle = _render_bundle(
        tmp_path,
        bootstrap_payload,
        require_hosted_signature=True,
    )
    installed = _run_installer(
        bundle,
        tmp_path / "bootstrap",
        bootstrap_payload,
        manifest_payload=bootstrap_manifest,
        signature_payload=bootstrap_signature,
    )
    assert installed.returncode == 0, installed.stderr
    root = tmp_path / "bootstrap/root"
    layout = ManagedLayout(
        release_root=root / "opt/xferry",
        config_file=root / "etc/xferry/xferry.ini",
        auth_file=root / "etc/xferry/auth",
        data_root=root / "var/lib/xferry",
        lock_file=root / "run/lock/xferry-ops.lock",
        unit_file=root / "etc/systemd/system/xferry.service",
        cli_link=root / "usr/local/bin/xferry",
    )
    layout.config_file.parent.mkdir(parents=True)
    layout.config_file.parent.chmod(0o755)
    layout.config_file.write_text("[server]\nport = 8080\n", encoding="utf-8")
    layout.auth_file.write_text("admin:known-password\n", encoding="utf-8")
    update_payload = b"updated-release"
    base_url = "https://releases.example.test/xferry/releases"
    update_manifest = ReleaseManifest.create_v2(
        version="0.2.0",
        platform="linux-x86_64",
        executable_size=len(update_payload),
        executable_sha256=hashlib.sha256(update_payload).hexdigest(),
        source_commit=TEST_SOURCE_COMMIT,
        workflow_run=TEST_WORKFLOW_RUN,
        signing_key_ids=(key_id,),
    ).to_bytes()
    update_signature = create_detached_signature(
        update_manifest,
        payload_type=MANIFEST_SIGNATURE_TYPE,
        key_id=key_id,
        signer=private_key,
    )
    downloader = _LifecycleDownloader(
        {
            f"{base_url}/download/v0.2.0/xferry-release-linux-x86_64.json": update_manifest,
            f"{base_url}/download/v0.2.0/xferry-release-linux-x86_64.json.sig": update_signature,
            f"{base_url}/download/v0.2.0/xferry-0.2.0-linux-x86_64": update_payload,
        }
    )

    def exact_current_health(*_args: object) -> HealthResult:
        active = layout.release_root.joinpath("current").readlink().name
        return HealthResult(True, "healthy", active)

    installed_bootstrap = layout.release_root / "releases/0.1.0"
    verified_bootstrap = verify_signed_manifest(
        installed_bootstrap.joinpath("xferry-release.json").read_bytes(),
        installed_bootstrap.joinpath("xferry-release.json.sig").read_bytes(),
        key_ring=key_ring,
    )
    assert verified_bootstrap.version == "0.1.0"
    manager = ReleaseManager(
        layout=layout,
        runner=_LifecycleRunner(),
        downloader=downloader,
        health_check=exact_current_health,
        effective_uid=lambda: 0,
        root_uid=os.getuid(),
        release_base_url=base_url,
        platform_id=lambda: "linux-x86_64",
        unit_path=layout.unit_file,
        cli_link=layout.cli_link,
        acme_root=layout.acme_root,
        staging_parent=tmp_path / "staging",
        remote_updates_enabled=True,
        release_key_ring=key_ring,
        host_facts=lambda: HostFacts(
            os_id="ubuntu",
            os_version="24.04",
            machine="x86_64",
            has_systemd=True,
            ram_mib=1024,
            cpu_count=2,
            disk_free_mib=4096,
        ),
    )

    updated = manager.update("0.2.0", False)
    rolled_back = manager.rollback(None, False)

    assert updated.exit_code == 0
    assert rolled_back.exit_code == 0
    assert rolled_back.version == "0.1.0"
    assert layout.release_root.joinpath("current").readlink() == Path("releases/0.1.0")
