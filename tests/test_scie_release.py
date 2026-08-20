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

from tools.build_scie_release import CommandRunner, ReleaseBundle, build_release_bundle
from xferry.management.health import HealthResult
from xferry.management.model import ManagedLayout
from xferry.management.releases import ReleaseManager
from xferry.management.system import CommandResult

REPO_ROOT = Path(__file__).resolve().parents[1]
UNSUPPORTED_MANAGED_STATE_INSTRUCTION_CLAUSES = (
    (
        "Unsupported or ambiguous XFerry managed state was detected and preserved; "
        "no changes were made."
    ),
    "Back up the existing XFerry configuration and data.",
    "Remove the managed state with its original tooling.",
    "Then install XFerry in a clean environment.",
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
    assert "Build the deterministic SCIE assets" in result.stdout


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


def _render_bundle(tmp_path: Path, payload: bytes = b"scie") -> ReleaseBundle:
    return build_release_bundle(
        REPO_ROOT,
        tmp_path / "bundle",
        "0.1.0",
        FakeRunner(payload),
    )


def test_release_builder_rejects_a_wheel_with_an_internal_public_surface(tmp_path: Path) -> None:
    """Catches SCIE construction accepting an internal artifact from its real wheel input."""
    with pytest.raises(RuntimeError, match="CLAU" + "DE.md"):
        build_release_bundle(REPO_ROOT, tmp_path / "bundle", "0.1.0", ForbiddenWheelRunner(b"scie"))


def test_release_builder_rejects_nested_internal_wheel_content(tmp_path: Path) -> None:
    """Catches SCIE construction accepting a nested internal path in its wheel."""
    with pytest.raises(RuntimeError, match="implementation" + "-plan"):
        build_release_bundle(
            REPO_ROOT,
            tmp_path / "bundle",
            "0.1.0",
            NestedForbiddenWheelRunner(b"scie"),
        )


def _run_installer(
    bundle: ReleaseBundle,
    tmp_path: Path,
    payload: bytes,
    *,
    os_id: str = "ubuntu",
    os_version: str = "24.04",
    has_systemd: bool = True,
    ram_mib: int = 1024,
    prepare_root: Callable[[Path], None] | None = None,
) -> subprocess.CompletedProcess[str]:
    fake_bin = tmp_path / "fake-bin"
    fake_bin.mkdir(parents=True)
    tmp_path.chmod(0o755)
    (fake_bin / "id").write_text("#!/bin/sh\necho 0\n", encoding="utf-8")
    (fake_bin / "uname").write_text(
        '#!/bin/sh\ncase "$1" in -s) echo Linux ;; -m) echo x86_64 ;; esac\n',
        encoding="utf-8",
    )
    (fake_bin / "curl").write_text(
        "#!/bin/sh\n"
        ': > "$XFERRY_TEST_CURL_MARKER"\n'
        'while [ "$#" -gt 0 ]; do\n'
        '  if [ "$1" = "-o" ]; then cp "$XFERRY_TEST_PAYLOAD" "$2"; exit 0; fi\n'
        "  shift\n"
        "done\n"
        "exit 2\n",
        encoding="utf-8",
    )
    real_mktemp = shutil.which("mktemp")
    assert real_mktemp is not None
    (fake_bin / "mktemp").write_text(
        f'#!/bin/sh\n: > "$XFERRY_TEST_MKTEMP_MARKER"\nexec "{real_mktemp}" "$@"\n',
        encoding="utf-8",
    )
    for tool in fake_bin.iterdir():
        tool.chmod(0o755)

    downloaded = tmp_path / "downloaded-scie"
    downloaded.write_bytes(payload)
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
        "XFERRY_RELEASE_BASE_URL": "https://releases.example.test/xferry",
        "XFERRY_TEST_CURL_MARKER": str(tmp_path / "curl-called"),
        "XFERRY_TEST_MKTEMP_MARKER": str(tmp_path / "mktemp-called"),
        "XFERRY_TEST_PAYLOAD": str(downloaded),
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
) -> None:
    described_version = manifest_version or version
    payload = f"xferry-{version}".encode()
    release = root / "opt/xferry/releases" / version
    release.mkdir(parents=True)
    executable = release / "xferry"
    executable.write_bytes(payload)
    executable.chmod(0o755)
    release.joinpath("xferry-release.json").write_text(
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
        + "\n",
        encoding="utf-8",
    )
    root.joinpath("opt/xferry/current").symlink_to(Path("releases") / version)
    cli_link = root / "usr/local/bin/xferry"
    cli_link.parent.mkdir(parents=True)
    cli_link.symlink_to("/opt/xferry/current/xferry")


def test_release_bundle_writes_literal_manifest_and_checksum(tmp_path: Path) -> None:
    payload = b"scie-payload"
    bundle = _render_bundle(tmp_path, payload)

    executable = bundle.output_dir / "xferry-0.1.0-linux-x86_64"
    manifest = json.loads(bundle.manifest.read_text(encoding="utf-8"))
    expected_sha256 = hashlib.sha256(payload).hexdigest()

    assert executable.read_bytes() == payload
    assert manifest == {
        "schema_version": 1,
        "version": "0.1.0",
        "tag": "v0.1.0",
        "platform": "linux-x86_64",
        "executable": {
            "name": "xferry-0.1.0-linux-x86_64",
            "size": 12,
            "sha256": expected_sha256,
        },
    }
    assert bundle.manifest.read_bytes().endswith(b"\n")
    assert bundle.checksums.read_text(encoding="utf-8") == (
        f"{expected_sha256}  xferry-0.1.0-linux-x86_64\n"
    )


@pytest.mark.parametrize("version", ["1.0.0", "4.1.0", "99.0.0"])
def test_release_builder_rejects_other_majors_before_build_or_output(
    tmp_path: Path,
    version: str,
) -> None:
    """An unsupported release line must not create output or invoke build tools."""
    runner = FakeRunner(b"scie")
    output = tmp_path / "bundle"

    with pytest.raises(ValueError, match="supported release line"):
        build_release_bundle(REPO_ROOT, output, version, runner)

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
        build_release_bundle(REPO_ROOT, output, version, runner)

    assert runner.commands == []
    assert not output.exists()


@pytest.mark.parametrize("version", ["0.1.0", "0.2.0", "0.2.0-rc.1", "0.2.0+build.1"])
def test_release_builder_accepts_canonical_supported_versions(
    tmp_path: Path,
    version: str,
) -> None:
    runner = FakeRunner(b"scie")

    bundle = build_release_bundle(REPO_ROOT, tmp_path / "bundle", version, runner)

    assert bundle.executable.name == f"xferry-{version}-linux-x86_64"


def test_release_builder_uses_pinned_pex_lock_and_eager_cpython_scie(tmp_path: Path) -> None:
    runner: CommandRunner = FakeRunner(b"scie")
    _ = build_release_bundle(REPO_ROOT, tmp_path / "bundle", "0.1.0", runner)
    commands = [command for command, _cwd in runner.commands]

    assert any(command[:4] == ("python", "-m", "build", "--wheel") for command in commands)
    lock_command = next(
        command for command in commands if command[:3] == ("pex3", "lock", "create")
    )
    scie_command = next(command for command in commands if "--scie" in command)
    assert "constraints/ci.txt" in lock_command
    assert "pex==2.99.0" in (REPO_ROOT / "constraints/ci.txt").read_text(encoding="utf-8")
    assert ("--scie", "eager") == tuple(scie_command[scie_command.index("--scie") :][:2])
    assert "CPython>=3.12,<3.13" in scie_command
    assert ("-c", "xferry") == tuple(scie_command[scie_command.index("-c") :][:2])


def test_release_builder_passes_the_wheel_as_a_positional_pex_requirement(tmp_path: Path) -> None:
    """PEX treats ``--requirement`` inputs as UTF-8 requirement files, not wheels."""
    runner: CommandRunner = FakeRunner(b"scie")
    _ = build_release_bundle(REPO_ROOT, tmp_path / "bundle", "0.1.0", runner)
    lock_command = next(
        command for command, _cwd in runner.commands if command[:3] == ("pex3", "lock", "create")
    )

    assert "--requirement" not in lock_command
    assert any(argument.endswith(".whl") for argument in lock_command)


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


def test_installer_allows_a_valid_same_major_managed_installation(tmp_path: Path) -> None:
    """The guard must not reject an ordinary supported-line bootstrap rerun."""
    payload = b"scie"
    bundle = _render_bundle(tmp_path / "bundle", payload)

    result = _run_installer(
        bundle,
        tmp_path / "same-major",
        payload,
        prepare_root=_seed_valid_supported_installation,
    )
    root = tmp_path / "same-major/root"

    assert result.returncode == 0, result.stderr
    assert tmp_path.joinpath("same-major/mktemp-called").exists()
    assert tmp_path.joinpath("same-major/curl-called").exists()
    assert root.joinpath("opt/xferry/current").readlink() == Path("releases/0.1.0")
    assert root.joinpath("opt/xferry/releases/0.2.0/xferry").is_file()


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

    def download(self, url: str, destination: Path, max_bytes: int) -> None:
        payload = self.assets[url]
        assert len(payload) <= max_bytes
        destination.write_bytes(payload)


def test_bootstrap_install_is_eligible_for_default_rollback_after_update(tmp_path: Path) -> None:
    """Omitting bootstrap metadata makes the first verified update impossible to roll back."""
    bootstrap_payload = b"bootstrap-release"
    bundle = _render_bundle(tmp_path, bootstrap_payload)
    installed = _run_installer(bundle, tmp_path / "bootstrap", bootstrap_payload)
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
    update_manifest = (
        json.dumps(
            {
                "schema_version": 1,
                "version": "0.2.0",
                "tag": "v0.2.0",
                "platform": "linux-x86_64",
                "executable": {
                    "name": "xferry-0.2.0-linux-x86_64",
                    "size": len(update_payload),
                    "sha256": hashlib.sha256(update_payload).hexdigest(),
                },
            }
        )
        + "\n"
    ).encode()
    downloader = _LifecycleDownloader(
        {
            f"{base_url}/download/v0.2.0/xferry-release.json": update_manifest,
            f"{base_url}/download/v0.2.0/xferry-0.2.0-linux-x86_64": update_payload,
        }
    )
    manager = ReleaseManager(
        layout=layout,
        runner=_LifecycleRunner(),
        downloader=downloader,
        health_check=lambda *_args: HealthResult(True, "healthy"),
        effective_uid=lambda: 0,
        root_uid=os.getuid(),
        release_base_url=base_url,
        platform_id=lambda: "linux-x86_64",
        unit_path=layout.unit_file,
        cli_link=layout.cli_link,
        acme_root=layout.acme_root,
        staging_parent=tmp_path / "staging",
    )

    updated = manager.update("0.2.0", False)
    rolled_back = manager.rollback(None, False)

    assert updated.exit_code == 0
    assert rolled_back.exit_code == 0
    assert rolled_back.version == "0.1.0"
    assert layout.release_root.joinpath("current").readlink() == Path("releases/0.1.0")
