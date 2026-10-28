"""Unit safety checks only; not public/network/systemd execution evidence."""

from __future__ import annotations

import hashlib
import json
from contextlib import nullcontext
from pathlib import Path
from typing import Any

import pytest

from tools import managed_public_probe as public


def test_public_child_does_not_inherit_credentials_proxy_or_release_ca_overrides(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for key in (
        "GH_TOKEN",
        "GITHUB_TOKEN",
        "HTTPS_PROXY",
        "HTTP_PROXY",
        "SSL_CERT_FILE",
        "CURL_CA_BUNDLE",
        "XFERRY_RELEASE_BASE_URL",
    ):
        monkeypatch.setenv(key, "sensitive-unit-value")
    environment = public._environment()
    assert environment["TMPDIR"] == "/var/tmp"
    assert set(environment) == {"PATH", "HOME", "LANG", "LC_ALL", "TMPDIR"}
    assert "sensitive-unit-value" not in str(environment)


def test_installed_bytes_must_match_public_manifest_digest_and_size(tmp_path: Path) -> None:
    path = tmp_path / "executable"
    path.write_bytes(b"exact public unit bytes")
    record = {"size": path.stat().st_size, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
    public._digest(path, record)
    path.write_bytes(b"changed public unit bytes")
    with pytest.raises(public.common.ProbeFailure):
        public._digest(path, record)


def test_installed_digest_check_rejects_symlinks(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.write_bytes(b"payload")
    link = tmp_path / "link"
    link.symlink_to(target)
    with pytest.raises(OSError):
        public._digest(link, {"size": 7, "sha256": hashlib.sha256(b"payload").hexdigest()})


def test_public_guard_failure_prevents_installer_and_emits_only_fixed_code(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    options = public.PublicProbeOptions(
        plan=tmp_path / "plan.json",
        assets_root=tmp_path,
        evidence=tmp_path / "evidence.json",
        distro="ubuntu",
        distro_version="24.04",
        machine="x86_64",
        platform="linux-x86_64",
        host_cgroup_namespace="cgroup:[1]",
    )

    def fail(**_kwargs: Any) -> None:
        raise public.common.ProbeFailure("root_required")

    def forbidden(*_args: Any, **_kwargs: Any) -> None:
        raise AssertionError("installer must not run after failed guard")

    monkeypatch.setattr(public.common, "guard_host", fail)
    monkeypatch.setattr(public.common, "_command", forbidden)
    result = public.run_public_probe(options)
    assert result["status"] == "failed"
    assert result["failure"] == {"phase": "guard", "code": "root_required"}
    assert json.loads(options.evidence.read_bytes()) == result
    assert "sensitive" not in options.evidence.read_text()


@pytest.mark.parametrize("lose_auth", [False, True])
@pytest.mark.parametrize("conversion", [False, True])
def test_public_engine_drives_distinct_versions_and_checks_preservation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    lose_auth: bool,
    conversion: bool,
) -> None:
    """Mocked lifecycle orchestration; never evidence that public releases ran."""
    options = public.PublicProbeOptions(
        plan=tmp_path / "plan.json",
        assets_root=tmp_path,
        evidence=tmp_path / "evidence.json",
        distro="ubuntu",
        distro_version="24.04",
        machine="x86_64",
        platform="linux-x86_64",
        host_cgroup_namespace="cgroup:[1]",
    )
    paths = public.common.SystemPaths(
        release_root=tmp_path / "releases",
        config_root=tmp_path / "config",
        data_root=tmp_path / "data",
        unit=tmp_path / "unit",
        cli=tmp_path / "bin" / "xferry",
    )
    paths.data_root.mkdir()
    paths.config_root.mkdir()
    canonical = (
        f"[server]\naccess = private\nhost = 127.0.0.1\nport = 8080\n"
        f"files_dir = {paths.data_root / 'uploads'}\nlog_level = info\nlog_format = json\n"
        f"[security]\nauth_file = {paths.auth}\n[tls]\nhttps_mode = off\n"
    ).encode()
    legacy = (
        f"[server]\npreset = local\nhost = 127.0.0.1\nport = 8080\n"
        f"root_dir = {paths.data_root}\njson_log = true\n"
        f"[security]\nauth_file = {paths.auth}\n[tls]\ntls = false\n"
    ).encode()
    baseline_config = legacy if conversion else canonical
    old_unit = (
        f"[Service]\nUser=xferry\nGroup=xferry\nProtectHome=true\n"
        f"ExecStartPre={paths.release_root}/current/xferry run --config "
        f"{paths.config} --check-config\n"
        f"ExecStart={paths.release_root}/current/xferry run --config {paths.config}\n"
    ).encode()
    new_unit = (
        old_unit.replace(
            f"run --config {paths.config} --check-config".encode(),
            f"config check --config {paths.config}".encode(),
        )
        + f"Environment=XFERRY_STATE_HOME={paths.data_root}\n".encode()
    )
    baseline_unit = old_unit if conversion else new_unit
    paths.config.write_bytes(baseline_config)
    paths.unit.write_bytes(baseline_unit)
    controller = tmp_path / "verified-target-controller"
    monkeypatch.setattr(public, "_maintenance_cli", lambda *_args: nullcontext(controller))
    monkeypatch.setattr(
        public,
        "_cli_contract",
        lambda executable, _version: (
            "legacy" if conversion and executable == paths.cli else "canonical"
        ),
    )
    plan = {
        "previousTag": "v0.1.0",
        "releases": {"previous": {"version": "0.1.0"}, "target": {"version": "0.2.0"}},
    }
    commands: list[tuple[tuple[str, ...], dict[str, Any]]] = []
    health: list[str] = []
    monkeypatch.setattr(public.common, "guard_host", lambda **_kwargs: {"unit": "mock host only"})
    monkeypatch.setattr(public, "_inputs", lambda _options: plan)
    monkeypatch.setattr(public.common, "_version", lambda *_args: None)
    monkeypatch.setattr(
        public.common, "verify_health", lambda version, _paths: health.append(version)
    )
    monkeypatch.setattr(public.common, "_service", lambda active: {"active": active})
    monkeypatch.setattr(
        public.common, "_state_hashes", lambda _paths: {"auth": "not-exported-unit-hash"}
    )
    monkeypatch.setattr(
        public,
        "_release_state",
        lambda _paths, version, retained, *_args: {
            "version": version,
            "retained_versions": list(retained),
        },
    )
    preserve_calls = []

    def preservation(*_args: Any) -> dict[str, bool]:
        preserve_calls.append(True)
        return {
            "config": True,
            "auth": not (lose_auth and len(preserve_calls) == 2),
            "sentinel": True,
        }

    monkeypatch.setattr(public.common, "_preservation", preservation)

    def command(argv: tuple[str, ...], **kwargs: Any) -> bytes:
        commands.append((tuple(argv), kwargs))
        return b""

    monkeypatch.setattr(public.common, "_command", command)

    def json_command(argv: tuple[str, ...], **kwargs: Any) -> dict[str, Any]:
        commands.append((tuple(argv), kwargs))
        phase = argv[1]
        if phase == "setup":
            result = {"exit_code": 0, "status": "ok", "url": "http://127.0.0.1:8080"}
            if not conversion:
                result["files_dir"] = str(paths.data_root / "files")
            return result
        if phase == "doctor":
            result = dict.fromkeys(public.common._DOCTOR_FIELDS)
            result.update(
                code="doctor-ok",
                checks={
                    key: {"status": value} for key, value in public.common._DOCTOR_STATUSES.items()
                },
            )
            return result
        result = dict.fromkeys(public.common._RELEASE_FIELDS)
        result.update(dry_run=False, rollback="not_attempted", code=f"{phase}_complete")
        if phase == "update":
            dry_run = "--dry-run" in argv
            result.update(
                version="0.2.0",
                before="0.1.0",
                target="0.2.0",
                dry_run=dry_run,
                active="0.1.0" if dry_run else "0.2.0",
                rollback="not_needed",
                code="update_dry_run" if dry_run else "update_complete",
            )
            if not dry_run and conversion:
                paths.config.write_bytes(canonical)
                paths.unit.write_bytes(new_unit)
        elif phase == "rollback":
            result["version"] = "0.1.0"
            paths.config.write_bytes(baseline_config)
            paths.unit.write_bytes(baseline_unit)
        elif phase == "uninstall":
            paths.unit.unlink()
        return result

    monkeypatch.setattr(public.common, "_json_command", json_command)
    result = public.run_public_probe(options, paths)
    assert result["status"] == ("failed" if lose_auth else "passed")
    assert commands[0][0] == ("sh", str(tmp_path / "v0.1.0" / "install-linux-x86_64.sh"))
    assert all(set(kwargs["environment"]) == set(public._environment()) for _, kwargs in commands)
    update_commands = [argv for argv, _ in commands if len(argv) > 1 and argv[1] == "update"]
    assert update_commands == [
        (
            str(controller),
            "update",
            "--to",
            "0.2.0",
            "--dry-run",
            "--config",
            str(paths.config),
            "--json",
        ),
        (str(controller), "update", "--to", "0.2.0", "--config", str(paths.config), "--json"),
    ]
    if lose_auth:
        assert result["failure"] == {"phase": "update", "code": "state_preservation_failed"}
        assert not any(argv[1] == "rollback" for argv, _ in commands)
    else:
        assert [stage["phase"] for stage in result["stages"]] == [
            "guard",
            "install",
            "setup",
            "doctor",
            "dry_run",
            "update",
            "rollback",
            "uninstall",
        ]
        assert health == ["0.1.0", "0.1.0", "0.1.0", "0.2.0", "0.1.0"]
        assert (
            str(controller),
            "rollback",
            "--to",
            "0.1.0",
            "--config",
            str(paths.config),
            "--json",
        ) in [argv for argv, _ in commands]
    assert "not-exported-unit-hash" not in options.evidence.read_text()


@pytest.mark.parametrize(
    ("help_text", "expected"),
    [
        (b"usage: xferry setup [--private]\n", "legacy"),
        (b"usage: xferry setup [--access {private,public}]\n", "canonical"),
        (b"usage: setup [--private] [--access {private,public}]\n", None),
        (b"use --accessibility and --private-data\n", None),
        (b"no recognized access switch\n", None),
    ],
)
def test_cli_contract_uses_exact_authenticated_help_without_fallback(
    monkeypatch: pytest.MonkeyPatch, help_text: bytes, expected: str | None
) -> None:
    calls = []

    def command(argv, **kwargs):
        calls.append(tuple(argv))
        assert kwargs["environment"] == public._environment()
        return b"xferry 0.3.0\n" if argv[-1] == "--version" else help_text

    monkeypatch.setattr(public.common, "_command", command)
    executable = Path("/verified/target")
    if expected is None:
        with pytest.raises(public.common.ProbeFailure, match="command_output_invalid"):
            public._cli_contract(executable, "0.3.0")
    else:
        assert public._cli_contract(executable, "0.3.0") == expected
    assert calls == [(str(executable), "--version"), (str(executable), "setup", "--help")]


def test_cli_contract_refuses_wrong_version_before_help(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = []

    def command(argv, **_kwargs):
        calls.append(tuple(argv))
        return b"xferry 0.2.1\n"

    monkeypatch.setattr(public.common, "_command", command)
    with pytest.raises(public.common.ProbeFailure, match="cli_version_mismatch"):
        public._cli_contract(Path("/verified/target"), "0.3.0")
    assert len(calls) == 1


def test_maintenance_controller_copy_is_exact_private_executable_and_temporary(
    tmp_path: Path,
) -> None:
    """The controller must survive changing installed current, without executing fixtures."""
    import stat

    directory = tmp_path / "v0.3.0"
    directory.mkdir()
    name = "xferry-0.3.0-linux-x86_64"
    source = directory / name
    payload = b"not executable: synthetic verified fixture"
    source.write_bytes(payload)
    source.chmod(0o644)
    record = {"size": len(payload), "sha256": hashlib.sha256(payload).hexdigest()}
    plan = {
        "releases": {
            "target": {
                "version": "0.3.0",
                "tag": "v0.3.0",
                "platforms": {"linux-x86_64": {"assets": {name: record}}},
            }
        }
    }
    options = public.PublicProbeOptions(
        plan=tmp_path / "plan",
        assets_root=tmp_path,
        evidence=tmp_path / "evidence",
        distro="ubuntu",
        distro_version="24.04",
        machine="x86_64",
        platform="linux-x86_64",
        host_cgroup_namespace="cgroup:[1]",
    )
    with public._maintenance_cli(options, plan) as controller:
        assert controller != source
        assert controller.read_bytes() == payload
        assert stat.S_IMODE(controller.stat().st_mode) == 0o700
        assert stat.S_IMODE(controller.parent.stat().st_mode) == 0o700
        assert stat.S_IMODE(source.stat().st_mode) == 0o644
        assert controller.parent.parent == Path("/var/tmp")
    assert not controller.exists()
    assert not controller.parent.exists()


@pytest.fixture
def converted_private_baseline(tmp_path: Path):
    paths = public.common.SystemPaths(
        release_root=tmp_path / "releases",
        config_root=tmp_path / "config",
        data_root=tmp_path / "state",
        unit=tmp_path / "unit",
        cli=tmp_path / "cli",
    )
    paths.config_root.mkdir()
    before = (
        f"[server]\npreset = local\nhost = 127.0.0.1\nport = 8080\n"
        f"root_dir = {paths.data_root}\njson_log = true\n"
        f"[security]\nauth_file = {paths.auth}\n"
        "[limits]\nmax_size_mb = 123\n"
    ).encode()
    after = (
        f"[server]\naccess = private\nhost = 127.0.0.1\nport = 8080\n"
        f"files_dir = {paths.data_root / 'uploads'}\nlog_level = info\nlog_format = json\n"
        f"[security]\nauth_file = {paths.auth}\n"
        "[limits]\nmax_size_mb = 123\n[tls]\nhttps_mode = off\n"
    ).encode()
    unit = (
        f"[Service]\nUser=xferry\nGroup=xferry\nProtectHome=true\n"
        f"ExecStartPre={paths.release_root}/current/xferry run --config "
        f"{paths.config} --check-config\n"
        f"ExecStart={paths.release_root}/current/xferry run --config {paths.config}\n"
    ).encode()
    canonical_unit = (
        unit.replace(
            f"run --config {paths.config} --check-config".encode(),
            f"config check --config {paths.config}".encode(),
        )
        + f"Environment=XFERRY_STATE_HOME={paths.data_root}\n".encode()
    )
    paths.config.write_bytes(after)
    paths.unit.write_bytes(canonical_unit)
    return paths, before, unit


def test_cross_schema_config_proof_distinguishes_conversion_from_unchanged_bytes(
    converted_private_baseline,
) -> None:
    paths, before, unit = converted_private_baseline
    assert paths.config.read_bytes() != before
    proof = public._configuration_transition(paths, before, unit)
    assert proof == {
        "transition": "legacy-to-canonical",
        "values_preserved": True,
        "files_path_preserved": True,
        "state_path_preserved": True,
        "unit_updated": True,
    }
    assert str(paths.data_root) not in json.dumps(proof)
    assert "sha256" not in json.dumps(proof)


@pytest.mark.parametrize("change", ["quota", "files", "auth", "state", "sandbox", "old-unit"])
def test_cross_schema_config_proof_rejects_changed_values_paths_or_unit(
    converted_private_baseline, change: str
) -> None:
    paths, before, unit = converted_private_baseline
    if change in {"quota", "files", "auth"}:
        original, replacement = {
            "quota": ("max_size_mb = 123", "max_size_mb = 0"),
            "files": (str(paths.data_root / "uploads"), str(paths.data_root / "empty")),
            "auth": (str(paths.auth), str(paths.config_root / "different-auth")),
        }[change]
        paths.config.write_text(paths.config.read_text().replace(original, replacement))
    elif change == "state":
        paths.unit.write_text(
            paths.unit.read_text().replace(
                f"XFERRY_STATE_HOME={paths.data_root}", "XFERRY_STATE_HOME=/unrelated"
            )
        )
    elif change == "sandbox":
        paths.unit.write_text(paths.unit.read_text().replace("ProtectHome=true\n", ""))
    else:
        paths.unit.write_bytes(unit)
    with pytest.raises(public.common.ProbeFailure, match="state_preservation_failed"):
        public._configuration_transition(paths, before, unit)
