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
def test_public_engine_drives_distinct_versions_and_checks_preservation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    lose_auth: bool,
) -> None:
    """Mocked orchestration of the current schema; not public release evidence."""
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
    paths.unit.write_bytes(b"verified current native unit")
    controller = tmp_path / "verified-target-controller"
    monkeypatch.setattr(public, "_maintenance_cli", lambda *_args: nullcontext(controller))
    monkeypatch.setattr(public, "_cli_contract", lambda *_args: "canonical")
    plan = {
        "previousTag": "v0.5.0",
        "releases": {"previous": {"version": "0.5.0"}, "target": {"version": "0.6.0"}},
    }
    identity = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    identities = []
    monkeypatch.setattr(
        public.common, "_deployment_identity", lambda p, v, i: identities.append((p, v, i))
    )
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
            "profile": True,
            "auth": not (lose_auth and len(preserve_calls) == 2),
            "sentinel": True,
        }

    monkeypatch.setattr(public.common, "_preservation", preservation)

    def command(argv: tuple[str, ...], **kwargs: Any) -> bytes:
        commands.append((tuple(argv), kwargs))
        return b""

    monkeypatch.setattr(public.common, "_command", command)

    def operation(details, *, state=None, url=None):
        return {
            "exit_code": 0,
            "message": "unit outcome",
            "details": details,
            "url": url,
            "plan": None,
            "state": state,
        }

    def observed(retained=False):
        return {
            "state": "retained" if retained else "running",
            "instance_id": identity,
            "backend": "native",
            "health": "not_checked",
            "detail": "unit state",
            "running": not retained,
            "config": "valid",
            "enabled": "unknown" if retained else "enabled",
        }

    def json_command(argv: tuple[str, ...], **kwargs: Any) -> dict[str, Any]:
        commands.append((tuple(argv), kwargs))
        phase = argv[1]
        if phase == "setup":
            return operation(
                {"instance_id": identity, "files_dir": str(paths.data_root / "files")},
                url="http://127.0.0.1:8080",
            )
        if phase == "doctor":
            state = observed()
            state["health"] = "healthy"
            checks = {
                name: {"status": status, "detail": "unit check"}
                for name, status in {
                    "manifest": "valid",
                    "configuration": "valid",
                    "runtime": "running",
                    "files": "available",
                    "health": "healthy",
                }.items()
            }
            return operation({"checks": checks}, state=state)
        if phase == "uninstall":
            paths.unit.unlink()
            return operation(
                {
                    "retained": [
                        str(paths.profile),
                        str(paths.data_root),
                        str(paths.data_root / "files"),
                    ]
                },
                state=observed(True),
            )
        details = {
            "version": "0.5.0" if phase == "rollback" else "0.6.0",
            "dry_run": False,
            "code": "rollback_complete",
            "detail": "unit release",
            "before": None,
            "target": None,
            "active": None,
            "rollback": "not_attempted",
            "next_actions": [],
        }
        if phase == "update":
            dry_run = "--dry-run" in argv
            details.update(
                dry_run=dry_run,
                code="update_dry_run" if dry_run else "update_complete",
                before="0.5.0",
                target="0.6.0",
                active="0.5.0" if dry_run else "0.6.0",
                rollback="not_needed",
            )
        return operation(details, state=observed())

    monkeypatch.setattr(public.common, "_json_command", json_command)
    result = public.run_public_probe(options, paths)
    assert result["status"] == ("failed" if lose_auth else "passed"), result
    assert commands[0][0] == ("sh", str(tmp_path / "v0.5.0" / "install-linux-x86_64.sh"))
    assert all(set(kwargs["environment"]) == set(public._environment()) for _, kwargs in commands)
    assert (str(paths.cli), "setup", "--backend", "native", "--access", "private", "--json") in [
        argv for argv, _ in commands
    ]
    update_commands = [argv for argv, _ in commands if len(argv) > 1 and argv[1] == "update"]
    assert update_commands == [
        (str(controller), "update", "--to", "0.6.0", "--dry-run", "--instance", identity, "--json"),
        (str(controller), "update", "--to", "0.6.0", "--instance", identity, "--json"),
    ]
    if lose_auth:
        assert result["failure"] == {"phase": "update", "code": "state_preservation_failed"}
        assert not any(argv[1] == "rollback" for argv, _ in commands)
    else:
        doctor_stage = next(stage for stage in result["stages"] if stage["phase"] == "doctor")
        assert set(doctor_stage["checks"]) == {
            "manifest",
            "configuration",
            "runtime",
            "files",
            "health",
        }
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
        assert health == ["0.5.0", "0.5.0", "0.5.0", "0.6.0", "0.5.0"]
        assert identities == [(paths, v, identity) for v in ("0.5.0", "0.5.0", "0.6.0", "0.5.0")]
        assert (str(controller), "rollback", "--to", "0.5.0", "--instance", identity, "--json") in [
            argv for argv, _ in commands
        ]
    assert "not-exported-unit-hash" not in options.evidence.read_text()


@pytest.mark.parametrize(
    ("help_text", "expected"),
    [
        (b"usage: xferry setup [--private]\n", None),
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
        return b"xferry 0.6.0\n" if argv[-1] == "--version" else help_text

    monkeypatch.setattr(public.common, "_command", command)
    executable = Path("/verified/target")
    if expected is None:
        with pytest.raises(public.common.ProbeFailure, match="command_output_invalid"):
            public._cli_contract(executable, "0.6.0")
    else:
        assert public._cli_contract(executable, "0.6.0") == expected
    assert calls == [(str(executable), "--version"), (str(executable), "setup", "--help")]


def test_cli_contract_refuses_wrong_version_before_help(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = []

    def command(argv, **_kwargs):
        calls.append(tuple(argv))
        return b"xferry 0.5.1\n"

    monkeypatch.setattr(public.common, "_command", command)
    with pytest.raises(public.common.ProbeFailure, match="cli_version_mismatch"):
        public._cli_contract(Path("/verified/target"), "0.6.0")
    assert len(calls) == 1


def test_maintenance_controller_copy_is_exact_private_executable_and_temporary(
    tmp_path: Path,
) -> None:
    """The controller must survive changing installed current, without executing fixtures."""
    import stat

    directory = tmp_path / "v0.6.0"
    directory.mkdir()
    name = "xferry-0.6.0-linux-x86_64"
    source = directory / name
    payload = b"not executable: synthetic verified fixture"
    source.write_bytes(payload)
    source.chmod(0o644)
    record = {"size": len(payload), "sha256": hashlib.sha256(payload).hexdigest()}
    plan = {
        "releases": {
            "target": {
                "version": "0.6.0",
                "tag": "v0.6.0",
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
