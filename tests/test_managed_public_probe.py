"""Unit safety checks only; not public/network/systemd execution evidence."""

from __future__ import annotations

import hashlib
import json
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
            return {"exit_code": 0, "status": "ok", "url": "http://127.0.0.1:8080"}
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
        elif phase == "rollback":
            result["version"] = "0.1.0"
        return result

    monkeypatch.setattr(public.common, "_json_command", json_command)
    result = public.run_public_probe(options, paths)
    assert result["status"] == ("failed" if lose_auth else "passed")
    assert commands[0][0] == ("sh", str(tmp_path / "v0.1.0" / "install-linux-x86_64.sh"))
    assert all(set(kwargs["environment"]) == set(public._environment()) for _, kwargs in commands)
    update_commands = [argv for argv, _ in commands if len(argv) > 1 and argv[1] == "update"]
    assert update_commands == [
        (str(paths.cli), "update", "--to", "0.2.0", "--dry-run", "--json"),
        (str(paths.cli), "update", "--to", "0.2.0", "--json"),
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
        assert (str(paths.cli), "rollback", "--to", "0.1.0", "--json") in [
            argv for argv, _ in commands
        ]
    assert "not-exported-unit-hash" not in options.evidence.read_text()
