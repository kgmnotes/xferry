"""Stdlib-only consumer of real public releases in a disposable systemd container.

The native parent verifies public signatures before mounting the plan/assets.
This child never patches a runtime, redirects releases, imports checkout XFerry,
or exports generated authentication/configuration values or their hashes.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

if TYPE_CHECKING:
    from tools import managed_systemd_probe as common
elif __package__:
    from . import managed_systemd_probe as common
else:
    import managed_systemd_probe as common

SCOPE = "native-systemd-public-lifecycle"


@dataclass(frozen=True)
class PublicProbeOptions:
    plan: Path
    assets_root: Path
    evidence: Path
    distro: str
    distro_version: str
    machine: str
    platform: str
    host_cgroup_namespace: str


def _environment() -> dict[str, str]:
    """No token, proxy, release URL override or custom CA reaches the installed CLI."""
    return {
        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "HOME": "/root",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "TMPDIR": "/var/tmp",
    }


def _digest(path: Path, expected: dict[str, Any]) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        metadata = os.fstat(stream.fileno())
        common._require(
            stat.S_ISREG(metadata.st_mode) and metadata.st_size == expected["size"],
            "release_state_invalid",
        )
        digest = hashlib.sha256()
        for chunk in iter(lambda: stream.read(64 * 1024), b""):
            digest.update(chunk)
    common._require(digest.hexdigest() == expected["sha256"], "release_state_invalid")


def _release_state(
    paths: common.SystemPaths,
    version: str,
    retained: tuple[str, ...],
    plan: dict[str, Any],
    platform: str,
) -> dict[str, object]:
    result = common._release_state(paths, version, retained)
    installed: dict[str, object] = {}
    for release in plan["releases"].values():
        if release["version"] not in retained:
            continue
        assets = release["platforms"][platform]["assets"]
        name = f"xferry-release-{platform}.json"
        executable = f"xferry-{release['version']}-{platform}"
        root = paths.release_root / "releases" / release["version"]
        _digest(root / "xferry-release.json", assets[name])
        _digest(root / "xferry-release.json.sig", assets[name + ".sig"])
        _digest(root / "xferry", assets[executable])
        installed[release["version"]] = {
            "manifestSha256": assets[name]["sha256"],
            "signatureSha256": assets[name + ".sig"]["sha256"],
            "executableSha256": assets[executable]["sha256"],
            "executableSize": assets[executable]["size"],
        }
    result["installed"] = installed
    return result


def _inputs(options: PublicProbeOptions) -> dict[str, Any]:
    document = json.loads(
        common._regular_bytes(options.plan, 4 * 1024 * 1024), object_pairs_hook=common._json_object
    )
    common._require(
        isinstance(document, dict)
        and document.get("schema") == 1
        and document.get("scope") == "managed-public-lifecycle-plan"
        and document.get("repository") == "kgmnotes/xferry",
        "fixture_layout_invalid",
    )
    common._require(
        options.assets_root.is_absolute()
        and options.assets_root.is_dir()
        and options.assets_root.resolve() == options.assets_root
        and not options.assets_root.is_symlink(),
        "fixture_layout_invalid",
    )
    # The parent has already authenticated both signed release identities. Keep
    # the child path grammar narrow before using either tag as a local component.
    import re

    tags = []
    for role in ("previous", "target"):
        release = document["releases"][role]
        tag = release["tag"]
        common._require(
            isinstance(tag, str)
            and re.fullmatch(r"v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)", tag)
            is not None
            and release["version"] == tag[1:],
            "fixture_layout_invalid",
        )
        tags.append(tuple(map(int, tag[1:].split("."))))
        for name, expected in release["platforms"][options.platform]["assets"].items():
            common._require(
                isinstance(name, str)
                and "/" not in name
                and "\\" not in name
                and name not in {".", ".."},
                "fixture_layout_invalid",
            )
            _digest(options.assets_root / tag / name, expected)
    common._require(tags[0] < tags[1], "fixture_layout_invalid")
    return cast(dict[str, Any], document)


def run_public_probe(
    options: PublicProbeOptions, paths: common.SystemPaths = common.SYSTEM_PATHS
) -> dict[str, object]:
    evidence: dict[str, Any] = {"schema": 1, "scope": SCOPE, "status": "failed", "stages": []}
    stage: dict[str, Any] = {"phase": "guard", "status": "started"}
    evidence["stages"].append(stage)
    phase = "guard"
    try:
        evidence["host"] = common.guard_host(
            distro=options.distro,
            distro_version=options.distro_version,
            machine=options.machine,
            platform=options.platform,
            host_cgroup_namespace=options.host_cgroup_namespace,
            paths=paths,
        )
        plan = _inputs(options)
        previous = plan["releases"]["previous"]["version"]
        target = plan["releases"]["target"]["version"]
        stage["status"] = "passed"
        phase = "install"
        stage = {"phase": phase, "status": "started"}
        evidence["stages"].append(stage)
        installer = options.assets_root / plan["previousTag"] / f"install-{options.platform}.sh"
        # The unchanged verified installer performs real public HTTPS downloads.
        common._command(("sh", str(installer)), environment=_environment())
        common._version(paths, previous)
        stage.update(_release_state(paths, previous, (previous,), plan, options.platform))
        stage.update(service=common._service(False), status="passed")

        phase = "setup"
        stage = {"phase": phase, "status": "started"}
        evidence["stages"].append(stage)
        setup = common._json_command(
            (str(paths.cli), "setup", "--private", "--json"),
            environment=_environment(),
            discard_stderr=True,
        )
        common._require(
            set(setup) == {"exit_code", "status", "url"}
            and setup["url"] == "http://127.0.0.1:8080",
            "setup_outcome_invalid",
        )
        common._version(paths, previous)
        common.verify_health(previous, paths)
        descriptor = os.open(
            paths.sentinel, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
        )
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(b"xferry public managed lifecycle sentinel\n")
        baseline = common._state_hashes(paths)
        stage.update(_release_state(paths, previous, (previous,), plan, options.platform))
        stage.update(service=common._service(True), health=True, status="passed")

        phase = "doctor"
        stage = {"phase": phase, "status": "started"}
        evidence["stages"].append(stage)
        doctor = common._json_command(
            (str(paths.cli), "doctor", "--deep", "--json"), environment=_environment()
        )
        common._require(
            set(doctor) == common._DOCTOR_FIELDS
            and doctor["code"] == "doctor-ok"
            and isinstance(doctor["checks"], dict)
            and set(doctor["checks"]) == set(common._DOCTOR_STATUSES),
            "doctor_outcome_invalid",
        )
        checks = {
            name: isinstance(doctor["checks"][name], dict)
            and doctor["checks"][name].get("status") == status
            for name, status in common._DOCTOR_STATUSES.items()
        }
        common._require(all(checks.values()), "doctor_outcome_invalid")
        common._version(paths, previous)
        common.verify_health(previous, paths)
        stage.update(_release_state(paths, previous, (previous,), plan, options.platform))
        stage.update(service=common._service(True), health=True, checks=checks, status="passed")

        for phase in ("dry_run", "update", "rollback", "uninstall"):
            stage = {"phase": phase, "status": "started"}
            evidence["stages"].append(stage)
            if phase in {"dry_run", "update"}:
                argv = [str(paths.cli), "update", "--to", target]
                if phase == "dry_run":
                    argv.append("--dry-run")
                result = common._json_command((*argv, "--json"), environment=_environment())
                version = previous if phase == "dry_run" else target
                common._require(
                    set(result) == common._RELEASE_FIELDS | {"version"}
                    and result["code"]
                    == ("update_dry_run" if phase == "dry_run" else "update_complete")
                    and result["dry_run"] is (phase == "dry_run")
                    and result["before"] == previous
                    and result["target"] == result["version"] == target
                    and result["active"] == version
                    and result["rollback"] == "not_needed",
                    "update_outcome_invalid",
                )
            else:
                argv = [str(paths.cli), phase]
                if phase == "rollback":
                    argv.extend(("--to", previous))
                result = common._json_command((*argv, "--json"), environment=_environment())
                common._require(
                    set(result)
                    == common._RELEASE_FIELDS | ({"version"} if phase == "rollback" else set())
                    and result["code"] == f"{phase}_complete"
                    and result["dry_run"] is False
                    and result["active"] is None
                    and result["before"] is None
                    and result["target"] is None
                    and result["rollback"] == "not_attempted",
                    "release_outcome_invalid",
                )
                version = previous
                if phase == "rollback":
                    common._require(result["version"] == previous, "rollback_outcome_invalid")
            preserved = common._preservation(baseline, paths)
            common._require(all(preserved.values()), "state_preservation_failed")
            stage["preserved"] = preserved
            if phase == "uninstall":
                common._require(
                    all(
                        not os.path.lexists(path)
                        for path in (paths.release_root, paths.unit, paths.cli)
                    ),
                    "uninstall_state_invalid",
                )
                stage.update(service=common._service(False), removed=True)
            else:
                common._version(paths, version)
                common.verify_health(version, paths)
                retained = (previous,) if phase == "dry_run" else (previous, target)
                stage.update(_release_state(paths, version, retained, plan, options.platform))
                stage.update(service=common._service(True), health=True)
            stage["status"] = "passed"
        evidence["status"] = "passed"
    except Exception as exc:
        code = str(exc) if isinstance(exc, common.ProbeFailure) else "probe_failed"
        stage.update(status="failed", code=code)
        evidence["failure"] = {"phase": phase, "code": code}
    options.evidence.parent.mkdir(parents=True, exist_ok=True)
    options.evidence.write_text(
        json.dumps(evidence, sort_keys=True, indent=2) + "\n", encoding="utf-8"
    )
    return evidence


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("plan", "assets-root", "evidence"):
        parser.add_argument(f"--{name}", type=Path, required=True)
    for name in ("distro", "distro-version", "machine", "platform", "host-cgroup-namespace"):
        parser.add_argument(f"--{name}", required=True)
    try:
        result = run_public_probe(PublicProbeOptions(**vars(parser.parse_args(argv))))
        print(json.dumps({"scope": result["scope"], "status": result["status"]}))
        return 0 if result["status"] == "passed" else 1
    except Exception:
        print('{"status":"failed","code":"probe_failed"}')
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
