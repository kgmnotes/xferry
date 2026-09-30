"""Verify the fixed STAGE-009 candidate and consume only its TestPyPI bytes."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sys
import urllib.request
from pathlib import Path
from urllib.parse import urlsplit

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tools.candidate_inventory import unpack_candidate, verify_inventory  # noqa: E402
from tools.verify_python_artifacts import (  # noqa: E402
    _probe_installed_artifact,
    _require_outside_workspace,
    _run_checked,
    _server_lifecycle_smoke,
    _venv_commands,
)

IDENTITY_FILE = REPO_ROOT / "packaging/testpypi-candidate.json"
INDEX_JSON = "https://test.pypi.org/pypi/xferry/0.1.0/json"


def verify_api_identity(identity: dict, artifact: dict, run: dict) -> None:
    """Reject foreign, expired, rerun, or unsuccessful producer artifacts."""
    expected_artifact = {
        "id": identity["artifact_id"],
        "name": identity["artifact_name"],
        "digest": "sha256:" + identity["artifact_sha256"],
        "size_in_bytes": identity["artifact_size"],
        "expired": False,
    }
    expected_run = {
        "id": identity["workflow_run"],
        "run_attempt": 1,
        "head_sha": identity["source_commit"],
        "event": "workflow_dispatch",
        "path": ".github/workflows/release.yml",
        "status": "completed",
        "conclusion": "success",
    }
    producer = artifact.get("workflow_run", {})
    repository = run.get("repository", {})
    if (
        any(artifact.get(k) != v for k, v in expected_artifact.items())
        or any(run.get(k) != v for k, v in expected_run.items())
        or producer.get("id") != identity["workflow_run"]
        or producer.get("head_sha") != identity["source_commit"]
        or producer.get("repository_id") != identity["repository_id"]
        or repository.get("id") != identity["repository_id"]
        or repository.get("full_name") != identity["repository"]
    ):
        raise ValueError("GitHub candidate API identity differs from STAGE-009")


def _verify_file(path: Path, record: dict) -> None:
    if (
        path.is_symlink()
        or not path.is_file()
        or path.stat().st_size != record["size"]
        or hashlib.sha256(path.read_bytes()).hexdigest() != record["sha256"]
    ):
        raise ValueError(f"distribution bytes differ from STAGE-009: {path.name}")


def prepare_distributions(identity: dict, archive: Path, candidate: Path, packages: Path) -> None:
    """Authenticate the whole candidate before copying exactly the wheel/sdist."""
    if packages.exists():
        raise ValueError("packages directory must be new")
    unpack_candidate(archive, identity["archive_sha256"], candidate)
    verify_inventory(
        candidate,
        identity["tag"],
        identity["source_commit"],
        str(identity["workflow_run"]),
        expected_sha256=identity["inventory_sha256"],
    )
    inventory = json.loads((candidate / "candidate-inventory.json").read_bytes())
    for name, record in identity["distributions"].items():
        if any(inventory["files"]["python/" + name][key] != record[key] for key in record):
            raise ValueError("distribution identity differs from authenticated inventory")
        _verify_file(candidate / "python" / name, record)
    packages.mkdir(parents=True)
    for name, record in identity["distributions"].items():
        shutil.copyfile(candidate / "python" / name, packages / name)
        _verify_file(packages / name, record)


def verify_index_identity(identity: dict, document: dict) -> dict[str, dict]:
    """Require TestPyPI's complete exact-version file set, digests, and origin."""
    if (
        document.get("info", {}).get("name") != "xferry"
        or document["info"].get("version") != identity["version"]
    ):
        raise ValueError("TestPyPI project/version identity differs from candidate")
    files = document.get("urls", [])
    by_name = {entry["filename"]: entry for entry in files}
    if len(by_name) != len(files) or set(by_name) != set(identity["distributions"]):
        raise ValueError("TestPyPI file set differs from candidate")
    for name, record in identity["distributions"].items():
        entry = by_name[name]
        location = urlsplit(entry["url"])
        if (
            entry.get("digests", {}).get("sha256") != record["sha256"]
            or entry.get("size") != record["size"]
            or entry.get("yanked") is not False
            or location.scheme != "https"
            or location.netloc != "test-files.pythonhosted.org"
            or not location.path.startswith("/packages/")
            or location.query
            or location.fragment
        ):
            raise ValueError(f"TestPyPI file identity differs from candidate: {name}")
    return by_name


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError("TestPyPI evidence download must not redirect")


def fetch_bytes(url: str, limit: int) -> bytes:
    """Bound downloads; never send credentials or follow alternate-index redirects."""
    request = urllib.request.Request(url, headers={"User-Agent": "xferry-stage-010-verifier"})
    with urllib.request.build_opener(_NoRedirect()).open(request, timeout=30) as response:
        payload = response.read(limit + 1)
    if len(payload) > limit:
        raise ValueError("TestPyPI evidence exceeds expected size")
    return payload


def download_distributions(identity: dict, document: dict, destination: Path) -> Path:
    entries = verify_index_identity(identity, document)
    destination.mkdir(parents=True, exist_ok=False)
    for name, record in identity["distributions"].items():
        payload = fetch_bytes(entries[name]["url"], record["size"])
        target = destination / name
        target.write_bytes(payload)
        _verify_file(target, record)
    receipt = {"index": INDEX_JSON, "candidate": identity, "accepted": document}
    (destination / "testpypi-receipt.json").write_text(
        json.dumps(receipt, sort_keys=True, indent=2) + "\n", encoding="utf-8"
    )
    return destination / "xferry-0.1.0-py3-none-any.whl"


def pipx_environment(root: Path) -> dict[str, str]:
    environment = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith(("PIP_", "PIPX_", "PYTHON", "UV_"))
        and key not in {"VIRTUAL_ENV", "PYTEST_ADDOPTS"}
    }
    environment.update(
        PIPX_HOME=str(root / "pipx"),
        PIPX_BIN_DIR=str(root / "bin"),
        PIPX_MAN_DIR=str(root / "man"),
        PIP_CONFIG_FILE=os.devnull,
        PYTHONNOUSERSITE="1",
    )
    return environment


def pipx_install_command(wheel: Path) -> tuple[str, ...]:
    pip_args = "--index-url https://pypi.org/simple/ --only-binary=:all: --no-cache-dir"
    return (
        sys.executable,
        "-I",
        "-m",
        "pipx",
        "install",
        "--python",
        sys.executable,
        "--pip-args",
        pip_args,
        str(wheel),
    )


def pipx_smoke(wheel: Path, root: Path, workspace: Path, constraints: Path) -> None:
    """Exercise actual pipx and the installed application outside the source tree."""
    root = _require_outside_workspace(root, workspace=workspace, label="TestPyPI pipx root")
    root.mkdir(parents=True, exist_ok=False)
    probe = root / "outside-checkout"
    probe.mkdir()
    environment = pipx_environment(root)
    # pipx changes pip's cwd, and Windows pip-args parsing preserves quotes.
    # A trusted absolute environment value avoids both path interpretation bugs.
    environment["PIP_CONSTRAINT"] = str(constraints.resolve())
    _run_checked(pipx_install_command(wheel), cwd=probe, env=environment)
    venv = root / "pipx" / "venvs" / "xferry"
    python, console = _venv_commands(venv)
    exposed = root / "bin" / console.name
    _run_checked((str(exposed), "--version"), cwd=probe, env=environment)
    _run_checked((str(exposed), "run", "--print-config"), cwd=probe, env=environment)
    _run_checked(
        (
            str(python),
            "-I",
            "-c",
            "from importlib.metadata import version; assert version('xferry') == '0.1.0'",
        ),
        cwd=probe,
        env=environment,
    )
    _probe_installed_artifact(venv_dir=venv, probe_dir=probe, workspace=workspace)
    _server_lifecycle_smoke(venv_dir=venv, probe_dir=probe, workspace=workspace)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("identity", "prepare", "verify-index", "smoke"))
    parser.add_argument("--artifact-metadata", type=Path)
    parser.add_argument("--run-metadata", type=Path)
    parser.add_argument("--archive", type=Path)
    parser.add_argument("--candidate-dir", type=Path)
    parser.add_argument("--packages-dir", type=Path)
    parser.add_argument("--download-dir", type=Path)
    parser.add_argument("--fresh-root", type=Path)
    args = parser.parse_args(argv)
    identity = json.loads(IDENTITY_FILE.read_bytes())
    try:
        if args.command in {"identity", "prepare"}:
            if args.artifact_metadata is None or args.run_metadata is None:
                parser.error("GitHub artifact and run metadata are required")
            verify_api_identity(
                identity,
                json.loads(args.artifact_metadata.read_bytes()),
                json.loads(args.run_metadata.read_bytes()),
            )
            if args.command == "prepare":
                if any(
                    value is None for value in (args.archive, args.candidate_dir, args.packages_dir)
                ):
                    parser.error("archive, candidate-dir and packages-dir are required")
                prepare_distributions(identity, args.archive, args.candidate_dir, args.packages_dir)
        else:
            if args.download_dir is None or (args.command == "smoke" and args.fresh_root is None):
                parser.error("download-dir and (for smoke) fresh-root are required")
            document = json.loads(fetch_bytes(INDEX_JSON, 2 * 1024 * 1024))
            wheel = download_distributions(identity, document, args.download_dir)
            if args.command == "smoke":
                pipx_smoke(wheel, args.fresh_root, REPO_ROOT, REPO_ROOT / "constraints/ci.txt")
    except (ValueError, OSError, KeyError, TypeError) as error:
        print(f"TestPyPI {args.command} failed: {error}", file=sys.stderr)
        return 1
    print(f"TestPyPI {args.command}: exact STAGE-009 identity verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
