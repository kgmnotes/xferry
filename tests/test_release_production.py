"""Production release workflow stays tag-only, immutable, and fail closed."""

from __future__ import annotations

import os
import re
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
PRODUCTION_WORKFLOW = REPO_ROOT / ".github/workflows/release-production.yml"
CANDIDATE_WORKFLOW = REPO_ROOT / ".github/workflows/release.yml"


def _job(workflow: str, name: str) -> str:
    marker = f"  {name}:"
    lines = workflow.splitlines()
    start = lines.index(marker)
    end = len(lines)
    for index in range(start + 1, len(lines)):
        line = lines[index]
        if line.startswith("  ") and not line.startswith("    ") and line.endswith(":"):
            end = index
            break
    return "\n".join(lines[start:end])


def production_policy_findings(workflow: str) -> list[str]:
    findings: list[str] = []
    required = (
        '    tags:\n      - "v*.*.*"',
        'test "$GITHUB_EVENT_NAME" = "push"',
        'test "$GITHUB_REF_PROTECTED" = "true"',
        "git fetch --no-tags origin +refs/heads/main:refs/remotes/origin/main",
        'git merge-base --is-ancestor "$GITHUB_SHA" refs/remotes/origin/main',
        '[[ "$RELEASE_TAG" =~ ^v(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)$ ]]',
        'python tools/check_release_preflight.py --tag "$RELEASE_TAG"',
        "uses: ./.github/workflows/release.yml",
        "python tools/production_release.py prepare",
        '--artifact-id "${{ needs.candidate.outputs.artifact-id }}"',
        '--archive-sha256 "${{ needs.candidate.outputs.archive-sha256 }}"',
        '--inventory-sha256 "${{ needs.candidate.outputs.inventory-sha256 }}"',
        "environment: production-release",
        "environment: release-production",
        "pypa/gh-action-pypi-publish@dc37677b2e1c63e2034f94d8a5b11f265b73ba33",
        "python tools/production_release_state.py draft",
        "python tools/production_release_state.py expose",
        "release-id: ${{ steps.release.outputs.release-id }}",
        "skopeo copy --all --preserve-digests",
        "--notes-file final-release-notes.md",
        "https://pypi.org/pypi/xferry/${RELEASE_VERSION}/json",
        "ghcr.io/kgmnotes/xferry@${GHCR_DIGEST}",
        "https://github.com/kgmnotes/xferry/releases/download/${RELEASE_TAG}/",
        "Full managed ten-pair systemd evidence has not yet been verified for this release",
        "Pages deployment remains forbidden until all post-publish evidence passes",
    )
    for item in required:
        if item not in workflow:
            findings.append(f"missing production contract: {item}")

    if "workflow_dispatch:" in workflow or "pull_request:" in workflow or "branches:" in workflow:
        findings.append("production workflow must have no manual, PR, or branch trigger")
    if "actions/deploy-pages" in workflow or "pages: write" in workflow:
        findings.append("production release must not deploy Pages")
    for match in re.finditer(r"uses:\s+([^\s#]+)", workflow):
        target = match.group(1)
        if not target.startswith("./") and not re.fullmatch(r"[^@]+@[0-9a-f]{40}", target):
            findings.append("every external action must be pinned to a full commit SHA")
            break
    if "skip-existing" in workflow or "password:" in workflow or "docker build" in workflow:
        findings.append("publishers must not skip, use static credentials, or rebuild")

    sign = _job(workflow, "sign-assets")
    for name in (
        "prepare-candidate",
        "create-draft-release",
        "publish-pypi",
        "publish-ghcr",
        "publish-github-release",
        "post-pypi",
        "post-ghcr",
        "post-release",
        "production-readiness",
        "final-gate",
    ):
        try:
            block = _job(workflow, name)
        except ValueError:
            findings.append(f"missing job: {name}")
            continue
        if name != "sign-assets" and "XFERRY_RELEASE_ED25519_PRIVATE_KEY_PEM" in block:
            findings.append(f"private signing key escaped into {name}")
    if "XFERRY_RELEASE_ED25519_PRIVATE_KEY_PEM" not in sign:
        findings.append("signing job does not consume the protected key")
    if "contents: write" in sign or "packages: write" in sign or "id-token: write" in sign:
        findings.append("signing job has an external publication permission")

    for name in (
        "create-draft-release",
        "publish-pypi",
        "publish-ghcr",
        "publish-github-release",
    ):
        block = _job(workflow, name)
        if "environment: release-production" not in block:
            findings.append(f"{name} is not protected by release-production")

    pypi = _job(workflow, "publish-pypi")
    if not all(item in pypi for item in ("actions: read", "id-token: write")):
        findings.append("PyPI job lacks its exact OIDC permissions")
    if any(item in pypi for item in ("contents: write", "packages: write", "actions/checkout@")):
        findings.append("PyPI job has an extra capability")

    ghcr = _job(workflow, "publish-ghcr")
    if not all(item in ghcr for item in ("actions: read", "packages: write")):
        findings.append("GHCR job lacks its exact package permissions")
    if any(item in ghcr for item in ("contents: write", "id-token: write")):
        findings.append("GHCR job has an extra capability")

    public = _job(workflow, "publish-github-release")
    if not all(item in public for item in ("actions: read", "contents: write")):
        findings.append("GitHub Release activation lacks exact permissions")
    for job, required_needs in (
        ("verify-pypi-identity", {"publish-pypi"}),
        ("post-pypi", {"publish-pypi", "verify-pypi-identity"}),
        ("publish-ghcr", {"publish-pypi", "post-pypi"}),
        ("post-ghcr", {"publish-ghcr"}),
        ("publish-github-release", {"create-draft-release", "post-pypi", "post-ghcr"}),
        ("post-release", {"create-draft-release", "publish-github-release"}),
    ):
        if not required_needs <= _needs(workflow, job):
            findings.append(f"{job} bypasses a required consumer gate")
    consumers = _job(workflow, "post-pypi")
    if (
        "actions/checkout@" not in consumers
        or "persist-credentials: false" not in consumers
        or "ref: ${{ needs.preflight.outputs.source-commit }}" not in consumers
        or consumers.index("actions/checkout@") > consumers.index("Install pipx bootstrap")
    ):
        findings.append("public pipx consumer lacks source-pinned checkout before pip bootstrap")
    anonymous = _job(workflow, "post-ghcr")
    if any(item in anonymous for item in ("GH_TOKEN", "docker login", "packages: read")):
        findings.append("public GHCR consumer uses registry authentication")
    if "DOCKER_CONFIG: ${{ runner.temp }}/xferry-anonymous-docker-" not in anonymous:
        findings.append("public GHCR consumer does not isolate its anonymous Docker config")
    if "/releases/tags/" in workflow:
        findings.append(
            "bound Release operations must not resolve drafts through the public tag API"
        )
    return findings


def _needs(workflow: str, job: str) -> set[str]:
    match = re.search(r"(?m)^    needs: \[([^]]+)]$", _job(workflow, job))
    return {name.strip() for name in match[1].split(",")} if match else set()


def test_production_workflow_has_fail_closed_boundaries() -> None:
    workflow = PRODUCTION_WORKFLOW.read_text(encoding="utf-8")
    assert production_policy_findings(workflow) == []

    assert "needs: [preflight, prepare-candidate, create-draft-release]" in _job(
        workflow, "publish-pypi"
    )
    assert "needs: [preflight, sign-assets]" in _job(workflow, "create-draft-release")
    assert _needs(workflow, "publish-ghcr") == {
        "preflight",
        "prepare-candidate",
        "publish-pypi",
        "post-pypi",
    }
    public = _job(workflow, "publish-github-release")
    assert _needs(workflow, "publish-github-release") == {
        "preflight",
        "prepare-candidate",
        "sign-assets",
        "create-draft-release",
        "publish-ghcr",
        "post-pypi",
        "post-ghcr",
    }
    for marker in (
        "PyPI distributions",
        "record['sha256']",
        "record['size']",
        "GHCR_DIGEST",
        "Signed GitHub Release assets",
        "signing_key_id",
        "docs/release-runbook.md",
        "docs/incident-response.md",
        "--notes-file final-release-notes.md",
    ):
        assert marker in public
    readiness = _job(workflow, "production-readiness")
    assert "needs: [preflight, candidate, prepare-candidate]" in readiness
    assert "exit 1" in readiness
    assert "production-readiness" in _job(workflow, "sign-assets").splitlines()[1]
    assert workflow.count("retention-days: 14") >= 4
    assert not re.search(r"(?m)^\s*retention-days:\s*[0-9]\s*$", workflow)
    assert workflow.count("environment: release-production") == 4
    for writer in (
        "create-draft-release",
        "publish-pypi",
        "publish-ghcr",
        "publish-github-release",
    ):
        assert "environment: release-production" in _job(workflow, writer)


def test_candidate_workflow_is_reusable_and_exposes_immutable_identity() -> None:
    workflow = CANDIDATE_WORKFLOW.read_text(encoding="utf-8")
    assert "workflow_call:" in workflow
    for output in (
        "artifact-id",
        "archive-sha256",
        "inventory-sha256",
        "candidate-tag",
        "source-commit",
        "workflow-run",
    ):
        assert f"      {output}:" in workflow
    assert "workflow_dispatch:" in workflow
    assert "pypa/gh-action-pypi-publish" not in workflow
    assert "packages: write" not in workflow
    assert "contents: write" not in workflow


@pytest.mark.parametrize(
    ("before", "after"),
    [
        ('      - "v*.*.*"', '      - "*"'),
        ("  push:", "  workflow_dispatch:"),
        ('          test "$GITHUB_REF_PROTECTED" = "true"\n', ""),
        (
            '          git merge-base --is-ancestor "$GITHUB_SHA" refs/remotes/origin/main\n',
            "",
        ),
        ("environment: release-production", "environment: production-release"),
        ("id-token: write", "contents: write"),
        ("skopeo copy --all --preserve-digests", "docker build --push"),
        ("python tools/production_release_state.py draft", "gh release create --latest"),
        (
            "python tools/production_release_state.py expose",
            "gh release edit --latest",
        ),
        (
            "Full managed ten-pair systemd evidence has not yet been verified for this release",
            "Hosted runners prove all managed targets",
        ),
    ],
)
def test_production_policy_rejects_release_boundary_regressions(before: str, after: str) -> None:
    workflow = PRODUCTION_WORKFLOW.read_text(encoding="utf-8")
    assert production_policy_findings(workflow) == []
    assert before in workflow
    assert production_policy_findings(workflow.replace(before, after, 1))


def test_production_consumers_precede_each_subsequent_publication() -> None:
    workflow = PRODUCTION_WORKFLOW.read_text(encoding="utf-8")
    assert _needs(workflow, "verify-pypi-identity") == {
        "preflight",
        "prepare-candidate",
        "publish-pypi",
    }
    assert _needs(workflow, "post-pypi") == {"preflight", "publish-pypi", "verify-pypi-identity"}
    assert _needs(workflow, "post-ghcr") == {"preflight", "publish-ghcr"}
    assert "publish-github-release" not in _needs(workflow, "post-pypi")
    assert "publish-github-release" not in _needs(workflow, "post-ghcr")
    assert "name: Public pipx (${{ matrix.os }}, Python ${{ matrix.python }})" in _job(
        workflow, "post-pypi"
    )
    assert "name: Public GHCR (${{ matrix.arch }}, native)" in _job(workflow, "post-ghcr")
    for gate, publisher in (("post-pypi", "publish-ghcr"), ("post-ghcr", "publish-github-release")):
        mutation = workflow.replace(
            _job(workflow, publisher),
            _job(workflow, publisher).replace(f", {gate}]", "]"),
            1,
        )
        assert production_policy_findings(mutation)


def _run_step(job: str, step: str) -> str:
    block = _job(PRODUCTION_WORKFLOW.read_text(encoding="utf-8"), job)
    content = block.split(f"      - name: {step}\n", 1)[1].split("      - name:", 1)[0]
    return textwrap.dedent(content.split("        run: |\n", 1)[1])


@pytest.mark.parametrize("runner_os", ["Linux", "macOS", "Windows"])
@pytest.mark.parametrize("actual_version", ["xferry 1.2.3", "xferry 1.2.4"])
@pytest.mark.skipif(os.name == "nt", reason="fake POSIX executables require a POSIX host")
def test_public_pipx_step_installs_exact_pypi_version_and_rejects_wrong_cli(
    tmp_path: Path, runner_os: str, actual_version: str
) -> None:
    tools = tmp_path / "tools"
    tools.mkdir()
    python = tools / "python"
    python.write_text('#!/bin/bash\nprintf "%s\\n" "$@" > "$INSTALL_ARGUMENTS"\n')
    python.chmod(0o755)
    binary_dir = tmp_path / "bin"
    binary_dir.mkdir()
    executable = binary_dir / ("xferry.exe" if runner_os == "Windows" else "xferry")
    executable.write_text(
        '#!/bin/bash\nprintf "%s\\n" "$@" >> "$CLI_ARGUMENTS"\n'
        'if [ "$1" = --version ]; then printf "%s\\n" "$CONSUMER_VERSION"; fi\n'
    )
    executable.chmod(0o755)
    env = {
        **os.environ,
        "PATH": f"{tools}:/usr/bin:/bin",
        "RUNNER_OS": runner_os,
        "PIPX_HOME": str(tmp_path / "pipx"),
        "PIPX_BIN_DIR": str(binary_dir),
        "RELEASE_VERSION": "1.2.3",
        "CONSUMER_VERSION": actual_version,
        "INSTALL_ARGUMENTS": str(tmp_path / "install.txt"),
        "CLI_ARGUMENTS": str(tmp_path / "cli.txt"),
    }
    result = subprocess.run(
        [
            "bash",
            "-c",
            _run_step("post-pypi", "Install and exercise the exact public PyPI version"),
        ],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert (result.returncode == 0) == (actual_version == "xferry 1.2.3"), result.stderr
    assert (tmp_path / "install.txt").read_text().splitlines() == [
        "-m",
        "pipx",
        "install",
        "--pip-args=--index-url https://pypi.org/simple/ --no-cache-dir",
        "xferry==1.2.3",
    ]
    cli = (tmp_path / "cli.txt").read_text().splitlines()
    expected_cli = (
        ["--version", "run", "--print-config"] if result.returncode == 0 else ["--version"]
    )
    assert cli == expected_cli


@pytest.mark.parametrize(("arch", "machine"), [("amd64", "x86_64"), ("arm64", "aarch64")])
@pytest.mark.parametrize("actual_version", ["xferry 1.2.3", "xferry 1.2.4"])
@pytest.mark.skipif(os.name == "nt", reason="fake POSIX executables require a POSIX host")
def test_public_ghcr_step_pulls_anonymously_and_rejects_wrong_cli(
    tmp_path: Path, arch: str, machine: str, actual_version: str
) -> None:
    tools = tmp_path / "tools"
    tools.mkdir()
    uname = tools / "uname"
    uname.write_text('#!/bin/bash\nprintf "%s\\n" "$CONSUMER_MACHINE"\n')
    uname.chmod(0o755)
    docker = tools / "docker"
    docker.write_text(
        "#!/bin/bash\nset -euo pipefail\n"
        'test -d "$DOCKER_CONFIG"\n'
        'test -z "$(ls -A "$DOCKER_CONFIG")"\n'
        'printf "%s\\n" "$*" >> "$DOCKER_ARGUMENTS"\n'
        'if [ "$1" = login ]; then exit 99; fi\n'
        'if [ "$1" = run ] && [ "$4" = --version ]; then '
        'printf "%s\\n" "$CONSUMER_VERSION"; fi\n'
    )
    docker.chmod(0o755)
    digest = "sha256:" + "a" * 64
    env = {
        **os.environ,
        "PATH": f"{tools}:/usr/bin:/bin",
        "CONSUMER_MACHINE": machine,
        "DOCKER_CONFIG": str(tmp_path / "anonymous-docker"),
        "DOCKER_ARGUMENTS": str(tmp_path / "docker.txt"),
        "GHCR_DIGEST": digest,
        "RELEASE_VERSION": "1.2.3",
        "CONSUMER_VERSION": actual_version,
    }
    command = _run_step("post-ghcr", "Pull the immutable GHCR digest on its native architecture")
    command = command.replace("${{ matrix.machine }}", machine).replace("${{ matrix.arch }}", arch)
    result = subprocess.run(
        ["bash", "-c", command],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert (result.returncode == 0) == (actual_version == "xferry 1.2.3"), result.stderr
    commands = (tmp_path / "docker.txt").read_text().splitlines()
    assert commands[:3] == [
        f"pull --platform linux/{arch} ghcr.io/kgmnotes/xferry@{digest}",
        f"image inspect ghcr.io/kgmnotes/xferry@{digest}",
        f"run --rm ghcr.io/kgmnotes/xferry@{digest} --version",
    ]
    assert len(commands) == (4 if result.returncode == 0 else 3)
    if result.returncode == 0:
        assert commands[-1] == f"run --rm ghcr.io/kgmnotes/xferry@{digest} run --print-config"


@pytest.mark.parametrize("mode", ["empty", "partial", "conflicting", "unexpected"])
@pytest.mark.skipif(os.name == "nt", reason="fake POSIX executables require a POSIX host")
def test_draft_step_uploads_only_missing_bytes_and_rejects_conflicting_assets(
    tmp_path: Path, mode: str
) -> None:
    import json

    signed = tmp_path / "signed-handoff/signed-assets"
    signed.mkdir(parents=True)
    expected = {"a.bin": b"signed A", "b.bin": b"signed B", "github-release-assets.json": b"{}"}
    for name, payload in expected.items():
        (signed / name).write_bytes(payload)
    database = tmp_path / "database"
    database.mkdir()
    assets = []
    if mode != "empty":
        name = "unexpected.bin" if mode == "unexpected" else "a.bin"
        payload = b"changed bytes" if mode in {"conflicting", "unexpected"} else expected[name]
        (database / name).write_bytes(payload)
        assets.append({"id": 100, "name": name})
    state_file = database / "state.json"
    state_file.write_text(json.dumps({"id": 321, "assets": assets}))
    helper = textwrap.dedent("""\
        import json
        import os
        import sys
        from pathlib import Path
        from urllib.parse import parse_qs, urlparse

        args = sys.argv[1:]
        command = Path(sys.argv[0]).name
        database = Path(os.environ["DRAFT_DATABASE"])
        state_file = database / "state.json"
        state = json.loads(state_file.read_text())
        if command == "python":
            assert args[0] == "tools/production_release_state.py"
            assert args[1] in {"draft", "read"}
            assert args[args.index("--repository") + 1] == "kgmnotes/xferry"
            if args[1] == "read":
                assert args[args.index("--release-id") + 1] == "321"
                assert args[args.index("--state") + 1] == "draft"
            Path(args[args.index("--output") + 1]).write_text(json.dumps(state))
            print(state["id"])
        elif command == "jq":
            document = json.loads(Path(args[-1]).read_text())
            if "--arg" in args:
                name = args[args.index("--arg") + 2]
                matches = [asset["id"] for asset in document["assets"] if asset["name"] == name]
                assert len(matches) == 1
                print(matches[0])
            else:
                assert args[-2] == ".assets[].name"
                for asset in document["assets"]:
                    print(asset["name"])
        elif command == "gh":
            assert args[0] == "api"
            method = args[args.index("--method") + 1] if "--method" in args else "GET"
            with (database / "calls.txt").open("a") as log:
                log.write(method + "\\n")
            if method == "POST":
                url = urlparse(args[3])
                assert url.netloc == "uploads.github.com"
                assert url.path == "/repos/kgmnotes/xferry/releases/321/assets"
                name = parse_qs(url.query)["name"][0]
                assert all(asset["name"] != name for asset in state["assets"])
                payload = Path(args[args.index("--input") + 1]).read_bytes()
                (database / name).write_bytes(payload)
                state["assets"].append({"id": 100 + len(state["assets"]), "name": name})
                state_file.write_text(json.dumps(state))
                print("{}")
            else:
                prefix = "repos/kgmnotes/xferry/releases/assets/"
                assert args[1].startswith(prefix)
                asset_id = int(args[1][len(prefix):])
                matches = [asset for asset in state["assets"] if asset["id"] == asset_id]
                assert len(matches) == 1
                sys.stdout.buffer.write((database / matches[0]["name"]).read_bytes())
        else:
            raise AssertionError(command)
        """)
    tools = tmp_path / "tools"
    tools.mkdir()
    for name in ("python", "jq", "gh"):
        program = tools / name
        program.write_text(f"#!{sys.executable}\n{helper}")
        program.chmod(0o755)
    output = tmp_path / "outputs.txt"
    output.touch()
    env = {
        **os.environ,
        "PATH": f"{tools}:/usr/bin:/bin",
        "DRAFT_DATABASE": str(database),
        "GITHUB_REPOSITORY": "kgmnotes/xferry",
        "GITHUB_OUTPUT": str(output),
        "RELEASE_TAG": "v1.2.3",
        "SOURCE_COMMIT": "a" * 40,
    }
    command = _run_step(
        "create-draft-release", "Create or resume the exact draft without overwriting assets"
    )
    result = subprocess.run(
        ["bash", "-c", command],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    calls_file = database / "calls.txt"
    calls = calls_file.read_text().splitlines() if calls_file.exists() else []
    if mode in {"empty", "partial"}:
        assert result.returncode == 0, result.stderr
        assert output.read_text() == "release-id=321\n"
        assert calls.count("POST") == (3 if mode == "empty" else 2)
        for name, payload in expected.items():
            assert (database / name).read_bytes() == payload
            assert (tmp_path / "downloaded-draft" / name).read_bytes() == payload
    else:
        assert result.returncode != 0
        assert "POST" not in calls
        assert output.read_text() == ""
