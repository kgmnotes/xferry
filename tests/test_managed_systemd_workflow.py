"""Manual fixture matrix stays native, source-bound, secret-free and nonpublic."""

from __future__ import annotations

import os
import subprocess
import textwrap
from pathlib import Path

import pytest

from tools import check_stale_docs

REPO_ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = REPO_ROOT / ".github/workflows/managed-systemd-matrix.yml"


def _run_block(workflow: str, name: str) -> str:
    start = workflow.index(f"      - name: {name}\n")
    start = workflow.index("        run: |\n", start) + len("        run: |\n")
    commands = []
    for line in workflow[start:].splitlines():
        if line and not line.startswith("          "):
            break
        commands.append(line)
    return textwrap.dedent("\n".join(commands))


def _policy_findings(workflow: str) -> list[str]:
    return [
        finding.message
        for finding in check_stale_docs.managed_systemd_workflow_policy_findings(workflow)
    ]


def test_native_systemd_workflow_policy_and_publication_boundary() -> None:
    workflow = WORKFLOW.read_text()
    assert _policy_findings(workflow) == []
    production = (REPO_ROOT / ".github/workflows/release-production.yml").read_text()
    assert "uses: ./.github/workflows/managed-systemd-matrix.yml" in production
    assert "python tools/production_readiness.py verify-native" in production
    assert "uses: ./.github/workflows/managed-public-matrix.yml" in production
    docs = (REPO_ROOT / "docs/release-runbook.md").read_text()
    assert "publicReleaseEvidence: false" in docs
    assert "two distinct public managed versions" in docs


@pytest.mark.parametrize(
    ("before", "after"),
    [
        ("contents: read", "contents: write"),
        ("runner: ubuntu-24.04-arm", "runner: ubuntu-24.04"),
        ('test "$GITHUB_REF_PROTECTED" = "true"', "true"),
        ("merge-multiple: false", "merge-multiple: true"),
        ("needs: lifecycle", "needs: []"),
        ('--workflow-attempt "$GITHUB_RUN_ATTEMPT"', "--workflow-attempt 1"),
        (
            "${{ runner.temp }}/systemd-matrix-evidence/architecture.json",
            "${{ runner.temp }}/**/*",
        ),
        (
            "permissions:\n  contents: read",
            "permissions:\n  contents: read\n\nenvironment: production-release",
        ),
        ("on:\n  workflow_dispatch:", "on:\n  push:"),
        ("subject-name: systemd-matrix-verified.json", "subject-name: variable.json"),
        (
            "subject-digest: sha256:${{ steps.subject.outputs.sha256 }}",
            "subject-digest: sha256:abcd",
        ),
        ("needs: lifecycle", "needs: [lifecycle, other]"),
        ('test "$GITHUB_WORKFLOW_REF" =', 'echo "$GITHUB_WORKFLOW_REF" ='),
        ('--base-commit "$GITHUB_SHA"', '--base-commit "stale"'),
        ("ref: ${{ github.sha }}", "ref: main"),
        ("LIFECYCLE_RESULT: ${{ needs.lifecycle.result }}", "LIFECYCLE_RESULT: success"),
        (
            "actions/attest-build-provenance@977bb373ede98d70efdf65b84cb5f73e068dcc2a",
            "actions/attest-build-provenance@v3",
        ),
        (
            "BUNDLE_PATH: ${{ steps.attest.outputs.bundle-path }}",
            "BUNDLE_PATH: verification-result.json",
        ),
    ],
)
def test_native_systemd_workflow_rejects_boundary_regressions(before: str, after: str) -> None:
    workflow = WORKFLOW.read_text()
    assert before in workflow
    # Replace all attempt/protection copies: every execution boundary must retain them.
    assert _policy_findings(workflow.replace(before, after))


@pytest.mark.parametrize(
    "override",
    [
        {},
        {"GITHUB_REPOSITORY": "fork/xferry"},
        {"GITHUB_EVENT_NAME": "push"},
        {"GITHUB_EVENT_NAME": "pull_request"},
        {"GITHUB_REF": "refs/heads/unreviewed"},
        {"GITHUB_REF": "refs/tags/v0.2.0"},
        {"GITHUB_REF_PROTECTED": "false"},
        {"RUNNER_ENVIRONMENT": "self-hosted"},
    ],
)
def test_actual_shell_boundary_rejects_other_repositories_refs_events_and_hosts(
    override: dict[str, str],
) -> None:
    environment = {
        "PATH": os.environ["PATH"],
        "GITHUB_REPOSITORY": "kgmnotes/xferry",
        "GITHUB_EVENT_NAME": "workflow_dispatch",
        "GITHUB_REF": "refs/heads/main",
        "GITHUB_REF_PROTECTED": "true",
        "RUNNER_ENVIRONMENT": "github-hosted",
    } | override
    result = subprocess.run(
        [
            "bash",
            "--noprofile",
            "--norc",
            "-c",
            _run_block(WORKFLOW.read_text(), "Require protected manual fixture boundary"),
        ],
        env=environment,
        capture_output=True,
        check=False,
    )
    assert (result.returncode == 0) is (not override)


@pytest.mark.parametrize("outcome", ["success", "failure", "skipped", "cancelled", ""])
def test_actual_aggregate_gate_cannot_accept_a_failed_or_skipped_architecture(outcome: str) -> None:
    result = subprocess.run(
        [
            "bash",
            "--noprofile",
            "--norc",
            "-c",
            _run_block(WORKFLOW.read_text(), "Require both architecture jobs to pass"),
        ],
        env={
            "PATH": os.environ["PATH"],
            "LIFECYCLE_RESULT": outcome,
            "GITHUB_REF_PROTECTED": "true",
        },
        capture_output=True,
        check=False,
    )
    assert (result.returncode == 0) is (outcome == "success")


@pytest.mark.parametrize(
    "override",
    [
        {},
        {"GITHUB_WORKFLOW_REF": "kgmnotes/xferry/.github/workflows/other.yml@refs/tags/v0.2.0"},
        {"GITHUB_REF": "refs/tags/v00.2.0"},
        {"GITHUB_REF": "refs/heads/main"},
        {"GITHUB_REPOSITORY": "fork/xferry"},
        {"GITHUB_EVENT_NAME": "pull_request"},
        {"GITHUB_REF_PROTECTED": "false"},
        {"RUNNER_ENVIRONMENT": "self-hosted"},
    ],
)
def test_native_fixture_reusable_boundary_accepts_only_the_real_protected_tag_caller(
    override: dict[str, str],
) -> None:
    environment = {
        "PATH": os.environ["PATH"],
        "GITHUB_REPOSITORY": "kgmnotes/xferry",
        "GITHUB_EVENT_NAME": "push",
        "GITHUB_REF": "refs/tags/v0.2.0",
        "GITHUB_WORKFLOW_REF": (
            "kgmnotes/xferry/.github/workflows/release-production.yml@refs/tags/v0.2.0"
        ),
        "GITHUB_REF_PROTECTED": "true",
        "RUNNER_ENVIRONMENT": "github-hosted",
    } | override
    result = subprocess.run(
        [
            "bash",
            "--noprofile",
            "--norc",
            "-c",
            _run_block(WORKFLOW.read_text(), "Require protected manual fixture boundary"),
        ],
        env=environment,
        capture_output=True,
        check=False,
    )
    assert (result.returncode == 0) is (not override)


@pytest.mark.parametrize("invalid", ["none", "source", "machine", "docker-host", "docker-context"])
def test_actual_native_source_boundary_rejects_wrong_source_architecture_or_daemon(
    tmp_path: Path,
    invalid: str,
) -> None:
    tools = tmp_path / "tools"
    tools.mkdir()
    programs = {
        "git": 'printf "%s\\n" "$ACTUAL_SOURCE"',
        "uname": 'printf "%s\\n" "$ACTUAL_MACHINE"',
        "docker": 'if [ "$1" = context ]; then printf "%s\\n" "$ACTUAL_CONTEXT"; fi',
    }
    for name, body in programs.items():
        executable = tools / name
        executable.write_text("#!/bin/sh\n" + body + "\n")
        executable.chmod(0o755)
    environment = {
        "PATH": str(tools) + os.pathsep + os.environ["PATH"],
        "GITHUB_SHA": "a" * 40,
        "MATRIX_MACHINE": "x86_64",
        "ACTUAL_SOURCE": "b" * 40 if invalid == "source" else "a" * 40,
        "ACTUAL_MACHINE": "aarch64" if invalid == "machine" else "x86_64",
        "ACTUAL_CONTEXT": "remote" if invalid == "docker-context" else "default",
        "DOCKER_HOST": "tcp://remote.example" if invalid == "docker-host" else "",
    }
    result = subprocess.run(
        [
            "bash",
            "--noprofile",
            "--norc",
            "-c",
            _run_block(WORKFLOW.read_text(), "Confirm exact native source and local Docker daemon"),
        ],
        env=environment,
        capture_output=True,
        check=False,
    )
    assert (result.returncode == 0) is (invalid == "none")
