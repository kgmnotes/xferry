"""Manual fixture matrix stays native, source-bound, secret-free and nonpublic."""

from __future__ import annotations

import os
import re
import subprocess
import textwrap
from pathlib import Path

import pytest

from xferry.management.model import SUPPORTED_MANAGED_DISTRIBUTIONS

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
    required = (
        "on:\n  workflow_dispatch:",
        "github.repository == 'kgmnotes/xferry'",
        "github.event_name == 'workflow_dispatch'",
        "github.ref == 'refs/heads/main'",
        'test "$GITHUB_REPOSITORY" = "kgmnotes/xferry"',
        'test "$GITHUB_EVENT_NAME" = "workflow_dispatch"',
        'test "$GITHUB_REF" = "refs/heads/main"',
        'test "$GITHUB_REF_PROTECTED" = "true"',
        'test "$RUNNER_ENVIRONMENT" = "github-hosted"',
        'test "$(git rev-parse HEAD)" = "$GITHUB_SHA"',
        'test "$(uname -m)" = "$MATRIX_MACHINE"',
        "runner: ubuntu-24.04-arm",
        "runner: ubuntu-24.04\n",
        "platform: linux-x86_64",
        "platform: linux-aarch64",
        "fail-fast: false",
        "persist-credentials: false",
        "ref: ${{ github.sha }}",
        "python -m pip install build pex==2.99.0 cryptography",
        "python tools/managed_update_rehearsal.py prepare",
        "python tools/managed_systemd_matrix.py run",
        "python tools/managed_systemd_matrix.py verify-matrix",
        '--source-commit "$GITHUB_SHA"',
        '--workflow-run "$GITHUB_RUN_ID"',
        '--workflow-attempt "$GITHUB_RUN_ATTEMPT"',
        "needs: lifecycle",
        'test "$LIFECYCLE_RESULT" = "success"',
        "if: ${{ always() && github.repository",
        "pattern: systemd-matrix-${{ github.run_id }}-${{ github.run_attempt }}-linux-*",
        "merge-multiple: false",
        "if-no-files-found: error",
    )
    findings = [f"missing {item}" for item in required if item not in workflow]
    for item in (
        "secrets.",
        "environment:",
        ": write",
        "workflow_call:",
        "pull_request:",
        "push:",
        "continue-on-error:",
        "setup-qemu",
    ):
        if item in workflow:
            findings.append(f"forbidden {item}")
    for action in re.findall(r"uses:\s+([^\s#]+)", workflow):
        if not re.fullmatch(r"[^@]+@[0-9a-f]{40}", action):
            findings.append("unpinned external action")
    prefix = "${{ runner.temp }}/systemd-matrix-evidence/"
    expected = {
        prefix + "architecture.json",
        *(
            prefix + f"{distro}-{version}.json"
            for distro, versions in SUPPORTED_MANAGED_DISTRIBUTIONS
            for version in versions
        ),
    }
    start = workflow.index("      - name: Preserve only sanitized lifecycle receipts\n")
    start = workflow.index("          path: |\n", start) + len("          path: |\n")
    observed = []
    for line in workflow[start:].splitlines():
        if not line.startswith("            "):
            break
        observed.append(line.strip())
    if set(observed) != expected or len(observed) != len(expected):
        findings.append("unsafe or incomplete uploaded receipt paths")
    return findings


def test_native_systemd_workflow_policy_and_publication_boundary() -> None:
    workflow = WORKFLOW.read_text()
    assert _policy_findings(workflow) == []
    production = (REPO_ROOT / ".github/workflows/release-production.yml").read_text()
    assert "Full managed ten-pair systemd evidence has not yet been verified" in production
    assert "managed-systemd-matrix.yml" not in production
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
