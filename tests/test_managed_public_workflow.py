"""Public managed evidence stays native, attested and behind exact public-version gates."""

from __future__ import annotations

import os
import subprocess
import textwrap
from pathlib import Path

import pytest

from tools import check_stale_docs

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/managed-public-matrix.yml"


def _run_block(name: str) -> str:
    text = WORKFLOW.read_text()
    start = text.index(f"      - name: {name}\n")
    start = text.index("        run: |\n", start) + len("        run: |\n")
    lines = []
    for line in text[start:].splitlines():
        if line and not line.startswith("          "):
            break
        lines.append(line)
    return textwrap.dedent("\n".join(lines))


def test_public_managed_workflow_is_reusable_and_uses_the_shared_fail_closed_policy() -> None:
    assert check_stale_docs.managed_public_workflow_policy_findings(WORKFLOW.read_text()) == []
    production = (ROOT / ".github/workflows/release-production.yml").read_text()
    assert "uses: ./.github/workflows/managed-public-matrix.yml" in production
    assert "MANAGED_RESULT: ${{ needs.post-managed.result }}" in production
    assert 'test "$MANAGED_RESULT" = success' in production


@pytest.mark.parametrize(
    ("before", "after"),
    [
        ("on:\n  workflow_call:", "on:\n  workflow_dispatch:"),
        ("permissions:\n  contents: read", "permissions:\n  contents: write"),
        ("runner: ubuntu-24.04-arm", "runner: ubuntu-24.04"),
        ('test "$GITHUB_REPOSITORY" = kgmnotes/xferry', "true"),
        ('test "$GITHUB_EVENT_NAME" = push', "true"),
        ('test "$GITHUB_REF_PROTECTED" = true', "true"),
        ('test "$RUNNER_ENVIRONMENT" = github-hosted', "true"),
        ('test "$GITHUB_REF" = "refs/tags/${TARGET_TAG}"', "true"),
        ('test "$GITHUB_SHA" = "$SOURCE_COMMIT"', "true"),
        ('test "$GITHUB_WORKFLOW_REF" =', 'echo "$GITHUB_WORKFLOW_REF" ='),
        ("ref: ${{ inputs.source_commit }}", "ref: main"),
        ("needs: plan", "needs: []"),
        ("needs: [plan, lifecycle]", "needs: [plan]"),
        ('test "$PLAN_RESULT" = success', "true"),
        ('test "$LIFECYCLE_RESULT" = success', "true"),
        ("PLAN_RESULT: ${{ needs.plan.result }}", "PLAN_RESULT: success"),
        ("LIFECYCLE_RESULT: ${{ needs.lifecycle.result }}", "LIFECYCLE_RESULT: success"),
        ("merge-multiple: false", "merge-multiple: true"),
        ('--workflow-attempt "$GITHUB_RUN_ATTEMPT"', "--workflow-attempt 1"),
        ("subject-name: managed-public-verified.json", "subject-name: directory/receipt.json"),
        (
            "subject-digest: sha256:${{ steps.subject.outputs.sha256 }}",
            "subject-digest: sha256:abcd",
        ),
        (
            "actions/attest-build-provenance@977bb373ede98d70efdf65b84cb5f73e068dcc2a",
            "actions/attest-build-provenance@v3",
        ),
        (
            "BUNDLE_PATH: ${{ steps.attest.outputs.bundle-path }}",
            "BUNDLE_PATH: verification-result.json",
        ),
        (
            "${{ runner.temp }}/managed-public-evidence/architecture.json",
            "${{ runner.temp }}/**/*",
        ),
        (
            "python tools/production_readiness.py verify-public",
            "echo 'trust the exported verification result'",
        ),
        ("python tools/managed_public_matrix.py prepare", "echo use-staging-fixtures"),
        ("if-no-files-found: error", "if-no-files-found: ignore"),
    ],
)
def test_public_managed_workflow_rejects_boundary_regressions(before: str, after: str) -> None:
    text = WORKFLOW.read_text()
    assert before in text
    assert check_stale_docs.managed_public_workflow_policy_findings(text.replace(before, after))


@pytest.mark.parametrize(
    "extra",
    [
        '      - run: echo "${{ secrets.STATIC_TOKEN }}"\n',
        "    environment: production-release\n",
        "    continue-on-error: true\n",
        "      - run: docker push unapproved/image\n",
        "      - run: gh release create v0.2.0\n",
    ],
)
def test_public_evidence_never_consumes_secrets_or_publishes(extra: str) -> None:
    assert check_stale_docs.managed_public_workflow_policy_findings(WORKFLOW.read_text() + extra)


@pytest.mark.parametrize("job_name", ["plan", "lifecycle"])
def test_only_the_public_collector_may_request_oidc_attestation_writes(job_name: str) -> None:
    text = WORKFLOW.read_text()
    job = next(job for job in check_stale_docs._workflow_jobs(text) if job.name == job_name)
    changed = job.text.replace("contents: read", "contents: read\n      id-token: write", 1)
    assert check_stale_docs.managed_public_workflow_policy_findings(text.replace(job.text, changed))


@pytest.mark.parametrize(
    "override",
    [
        {},
        {"GITHUB_REPOSITORY": "fork/xferry"},
        {"GITHUB_EVENT_NAME": "workflow_dispatch"},
        {"GITHUB_EVENT_NAME": "pull_request"},
        {"GITHUB_REF_PROTECTED": "false"},
        {"RUNNER_ENVIRONMENT": "self-hosted"},
        {"TARGET_TAG": "v00.2.0"},
        {"TARGET_TAG": "v0.2.0-rc1"},
        {"GITHUB_REF": "refs/heads/main"},
        {"GITHUB_REF": "refs/tags/v0.2.1"},
        {"GITHUB_SHA": "b" * 40},
        {"SOURCE_COMMIT": "b" * 40},
        {"GITHUB_WORKFLOW_REF": "kgmnotes/xferry/.github/workflows/other.yml@refs/tags/v0.2.0"},
    ],
)
def test_actual_public_plan_shell_requires_the_protected_exact_source_tag_caller(
    override: dict[str, str],
) -> None:
    environment = {
        "PATH": os.environ["PATH"],
        "GITHUB_REPOSITORY": "kgmnotes/xferry",
        "GITHUB_EVENT_NAME": "push",
        "GITHUB_REF_PROTECTED": "true",
        "RUNNER_ENVIRONMENT": "github-hosted",
        "TARGET_TAG": "v0.2.0",
        "GITHUB_REF": "refs/tags/v0.2.0",
        "GITHUB_SHA": "a" * 40,
        "SOURCE_COMMIT": "a" * 40,
        "GITHUB_WORKFLOW_REF": (
            "kgmnotes/xferry/.github/workflows/release-production.yml@refs/tags/v0.2.0"
        ),
    } | override
    result = subprocess.run(
        [
            "bash",
            "--noprofile",
            "--norc",
            "-c",
            _run_block("Require the protected production caller"),
        ],
        env=environment,
        capture_output=True,
        check=False,
    )
    assert (result.returncode == 0) is (not override)


@pytest.mark.parametrize(
    "invalid",
    ["none", "source", "github-source", "machine", "docker-host", "docker-context", "runner"],
)
def test_actual_public_lifecycle_shell_requires_native_exact_source_and_local_daemon(
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
        "GITHUB_REF_PROTECTED": "true",
        "RUNNER_ENVIRONMENT": "self-hosted" if invalid == "runner" else "github-hosted",
        "GITHUB_SHA": "b" * 40 if invalid == "github-source" else "a" * 40,
        "SOURCE_COMMIT": "a" * 40,
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
            _run_block("Require exact native hosted source and local Docker"),
        ],
        env=environment,
        capture_output=True,
        check=False,
    )
    assert (result.returncode == 0) is (invalid == "none")


@pytest.mark.parametrize("variable", ["PLAN_RESULT", "LIFECYCLE_RESULT"])
@pytest.mark.parametrize("outcome", ["success", "failure", "skipped", "cancelled", ""])
def test_actual_public_collector_rejects_failed_or_skipped_plan_and_native_architectures(
    variable: str,
    outcome: str,
) -> None:
    environment = {
        "PATH": os.environ["PATH"],
        "PLAN_RESULT": "success",
        "LIFECYCLE_RESULT": "success",
        "GITHUB_REF_PROTECTED": "true",
        "RUNNER_ENVIRONMENT": "github-hosted",
        variable: outcome,
    }
    result = subprocess.run(
        [
            "bash",
            "--noprofile",
            "--norc",
            "-c",
            _run_block("Require both native public architecture jobs to succeed"),
        ],
        env=environment,
        capture_output=True,
        check=False,
    )
    assert (result.returncode == 0) is (outcome == "success")
