"""Production release workflow stays tag-only, immutable, and fail closed."""

from __future__ import annotations

import re
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
        "gh release create",
        "--draft --latest=false --verify-tag",
        "skopeo copy --all --preserve-digests",
        "--notes-file final-release-notes.md",
        "preliminary immutable notes differ from existing draft body",
        "final immutable notes differ from public Release body",
        "https://pypi.org/pypi/xferry/${RELEASE_VERSION}/json",
        "ghcr.io/kgmnotes/xferry@${GHCR_DIGEST}",
        "https://github.com/kgmnotes/xferry/releases/download/${RELEASE_TAG}/",
        "Full managed ten-pair systemd evidence is not available on hosted runners",
        "main merge and Pages deployment remain forbidden until all post-publish evidence passes",
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
    return findings


def test_production_workflow_has_fail_closed_boundaries() -> None:
    workflow = PRODUCTION_WORKFLOW.read_text(encoding="utf-8")
    assert production_policy_findings(workflow) == []

    assert "needs: [preflight, prepare-candidate, create-draft-release]" in _job(
        workflow, "publish-pypi"
    )
    assert "needs: [preflight, sign-assets]" in _job(workflow, "create-draft-release")
    assert "needs: [preflight, prepare-candidate, publish-pypi]" in _job(workflow, "publish-ghcr")
    public = _job(workflow, "publish-github-release")
    assert (
        "needs: [preflight, prepare-candidate, sign-assets, create-draft-release, publish-ghcr]"
        in public
    )
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
        ("--draft --latest=false --verify-tag", "--latest"),
        (
            "final immutable notes differ from public Release body",
            "public body is not checked",
        ),
        (
            "Full managed ten-pair systemd evidence is not available on hosted runners",
            "Hosted runners prove all managed targets",
        ),
    ],
)
def test_production_policy_rejects_release_boundary_regressions(before: str, after: str) -> None:
    workflow = PRODUCTION_WORKFLOW.read_text(encoding="utf-8")
    assert production_policy_findings(workflow) == []
    assert before in workflow
    assert production_policy_findings(workflow.replace(before, after, 1))
