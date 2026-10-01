"""Artifact-only native managed-update rehearsal contracts."""

from __future__ import annotations

from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
REHEARSAL_WORKFLOW = REPO_ROOT / ".github/workflows/managed-update-rehearsal.yml"
RELEASE_WORKFLOW = REPO_ROOT / ".github/workflows/release.yml"
REHEARSAL_TOOL = REPO_ROOT / "tools/managed_update_rehearsal.py"


def test_fixture_patch_changes_only_the_ephemeral_source_contract(tmp_path: Path) -> None:
    """A rehearsal copy must use its own version, URL, and public trust root."""
    assert REHEARSAL_TOOL.is_file()
    from tools.managed_update_rehearsal import REHEARSAL_KEY_ID, patch_fixture_source

    source = tmp_path / "source"
    for relative in (
        Path("xferry/config.py"),
        Path("xferry/management/release_trust.py"),
        Path("xferry/management/releases.py"),
    ):
        target = source / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((REPO_ROOT / relative).read_bytes())

    patch_fixture_source(
        source,
        version="0.1.1",
        public_key_hex="ab" * 32,
        release_base_url="https://127.0.0.1:44443/releases",
    )

    assert '__version__ = "0.1.1"' in source.joinpath("xferry/config.py").read_text()
    trust = source.joinpath("xferry/management/release_trust.py").read_text()
    assert f'key_id="{REHEARSAL_KEY_ID}"' in trust
    assert 'public_key=bytes.fromhex("' + "ab" * 32 + '")' in trust
    assert 'key_id="xferry-release-2026-09"' not in trust
    releases = source.joinpath("xferry/management/releases.py").read_text()
    assert 'release_base_url: str = "https://127.0.0.1:44443/releases"' in releases

    production_trust = REPO_ROOT.joinpath("xferry/management/release_trust.py").read_text()
    assert 'key_id="xferry-release-2026-09"' in production_trust
    assert REHEARSAL_KEY_ID not in production_trust


def test_rehearsal_public_key_evidence_never_serializes_private_material() -> None:
    """Only a public fingerprint may leave the in-memory release signer."""
    assert REHEARSAL_TOOL.is_file()
    from tools.managed_update_rehearsal import public_key_evidence

    evidence = public_key_evidence(bytes.fromhex("01" * 32))

    assert set(evidence) == {"key_id", "public_key_sha256"}
    assert len(evidence["public_key_sha256"]) == 64
    assert "private" not in repr(evidence).casefold()


def test_managed_update_rehearsal_policy_is_registered_and_clean() -> None:
    assert REHEARSAL_WORKFLOW.is_file()
    from tools.check_stale_docs import managed_update_rehearsal_policy_findings

    rehearsal = REHEARSAL_WORKFLOW.read_text(encoding="utf-8")
    release = RELEASE_WORKFLOW.read_text(encoding="utf-8")

    assert managed_update_rehearsal_policy_findings(rehearsal, release) == []


@pytest.mark.parametrize(
    ("target", "before", "after"),
    [
        (
            "rehearsal",
            "refs/heads/codex/stage-013-managed-update-rehearsal",
            "refs/heads/main",
        ),
        ("rehearsal", "runner: ubuntu-24.04-arm", "runner: ubuntu-24.04"),
        ("rehearsal", "contents: read", "contents: write"),
        (
            "rehearsal",
            "    permissions:\n      contents: read",
            "    environment: production-release\n    permissions:\n      contents: read",
        ),
        ("rehearsal", 'TARGET_VERSION: "0.1.2"', 'TARGET_VERSION: "0.1.3"'),
        (
            "rehearsal",
            "MANAGED_XFERRY: /usr/local/bin/xferry",
            "MANAGED_XFERRY: xferry",
        ),
        (
            "rehearsal",
            'test "$("$MANAGED_XFERRY" --version)" = "xferry 0.1.1"',
            'test "$(xferry --version)" = "xferry 0.1.1"',
        ),
        (
            "rehearsal",
            "permissions:\n  contents: read",
            "permissions:\n  contents: read\n\nenv:\n  LEAK: ${{ secrets.REHEARSAL_KEY }}",
        ),
        (
            "release",
            "if: ${{ !inputs.managed_update_rehearsal }}",
            "if: ${{ always() }}",
        ),
    ],
)
def test_managed_update_rehearsal_policy_rejects_boundary_regressions(
    target: str,
    before: str,
    after: str,
) -> None:
    from tools.check_stale_docs import managed_update_rehearsal_policy_findings

    rehearsal = REHEARSAL_WORKFLOW.read_text(encoding="utf-8")
    release = RELEASE_WORKFLOW.read_text(encoding="utf-8")
    selected = rehearsal if target == "rehearsal" else release
    assert before in selected
    mutated = selected.replace(before, after, 1)

    findings = managed_update_rehearsal_policy_findings(
        mutated if target == "rehearsal" else rehearsal,
        mutated if target == "release" else release,
    )

    assert findings


def test_managed_update_rehearsal_runs_the_complete_lifecycle_in_order() -> None:
    workflow = REHEARSAL_WORKFLOW.read_text(encoding="utf-8")
    steps = (
        "Install signed 0.1.1",
        "Setup private managed service",
        "Dry-run signed update to 0.1.2",
        "Apply signed update to 0.1.2",
        "Verify exact 0.1.2 health",
        "Rollback to retained 0.1.1",
        "Conservative uninstall",
    )

    positions = [workflow.index(step) for step in steps]
    assert positions == sorted(positions)
    assert "--purge-data" not in workflow
    assert '"$MANAGED_XFERRY" uninstall --json' in workflow
    assert 'result["code"] == "uninstall_complete"' in workflow


def test_repository_guard_includes_managed_update_rehearsal() -> None:
    from tools.check_stale_docs import find_release_policy_issues

    assert find_release_policy_issues(REPO_ROOT) == []
