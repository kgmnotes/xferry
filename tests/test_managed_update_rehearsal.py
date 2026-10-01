"""Artifact-only native managed-update rehearsal contracts."""

from __future__ import annotations

import hashlib
import json
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


def test_managed_update_rehearsal_policy_requires_protected_opt_on_disposable_runner() -> None:
    from tools.check_stale_docs import managed_update_rehearsal_policy_findings

    rehearsal = REHEARSAL_WORKFLOW.read_text(encoding="utf-8")
    release = RELEASE_WORKFLOW.read_text(encoding="utf-8")
    normalization = """      - name: Normalize disposable runner managed parent
        run: |
          set -euo pipefail
          test "$RUNNER_ENVIRONMENT" = "github-hosted"
          test "$(sudo stat -c '%u' /opt)" = "0"
          sudo chmod 0755 /opt
          test "$(sudo stat -c '%u:%a' /opt)" = "0:755"

"""
    if normalization not in rehearsal:
        rehearsal = rehearsal.replace(
            "      - name: Install signed 0.1.1\n",
            normalization + "      - name: Install signed 0.1.1\n",
        )

    assert managed_update_rehearsal_policy_findings(rehearsal, release) == []
    findings = managed_update_rehearsal_policy_findings(
        rehearsal.replace(normalization, "", 1),
        release,
    )
    assert findings

    moved_after_install = rehearsal.replace(normalization, "", 1).replace(
        "      - name: Setup private managed service\n",
        normalization + "      - name: Setup private managed service\n",
        1,
    )
    findings = managed_update_rehearsal_policy_findings(moved_after_install, release)
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


def test_managed_update_rehearsal_reports_only_allowlisted_setup_failure_fields() -> None:
    """A failed native setup must be diagnosable without printing credentials stderr."""
    workflow = REHEARSAL_WORKFLOW.read_text(encoding="utf-8")

    assert "setup_exit=0" in workflow
    assert 'setup_exit="$?"' in workflow
    assert (
        'allowed = {"code", "detail", "exit_code", "message", "next_actions", "status"}' in workflow
    )
    assert "unexpected = set(result) - allowed" in workflow
    assert "print(json.dumps(result, sort_keys=True), file=sys.stderr)" in workflow
    assert '"release_state": release_state.value' in workflow
    assert '"owned_state_safe": owned_state_safe' in workflow
    assert '"manifest_valid": manifest_valid' in workflow
    assert '"executable_sha256_valid": executable_sha256_valid' in workflow
    assert '"release_permissions_valid": release_permissions_valid' in workflow
    assert 'cat "$setup_credentials"' not in workflow


def test_managed_update_release_diagnostic_executes_with_fixed_boolean_schema(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The hosted failure diagnostic must execute without exposing raw metadata."""
    from xferry.management import model
    from xferry.management.model import ManagedLayout
    from xferry.management.release_contract import ReleaseManifest, current_platform_id

    root = tmp_path / "host"
    release_root = root / "opt/xferry"
    release = release_root / "releases/0.1.1"
    release.mkdir(parents=True)
    executable = release / "xferry"
    executable_payload = b"diagnostic-release"
    executable.write_bytes(executable_payload)
    executable.chmod(0o755)
    release.joinpath("xferry-release.json").write_bytes(
        ReleaseManifest.create_v2(
            version="0.1.1",
            platform=current_platform_id(),
            executable_size=len(executable_payload),
            executable_sha256=hashlib.sha256(executable_payload).hexdigest(),
            source_commit="a" * 40,
            workflow_run="123456",
        ).to_bytes()
    )
    release_root.joinpath("current").symlink_to("releases/0.1.1")
    layout = ManagedLayout(
        release_root=release_root,
        config_file=root / "etc/xferry/xferry.ini",
        auth_file=root / "etc/xferry/auth",
        data_root=root / "var/lib/xferry",
        lock_file=root / "run/lock/xferry-ops.lock",
        unit_file=root / "etc/systemd/system/xferry.service",
        cli_link=root / "usr/local/bin/xferry",
    )
    monkeypatch.setattr(model, "ManagedLayout", lambda: layout)

    workflow = REHEARSAL_WORKFLOW.read_text(encoding="utf-8")
    marker = "            sudo \"$python_bin\" - <<'PY'\n"
    diagnostic = workflow.split(marker, 1)[1].split("\n          PY", 1)[0]
    diagnostic = "\n".join(line[10:] for line in diagnostic.splitlines())
    exec(compile(diagnostic, str(REHEARSAL_WORKFLOW), "exec"), {})

    evidence = json.loads(capsys.readouterr().out)
    permission_checks = evidence["release_checks"]["permission_checks"]
    assert set(permission_checks) == {
        "executable",
        "manifest",
        "opt",
        "release",
        "release_root",
        "releases_root",
        "root",
    }
    assert all(
        set(checks) == {"mode_valid", "owner_valid"}
        and all(isinstance(value, bool) for value in checks.values())
        for checks in permission_checks.values()
    )


def test_repository_guard_includes_managed_update_rehearsal() -> None:
    from tools.check_stale_docs import find_release_policy_issues

    assert find_release_policy_issues(REPO_ROOT) == []
