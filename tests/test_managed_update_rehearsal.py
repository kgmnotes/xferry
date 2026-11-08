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


def test_native_fixture_pair_matches_the_deployment_compatibility_floor() -> None:
    from tools import managed_systemd_matrix, managed_systemd_probe, managed_update_rehearsal
    from xferry.management.versions import MIN_DEPLOYMENT_RELEASE, compare_release_versions

    versions = managed_update_rehearsal.REHEARSAL_VERSIONS
    assert versions == (managed_systemd_probe.SOURCE_VERSION, managed_systemd_probe.TARGET_VERSION)
    assert versions == managed_systemd_matrix.VERSIONS
    assert compare_release_versions(versions[0], MIN_DEPLOYMENT_RELEASE) >= 0
    assert compare_release_versions(versions[1], versions[0]) > 0


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
        version="0.5.0",
        public_key_hex="ab" * 32,
        release_base_url="https://127.0.0.1:44443/releases",
    )

    assert '__version__ = "0.5.0"' in source.joinpath("xferry/config.py").read_text()
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
        ("rehearsal", 'TARGET_VERSION: "0.5.1"', 'TARGET_VERSION: "0.1.3"'),
        (
            "rehearsal",
            "MANAGED_XFERRY: /usr/local/bin/xferry",
            "MANAGED_XFERRY: xferry",
        ),
        (
            "rehearsal",
            'test "$("$MANAGED_XFERRY" --version)" = "xferry 0.5.0"',
            'test "$(xferry --version)" = "xferry 0.5.0"',
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


def test_managed_update_rehearsal_policy_requires_protected_parents_on_disposable_runner() -> None:
    from tools.check_stale_docs import managed_update_rehearsal_policy_findings

    rehearsal = REHEARSAL_WORKFLOW.read_text(encoding="utf-8")
    release = RELEASE_WORKFLOW.read_text(encoding="utf-8")
    normalization = """      - name: Normalize disposable runner managed parents
        run: |
          set -euo pipefail
          test "$RUNNER_ENVIRONMENT" = "github-hosted"
          test "$(sudo stat -c '%u' /opt)" = "0"
          sudo chmod 0755 /opt
          test "$(sudo stat -c '%u:%a' /opt)" = "0:755"
          test "$(sudo stat -c '%u' /usr/local/bin)" = "0"
          sudo chmod 0755 /usr/local/bin
          test "$(sudo stat -c '%u:%a' /usr/local/bin)" = "0:755"

"""
    if normalization not in rehearsal:
        rehearsal = rehearsal.replace(
            "      - name: Install signed 0.5.0\n",
            normalization + "      - name: Install signed 0.5.0\n",
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

    cli_chmod = "          sudo chmod 0755 /usr/local/bin\n"
    assert cli_chmod in rehearsal
    split_normalization = rehearsal.replace(cli_chmod, "", 1).replace(
        "      - name: Setup private managed service\n",
        "      - name: Deferred CLI parent normalization\n"
        "        run: |\n" + cli_chmod + "\n      - name: Setup private managed service\n",
        1,
    )
    findings = managed_update_rehearsal_policy_findings(split_normalization, release)
    assert findings


def test_managed_update_rehearsal_runs_the_complete_lifecycle_in_order() -> None:
    workflow = REHEARSAL_WORKFLOW.read_text(encoding="utf-8")
    steps = (
        "Install signed 0.5.0",
        "Setup private managed service",
        "Dry-run signed update to 0.5.1",
        "Apply signed update to 0.5.1",
        "Verify exact 0.5.1 health",
        "Rollback to retained 0.5.0",
        "Conservative uninstall",
    )

    positions = [workflow.index(step) for step in steps]
    assert positions == sorted(positions)
    assert "--purge-data" not in workflow
    assert '"$MANAGED_XFERRY" uninstall --json' in workflow
    assert '--phase uninstall --result "$result"' in workflow


def test_managed_update_rehearsal_reports_only_allowlisted_setup_failure_fields() -> None:
    """A failed native setup must be diagnosable without printing credentials stderr."""
    workflow = REHEARSAL_WORKFLOW.read_text(encoding="utf-8")

    assert "setup_exit=0" in workflow
    assert 'setup_exit="$?"' in workflow
    assert 'expected = {"exit_code", "message", "details", "url", "plan", "state"}' in workflow
    assert (
        'print(json.dumps({"phase": "setup", "exit_code": result["exit_code"]}), file=sys.stderr)'
        in workflow
    )
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
    release = release_root / "releases/0.5.0"
    release.mkdir(parents=True)
    for directory in (
        root,
        root / "opt",
        release_root,
        release_root / "releases",
        release,
    ):
        directory.chmod(0o755)
    executable = release / "xferry"
    executable_payload = b"diagnostic-release"
    executable.write_bytes(executable_payload)
    executable.chmod(0o755)
    release.joinpath("xferry-release.json").write_bytes(
        ReleaseManifest.create_v2(
            version="0.5.0",
            platform=current_platform_id(),
            executable_size=len(executable_payload),
            executable_sha256=hashlib.sha256(executable_payload).hexdigest(),
            source_commit="a" * 40,
            workflow_run="123456",
        ).to_bytes()
    )
    release_root.joinpath("current").symlink_to("releases/0.5.0")
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
    descriptor_directory = Path("/proc/self/fd")
    descriptor_count_before = (
        len(tuple(descriptor_directory.iterdir())) if descriptor_directory.is_dir() else None
    )
    exec(compile(diagnostic, str(REHEARSAL_WORKFLOW), "exec"), {})
    if descriptor_count_before is not None:
        assert len(tuple(descriptor_directory.iterdir())) == descriptor_count_before

    evidence = json.loads(capsys.readouterr().out)
    owned_entry_checks = evidence["owned_entry_checks"]
    assert set(owned_entry_checks) == {
        "auth_file",
        "cli_link",
        "config_file",
        "data_root",
        "unit_file",
    }
    assert all(
        set(checks) == {"descriptor_close_ok", "inspection_ok", "witness_valid"}
        and all(isinstance(value, bool) for value in checks.values())
        for checks in owned_entry_checks.values()
    )
    assert all(all(checks.values()) for checks in owned_entry_checks.values()), owned_entry_checks
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


def test_managed_update_apply_failure_diagnostic_is_sanitized_and_executable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Failed apply evidence must identify recovery state without logging details."""
    import sys

    sensitive = "must-not-appear"
    result_path = tmp_path / "update-apply.json"
    result_path.write_text(
        json.dumps(
            {
                "exit_code": 6,
                "message": sensitive,
                "details": {"code": "candidate_unhealthy", "detail": sensitive},
                "url": None,
                "plan": None,
                "state": {"detail": sensitive},
            }
        ),
        encoding="utf-8",
    )

    workflow = REHEARSAL_WORKFLOW.read_text(encoding="utf-8")
    failure_marker = '          if [ "$apply_exit" -ne 0 ]; then\n'
    failure_section = workflow.split(failure_marker, 1)[1]
    python_marker = "            python - \"$result\" <<'PY'\n"
    diagnostic = failure_section.split(python_marker, 1)[1].split("\n          PY", 1)[0]
    diagnostic = "\n".join(line[10:] for line in diagnostic.splitlines())
    monkeypatch.setattr(sys, "argv", ["apply-diagnostic", str(result_path)])

    exec(compile(diagnostic, str(REHEARSAL_WORKFLOW), "exec"), {})

    output = capsys.readouterr().out
    assert sensitive not in output
    assert json.loads(output) == {"phase": "update", "exit_code": 6}


def test_repository_guard_includes_managed_update_rehearsal() -> None:
    from tools.check_stale_docs import find_release_policy_issues

    assert find_release_policy_issues(REPO_ROOT) == []


@pytest.fixture
def outcome_fixtures(tmp_path: Path):
    """Host-generated public fixture records; no real network/systemd evidence."""
    from xferry.management.release_contract import ReleaseManifest

    root = tmp_path / "fixtures"
    evidence_path = tmp_path / "fixtures.json"
    document = {"platform": "linux-x86_64", "versions": {}}
    for version, commit in (("0.5.0", "a" * 40), ("0.5.1", "b" * 40)):
        folder = root / "releases" / "download" / ("v" + version)
        folder.mkdir(parents=True)
        name = "xferry-release-linux-x86_64.json"
        executable = b"fixture executable " + version.encode()
        payload = ReleaseManifest.create_v2(
            version=version,
            platform="linux-x86_64",
            executable_size=len(executable),
            executable_sha256=hashlib.sha256(executable).hexdigest(),
            source_commit=commit,
            workflow_run="123",
            signing_key_ids=["xferry-rehearsal-2026-10"],
        ).to_bytes()
        records = {}
        for asset, body in ((name, payload), (name + ".sig", b"host-generated fixture signature")):
            (folder / asset).write_bytes(body)
            records[asset] = {"size": len(body), "sha256": hashlib.sha256(body).hexdigest()}
        document["versions"][version] = {
            "version": version,
            "fixture_commit": commit,
            "assets": records,
        }
    evidence_path.write_text(json.dumps(document))
    return root, evidence_path


@pytest.mark.parametrize(
    ("phase", "version", "modern"),
    [
        ("setup", "0.5.0", False),
        ("dry_run", "0.5.0", False),
        ("update", "0.5.1", True),
        ("rollback", "0.5.0", True),
    ],
)
def test_verify_outcome_binds_each_phase_to_explicit_fixture_input(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, outcome_fixtures, phase, version, modern
):
    from tools import managed_systemd_probe as probe
    from tools import managed_update_rehearsal as rehearsal

    root, evidence = outcome_fixtures
    result = tmp_path / "result.json"
    setup = tmp_path / "setup.json"
    result.write_text("{}")
    setup.write_text("{}")
    calls = []
    monkeypatch.setattr(probe, "_setup_outcome", lambda *_args, **_kwargs: "unit-instance")
    monkeypatch.setattr(probe, "_operation_outcome", lambda *_args: None)
    monkeypatch.setattr(probe, "_release_outcome", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        probe, "_deployment_identity", lambda *args, **kwargs: calls.append((args, kwargs))
    )
    rehearsal.verify_outcome(phase, result, setup, fixtures_root=root, fixture_evidence=evidence)
    assert len(calls) == 1
    args, kwargs = calls[0]
    assert args == (probe.SYSTEM_PATHS, version, "unit-instance")
    expected = {
        "version": version,
        "sha256": hashlib.sha256(b"fixture executable " + version.encode()).hexdigest(),
    }
    if modern:
        expected.update(channel="stable", source_commit=("b" if version == "0.5.1" else "a") * 40)
    assert kwargs == {"expected_artifact": expected}


@pytest.mark.parametrize("mutation", ["source", "manifest", "signature", "version", "digest"])
def test_verify_outcome_reference_is_bound_to_prepared_fixture_inventory(
    outcome_fixtures, mutation
):
    from tools import managed_systemd_probe as probe
    from tools import managed_update_rehearsal as rehearsal

    root, evidence = outcome_fixtures
    document = json.loads(evidence.read_text())
    metadata = document["versions"]["0.5.1"]
    if mutation == "source":
        metadata["fixture_commit"] = "c" * 40
    elif mutation == "version":
        metadata["version"] = "0.5.0"
    elif mutation == "digest":
        metadata["assets"]["xferry-release-linux-x86_64.json"]["sha256"] = "0" * 64
    else:
        name = "xferry-release-linux-x86_64.json" + (".sig" if mutation == "signature" else "")
        with (root / "releases/download/v0.5.1" / name).open("ab") as stream:
            stream.write(b"tampered")
    evidence.write_text(json.dumps(document))
    with pytest.raises(probe.ProbeFailure, match="fixture_layout_invalid"):
        rehearsal._expected_fixture_artifact(root, evidence, "0.5.1", release_metadata=True)


def test_verify_outcome_requires_explicit_fixture_inputs_in_cli_and_workflow(tmp_path):
    from tools.managed_update_rehearsal import _parser

    arguments = [
        "verify-outcome",
        "--phase",
        "setup",
        "--result",
        str(tmp_path / "result.json"),
        "--setup-result",
        str(tmp_path / "setup.json"),
    ]
    with pytest.raises(SystemExit):
        _parser().parse_args(arguments)
    parsed = _parser().parse_args(
        arguments
        + [
            "--fixtures-root",
            str(tmp_path / "fixtures"),
            "--fixture-evidence",
            str(tmp_path / "fixtures.json"),
        ]
    )
    assert parsed.fixtures_root == tmp_path / "fixtures"
    assert parsed.fixture_evidence == tmp_path / "fixtures.json"
    workflow = REHEARSAL_WORKFLOW.read_text()
    assert workflow.count("tools/managed_update_rehearsal.py verify-outcome \\\n") == 6
    assert workflow.count('--fixtures-root "$RUNNER_TEMP/managed-update-fixtures" \\\n') == 6
    assert (
        workflow.count(
            '--fixture-evidence "$RUNNER_TEMP/managed-update-evidence/fixtures.json" \\\n'
        )
        == 6
    )
