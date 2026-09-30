"""TestPyPI promotion rejects identity substitution and index fallback."""

from __future__ import annotations

import copy
import hashlib
import json
import shlex
from pathlib import Path

import pytest

from tools import testpypi_publish as publisher
from tools.check_stale_docs import testpypi_workflow_policy_findings as staging_policy_findings

REPO_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def identity() -> dict:
    return json.loads((REPO_ROOT / "packaging/testpypi-candidate.json").read_text())


def metadata(identity: dict) -> tuple[dict, dict]:
    artifact = {
        "id": identity["artifact_id"],
        "name": identity["artifact_name"],
        "digest": "sha256:" + identity["artifact_sha256"],
        "expired": False,
        "size_in_bytes": identity["artifact_size"],
        "workflow_run": {
            "id": identity["workflow_run"],
            "head_sha": identity["source_commit"],
            "repository_id": identity["repository_id"],
        },
    }
    run = {
        "id": identity["workflow_run"],
        "run_attempt": 1,
        "head_sha": identity["source_commit"],
        "event": "workflow_dispatch",
        "path": ".github/workflows/release.yml",
        "status": "completed",
        "conclusion": "success",
        "repository": {"id": identity["repository_id"], "full_name": identity["repository"]},
    }
    return artifact, run


@pytest.mark.parametrize(
    ("document", "field", "value"),
    [
        (0, "id", 1),
        (0, "name", "release-candidate-other"),
        (0, "digest", "sha256:" + "a" * 64),
        (0, "expired", True),
        (0, "size_in_bytes", 1),
        (1, "head_sha", "a" * 40),
        (1, "conclusion", "failure"),
        (1, "event", "pull_request"),
        (1, "run_attempt", 2),
        (1, "path", ".github/workflows/ci.yml"),
    ],
)
def test_api_identity_substitution_is_rejected(identity, document, field, value):
    documents = metadata(identity)
    publisher.verify_api_identity(identity, *documents)
    documents[document][field] = value
    with pytest.raises(ValueError, match="identity"):
        publisher.verify_api_identity(identity, *documents)


def index_document(identity: dict) -> dict:
    return {
        "info": {"name": "xferry", "version": "0.1.0"},
        "urls": [
            {
                "filename": name,
                "digests": {"sha256": record["sha256"]},
                "size": record["size"],
                "yanked": False,
                "url": "https://test-files.pythonhosted.org/packages/" + name,
            }
            for name, record in identity["distributions"].items()
        ],
    }


@pytest.mark.parametrize(
    "mutation", ["hash", "missing", "duplicate", "extra", "host", "yank", "version"]
)
def test_remote_identity_failures_stop_before_install(identity, mutation):
    document = index_document(identity)
    publisher.verify_index_identity(identity, document)
    if mutation == "hash":
        document["urls"][0]["digests"]["sha256"] = "a" * 64
    elif mutation == "missing":
        document["urls"].pop()
    elif mutation == "duplicate":
        document["urls"].append(copy.deepcopy(document["urls"][0]))
    elif mutation == "extra":
        extra = copy.deepcopy(document["urls"][0])
        extra["filename"] = "xferry-0.1.0-extra.whl"
        document["urls"].append(extra)
    elif mutation == "host":
        document["urls"][0]["url"] = "https://files.pythonhosted.org/production.whl"
    elif mutation == "yank":
        document["urls"][0]["yanked"] = True
    else:
        document["info"]["version"] = "0.1.1"
    with pytest.raises(ValueError):
        publisher.verify_index_identity(identity, document)


def test_remote_downloaded_bytes_are_independently_verified(tmp_path, identity, monkeypatch):
    identity = copy.deepcopy(identity)
    for record in identity["distributions"].values():
        record.update(sha256=hashlib.sha256(b"expected").hexdigest(), size=8)
    document = index_document(identity)
    monkeypatch.setattr(publisher, "fetch_bytes", lambda url, limit: b"modified")
    with pytest.raises(ValueError, match="bytes"):
        publisher.download_distributions(identity, document, tmp_path / "downloads")


def test_pipx_install_uses_verified_file_and_one_dependency_index(tmp_path):
    command = publisher.pipx_install_command(tmp_path / "xferry-0.1.0-py3-none-any.whl")
    assert command[-1] == str(tmp_path / "xferry-0.1.0-py3-none-any.whl")
    args = command[command.index("--pip-args") + 1]
    assert "--index-url https://pypi.org/simple/" in args
    assert "--extra-index-url" not in args
    assert "test.pypi.org" not in args
    assert "--only-binary=:all:" in args


def test_pipx_environment_discards_ambient_indexes(tmp_path, monkeypatch):
    monkeypatch.setenv("PIP_EXTRA_INDEX_URL", "https://untrusted.invalid/simple")
    monkeypatch.setenv("PYTHONPATH", "/checkout")
    monkeypatch.setenv("PIPX_HOME", "/existing-pipx")
    environment = publisher.pipx_environment(tmp_path)
    assert "PIP_EXTRA_INDEX_URL" not in environment
    assert "PYTHONPATH" not in environment
    assert environment["PIPX_HOME"] == str(tmp_path / "pipx")
    assert environment["PIP_CONFIG_FILE"] != ""


def test_windows_pipx_argument_parser_needs_no_drive_path_quoting():
    command = publisher.pipx_install_command(Path("D:/User Name/xferry-0.1.0-py3-none-any.whl"))
    args = command[command.index("--pip-args") + 1]
    assert shlex.split(args, posix=False) == shlex.split(args, posix=True)
    assert "--constraint" not in args


def test_pipx_constraints_survive_cwd_changes_and_spaces(tmp_path, monkeypatch):
    constraints = tmp_path / "User Name" / "ci.txt"
    constraints.parent.mkdir()
    constraints.write_text("cryptography==50.0.0\n")
    captured = []
    monkeypatch.setattr(
        publisher, "_run_checked", lambda command, **kw: captured.append((command, kw))
    )
    monkeypatch.setattr(publisher, "_probe_installed_artifact", lambda **kw: None)
    monkeypatch.setattr(publisher, "_server_lifecycle_smoke", lambda **kw: None)
    publisher.pipx_smoke(tmp_path / "wheel.whl", tmp_path / "fresh", REPO_ROOT, constraints)
    environment = captured[0][1]["env"]
    assert Path(environment["PIP_CONSTRAINT"]).is_absolute()
    assert Path(environment["PIP_CONSTRAINT"]).read_text() == constraints.read_text()
    assert captured[0][1]["cwd"] != constraints.parent


def test_prepare_does_not_write_before_archive_identity_verifies(tmp_path, identity):
    archive = tmp_path / "release-candidate.tar"
    archive.write_bytes(b"substituted")
    with pytest.raises(ValueError, match="SHA256"):
        publisher.prepare_distributions(
            identity, archive, tmp_path / "candidate", tmp_path / "dist"
        )
    assert not (tmp_path / "dist").exists()
    assert not (tmp_path / "candidate").exists()


@pytest.mark.parametrize(
    ("before", "after"),
    [
        ("workflow_dispatch:", "push:"),
        ("https://test.pypi.org/legacy/", "https://upload.pypi.org/legacy/"),
        ("environment: testpypi", "environment: production-release"),
        ("id-token: write", "id-token: read"),
        ("contents: read\n  actions: read", "contents: write\n  actions: read"),
        ("packages-dir: dist/", "packages-dir: promoted/python/"),
        ("run-id: 36712344792", "run-id: 1"),
        ("artifact-ids: 11095067140", "artifact-ids: 1"),
        ("skip-existing: false", "skip-existing: true"),
        ("persist-credentials: false", "persist-credentials: true"),
        ("dc37677b2e1c63e2034f94d8a5b11f265b73ba33", "release/v1"),
        ("python tools/testpypi_publish.py prepare", "python -m build"),
        ("attestations: true", "password: ${{ secrets.PYPI_TOKEN }}"),
        ("refs/heads/codex/stage-010-testpypi-rehearsal", "refs/heads/main"),
        ("needs: publish", "needs: identity"),
        (
            "github.ref == 'refs/heads/codex/stage-010-testpypi-rehearsal' }}",
            "github.ref == 'refs/heads/codex/stage-010-testpypi-rehearsal' || true }}",
        ),
        ("    if: ${{ inputs.confirm_testpypi", "    # if: ${{ inputs.confirm_testpypi"),
        (
            "          python tools/testpypi_publish.py prepare",
            "          # python tools/testpypi_publish.py prepare",
        ),
    ],
)
def test_staging_policy_rejects_boundary_regressions(before, after):
    workflow = (REPO_ROOT / ".github/workflows/testpypi.yml").read_text()
    assert staging_policy_findings(workflow) == []
    assert before in workflow
    assert staging_policy_findings(workflow.replace(before, after))


def test_staging_policy_is_included_in_repository_guard():
    from tools.check_stale_docs import find_release_policy_issues

    assert find_release_policy_issues(REPO_ROOT) == []


def test_staging_policy_requires_explicit_top_level_permissions():
    workflow = (REPO_ROOT / ".github/workflows/testpypi.yml").read_text()
    without_permissions = workflow.replace(
        "\npermissions:\n  contents: read\n  actions: read\n", "\n", 1
    )

    findings = staging_policy_findings(without_permissions)

    assert any("permissions" in finding.message.lower() for finding in findings)


@pytest.mark.parametrize(
    "unsafe_step",
    [
        (
            "      - uses: actions/checkout@"
            "3d3c42e5aac5ba805825da76410c181273ba90b1\n"
            "        with:\n"
            "          persist-credentials: false\n"
        ),
        "      - uses: ./.github/actions/prepare-testpypi\n",
        (
            "      - name: Execute repository code\n"
            "        run: python tools/testpypi_publish.py prepare\n"
        ),
    ],
)
def test_staging_policy_rejects_repository_execution_in_oidc_job(unsafe_step):
    workflow = (REPO_ROOT / ".github/workflows/testpypi.yml").read_text()
    anchor = "      - name: Trusted Publishing to TestPyPI only\n"
    assert anchor in workflow

    findings = staging_policy_findings(workflow.replace(anchor, unsafe_step + anchor, 1))

    assert any("oidc" in finding.message.lower() for finding in findings)


@pytest.mark.parametrize(
    ("before", "after"),
    [
        ("Require protected rehearsal branch", "Trust mutable rehearsal branch"),
        ('branches/codex%2Fstage-010-testpypi-rehearsal")', 'branches/main")'),
        ('.commit.sha\' <<<"${branch_json}"', '.name\' <<<"${branch_json}"'),
        (
            '.protected\' <<<"${branch_json}"',
            '.name\' <<<"${branch_json}"',
        ),
    ],
)
def test_staging_policy_requires_protected_branch_preflight(before, after):
    workflow = (REPO_ROOT / ".github/workflows/testpypi.yml").read_text()
    assert before in workflow
    assert staging_policy_findings(workflow) == []

    findings = staging_policy_findings(workflow.replace(before, after, 1))

    assert any("protected" in finding.message.lower() for finding in findings)


def test_staging_policy_rejects_administration_only_branch_endpoint():
    workflow = (REPO_ROOT / ".github/workflows/testpypi.yml").read_text()
    anchor = 'branch_json="$(gh api "repos/${GITHUB_REPOSITORY}/branches/'
    assert anchor in workflow
    injection = (
        'protection_json="$(gh api "repos/${GITHUB_REPOSITORY}/branches/'
        'codex%2Fstage-010-testpypi-rehearsal/protection")"\n          '
    )

    findings = staging_policy_findings(workflow.replace(anchor, injection + anchor, 1))

    assert any("administration" in finding.message.lower() for finding in findings)


def test_staging_policy_checks_every_publish_destination():
    workflow = (REPO_ROOT / ".github/workflows/testpypi.yml").read_text()
    injection = (
        "      - uses: pypa/gh-action-pypi-publish@"
        "dc37677b2e1c63e2034f94d8a5b11f265b73ba33\n"
        "        with:\n"
        "          repository-url: https://evil.invalid/legacy/\n"
    )
    assert staging_policy_findings(
        workflow.replace("\n  pipx-smoke:", "\n" + injection + "\n  pipx-smoke:")
    )


def test_path_scoped_staging_guard_does_not_depend_on_release_workflow(tmp_path):
    from tools.check_stale_docs import find_release_policy_issues

    path = Path(".github/workflows/testpypi.yml")
    (tmp_path / path).parent.mkdir(parents=True)
    text = (
        (REPO_ROOT / path)
        .read_text()
        .replace("https://test.pypi.org/legacy/", "https://upload.pypi.org/legacy/")
    )
    (tmp_path / path).write_text(text)
    assert find_release_policy_issues(tmp_path, targets=(path.as_posix(),))


@pytest.mark.parametrize("field", ["repository_id", "id", "head_sha"])
def test_nested_artifact_identity_is_rejected(identity, field):
    artifact, run = metadata(identity)
    artifact["workflow_run"][field] = "foreign"
    with pytest.raises(ValueError, match="identity"):
        publisher.verify_api_identity(identity, artifact, run)
