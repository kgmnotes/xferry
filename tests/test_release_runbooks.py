"""Production release and incident-response documentation contracts."""

from __future__ import annotations

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
RELEASE_RUNBOOK = REPO_ROOT / "docs" / "release-runbook.md"
INCIDENT_RUNBOOK = REPO_ROOT / "docs" / "incident-response.md"


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_release_runbook_preserves_production_order_and_key_boundary() -> None:
    text = _read(RELEASE_RUNBOOK)
    normalized = " ".join(text.split())

    ordered = (
        "1. Verify the candidate.",
        "2. Cross the `production-release` signing-key custody boundary.",
        "3. Create the signed draft GitHub Release.",
        "4. Publish PyPI.",
        "5. Publish GHCR.",
        "6. Make the GitHub Release public.",
        "7. Run post-publish managed checks.",
        "8. Prepare separate Pages publication.",
    )
    positions = [text.index(marker) for marker in ordered]

    assert positions == sorted(positions)
    assert "XFERRY_RELEASE_ED25519_PRIVATE_KEY_PEM" in text
    assert "`production-release` is the signing-key custody boundary and the single" in normalized
    assert (
        "`release-production` is the secret-free production publication boundary. "
        "It has no required reviewers." in normalized
    )
    assert "`release-production` publisher jobs receive only signed artifacts" in normalized
    assert "The current production workflow does not deploy Pages." in text
    assert "they must not receive or export the private key" in normalized
    assert "automatically, without further publisher approvals." in normalized
    assert "A failed prerequisite stops dependent publishers" in normalized
    assert "it does not assert an independent code review." in normalized


def test_release_runbook_has_exact_go_no_go_and_no_mutable_recovery() -> None:
    text = _read(RELEASE_RUNBOOK)

    for required in (
        "| Target version | Exact `vX.Y.Z`; no pre-release or build metadata |",
        "| Prior stages | STAGE-010 through STAGE-014 are `CLOSED` |",
        "| Release authorization | Approve `production-release` once after preparation; "
        "downstream `release-production` publishers run automatically |",
        "| Reviewer independence | The approver is not the actor who requested the deployment |",
        "Any `No`, `Unknown`, or expired evidence is a no-go.",
        "Rollback uses a previously verified exact version or digest.",
    ):
        assert required in text

    assert "releases/latest" not in text
    assert "ghcr.io/kgmnotes/xferry:latest" not in text
    assert "xferry update --to latest" not in text
    assert (
        "BEGIN "
        # PEM marker only; keep source fragments separate for secret scanners.
        "PRIVATE KEY"
    ) not in text


def test_incident_response_covers_partial_release_and_tabletop() -> None:
    text = _read(INCIDENT_RUNBOOK)

    for required in (
        "| PyPI public, GHCR and Release still private |",
        "| GHCR public, PyPI or Release incomplete |",
        "| Public GitHub Release exists |",
        "| Signing key suspected compromised |",
        "Run this tabletop without changing public artifacts:",
        "PyPI Yank",
        "GHCR Withdrawal Without Deletion",
        "GitHub Release Withdrawal",
        "Signing-Key Revocation and Rotation",
        "Operator Rollback Communication",
    ):
        assert required in text

    assert "Do not delete a digest as the first response." in text
    assert "Do not upload replacement files under the same version." in text
    assert "no step requires reading, printing, exporting, or copying" in text
    normalized = " ".join(text.split())
    assert "Cancel the release run and stop remaining jobs promptly." in normalized
    assert "Reject any pending `production-release` signer approval." in normalized
    assert "there are no `release-production` approvals to hold." in normalized
    assert (
        "BEGIN "
        # PEM marker only; keep source fragments separate for secret scanners.
        "PRIVATE KEY"
    ) not in text


def test_mkdocs_nav_exposes_release_operations_docs() -> None:
    nav = _read(REPO_ROOT / "mkdocs.yml")

    assert "Production release: release-runbook.md" in nav
    assert "Release incident response: incident-response.md" in nav
