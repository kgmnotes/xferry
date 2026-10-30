"""A real HTTP cold-restore rehearsal using isolated synthetic data only."""

import json
import sys

import pytest

from tools import restore_drill
from tools.restore_drill import run_restore_drill
from xferry.config import __version__


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux offline rebind")
def test_cold_copy_restores_files_notes_and_encrypted_resume_over_http():
    result = run_restore_drill()

    assert result["status"] == "passed"
    assert result["version"] == __version__
    assert result["transport"] == "authenticated loopback HTTP"
    assert result["verified_records"] == 3
    assert result["backup_unchanged"] is True
    assert result["new_file_lifecycle"] is True
    for name in ("ordinary_sha256", "completed_sha256", "resumed_sha256", "note_ciphertext_sha256"):
        assert len(result[name]) == 64
    rendered = json.dumps(result)
    assert "temporary-test-password" not in rendered
    assert "synthetic restore fixture" not in rendered
    assert "key" not in rendered


def test_json_cli_separates_runtime_diagnostics_from_receipt(monkeypatch, capsys):
    def noisy_drill():
        print("Server stopped")
        return {"status": "passed"}

    monkeypatch.setattr(restore_drill, "run_restore_drill", noisy_drill)
    assert restore_drill.main(["--json"]) == 0
    output = capsys.readouterr()
    assert json.loads(output.out) == {"status": "passed"}
    assert output.err == "Server stopped\n"
