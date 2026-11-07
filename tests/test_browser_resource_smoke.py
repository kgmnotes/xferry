"""Large-file browser measurement helpers retain bounded storage and honest evidence."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from tools import browser_resource_smoke as smoke


def test_profiles_have_boundary_sizes_and_explicit_recovery():
    assert smoke.workloads("quick") == ((64 * smoke.MIB, False), (64 * smoke.MIB + 1, True))
    assert smoke.workloads("extended")[0] == (256 * smoke.MIB + 1, False)
    assert smoke.workloads("extended")[1] == (2 * 1024 * smoke.MIB, False)
    with pytest.raises(ValueError):
        smoke.workloads("unknown")


def test_streamed_fixture_hash_covers_final_short_chunk(tmp_path: Path):
    path = tmp_path / "fixture"
    size = smoke.MIB * 2 + 1
    digest = smoke.write_fixture(path, size)
    expected = hashlib.sha256(b"\0" * smoke.MIB + b"\1" * smoke.MIB + b"\2").hexdigest()
    assert path.stat().st_size == size
    assert digest == smoke.file_sha256(path) == expected


def test_cli_error_containing_success_json_is_never_a_valid_receipt():
    result = {"kind": "browser-resource-case", "status": "passed"}
    assert smoke.parse_receipt(json.dumps(result), result["kind"]) == result
    with pytest.raises(RuntimeError, match="command failed"):
        smoke.parse_receipt("### Error\n" + json.dumps(result), result["kind"])
    with pytest.raises(RuntimeError, match="no valid"):
        smoke.parse_receipt(json.dumps(result), "different-kind")


def test_unavailable_browser_process_metrics_are_null_not_zero(monkeypatch):
    def missing(_pid):
        raise FileNotFoundError

    monkeypatch.setattr(smoke.network, "process_memory", missing)
    assert smoke.process_rss([]) is None
    assert smoke.process_rss([999]) is None


def test_extended_profile_requires_explicit_disk_acknowledgement():
    with pytest.raises(SystemExit) as exc:
        smoke.main(["--profile", "extended"])
    assert exc.value.code == 2


def test_external_plain_http_is_refused_before_starting_browser():
    with pytest.raises(SystemExit) as exc:
        smoke.main(["--target-url", "http://example.com/"])
    assert exc.value.code == 2
