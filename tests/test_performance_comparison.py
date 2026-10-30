"""Timing reports use comparable trusted data and never block on regressions."""

from __future__ import annotations

import copy
import io
import json
import zipfile
from pathlib import Path

import pytest

from tools import compare_performance as comparison


def _receipt():
    latency = {"count": 100, "p50_ms": 10, "p95_ms": 20, "p99_ms": 30}
    return {
        "schema_version": 1,
        "profile": "weekly",
        "environment": {"python": "3.12", "architecture": "x86_64"},
        "server_settings": {"workers": 10},
        "run_id": "10",
        "source_sha": "a" * 40,
        "cases": [
            {
                "name": "256mib-4",
                "sizes_bytes": [256] * 4,
                "concurrency": 4,
                "chunks_in_flight_per_file": 2,
                "timing_eligible": True,
                "roundtrip_mib_per_second": 100,
                "chunk_attempt_latency": {"upload": latency.copy(), "download": latency.copy()},
            }
        ],
    }


def test_compare_reports_speed_and_latency_regressions_without_mixing_directions() -> None:
    old = _receipt()
    new = copy.deepcopy(old)
    new["cases"][0]["roundtrip_mib_per_second"] = 79
    new["cases"][0]["chunk_attempt_latency"]["upload"]["p95_ms"] = 26
    warnings = comparison.compare_network(new, old)
    assert {item["metric"] for item in warnings} == {"roundtrip_mib_per_second", "upload.p95_ms"}


@pytest.mark.parametrize("field", ["environment", "server_settings", "profile", "schema_version"])
def test_changed_measurement_contract_has_no_compatible_baseline(field) -> None:
    old = _receipt()
    new = copy.deepcopy(old)
    new[field] = "different"
    assert not comparison.compatible(new, old)
    with pytest.raises(ValueError, match="incompatible"):
        comparison.compare_network(new, old)


def test_restart_profile_and_missing_percentiles_are_not_timing_regressions() -> None:
    old = _receipt()
    new = copy.deepcopy(old)
    old["cases"][0]["timing_eligible"] = new["cases"][0]["timing_eligible"] = False
    new["cases"][0]["roundtrip_mib_per_second"] = 1
    assert comparison.compare_network(new, old) == []
    old["cases"][0]["timing_eligible"] = new["cases"][0]["timing_eligible"] = True
    new["cases"][0]["roundtrip_mib_per_second"] = 100
    new["cases"][0]["chunk_attempt_latency"]["upload"]["p99_ms"] = None
    assert comparison.compare_network(new, old) == []


def _archive(network):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        archive.writestr("network.json", json.dumps(network))
        archive.writestr("../../never-extract", "not executable")
    return stream.getvalue()


def test_artifact_json_is_read_without_extracting_paths(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    network, micro = comparison.artifact_documents(_archive(_receipt()))
    assert network == _receipt() and micro is None
    assert list(tmp_path.iterdir()) == []


def test_baseline_ignores_pr_wrong_branch_and_wrong_artifact_identity(monkeypatch) -> None:
    current = _receipt()
    current["run_id"] = "99"
    good = {
        "id": 10,
        "head_branch": "main",
        "status": "completed",
        "conclusion": "success",
        "event": "schedule",
        "head_sha": "a" * 40,
    }
    runs = [
        {**good, "id": 13, "event": "pull_request"},
        {**good, "id": 12, "head_branch": "feature"},
        {**good, "id": 11, "head_sha": "b" * 40},
        good,
    ]
    calls = []

    def api(path):
        calls.append(path)
        if "/workflows/" in path:
            return json.dumps({"workflow_runs": runs}).encode()
        if "/runs/" in path:
            return json.dumps(
                {
                    "artifacts": [
                        {
                            "id": 100,
                            "name": comparison.ARTIFACT_NAME,
                            "expired": False,
                            "size_in_bytes": 1000,
                        }
                    ]
                }
            ).encode()
        return _archive(_receipt())

    monkeypatch.setattr(comparison, "github_api", api)
    result = comparison.find_baseline(
        current, repository="owner/repo", branch="main", workflow="performance.yml"
    )
    assert result[0]["run_id"] == "10"
    assert not any("/runs/12/" in path or "/runs/13/" in path for path in calls)


def test_main_keeps_timing_regression_advisory(tmp_path: Path) -> None:
    baseline = _receipt()
    current = copy.deepcopy(baseline)
    current["cases"][0]["roundtrip_mib_per_second"] = 50
    old_path, new_path, output = (tmp_path / name for name in ("old.json", "new.json", "out.json"))
    old_path.write_text(json.dumps(baseline))
    new_path.write_text(json.dumps(current))
    assert (
        comparison.main(
            ["--current", str(new_path), "--baseline", str(old_path), "--output", str(output)]
        )
        == 0
    )
    assert json.loads(output.read_text())["status"] == "regression_warning"


def test_missing_baseline_is_explicit(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("GITHUB_REPOSITORY", raising=False)
    current, output = tmp_path / "current.json", tmp_path / "output.json"
    current.write_text(json.dumps(_receipt()))
    assert comparison.main(["--current", str(current), "--output", str(output)]) == 0
    assert json.loads(output.read_text())["status"] == "baseline_unavailable"


def test_microbenchmark_names_and_parameters_must_match() -> None:
    old = {"benchmarks": [{"fullname": "test_case[a]", "params": {"n": 1}, "stats": {"median": 1}}]}
    new = copy.deepcopy(old)
    new["benchmarks"][0]["stats"]["median"] = 2
    assert len(comparison.compare_microbenchmarks(new, old)) == 1
    new["benchmarks"][0]["params"] = {"n": 2}
    assert comparison.compare_microbenchmarks(new, old) == []


@pytest.mark.parametrize("bad", [None, "100", float("nan"), float("inf"), -1, True, 10**1000])
def test_corrupt_baseline_measurements_are_incompatible(bad) -> None:
    original = _receipt()
    broken = copy.deepcopy(original)
    broken["cases"][0]["roundtrip_mib_per_second"] = bad
    assert not comparison.compatible(original, broken)


def test_incomplete_baseline_is_not_selected() -> None:
    original = _receipt()
    broken = copy.deepcopy(original)
    del broken["cases"][0]["chunk_attempt_latency"]["upload"]["p95_ms"]
    assert not comparison.compatible(original, broken)
    assert (
        comparison.compare_microbenchmarks(
            {"benchmarks": [{"fullname": "broken", "stats": {}}]},
            {"benchmarks": None},
        )
        == []
    )
