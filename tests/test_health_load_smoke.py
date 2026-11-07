"""Health measurements keep overload, malformed responses and failures observable."""

from __future__ import annotations

import copy
import json
import ssl
import subprocess
import sys
from pathlib import Path

import pytest

from tools import health_load_smoke as smoke
from tools import network_transfer_smoke as network


def fake_client():
    client = object.__new__(network.Client)
    client.port = 1234
    client.context = ssl.create_default_context()
    client.timeout = 1
    client.authorization = "Basic synthetic"
    return client


@pytest.mark.parametrize(
    "status,payload,error,ready",
    [
        (200, b'{"health":"ready"}', None, True),
        (200, b'{"health":"starting"}', "invalid_health", False),
        (200, b"[]", "invalid_health", False),
        (200, b"invalid", "invalid_json", False),
        (429, b"{}", None, False),
        (503, b"{}", None, False),
        (500, b"{}", "unexpected_status", False),
        (401, b"{}", "unexpected_status", False),
    ],
)
def test_probe_is_one_authenticated_attempt_without_hidden_retries(
    monkeypatch, status, payload, error, ready
):
    calls = []

    class Connection:
        def __init__(self, *args, **kwargs):
            self.status = status
            calls.append("connect")

        def request(self, method, path, *, headers):
            assert (method, path) == ("PING", "/")
            assert headers == {"Authorization": "Basic synthetic"}

        def getresponse(self):
            return self

        def read(self, maximum):
            assert maximum == smoke.MAX_PING_BYTES + 1
            return payload

        def close(self):
            calls.append("close")

    monkeypatch.setattr(smoke.http.client, "HTTPSConnection", Connection)
    result = smoke.ping_once(fake_client())
    assert calls == ["connect", "close"]
    assert (result["status"], result["error"], result["ready"]) == (status, error, ready)


def test_summary_separates_success_latency_from_failures():
    result = smoke.summarize(
        [
            {"status": 200, "error": None, "ready": True, "elapsed_ms": 10},
            {"status": 429, "error": None, "ready": False, "elapsed_ms": 1},
            {"status": None, "error": "timeout", "ready": False, "elapsed_ms": 1000},
        ]
    )
    assert result["ready_latency"]["p50_ms"] == 10
    assert result["ready_latency"]["p95_ms"] is None
    assert result["statuses"] == {"200": 1, "429": 1, "no_response": 1}
    assert result["errors"] == {"timeout": 1}


def receipt():
    return {
        "schema": 1,
        "kind": "health-load",
        "status": "passed",
        "environment": {"cpu": "a"},
        "settings": {"files": 20000},
        "profile": "quick",
        "sample_count": 20,
        "transfer_size_bytes": 123,
        "source_commit": "a" * 40,
        "cases": [
            {
                "file_count": 1000,
                "phases": {
                    phase: {"ready_latency": {"p95_ms": 10}} for phase in ("idle", "loaded")
                },
            }
        ],
    }


def test_only_compatible_successful_baselines_can_produce_advisory_comparison():
    current, baseline = receipt(), receipt()
    current["cases"][0]["phases"]["loaded"]["ready_latency"]["p95_ms"] = 15
    result = smoke.compare(current, baseline)
    assert result["status"] == "compared"
    assert result["warnings"] == [
        {"file_count": 1000, "phase": "loaded", "p95_increase_percent": 50}
    ]
    for key, value in (
        ("environment", {"cpu": "b"}),
        ("status", "failed"),
        ("settings", {}),
        ("cases", []),
        ("cases", [None]),
    ):
        incompatible = copy.deepcopy(baseline)
        incompatible[key] = value
        assert smoke.compare(current, incompatible)["status"] == "baseline_unavailable"
    assert smoke.compare(current, None)["status"] == "baseline_unavailable"


@pytest.mark.skipif(sys.platform != "linux", reason="Linux resource counters")
def test_real_tls_populated_health_with_concurrent_authenticated_transfer(tmp_path: Path):
    result = smoke.run_case(tmp_path, 3, samples=3, transfer_size=19)
    assert result["status"] == "passed"
    assert result["ping_retries"] == 0
    assert result["file_count"] == 3
    assert all(len(phase["samples"]) == 3 for phase in result["phases"].values())
    assert all(item["source_sha256"] == item["roundtrip_sha256"] for item in result["transfers"])
    assert result["server_memory"][0]["peak_rss_bytes"] > 0


@pytest.mark.parametrize("content", [None, "not JSON", "[]", "null"])
@pytest.mark.skipif(sys.platform != "linux", reason="Linux measurement CLI")
def test_unavailable_baseline_still_produces_explicit_current_run_result(
    tmp_path: Path, monkeypatch, content: str | None
):
    baseline = tmp_path / "baseline.json"
    if content is not None:
        baseline.write_text(content)
    output = tmp_path / "result.json"
    monkeypatch.setattr(smoke, "isolated_case", lambda count, *_: {"status": "passed"})
    assert smoke.main(["--baseline", str(baseline), "--output", str(output)]) == 0
    result = json.loads(output.read_text())
    assert result["status"] == "passed"
    assert result["comparison"]["status"] == "baseline_unavailable"
    assert "error" not in result


@pytest.mark.skipif(sys.platform != "linux", reason="Linux measurement CLI")
def test_case_failure_cannot_leave_success_status(tmp_path: Path, monkeypatch):
    def failed(*_args):
        raise RuntimeError("synthetic case failure")

    monkeypatch.setattr(smoke, "isolated_case", failed)
    output = tmp_path / "result.json"
    assert smoke.main(["--output", str(output)]) == 1
    result = json.loads(output.read_text())
    assert result["status"] == "failed"
    assert "synthetic case failure" in result["error"]


def test_source_identity_ignores_generated_receipts_but_retains_new_source(
    tmp_path: Path, monkeypatch
):
    def git(*arguments):
        subprocess.run(["git", *arguments], cwd=tmp_path, check=True, capture_output=True)

    git("init", "-q")
    source = tmp_path / "source.py"
    source.write_text("original\n")
    git("add", ".")
    git("-c", "user.name=Test", "-c", "user.email=test@example.invalid", "commit", "-qm", "base")
    monkeypatch.setattr(smoke, "REPO_ROOT", tmp_path)
    for folder in ("output", "performance-results"):
        directory = tmp_path / folder
        directory.mkdir()
        (directory / "receipt.json").write_text("{}")
    assert smoke.source_dirty() is False
    source.write_text("modified\n")
    assert smoke.source_dirty() is True
    source.write_text("original\n")
    (tmp_path / "new_source.py").write_text("new\n")
    assert smoke.source_dirty() is True
