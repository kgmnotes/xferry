"""Network measurements retain authentication, bounded retries and byte integrity."""

from __future__ import annotations

import http.client
import ssl
from pathlib import Path

import pytest

from tools import network_transfer_smoke as smoke


def test_profiles_exercise_short_final_chunk_and_separate_faults() -> None:
    quick = smoke.workloads("quick")
    assert quick[0].sizes == (16 * smoke.MIB, 16 * smoke.MIB + 1)
    assert quick[1].recovery
    weekly = smoke.workloads("weekly")
    assert [len(case.sizes) for case in weekly[:3]] == [1, 2, 4]
    assert weekly[3].sizes == (2048 * smoke.MIB,)


def test_sparse_latency_receipts_do_not_claim_high_percentiles() -> None:
    assert smoke.latency_summary([]) == {"count": 0, "p50_ms": None, "p95_ms": None, "p99_ms": None}
    sparse = smoke.latency_summary([1, 2, 3, 4])
    assert sparse == {"count": 4, "p50_ms": 2, "p95_ms": None, "p99_ms": None}
    dense = smoke.latency_summary(list(range(1, 101)))
    assert dense == {"count": 100, "p50_ms": 50, "p95_ms": 95, "p99_ms": 99}


def test_retry_after_is_honored_without_unbounded_wait() -> None:
    assert smoke.retry_delay("3", 0) == 3
    assert smoke.retry_delay("malformed", 1) == 0.5
    assert smoke.retry_delay("0", 0) == 0.25
    with pytest.raises(RuntimeError, match="budget"):
        smoke.retry_delay("1000", 0)
    with pytest.raises(RuntimeError, match="invalid"):
        smoke.retry_delay("nan", 0)


def _client() -> smoke.Client:
    client = object.__new__(smoke.Client)
    client.port = 1234
    client.timeout = smoke.REQUEST_TIMEOUT
    client.attempts = smoke.MAX_ATTEMPTS
    client.context = ssl.create_default_context()
    client.authorization = "Basic synthetic-fixture"
    client.measurements = smoke.Measurements()
    return client


def _transport(monkeypatch, statuses):
    sent = []
    closed = []
    pending = iter(statuses)

    class Connection:
        def __init__(self, *_args, **_kwargs):
            self.status = next(pending)

        def request(self, method, path, body, headers):
            sent.append((method, path, body, headers))

        def getresponse(self):
            if isinstance(self.status, Exception):
                raise self.status
            return self

        def read(self, size):
            return b"ok"

        def getheader(self, name):
            return "0"

        def close(self):
            closed.append(self)

    monkeypatch.setattr(smoke.http.client, "HTTPSConnection", Connection)
    monkeypatch.setattr(smoke.time, "sleep", lambda _delay: None)
    return sent, closed


def test_throttled_chunk_retry_preserves_exact_payload_and_auth(monkeypatch) -> None:
    sent, closed = _transport(monkeypatch, [429, 503, 201])
    client = _client()
    status, body = client.request(
        "PUT", "/chunk", body=b"same ciphertext", expected=(200, 201), direction="upload"
    )
    assert (status, body) == (201, b"ok")
    assert len(sent) == len(closed) == 3
    assert all(item == sent[0] for item in sent)
    assert sent[0][3]["Authorization"] == client.authorization
    assert client.measurements.report()["throttle_responses"] == {"429": 1, "503": 1}


def test_certificate_failures_are_never_retried_or_ignored(monkeypatch) -> None:
    sent, closed = _transport(monkeypatch, [ssl.SSLCertVerificationError("fixture")])
    with pytest.raises(ssl.SSLCertVerificationError):
        _client().request("GET", "/chunk")
    assert len(sent) == len(closed) == 1


def test_retry_budget_terminates_persistent_connection_failures(monkeypatch) -> None:
    sent, closed = _transport(monkeypatch, [http.client.RemoteDisconnected()] * smoke.MAX_ATTEMPTS)
    client = _client()
    with pytest.raises(RuntimeError, match="exhausted"):
        client.request("GET", "/chunk")
    assert len(sent) == len(closed) == smoke.MAX_ATTEMPTS
    assert client.measurements.network_retries == smoke.MAX_ATTEMPTS


def test_auth_failure_does_not_become_a_retry_success(monkeypatch) -> None:
    sent, closed = _transport(monkeypatch, [401])
    with pytest.raises(RuntimeError, match="401"):
        _client().request("GET", "/chunk")
    assert len(sent) == len(closed) == 1


@pytest.mark.skipif(smoke.sys.platform != "linux", reason="Linux RSS measurements")
def test_small_real_tls_roundtrip_and_client_authentication(tmp_path: Path) -> None:
    result = smoke.run_case(smoke.Workload("small-real-tls", (17,)), tmp_path)
    item = result["files"][0]
    assert item["roundtrip_bytes"] == 17
    assert item["source_sha256"] == item["roundtrip_sha256"]
    assert result["server_memory"][0]["peak_rss_bytes"] > 0
    assert result["server_memory"][0]["peak_rss_delta_bytes"] <= smoke.SERVER_RSS_LIMIT
    assert result["chunk_attempt_latency"]["upload"]["count"] >= 1
    assert result["chunk_attempt_latency"]["download"]["count"] >= 1


def test_weekly_profile_requires_explicit_disk_acknowledgement() -> None:
    with pytest.raises(SystemExit) as exc:
        smoke.main(["--profile", "weekly"])
    assert exc.value.code == 2


def test_failed_memory_sample_cannot_skip_server_cleanup(tmp_path, monkeypatch) -> None:
    stopped = []

    class Process:
        pid = 123456
        returncode = None

        def poll(self):
            return self.returncode

        def terminate(self):
            stopped.append("terminate")

        def wait(self, timeout=None):
            self.returncode = 0
            stopped.append("wait")
            return 0

    def missing(_pid):
        raise FileNotFoundError("process exited while sampling")

    monkeypatch.setattr(smoke, "process_memory", missing)
    server = smoke.ServerProcess(tmp_path)
    server.process = Process()
    server.close()
    assert stopped == ["terminate", "wait"]
    assert server.process is None


def test_case_cleanup_targets_server_descendants_even_after_case_exit(monkeypatch) -> None:
    signals = []

    class Process:
        pid = 123456

        def communicate(self, timeout):
            return "", ""

    monkeypatch.setattr(smoke.os, "killpg", lambda pid, sig: signals.append((pid, sig)))
    smoke.terminate_case(Process())
    assert signals == [(123456, smoke.signal.SIGTERM), (123456, smoke.signal.SIGKILL)]
