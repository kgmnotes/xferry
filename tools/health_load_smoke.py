#!/usr/bin/env python3
"""Measure authenticated PING latency on populated workspaces during TLS transfers."""

from __future__ import annotations

import argparse
import http.client
import json
import signal
import ssl
import subprocess
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tools import network_transfer_smoke as network  # noqa: E402
from xferry.config import __version__  # noqa: E402

SCRIPT = Path(__file__).resolve()
SERVER_SETTINGS = {
    **network.SERVER_SETTINGS,
    "upload_file_limit": 20000,
    "upload_storage_limit_bytes": 8 * 1024 * network.MIB,
}
MAX_PING_BYTES = 1024 * 1024


def serve(root: Path, port: int, *, browser: bool = False) -> None:
    from xferry import XFerryServer
    from xferry.server_config import (
        AuthConfig,
        LoggingConfig,
        ServerConfig,
        ServerLimits,
        TLSConfig,
    )

    server = XFerryServer(
        ServerConfig(
            host="127.0.0.1",
            port=port,
            root_dir=root / "state",
            files_dir=root / "files",
            encrypted_uploads=True,
            auth=AuthConfig() if browser else AuthConfig(auth_file=root / "auth"),
            tls=TLSConfig()
            if browser
            else TLSConfig(cert_file=root / "cert.pem", key_file=root / "key.pem"),
            limits=ServerLimits(
                max_workers=SERVER_SETTINGS["workers"],
                body_memory_budget=SERVER_SETTINGS["body_memory_budget_bytes"],
                upload_storage_limit=SERVER_SETTINGS["upload_storage_limit_bytes"],
                upload_file_limit=SERVER_SETTINGS["upload_file_limit"],
            ),
            logging=LoggingConfig(quiet=True),
        )
    )
    signal.signal(signal.SIGTERM, lambda *_: server.stop())
    signal.signal(signal.SIGINT, lambda *_: server.stop())
    server.start()


class MeasurementServer(network.ServerProcess):
    """Reuse bounded process teardown and RSS tracking with an explicit larger file quota."""

    def __init__(self, root: Path, *, browser: bool = False) -> None:
        super().__init__(root)
        self.browser = browser

    def start(self) -> None:
        command = [sys.executable, str(SCRIPT), "--serve", str(self.root), "--port", str(self.port)]
        if self.browser:
            command.append("--browser-server")
        self.process = subprocess.Popen(command, stdout=self.log, stderr=self.log)
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise RuntimeError("measurement server exited before readiness")
            try:
                if self.browser:
                    connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=0.5)
                    try:
                        connection.request("PING", "/")
                        response = connection.getresponse()
                        ready = (
                            response.status == 200
                            and json.loads(response.read(MAX_PING_BYTES))["health"] == "ready"
                        )
                    finally:
                        connection.close()
                else:
                    probe = network.Client(
                        self.port, self.root, network.Measurements(), timeout=10, attempts=1
                    )
                    ready = probe.json("PING", "/").get("health") == "ready"
                    if ready:
                        probe.request("PING", "/", authenticated=False, expected=(401,))
                if ready:
                    self.baseline, self.peak = network.process_memory(self.process.pid)
                    return
            except ssl.SSLCertVerificationError:
                raise
            except (OSError, http.client.HTTPException, RuntimeError):
                pass
            time.sleep(0.05)
        raise RuntimeError("measurement server readiness timed out")


def ping_once(client: network.Client) -> dict[str, Any]:
    """One attempt, never a retry: throttling and failures remain visible in the receipt."""
    connection = http.client.HTTPSConnection(
        "127.0.0.1", client.port, context=client.context, timeout=client.timeout
    )
    started = time.perf_counter()
    status: int | None = None
    error: str | None = None
    ready = False
    try:
        connection.request("PING", "/", headers={"Authorization": client.authorization})
        response = connection.getresponse()
        status = response.status
        payload = response.read(MAX_PING_BYTES + 1)
        if len(payload) > MAX_PING_BYTES:
            error = "response_too_large"
        elif status == 200:
            document = json.loads(payload)
            ready = isinstance(document, dict) and document.get("health") == "ready"
            if not ready:
                error = "invalid_health"
        elif status not in (429, 503):
            error = "unexpected_status"
    except ssl.SSLCertVerificationError:
        raise
    except TimeoutError:
        error = "timeout"
    except (OSError, http.client.HTTPException):
        error = "transport_error"
    except (ValueError, UnicodeError):
        error = "invalid_json"
    finally:
        connection.close()
    return {
        "status": status,
        "error": error,
        "ready": ready,
        "elapsed_ms": round((time.perf_counter() - started) * 1000, 3),
    }


def summarize(samples: list[dict[str, Any]]) -> dict[str, Any]:
    statuses: dict[str, int] = {}
    errors: dict[str, int] = {}
    for sample in samples:
        key = str(sample["status"]) if sample["status"] is not None else "no_response"
        statuses[key] = statuses.get(key, 0) + 1
        if sample["error"]:
            errors[sample["error"]] = errors.get(sample["error"], 0) + 1
    return {
        "attempt_latency": network.latency_summary([item["elapsed_ms"] for item in samples]),
        "ready_latency": network.latency_summary(
            [item["elapsed_ms"] for item in samples if item["ready"]]
        ),
        "statuses": statuses,
        "errors": errors,
        "samples": samples,
    }


def run_case(
    root: Path, count: int, *, samples: int = 20, transfer_size: int = 64 * network.MIB
) -> dict[str, Any]:
    if not 0 <= count <= 10000 or not 1 <= samples <= 1000 or transfer_size <= 0:
        raise ValueError("invalid health workload")
    files = root / "files"
    files.mkdir()
    for index in range(count):
        (files / f"fixture-{index:05}.txt").write_bytes(b"synthetic\n")
    network.make_credentials(root)
    server = MeasurementServer(root)
    stop = threading.Event()
    failures: list[BaseException] = []
    transfers: list[dict[str, Any]] = []
    metrics = network.Measurements()
    active = threading.Event()
    try:
        server.start()
        client = network.Client(server.port, root, metrics)
        probe = network.Client(server.port, root, network.Measurements(), timeout=10, attempts=1)
        idle = [ping_once(probe) for _ in range(samples)]

        def load() -> None:
            try:
                # At most two complete synthetic transfers remain on disk at a time.
                while not stop.is_set():
                    transfer = network.new_transfer(transfer_size, len(transfers))
                    network.create_transfer(client, transfer)
                    active.set()
                    transfers.append(network.roundtrip(client, transfer))
                    client.request(
                        "DELETE",
                        f"/_xferry/encrypted-files/{transfer.manifest.file_id}",
                        expected=(200, 204),
                    )
            except BaseException as exc:
                failures.append(exc)
                active.set()

        with ThreadPoolExecutor(max_workers=1) as pool:
            worker = pool.submit(load)
            if not active.wait(timeout=30):
                stop.set()
                raise RuntimeError("transfer load did not start")
            try:
                loaded = [ping_once(probe) for _ in range(samples)]
            finally:
                stop.set()
            worker.result(timeout=180)
        if failures:
            raise RuntimeError("transfer failed during PING measurement") from failures[0]
        server.sample()
    finally:
        stop.set()
        server.close()
    results = {"idle": summarize(idle), "loaded": summarize(loaded)}
    passed = bool(transfers) and all(
        not result["errors"] and any(sample["ready"] for sample in result["samples"])
        for result in results.values()
    )
    return {
        "file_count": count,
        "status": "passed" if passed else "failed",
        "transfer_size_bytes": transfer_size,
        "transfer_concurrency": 1,
        "ping_retries": 0,
        "phases": results,
        "transfers": transfers,
        "server_memory": server.segments,
        "transfer_attempts": metrics.report(),
    }


def _compare(current: dict[str, Any], baseline: dict[str, Any] | None) -> dict[str, Any]:
    keys = (
        "schema",
        "kind",
        "environment",
        "settings",
        "profile",
        "sample_count",
        "transfer_size_bytes",
    )
    if (
        baseline is None
        or baseline.get("status") != "passed"
        or any(current.get(k) != baseline.get(k) for k in keys)
    ):
        return {"status": "baseline_unavailable", "warnings": []}
    prior = {case["file_count"]: case for case in baseline.get("cases", [])}
    warnings = []
    if set(prior) != {case["file_count"] for case in current["cases"]}:
        return {"status": "baseline_unavailable", "warnings": []}
    for case in current["cases"]:
        for phase in ("idle", "loaded"):
            old = prior[case["file_count"]]["phases"][phase]["ready_latency"]["p95_ms"]
            new = case["phases"][phase]["ready_latency"]["p95_ms"]
            if old and new and new > old * 1.25:
                warnings.append(
                    {
                        "file_count": case["file_count"],
                        "phase": phase,
                        "p95_increase_percent": round((new / old - 1) * 100, 2),
                    }
                )
    return {
        "status": "compared",
        "baseline_source_commit": baseline.get("source_commit"),
        "warnings": warnings,
    }


def compare(current: dict[str, Any], baseline: dict[str, Any] | None) -> dict[str, Any]:
    """Malformed or incompatible historical measurements are unavailable, never comparable."""
    try:
        return _compare(current, baseline)
    except (KeyError, TypeError, ValueError, AttributeError):
        return {"status": "baseline_unavailable", "warnings": []}


def isolated_case(count: int, samples: int, size: int) -> dict[str, Any]:
    """A case owns its process group and cannot leave a hung server/transfer behind."""
    with tempfile.TemporaryDirectory(prefix="xferry-health-") as temporary:
        process = subprocess.Popen(
            [
                sys.executable,
                str(SCRIPT),
                "--case-root",
                temporary,
                "--file-count",
                str(count),
                "--samples",
                str(samples),
                "--transfer-size",
                str(size),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
        try:
            stdout, _stderr = process.communicate(timeout=600)
            if process.returncode:
                raise RuntimeError(f"health case exited with {process.returncode}")
            result = json.loads(stdout)
            if not isinstance(result, dict):
                raise RuntimeError("invalid health case receipt")
            return result
        finally:
            network.terminate_case(process)


def source_commit() -> str | None:
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=REPO_ROOT, capture_output=True, text=True, check=False
    )
    return result.stdout.strip() if result.returncode == 0 else None


def source_dirty() -> bool | None:
    result = subprocess.run(
        [
            "git",
            "status",
            "--porcelain",
            "--untracked-files=all",
            "--",
            ".",
            ":(top,exclude)output/**",
            ":(top,exclude)performance-results/**",
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    return bool(result.stdout) if result.returncode == 0 else None


def load_baseline(path: Path | None) -> dict[str, Any] | None:
    """A missing or malformed prior receipt is unavailable, not a failed current run."""
    if path is None:
        return None
    try:
        document = json.loads(path.read_text())
    except (OSError, UnicodeError, ValueError):
        return None
    return document if isinstance(document, dict) else None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", choices=("quick", "weekly"), default="quick")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--baseline", type=Path)
    parser.add_argument("--serve", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--port", type=int, help=argparse.SUPPRESS)
    parser.add_argument("--browser-server", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--case-root", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--file-count", type=int, default=0, help=argparse.SUPPRESS)
    parser.add_argument("--samples", type=int, default=20, help=argparse.SUPPRESS)
    parser.add_argument(
        "--transfer-size", type=int, default=16 * network.MIB + 1, help=argparse.SUPPRESS
    )
    args = parser.parse_args(argv)
    if sys.platform != "linux":
        parser.error("health resource measurements require Linux /proc")
    if args.serve:
        if not args.port:
            parser.error("--serve requires --port")
        serve(args.serve, args.port, browser=args.browser_server)
        return 0
    if args.case_root:
        print(
            json.dumps(
                run_case(
                    args.case_root,
                    args.file_count,
                    samples=args.samples,
                    transfer_size=args.transfer_size,
                )
            )
        )
        return 0
    count = 20 if args.profile == "quick" else 100
    size = (16 if args.profile == "quick" else 64) * network.MIB + 1
    report: dict[str, Any] = {
        "schema": 1,
        "kind": "health-load",
        "xferry_version": __version__,
        "source_commit": source_commit(),
        "source_dirty": source_dirty(),
        "environment": network.environment_identity(),
        "settings": SERVER_SETTINGS,
        "profile": args.profile,
        "sample_count": count,
        "transfer_size_bytes": size,
        "cases": [],
        "status": "failed",
    }
    try:
        for files in (0, 1000, 10000):
            report["cases"].append(isolated_case(files, count, size))
        report["status"] = (
            "passed" if all(case["status"] == "passed" for case in report["cases"]) else "failed"
        )
        report["comparison"] = compare(report, load_baseline(args.baseline))
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as exc:
        report["status"] = "failed"
        report["error"] = type(exc).__name__ + ": " + str(exc)
    rendered = json.dumps(report, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered)
    else:
        print(rendered, end="")
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
