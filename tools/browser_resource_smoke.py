#!/usr/bin/env python3
"""Measure real Chromium encrypted transfer storage with a disk-backed synthetic picker."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
from pathlib import Path
from typing import Any
from uuid import uuid4

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tools import browser_smoke as browser  # noqa: E402
from tools import network_transfer_smoke as network  # noqa: E402
from tools.health_load_smoke import MeasurementServer, source_commit, source_dirty  # noqa: E402
from xferry.config import __version__  # noqa: E402

MIB = network.MIB


def workloads(profile: str) -> tuple[tuple[int, bool], ...]:
    if profile == "quick":
        return ((64 * MIB, False), (64 * MIB + 1, True))
    if profile == "extended":
        return ((256 * MIB + 1, False), (2 * 1024 * MIB, False), (64 * MIB + 1, True))
    raise ValueError("unknown browser profile")


def write_fixture(path: Path, size: int) -> str:
    digest = hashlib.sha256()
    with path.open("wb") as stream:
        for index in range((size + MIB - 1) // MIB):
            chunk = bytes([index % 251]) * min(MIB, size - index * MIB)
            stream.write(chunk)
            digest.update(chunk)
    return digest.hexdigest()


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(MIB), b""):
            digest.update(chunk)
    return digest.hexdigest()


def parse_receipt(output: str, kind: str) -> dict[str, Any]:
    if "### Error" in output:
        raise RuntimeError(
            "browser command failed: " + browser._sanitize_browser_diagnostic(output)[:4096]
        )
    for line in reversed(output.splitlines()):
        try:
            result = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(result, dict) and result.get("kind") == kind:
            return result
    raise RuntimeError("browser command returned no valid measurement receipt")


def run_cli(command: list[str], session: str, *args: str, local: bool) -> str:
    """Bound each driver command while preserving diagnostics and explicit session ownership."""
    environment = os.environ.copy()
    if local:
        bypass = ",".join(filter(None, (environment.get("NO_PROXY"), "127.0.0.1,localhost,::1")))
        environment["NO_PROXY"] = bypass
        environment["no_proxy"] = bypass
    completed = subprocess.run(
        [*command, f"-s={session}", *args],
        cwd=REPO_ROOT,
        env=environment,
        capture_output=True,
        text=True,
        timeout=2400 if "run-code" in args else 90,
        check=False,
    )
    output = "\n".join(
        part.strip() for part in (completed.stdout, completed.stderr) if part.strip()
    )
    if completed.returncode:
        raise RuntimeError(browser._sanitize_browser_diagnostic(output)[:4096])
    return output


def process_tree(root_pid: int | None) -> list[int]:
    if root_pid is None:
        return []
    parents: dict[int, int] = {}
    for directory in Path("/proc").iterdir():
        if not directory.name.isdecimal():
            continue
        try:
            tail = (directory / "stat").read_text().rpartition(")")[2].split()
            parents[int(directory.name)] = int(tail[1])
        except (OSError, ValueError, IndexError):
            continue
    found = {root_pid}
    while additions := {pid for pid, parent in parents.items() if parent in found} - found:
        found.update(additions)
    return sorted(found)


def process_rss(pids: list[int]) -> int | None:
    total = 0
    found = False
    for pid in pids:
        try:
            current, _peak = network.process_memory(pid)
        except (OSError, RuntimeError):
            continue
        total += current
        found = True
    return total if found else None


def run_case(
    root: Path, size: int, *, recovery: bool, target_url: str | None = None
) -> dict[str, Any]:
    if shutil.disk_usage(root).free < size * 5 + 256 * MIB:
        raise RuntimeError("insufficient disk for fixture, ciphertext, OPFS cache and saved output")
    fixture = root / "resource-input.bin"
    expected = write_fixture(fixture, size)
    output = root / "resource-output.bin"
    config = root / "cli.json"
    server: MeasurementServer | None = None
    command = browser._playwright_command()
    session = f"resource-{uuid4().hex}"
    stop = threading.Event()
    sampler: threading.Thread | None = None
    peak: int | None = None
    baseline: int | None = None
    pids: list[int] = []
    try:
        if target_url is None:
            server = MeasurementServer(root, browser=True)
            server.start()
            url = f"http://127.0.0.1:{server.port}/"
        else:
            url = browser.normalize_target_url(target_url)
        auth = os.environ.get("XFERRY_BROWSER_AUTH_FILE") if target_url else None
        browser._write_cli_config(
            config,
            local_target=target_url is None,
            auth_file=Path(auth) if auth else None,
            auth_origin=url if auth else None,
        )
        # Existing pinned CLI supports browser-context downloads; keep the measurement bounded.
        document = json.loads(config.read_text())
        # An in-memory context has a smaller origin quota and does not measure a
        # normal disk-backed browser's large-file recovery behavior.
        document["browser"]["userDataDir"] = str(root / "browser-profile")
        document["browser"]["contextOptions"]["acceptDownloads"] = True
        document["timeouts"] = {"action": 1800000, "navigation": 60000}
        config.write_text(json.dumps(document))
        config.chmod(0o600)
        run_cli(
            command,
            session,
            "open",
            "about:blank",
            "--config",
            str(config),
            local=target_url is None,
        )
        identity_script = """async (page) => {
            const browser = page.context().browser();
            let pids = []; let rootPid = null;
            try {
                const session = await browser.newBrowserCDPSession();
                const info = await session.send('SystemInfo.getProcessInfo');
                pids = info.processInfo.map(process => process.id);
                rootPid = info.processInfo.find(process => process.type === 'browser')?.id ?? null;
                await session.detach();
            } catch (_) {}
            return {kind:'browser-resource-identity',browser:browser.version(),pids,rootPid};
        }"""
        identity = parse_receipt(
            run_cli(
                command,
                session,
                "--raw",
                "run-code",
                identity_script,
                local=target_url is None,
            ),
            "browser-resource-identity",
        )
        root_pid = identity.get("rootPid")
        pids = process_tree(root_pid)
        baseline = process_rss(pids)
        peak = baseline

        def sample() -> None:
            nonlocal peak
            while not stop.wait(0.1):
                value = process_rss(process_tree(root_pid))
                if value is not None:
                    peak = max(peak or 0, value)
                if server is not None:
                    try:
                        server.sample()
                    except OSError:
                        pass

        sampler = threading.Thread(target=sample, daemon=True)
        sampler.start()
        options = {
            "url": url,
            "input": str(fixture),
            "output": str(output),
            "size": size,
            "recovery": recovery,
            "transport": "external-https" if url.startswith("https:") else "loopback-http",
        }
        script = root / "resource.js"
        script.write_text(
            Path(__file__)
            .with_suffix(".playwright.js")
            .read_text()
            .replace("__RESOURCE_OPTIONS__", json.dumps(options))
        )
        result = parse_receipt(
            run_cli(
                command,
                session,
                "--raw",
                "run-code",
                "--filename",
                str(script),
                local=target_url is None,
            ),
            "browser-resource-case",
        )
        actual = file_sha256(output)
        if actual != expected or output.stat().st_size != size:
            raise RuntimeError("browser plaintext roundtrip SHA-256 or size mismatch")
        result.update(
            plaintext_bytes=size,
            source_sha256=expected,
            roundtrip_sha256=actual,
            browser_version=identity["browser"],
            browser_sampled_processes=len(pids),
            browser_rss_scope=(
                "sum of sampled Chromium process-tree RSS; shared pages may be counted twice"
            ),
            browser_baseline_rss_bytes=baseline,
            browser_peak_rss_bytes=peak,
            browser_peak_rss_delta_bytes=max(0, peak - baseline)
            if peak is not None and baseline is not None
            else None,
            server_peak_rss_bytes=server.peak if server else None,
            server_peak_rss_delta_bytes=max(0, server.peak - server.baseline) if server else None,
            external_target=target_url is not None,
            browser_profile_storage="task-owned-disk-backed",
            timing_eligible=not recovery,
        )
        return result
    finally:
        stop.set()
        if sampler:
            sampler.join(timeout=2)
        try:
            run_cli(command, session, "close", local=target_url is None)
        finally:
            if server:
                server.close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", choices=("quick", "extended"), default="quick")
    parser.add_argument("--allow-large", action="store_true")
    parser.add_argument("--output", type=Path)
    parser.add_argument(
        "--target-url", help="Disposable owned server; encrypted uploads must be enabled."
    )
    args = parser.parse_args(argv)
    if sys.platform != "linux":
        parser.error("browser resource measurements require Linux /proc")
    if args.profile == "extended" and not args.allow_large:
        parser.error("extended profile writes 2 GiB and requires --allow-large")
    if args.target_url:
        args.target_url = browser.normalize_target_url(args.target_url)
        if not args.target_url.startswith(("https://", "http://127.0.0.1:", "http://localhost:")):
            parser.error("external browser measurements require HTTPS")
    report: dict[str, Any] = {
        "schema": 1,
        "kind": "browser-resource",
        "status": "failed",
        "harness_identity": {
            "source_commit": source_commit(),
            "source_dirty": source_dirty(),
            "xferry_version": __version__,
        },
        "profile": args.profile,
        "environment": network.environment_identity(),
        "syntheticPicker": True,
        "native_picker_verified": False,
        "cases": [],
    }
    try:
        for size, recovery in workloads(args.profile):
            with tempfile.TemporaryDirectory(prefix="xferry-browser-resource-") as temporary:
                report["cases"].append(
                    run_case(Path(temporary), size, recovery=recovery, target_url=args.target_url)
                )
        report["status"] = "passed"
    except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as exc:
        report["error"] = browser._sanitize_browser_diagnostic(str(exc))[:4096]
    rendered = json.dumps(report, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered)
    else:
        print(rendered, end="")
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
