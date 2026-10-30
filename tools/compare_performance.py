#!/usr/bin/env python3
"""Compare performance with compatible successful default-branch evidence.

Timing changes are advisory. Baseline JSON is parsed as data, never executed
or extracted onto the filesystem.
"""

from __future__ import annotations

import argparse
import io
import json
import math
import os
import re
import subprocess
import zipfile
from pathlib import Path
from typing import Any
from urllib.parse import quote

MAX_ARTIFACT_BYTES = 16 * 1024 * 1024
MAX_JSON_BYTES = 8 * 1024 * 1024
ARTIFACT_NAME = "performance-measurements"
IDENTITY_FIELDS = ("schema_version", "profile", "environment", "server_settings")


def _nonnegative_number(value: object) -> bool:
    try:
        return type(value) in (int, float) and math.isfinite(value) and value >= 0
    except OverflowError:
        return False


def valid_network(value: object) -> bool:
    """Do not let malformed or non-finite artifact metrics break an advisory job."""
    if not isinstance(value, dict) or value.get("schema_version") != 1:
        return False
    if value.get("profile") not in ("quick", "weekly"):
        return False
    if not all(isinstance(value.get(key), dict) for key in ("environment", "server_settings")):
        return False
    cases = value.get("cases")
    if not isinstance(cases, list) or not cases:
        return False
    seen = set()
    try:
        for case in cases:
            if (
                not isinstance(case, dict)
                or not isinstance(case["name"], str)
                or case["name"] in seen
                or type(case["timing_eligible"]) is not bool
                or type(case["concurrency"]) is not int
                or case["concurrency"] < 1
                or type(case["chunks_in_flight_per_file"]) is not int
                or case["chunks_in_flight_per_file"] < 1
                or not isinstance(case["sizes_bytes"], list)
                or len(case["sizes_bytes"]) != case["concurrency"]
                or not all(type(size) is int and size > 0 for size in case["sizes_bytes"])
                or not _nonnegative_number(case["roundtrip_mib_per_second"])
            ):
                return False
            seen.add(case["name"])
            for direction in ("upload", "download"):
                latency = case["chunk_attempt_latency"][direction]
                if type(latency["count"]) is not int or latency["count"] < 0:
                    return False
                for key in ("p50_ms", "p95_ms", "p99_ms"):
                    if latency[key] is not None and not _nonnegative_number(latency[key]):
                        return False
    except (KeyError, TypeError):
        return False
    return True


def case_identity(case: dict[str, Any]) -> tuple[Any, ...]:
    return (
        case["name"],
        tuple(case["sizes_bytes"]),
        case["concurrency"],
        case["chunks_in_flight_per_file"],
        case["timing_eligible"],
    )


def compatible(current: dict[str, Any], baseline: dict[str, Any]) -> bool:
    if not valid_network(current) or not valid_network(baseline):
        return False
    try:
        return all(current[key] == baseline[key] for key in IDENTITY_FIELDS) and sorted(
            case_identity(case) for case in current["cases"]
        ) == sorted(case_identity(case) for case in baseline["cases"])
    except (KeyError, TypeError):
        return False


def compare_network(current: dict[str, Any], baseline: dict[str, Any]) -> list[dict[str, Any]]:
    """Report regressions separately for each concurrency and direction."""
    if not compatible(current, baseline):
        raise ValueError("incompatible network baseline")
    previous = {case["name"]: case for case in baseline["cases"]}
    warnings: list[dict[str, Any]] = []
    for case in current["cases"]:
        if not case["timing_eligible"]:
            continue
        old = previous[case["name"]]
        speed = case["roundtrip_mib_per_second"]
        old_speed = old["roundtrip_mib_per_second"]
        if old_speed > 0 and speed < old_speed * 0.8:
            warnings.append(
                {
                    "case": case["name"],
                    "metric": "roundtrip_mib_per_second",
                    "baseline": old_speed,
                    "current": speed,
                    "change_percent": round((speed / old_speed - 1) * 100, 2),
                }
            )
        for direction in ("upload", "download"):
            for percentile in ("p50_ms", "p95_ms", "p99_ms"):
                value = case["chunk_attempt_latency"][direction][percentile]
                old_value = old["chunk_attempt_latency"][direction][percentile]
                if value is not None and old_value and value > old_value * 1.25:
                    warnings.append(
                        {
                            "case": case["name"],
                            "metric": f"{direction}.{percentile}",
                            "baseline": old_value,
                            "current": value,
                            "change_percent": round((value / old_value - 1) * 100, 2),
                        }
                    )
    return warnings


def compare_microbenchmarks(
    current: dict[str, Any], baseline: dict[str, Any]
) -> list[dict[str, Any]]:
    def valid_items(document):
        if not isinstance(document, dict) or not isinstance(document.get("benchmarks"), list):
            return []
        valid = []
        for item in document["benchmarks"]:
            if (
                isinstance(item, dict)
                and isinstance(item.get("fullname"), str)
                and isinstance(item.get("stats"), dict)
                and _nonnegative_number(item["stats"].get("median"))
            ):
                valid.append(item)
        return valid

    old_by_name = {item["fullname"]: item for item in valid_items(baseline)}
    warnings = []
    for item in valid_items(current):
        old = old_by_name.get(item["fullname"])
        if old is None or old.get("params") != item.get("params"):
            continue
        median, previous = item["stats"]["median"], old["stats"]["median"]
        if previous > 0 and median > previous * 1.25:
            warnings.append(
                {
                    "case": item["fullname"],
                    "metric": "microbenchmark.median_seconds",
                    "baseline": previous,
                    "current": median,
                    "change_percent": round((median / previous - 1) * 100, 2),
                }
            )
    return warnings


def artifact_documents(payload: bytes) -> tuple[dict[str, Any], dict[str, Any] | None]:
    if len(payload) > MAX_ARTIFACT_BYTES:
        raise ValueError("baseline artifact is too large")
    with zipfile.ZipFile(io.BytesIO(payload)) as archive:
        documents = {}
        for name in ("network.json", "microbenchmarks.json"):
            entries = [
                item for item in archive.infolist() if item.filename == name and not item.is_dir()
            ]
            if name == "network.json" and len(entries) != 1:
                raise ValueError("baseline must contain exactly one network.json")
            if len(entries) > 1:
                raise ValueError("duplicate baseline document")
            if entries:
                if entries[0].file_size > MAX_JSON_BYTES:
                    raise ValueError("baseline JSON is too large")
                value = json.loads(archive.read(entries[0]))
                if not isinstance(value, dict):
                    raise ValueError("baseline JSON must be an object")
                documents[name] = value
        return documents["network.json"], documents.get("microbenchmarks.json")


def github_api(path: str) -> bytes:
    # gh handles signed download redirects; no custom credential forwarding.
    result = subprocess.run(["gh", "api", path], capture_output=True, check=False, timeout=60)
    if result.returncode:
        raise RuntimeError("GitHub baseline API is unavailable")
    return result.stdout


def find_baseline(
    current: dict[str, Any], *, repository: str, branch: str, workflow: str
) -> tuple[dict[str, Any], dict[str, Any] | None] | None:
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
        raise ValueError("invalid GitHub repository")
    if not re.fullmatch(r"[A-Za-z0-9_.-]+\.ya?ml", workflow):
        raise ValueError("invalid workflow filename")
    prefix = f"repos/{repository}/actions"
    runs = json.loads(
        github_api(
            f"{prefix}/workflows/{workflow}/runs?"
            f"status=success&branch={quote(branch, safe='')}&per_page=30"
        )
    )["workflow_runs"]
    for run in runs:
        if (
            run.get("head_branch") != branch
            or run.get("status") != "completed"
            or run.get("conclusion") != "success"
            or run.get("event") not in {"schedule", "workflow_dispatch"}
            or str(run["id"]) == str(current.get("run_id"))
        ):
            continue
        artifacts = json.loads(github_api(f"{prefix}/runs/{run['id']}/artifacts"))["artifacts"]
        for artifact in artifacts:
            if (
                artifact["name"] != ARTIFACT_NAME
                or artifact["expired"]
                or artifact["size_in_bytes"] > MAX_ARTIFACT_BYTES
            ):
                continue
            try:
                network, micro = artifact_documents(
                    github_api(f"{prefix}/artifacts/{int(artifact['id'])}/zip")
                )
                if (
                    str(network.get("run_id")) != str(run["id"])
                    or network.get("source_sha") != run["head_sha"]
                    or not compatible(current, network)
                ):
                    continue
            except (ValueError, KeyError, TypeError, RecursionError, zipfile.BadZipFile):
                continue
            return network, micro
    return None


def render_summary(report: dict[str, Any]) -> str:
    lines = [
        "## Transfer performance",
        "",
        f"Comparison: **{report['status']}**. Timing results are advisory.",
        "",
    ]
    if report.get("baseline"):
        baseline = report["baseline"]
        lines.extend([f"Baseline run: {baseline['run_id']}; source: {baseline['source_sha']}.", ""])
    if report.get("reason"):
        lines.extend([report["reason"], ""])
    for warning in report["warnings"]:
        case = str(warning["case"]).replace(chr(96), "").replace("\n", " ")
        metric = str(warning["metric"]).replace(chr(96), "").replace("\n", " ")
        lines.append(f"- {case} / {metric}: {warning['change_percent']:+.2f}%.")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--current", type=Path, required=True)
    parser.add_argument("--microbenchmarks", type=Path)
    parser.add_argument("--baseline", type=Path, help="Explicit local baseline JSON.")
    parser.add_argument("--repository", default=os.environ.get("GITHUB_REPOSITORY"))
    parser.add_argument("--branch", default="main")
    parser.add_argument("--workflow", default="performance.yml")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--summary", type=Path)
    args = parser.parse_args(argv)
    current = json.loads(args.current.read_text(encoding="utf-8"))
    report: dict[str, Any] = {
        "schema_version": 1,
        "status": "baseline_unavailable",
        "warnings": [],
        "baseline": None,
    }
    selected = None
    try:
        if args.baseline:
            candidate = json.loads(args.baseline.read_text(encoding="utf-8"))
            if compatible(current, candidate):
                selected = candidate, None
        elif args.repository:
            selected = find_baseline(
                current, repository=args.repository, branch=args.branch, workflow=args.workflow
            )
    except (
        OSError,
        RuntimeError,
        ValueError,
        KeyError,
        TypeError,
        RecursionError,
        subprocess.TimeoutExpired,
    ):
        report["reason"] = "Baseline lookup failed; current measurements remain available."
    if selected:
        baseline, micro = selected
        report["baseline"] = {
            "run_id": baseline.get("run_id"),
            "source_sha": baseline.get("source_sha"),
        }
        report["warnings"] = compare_network(current, baseline)
        if args.microbenchmarks and micro:
            report["warnings"].extend(
                compare_microbenchmarks(
                    json.loads(args.microbenchmarks.read_text(encoding="utf-8")), micro
                )
            )
        report["status"] = "regression_warning" if report["warnings"] else "compared"
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    summary = render_summary(report)
    if args.summary:
        with args.summary.open("a", encoding="utf-8") as stream:
            stream.write(summary)
    print(summary)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
