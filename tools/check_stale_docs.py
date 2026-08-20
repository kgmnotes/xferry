#!/usr/bin/env python3
"""Reject stale references and missing contracts in active public documentation."""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

DEFAULT_TARGETS: tuple[str, ...] = (
    "README.md",
    "API.md",
    "CHANGELOG.md",
    "CONTRIBUTING.md",
    "SECURITY.md",
    "pyproject.toml",
    "mkdocs.yml",
    "docs",
    "examples",
    ".github/PULL_REQUEST_TEMPLATE.md",
    ".github/workflows",
    "xferry/config.py",
    "xferry/data/index.html",
    "xferry/request_pipeline.py",
    "xferry/handlers/notepad.py",
    "xferry/data/static/ui/core.js",
    "tools/browser_smoke.playwright.js",
    "tools/browser_smoke.py",
)

SKIPPED_DIRS = frozenset({"__pycache__"})


@dataclass(frozen=True)
class StalePattern:
    """One obsolete public-contract expression."""

    regex: re.Pattern[str]
    message: str
    ignored_paths: frozenset[Path] = frozenset()
    allow_in_superseded_adr: bool = False


@dataclass(frozen=True)
class SemanticRequirement:
    """One required contract owned by one public document."""

    path: Path
    regex: re.Pattern[str]
    message: str


@dataclass(frozen=True)
class OrderedMarkersRequirement:
    """Markers that must occur in one document in the declared order."""

    path: Path
    markers: tuple[str, ...]
    message: str


@dataclass(frozen=True)
class Finding:
    """One actionable documentation-contract finding."""

    path: Path
    line_number: int
    line: str
    message: str


SMUGGLE_REQUIRED_ERROR_CODES: tuple[str, ...] = (
    "invalid_smuggle_locale",
    "invalid_smuggle_extension",
    "invalid_smuggle_preset",
    "invalid_smuggle_payload_encoding",
    "invalid_smuggle_trigger_method",
    "invalid_smuggle_trigger_event",
    "invalid_smuggle_output_format",
    "invalid_smuggle_download_variant",
    "invalid_smuggle_page_template",
    "invalid_smuggle_delay",
    "invalid_smuggle_show_notice",
    "invalid_smuggle_null_byte",
    "invalid_smuggle_mime_type",
    "invalid_smuggle_configuration",
    "unknown_smuggle_parameter",
    "smuggle_field_too_long",
    "smuggle_source_not_found",
    "smuggle_source_too_large",
    "smuggle_temp_quota_exceeded",
    "invalid_smuggle_mode",
    "invalid_smuggle_encryption",
    "invalid_smuggle_query",
    "duplicate_smuggle_parameter",
    "invalid_smuggle_policy",
    "invalid_smuggle_download_name",
    "invalid_smuggle_title",
    "invalid_smuggle_message",
    "invalid_smuggle_cta_label",
)
SMUGGLE_ERROR_CODE_LIST_PATTERN = re.compile(
    r"Current SMUGGLE code tokens are (?P<codes>[\s\S]*?)\. Clients should",
    re.IGNORECASE,
)
SMUGGLE_413_RESPONSE_PATTERN = re.compile(
    r"\*\*Too large response \(413\):\*\*\s*```json\s*(?P<response>[\s\S]*?)```",
    re.IGNORECASE,
)
SMUGGLE_413_DETAILS = {
    "scope": "uploads",
    "resource": "upload",
    "actual_bytes": 10485761,
    "limit_bytes": 10485760,
}
GLOBAL_INTERNAL_ERROR_PATTERN = re.compile(
    r"stable\s+shared/global\s+`internal_error`\s+code\s+documents\s+handler\s+failures\s+"
    r"that\s+return\s+HTTP\s+500",
    re.IGNORECASE,
)
SMUGGLE_STATUS_500_PATTERN = re.compile(
    r"\*\*Status codes:\*\*[^\n]*`500`\s+Artifact\s+creation\s+failed",
    re.IGNORECASE,
)

CANONICAL_QUALITY_COMMANDS: tuple[str, ...] = (
    "ruff check xferry tests tools",
    "ruff format --check xferry tests tools",
    "mypy xferry",
)
QUALITY_COMMAND_PATHS: tuple[Path, ...] = (
    Path(".github/workflows/ci.yml"),
    Path("CONTRIBUTING.md"),
    Path(".github/PULL_REQUEST_TEMPLATE.md"),
)

SERVER_COMMAND_PATTERN = re.compile(
    r"(?:^[ \t]*(?:[-*][ \t]+)?|`)(?:sudo[ \t]+)?(?:exec[ \t]+)?"
    r"(?:python[ \t]+-m[ \t]+xferry|xferry)"
    r"(?:[ \t]*\\[ \t]*\r?\n[ \t]*|[ \t]+)"
    r"(?P<argument>--?[A-Za-z][\w-]*)",
    re.MULTILINE,
)
BASH_ARRAY_ASSIGNMENT_PATTERN = re.compile(
    r"^[ \t]*(?P<name>[A-Za-z_][A-Za-z0-9_]*)=\((?P<body>[\s\S]*?)^[ \t]*\)",
    re.MULTILINE,
)
SERVER_COMMAND_ARRAY_EXPANSION_PATTERN = re.compile(
    r"(?:^[ \t]*(?:[-*][ \t]+)?|`)(?:sudo[ \t]+)?(?:exec[ \t]+)?"
    r"(?:(?:[^\s`]+/)?python[ \t]+-m[ \t]+xferry|xferry)"
    r"(?:[ \t]*\\[ \t]*\r?\n[ \t]*|[ \t]+)"
    r"\"?\$\{(?P<name>[A-Za-z_][A-Za-z0-9_]*)\[@\]\}\"?",
    re.MULTILINE,
)
ROOT_CLI_FLAGS = frozenset({"-h", "--help", "--version"})

SMUGGLE_LEGACY_ASSERTION_PATHS = frozenset({Path("tools/browser_smoke.playwright.js")})
STALE_PATTERNS: tuple[StalePattern, ...] = (
    StalePattern(re.compile(r"--root\b"), "legacy CLI flag `--root`; use `--dir`"),
    StalePattern(
        re.compile(r"--max-upload\b(?!-)"),
        "legacy CLI flag `--max-upload`; use `--max-size`",
    ),
    StalePattern(re.compile(r"/notes/pubkey\b"), "removed Notepad public-key endpoint"),
    StalePattern(re.compile(r"\bX-Enc-Key\b"), "removed Secure Notepad encrypted key header"),
    StalePattern(re.compile(r"\bX-HMAC\b"), "removed Secure Notepad HMAC header"),
    StalePattern(re.compile(r"--no-info\b"), "removed CLI flag `--no-info`"),
    StalePattern(re.compile(r"(?<![\w-])--opsec\b"), "removed CLI flag `--opsec`"),
    StalePattern(re.compile(r"--sandbox\b"), "removed CLI flag `--sandbox`"),
    StalePattern(
        re.compile(r"(?<![\w/.-])(?:xferry|python\s+-m\s+xferry)\s+[^\n`]*--profile\b"),
        "removed xferry feature-profile flag; xferry now has one full method surface",
    ),
    StalePattern(
        re.compile(r"\bpython\s+tools/browser_smoke\.py(?:\s|[^\n`])*--profile\b"),
        "removed browser-smoke profile flag; use `python tools/browser_smoke.py --mode full`",
    ),
    StalePattern(
        re.compile(r"\bserver\.profile\b"),
        "removed config key `server.profile`; xferry now has one full method surface",
    ),
    StalePattern(
        re.compile(r"\bXFERRY_PROFILE\b"),
        "removed environment variable `XFERRY_PROFILE`; xferry now has one full method surface",
    ),
    StalePattern(
        re.compile(r"(?<![\w-])--advanced-upload\b"),
        "removed CLI flag `--advanced-upload`; advanced upload is part of the full surface",
    ),
    StalePattern(
        re.compile(r"\bexperimental[- ]only\b", re.IGNORECASE),
        "stale experimental-only availability claim; xferry has one full surface",
    ),
    StalePattern(
        re.compile(r"\bprofile[- ]gated\b", re.IGNORECASE),
        "stale profile-gated availability claim; launch presets do not gate methods",
    ),
    StalePattern(
        re.compile(r"\bselected\s+(?:feature\s+)?profile\b", re.IGNORECASE),
        "stale selected-profile discovery claim; use `PING.supported_methods`",
    ),
    StalePattern(
        re.compile(r"Advanced upload is enabled only by the `experimental` profile"),
        "stale advanced-upload profile gating wording",
    ),
    StalePattern(re.compile(r"ciphertext \+ metadata"), "stale Notepad recovery wording"),
    StalePattern(
        re.compile(r"xferry\[[^\]\n]*\bcrypto\b[^\]\n]*\]"),
        "stale crypto-extra guidance; cryptography is a default runtime dependency",
        ignored_paths=frozenset({Path("pyproject.toml")}),
    ),
    StalePattern(
        re.compile(r'\.\[[^"\]\n]*crypto[^"\]\n]*\]'),
        "stale active install command with compatibility-only `crypto` extra",
    ),
    StalePattern(
        re.compile(r"zero external dependencies", re.IGNORECASE),
        "stale zero-dependency runtime wording",
    ),
    StalePattern(
        re.compile(r"\bpure Python\b", re.IGNORECASE),
        "stale pure-Python runtime wording",
    ),
    StalePattern(
        re.compile(r"Optional cryptography", re.IGNORECASE),
        "stale optional-cryptography wording; cryptography is required",
    ),
    StalePattern(
        re.compile(r"Public access(?:\s+on port 443)?", re.IGNORECASE),
        "stale public-exposure shortcut; document external prerequisites",
    ),
    StalePattern(
        re.compile(r"\bDLP/proxy bypass\b", re.IGNORECASE),
        "stale SMUGGLE framing; avoid bypass wording",
    ),
    StalePattern(
        re.compile(
            r"(?:via\s+email\s+and\s+messengers|email(?:,|\s+and)\s+messengers)", re.IGNORECASE
        ),
        "stale SMUGGLE framing; avoid third-party delivery wording",
    ),
    StalePattern(
        re.compile(r"(?<![A-Za-z0-9_-])encrypt\s*=", re.IGNORECASE),
        "removed SMUGGLE encryption alias; use canonical `encryption=none|xor|aes`",
        ignored_paths=SMUGGLE_LEGACY_ASSERTION_PATHS,
    ),
    StalePattern(
        re.compile(r"\buse_constructor\b"),
        "removed SMUGGLE constructor selector; use canonical `mode=constructor`",
        ignored_paths=SMUGGLE_LEGACY_ASSERTION_PATHS,
    ),
    StalePattern(
        re.compile(r"\b(?:payload_encoding\s*=\s*)?b64\b", re.IGNORECASE),
        "removed SMUGGLE payload shorthand; use canonical `base64`",
        ignored_paths=SMUGGLE_LEGACY_ASSERTION_PATHS,
    ),
    StalePattern(
        re.compile(r"\btrigger_?alias(?:es)?\b", re.IGNORECASE),
        "removed SMUGGLE trigger alias discovery; use canonical `trigger_events`",
    ),
    StalePattern(
        re.compile(r"\bnpf-rar-archive-help\b"),
        "removed SMUGGLE archive template; use an advertised template",
    ),
    StalePattern(
        re.compile(r"Content-Length smuggling \(duplicate/negative CL\)", re.IGNORECASE),
        "stale Content-Length wording; identical duplicates are accepted",
    ),
    StalePattern(
        re.compile(r"\bpython\s+-m\s+src(?:\b|\.)"),
        "stale public module command `python -m src`; use `python -m xferry`",
    ),
    StalePattern(
        re.compile(r"\bfrom\s+src\s+import\b"),
        "stale public import path `from src`; use `from xferry`",
    ),
    StalePattern(
        re.compile(r"(?<![\w.])import\s+src\b"),
        "stale public import path `import src`; use `import xferry`",
    ),
    StalePattern(
        re.compile(r"/_xferry/advanced-routing\b"),
        "retired Advanced global routing endpoint; use token-scoped Advanced Sessions",
        allow_in_superseded_adr=True,
    ),
    StalePattern(
        re.compile(r"(?<![A-Za-z0-9_-])X-(?:D(?:-(?:[0-9]+|N))?|N)(?![A-Za-z0-9_-])"),
        "retired Advanced carrier header; use canonical `X-XFerry-*` headers",
        allow_in_superseded_adr=True,
    ),
    StalePattern(
        re.compile(r'"(?:d|n)"\s*:'),
        "retired Advanced structured-field alias; use canonical logical fields",
        allow_in_superseded_adr=True,
    ),
    StalePattern(
        re.compile(r"\balways-on fallback\b", re.IGNORECASE),
        "retired Advanced fallback; routing is session-token scoped",
        allow_in_superseded_adr=True,
    ),
    StalePattern(
        re.compile(r"\bprocess-(?:local|global)\s+(?:routing|prefix/decoder)", re.IGNORECASE),
        "retired Advanced process-global routing state",
        allow_in_superseded_adr=True,
    ),
)

REQUIRED_ADR_NAV_PATHS: tuple[str, ...] = tuple(f"ADR-{number:03d}" for number in range(1, 11))

ORDERED_MARKER_REQUIREMENTS: tuple[OrderedMarkersRequirement, ...] = (
    OrderedMarkersRequirement(
        Path("docs/quick-start.md"),
        (
            "## Install",
            "## Send a first file",
            "## Try a custom method",
            "## Stop and protect data",
        ),
        "quick start must keep source install, first file, custom method, and lifecycle ordered",
    ),
    OrderedMarkersRequirement(
        Path("docs/operations.md"),
        (
            "## Source process",
            "## Data layout",
            "## Docker from the checkout",
            "## Capacity",
            "## Health and diagnostics",
            "## Public services",
        ),
        "operations must keep lifecycle, storage, capacity, diagnostics, and service "
        "guidance ordered",
    ),
)

SEMANTIC_REQUIREMENTS: tuple[SemanticRequirement, ...] = (
    SemanticRequirement(
        Path("README.md"),
        re.compile(
            r"\A(?=[\s\S]*No GitHub Release, PyPI[\s\S]*GHCR[\s\S]*published)"
            r"(?=[\s\S]*python -m pip install \.)"
            r"(?=[\s\S]*xferry run --preset local --open)"
            r"(?=[\s\S]*web UI)(?=[\s\S]*curl --fail-with-body)"
            r"(?=[\s\S]*Advanced Session)(?=[\s\S]*SYNCDATA)"
            r"(?=[\s\S]*`none`[\s\S]*XOR[\s\S]*AES-256-GCM)[\s\S]*",
            re.IGNORECASE,
        ),
        "README must keep source installation, UI, curl, Advanced Sessions, custom "
        "methods, and crypto support discoverable",
    ),
    SemanticRequirement(
        Path("docs/quick-start.md"),
        re.compile(
            r"\A(?=[\s\S]*installed from source)"
            r"(?=[\s\S]*No GitHub Release, PyPI package[\s\S]*GHCR image)"
            r"(?=[\s\S]*git clone https://github\.com/kgmnotes/xferry\.git)"
            r"(?=[\s\S]*python -m pip install \.)"
            r"(?=[\s\S]*xferry run --preset local --open)"
            r"(?=[\s\S]*operations\.md)(?=[\s\S]*public-direct\.md)[\s\S]*",
            re.IGNORECASE,
        ),
        "quick start must remain source-first and link lifecycle and exposure guidance",
    ),
    SemanticRequirement(
        Path("SECURITY.md"),
        re.compile(
            r"\A(?=[\s\S]*authoriz\w*[\s\S]*test data)"
            r"(?=[\s\S]*## External exposure baseline)"
            r"(?=[\s\S]*TLS[\s\S]*Basic Auth[\s\S]*finite[\s\S]*quota)"
            r"(?=[\s\S]*server does not retain[\s\S]*client-derived AES key)[\s\S]*",
            re.IGNORECASE,
        ),
        "SECURITY must preserve authorized-use, external-exposure, and Notepad recovery boundaries",
    ),
    SemanticRequirement(
        Path("CONTRIBUTING.md"),
        re.compile(
            r"\A(?=[\s\S]*python -m pip install -e)"
            r"(?=[\s\S]*python tools/sync_docs\.py --check)"
            r"(?=[\s\S]*python tools/check_stale_docs\.py)"
            r"(?=[\s\S]*No release artifact is currently public)"
            r"(?=[\s\S]*source installation first)[\s\S]*",
            re.IGNORECASE,
        ),
        "CONTRIBUTING must preserve local checks, documentation sync, and source-first "
        "release status",
    ),
    SemanticRequirement(
        Path("docs/operations.md"),
        re.compile(
            r"\A(?=[\s\S]*public distribution[\s\S]*source-only)"
            r"(?=[\s\S]*uploads/)(?=[\s\S]*notes/)"
            r"(?=[\s\S]*body-memory-budget[\s\S]*not an[\s\S]*RSS ceiling)"
            r"(?=[\s\S]*docker compose)(?=[\s\S]*--volumes)"
            r"(?=[\s\S]*destructive)[\s\S]*",
            re.IGNORECASE,
        ),
        "operations must own source lifecycle, persistent data, capacity, and destructive cleanup",
    ),
    SemanticRequirement(
        Path("docs/public-direct.md"),
        re.compile(
            r"\A(?=[\s\S]*security\.md#external-exposure-baseline)"
            r"(?=[\s\S]*--write-sample-config)"
            r"(?=[\s\S]*--check-config)(?=[\s\S]*--print-config)"
            r"(?=[\s\S]*direct TCP peer)"
            r"(?=[\s\S]*no published binary or container image)[\s\S]*",
            re.IGNORECASE,
        ),
        "public-direct must defer to security policy and preserve validation and proxy boundaries",
    ),
    SemanticRequirement(
        Path("docs/threat-model.md"),
        re.compile(r"conflicting content lengths[\s\S]*identical duplicate values", re.IGNORECASE),
        "threat model must distinguish conflicting from identical duplicate Content-Length",
    ),
    SemanticRequirement(
        Path("API.md"),
        re.compile(r"Request Framing and Caps", re.IGNORECASE),
        "API docs must describe receive-layer header/body caps and framing behavior",
    ),
    SemanticRequirement(
        Path("API.md"),
        re.compile(
            r"\A(?=[\s\S]*one\s+unversioned\s+HTTP\s+API\s+shipped\s+by\s+the\s+current\s+0\.x\s+line)"
            r"(?=[\s\S]*HTTP/WebSocket\s+contract\s+shipped\s+by\s+XFerry\s+0\.x)[\s\S]*",
            re.IGNORECASE,
        ),
        "API must identify the unversioned HTTP/WebSocket contract shipped by XFerry 0.x",
    ),
    SemanticRequirement(
        Path("API.md"),
        re.compile(
            r"\A(?=[\s\S]*smuggle_capabilities)(?=[\s\S]*schema_version=1)"
            r"(?=[\s\S]*mode=simple\|constructor)(?=[\s\S]*encryption=none\|xor\|aes)"
            r"(?=[\s\S]*payload_encoding=base64)(?=[\s\S]*AES-256-GCM)"
            r"(?=[\s\S]*no AES-to-XOR or XOR-to-AES fallback)[\s\S]*",
            re.IGNORECASE,
        ),
        "API docs must describe the canonical schema-v1 SMUGGLE contract",
    ),
    SemanticRequirement(
        Path("API.md"),
        re.compile(
            r"requests[\s\S]+receive[\s\S]+response[\s\S]+worker"
            r"[\s\S]+storage[\s\S]+usage[\s\S]+quota_denials[\s\S]+scans"
            r"[\s\S]+advanced_upload[\s\S]+decode_rejections",
            re.IGNORECASE,
        ),
        "API docs must include finalized operational metrics fields",
    ),
    SemanticRequirement(
        Path("API.md"),
        re.compile(r"Notepad-specific encrypted blob limit", re.IGNORECASE),
        "API docs must describe the finalized Notepad encrypted-blob limit",
    ),
    SemanticRequirement(
        Path("API.md"),
        re.compile(r"Sec-Fetch-Site: cross-site", re.IGNORECASE),
        "API docs must describe the browser-origin mutation policy",
    ),
    SemanticRequirement(
        Path("API.md"),
        re.compile(
            r"script-src\s+'self'[\s\S]+style-src\s+'self'\s+'unsafe-inline'", re.IGNORECASE
        ),
        "API docs must describe the current HTML CSP contract",
    ),
    SemanticRequirement(
        Path("examples/advanced_upload_nginx.md"),
        re.compile(
            r"\A(?=[\s\S]*POST /_xferry/advanced-sessions)"
            r"(?=[\s\S]*GET /_xferry/advanced-sessions/current)"
            r"(?=[\s\S]*DELETE /_xferry/advanced-sessions/current)"
            r"(?=[\s\S]*X-XFerry-Advanced-Session)"
            r"(?=[\s\S]*\{\"prefix\":\"/advanced\",\"decoder\":\"auto\",\"diagnostic_headers\":true\})"
            r"(?=[\s\S]*curl --silent --show-error --fail-with-body)[\s\S]*",
            re.IGNORECASE,
        ),
        "Advanced nginx example must preserve the session journey and canonical payload",
    ),
    SemanticRequirement(
        Path("examples/advanced_upload_nginx.md"),
        re.compile(
            r"\{\"data\":\"aGVsbG8=\",\"encoding\":\"base64\",\"encryption\":\"none\",\"name\":\"hello\.txt\"\}"
            r"[\s\S]+none\|xor\|aes[\s\S]+AES-256-GCM[\s\S]+no AES-to-XOR or XOR-to-AES fallback",
            re.IGNORECASE,
        ),
        "Advanced nginx example must preserve canonical encryption semantics",
    ),
    SemanticRequirement(
        Path("examples/advanced_upload_nginx.md"),
        re.compile(
            r"\A(?![\s\S]*(?:--user|-u)(?:\s+|=)[\"']?\$credentials)"
            r"(?![\s\S]*(?:--header|-H)(?:\s+|=)[\"'][^\n]*X-XFerry-Advanced-Session[^\n]*\$advanced_token)"
            r"(?=[\s\S]*--config /run/secrets/xferry_curl\.conf --config -)[\s\S]*",
            re.IGNORECASE,
        ),
        "Advanced nginx example must keep secret-bearing curl options out of process argv",
    ),
    *(
        SemanticRequirement(
            Path(f"docs/ADR/{filename}"),
            re.compile(r"\*\*Status:\*\*\s+accepted", re.IGNORECASE),
            f"ADR-{number:03d} must exist and remain accepted",
        )
        for number, filename in (
            (1, "ADR-001-handler-registry.md"),
            (2, "ADR-002-payload-protection.md"),
            (3, "ADR-003-runtime-crypto-acme.md"),
            (4, "ADR-004-upload-containment.md"),
            (5, "ADR-005-thread-pool.md"),
            (6, "ADR-006-release-artifacts.md"),
            (7, "ADR-007-trusted-proxy-identity.md"),
            (8, "ADR-008-notepad-recovery.md"),
            (9, "ADR-009-api-client-compatibility.md"),
            (10, "ADR-010-methods-and-presets.md"),
        )
    ),
)


def relative_to_root(path: Path, repo_root: Path) -> Path:
    try:
        return path.relative_to(repo_root)
    except ValueError:
        return path


def expand_target(target: Path, repo_root: Path) -> Iterable[Path]:
    if not target.exists():
        return
    if target.is_file():
        yield target
        return
    for child in sorted(target.rglob("*")):
        relative = relative_to_root(child, repo_root)
        if child.is_file() and not any(part in SKIPPED_DIRS for part in relative.parts):
            yield child


def iter_check_paths(repo_root: Path, targets: Sequence[str] = DEFAULT_TARGETS) -> Iterable[Path]:
    for target in targets:
        target_path = Path(target)
        if not target_path.is_absolute():
            target_path = repo_root / target_path
        yield from expand_target(target_path, repo_root)


def targets_cover_path(path: Path, repo_root: Path, targets: Sequence[str]) -> bool:
    for target in targets:
        target_path = Path(target)
        if not target_path.is_absolute():
            target_path = repo_root / target_path
        relative_target = relative_to_root(target_path, repo_root)
        if relative_target == path or relative_target in path.parents:
            return True
    return False


def read_contract_text(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8")
    except (FileNotFoundError, UnicodeDecodeError):
        return None


def contract_finding(path: Path, message: str, line: str = "<contract mismatch>") -> Finding:
    return Finding(path=path, line_number=1, line=line, message=message)


def is_superseded_adr(path: Path, text: str) -> bool:
    return (
        path.parts[:2] == ("docs", "ADR")
        and re.search(
            r"^\s*-\s+\*\*Status:\*\*\s+superseded by ADR-\d+\s*$",
            text,
            re.IGNORECASE | re.MULTILINE,
        )
        is not None
    )


def first_bash_array_argument(body: str) -> str | None:
    for raw_line in body.splitlines():
        line = raw_line.strip()
        if line and not line.startswith("#"):
            return line.split(maxsplit=1)[0].rstrip("\\").strip("'\"")
    return None


def expanded_server_launch_findings(
    text: str, relative: Path, lines: Sequence[str]
) -> list[Finding]:
    arrays_by_name: dict[str, list[tuple[int, str | None]]] = {}
    for assignment in BASH_ARRAY_ASSIGNMENT_PATTERN.finditer(text):
        arrays_by_name.setdefault(assignment.group("name"), []).append(
            (assignment.start(), first_bash_array_argument(assignment.group("body")))
        )

    findings: list[Finding] = []
    for launch in SERVER_COMMAND_ARRAY_EXPANSION_PATTERN.finditer(text):
        assignments = arrays_by_name.get(launch.group("name"), [])
        preceding = [assignment for assignment in assignments if assignment[0] < launch.start()]
        if not preceding:
            continue
        first_argument = preceding[-1][1]
        if (
            not first_argument
            or not first_argument.startswith("-")
            or first_argument in ROOT_CLI_FLAGS
        ):
            continue
        line_number = text.count("\n", 0, launch.start()) + 1
        findings.append(
            Finding(
                path=relative,
                line_number=line_number,
                line=lines[line_number - 1].strip() if lines else "",
                message="server launch must use the `run` subcommand",
            )
        )
    return findings


def scan_file(path: Path, repo_root: Path) -> list[Finding]:
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return []
    relative = relative_to_root(path, repo_root)
    superseded_adr = is_superseded_adr(relative, text)
    lines = text.splitlines()
    findings: list[Finding] = []

    for line_number, line in enumerate(lines, start=1):
        for pattern in STALE_PATTERNS:
            if relative in pattern.ignored_paths:
                continue
            if superseded_adr and pattern.allow_in_superseded_adr:
                continue
            if pattern.regex.search(line):
                findings.append(Finding(relative, line_number, line.strip(), pattern.message))

    if superseded_adr:
        return findings
    for match in SERVER_COMMAND_PATTERN.finditer(text):
        if match.group("argument") in ROOT_CLI_FLAGS:
            continue
        line_number = text.count("\n", 0, match.start()) + 1
        if any(finding.line_number == line_number for finding in findings):
            continue
        findings.append(
            Finding(
                relative,
                line_number,
                lines[line_number - 1].strip() if lines else "",
                "server launch must use the `run` subcommand",
            )
        )
    findings.extend(expanded_server_launch_findings(text, relative, lines))
    return findings


def find_stale_references(
    repo_root: Path = REPO_ROOT,
    targets: Sequence[str] = DEFAULT_TARGETS,
) -> list[Finding]:
    return [
        finding
        for path in iter_check_paths(repo_root, targets)
        for finding in scan_file(path, repo_root)
    ]


def find_semantic_contract_issues(
    repo_root: Path = REPO_ROOT,
    targets: Sequence[str] = DEFAULT_TARGETS,
) -> list[Finding]:
    findings: list[Finding] = []
    for requirement in SEMANTIC_REQUIREMENTS:
        if not targets_cover_path(requirement.path, repo_root, targets):
            continue
        text = read_contract_text(repo_root / requirement.path)
        if text is None:
            findings.append(
                contract_finding(
                    requirement.path, f"{requirement.message}; required file is missing"
                )
            )
        elif requirement.regex.search(text) is None:
            findings.append(contract_finding(requirement.path, requirement.message))
    findings.extend(find_global_error_contract_issues(repo_root, targets))
    findings.extend(find_smuggle_error_contract_issues(repo_root, targets))
    findings.extend(find_smuggle_status_contract_issues(repo_root, targets))
    return findings


def find_global_error_contract_issues(repo_root: Path, targets: Sequence[str]) -> list[Finding]:
    path = Path("API.md")
    if not targets_cover_path(path, repo_root, targets):
        return []
    text = read_contract_text(repo_root / path)
    if text is not None and GLOBAL_INTERNAL_ERROR_PATTERN.search(text):
        return []
    return [contract_finding(path, "API docs must document the shared `internal_error` code")]


def find_smuggle_error_contract_issues(repo_root: Path, targets: Sequence[str]) -> list[Finding]:
    path = Path("API.md")
    if not targets_cover_path(path, repo_root, targets):
        return []
    text = read_contract_text(repo_root / path)
    if text is None:
        return []
    findings: list[Finding] = []
    code_list = SMUGGLE_ERROR_CODE_LIST_PATTERN.search(text)
    documented_codes = code_list.group("codes") if code_list else ""
    missing_codes = tuple(
        code for code in SMUGGLE_REQUIRED_ERROR_CODES if f"`{code}`" not in documented_codes
    )
    if missing_codes:
        findings.append(
            contract_finding(
                path,
                "API docs must provide the complete SMUGGLE error-code list; missing: "
                + ", ".join(missing_codes),
            )
        )
    response_match = SMUGGLE_413_RESPONSE_PATTERN.search(text)
    try:
        response = json.loads(response_match.group("response")) if response_match else None
    except json.JSONDecodeError:
        response = None
    if not (
        isinstance(response, dict)
        and isinstance(response.get("error"), dict)
        and response["error"].get("code") == "smuggle_source_too_large"
        and response["error"].get("details") == SMUGGLE_413_DETAILS
    ):
        findings.append(
            contract_finding(path, "API docs must use the current SMUGGLE 413 details object")
        )
    return findings


def find_smuggle_status_contract_issues(repo_root: Path, targets: Sequence[str]) -> list[Finding]:
    path = Path("API.md")
    if not targets_cover_path(path, repo_root, targets):
        return []
    text = read_contract_text(repo_root / path)
    if text is not None and SMUGGLE_STATUS_500_PATTERN.search(text):
        return []
    return [contract_finding(path, "SMUGGLE status table must document HTTP 500 failures")]


def find_ordered_contract_issues(
    repo_root: Path = REPO_ROOT,
    targets: Sequence[str] = DEFAULT_TARGETS,
) -> list[Finding]:
    findings: list[Finding] = []
    for requirement in ORDERED_MARKER_REQUIREMENTS:
        if not targets_cover_path(requirement.path, repo_root, targets):
            continue
        text = read_contract_text(repo_root / requirement.path)
        if text is None:
            findings.append(contract_finding(requirement.path, requirement.message))
            continue
        folded = text.casefold()
        offsets = tuple(folded.find(marker.casefold()) for marker in requirement.markers)
        if any(offset < 0 for offset in offsets) or offsets != tuple(sorted(offsets)):
            findings.append(contract_finding(requirement.path, requirement.message))
    return findings


def find_source_first_issues(
    repo_root: Path = REPO_ROOT,
    targets: Sequence[str] = DEFAULT_TARGETS,
) -> list[Finding]:
    path = Path("docs/quick-start.md")
    if not targets_cover_path(path, repo_root, targets):
        return []
    text = read_contract_text(repo_root / path)
    if text is None:
        return []
    folded = text.casefold()
    markers = (
        "git clone https://github.com/kgmnotes/xferry.git",
        "python -m pip install .",
        "xferry run --preset local --open",
    )
    offsets = tuple(folded.find(marker) for marker in markers)
    forbidden_routes = ("releases/latest", "ghcr.io/kgmnotes/xferry", "pip install xferry")
    if (
        any(offset < 0 for offset in offsets)
        or offsets != tuple(sorted(offsets))
        or any(marker in folded for marker in forbidden_routes)
    ):
        return [
            contract_finding(
                path, "source install must precede launch and exclude unpublished artifacts"
            )
        ]
    return []


def find_adr_navigation_issues(
    repo_root: Path = REPO_ROOT,
    targets: Sequence[str] = DEFAULT_TARGETS,
) -> list[Finding]:
    findings: list[Finding] = []
    for path in (Path("mkdocs.yml"), Path("docs/ADR/README.md")):
        if not targets_cover_path(path, repo_root, targets):
            continue
        text = read_contract_text(repo_root / path)
        if text is None:
            findings.append(contract_finding(path, "ADR navigation file is missing"))
        elif path == Path("mkdocs.yml") and "ADR/README.md" not in text:
            findings.append(contract_finding(path, "ADR index must be present in site navigation"))
        elif path.name == "README.md":
            for marker in REQUIRED_ADR_NAV_PATHS:
                if marker not in text:
                    findings.append(contract_finding(path, f"{marker} must be discoverable"))
    return findings


def find_contributor_command_issues(
    repo_root: Path = REPO_ROOT,
    targets: Sequence[str] = DEFAULT_TARGETS,
) -> list[Finding]:
    findings: list[Finding] = []
    for path in QUALITY_COMMAND_PATHS:
        if not targets_cover_path(path, repo_root, targets):
            continue
        text = read_contract_text(repo_root / path)
        if text is None:
            findings.append(contract_finding(path, "contributor/CI command authority is missing"))
            continue
        for command in CANONICAL_QUALITY_COMMANDS:
            if command not in text:
                findings.append(
                    contract_finding(path, f"quality command must match CI exactly: `{command}`")
                )
    return findings


def find_version_consistency_issues(
    repo_root: Path = REPO_ROOT,
    targets: Sequence[str] = DEFAULT_TARGETS,
) -> list[Finding]:
    config_path = Path("xferry/config.py")
    if not targets_cover_path(config_path, repo_root, targets):
        return []
    config_text = read_contract_text(repo_root / config_path)
    version_match = re.search(r'^__version__\s*=\s*"([^"]+)"', config_text or "", re.MULTILINE)
    if version_match is None:
        return [contract_finding(config_path, "xferry.config.__version__ must remain readable")]
    version = version_match.group(1)
    findings: list[Finding] = []

    html_path = Path("xferry/data/index.html")
    if targets_cover_path(html_path, repo_root, targets):
        html = read_contract_text(repo_root / html_path) or ""
        html_match = re.search(r'id="appVersion"\s+data-app-version="([^"]+)">v([^<]+)</p>', html)
        if html_match is None or html_match.groups() != (version, version):
            findings.append(
                contract_finding(html_path, f"UI version must match package version {version}")
            )

    readme_path = Path("README.md")
    if targets_cover_path(readme_path, repo_root, targets):
        readme = read_contract_text(repo_root / readme_path) or ""
        if f"version-{version}-orange.svg" not in readme:
            findings.append(
                contract_finding(readme_path, f"README badge must match package version {version}")
            )

    api_path = Path("API.md")
    if targets_cover_path(api_path, repo_root, targets):
        api = read_contract_text(repo_root / api_path) or ""
        if f'"server": "XFerry/{version}"' not in api:
            findings.append(
                contract_finding(
                    api_path, f"API server example must match package version {version}"
                )
            )

    changelog_path = Path("CHANGELOG.md")
    if targets_cover_path(changelog_path, repo_root, targets):
        changelog = read_contract_text(repo_root / changelog_path) or ""
        if f"## [{version}] - 2026-08-20" not in changelog:
            findings.append(
                contract_finding(
                    changelog_path, f"CHANGELOG must contain the {version} section dated 2026-08-20"
                )
            )
        sections = tuple(
            section
            for section in re.findall(r"^## \[([^]]+)](?:\s+-[^\n]*)?$", changelog, re.MULTILINE)
            if section.casefold() != "unreleased"
        )
        if set(sections) != {version}:
            findings.append(
                contract_finding(changelog_path, f"CHANGELOG must contain only version {version}")
            )

    pyproject_path = Path("pyproject.toml")
    if targets_cover_path(pyproject_path, repo_root, targets):
        pyproject = read_contract_text(repo_root / pyproject_path) or ""
        if 'version = {attr = "xferry.config.__version__"}' not in pyproject:
            findings.append(
                contract_finding(
                    pyproject_path, "package metadata must use xferry.config.__version__"
                )
            )
    return findings


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("targets", nargs="*", help="optional files or directories")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    targets = tuple(args.targets) if args.targets else DEFAULT_TARGETS
    findings = find_stale_references(REPO_ROOT, targets)
    findings.extend(find_semantic_contract_issues(REPO_ROOT, targets))
    findings.extend(find_ordered_contract_issues(REPO_ROOT, targets))
    findings.extend(find_source_first_issues(REPO_ROOT, targets))
    findings.extend(find_adr_navigation_issues(REPO_ROOT, targets))
    findings.extend(find_contributor_command_issues(REPO_ROOT, targets))
    findings.extend(find_version_consistency_issues(REPO_ROOT, targets))

    if not findings:
        print("No stale documented contract references found.")
        return 0
    print("Found stale documented contract references:", file=sys.stderr)
    for finding in findings:
        print(
            f"  - {finding.path}:{finding.line_number}: {finding.message}: {finding.line}",
            file=sys.stderr,
        )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
