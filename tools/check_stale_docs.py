#!/usr/bin/env python3
"""Reject stale references and missing contracts in active public documentation."""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import date
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


@dataclass(frozen=True)
class WorkflowJob:
    """One top-level GitHub Actions job extracted from workflow text."""

    name: str
    start_line: int
    text: str


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

WORKFLOW_ACTION_PATTERN = re.compile(
    r"^\s*(?:-\s+)?(?P<quote>[\"']?)uses(?P=quote):\s*(?P<reference>\S+)",
    re.MULTILINE,
)
WORKFLOW_COMMIT_SHA_PATTERN = re.compile(r"[0-9a-f]{40}")
RELEASE_TAG_FILTER_PATTERN = re.compile(
    r"^v(?:[0-9]+|\[0-9\][+*])\."
    r"(?:[0-9]+|\[0-9\][+*])\."
    r"(?:[0-9]+|\[0-9\][+*])$"
)
PUBLISHER_CHANNEL_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "pypi",
        re.compile(
            r"(?:pypa/gh-action-pypi-publish|twine\s+upload|"
            r"(?:uv|hatch)\s+publish)",
            re.IGNORECASE,
        ),
    ),
    (
        "ghcr",
        re.compile(
            r"(?:docker/(?:login|build-push)-action|docker\s+push|"
            r"ghcr\.io/kgmnotes/xferry)",
            re.IGNORECASE,
        ),
    ),
    (
        "github-release",
        re.compile(
            r"(?:softprops/action-gh-release|actions/upload-release-asset|"
            r"gh\s+release\s+(?:create|upload))",
            re.IGNORECASE,
        ),
    ),
)
PUBLISH_JOB_REBUILD_PATTERN = re.compile(
    r"(?:python(?:3)?\s+-m\s+build|docker\s+(?:build|buildx\s+build)|"
    r"docker/build-push-action|tools/build_scie_release\.py)",
    re.IGNORECASE,
)
PYPI_STATIC_CREDENTIAL_PATTERN = re.compile(
    r"(?:\$\{\{\s*secrets\.|PYPI(?:_API)?_TOKEN|TWINE_(?:PASSWORD|USERNAME))",
    re.IGNORECASE,
)

SMUGGLE_LEGACY_ASSERTION_PATHS = frozenset({Path("tools/browser_smoke.playwright.js")})
STALE_PATTERNS: tuple[StalePattern, ...] = (
    StalePattern(re.compile(r"--root\b"), "legacy CLI flag `--root`; use `--files-dir`"),
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
        re.compile(r"Public access\s+on port 443", re.IGNORECASE),
        "stale public-exposure shortcut; document external prerequisites",
    ),
    StalePattern(
        re.compile(r"\bDLP/proxy bypass\b", re.IGNORECASE),
        "stale SMUGGLE framing; avoid bypass wording",
    ),
    StalePattern(
        re.compile(r"\bQuarterly[- ]Report\b", re.IGNORECASE),
        "replace lure-style document naming with a neutral controlled-test artifact",
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

STALE_DOCUMENT_PATTERNS: tuple[StalePattern, ...] = (
    StalePattern(
        re.compile(
            r"(?:tag-triggered\s+publication|release\s+artifact\s+is\s+currently\s+public|"
            r"no\s+GitHub\s+Release,\s*PyPI|"
            r"no\s+published\s+(?:binary|container\s+image)[\s\S]{0,120}?at\s+this\s+time|"
            r"(?:before|until)\s+publication\s+exists)",
            re.IGNORECASE,
        ),
        "temporal publication wording must use the stage-owned availability contract",
    ),
)

REQUIRED_ADR_NAV_PATHS: tuple[str, ...] = tuple(f"ADR-{number:03d}" for number in range(1, 13))

ORDERED_MARKER_REQUIREMENTS: tuple[OrderedMarkersRequirement, ...] = (
    OrderedMarkersRequirement(
        Path("docs/quick-start.md"),
        (
            "## Portable",
            "## Managed Linux",
            "## Container",
            "## Send a first file",
            "## Stop and protect data",
        ),
        "quick start must keep portable, managed, container, first-success, and lifecycle ordered",
    ),
    OrderedMarkersRequirement(
        Path("docs/operations.md"),
        (
            "## Portable lifecycle",
            "## Managed Linux lifecycle",
            "## Container lifecycle",
            "## Data layout",
            "## Capacity",
            "## Health and diagnostics",
            "## Public services",
        ),
        "operations must keep all three lifecycles, storage, capacity, diagnostics, and "
        "service guidance ordered",
    ),
)

SEMANTIC_REQUIREMENTS: tuple[SemanticRequirement, ...] = (
    SemanticRequirement(
        Path("README.md"),
        re.compile(
            r"\A(?=[\s\S]*pipx install xferry)"
            r"(?=[\s\S]*managed-hosts\.md)"
            r"(?=[\s\S]*archive/0\.2\.0-installation\.md)"
            r"(?=[\s\S]*xferry run --open)"
            r"(?=[\s\S]*web UI)(?=[\s\S]*curl --fail-with-body)"
            r"(?=[\s\S]*Advanced Session)(?=[\s\S]*SYNCDATA)"
            r"(?=[\s\S]*`none`[\s\S]*XOR[\s\S]*AES-256-GCM)[\s\S]*",
            re.IGNORECASE,
        ),
        "README must route portable, managed and container users while keeping UI, curl, "
        "Advanced Sessions, custom methods, and crypto support discoverable",
    ),
    SemanticRequirement(
        Path("docs/quick-start.md"),
        re.compile(
            r"\A(?=[\s\S]*py -m pip install --user pipx)"
            r"(?![\s\S]*python3 -m pip install --user pipx)"
            r"(?=[\s\S]*sudo apt install pipx)"
            r"(?=[\s\S]*brew install pipx)"
            r"(?=[\s\S]*pipx ensurepath)"
            r"(?=[\s\S]*pipx install xferry)"
            r"(?=[\s\S]*xferry run --open)"
            r"(?=[\s\S]*managed-hosts\.md)"
            r"(?=[\s\S]*archive/0\.2\.0-installation\.md)"
            r"(?=[\s\S]*operations\.md)(?=[\s\S]*public-direct\.md)[\s\S]*",
            re.IGNORECASE,
        ),
        "quick start must provide platform-specific pipx bootstrap, portable first success, "
        "managed and "
        "immutable container paths",
    ),
    SemanticRequirement(
        Path("SECURITY.md"),
        re.compile(
            r"\A(?=[\s\S]*portable[\s\S]*managed[\s\S]*container)"
            r"(?=[\s\S]*immutable[\s\S]*version or digest)"
            r"(?=[\s\S]*authoriz\w*[\s\S]*test data)"
            r"(?=[\s\S]*## External exposure baseline)"
            r"(?=[\s\S]*TLS[\s\S]*Basic Auth[\s\S]*finite[\s\S]*quota)"
            r"(?=[\s\S]*server does not retain[\s\S]*client-derived AES key)[\s\S]*",
            re.IGNORECASE,
        ),
        "SECURITY must preserve authorized-use, external-exposure, and Notepad recovery boundaries",
    ),
    SemanticRequirement(
        Path("SECURITY.md"),
        re.compile(
            r"\A(?=[\s\S]*## Release and update supply chain)"
            r"(?=[\s\S]*protected `vX\.Y\.Z` tag)"
            r"(?=[\s\S]*exact[\s\S]*verified bytes or OCI digests)"
            r"(?=[\s\S]*full commit-SHA pins)"
            r"(?=[\s\S]*PyPI uses OIDC trusted publishing)"
            r"(?=[\s\S]*Designated release maintainers own signing-key custody)"
            r"(?=[\s\S]*Verification fails closed)[\s\S]*",
            re.IGNORECASE,
        ),
        "SECURITY must preserve controlled-publication and signing-key ownership controls",
    ),
    SemanticRequirement(
        Path("docs/threat-model.md"),
        re.compile(
            r"\A(?=[\s\S]*protected release tags and workflow definitions)"
            r"(?=[\s\S]*publisher identities[\s\S]*signing keys)"
            r"(?=[\s\S]*Branch or pull-request publication)"
            r"(?=[\s\S]*Candidate substitution or publish-job rebuild)"
            r"(?=[\s\S]*Installer or update metadata tampering)"
            r"(?=[\s\S]*protected `release-production`)"
            r"(?=[\s\S]*Rollback[\s\S]*previously verified)[\s\S]*",
            re.IGNORECASE,
        ),
        "threat model must preserve release, publisher, signing, installer, and update boundaries",
    ),
    SemanticRequirement(
        Path("CONTRIBUTING.md"),
        re.compile(
            r"\A(?=[\s\S]*python -m pip install -e)"
            r"(?=[\s\S]*source checkout is the contributor workflow)"
            r"(?=[\s\S]*python tools/sync_docs\.py --check)"
            r"(?=[\s\S]*python tools/check_stale_docs\.py)"
            r"(?=[\s\S]*generated\s+CLI\s+reference)"
            r"(?=[\s\S]*managed\s+support\s+matrix)[\s\S]*",
            re.IGNORECASE,
        ),
        "CONTRIBUTING must preserve local checks, contributor-source scope, and generated docs",
    ),
    SemanticRequirement(
        Path("CONTRIBUTING.md"),
        re.compile(
            r"\A(?=[\s\S]*PluginServices\(upload_dir, upload_storage\))"
            r"(?=[\s\S]*HandlerContext\(services, plugin_name\))"
            r"(?=[\s\S]*context\.server[\s\S]*without[\s\S]*compatibility shim)"
            r"(?=[\s\S]*upload_storage\.publish_bytes)"
            r"(?=[\s\S]*ordinary XHTML[\s\S]*attachment)"
            r"(?=[\s\S]*admission[\s\S]*authentication[\s\S]*before plugin dispatch)"
            r"[\s\S]*",
            re.IGNORECASE,
        ),
        "CONTRIBUTING must document the exact narrow plugin API and provenance boundary",
    ),
    SemanticRequirement(
        Path("docs/architecture.md"),
        re.compile(
            r"\A(?=[\s\S]*PluginServices\(upload_dir, upload_storage\))"
            r"(?=[\s\S]*HandlerContext\(services, plugin_name\))"
            r"(?=[\s\S]*no `context\.server` compatibility path)"
            r"(?=[\s\S]*admission[\s\S]*authentication[\s\S]*before[\s\S]*plugin dispatch)"
            r"(?=[\s\S]*ordinary XHTML[\s\S]*attachment)[\s\S]*",
            re.IGNORECASE,
        ),
        "architecture docs must preserve least-authority plugin services and provenance",
    ),
    SemanticRequirement(
        Path("pyproject.toml"),
        re.compile(
            r'\A(?![\s\S]*"(?:dlp|red-team)")'
            r'(?=[\s\S]*"security-research")'
            r'(?=[\s\S]*"authorized-testing")'
            r'(?=[\s\S]*"controlled-testing")'
            r'(?=[\s\S]*"http-testing")[\s\S]*',
            re.IGNORECASE,
        ),
        "package keywords must describe authorized, controlled security research",
    ),
    SemanticRequirement(
        Path("docs/operations.md"),
        re.compile(
            r"\A(?=[\s\S]*pipx upgrade xferry)(?=[\s\S]*pipx uninstall xferry)"
            r"(?=[\s\S]*xferry update --to (?:[0-9]+\.[0-9]+\.[0-9]+|VERSION))"
            r"(?=[\s\S]*xferry rollback)(?=[\s\S]*xferry uninstall)"
            r"(?=[\s\S]*ghcr\.io/kgmnotes/xferry@sha256:)"
            r"(?=[\s\S]*files_dir)(?=[\s\S]*notes/)"
            r"(?=[\s\S]*body_memory_budget_mb[\s\S]*not an[\s\S]*RSS ceiling)"
            r"(?=[\s\S]*docker compose)(?=[\s\S]*--volumes)"
            r"(?=[\s\S]*destructive)[\s\S]*",
            re.IGNORECASE,
        ),
        "operations must own portable, managed and container lifecycle plus persistent data",
    ),
    SemanticRequirement(
        Path("docs/public-direct.md"),
        re.compile(
            r"\A(?=[\s\S]*security\.md#external-exposure-baseline)"
            r"(?=[\s\S]*archive/0\.2\.0-installation\.md)"
            r"(?=[\s\S]*ghcr\.io/kgmnotes/xferry@sha256:)"
            r"(?=[\s\S]*xferry config check)"
            r"(?=[\s\S]*xferry config show --all)"
            r"(?=[\s\S]*direct TCP peer)[\s\S]*",
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
            (7, "ADR-007-trusted-proxy-identity.md"),
            (8, "ADR-008-notepad-recovery.md"),
            (9, "ADR-009-api-client-compatibility.md"),
            (10, "ADR-010-methods-and-presets.md"),
            (11, "ADR-011-controlled-distribution.md"),
            (12, "ADR-012-encrypted-streaming-transfers.md"),
        )
    ),
    SemanticRequirement(
        Path("docs/ADR/ADR-006-release-artifacts.md"),
        re.compile(r"\*\*Status:\*\*\s+superseded by ADR-011", re.IGNORECASE),
        "ADR-006 must remain recorded as superseded by ADR-011",
    ),
    SemanticRequirement(
        Path("docs/ADR/ADR-011-controlled-distribution.md"),
        re.compile(
            r"\A(?=[\s\S]*\*\*Supersedes:\*\* ADR-006)"
            r"(?=[\s\S]*Portable CLI[\s\S]*PyPI)"
            r"(?=[\s\S]*Container[\s\S]*GHCR)"
            r"(?=[\s\S]*Managed Linux[\s\S]*GitHub Release)"
            r"(?=[\s\S]*protected version-tag refs)"
            r"(?=[\s\S]*publisher jobs must not rebuild)"
            r"(?=[\s\S]*protected `release-production`)"
            r"(?=[\s\S]*OIDC trusted publishing)"
            r"(?=[\s\S]*Signing and key ownership)"
            r"(?=[\s\S]*Rollback and incident response)"
            r"(?=[\s\S]*Documentation ownership)[\s\S]*",
            re.IGNORECASE,
        ),
        "ADR-011 must preserve all controlled-distribution journeys and launch invariants",
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


def _workflow_jobs(text: str) -> tuple[WorkflowJob, ...]:
    jobs_marker = re.search(
        r"^(?P<quote>[\"']?)jobs(?P=quote):\s*$",
        text,
        re.MULTILINE,
    )
    if jobs_marker is None:
        return ()
    matches = tuple(
        match
        for match in re.finditer(
            r"^  (?P<quote>[\"']?)(?P<name>[A-Za-z_][A-Za-z0-9_-]*)"
            r"(?P=quote):\s*(?:#.*)?$",
            text[jobs_marker.end() :],
            re.MULTILINE,
        )
    )
    jobs: list[WorkflowJob] = []
    offset = jobs_marker.end()
    for index, match in enumerate(matches):
        start = offset + match.start()
        end = offset + matches[index + 1].start() if index + 1 < len(matches) else len(text)
        jobs.append(
            WorkflowJob(
                name=match.group("name"),
                start_line=text.count("\n", 0, start) + 1,
                text=text[start:end],
            )
        )
    return tuple(jobs)


def _workflow_step_with_id(job_text: str, step_id: str) -> str | None:
    marker = f"\n        id: {step_id}\n"
    for step in re.split(r"(?=^      - )", job_text, flags=re.MULTILINE):
        if marker in f"\n{step}\n":
            return step
    return None


def _permission_entries(
    text: str,
    indent: int,
) -> tuple[bool, tuple[tuple[str, str, int], ...]]:
    lines = text.splitlines()
    marker = re.compile(
        rf"^ {{{indent}}}(?P<quote>[\"']?)permissions(?P=quote):\s*"
        r"(?P<value>[^#]*?)\s*(?:#.*)?$"
    )
    for index, line in enumerate(lines):
        match = marker.match(line)
        if match is None:
            continue
        inline_value = match.group("value").strip().strip("\"'")
        if inline_value:
            if inline_value.startswith("{") and inline_value.endswith("}"):
                inline_entries: list[tuple[str, str, int]] = []
                body = inline_value[1:-1].strip()
                if not body:
                    return True, ()
                for item in body.split(","):
                    scope, separator, access = item.partition(":")
                    if not separator:
                        return True, (("*", inline_value, index + 1),)
                    inline_entries.append(
                        (
                            scope.strip().strip("\"'"),
                            access.strip().strip("\"'"),
                            index + 1,
                        )
                    )
                return True, tuple(inline_entries)
            return True, (("*", inline_value, index + 1),)

        entries: list[tuple[str, str, int]] = []
        for child_index in range(index + 1, len(lines)):
            child = lines[child_index]
            stripped = child.strip()
            if not stripped or stripped.startswith("#"):
                continue
            child_indent = len(child) - len(child.lstrip())
            if child_indent <= indent:
                break
            if child_indent != indent + 2:
                continue
            entry = re.match(
                r"^[A-Za-z0-9_-]+:\s*[^#]+",
                stripped,
            )
            if entry is None:
                continue
            scope, access = stripped.split(":", maxsplit=1)
            entries.append((scope, access.split("#", maxsplit=1)[0].strip(), child_index + 1))
        return True, tuple(entries)
    return False, ()


def _workflow_events(text: str) -> tuple[frozenset[str], str]:
    lines = text.splitlines()
    try:
        on_index = lines.index("on:")
    except ValueError:
        return frozenset(), ""

    event_lines: list[str] = []
    for line in lines[on_index + 1 :]:
        if line.strip() and len(line) - len(line.lstrip()) == 0:
            break
        event_lines.append(line)

    events: set[str] = set()
    push_lines: list[str] = []
    in_push = False
    for line in event_lines:
        indent = len(line) - len(line.lstrip())
        event = re.match(
            r"^  (?P<quote>[\"']?)(?P<name>[A-Za-z0-9_-]+)(?P=quote):",
            line,
        )
        if event is not None:
            name = event.group("name")
            events.add(name)
            in_push = name == "push"
            if in_push:
                push_lines.append(line)
            continue
        if in_push:
            if line.strip() and indent <= 2:
                in_push = False
            else:
                push_lines.append(line)
    return frozenset(events), "\n".join(push_lines)


def _push_tag_filters(push_block: str) -> tuple[str, ...]:
    lines = push_block.splitlines()
    for index, line in enumerate(lines):
        match = re.match(
            r"^    (?P<quote>[\"']?)tags(?P=quote):\s*"
            r"(?P<value>[^#]*?)\s*(?:#.*)?$",
            line,
        )
        if match is None:
            continue
        inline = match.group("value").strip()
        if inline:
            if inline.startswith("[") and inline.endswith("]"):
                inline = inline[1:-1]
                return tuple(
                    item.strip().strip("\"'") for item in inline.split(",") if item.strip()
                )
            return (inline.strip("\"'"),)

        filters: list[str] = []
        for child in lines[index + 1 :]:
            if not child.strip() or child.lstrip().startswith("#"):
                continue
            indent = len(child) - len(child.lstrip())
            if indent <= 4:
                break
            item = re.match(r"^      -\s*(?P<value>[^#]+?)\s*(?:#.*)?$", child)
            if item is not None:
                filters.append(item.group("value").strip().strip("\"'"))
        return tuple(filters)
    return ()


def _publisher_channels(job: WorkflowJob) -> frozenset[str]:
    return frozenset(
        channel for channel, pattern in PUBLISHER_CHANNEL_PATTERNS if pattern.search(job.text)
    )


def _uses_named_environment(job: WorkflowJob, name: str) -> bool:
    escaped = re.escape(name)
    if re.search(
        r"^    (?P<quote>[\"']?)environment(?P=quote):\s*"
        rf"[\"']?{escaped}[\"']?\s*(?:#.*)?$",
        job.text,
        re.MULTILINE,
    ):
        return True
    match = re.search(
        r"^    (?P<quote>[\"']?)environment(?P=quote):\s*$",
        job.text,
        re.MULTILINE,
    )
    if match is None:
        return False
    environment_block = job.text[match.end() :]
    end = re.search(r"^    \S", environment_block, re.MULTILINE)
    if end is not None:
        environment_block = environment_block[: end.start()]
    return (
        re.search(
            rf"^      name:\s*[\"']?{escaped}[\"']?\s*(?:#.*)?$",
            environment_block,
            re.MULTILINE,
        )
        is not None
    )


def _uses_production_environment(job: WorkflowJob) -> bool:
    return _uses_named_environment(job, "release-production")


def _job_dependencies(job: WorkflowJob) -> frozenset[str] | None:
    """Read a literal dependency list; reject expressions and ambiguous YAML."""
    matches = tuple(re.finditer(r"^    needs:\s*([^\n#]+)(?:\s*#.*)?$", job.text, re.MULTILINE))
    if len(matches) != 1:
        return None
    value = matches[0].group(1).strip()
    if value.startswith("[") and value.endswith("]"):
        entries = tuple(item.strip().strip("\"'") for item in value[1:-1].split(","))
    else:
        entries = (value.strip("\"'"),)
    if not entries or any(
        re.fullmatch(r"[A-Za-z_][A-Za-z0-9_-]*", item) is None for item in entries
    ):
        return None
    if len(set(entries)) != len(entries):
        return None
    return frozenset(entries)


def release_workflow_policy_findings(
    text: str,
    path: Path = Path(".github/workflows/release.yml"),
) -> list[Finding]:
    """Validate both the current no-publish and future controlled-publish modes."""
    findings: list[Finding] = []
    lines = text.splitlines()

    for match in WORKFLOW_ACTION_PATTERN.finditer(text):
        reference = match.group("reference").strip("\"'")
        if reference.startswith("./"):
            continue
        action, separator, revision = reference.partition("@")
        if separator and WORKFLOW_COMMIT_SHA_PATTERN.fullmatch(revision):
            continue
        line_number = text.count("\n", 0, match.start()) + 1
        received = revision if separator else "(missing ref)"
        findings.append(
            Finding(
                path,
                line_number,
                lines[line_number - 1].strip() if lines else "",
                f"external actions must use a lowercase 40-hex commit SHA; "
                f"{action} uses {received}",
            )
        )

    _, workflow_permissions = _permission_entries(text, 0)
    for _scope, access, line_number in workflow_permissions:
        if access.casefold() == "write-all" or access.casefold() == "write":
            findings.append(
                Finding(
                    path,
                    line_number,
                    lines[line_number - 1].strip() if lines else "",
                    "workflow-level write permission is forbidden; scope writes to one "
                    "protected publisher job",
                )
            )

    jobs = _workflow_jobs(text)
    publishers = tuple((job, channels) for job in jobs if (channels := _publisher_channels(job)))
    if not publishers:
        return findings

    publisher_names = {job.name for job, _channels in publishers}
    for job in jobs:
        if job.name not in publisher_names and _uses_production_environment(job):
            findings.append(
                Finding(
                    path,
                    job.start_line,
                    job.text.splitlines()[0].strip(),
                    "`release-production` must be referenced only by publisher jobs; "
                    f"{job.name!r} is not a publisher",
                )
            )

    events, push_block = _workflow_events(text)
    if "pull_request" in events or "pull_request_target" in events:
        findings.append(contract_finding(path, "pull-request publication is forbidden"))
    tag_filters = _push_tag_filters(push_block)
    if (
        events != frozenset({"push"})
        or not tag_filters
        or any(RELEASE_TAG_FILTER_PATTERN.fullmatch(item) is None for item in tag_filters)
        or re.search(r"^    [\"']?tags-ignore[\"']?:", push_block, re.MULTILINE)
        or re.search(r"^    [\"']?branches(?:-ignore)?[\"']?:", push_block, re.MULTILINE)
    ):
        findings.append(
            contract_finding(
                path,
                "publisher workflows require exact `vX.Y.Z` version tag filters on a "
                "version-tag-only push trigger",
            )
        )

    for job, channels in publishers:
        line = job.text.splitlines()[0].strip()

        if not _uses_production_environment(job):
            findings.append(
                Finding(
                    path,
                    job.start_line,
                    line,
                    f"publisher job {job.name!r} must use the protected "
                    "`release-production` environment",
                )
            )
        if re.search(r"^    [\"']?needs[\"']?:", job.text, re.MULTILINE) is None or (
            "actions/download-artifact@" not in job.text
        ):
            findings.append(
                Finding(
                    path,
                    job.start_line,
                    line,
                    f"publisher job {job.name!r} must consume an exact previously built artifact",
                )
            )
        if PUBLISH_JOB_REBUILD_PATTERN.search(job.text):
            findings.append(
                Finding(
                    path,
                    job.start_line,
                    line,
                    f"publisher job {job.name!r} must not rebuild release artifacts",
                )
            )

        has_permissions, job_permissions = _permission_entries(job.text, 4)
        if not has_permissions:
            findings.append(
                Finding(
                    path,
                    job.start_line,
                    line,
                    f"publisher job {job.name!r} must declare explicit least-privilege permissions",
                )
            )
            job_permissions = ()
        granted_writes = {
            scope
            for scope, access, _ in job_permissions
            if access.casefold() in {"write", "write-all"}
        }
        required_writes: set[str] = set()
        if "pypi" in channels:
            required_writes.add("id-token")
        if "ghcr" in channels:
            required_writes.add("packages")
        if "github-release" in channels:
            required_writes.add("contents")
        if re.search(r"(?:actions/attest|sigstore|cosign)", job.text, re.IGNORECASE):
            required_writes.add("id-token")
        if "actions/attest" in job.text:
            required_writes.add("attestations")

        if "*" in granted_writes or granted_writes - required_writes:
            findings.append(
                Finding(
                    path,
                    job.start_line,
                    line,
                    f"publisher job {job.name!r} grants broad or unrelated write permissions",
                )
            )
        if required_writes - granted_writes:
            missing = ", ".join(sorted(required_writes - granted_writes))
            findings.append(
                Finding(
                    path,
                    job.start_line,
                    line,
                    f"publisher job {job.name!r} is missing required write permissions: {missing}",
                )
            )

        if "pypi" in channels:
            if PYPI_STATIC_CREDENTIAL_PATTERN.search(job.text):
                findings.append(
                    Finding(
                        path,
                        job.start_line,
                        line,
                        f"publisher job {job.name!r} must not use a static PyPI credential",
                    )
                )
            if "pypa/gh-action-pypi-publish" not in job.text:
                findings.append(
                    Finding(
                        path,
                        job.start_line,
                        line,
                        f"publisher job {job.name!r} must use PyPI trusted publishing",
                    )
                )
    return findings


def production_release_workflow_policy_findings(
    text: str,
    path: Path = Path(".github/workflows/release-production.yml"),
) -> list[Finding]:
    """Validate the production tag workflow's approval and publisher boundaries."""
    findings: list[Finding] = []
    lines = text.splitlines()

    def reject(reason: str) -> None:
        findings.append(contract_finding(path, reason))

    for match in WORKFLOW_ACTION_PATTERN.finditer(text):
        reference = match.group("reference").strip("\"'")
        if reference.startswith("./"):
            continue
        action, separator, revision = reference.partition("@")
        if separator and WORKFLOW_COMMIT_SHA_PATTERN.fullmatch(revision):
            continue
        line_number = text.count("\n", 0, match.start()) + 1
        received = revision if separator else "(missing ref)"
        findings.append(
            Finding(
                path,
                line_number,
                lines[line_number - 1].strip() if lines else "",
                f"external actions must use a lowercase 40-hex commit SHA; "
                f"{action} uses {received}",
            )
        )

    _, workflow_permissions = _permission_entries(text, 0)
    for _scope, access, line_number in workflow_permissions:
        if access.casefold() == "write-all" or access.casefold() == "write":
            findings.append(
                Finding(
                    path,
                    line_number,
                    lines[line_number - 1].strip() if lines else "",
                    "workflow-level write permission is forbidden; scope writes to one "
                    "protected publisher job",
                )
            )

    events, push_block = _workflow_events(text)
    tag_filters = _push_tag_filters(push_block)
    if (
        events != frozenset({"push"})
        or tag_filters != ("v*.*.*",)
        or re.search(r"^    [\"']?tags-ignore[\"']?:", push_block, re.MULTILINE)
        or re.search(r"^    [\"']?branches(?:-ignore)?[\"']?:", push_block, re.MULTILINE)
    ):
        reject(
            "production release requires exact `vX.Y.Z` version tag filters on a "
            "version-tag-only push trigger"
        )
    if "workflow_dispatch:" in text or "pull_request:" in text or "branches:" in text:
        reject("production release must not have manual, PR, or branch triggers")
    if 'test "$GITHUB_REF_PROTECTED" = "true"' not in text:
        reject("production release must fail closed unless the tag ref is protected")
    if "uses: ./.github/workflows/release.yml" not in text:
        reject("production release must build candidates through the reusable candidate workflow")
    if "actions/deploy-pages" in text or "pages: write" in text:
        reject("production release must not deploy Pages before final evidence")
    if "skip-existing" in text or "docker build" in text or "docker/build-push-action" in text:
        reject("production publishers must not skip existing files or rebuild artifacts")

    jobs = {job.name: job for job in _workflow_jobs(text)}
    required_dependencies = {
        "candidate": {"preflight"},
        "prepare-candidate": {"preflight", "candidate"},
        "native-readiness": {"preflight", "candidate"},
        "production-readiness": {"preflight", "candidate", "prepare-candidate", "native-readiness"},
        "sign-assets": {"preflight", "prepare-candidate", "production-readiness"},
        "create-draft-release": {"preflight", "sign-assets"},
        "publish-pypi": {"preflight", "prepare-candidate", "create-draft-release"},
        "verify-pypi-identity": {"preflight", "prepare-candidate", "publish-pypi"},
        "post-pypi": {"preflight", "publish-pypi", "verify-pypi-identity"},
        "publish-ghcr": {"preflight", "prepare-candidate", "publish-pypi", "post-pypi"},
        "post-ghcr": {"preflight", "publish-ghcr"},
        "publish-github-release": {
            "preflight",
            "prepare-candidate",
            "sign-assets",
            "create-draft-release",
            "publish-ghcr",
            "post-pypi",
            "post-ghcr",
        },
        "post-release": {
            "preflight",
            "sign-assets",
            "create-draft-release",
            "publish-github-release",
        },
        "post-managed": {"preflight", "post-release"},
        "final-gate": {
            "post-pypi",
            "post-ghcr",
            "post-release",
            "production-readiness",
            "post-managed",
        },
    }
    required_jobs = {"preflight", *required_dependencies}
    for name in sorted(required_jobs - set(jobs)):
        reject(f"production release workflow is missing job {name!r}")

    for name, required in required_dependencies.items():
        job = jobs.get(name)
        dependencies = _job_dependencies(job) if job is not None else None
        if dependencies is None or not required.issubset(dependencies):
            reject(f"production job {name!r} must depend on {', '.join(sorted(required))}")

    for name in sorted(required_jobs & jobs.keys()):
        job = jobs[name]
        # Preflight admits owner tag pushes; final-gate deliberately runs after
        # failures and checks each result. Every intermediate job must inherit
        # Actions' default success() dependency condition.
        if name not in {"preflight", "final-gate"} and re.search(
            r"^    (?P<quote>[\"']?)if(?P=quote):", job.text, re.MULTILINE
        ):
            reject(f"production job {name!r} must not bypass successful dependencies")
        # A skipped verification step can still leave its job green. Do not
        # allow conditional or tolerated steps anywhere along the release chain.
        if re.search(
            r"^(?:    |        |      - )(?P<quote>[\"']?)"
            r"continue-on-error(?P=quote):",
            job.text,
            re.MULTILINE,
        ):
            reject(f"production job {name!r} must not suppress job or step failures")
        if re.search(
            r"^(?:        |      - )(?P<quote>[\"']?)if(?P=quote):",
            job.text,
            re.MULTILINE,
        ):
            reject(f"production job {name!r} must not skip required steps")
        # These explicit shell suppressors defeat a successful dependency DAG.
        # Keep fail-closed if/! absence probes and the signer's shred || rm
        # cleanup fallback valid; neither turns a failed gate into success.
        execution_text = "\n".join(
            line for line in job.text.splitlines() if not line.lstrip().startswith("#")
        )
        if re.search(
            r"\|\|(?:\s|\\\r?\n)*(?:true\b|:(?=\s|;|$)|echo\b|printf\b|"
            r"(?:exit|return)\s+0\b|continue\b|break\b)"
            r"|^\s*set\s+[^\n]*(?:\+[a-zA-Z]*e[a-zA-Z]*(?=\s|;|$)|"
            r"\+o\s+(?:errexit|pipefail)\b)",
            execution_text,
            re.MULTILINE,
        ):
            reject(f"production job {name!r} must not mask shell failures")

    pypi_consumer = jobs.get("post-pypi")
    if pypi_consumer is not None:
        checkout = pypi_consumer.text.find("actions/checkout@")
        bootstrap = pypi_consumer.text.find("python -m pip install pipx")
        if checkout < 0 or bootstrap < 0 or checkout > bootstrap:
            reject("public pipx checks must materialize constraints before pip bootstrap")
        if "ref: ${{ needs.preflight.outputs.source-commit }}" not in pypi_consumer.text:
            reject("public pipx checks must checkout the exact release source")
    ghcr_consumer = jobs.get("post-ghcr")
    if ghcr_consumer is not None and re.search(
        r"(?:GH_TOKEN|github.token|docker\s+login|packages:\s*read)", ghcr_consumer.text
    ):
        reject("public GHCR checks must prove anonymous access without registry credentials")

    sign = jobs.get("sign-assets")
    if sign is not None:
        if not _uses_named_environment(sign, "production-release"):
            reject("signing job must use the protected `production-release` environment")
        if "XFERRY_RELEASE_ED25519_PRIVATE_KEY_PEM" not in sign.text:
            reject("signing job does not consume the protected signing key")

    private_key = "XFERRY_RELEASE_ED25519_PRIVATE_KEY_PEM"
    for name, job in jobs.items():
        if name != "sign-assets" and private_key in job.text:
            findings.append(
                Finding(
                    path,
                    job.start_line,
                    job.text.splitlines()[0].strip(),
                    f"private signing key must not escape into job {name!r}",
                )
            )

    publisher_writes = {
        "create-draft-release": {"contents"},
        "publish-pypi": {"id-token"},
        "publish-ghcr": {"packages"},
        "publish-github-release": {"contents"},
    }
    for name, required_writes in publisher_writes.items():
        job = jobs.get(name)
        if job is None:
            continue
        line = job.text.splitlines()[0].strip()
        if not _uses_production_environment(job):
            findings.append(
                Finding(
                    path,
                    job.start_line,
                    line,
                    f"production publisher job {name!r} must use the protected "
                    "`release-production` environment",
                )
            )
        if re.search(r"^    [\"']?needs[\"']?:", job.text, re.MULTILINE) is None:
            findings.append(
                Finding(
                    path,
                    job.start_line,
                    line,
                    f"production publisher job {name!r} must depend on verified handoff jobs",
                )
            )
        has_permissions, job_permissions = _permission_entries(job.text, 4)
        if not has_permissions:
            findings.append(
                Finding(
                    path,
                    job.start_line,
                    line,
                    f"production publisher job {name!r} must declare explicit permissions",
                )
            )
            continue
        granted_writes = {
            scope
            for scope, access, _ in job_permissions
            if access.casefold() in {"write", "write-all"}
        }
        if "*" in granted_writes or granted_writes != required_writes:
            findings.append(
                Finding(
                    path,
                    job.start_line,
                    line,
                    f"production publisher job {name!r} must grant only "
                    f"{', '.join(sorted(required_writes))}: write",
                )
            )
        if name == "publish-pypi":
            if PYPI_STATIC_CREDENTIAL_PATTERN.search(job.text):
                findings.append(
                    Finding(
                        path,
                        job.start_line,
                        line,
                        "production PyPI publisher must not use a static credential",
                    )
                )
            if "pypa/gh-action-pypi-publish" not in job.text:
                findings.append(
                    Finding(
                        path,
                        job.start_line,
                        line,
                        "production PyPI publisher must use trusted publishing",
                    )
                )

    for name, job in jobs.items():
        if name not in publisher_writes and _uses_production_environment(job):
            findings.append(
                Finding(
                    path,
                    job.start_line,
                    job.text.splitlines()[0].strip(),
                    f"`release-production` must be referenced only by publisher jobs; "
                    f"{name!r} is not a publisher",
                )
            )

    for name, workflow in (
        ("native-readiness", "managed-systemd-matrix.yml"),
        ("post-managed", "managed-public-matrix.yml"),
    ):
        job = jobs.get(name)
        if job is not None:
            permissions = {
                scope: access for scope, access, _ in _permission_entries(job.text, 4)[1]
            }
            if permissions != {
                "contents": "read",
                "actions": "read",
                "id-token": "write",
                "attestations": "write",
            }:
                reject(f"{name} must grant only source/artifact reads and OIDC attestations")
            if f"uses: ./.github/workflows/{workflow}" not in job.text:
                reject(f"{name} must use the dedicated native evidence workflow")
    readiness = jobs.get("production-readiness")
    if readiness is not None and any(
        marker not in readiness.text
        for marker in (
            "python tools/install_attestation_cli.py",
            "python tools/production_readiness.py verify-native",
            "needs.native-readiness.outputs.artifact-id",
            "needs.native-readiness.outputs.evidence-sha256",
            '--workflow-attempt "$GITHUB_RUN_ATTEMPT"',
            '--source-commit "$SOURCE_COMMIT"',
            "ref: ${{ needs.preflight.outputs.source-commit }}",
        )
    ):
        reject("production readiness must cryptographically verify exact-source native evidence")
    if readiness is not None and (
        "continue-on-error:" in readiness.text or "\n    if:" in readiness.text
    ):
        reject("production readiness must not bypass failed evidence")
    final_gate = jobs.get("final-gate")
    if final_gate is not None and (
        any(
            marker not in final_gate.text
            for marker in (
                "Pages deployment remains forbidden until all post-publish evidence passes",
                "MANAGED_RESULT: ${{ needs.post-managed.result }}",
                'test "$MANAGED_RESULT" = success',
            )
        )
    ):
        reject("final gate must keep Pages blocked until post-publish evidence passes")
    return findings


def docs_pages_workflow_policy_findings(text: str) -> list[Finding]:
    """Allow source merges while gating public docs on production evidence."""
    path = Path(".github/workflows/docs-pages.yml")
    findings: list[Finding] = []

    def reject(reason: str) -> None:
        findings.append(contract_finding(path, reason))

    events, push = _workflow_events(text)
    if events != frozenset({"push", "workflow_dispatch"}) or "branches: [main]" not in push:
        reject("Pages requires main-only builds and explicit production-evidence dispatch")
    declared, permissions = _permission_entries(text, 0)
    if not declared or {scope: access for scope, access, _ in permissions} not in (
        {},
        {"contents": "read"},
    ):
        reject("Pages workflow permissions must default to read-only or no permissions")
    jobs = {job.name: job for job in _workflow_jobs(text)}
    if not {"build", "publication-gate", "deploy"}.issubset(jobs):
        reject("Pages requires separate build, publication-gate and deploy jobs")
        return findings
    for name, job in jobs.items():
        _, granted = _permission_entries(job.text, 4)
        writes = {scope for scope, access, _ in granted if access == "write"}
        if name == "deploy":
            if writes != {"pages", "id-token"}:
                reject("only the Pages deploy job may grant pages/id-token write")
        elif writes:
            reject(f"Pages job {name!r} must remain read-only")
    for name in ("publication-gate", "deploy"):
        job = jobs[name]
        if not all(
            marker in job.text
            for marker in (
                "github.event_name == 'workflow_dispatch'",
                "github.ref == 'refs/heads/main'",
                "github.repository == 'kgmnotes/xferry'",
            )
        ):
            reject(f"Pages job {name!r} must require an explicit main dispatch in the owner repo")
    deploy_dependencies = _job_dependencies(jobs["deploy"])
    if deploy_dependencies is None or not {"build", "publication-gate"}.issubset(
        deploy_dependencies
    ):
        reject("Pages deployment must depend on both strict build and successful publication gate")
    if not _uses_named_environment(jobs["deploy"], "github-pages"):
        reject("Pages deploy must use the protected github-pages environment")
    if "python tools/docs_publication.py" not in jobs["publication-gate"].text:
        reject("Pages publication gate must verify production and public channel evidence")
    if "python tools/install_attestation_cli.py" not in jobs["publication-gate"].text:
        reject("Pages publication gate must install the pinned cryptographic evidence verifier")
    for job in jobs.values():
        if "actions/deploy-pages@" in job.text and job.name != "deploy":
            reject("Pages publication must be isolated to the gated deploy job")
        if "actions/upload-pages-artifact@" in job.text and job.name == "build":
            dependencies = _job_dependencies(job)
            if dependencies is None or "publication-gate" not in dependencies:
                reject("Pages artifact upload must wait for publication evidence")
    return findings


def managed_evidence_workflow_policy_findings(text: str, *, public: bool) -> list[Finding]:
    """Bound the two native evidence producers without treating attestations as publication.

    This is a static contract, complemented by executable shell-boundary and
    receipt-verifier tests; it is not a proof of arbitrary shell semantics.
    """
    filename = "managed-public-matrix.yml" if public else "managed-systemd-matrix.yml"
    path = Path(".github/workflows") / filename
    findings: list[Finding] = []
    text = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))

    def reject(message: str) -> None:
        findings.append(contract_finding(path, message))

    def require_markers(block: str, markers: Sequence[str], message: str) -> None:
        if any(marker not in block for marker in markers):
            reject(message)

    def named_step(block: str, name: str) -> str:
        marker = f"      - name: {name}\n"
        return next(
            (
                step
                for step in re.split(r"(?=^      - )", block, flags=re.MULTILINE)
                if step.startswith(marker)
            ),
            "",
        )

    def upload_paths(block: str) -> tuple[str, ...]:
        match = re.search(r"^          path:\s*\|\s*$", block, re.MULTILINE)
        if match is None:
            return ()
        lines = []
        for line in block[match.end() :].splitlines():
            if not line.strip():
                continue
            if not line.startswith("            "):
                break
            lines.append(line.strip())
        return tuple(lines)

    expected_events = {"workflow_call"} if public else {"workflow_call", "workflow_dispatch"}
    if _workflow_events(text)[0] != frozenset(expected_events):
        reject("managed evidence requires only its dedicated reusable/manual triggers")
    declared, permissions = _permission_entries(text, 0)
    if len(re.findall(r"^permissions:", text, re.MULTILINE)) != 1:
        reject("managed evidence workflow permissions must be unambiguous")
    if (
        not declared
        or len(permissions) != 1
        or {scope: access for scope, access, _ in permissions} != {"contents": "read"}
    ):
        reject("managed evidence workflow must explicitly default to contents read only")
    records = _workflow_jobs(text)
    jobs = {job.name: job for job in records}
    expected_jobs = (
        {"plan", "lifecycle", "verify-matrix"} if public else {"lifecycle", "verify-matrix"}
    )
    if set(jobs) != expected_jobs or len(records) != len(expected_jobs):
        reject("managed evidence must contain exactly its plan/native/collector jobs")
        return findings
    if any(
        re.search(pattern, text)
        for pattern in (
            r"secrets\.",
            r"(?m)^\s*secrets\s*:",
            r"(?m)^\s*environment\s*:",
            r"continue-on-error\s*:",
            r"setup-qemu",
            r"XFERRY_RELEASE_ED25519_PRIVATE_KEY_PEM",
            r"gh\s+release\s",
            r"docker\s+(?:push|login)\b",
            r"--push\b",
            r"mkdocs\s+gh-deploy\b",
        )
    ) or any(_publisher_channels(job) for job in jobs.values()):
        reject("managed evidence must not consume secrets/environments, emulate, bypass or publish")
    for match in WORKFLOW_ACTION_PATTERN.finditer(text):
        action = match.group("reference").strip("\"'")
        if (
            "@" not in action
            or action.startswith("./")
            or action.partition("@")[0]
            not in {
                "actions/checkout",
                "actions/setup-python",
                "actions/download-artifact",
                "actions/upload-artifact",
                "actions/attest-build-provenance",
            }
            or WORKFLOW_COMMIT_SHA_PATTERN.fullmatch(action.split("@", 1)[1]) is None
        ):
            reject("managed evidence actions must be full commit-SHA pinned")
    for name, job in jobs.items():
        expected = {"contents": "read"}
        if name == "verify-matrix":
            expected.update({"actions": "read", "id-token": "write", "attestations": "write"})
        elif public and name == "lifecycle":
            expected["actions"] = "read"
        declared, granted = _permission_entries(job.text, 4)
        if len(re.findall(r"^    permissions:", job.text, re.MULTILINE)) != 1:
            reject(f"managed evidence {name} permission blocks must not be duplicated")
        if (
            not declared
            or len(granted) != len(expected)
            or {scope: access for scope, access, _ in granted} != expected
        ):
            reject(f"managed evidence {name} must grant only its dedicated read/OIDC scopes")
        ref = "${{ inputs.source_commit }}" if public else "${{ github.sha }}"
        require_markers(
            job.text,
            ("persist-credentials: false", f"ref: {ref}"),
            f"managed evidence {name} must checkout its exact source without credentials",
        )
        if (
            name != "lifecycle"
            and "    runs-on: ubuntu-24.04" not in job.text.split("    steps:")[0]
        ):
            reject(f"managed evidence {name} must use its fixed GitHub-hosted collector runner")
    lifecycle, collector = jobs["lifecycle"], jobs["verify-matrix"]
    observed = re.findall(
        r"platform:\s*(linux-\S+)\s*\n\s*machine:\s*(\S+)\s*\n\s*runner:\s*(\S+)",
        lifecycle.text,
    )
    if observed != [
        ("linux-x86_64", "x86_64", "ubuntu-24.04"),
        ("linux-aarch64", "aarch64", "ubuntu-24.04-arm"),
    ]:
        reject("managed evidence requires exactly the two correct native platform/runner pairs")
    require_markers(
        lifecycle.text,
        (
            "runs-on: ${{ matrix.runner }}",
            "fail-fast: false",
            'test "$(uname -m)" = "$MATRIX_MACHINE"',
            'test -z "${DOCKER_HOST:-}"',
            'test "$(docker context show)"',
        ),
        "managed evidence lifecycle must enforce its native source/local-Docker boundary",
    )
    require_markers(
        text,
        (
            "value: ${{ jobs.verify-matrix.outputs.artifact-id }}",
            "value: ${{ jobs.verify-matrix.outputs.evidence-sha256 }}",
        ),
        "managed evidence must expose immutable artifact and JSON-subject identities",
    )

    if public:
        boundary = named_step(jobs["plan"].text, "Require the protected production caller")
        require_markers(
            boundary,
            (
                'test "$GITHUB_REPOSITORY" = kgmnotes/xferry',
                'test "$GITHUB_EVENT_NAME" = push',
                'test "$GITHUB_REF_PROTECTED" = true',
                'test "$RUNNER_ENVIRONMENT" = github-hosted',
                '[[ "$TARGET_TAG" =~ ^v(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)$ ]]',
                'test "$GITHUB_REF" = "refs/tags/${TARGET_TAG}"',
                'test "$GITHUB_SHA" = "$SOURCE_COMMIT"',
                'test "$GITHUB_WORKFLOW_REF" = '
                '"kgmnotes/xferry/.github/workflows/release-production.yml@${GITHUB_REF}"',
            ),
            "public managed evidence must require the exact protected production tag/source/caller",
        )
        require_markers(
            jobs["plan"].text,
            (
                "python tools/managed_public_matrix.py prepare",
                '--target-tag "$TARGET_TAG" --source-commit "$SOURCE_COMMIT"',
                '--workflow-run "$GITHUB_RUN_ID" --workflow-attempt "$GITHUB_RUN_ATTEMPT"',
                "github.repository == 'kgmnotes/xferry'",
                "github.event_name == 'push'",
                "startsWith(github.ref, 'refs/tags/v')",
            ),
            "public managed plan must resolve two actual public versions for the current caller",
        )
        plan_upload = _workflow_step_with_id(jobs["plan"].text, "upload") or ""
        require_markers(
            plan_upload,
            (
                "name: managed-public-plan-${{ github.run_id }}-${{ github.run_attempt }}",
                "path: ${{ runner.temp }}/managed-public-plan.json",
                "if-no-files-found: error",
                "retention-days: 14",
            ),
            "public managed plan upload must preserve only its exact immutable "
            "current-attempt JSON",
        )
        if _job_dependencies(lifecycle) != frozenset({"plan"}):
            reject("public managed lifecycle must depend on the verified immutable plan")
        if re.search(r"^    if:", lifecycle.text, re.MULTILINE):
            reject("public managed lifecycle must not bypass its plan result")
        require_markers(
            lifecycle.text,
            (
                'test "$(git rev-parse HEAD)" = "$SOURCE_COMMIT"',
                'test "$GITHUB_SHA" = "$SOURCE_COMMIT"',
                'test "$GITHUB_REF_PROTECTED" = true',
                'test "$RUNNER_ENVIRONMENT" = github-hosted',
                "artifact-ids: ${{ needs.plan.outputs.artifact-id }}",
                "python tools/managed_public_matrix.py run",
            ),
            "public managed lifecycle must consume only its current-source immutable plan",
        )
        expected_dependencies = frozenset({"plan", "lifecycle"})
        require_markers(
            collector.text,
            (
                "if: ${{ always() }}",
                'test "$PLAN_RESULT" = success',
                'test "$LIFECYCLE_RESULT" = success',
                'test "$GITHUB_REF_PROTECTED" = true',
                "PLAN_RESULT: ${{ needs.plan.result }}",
                "LIFECYCLE_RESULT: ${{ needs.lifecycle.result }}",
                'test "$RUNNER_ENVIRONMENT" = github-hosted',
                "artifact-ids: ${{ needs.plan.outputs.artifact-id }}",
                'test "$(git rev-parse HEAD)" = "$SOURCE_COMMIT"',
                "python tools/install_attestation_cli.py",
                "python tools/production_readiness.py verify-public",
                '--evidence-sha256 "$EVIDENCE_SHA256"',
                '--tag "$TARGET_TAG"',
            ),
            "public managed collector must reject failed/skipped inputs and verify signed evidence",
        )
        prefix, handoff = "managed-public", "managed-public-handoff"
        subject, command = (
            "managed-public-verified.json",
            "python tools/managed_public_matrix.py verify-matrix",
        )
        upload_name = "Preserve only sanitized native public receipts"
        source = '"$SOURCE_COMMIT"'
    else:
        boundary = named_step(lifecycle.text, "Require protected manual fixture boundary")
        require_markers(
            boundary,
            (
                'test "$GITHUB_REPOSITORY" = "kgmnotes/xferry"',
                'test "$GITHUB_REF_PROTECTED" = "true"',
                'test "$RUNNER_ENVIRONMENT" = "github-hosted"',
                'if [ "$GITHUB_EVENT_NAME" = workflow_dispatch ]; then',
                'test "$GITHUB_REF" = "refs/heads/main"',
                'test "$GITHUB_EVENT_NAME" = push',
                '[[ "$GITHUB_REF" =~ ^refs/tags/v(0|[1-9][0-9]*)\\.'
                "(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)$ ]]",
                'test "$GITHUB_WORKFLOW_REF" = '
                '"kgmnotes/xferry/.github/workflows/release-production.yml@${GITHUB_REF}"',
            ),
            "native fixture evidence must require protected main or the exact production caller",
        )
        for job in (lifecycle, collector):
            require_markers(
                job.text,
                (
                    "github.repository == 'kgmnotes/xferry'",
                    "github.event_name == 'workflow_dispatch'",
                    "github.ref == 'refs/heads/main'",
                    "github.event_name == 'push'",
                    "startsWith(github.ref, 'refs/tags/v')",
                    'test "$(git rev-parse HEAD)" = "$GITHUB_SHA"',
                ),
                "native fixture evidence must remain exact-source and dedicated-caller gated",
            )
        require_markers(
            lifecycle.text,
            (
                "python tools/managed_update_rehearsal.py prepare",
                '--base-commit "$GITHUB_SHA"',
                "python tools/managed_systemd_matrix.py run",
                "python -m pip install build pex==2.99.0 cryptography",
            ),
            "native fixture lifecycle must preserve current-source nonproduction fixtures",
        )
        require_markers(
            collector.text,
            (
                "if: ${{ always() && github.repository",
                'test "$LIFECYCLE_RESULT" = "success"',
                'test "$GITHUB_REF_PROTECTED" = "true"',
                "LIFECYCLE_RESULT: ${{ needs.lifecycle.result }}",
            ),
            "native fixture collector must reject a failed or skipped architecture",
        )
        expected_dependencies = frozenset({"lifecycle"})
        prefix, handoff = "systemd-matrix", "managed-native-handoff"
        subject, command = (
            "systemd-matrix-verified.json",
            "python tools/managed_systemd_matrix.py verify-matrix",
        )
        upload_name = "Preserve only sanitized lifecycle receipts"
        source = '"$GITHUB_SHA"'
    if _job_dependencies(collector) != expected_dependencies:
        reject("managed evidence collector must depend on all mandatory native/plan jobs")
    require_markers(
        collector.text,
        (
            command,
            f"--source-commit {source}",
            '--workflow-run "$GITHUB_RUN_ID"',
            '--workflow-attempt "$GITHUB_RUN_ATTEMPT"',
            f"pattern: {prefix}-${{{{ github.run_id }}}}-${{{{ github.run_attempt }}}}-linux-*",
            "merge-multiple: false",
        ),
        "managed evidence collector must verify the complete exact-source/current-attempt matrix",
    )
    receipts = named_step(lifecycle.text, upload_name)
    actual_paths = upload_paths(receipts)
    receipt_prefix = f"${{{{ runner.temp }}}}/{prefix}-evidence/"
    expected_paths = {receipt_prefix + "architecture.json"} | {
        receipt_prefix + f"{distro}-{version}.json"
        for distro, version in (
            ("ubuntu", "22.04"),
            ("ubuntu", "24.04"),
            ("ubuntu", "26.04"),
            ("debian", "12"),
            ("debian", "13"),
        )
    }
    if set(actual_paths) != expected_paths or len(actual_paths) != len(expected_paths):
        reject("managed evidence must upload only its six explicit sanitized receipt paths")
    attest = _workflow_step_with_id(collector.text, "attest") or ""
    subject_step = _workflow_step_with_id(collector.text, "subject") or ""
    upload = _workflow_step_with_id(collector.text, "upload") or ""
    attester = "actions/attest-build-provenance@977bb373ede98d70efdf65b84cb5f73e068dcc2a"
    require_markers(
        attest,
        (
            f"uses: {attester}",
            f"subject-name: {subject}",
            "subject-digest: sha256:${{ steps.subject.outputs.sha256 }}",
        ),
        "managed evidence must attest its exact basename and explicit computed SHA256",
    )
    if text.count("uses: actions/attest-build-provenance@") != 1 or "subject-path:" in attest:
        reject("managed evidence requires one pinned explicit-digest OIDC attestation")
    require_markers(
        subject_step,
        (
            f'sha256sum "$RUNNER_TEMP/{handoff}/{subject}"',
            '>> "$GITHUB_OUTPUT"',
        ),
        "managed evidence subject digest must be computed from the verified JSON bytes",
    )
    require_markers(
        collector.text,
        (
            "BUNDLE_PATH: ${{ steps.attest.outputs.bundle-path }}",
            f'cp "$BUNDLE_PATH" "$RUNNER_TEMP/{handoff}/attestation.json"',
            "artifact-id: ${{ steps.upload.outputs.artifact-id }}",
            "evidence-sha256: ${{ steps.subject.outputs.sha256 }}",
        ),
        "managed evidence must retain the original Sigstore bundle and immutable output identities",
    )
    wanted = {
        f"${{{{ runner.temp }}}}/{handoff}/{subject}",
        f"${{{{ runner.temp }}}}/{handoff}/attestation.json",
    }
    if public:
        wanted.add(f"${{{{ runner.temp }}}}/{handoff}/managed-public-plan.json")
    if set(upload_paths(upload)) != wanted or len(upload_paths(upload)) != len(wanted):
        reject(
            "managed evidence final artifact must contain only the exact "
            "receipt/plan/Sigstore files"
        )
    require_markers(
        upload,
        (
            f"name: {prefix}-verified-${{{{ github.run_id }}}}-${{{{ github.run_attempt }}}}",
            "if-no-files-found: error",
            "retention-days: 14",
        ),
        "managed evidence final artifact identity/retention must be exact and fail closed",
    )
    require_markers(
        receipts,
        ("if-no-files-found: error", "retention-days: 14"),
        "managed evidence receipt uploads must retain complete nonempty outputs",
    )
    positions = [
        collector.text.find(marker)
        for marker in (command, "        id: subject", f"uses: {attester}", "        id: upload")
    ]
    if any(position < 0 for position in positions) or positions != sorted(positions):
        reject("managed evidence must validate receipts before attesting and uploading")
    return findings


def managed_systemd_workflow_policy_findings(text: str) -> list[Finding]:
    return managed_evidence_workflow_policy_findings(text, public=False)


def managed_public_workflow_policy_findings(text: str) -> list[Finding]:
    return managed_evidence_workflow_policy_findings(text, public=True)


def testpypi_workflow_policy_findings(text: str) -> list[Finding]:
    """Keep the fixed staging rehearsal separate from production release policy."""
    path = Path(".github/workflows/testpypi.yml")
    findings: list[Finding] = []

    def reject(reason: str) -> None:
        findings.append(contract_finding(path, reason))

    # A commented safety check provides no execution boundary. Ignore comments
    # before examining both YAML fields and commands inside run blocks.
    text = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))
    if _workflow_events(text)[0] != frozenset({"workflow_dispatch"}):
        reject("TestPyPI rehearsal must be manual-only")
    for match in WORKFLOW_ACTION_PATTERN.finditer(text):
        reference = match.group("reference").strip("\"'")
        if not reference.startswith("./") and (
            "@" not in reference
            or WORKFLOW_COMMIT_SHA_PATTERN.fullmatch(reference.split("@", 1)[1]) is None
        ):
            reject("TestPyPI actions must be commit-SHA pinned")
    permissions_found, permission_entries = _permission_entries(text, 0)
    permissions = {scope: access for scope, access, _ in permission_entries}
    if (
        not permissions_found
        or len(permission_entries) != 2
        or permissions != {"contents": "read", "actions": "read"}
    ):
        reject("TestPyPI workflow permissions must explicitly grant only read access")
    jobs = {job.name: job for job in _workflow_jobs(text)}
    if set(jobs) != {"identity", "publish", "pipx-smoke"}:
        reject("TestPyPI rehearsal requires exactly identity, publish and pipx-smoke jobs")
        return findings
    expected_gate = (
        "    if: ${{ inputs.confirm_testpypi && github.repository == 'kgmnotes/xferry' "
        "&& github.ref == 'refs/heads/codex/stage-010-testpypi-rehearsal-v2' }}"
    )
    if expected_gate not in jobs["identity"].text.splitlines():
        reject("TestPyPI identity gate must enforce the exact confirmation/repository/ref")
    protected_branch_contract = (
        "Require protected rehearsal branch",
        'branches/codex%2Fstage-010-testpypi-rehearsal-v2")',
        '.commit.sha\' <<<"${branch_json}"',
        '.protected\' <<<"${branch_json}"',
    )
    if any(item not in jobs["identity"].text for item in protected_branch_contract):
        reject("TestPyPI identity must verify the exact protected rehearsal branch")
    if "stage-010-testpypi-rehearsal-v2/protection" in jobs["identity"].text:
        reject("TestPyPI cannot call the Administration-only branch protection endpoint")
    for command in ("identity", "prepare"):
        if (
            re.search(
                rf"^          python tools/testpypi_publish\.py {command} ",
                jobs["identity"].text,
                re.MULTILINE,
            )
            is None
        ):
            reject(f"TestPyPI identity must execute its {command} verifier")
    handoff_step = _workflow_step_with_id(jobs["identity"].text, "staged-distributions")
    if handoff_step is None or "retention-days: 14" not in handoff_step:
        reject("TestPyPI authenticated handoff retention must be fourteen days")
    if text.count("uses: pypa/gh-action-pypi-publish@") != 1 or _publisher_channels(
        jobs["publish"]
    ) != frozenset({"pypi"}):
        reject("TestPyPI requires exactly one official publisher and no other write channel")
    if re.search(r"(?:twine\s+upload|(?:uv|hatch)\s+publish)", text):
        reject("TestPyPI uploads must use only the official publisher step")
    required = {
        "identity": (
            "inputs.confirm_testpypi",
            "github.repository == 'kgmnotes/xferry'",
            "github.ref == 'refs/heads/codex/stage-010-testpypi-rehearsal-v2'",
            "artifact-id: ${{ steps.staged-distributions.outputs.artifact-id }}",
            "testpypi_publish.py identity",
            "repository: kgmnotes/xferry",
            "run-id: 36712344792",
            "artifact-ids: 11095067140",
            "github-token: ${{ github.token }}",
            "merge-multiple: true",
            "testpypi_publish.py prepare",
            "--archive downloaded/release-candidate.tar",
            "--candidate-dir promoted --packages-dir dist",
            "id: staged-distributions",
            "authenticated-testpypi-distributions-${{ github.run_id }}-${{ github.run_attempt }}",
            "if-no-files-found: error",
            "retention-days: 14",
        ),
        "publish": (
            "needs: identity",
            "environment: testpypi",
            "artifact-ids: ${{ needs.identity.outputs.artifact-id }}",
            "merge-multiple: true",
            "path: dist",
            "pypa/gh-action-pypi-publish@7245906fb61fa33a13554f9d5fb856fe61758086",
            "repository-url: https://test.pypi.org/legacy/",
            "packages-dir: dist/",
            "verify-metadata: true",
            "skip-existing: false",
            "attestations: true",
        ),
        "pipx-smoke": (
            "needs: publish",
            "os: [ubuntu-latest, macos-15, windows-latest]",
            "testpypi_publish.py smoke",
        ),
    }
    for name, job in jobs.items():
        if any(item not in job.text for item in required[name]):
            reject(f"TestPyPI {name} job lost its fixed staging contract")
        permissions = {scope: access for scope, access, _ in _permission_entries(job.text, 4)[1]}
        expected = {"actions": "read", "id-token": "write"}
        if name == "publish" and permissions != expected:
            reject("Only TestPyPI publish may grant job-scoped OIDC and read scopes")
        if name != "publish" and any(access != "read" for access in permissions.values()):
            reject("TestPyPI verification jobs must remain read-only")
    publish_actions = tuple(
        match.group("reference").strip("\"'")
        for match in WORKFLOW_ACTION_PATTERN.finditer(jobs["publish"].text)
    )
    if publish_actions != (
        "actions/download-artifact@9000827ccba6bdab643e8b6fd33ac0654aef8333",
        "pypa/gh-action-pypi-publish@7245906fb61fa33a13554f9d5fb856fe61758086",
    ) or re.search(r"^\s+run\s*:", jobs["publish"].text, re.MULTILINE):
        reject("TestPyPI OIDC publish must execute only the two approved pinned actions")
    for block in text.split("uses: actions/checkout@")[1:]:
        if "persist-credentials: false" not in block.split("\n      -", 1)[0]:
            reject("TestPyPI checkout credentials must not persist")
    if PUBLISH_JOB_REBUILD_PATTERN.search(jobs["publish"].text):
        reject("TestPyPI publisher must not rebuild candidates")
    if PYPI_STATIC_CREDENTIAL_PATTERN.search(text) or "${{ secrets." in text:
        reject("TestPyPI must not consume static credentials or signing secrets")
    if any(value in text for value in ("upload.pypi.org", "production", "--extra-index-url")):
        reject("TestPyPI cannot target production or mix package indexes")
    if any(_publisher_channels(job) for name, job in jobs.items() if name != "publish"):
        reject("TestPyPI writes must be isolated to the publish job")
    return findings


def github_release_rehearsal_policy_findings(text: str) -> list[Finding]:
    """Keep STAGE-012 draft Release publishing split across safe trust boundaries."""
    path = Path(".github/workflows/github-release-rehearsal.yml")
    findings: list[Finding] = []

    def reject(reason: str) -> None:
        findings.append(contract_finding(path, reason))

    text = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))
    if _workflow_events(text)[0] != frozenset({"workflow_dispatch"}):
        reject("GitHub Release rehearsal must be manual-only")
    for match in WORKFLOW_ACTION_PATTERN.finditer(text):
        reference = match.group("reference").strip("\"'")
        if not reference.startswith("./") and (
            "@" not in reference
            or WORKFLOW_COMMIT_SHA_PATTERN.fullmatch(reference.split("@", 1)[1]) is None
        ):
            reject("GitHub Release rehearsal actions must be commit-SHA pinned")
    permissions_found, permission_entries = _permission_entries(text, 0)
    permissions = {scope: access for scope, access, _ in permission_entries}
    if (
        not permissions_found
        or len(permission_entries) != 2
        or permissions != {"contents": "read", "actions": "read"}
    ):
        reject("GitHub Release rehearsal workflow permissions must grant only read access")

    jobs = {job.name: job for job in _workflow_jobs(text)}
    expected_jobs = {"identity", "sign-assets", "publish-draft", "download-verify"}
    if set(jobs) != expected_jobs:
        reject("GitHub Release rehearsal requires exactly identity/sign/publish/verify jobs")
        return findings

    expected_gate = (
        "    if: ${{ inputs.confirm_github_release_rehearsal && "
        "github.repository == 'kgmnotes/xferry' && "
        "github.ref == 'refs/heads/codex/stage-012-draft-release-rehearsal-v2' }}"
    )
    if expected_gate not in jobs["identity"].text.splitlines():
        reject("GitHub Release identity gate must enforce exact confirmation/repository/ref")
    protected_branch_contract = (
        "Require protected rehearsal branch",
        'branches/codex%2Fstage-012-draft-release-rehearsal-v2")',
        '.commit.sha\' <<<"${branch_json}"',
        '.protected\' <<<"${branch_json}"',
    )
    if any(item not in jobs["identity"].text for item in protected_branch_contract):
        reject("GitHub Release identity must verify the exact protected rehearsal branch")
    if "stage-012-draft-release-rehearsal-v2/protection" in jobs["identity"].text:
        reject("GitHub Release rehearsal cannot call the Administration branch protection API")

    exact_tag = "xferry-stage-012-rehearsal-v0.1.0-36712344792-v2"
    if f"RELEASE_TAG: {exact_tag}" not in text or "RELEASE_TAG: v0.1.0" in text:
        reject("GitHub Release rehearsal must use only the fixed non-production release tag")

    required = {
        "identity": (
            "inputs.confirm_github_release_rehearsal",
            "github.repository == 'kgmnotes/xferry'",
            "github.ref == 'refs/heads/codex/stage-012-draft-release-rehearsal-v2'",
            "gh api repos/kgmnotes/xferry/commits/${RELEASE_TAG}",
            "github_release_assets.py identity",
            "github_release_assets.py prepare",
            "repository: kgmnotes/xferry",
            "run-id: 36712344792",
            "artifact-ids: 11095067140",
            "github-token: ${{ github.token }}",
            "merge-multiple: true",
            "--archive downloaded/release-candidate.tar",
            "--candidate-dir promoted --unsigned-dir unsigned-assets",
            "unsigned-github-release-assets-${{ github.run_id }}-${{ github.run_attempt }}",
            "if-no-files-found: error",
        ),
        "sign-assets": (
            "needs: identity",
            "environment: production-release",
            "artifact-ids: ${{ needs.identity.outputs.artifact-id }}",
            "XFERRY_RELEASE_SIGNING_KEY_ID: ${{ vars.XFERRY_RELEASE_SIGNING_KEY_ID }}",
            "XFERRY_RELEASE_PRIVATE_KEY_PEM: ${{ secrets.XFERRY_RELEASE_ED25519_PRIVATE_KEY_PEM }}",
            "XFERRY_RELEASE_ED25519_PRIVATE_KEY_PEM",
            "umask 077",
            "trap cleanup EXIT",
            "shred -u",
            "printf '%s' \"${XFERRY_RELEASE_PRIVATE_KEY_PEM}\"",
            "python tools/github_release_assets.py sign",
            "python tools/github_release_assets.py verify --assets-dir signed-assets",
            "cleanup\n          trap - EXIT",
            "signed-github-release-assets-${{ github.run_id }}-${{ github.run_attempt }}",
        ),
        "publish-draft": (
            "needs: sign-assets",
            "environment: github-release-staging",
            "artifact-ids: ${{ needs.sign-assets.outputs.artifact-id }}",
            "artifact-id: ${{ steps.downloaded-assets.outputs.artifact-id }}",
            "gh release create",
            "--draft --prerelease --latest=false",
            "--verify-tag",
            (
                'gh release view "${RELEASE_TAG}" --repo kgmnotes/xferry '
                "--json tagName,isDraft,isPrerelease"
            ),
            ".tagName",
            ".isDraft",
            ".isPrerelease",
            'gh release download "${RELEASE_TAG}"',
            "downloaded-github-release-assets-${{ github.run_id }}-${{ github.run_attempt }}",
            "path: downloaded/",
            "if-no-files-found: error",
        ),
        "download-verify": (
            "needs: publish-draft",
            "artifact-ids: ${{ needs.publish-draft.outputs.artifact-id }}",
            "merge-multiple: true",
            "path: downloaded",
            "python tools/github_release_assets.py verify --assets-dir downloaded",
            "python tools/github_release_assets.py verify-tamper --assets-dir downloaded",
        ),
    }
    for name, job in jobs.items():
        if any(item not in job.text for item in required[name]):
            reject(f"GitHub Release {name} job lost its fixed rehearsal contract")

    expected_permissions = {
        "identity": {"contents": "read", "actions": "read"},
        "sign-assets": {"contents": "read", "actions": "read"},
        "publish-draft": {"actions": "read", "contents": "write"},
        "download-verify": {"contents": "read", "actions": "read"},
    }
    for name, job in jobs.items():
        has_permissions, entries = _permission_entries(job.text, 4)
        permissions = {scope: access for scope, access, _ in entries}
        if not has_permissions or permissions != expected_permissions[name]:
            reject(f"GitHub Release {name} job must keep its exact least-privilege permissions")

    for block in text.split("uses: actions/checkout@")[1:]:
        if "persist-credentials: false" not in block.split("\n      -", 1)[0]:
            reject("GitHub Release checkout credentials must not persist")

    publish = jobs["publish-draft"]
    publish_actions = tuple(
        match.group("reference").strip("\"'")
        for match in WORKFLOW_ACTION_PATTERN.finditer(publish.text)
    )
    if publish_actions != (
        "actions/download-artifact@9000827ccba6bdab643e8b6fd33ac0654aef8333",
        "actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9",
    ):
        reject("GitHub Release publisher may only transfer signed and Release-downloaded assets")
    if "actions/checkout@" in publish.text or "python " in publish.text:
        reject("GitHub Release publisher must not checkout or execute repository code")
    if _publisher_channels(jobs["identity"]) or _publisher_channels(jobs["sign-assets"]):
        reject("GitHub Release writes must be isolated to the secret-free publisher job")
    if _publisher_channels(publish) != frozenset({"github-release"}):
        reject("GitHub Release publisher must use exactly one GitHub Release write channel")
    if re.search(r"^\s*RELEASE_TAG\s*=", publish.text, re.MULTILINE):
        reject("GitHub Release publisher must not override the fixed release tag in shell")
    if (
        "gh release upload" in publish.text
        or "gh release edit" in publish.text
        or "--clobber" in publish.text
        or re.search(r"--draft(?:=|\s+)false", publish.text)
    ):
        reject("GitHub Release publisher must create once and never overwrite assets")

    secret_pattern = r"\$\{\{\s*secrets\.XFERRY_RELEASE_ED25519_PRIVATE_KEY_PEM\s*\}\}"
    if len(re.findall(secret_pattern, text)) != 1:
        reject("GitHub Release signing secret must be referenced exactly once")
    if re.search(secret_pattern, publish.text) is not None:
        reject("GitHub Release publisher must not receive the signing secret")
    if any(
        re.search(secret_pattern, jobs[name].text) is not None
        for name in ("identity", "download-verify")
    ):
        reject("GitHub Release signing secret must stay only in the protected signing job")
    approved_secret_line = (
        "          XFERRY_RELEASE_PRIVATE_KEY_PEM: "
        "${{ secrets.XFERRY_RELEASE_ED25519_PRIVATE_KEY_PEM }}"
    )
    if approved_secret_line not in jobs["sign-assets"].text:
        reject("GitHub Release signing secret must only enter the protected signer env")

    if "latest/download" in text:
        reject("GitHub Release rehearsal must use immutable versioned URLs, not latest")
    if re.search(
        r"(?:python(?:3)?\s+-m\s+build|pip\s+wheel|docker\s+(?:build|buildx\s+build)|"
        r"tools/build_scie_release\.py)",
        text,
        re.IGNORECASE,
    ):
        reject("GitHub Release rehearsal must not rebuild candidate artifacts")
    return findings


def managed_update_rehearsal_policy_findings(
    rehearsal_text: str,
    release_text: str,
) -> list[Finding]:
    """Keep STAGE-013 native lifecycle evidence read-only and non-publishing."""
    path = Path(".github/workflows/managed-update-rehearsal.yml")
    findings: list[Finding] = []

    def reject(reason: str) -> None:
        findings.append(contract_finding(path, reason))

    if _workflow_events(rehearsal_text)[0] != frozenset({"workflow_call"}):
        reject("managed update rehearsal must be reusable-only")
    for match in WORKFLOW_ACTION_PATTERN.finditer(rehearsal_text):
        reference = match.group("reference").strip("\"'")
        if not reference.startswith("./") and (
            "@" not in reference
            or WORKFLOW_COMMIT_SHA_PATTERN.fullmatch(reference.split("@", 1)[1]) is None
        ):
            reject("managed update rehearsal actions must be commit-SHA pinned")

    permissions_found, entries = _permission_entries(rehearsal_text, 0)
    permissions = {scope: access for scope, access, _line in entries}
    if not permissions_found or permissions != {"contents": "read"}:
        reject("managed update rehearsal workflow must grant only contents read")

    jobs = {job.name: job for job in _workflow_jobs(rehearsal_text)}
    if set(jobs) != {"lifecycle"}:
        reject("managed update rehearsal must contain only the native lifecycle matrix job")
        return findings
    lifecycle = jobs["lifecycle"]
    job_permissions_found, job_entries = _permission_entries(lifecycle.text, 4)
    job_permissions = {scope: access for scope, access, _line in job_entries}
    if not job_permissions_found or job_permissions != {"contents": "read"}:
        reject("managed update lifecycle job must grant only contents read")

    required_boundary = (
        "refs/heads/codex/stage-013-managed-update-rehearsal",
        'test "$GITHUB_REPOSITORY" = "kgmnotes/xferry"',
        'test "$GITHUB_EVENT_NAME" = "workflow_dispatch"',
        "fail-fast: false",
        "runs-on: ${{ matrix.runner }}",
    )
    if any(item not in lifecycle.text for item in required_boundary):
        reject("managed update lifecycle lost its exact repository/ref/native matrix boundary")

    required_parent_normalization = (
        "Normalize disposable runner managed parents",
        'test "$RUNNER_ENVIRONMENT" = "github-hosted"',
        'test "$(sudo stat -c \'%u\' /opt)" = "0"',
        "sudo chmod 0755 /opt",
        'test "$(sudo stat -c \'%u:%a\' /opt)" = "0:755"',
        'test "$(sudo stat -c \'%u\' /usr/local/bin)" = "0"',
        "sudo chmod 0755 /usr/local/bin",
        'test "$(sudo stat -c \'%u:%a\' /usr/local/bin)" = "0:755"',
    )
    normalization_marker = "      - name: Normalize disposable runner managed parents"
    install_marker = "      - name: Install signed 0.1.1"
    normalization_start = lifecycle.text.find(normalization_marker)
    install_start = lifecycle.text.find(install_marker)
    next_step_start = lifecycle.text.find(
        "\n      - ",
        normalization_start + len(normalization_marker),
    )
    normalization_step = (
        ""
        if normalization_start < 0 or next_step_start < 0
        else lifecycle.text[normalization_start:next_step_start]
    )
    if any(item not in normalization_step for item in required_parent_normalization):
        reject("managed update rehearsal must protect its disposable runner managed parents")
    elif install_start < 0 or normalization_start > install_start:
        reject("managed update rehearsal must protect managed parents before installation")

    runner_lines = tuple(
        line.strip() for line in rehearsal_text.splitlines() if line.strip().startswith("runner:")
    )
    if runner_lines != ("runner: ubuntu-24.04", "runner: ubuntu-24.04-arm"):
        reject("managed update rehearsal requires exactly amd64 and arm64 native runners")

    if (
        'SOURCE_VERSION: "0.1.1"' not in rehearsal_text
        or 'TARGET_VERSION: "0.1.2"' not in rehearsal_text
    ):
        reject("managed update rehearsal versions must remain fixed at 0.1.1 to 0.1.2")
    if "MANAGED_XFERRY: /usr/local/bin/xferry" not in rehearsal_text:
        reject("managed update rehearsal must pin the installed managed CLI path")
    bare_managed_cli_patterns = (
        r"\$\(\s*xferry\s",
        r"\bsudo\s+xferry\s",
        r"(?m)^\s+xferry\s+(?:setup|doctor|update|rollback|uninstall)\b",
    )
    if any(re.search(pattern, lifecycle.text) for pattern in bare_managed_cli_patterns):
        reject("managed update rehearsal must not resolve lifecycle commands from PATH")

    lifecycle_steps = (
        "Install signed 0.1.1",
        "Setup private managed service",
        "Dry-run signed update to 0.1.2",
        "Apply signed update to 0.1.2",
        "Verify exact 0.1.2 health",
        "Rollback to retained 0.1.1",
        "Conservative uninstall",
    )
    try:
        positions = [rehearsal_text.index(step) for step in lifecycle_steps]
    except ValueError:
        reject("managed update rehearsal is missing a required lifecycle step")
    else:
        if positions != sorted(positions):
            reject("managed update rehearsal lifecycle steps are out of order")

    forbidden = (
        "${{ secrets.",
        "environment:",
        "permissions: write-all",
        "contents: write",
        "packages: write",
        "id-token: write",
        "attestations: write",
        "XFERRY_RELEASE_ED25519_PRIVATE_KEY_PEM",
        "environment: production-release",
        "gh release ",
        "docker push",
        "--push",
        "gh-action-pypi-publish",
        "twine upload",
        "hatch publish",
        "mkdocs gh-deploy",
        "--purge-data",
    )
    if any(item in rehearsal_text for item in forbidden):
        reject("managed update rehearsal must not consume secrets, publish, or purge state")
    if _publisher_channels(lifecycle):
        reject("managed update rehearsal cannot contain a package or release publisher")

    release_jobs = {job.name: job for job in _workflow_jobs(release_text)}
    preflight = release_jobs.get("preflight")
    caller = release_jobs.get("managed-update-rehearsal")
    required_input = (
        "managed_update_rehearsal:",
        "default: false",
        "type: boolean",
    )
    if any(item not in release_text for item in required_input):
        reject("release dispatcher must expose an opt-in boolean rehearsal input")
    if preflight is None or "if: ${{ !inputs.managed_update_rehearsal }}" not in preflight.text:
        reject("ordinary release jobs must be disabled during managed update rehearsal")
    if caller is None or any(
        item not in caller.text
        for item in (
            "if: ${{ inputs.managed_update_rehearsal }}",
            "permissions:\n      contents: read",
            "uses: ./.github/workflows/managed-update-rehearsal.yml",
        )
    ):
        reject("release dispatcher must call only the read-only managed update workflow")
    return findings


def ghcr_workflow_policy_findings(text: str) -> list[Finding]:
    """Keep the fixed GHCR rehearsal separate from production release policy."""
    path = Path(".github/workflows/ghcr.yml")
    findings: list[Finding] = []

    def reject(reason: str) -> None:
        findings.append(contract_finding(path, reason))

    text = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))
    if _workflow_events(text)[0] != frozenset({"workflow_dispatch"}):
        reject("GHCR rehearsal must be manual-only")
    for match in WORKFLOW_ACTION_PATTERN.finditer(text):
        reference = match.group("reference").strip("\"'")
        if not reference.startswith("./") and (
            "@" not in reference
            or WORKFLOW_COMMIT_SHA_PATTERN.fullmatch(reference.split("@", 1)[1]) is None
        ):
            reject("GHCR actions must be commit-SHA pinned")
    permissions_found, permission_entries = _permission_entries(text, 0)
    permissions = {scope: access for scope, access, _ in permission_entries}
    if (
        not permissions_found
        or len(permission_entries) != 2
        or permissions != {"contents": "read", "actions": "read"}
    ):
        reject("GHCR workflow permissions must explicitly grant only read access")
    jobs = {job.name: job for job in _workflow_jobs(text)}
    if set(jobs) != {"identity", "publish", "registry-verify", "pull-smoke"}:
        reject("GHCR rehearsal requires identity, publish, registry-verify and pull-smoke jobs")
        return findings
    expected_gate = (
        "    if: ${{ inputs.confirm_ghcr && github.repository == 'kgmnotes/xferry' "
        "&& github.ref == 'refs/heads/codex/stage-011-ghcr-rehearsal-v2' }}"
    )
    if expected_gate not in jobs["identity"].text.splitlines():
        reject("GHCR identity gate must enforce the exact confirmation/repository/ref")
    protected_branch_contract = (
        "Require protected rehearsal branch",
        'branches/codex%2Fstage-011-ghcr-rehearsal-v2")',
        '.commit.sha\' <<<"${branch_json}"',
        '.protected\' <<<"${branch_json}"',
    )
    if any(item not in jobs["identity"].text for item in protected_branch_contract):
        reject("GHCR identity must verify the exact protected rehearsal branch")
    if "stage-011-ghcr-rehearsal-v2/protection" in jobs["identity"].text:
        reject("GHCR cannot call the Administration-only branch protection endpoint")
    required = {
        "identity": (
            "inputs.confirm_ghcr",
            "github.repository == 'kgmnotes/xferry'",
            "github.ref == 'refs/heads/codex/stage-011-ghcr-rehearsal-v2'",
            "artifact-id: ${{ steps.staged-oci.outputs.artifact-id }}",
            "ghcr_publish.py identity",
            "repository: kgmnotes/xferry",
            "run-id: 36712344792",
            "artifact-ids: 11095067140",
            "github-token: ${{ github.token }}",
            "merge-multiple: true",
            "ghcr_publish.py prepare",
            "--archive downloaded/release-candidate.tar",
            "--candidate-dir promoted",
            "--oci-dir staged/oci",
            "--receipt staged/ghcr-candidate-receipt.json",
            "authenticated-ghcr-oci-${{ github.run_id }}-${{ github.run_attempt }}",
            "if-no-files-found: error",
        ),
        "publish": (
            "needs: identity",
            "environment: ghcr-staging",
            "artifact-ids: ${{ needs.identity.outputs.artifact-id }}",
            "merge-multiple: true",
            "path: staged",
            "skopeo=1.13.3+ds1-2ubuntu0.24.04.3",
            "GHCR_IMAGE: ghcr.io/kgmnotes/xferry",
            "GHCR_TAG: v0.1.0",
            'test "$existing_digest" = "$EXPECTED_DIGEST"',
            'test "$registry_digest" = "$EXPECTED_DIGEST"',
            'skopeo copy --all --preserve-digests "oci:staged/oci" "docker://${GHCR_IMAGE}:${GHCR_TAG}"',
            "docker://${GHCR_IMAGE}:${GHCR_TAG}",
            "Refuse mutable latest tag",
            "docker://${GHCR_IMAGE}:latest",
        ),
        "registry-verify": (
            "needs: [identity, publish]",
            "skopeo=1.13.3+ds1-2ubuntu0.24.04.3",
            "mkdir -p registry",
            (
                "skopeo copy --all --preserve-digests "
                '"docker://ghcr.io/kgmnotes/xferry@${GHCR_DIGEST}" "oci:registry/oci"'
            ),
            "ghcr_publish.py verify-registry-layout",
        ),
        "pull-smoke": (
            "needs: publish",
            "runner: ubuntu-24.04-arm",
            "test \"$(uname -m)\" = '${{ matrix.machine }}'",
            "docker pull --platform",
            "ghcr.io/kgmnotes/xferry@${GHCR_DIGEST}",
            "verify_docker_image.py",
            "docker_image_smoke.py",
            "--browser-first-run",
        ),
    }
    for name, job in jobs.items():
        if any(item not in job.text for item in required[name]):
            reject(f"GHCR {name} job lost its fixed staging contract")
    latest_check = 'skopeo inspect --raw "docker://${GHCR_IMAGE}:latest"'
    publish_copy = (
        'skopeo copy --all --preserve-digests "oci:staged/oci" "docker://${GHCR_IMAGE}:${GHCR_TAG}"'
    )
    latest_check_index = jobs["publish"].text.find(latest_check)
    publish_copy_index = jobs["publish"].text.find(publish_copy)
    if (
        latest_check_index == -1
        or publish_copy_index == -1
        or latest_check_index > publish_copy_index
    ):
        reject("GHCR publish must refuse mutable latest before any registry write")
    if jobs["publish"].text.count("GHCR_IMAGE: ghcr.io/kgmnotes/xferry") != 2:
        reject("GHCR publish must pin both image references to ghcr.io/kgmnotes/xferry")
    if PUBLISH_JOB_REBUILD_PATTERN.search(jobs["publish"].text) or any(
        item in text
        for item in (
            "docker/build-push-action",
            "docker/login-action",
            "docker push",
            "--push",
            "actions/attest",
            "gh release",
            "gh-action-pypi-publish",
            "${{ secrets.",
        )
    ):
        reject("GHCR rehearsal must not rebuild, use unrelated publishers, or consume secrets")
    publish_permissions = {
        scope: access for scope, access, _ in _permission_entries(jobs["publish"].text, 4)[1]
    }
    if publish_permissions != {"actions": "read", "packages": "write"}:
        reject("Only GHCR publish may grant job-scoped package write access")
    for name, job in jobs.items():
        permissions = {scope: access for scope, access, _ in _permission_entries(job.text, 4)[1]}
        if name != "publish" and any(access not in {"read"} for access in permissions.values()):
            reject("GHCR non-publish jobs must remain read-only")
    if (
        "actions/checkout@" in jobs["publish"].text
        or "tools/ghcr_publish.py" in jobs["publish"].text
    ):
        reject("GHCR package write job must not checkout or execute repository code")
    for name, job in jobs.items():
        if name != "publish":
            writes_registry = any(
                re.search(r'skopeo\s+copy[^\n]*\s"[^"]+"\s+"docker://', line)
                for line in job.text.splitlines()
            )
            if writes_registry or re.search(
                r"(?:packages:\s*write|docker\s+push|docker/build-push-action)",
                job.text,
            ):
                reject("GHCR writes must be isolated to the publish job")
    if "environment: production" in text or "refs/heads/main" in text:
        reject("GHCR staging cannot target production or main directly")
    return findings


def find_release_policy_issues(
    repo_root: Path = REPO_ROOT,
    targets: Sequence[str] = DEFAULT_TARGETS,
) -> list[Finding]:
    findings: list[Finding] = []
    path = Path(".github/workflows/release.yml")
    release_text: str | None = None
    if targets_cover_path(path, repo_root, targets):
        release_text = read_contract_text(repo_root / path)
        if release_text is None:
            findings.append(contract_finding(path, "release workflow policy file is missing"))
        else:
            findings.extend(release_workflow_policy_findings(release_text, path))
    production = Path(".github/workflows/release-production.yml")
    if targets_cover_path(production, repo_root, targets) and (repo_root / production).is_file():
        findings.extend(
            production_release_workflow_policy_findings(
                read_contract_text(repo_root / production) or "",
                production,
            )
        )
    managed_rehearsal = Path(".github/workflows/managed-update-rehearsal.yml")
    if (
        targets_cover_path(managed_rehearsal, repo_root, targets)
        and (repo_root / managed_rehearsal).is_file()
    ):
        if release_text is None:
            release_text = read_contract_text(repo_root / path) or ""
        findings.extend(
            managed_update_rehearsal_policy_findings(
                read_contract_text(repo_root / managed_rehearsal) or "",
                release_text,
            )
        )
    for name, checker in (
        ("managed-systemd-matrix.yml", managed_systemd_workflow_policy_findings),
        ("managed-public-matrix.yml", managed_public_workflow_policy_findings),
    ):
        evidence = Path(".github/workflows") / name
        if targets_cover_path(evidence, repo_root, targets):
            content = read_contract_text(repo_root / evidence)
            if content is None:
                findings.append(contract_finding(evidence, "managed evidence workflow is missing"))
            else:
                findings.extend(checker(content))
    staging = Path(".github/workflows/testpypi.yml")
    if targets_cover_path(staging, repo_root, targets) and (repo_root / staging).is_file():
        findings.extend(
            testpypi_workflow_policy_findings(read_contract_text(repo_root / staging) or "")
        )
    github_release = Path(".github/workflows/github-release-rehearsal.yml")
    if (
        targets_cover_path(github_release, repo_root, targets)
        and (repo_root / github_release).is_file()
    ):
        findings.extend(
            github_release_rehearsal_policy_findings(
                read_contract_text(repo_root / github_release) or ""
            )
        )
    ghcr = Path(".github/workflows/ghcr.yml")
    if targets_cover_path(ghcr, repo_root, targets) and (repo_root / ghcr).is_file():
        findings.extend(ghcr_workflow_policy_findings(read_contract_text(repo_root / ghcr) or ""))
    pages = Path(".github/workflows/docs-pages.yml")
    if targets_cover_path(pages, repo_root, targets) and (repo_root / pages).is_file():
        findings.extend(
            docs_pages_workflow_policy_findings(read_contract_text(repo_root / pages) or "")
        )
    return findings


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

    for pattern in STALE_DOCUMENT_PATTERNS:
        if relative in pattern.ignored_paths:
            continue
        if superseded_adr and pattern.allow_in_superseded_adr:
            continue
        match = pattern.regex.search(text)
        if match is None:
            continue
        line_number = text.count("\n", 0, match.start()) + 1
        findings.append(
            Finding(
                relative,
                line_number,
                lines[line_number - 1].strip() if lines else "",
                pattern.message,
            )
        )

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
    """Reject unsafe mutable routes and require journey-first portable onboarding."""
    findings: list[Finding] = []
    unsafe_route = re.compile(
        r"(?:releases/latest|ghcr\.io/kgmnotes/xferry:latest\b|"
        r"(?<![\w.-])(?:python\s+-m\s+)?pip\s+install\b[^\n`]{0,160}?"
        r"(?<!\S)xferry(?:\b|\[)|"
        r"curl[^\n|]{0,300}\|\s*(?:sudo\s+)?(?:ba)?sh\b|"
        r"(?<![\w-])xferry\s+update\b"
        r"(?!\s+--to\s+(?:[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?|VERSION)(?:\s|`|$)))",
        re.IGNORECASE,
    )
    for path in (
        Path("README.md"),
        Path("docs/quick-start.md"),
        Path("docs/operations.md"),
        Path("docs/public-direct.md"),
    ):
        if not targets_cover_path(path, repo_root, targets):
            continue
        text = read_contract_text(repo_root / path)
        if text is None:
            continue
        match = unsafe_route.search(text)
        if match is None:
            continue
        line_number = text.count("\n", 0, match.start()) + 1
        lines = text.splitlines()
        findings.append(
            Finding(
                path,
                line_number,
                lines[line_number - 1].strip() if lines else "",
                "current user docs contain an unsafe distribution or lifecycle route",
            )
        )

    path = Path("docs/quick-start.md")
    if not targets_cover_path(path, repo_root, targets):
        return findings
    text = read_contract_text(repo_root / path)
    if text is None:
        return findings
    folded = text.casefold()
    markers = (
        "pipx install xferry",
        "## portable",
        "xferry run --open",
        "## managed linux",
        "## container",
    )
    offsets = tuple(folded.find(marker) for marker in markers)
    if any(offset < 0 for offset in offsets) or offsets != tuple(sorted(offsets)):
        findings.append(
            contract_finding(
                path,
                "quick start must order portable first success before managed and container paths",
            )
        )
    return findings


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
        headings = tuple(
            (match.group(1), match.group(2), position)
            for position, match in enumerate(
                re.finditer(
                    r"^## \[([^]]+)](?: - ([^\n]+))?$",
                    changelog,
                    re.MULTILINE,
                )
            )
        )
        released = tuple(
            (released_version, released_date, position)
            for released_version, released_date, position in headings
            if released_version.casefold() != "unreleased"
        )
        release_counts: dict[str, int] = {}
        for released_version, released_date, _position in released:
            release_counts[released_version] = release_counts.get(released_version, 0) + 1
            if released_date is None or re.fullmatch(r"\d{4}-\d{2}-\d{2}", released_date) is None:
                displayed_date = released_date or "missing"
                findings.append(
                    contract_finding(
                        changelog_path,
                        "CHANGELOG release date must use canonical ISO YYYY-MM-DD: "
                        f"{displayed_date}",
                    )
                )
                continue
            try:
                date.fromisoformat(released_date)
            except ValueError:
                findings.append(
                    contract_finding(
                        changelog_path,
                        f"CHANGELOG release date is not a valid ISO date: {released_date}",
                    )
                )

        for released_version, count in release_counts.items():
            if count > 1:
                findings.append(
                    contract_finding(
                        changelog_path,
                        f"CHANGELOG released version {released_version} must not be duplicated",
                    )
                )

        current_sections = tuple(item for item in released if item[0] == version)
        if len(current_sections) != 1:
            findings.append(
                contract_finding(
                    changelog_path,
                    "CHANGELOG must contain exactly one released section for current package "
                    f"version {version}",
                )
            )
        unreleased_positions = tuple(
            position
            for heading, _heading_date, position in headings
            if heading.casefold() == "unreleased"
        )
        if (
            len(unreleased_positions) != 1
            or not released
            or released[0][0] != version
            or released[0][2] <= unreleased_positions[0]
        ):
            findings.append(
                contract_finding(
                    changelog_path,
                    f"CHANGELOG current package version {version} must be the first released "
                    "section after [Unreleased]",
                )
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
    findings.extend(find_release_policy_issues(REPO_ROOT, targets))
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
