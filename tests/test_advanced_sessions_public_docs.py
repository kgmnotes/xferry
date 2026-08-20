"""Public documentation contract for token-scoped Advanced Sessions."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from tools import check_stale_docs

REPO_ROOT = Path(__file__).resolve().parents[1]
API_MIRROR_BANNER = (
    "<!-- Generated from ../API.md by tools/sync_docs.py. "
    "Edit API.md and rerun the sync tool. -->\n\n"
)
LEGACY_API_MARKERS = (
    "/_xferry/advanced-routing",
    "Advanced routing control API",
    '"revision": 0',
    "State is process-local",
    "Advanced upload fallback",
    "legacy fallback",
    "X-Encoding",
    "X-HTTP-Method-Override",
    "X-Payload-In-Path",
    "path_payload",
    "path_filename",
    "kb64",
)
LEGACY_API_PATTERNS = (
    r"(?<![A-Za-z0-9_-])(?i:X-(?:D(?:-(?:[0-9]+|N))?|E|K(?:b64)?|N|H))"
    r"(?![A-Za-z0-9_-])",
    r"(?<![A-Za-z0-9_-])(?:d(?:[-_]?[0-9]+)|data-?[0-9]+)"
    r"(?![A-Za-z0-9_-])",
    r'(?:"(?:d|e|k|n|h|enc|_method)"\s*:'
    r"|(?<![A-Za-z0-9_-])(?:d|e|k|n|h|enc|_method)(?=\s*=))",
    r"(?<![A-Za-z0-9_-])xf_(?:d|data|e|k|kb64|n|name|h|hmac|encoding|enc|method)"
    r"(?![A-Za-z0-9_-])",
    r"(?<![A-Za-z0-9_-])encoding\s*/\s*enc(?![A-Za-z0-9_-])",
    r"(?<![A-Za-z0-9_-])_method\s*/\s*method_override(?![A-Za-z0-9_-])",
)


def _read(relative_path: str) -> str:
    return (REPO_ROOT / relative_path).read_text(encoding="utf-8")


def _legacy_pattern_matches(document: str) -> tuple[str, ...]:
    return tuple(pattern for pattern in LEGACY_API_PATTERNS if re.search(pattern, document))


def test_legacy_api_patterns_are_mutation_sensitive_and_boundary_aware() -> None:
    """Proves every rejected alias family is caught without canonical collisions."""
    wire_keys = ("d", "e", "k", "n", "h", "enc", "_method")
    legacy_mutations = (
        "X-D: payload",
        "X-E: base64",
        "X-K: secret",
        "X-Kb64: true",
        "X-N: file.bin",
        "X-H: digest",
        "X-D-0: first chunk",
        "X-D-17: later chunk",
        "numeric `X-D-N` headers",
        '{"d0":"a"}',
        '{"d-0":"a"}',
        '{"d_0":"a"}',
        '{"data0":"a"}',
        '{"data-0":"a"}',
        "Cookie: xf_d=value",
        "Cookie: xf_data=value",
        "Cookie: xf_e=value",
        "Cookie: xf_k=value",
        "Cookie: xf_kb64=value",
        "Cookie: xf_n=value",
        "Cookie: xf_name=value",
        "Cookie: xf_h=value",
        "Cookie: xf_hmac=value",
        "Cookie: xf_encoding=value",
        "Cookie: xf_enc=value",
        "Cookie: xf_method=POST",
        "encoding / enc",
        "_method / method_override",
        *(f'{{"{key}":"value"}}' for key in wire_keys),
        *(f"/advanced?{key}=value" for key in wire_keys),
        *(f"{key}=value" for key in wire_keys),
    )
    canonical_controls = (
        "X-XFerry-Key: secret",
        "X-XFerry-Data-0: first chunk",
        '{"data_0":"a"}',
        "/advanced?data_0=value",
        "data_0=value",
        '{"method_override":"POST"}',
        "/advanced?method_override=POST",
        "method_override=POST",
        "Cookie: xferry_method_override=POST",
    )

    undetected = tuple(
        mutation for mutation in legacy_mutations if not _legacy_pattern_matches(mutation)
    )
    false_positives = tuple(
        control for control in canonical_controls if _legacy_pattern_matches(control)
    )

    assert undetected == ()
    assert false_positives == ()


def test_public_api_documents_only_token_scoped_advanced_sessions() -> None:
    """Catches a reintroduction of global routing or legacy carrier docs."""
    api = _read("API.md")

    for marker in LEGACY_API_MARKERS:
        assert marker not in api
    for pattern in LEGACY_API_PATTERNS:
        assert re.search(pattern, api) is None

    for marker in (
        "POST /_xferry/advanced-sessions",
        "GET /_xferry/advanced-sessions/current",
        "DELETE /_xferry/advanced-sessions/current",
        "X-XFerry-Advanced-Session",
        '{"data":"aGVsbG8=","encoding":"base64","encryption":"none","name":"hello.txt"}',
        "X-XFerry-Encryption: none",
        "curl --silent --show-error --fail-with-body",
    ):
        assert marker in api


def test_generated_api_mirror_has_the_same_advanced_session_contract() -> None:
    """Catches a stale generated API mirror after a root API contract change."""
    api = _read("API.md")
    mirror = _read("docs/api.md")

    assert mirror == API_MIRROR_BANNER + api.replace("(docs/ADR/", "(ADR/")
    for marker in LEGACY_API_MARKERS:
        assert marker not in mirror
    for pattern in LEGACY_API_PATTERNS:
        assert re.search(pattern, mirror) is None


def test_public_curl_journey_never_uses_a_session_token_after_revoke() -> None:
    """Catches a copy-paste journey that tries to use its revoked token."""
    api = _read("API.md")
    journey = api.split("### Public curl journey", maxsplit=1)[1].split("\n---", maxsplit=1)[0]
    commands = re.findall(r"(?ms)^\s*curl .*?(?=^\s*curl |\Z)", journey)
    revoke_indexes = [
        index
        for index, command in enumerate(commands)
        if "--request DELETE" in command
        and "$base_url/_xferry/advanced-sessions/current" in command
    ]

    assert len(revoke_indexes) == 1
    revoke_index = revoke_indexes[0]
    assert any("--request SYNCDATA" in command for command in commands[:revoke_index])
    assert all("$advanced_token" not in command for command in commands[revoke_index + 1 :])


def test_architecture_rejects_global_advanced_dispatch_descriptions() -> None:
    """Catches architecture guidance that selects Advanced routing globally."""
    architecture = _read("docs/architecture.md")

    for marker in (
        "advanced-routing",
        "process-local prefix/decoder state",
        "Unknown non-standard methods carrying payload retain the Advanced fallback",
        "marked paths",
    ):
        assert marker not in architecture

    for marker in (
        "X-XFerry-Advanced-Session",
        "per-server in-memory",
        "canonical carriers",
    ):
        assert marker in architecture


def test_nginx_example_documents_the_token_scoped_public_contract() -> None:
    """Catches an example that drifts from the public Advanced Sessions API."""
    example = _read("examples/advanced_upload_nginx.md")

    for marker in LEGACY_API_MARKERS:
        assert marker not in example
    for pattern in LEGACY_API_PATTERNS:
        assert re.search(pattern, example) is None
    for marker in (
        "xferry run",
        "POST /_xferry/advanced-sessions",
        "GET /_xferry/advanced-sessions/current",
        "DELETE /_xferry/advanced-sessions/current",
        "X-XFerry-Advanced-Session",
        '{"prefix":"/advanced","decoder":"auto","diagnostic_headers":true}',
        '{"data":"aGVsbG8=","encoding":"base64","encryption":"none","name":"hello.txt"}',
        "curl --silent --show-error --fail-with-body",
        "`none`, `xor`, or `aes`",
        "AES-256-GCM",
        "There is no AES-to-XOR or XOR-to-AES fallback",
    ):
        assert marker in example
    assert re.search(r"(?:--user|-u)(?:\s+|=)[\"']?\$credentials", example) is None
    assert (
        re.search(
            r"(?:--header|-H)(?:\s+|=)[\"'][^\n]*X-XFerry-Advanced-Session"
            r"[^\n]*\$advanced_token",
            example,
        )
        is None
    )
    assert "--config /run/secrets/xferry_curl.conf --config -" in example


@pytest.mark.parametrize(
    "secret_argv_mutation",
    (
        'curl --silent --show-error --fail-with-body --user "$credentials" "$base_url"',
        'curl --silent --show-error --fail-with-body --user="$credentials" "$base_url"',
        'curl --silent --show-error --fail-with-body -u "$credentials" "$base_url"',
        "curl --silent --show-error --fail-with-body --header "
        '"X-XFerry-Advanced-Session: $advanced_token" "$base_url"',
        "curl --silent --show-error --fail-with-body --header="
        '"X-XFerry-Advanced-Session: $advanced_token" "$base_url"',
        "curl --silent --show-error --fail-with-body -H "
        '"X-XFerry-Advanced-Session: $advanced_token" "$base_url"',
    ),
)
def test_mutation_nginx_example_rejects_secret_bearing_curl_argv(
    tmp_path: Path,
    secret_argv_mutation: str,
) -> None:
    """Catches Basic credentials or a session token expanded into curl argv."""
    example = tmp_path / "examples" / "advanced_upload_nginx.md"
    example.parent.mkdir(parents=True)
    document = _read("examples/advanced_upload_nginx.md")
    example.write_text(document, encoding="utf-8")
    baseline_findings = check_stale_docs.find_semantic_contract_issues(
        tmp_path,
        ("examples/advanced_upload_nginx.md",),
    )
    assert not any(
        "secret-bearing curl options" in finding.message for finding in baseline_findings
    )

    example.write_text(f"{document}\n```bash\n{secret_argv_mutation}\n```\n", encoding="utf-8")
    findings = check_stale_docs.find_semantic_contract_issues(
        tmp_path,
        ("examples/advanced_upload_nginx.md",),
    )

    assert any("secret-bearing curl options" in finding.message for finding in findings)


@pytest.mark.parametrize(
    "legacy_mutation",
    (
        "PUT /_xferry/advanced-routing",
        "X-D: payload",
        "X-N: file.bin",
        '{"d":"aGVsbG8="}',
    ),
)
def test_mutation_nginx_example_rejects_retired_routing_and_carriers(
    tmp_path: Path,
    legacy_mutation: str,
) -> None:
    """Proves the checker rejects each retired Advanced routing/carrier family."""
    example = tmp_path / "examples" / "advanced_upload_nginx.md"
    example.parent.mkdir(parents=True)
    document = (
        "POST /_xferry/advanced-sessions\n"
        "GET /_xferry/advanced-sessions/current\n"
        "DELETE /_xferry/advanced-sessions/current\n"
        "X-XFerry-Advanced-Session\n"
        '{"prefix":"/advanced","decoder":"auto","diagnostic_headers":true}\n'
        '{"data":"aGVsbG8=","encoding":"base64","encryption":"none","name":"hello.txt"}\n'
        "curl --silent --show-error --fail-with-body\n"
        "--config /run/secrets/xferry_curl.conf --config -\n"
        "encryption is required and exactly none|xor|aes; AES-256-GCM; "
        "no AES-to-XOR or XOR-to-AES fallback\n"
    )
    example.write_text(document, encoding="utf-8")
    assert (
        check_stale_docs.find_stale_references(
            tmp_path,
            ("examples/advanced_upload_nginx.md",),
        )
        == []
    )
    example.write_text(f"{document}{legacy_mutation}\n", encoding="utf-8")

    findings = check_stale_docs.find_stale_references(
        tmp_path,
        ("examples/advanced_upload_nginx.md",),
    )

    assert any("retired Advanced" in finding.message for finding in findings)


@pytest.mark.parametrize(
    "required_marker",
    (
        "POST /_xferry/advanced-sessions",
        "DELETE /_xferry/advanced-sessions/current",
        "X-XFerry-Advanced-Session",
        '{"prefix":"/advanced","decoder":"auto","diagnostic_headers":true}',
        "curl --silent --show-error --fail-with-body",
        "none|xor|aes",
    ),
)
def test_mutation_nginx_example_requires_session_journey_and_crypto_contract(
    tmp_path: Path,
    required_marker: str,
) -> None:
    """Proves removal of a required public-example contract is detected."""
    document = (
        "POST /_xferry/advanced-sessions\n"
        "GET /_xferry/advanced-sessions/current\n"
        "DELETE /_xferry/advanced-sessions/current\n"
        "X-XFerry-Advanced-Session\n"
        '{"prefix":"/advanced","decoder":"auto","diagnostic_headers":true}\n'
        '{"data":"aGVsbG8=","encoding":"base64","encryption":"none","name":"hello.txt"}\n'
        "curl --silent --show-error --fail-with-body\n"
        "--config /run/secrets/xferry_curl.conf --config -\n"
        "encryption is required and exactly none|xor|aes; AES-256-GCM; "
        "no AES-to-XOR or XOR-to-AES fallback\n"
    )
    example = tmp_path / "examples" / "advanced_upload_nginx.md"
    example.parent.mkdir(parents=True)
    example.write_text(document, encoding="utf-8")
    baseline_findings = check_stale_docs.find_semantic_contract_issues(
        tmp_path,
        ("examples/advanced_upload_nginx.md",),
    )
    assert not any("Advanced nginx example" in finding.message for finding in baseline_findings)
    example.write_text(document.replace(required_marker, "<removed>"), encoding="utf-8")

    findings = check_stale_docs.find_semantic_contract_issues(
        tmp_path,
        ("examples/advanced_upload_nginx.md",),
    )

    assert any("Advanced nginx example" in finding.message for finding in findings)
