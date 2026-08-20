"""Drift tests for the built-in HTTP method policy registry."""

from __future__ import annotations

import base64
import json
import re
import subprocess
import sys
from pathlib import Path

from tests.conftest import make_request
from tests.server_factory import make_server
from xferry.extensions import HandlerContext, PluginMethodSpec, PluginSpec
from xferry.features import (
    BROWSER_PROTECTED_MUTATION_METHODS,
    BROWSER_READ_ONLY_METHODS,
    CORE_METHOD_SPEC_BY_NAME,
    CORE_METHODS,
    CoreMethodSpec,
    core_method_spec,
    core_method_specs,
    cors_methods,
    registry_methods,
    ui_method_groups,
)
from xferry.http import HTTPRequest, HTTPResponse
from xferry.http.cors import CORS_ALLOW_METHODS, is_http_token

EXPECTED_CORE_METHOD_POLICY = (
    ("GET", "handle_get", False, True, True, "request"),
    ("HEAD", "handle_head", False, True, True, "request"),
    ("POST", "handle_post", True, True, False, "upload"),
    ("PUT", "handle_none", True, True, False, "upload"),
    ("PATCH", "handle_patch", True, True, False, "upload"),
    ("DELETE", "handle_delete", True, True, False, "files"),
    ("OPTIONS", "handle_options", False, True, True, "request"),
    ("FETCH", "handle_fetch", False, True, True, "files"),
    ("INFO", "handle_info", False, True, True, "request"),
    ("PING", "handle_ping", False, True, True, "request"),
    ("NONE", "handle_none", True, True, False, "upload"),
    ("NOTE", "handle_note", True, True, False, "notepad"),
    ("SMUGGLE", "handle_smuggle", True, True, False, "files"),
)

EXPECTED_CORE_METHODS = tuple(row[0] for row in EXPECTED_CORE_METHOD_POLICY)
EXPECTED_WILDCARD_CORS_METHODS = (
    "GET",
    "HEAD",
    "OPTIONS",
    "FETCH",
    "INFO",
    "PING",
)
EXPECTED_METHOD_GROUPS = {
    "request": ("GET", "HEAD", "OPTIONS", "INFO", "PING"),
    "upload": ("POST", "PUT", "PATCH", "NONE"),
    "files": ("DELETE", "FETCH", "SMUGGLE"),
    "notepad": ("NOTE",),
}
LEGACY_UI_CAPABILITY_SHIM_TOKENS = (
    "ALWAYS_ON_SERVER_CAPABILITIES",
    "serverCapabilities",
    "isServerCapabilityEnabled",
    "advancedUploadCapability",
    "getAdvancedUploadCapability",
    "setAdvancedUploadCapability",
    "data-required-capability",
    "is-capability-disabled",
    "capabilityAvailable",
)


def _policy_tuple(spec: CoreMethodSpec) -> tuple[str, str, bool, bool, bool, str]:
    return (
        spec.method,
        spec.handler_name,
        spec.mutating,
        spec.cors_exact,
        spec.cors_wildcard,
        spec.ui_group,
    )


def _upload_payload_headers(data: bytes = b"advanced upload") -> dict[str, str]:
    return {
        "X-D": base64.b64encode(data).decode("ascii"),
        "X-N": "advanced-policy.txt",
    }


def test_core_method_specs_are_the_exact_builtin_contract() -> None:
    specs = core_method_specs()

    assert tuple(_policy_tuple(spec) for spec in specs) == EXPECTED_CORE_METHOD_POLICY
    assert CORE_METHODS == EXPECTED_CORE_METHODS
    assert registry_methods() == EXPECTED_CORE_METHODS
    assert tuple(CORE_METHOD_SPEC_BY_NAME) == EXPECTED_CORE_METHODS

    for spec in specs:
        assert core_method_spec(spec.method.lower()) == spec


def test_core_method_specs_are_unique_http_tokens_and_documented() -> None:
    specs = core_method_specs()
    methods = [spec.method for spec in specs]

    assert len(methods) == len(set(methods)) == 13
    for spec in specs:
        assert spec.method == spec.method.upper()
        assert is_http_token(spec.method)
        assert spec.handler_name.startswith("handle_")
        assert spec.exposure_note.strip()


def test_core_method_policy_import_stays_independent_of_consumers() -> None:
    probe = subprocess.run(
        [
            sys.executable,
            "-c",
            (
                "import sys; import xferry.features; "
                "forbidden = [name for name in sys.modules "
                "if name == 'xferry.server' "
                "or name.startswith(('xferry.handlers', 'xferry.http'))]; "
                "assert not forbidden, f'unexpected imports: {forbidden}'"
            ),
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    assert probe.returncode == 0, probe.stderr or probe.stdout


def test_derived_cors_and_mutation_sets_match_registry_metadata() -> None:
    specs = core_method_specs()
    mutating_methods = frozenset(spec.method for spec in specs if spec.mutating)
    read_only_methods = frozenset(spec.method for spec in specs if spec.cors_wildcard)

    assert BROWSER_PROTECTED_MUTATION_METHODS == mutating_methods
    assert BROWSER_READ_ONLY_METHODS == read_only_methods
    assert cors_methods() == EXPECTED_CORE_METHODS
    assert CORS_ALLOW_METHODS == EXPECTED_CORE_METHODS
    assert cors_methods(read_only=True) == EXPECTED_WILDCARD_CORS_METHODS
    assert mutating_methods.isdisjoint(cors_methods(read_only=True))


def test_handler_registry_binds_each_core_method_to_declared_handler(temp_dir: Path) -> None:
    server = make_server(root_dir=str(temp_dir), quiet=True)

    assert tuple(server.method_handlers.keys()) == EXPECTED_CORE_METHODS
    for spec in core_method_specs():
        assert server.method_handlers[spec.method] == getattr(server, spec.handler_name)


def test_core_mutation_metadata_no_longer_depends_on_advanced_payload_sniffing() -> None:
    for spec in core_method_specs():
        assert core_method_spec(spec.method).mutating is spec.mutating  # type: ignore[union-attr]


def test_unknown_method_with_or_without_legacy_payload_is_405_without_session(
    temp_dir: Path,
) -> None:
    server = make_server(root_dir=str(temp_dir), quiet=True)

    no_payload = server._dispatch_handler(make_request("XUPLOAD", "/"))
    legacy_payload = server._dispatch_handler(
        make_request("XUPLOAD", "/", headers=_upload_payload_headers())
    )

    assert no_payload.status_code == 405
    assert legacy_payload.status_code == 405
    assert not (server.upload_dir / "advanced-policy.txt").exists()


def test_ping_reports_core_methods_groups_and_plugins_separately(temp_dir: Path) -> None:
    def handler(request: HTTPRequest, context: HandlerContext) -> HTTPResponse:
        response = HTTPResponse(200)
        response.set_body(f"{request.method}:{context.plugin_name}", "text/plain")
        return response

    plugin = PluginSpec(
        name="demo",
        methods=(
            PluginMethodSpec(
                method="ECHO",
                handler=handler,
                mutating=False,
                cors_allowed=True,
            ),
        ),
    )
    server = make_server(root_dir=str(temp_dir), quiet=True, plugins=[plugin])

    ping = json.loads(server._dispatch_handler(make_request("PING", "/")).body)

    assert ping["supported_methods"] == list(EXPECTED_CORE_METHODS)
    assert ping["method_groups"] == {
        group: list(methods) for group, methods in EXPECTED_METHOD_GROUPS.items()
    }
    assert ping["plugin_methods"] == ["ECHO"]
    assert "ECHO" not in ping["supported_methods"]
    assert all("ECHO" not in methods for methods in ping["method_groups"].values())


def test_ui_method_groups_are_stable_and_filter_only_supported_core_methods() -> None:
    assert ui_method_groups() == EXPECTED_METHOD_GROUPS
    assert ui_method_groups(["get", "post", "echo", "NOTE"]) == {
        "request": ("GET",),
        "upload": ("POST",),
        "notepad": ("NOTE",),
    }


def test_static_ui_is_bound_to_methods_not_legacy_fake_capabilities() -> None:
    ui_root = Path("xferry/data/static/ui")
    ui_paths = (
        Path("xferry/data/index.html"),
        *sorted(ui_root.glob("*.js")),
        *sorted(ui_root.glob("*.css")),
    )
    ui_source = "\n".join(path.read_text(encoding="utf-8") for path in ui_paths)

    for token in LEGACY_UI_CAPABILITY_SHIM_TOKENS:
        assert token not in ui_source

    assert "supported_methods" in ui_source
    assert "method_groups" in ui_source
    assert "setServerMethodsFromPing" in ui_source
    assert "isServerMethodSupported" in ui_source
    assert "if (!serverMethodGroups)" in ui_source
    assert (
        "return Array.isArray(groupedMethods) && groupedMethods.includes(normalizedMethod);"
        in ui_source
    )
    assert "isServerMethodInGroup('DELETE', 'files')" in ui_source
    assert "isServerMethodInGroup('FETCH', 'files')" in ui_source
    assert "isServerMethodSupported('NOTE')" in ui_source
    assert "isServerMethodInGroup('SMUGGLE', 'files')" in ui_source


def test_static_ui_request_and_upload_method_controls_match_registry_groups() -> None:
    html = Path("xferry/data/index.html").read_text(encoding="utf-8")
    requests_source = Path("xferry/data/static/ui/requests.js").read_text(encoding="utf-8")

    request_controls = re.findall(r'data-request-method="([^"]+)"', html)
    upload_controls = re.findall(r'data-upload-method="([^"]+)"', html)

    assert len(request_controls) == len(set(request_controls))
    assert set(request_controls) == set(EXPECTED_CORE_METHODS)
    assert len(upload_controls) == len(set(upload_controls))
    assert set(upload_controls) == set(EXPECTED_METHOD_GROUPS["upload"])

    for object_name in ("requestPreviewExpectedStatuses", "requestBatchInitialPaths"):
        match = re.search(
            rf"const {object_name} = \{{(?P<body>.*?)^\}};",
            requests_source,
            flags=re.MULTILINE | re.DOTALL,
        )
        assert match is not None
        object_methods = re.findall(r"^\s{4}([A-Z]+):", match.group("body"), flags=re.MULTILINE)
        assert set(object_methods) == set(EXPECTED_CORE_METHODS)
