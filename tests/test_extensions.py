"""Tests for the public xferry plugin API."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tests.server_factory import make_server
from xferry.extensions import HandlerContext, PluginMethodSpec, PluginSpec
from xferry.http import HTTPRequest, HTTPResponse


def _request(method: str, path: str = "/") -> HTTPRequest:
    return HTTPRequest(f"{method} {path} HTTP/1.1\r\nHost: example.test\r\n\r\n".encode("ascii"))


def test_plugin_method_registers_and_dispatches(temp_dir: Path) -> None:
    def handler(request: HTTPRequest, context: HandlerContext) -> HTTPResponse:
        response = HTTPResponse(200)
        response.set_body(
            f"{request.method}:{context.plugin_name}".encode(),
            "text/plain",
        )
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

    assert "ECHO" in server.method_handlers
    assert server.plugin_methods == {"ECHO": "demo"}
    response = server._dispatch_handler(_request("ECHO"))
    assert response.status_code == 200
    assert response.body == b"ECHO:demo"

    ping = json.loads(server.handle_ping(_request("PING")).body.decode("utf-8"))
    assert ping["plugin_methods"] == ["ECHO"]
    assert "ECHO" not in ping["supported_methods"]


def test_public_xferry_extensions_exports_plugin_api() -> None:
    from xferry.extensions import PluginMethodSpec as PublicPluginMethodSpec
    from xferry.extensions import PluginSpec as PublicPluginSpec

    assert PublicPluginMethodSpec is PluginMethodSpec
    assert PublicPluginSpec is PluginSpec


def test_plugin_method_cannot_override_core_method_by_default(temp_dir: Path) -> None:
    plugin = PluginSpec(
        name="bad",
        methods=(
            PluginMethodSpec(
                method="GET",
                handler=lambda _request, _context: HTTPResponse(200),
            ),
        ),
    )

    with pytest.raises(ValueError, match="core method"):
        make_server(root_dir=str(temp_dir), quiet=True, plugins=[plugin])


def test_plugin_method_can_override_core_method_when_enabled(temp_dir: Path) -> None:
    plugin = PluginSpec(
        name="shadow-smuggle",
        methods=(
            PluginMethodSpec(
                method="SMUGGLE",
                handler=lambda _request, _context: HTTPResponse(200),
            ),
        ),
    )

    server = make_server(
        root_dir=str(temp_dir),
        quiet=True,
        plugins=[plugin],
        plugins_override_core=True,
    )

    assert server.plugin_methods == {"SMUGGLE": "shadow-smuggle"}
    response = server._dispatch_handler(_request("SMUGGLE"))
    assert response.status_code == 200
    ping = json.loads(server.handle_ping(_request("PING")).body.decode("utf-8"))
    assert "smuggle_capabilities" not in ping
    assert "SMUGGLE" not in ping["supported_methods"]
    assert "SMUGGLE" not in ping["method_groups"]["files"]
    assert ping["plugin_methods"] == ["SMUGGLE"]


def test_plugin_method_spec_rejects_removed_profiles_argument() -> None:
    with pytest.raises(TypeError, match="profiles"):
        PluginMethodSpec(
            method="EXPX",
            handler=lambda _request, _context: HTTPResponse(200),
            profiles=("experimental",),
        )


def test_plugin_method_registers_when_plugin_is_enabled(temp_dir: Path) -> None:
    plugin = PluginSpec(
        name="enabled-plugin",
        methods=(
            PluginMethodSpec(
                method="EXPX",
                handler=lambda _request, _context: HTTPResponse(200),
            ),
        ),
    )

    server = make_server(root_dir=str(temp_dir), quiet=True, plugins=[plugin])

    assert "EXPX" in server.method_handlers


def test_mutating_plugin_method_uses_browser_mutation_guard(temp_dir: Path) -> None:
    plugin = PluginSpec(
        name="mutator",
        methods=(
            PluginMethodSpec(
                method="BURN",
                handler=lambda _request, _context: HTTPResponse(204),
                mutating=True,
                cors_allowed=True,
            ),
        ),
    )
    server = make_server(root_dir=str(temp_dir), quiet=True, plugins=[plugin])

    assert server._is_browser_protected_mutation(_request("BURN")) is True


def test_plugin_cors_policy_exposes_only_cors_allowed_methods(temp_dir: Path) -> None:
    plugin = PluginSpec(
        name="cors-demo",
        methods=(
            PluginMethodSpec(
                method="SAFEPLUGIN",
                handler=lambda _request, _context: HTTPResponse(200),
                mutating=False,
                cors_allowed=True,
            ),
            PluginMethodSpec(
                method="INTERNALPLUGIN",
                handler=lambda _request, _context: HTTPResponse(200),
                mutating=False,
                cors_allowed=False,
            ),
        ),
    )
    server = make_server(root_dir=str(temp_dir), quiet=True, plugins=[plugin])

    methods = server._cors_allow_methods_header().split(", ")

    assert "SAFEPLUGIN" in methods
    assert "INTERNALPLUGIN" not in methods
