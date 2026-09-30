"""Tests for the public xferry plugin API."""

from __future__ import annotations

import json
from dataclasses import FrozenInstanceError, fields
from pathlib import Path

import pytest

from tests.server_factory import make_server
from xferry.extensions import HandlerContext, PluginMethodSpec, PluginServices, PluginSpec
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
    from xferry.extensions import PluginServices as PublicPluginServices
    from xferry.extensions import PluginSpec as PublicPluginSpec

    assert PublicPluginMethodSpec is PluginMethodSpec
    assert PublicPluginServices is PluginServices
    assert PublicPluginSpec is PluginSpec


def test_plugin_context_exposes_only_narrow_services(temp_dir: Path) -> None:
    seen_contexts: list[HandlerContext] = []

    def handler(_request: HTTPRequest, context: HandlerContext) -> HTTPResponse:
        seen_contexts.append(context)
        response = HTTPResponse(200)
        response.set_body(context.services.upload_dir.name, "text/plain")
        return response

    plugin = PluginSpec(
        name="storage-plugin",
        methods=(PluginMethodSpec(method="STORE", handler=handler, mutating=False),),
    )
    server = make_server(root_dir=str(temp_dir), quiet=True, plugins=[plugin])

    response = server._dispatch_handler(_request("STORE"))

    assert response.status_code == 200
    assert response.body == b"uploads"
    assert len(seen_contexts) == 1
    context = seen_contexts[0]
    assert context.plugin_name == "storage-plugin"
    assert type(context.services) is PluginServices
    assert context.services.upload_dir is server.upload_dir
    assert context.services.upload_storage is server.upload_storage
    assert [field.name for field in fields(HandlerContext)] == [
        "services",
        "plugin_name",
    ]
    assert [field.name for field in fields(PluginServices)] == [
        "upload_dir",
        "upload_storage",
    ]
    assert not hasattr(context, "server")
    assert not hasattr(context, "__dict__")
    assert not hasattr(context.services, "__dict__")
    assert "__getattr__" not in HandlerContext.__dict__
    assert "__getattribute__" not in HandlerContext.__dict__

    for forbidden in (
        "server",
        "authenticator",
        "auth_controller",
        "auth_runtime",
        "advanced_sessions",
        "config",
        "lifecycle",
        "metrics",
        "notepad",
        "pipeline",
        "smuggle_temp",
        "tls",
    ):
        assert not hasattr(context, forbidden)
        assert not hasattr(context.services, forbidden)

    with pytest.raises(FrozenInstanceError):
        context.plugin_name = "changed"  # type: ignore[misc]
    with pytest.raises(FrozenInstanceError):
        context.services.upload_dir = temp_dir  # type: ignore[misc]
    with pytest.raises(TypeError, match="server"):
        HandlerContext(server=server, plugin_name="legacy")  # type: ignore[call-arg]


def test_plugin_storage_cannot_grant_smuggle_provenance(temp_dir: Path) -> None:
    artifact_name = "smuggle_0123456789abcdef.xhtml"

    def handler(_request: HTTPRequest, context: HandlerContext) -> HTTPResponse:
        context.services.upload_storage.publish_bytes(
            context.services.upload_dir / artifact_name,
            b"<html xmlns='http://www.w3.org/1999/xhtml'><script>0</script></html>",
        )
        return HTTPResponse(204)

    plugin = PluginSpec(
        name="storage",
        methods=(PluginMethodSpec(method="STORE", handler=handler, mutating=True),),
    )
    server = make_server(root_dir=str(temp_dir), quiet=True, plugins=[plugin])

    assert server._dispatch_handler(_request("STORE")).status_code == 204
    assert not server.handler_context.smuggle_temp.contains(server.upload_dir / artifact_name)

    response = server.handle_get(_request("GET", f"/uploads/{artifact_name}"))
    assert response.status_code == 200
    assert response.headers["Content-Type"] == "application/octet-stream"
    assert response.headers["Content-Disposition"].startswith("attachment;")


def test_plugin_methods_share_one_service_boundary(temp_dir: Path) -> None:
    seen_services: list[PluginServices] = []

    def handler(_request: HTTPRequest, context: HandlerContext) -> HTTPResponse:
        seen_services.append(context.services)
        return HTTPResponse(204)

    plugin = PluginSpec(
        name="shared",
        methods=(
            PluginMethodSpec(method="FIRST", handler=handler, mutating=False),
            PluginMethodSpec(method="SECOND", handler=handler, mutating=False),
        ),
    )
    server = make_server(root_dir=str(temp_dir), quiet=True, plugins=[plugin])

    server._dispatch_handler(_request("FIRST"))
    server._dispatch_handler(_request("SECOND"))

    assert len(seen_services) == 2
    assert seen_services[0] is seen_services[1]


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
