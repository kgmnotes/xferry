"""Tests for xferry.handlers.registry.HandlerRegistry."""

from __future__ import annotations

from typing import cast

import pytest

from xferry.features import registry_methods
from xferry.handlers import HandlerMixin
from xferry.handlers.registry import Handler, HandlerRegistry
from xferry.http import HTTPRequest, HTTPResponse


def _noop_handler(request: HTTPRequest) -> HTTPResponse:
    return HTTPResponse(200)


def _other_handler(request: HTTPRequest) -> HTTPResponse:
    return HTTPResponse(204)


class TestHandlerRegistry:
    def test_handler_mixin_registers_core_methods_without_feature_set(self) -> None:
        server = HandlerMixin()

        registry = server.build_method_handlers()

        assert registry.methods() == list(registry_methods())

    def test_register_and_lookup(self) -> None:
        reg = HandlerRegistry()
        reg.register("GET", _noop_handler)

        assert reg.get_handler("GET") is _noop_handler
        assert reg.get_handler("get") is _noop_handler  # case-insensitive
        assert reg.get_handler("POST") is None

    def test_register_many(self) -> None:
        reg = HandlerRegistry()
        reg.register_many({"GET": _noop_handler, "POST": _other_handler})

        assert reg.get_handler("GET") is _noop_handler
        assert reg.get_handler("POST") is _other_handler

    def test_overwrite_existing(self) -> None:
        reg = HandlerRegistry()
        reg.register("GET", _noop_handler)
        reg.register("GET", _other_handler)

        assert reg.get_handler("GET") is _other_handler

    def test_unregister_removes_handler(self) -> None:
        reg = HandlerRegistry()
        reg.register("GET", _noop_handler)
        reg.unregister("GET")

        assert reg.get_handler("GET") is None

    def test_unregister_missing_is_noop(self) -> None:
        reg = HandlerRegistry()
        reg.unregister("MISSING")  # must not raise

    def test_methods_preserves_insertion_order(self) -> None:
        reg = HandlerRegistry()
        reg.register("GET", _noop_handler)
        reg.register("POST", _other_handler)
        reg.register("PUT", _noop_handler)

        assert reg.methods() == ["GET", "POST", "PUT"]

    def test_mapping_protocol_getitem(self) -> None:
        reg = HandlerRegistry()
        reg.register("GET", _noop_handler)

        assert reg["GET"] is _noop_handler
        assert reg["get"] is _noop_handler

    def test_mapping_protocol_missing_key_raises(self) -> None:
        reg = HandlerRegistry()
        with pytest.raises(KeyError):
            _ = reg["MISSING"]

    def test_mapping_protocol_contains(self) -> None:
        reg = HandlerRegistry()
        reg.register("GET", _noop_handler)

        assert "GET" in reg
        assert "get" in reg
        assert "POST" not in reg
        assert 123 not in cast(dict, reg)  # non-string key

    def test_mapping_protocol_len_and_iter(self) -> None:
        reg = HandlerRegistry()
        reg.register("GET", _noop_handler)
        reg.register("POST", _other_handler)

        assert len(reg) == 2
        assert set(iter(reg)) == {"GET", "POST"}
        assert set(reg.keys()) == {"GET", "POST"}

    def test_register_normalises_case(self) -> None:
        reg = HandlerRegistry()
        reg.register("get", _noop_handler)

        assert "GET" in reg
        assert reg["GET"] is _noop_handler

    def test_is_usable_as_dict(self) -> None:
        """Callers that treat registry as Mapping must not break."""
        reg = HandlerRegistry()
        reg.register("GET", _noop_handler)

        for name, handler in reg.items():
            assert name == "GET"
            # Handler is callable with the right signature
            _ = cast(Handler, handler)
