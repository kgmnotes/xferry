"""Public plugin API for explicitly enabled xferry extensions."""

from __future__ import annotations

import importlib
import re
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass

from .http import HTTPRequest, HTTPResponse

_METHOD_RE = re.compile(r"^[A-Z][A-Z0-9_-]*$")


@dataclass(frozen=True)
class HandlerContext:
    """Context passed to plugin HTTP method handlers."""

    server: object
    plugin_name: str


PluginHandler = Callable[[HTTPRequest, HandlerContext], HTTPResponse]


@dataclass(frozen=True)
class PluginMethodSpec:
    """One HTTP method exported by a plugin."""

    method: str
    handler: PluginHandler
    mutating: bool = True
    cors_allowed: bool = False

    def normalized(self) -> PluginMethodSpec:
        method = self.method.strip().upper()
        if not _METHOD_RE.fullmatch(method):
            raise ValueError(f"invalid plugin method name: {self.method!r}")
        return PluginMethodSpec(
            method=method,
            handler=self.handler,
            mutating=self.mutating,
            cors_allowed=self.cors_allowed,
        )


@dataclass(frozen=True)
class PluginSpec:
    """A plugin declaration loaded only through explicit allowlists."""

    name: str
    methods: tuple[PluginMethodSpec, ...]

    def normalized(self) -> PluginSpec:
        name = self.name.strip()
        if not name:
            raise ValueError("plugin name must not be empty")
        return PluginSpec(
            name=name,
            methods=tuple(method.normalized() for method in self.methods),
        )


def load_plugin_specs(entries: Iterable[str]) -> tuple[PluginSpec, ...]:
    """Load plugin specs from explicit ``module`` or ``module:attribute`` entries."""
    specs: list[PluginSpec] = []
    for entry in entries:
        entry = entry.strip()
        if not entry:
            continue
        specs.append(_load_plugin_spec(entry))
    return tuple(specs)


def _load_plugin_spec(entry: str) -> PluginSpec:
    module_name, separator, attr_name = entry.partition(":")
    module = importlib.import_module(module_name)
    if separator:
        candidate = getattr(module, attr_name)
    elif hasattr(module, "plugin"):
        candidate = module.plugin
    elif hasattr(module, "get_plugin"):
        candidate = module.get_plugin
    else:
        raise ValueError(
            f"plugin module {module_name!r} must expose plugin, get_plugin(), or module:attribute"
        )

    if callable(candidate) and not isinstance(candidate, PluginSpec):
        candidate = candidate()
    if not isinstance(candidate, PluginSpec):
        raise ValueError(f"plugin entry {entry!r} did not resolve to PluginSpec")
    return candidate.normalized()


def coerce_plugin_specs(
    plugins: Sequence[PluginSpec] | None,
    plugin_modules: Sequence[str] | None,
) -> tuple[PluginSpec, ...]:
    """Combine directly supplied specs and explicitly allowed module entries."""
    direct = tuple(plugin.normalized() for plugin in (plugins or ()))
    loaded = load_plugin_specs(plugin_modules or ())
    return direct + loaded


__all__ = [
    "HandlerContext",
    "PluginHandler",
    "PluginMethodSpec",
    "PluginSpec",
    "coerce_plugin_specs",
    "load_plugin_specs",
]
