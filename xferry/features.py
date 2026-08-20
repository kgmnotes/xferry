"""Always-on core method policy.

This module deliberately stores handler bindings as names rather than importing
handler classes.  The registry can therefore be consumed by handlers, CORS,
discovery, browser-mutation policy, and tests without creating an import cycle.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Literal

CoreMethodUiGroup = Literal["request", "upload", "files", "notepad"]


@dataclass(frozen=True, slots=True)
class CoreMethodSpec:
    """Policy metadata for one always-on built-in HTTP method."""

    method: str
    handler_name: str
    mutating: bool
    cors_exact: bool
    cors_wildcard: bool
    ui_group: CoreMethodUiGroup
    exposure_note: str


CORE_METHOD_SPECS: tuple[CoreMethodSpec, ...] = (
    CoreMethodSpec(
        method="GET",
        handler_name="handle_get",
        mutating=False,
        cors_exact=True,
        cors_wildcard=True,
        ui_group="request",
        exposure_note="Reads the built-in UI or files within the uploads scope.",
    ),
    CoreMethodSpec(
        method="HEAD",
        handler_name="handle_head",
        mutating=False,
        cors_exact=True,
        cors_wildcard=True,
        ui_group="request",
        exposure_note="Reads response metadata without returning a response body.",
    ),
    CoreMethodSpec(
        method="POST",
        handler_name="handle_post",
        mutating=True,
        cors_exact=True,
        cors_wildcard=False,
        ui_group="upload",
        exposure_note="Stores an ordinary upload from the request body.",
    ),
    CoreMethodSpec(
        method="PUT",
        handler_name="handle_none",
        mutating=True,
        cors_exact=True,
        cors_wildcard=False,
        ui_group="upload",
        exposure_note="Stores an ordinary upload through the legacy upload handler.",
    ),
    CoreMethodSpec(
        method="PATCH",
        handler_name="handle_patch",
        mutating=True,
        cors_exact=True,
        cors_wildcard=False,
        ui_group="upload",
        exposure_note="Creates or updates an uploaded file from the request body.",
    ),
    CoreMethodSpec(
        method="DELETE",
        handler_name="handle_delete",
        mutating=True,
        cors_exact=True,
        cors_wildcard=False,
        ui_group="files",
        exposure_note="Deletes uploaded files or explicitly clears the uploads scope.",
    ),
    CoreMethodSpec(
        method="OPTIONS",
        handler_name="handle_options",
        mutating=False,
        cors_exact=True,
        cors_wildcard=True,
        ui_group="request",
        exposure_note="Reports CORS preflight policy without mutating server state.",
    ),
    CoreMethodSpec(
        method="FETCH",
        handler_name="handle_fetch",
        mutating=False,
        cors_exact=True,
        cors_wildcard=True,
        ui_group="files",
        exposure_note="Downloads an uploaded file with FETCH status metadata.",
    ),
    CoreMethodSpec(
        method="INFO",
        handler_name="handle_info",
        mutating=False,
        cors_exact=True,
        cors_wildcard=True,
        ui_group="request",
        exposure_note="Lists or inspects paths constrained to the uploads scope.",
    ),
    CoreMethodSpec(
        method="PING",
        handler_name="handle_ping",
        mutating=False,
        cors_exact=True,
        cors_wildcard=True,
        ui_group="request",
        exposure_note="Reports health, method discovery, and operational metrics.",
    ),
    CoreMethodSpec(
        method="NONE",
        handler_name="handle_none",
        mutating=True,
        cors_exact=True,
        cors_wildcard=False,
        ui_group="upload",
        exposure_note="Stores an ordinary upload through the legacy NONE method.",
    ),
    CoreMethodSpec(
        method="NOTE",
        handler_name="handle_note",
        mutating=True,
        cors_exact=True,
        cors_wildcard=False,
        ui_group="notepad",
        exposure_note="Reads and mutates encrypted Secure Notepad state.",
    ),
    CoreMethodSpec(
        method="SMUGGLE",
        handler_name="handle_smuggle",
        mutating=True,
        cors_exact=True,
        cors_wildcard=False,
        ui_group="files",
        exposure_note="Creates a controlled temporary HTML download artifact.",
    ),
)

_core_method_specs_by_name = {spec.method: spec for spec in CORE_METHOD_SPECS}
if len(_core_method_specs_by_name) != len(CORE_METHOD_SPECS):
    raise RuntimeError("duplicate method in CORE_METHOD_SPECS")

CORE_METHOD_SPEC_BY_NAME: Mapping[str, CoreMethodSpec] = MappingProxyType(
    _core_method_specs_by_name
)
CORE_METHODS: tuple[str, ...] = tuple(spec.method for spec in CORE_METHOD_SPECS)
BROWSER_PROTECTED_MUTATION_METHODS = frozenset(
    spec.method for spec in CORE_METHOD_SPECS if spec.mutating
)
BROWSER_READ_ONLY_METHODS = frozenset(
    spec.method for spec in CORE_METHOD_SPECS if spec.cors_wildcard
)
WEBSOCKET_NOTES_PATH_PREFIX = "/notes/ws"


def core_method_specs() -> tuple[CoreMethodSpec, ...]:
    """Return the immutable built-in method registry."""
    return CORE_METHOD_SPECS


def core_method_spec(method: str) -> CoreMethodSpec | None:
    """Return built-in policy metadata for *method*, case-insensitively."""
    return CORE_METHOD_SPEC_BY_NAME.get(method.strip().upper())


def registry_methods() -> tuple[str, ...]:
    """Return built-in HTTP methods in canonical registration order."""
    return CORE_METHODS


def cors_methods(*, read_only: bool = False) -> tuple[str, ...]:
    """Return core methods eligible for exact-origin or wildcard CORS."""
    return tuple(
        spec.method
        for spec in CORE_METHOD_SPECS
        if (spec.cors_wildcard if read_only else spec.cors_exact)
    )


def ui_method_groups(
    available_methods: Iterable[str] | None = None,
) -> dict[CoreMethodUiGroup, tuple[str, ...]]:
    """Project core methods into stable UI groups.

    ``available_methods`` can filter the projection to methods registered by a
    concrete server instance.  Availability still comes exclusively from
    PING ``supported_methods``; groups are presentation metadata.
    """
    available = (
        {method.strip().upper() for method in available_methods}
        if available_methods is not None
        else None
    )
    grouped: dict[CoreMethodUiGroup, list[str]] = {}
    for spec in CORE_METHOD_SPECS:
        if available is not None and spec.method not in available:
            continue
        grouped.setdefault(spec.ui_group, []).append(spec.method)
    return {group: tuple(methods) for group, methods in grouped.items()}


def allows_unknown_cors_method(requested_method: str, *, read_only: bool = False) -> bool:
    """Return True when CORS may echo an advanced-upload method token."""
    return not read_only and bool(requested_method.strip())


def websocket_route_enabled(path: str) -> bool:
    """Return True when the notepad WebSocket route is admitted."""
    return path == WEBSOCKET_NOTES_PATH_PREFIX
