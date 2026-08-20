"""Shared, non-sensitive upload diagnostics for Basic and Advanced handlers."""

from __future__ import annotations

from dataclasses import dataclass

from ..advanced_sessions import AdvancedSessionDispatch
from ..http import HTTPResponse

DIAGNOSTIC_HEADER_NAMES = ("X-XFerry-Handler",)


@dataclass(frozen=True)
class UploadDiagnostics:
    """The additive JSON diagnostics contract for one upload attempt."""

    dispatch: str
    profile: str
    carrier: str
    filename_source: str
    normalized_filename: str | None
    collision_renamed: bool | None
    request_body_size: int
    payload_size: int | None
    file_content_type: str | None
    sha256: str | None


def add_upload_diagnostics(
    response: HTTPResponse,
    diagnostics: UploadDiagnostics,
    dispatch: AdvancedSessionDispatch | None,
) -> HTTPResponse:
    """Optionally expose the dispatch header without mutating response content."""
    if diagnostics.dispatch == "advanced" and dispatch is not None and dispatch.diagnostic_headers:
        response.set_header("X-XFerry-Handler", diagnostics.dispatch)
        response.add_cors_expose_headers(*DIAGNOSTIC_HEADER_NAMES)

    return response
