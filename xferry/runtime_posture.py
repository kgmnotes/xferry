"""Derived, secret-free operator posture for one resolved xferry launch."""

from __future__ import annotations

import ipaddress
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Literal

from .encrypted_transfer import EUF_CHUNK_SIZE, EUF_GCM_TAG_SIZE
from .resource_policy import default_body_memory_budget

if TYPE_CHECKING:
    from .settings import ServerSettings


BODY_ADMISSION_BUDGET_NOTE = (
    "Body memory is an admission budget for in-flight request bodies, not an RSS "
    "ceiling; decoded, parsed, TLS, and Python overhead can coexist."
)
WEBSOCKET_WORKER_NOTE = (
    "Idle WebSockets hold connection/session slots; processing permits are released before sending."
)
_MIB = 1024 * 1024
_ENCRYPTED_UPLOAD_BODY_BUDGET_FLOOR_MB = (
    2 * (EUF_CHUNK_SIZE + EUF_GCM_TAG_SIZE) + _MIB - 1
) // _MIB


@dataclass(frozen=True)
class PostureWarning:
    """Stable warning code plus operator-facing remediation text."""

    code: str
    message: str


@dataclass(frozen=True)
class RuntimePosture:
    """Typed, redacted summary derived from effective settings."""

    effective_url: str
    exposure: Literal["loopback", "all-interfaces", "network"]
    data_root: str
    uploads_path: str
    notes_path: str
    persistence: Literal["operator-managed"]
    tls_mode: Literal[
        "disabled",
        "self-signed",
        "certificate-files",
        "acme-domain",
        "acme-sslip",
    ]
    auth_mode: Literal["disabled", "generated", "inline", "file"]
    allowed_hosts_mode: Literal["auto", "explicit"]
    allowed_hosts: tuple[str, ...]
    max_upload_mb: int
    encrypted_uploads: bool
    encrypted_upload_max_size_mb: int
    encrypted_upload_incomplete_ttl_seconds: int
    body_admission_budget_mb: int
    workers: int
    max_websocket_connections: int
    upload_storage_limit_mb: int | None
    upload_file_limit: int | None
    upload_reserve_free_mb: int
    upload_quota_externally_managed: bool
    warnings: tuple[PostureWarning, ...]
    access: str = "private"
    https_mode: str = "off"
    notes: tuple[str, ...] = (
        BODY_ADMISSION_BUDGET_NOTE,
        WEBSOCKET_WORKER_NOTE,
    )

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-safe representation that cannot contain credentials."""
        data = asdict(self)
        data["warnings"] = [asdict(warning) for warning in self.warnings]
        data["notes"] = list(self.notes)
        return data

    def render_lines(self, *, effective_url: str | None = None) -> list[str]:
        """Render one shared human-readable posture for checks and startup."""
        selected_url = effective_url or self.effective_url
        encrypted_max = (
            f"{self.encrypted_upload_max_size_mb} MB"
            if self.encrypted_upload_max_size_mb
            else "automatic (quota/free space)"
        )

        lines = [
            "Runtime posture:",
            f"  Access: {self.access}",
            f"  Effective URL: {selected_url}",
            f"  Exposure: {self.exposure}",
            f"  Files folder: {self.uploads_path}",
            f"  Private state: {self.data_root}",
            f"  HTTPS: {self.https_mode}; authentication: {self.auth_mode}",
            (
                "  Request authorities: "
                + (
                    ", ".join(self.allowed_hosts)
                    if self.allowed_hosts_mode == "explicit"
                    else "auto (listener/certificate derived)"
                )
            ),
            (
                f"  Body admission budget: {self.body_admission_budget_mb} MB; "
                f"workers: {self.workers}; WebSockets: {self.max_websocket_connections}"
            ),
            (
                "  Encrypted uploads: "
                + (
                    f"enabled (max: {encrypted_max}; "
                    f"incomplete TTL: {self.encrypted_upload_incomplete_ttl_seconds}s)"
                    if self.encrypted_uploads
                    else "disabled"
                )
            ),
        ]
        lines.extend(f"  NOTE: {note}" for note in self.notes)
        for warning in self.warnings:
            if effective_url is not None and warning.code == "sslip-hostname-pending":
                continue
            lines.append(f"  WARNING [{warning.code}]: {warning.message}")
        return lines


def derive_runtime_posture(
    settings: ServerSettings,
    *,
    effective_host: str | None = None,
) -> RuntimePosture:
    """Derive effective URL, boundaries, limits and warnings without secrets."""
    settings.validate()
    bind_exposure = _classify_exposure(settings.host)
    tls_mode = _tls_mode(settings)
    auth_mode = _auth_mode(settings)
    display_host = effective_host or _settings_display_host(settings)
    protocol = "https" if settings.effective_tls_enabled() else "http"
    effective_url = f"{protocol}://{_url_host(display_host)}:{settings.port}"
    data_root = Path(settings.state_dir or ".").expanduser().resolve()

    warnings: list[PostureWarning] = []
    if bind_exposure != "loopback" and settings.access != "public":
        warnings.append(
            PostureWarning(
                code="lab-network-access",
                message=(
                    "Lab access is intended for a trusted test network; "
                    "use public access before sharing outside it."
                ),
            )
        )
    if settings.https_mode == "auto" and effective_host is None and not settings.public_ip:
        warnings.append(
            PostureWarning(
                code="sslip-hostname-pending",
                message=(
                    "The final sslip.io hostname is resolved during TLS startup; the "
                    "displayed URL is a bind target until then."
                ),
            )
        )

    from .request_admission import normalize_allowed_hosts

    allowed_hosts = normalize_allowed_hosts(tuple(settings.allowed_hosts))
    body_admission_budget_mb = (
        settings.body_memory_budget_mb
        if settings.body_memory_budget_mb is not None
        else default_body_memory_budget() // _MIB
    )
    if settings.encrypted_uploads and settings.body_memory_budget_mb is None:
        body_admission_budget_mb = max(
            body_admission_budget_mb,
            _ENCRYPTED_UPLOAD_BODY_BUDGET_FLOOR_MB,
        )
    return RuntimePosture(
        effective_url=effective_url,
        exposure=bind_exposure,
        data_root=str(data_root),
        uploads_path=str(
            Path(settings.files_dir).expanduser().resolve()
            if settings.files_dir is not None
            else data_root / "uploads"
        ),
        notes_path=str(data_root / "notes"),
        persistence="operator-managed",
        tls_mode=tls_mode,
        auth_mode=auth_mode,
        allowed_hosts_mode="explicit" if allowed_hosts else "auto",
        allowed_hosts=allowed_hosts,
        max_upload_mb=settings.max_size_mb,
        encrypted_uploads=settings.encrypted_uploads,
        encrypted_upload_max_size_mb=settings.encrypted_upload_max_size_mb,
        encrypted_upload_incomplete_ttl_seconds=(settings.encrypted_upload_incomplete_ttl_seconds),
        body_admission_budget_mb=body_admission_budget_mb,
        workers=settings.workers,
        max_websocket_connections=(
            settings.max_websocket_connections
            if settings.max_websocket_connections is not None
            else 8
        ),
        upload_storage_limit_mb=settings.upload_storage_limit_mb or None,
        upload_file_limit=settings.upload_file_limit or None,
        upload_reserve_free_mb=settings.upload_reserve_free_mb,
        upload_quota_externally_managed=settings.upload_quota_externally_managed,
        warnings=tuple(warnings),
        access=settings.access,
        https_mode=settings.https_mode or "off",
    )


def _classify_exposure(
    host: str,
) -> Literal["loopback", "all-interfaces", "network"]:
    normalized = host.strip().lower().strip("[]")
    # Classify intentional wildcard bindings as public exposure.
    if normalized in {"0.0.0.0", "::"}:  # nosec B104
        return "all-interfaces"
    if normalized == "localhost":
        return "loopback"
    try:
        return "loopback" if ipaddress.ip_address(normalized).is_loopback else "network"
    except ValueError:
        return "network"


def _settings_display_host(settings: ServerSettings) -> str:
    if settings.https_mode == "domain" and settings.domain:
        return settings.domain
    if settings.https_mode == "auto" and settings.public_ip:
        return f"{settings.public_ip.replace('.', '-')}.sslip.io"
    return settings.host


def _url_host(host: str) -> str:
    normalized = host.strip("[]")
    if ":" in normalized:
        return f"[{normalized}]"
    return normalized


def _tls_mode(
    settings: ServerSettings,
) -> Literal[
    "disabled",
    "self-signed",
    "certificate-files",
    "acme-domain",
    "acme-sslip",
]:
    if settings.https_mode == "auto":
        return "acme-sslip"
    if settings.https_mode == "domain":
        return "acme-domain"
    if settings.cert_file and settings.key_file:
        return "certificate-files"
    if settings.https_mode == "self-signed":
        return "self-signed"
    return "disabled"


def _auth_mode(
    settings: ServerSettings,
) -> Literal["disabled", "generated", "inline", "file"]:
    if settings.auth_file:
        return "file"
    return "disabled"


__all__ = [
    "BODY_ADMISSION_BUDGET_NOTE",
    "WEBSOCKET_WORKER_NOTE",
    "PostureWarning",
    "RuntimePosture",
    "derive_runtime_posture",
]
