"""Derived, secret-free operator posture for one resolved xferry launch."""

from __future__ import annotations

import ipaddress
from dataclasses import asdict, dataclass
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING, Literal

if TYPE_CHECKING:
    from .settings import ServerSettings


BODY_ADMISSION_BUDGET_NOTE = (
    "Body memory is an admission budget for in-flight request bodies, not an RSS "
    "ceiling; decoded, parsed, TLS, and Python overhead can coexist."
)
WEBSOCKET_WORKER_NOTE = "Each active WebSocket occupies one worker while connected."


class LaunchPreset(str, Enum):
    """Named operator journeys; these select defaults, not feature profiles."""

    LOCAL = "local"
    LOCAL_SECURE = "local-secure"
    PUBLIC_DIRECT = "public-direct"


@dataclass(frozen=True)
class PostureWarning:
    """Stable warning code plus operator-facing remediation text."""

    code: str
    message: str


@dataclass(frozen=True)
class RuntimePosture:
    """Typed, redacted summary derived from effective settings."""

    preset: LaunchPreset | None
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
    public_direct: bool
    public_direct_validated: bool
    max_upload_mb: int
    body_admission_budget_mb: int
    workers: int
    max_websocket_connections: int
    upload_storage_limit_mb: int | None
    upload_file_limit: int | None
    upload_reserve_free_mb: int
    upload_quota_externally_managed: bool
    warnings: tuple[PostureWarning, ...]
    notes: tuple[str, ...] = (
        BODY_ADMISSION_BUDGET_NOTE,
        WEBSOCKET_WORKER_NOTE,
    )

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-safe representation that cannot contain credentials."""
        data = asdict(self)
        data["preset"] = self.preset.value if self.preset is not None else None
        data["warnings"] = [asdict(warning) for warning in self.warnings]
        data["notes"] = list(self.notes)
        return data

    def render_lines(self, *, effective_url: str | None = None) -> list[str]:
        """Render one shared human-readable posture for checks and startup."""
        selected_url = effective_url or self.effective_url
        preset = self.preset.value if self.preset is not None else "custom/legacy"
        if self.public_direct_validated:
            public_validation = "validated"
        elif self.preset is LaunchPreset.PUBLIC_DIRECT:
            public_validation = "disabled by explicit configuration"
        else:
            public_validation = "not requested"

        lines = [
            "Runtime posture:",
            f"  Preset: {preset}",
            f"  Effective URL: {selected_url}",
            f"  Exposure: {self.exposure}",
            (
                "  Data persistence: operator-managed "
                f"(root: {self.data_root}; uploads: {self.uploads_path}; "
                f"notes: {self.notes_path})"
            ),
            f"  TLS: {self.tls_mode}; Auth: {self.auth_mode}",
            f"  Public-direct validation: {public_validation}",
            (
                f"  Body admission budget: {self.body_admission_budget_mb} MB; "
                f"workers: {self.workers}; WebSockets: {self.max_websocket_connections}"
            ),
        ]
        lines.extend(f"  NOTE: {note}" for note in self.notes)
        for warning in self.warnings:
            if effective_url is not None and warning.code == "sslip-hostname-pending":
                continue
            lines.append(f"  WARNING [{warning.code}]: {warning.message}")
        return lines


def parse_launch_preset(value: object) -> LaunchPreset:
    """Normalize one preset name or raise a stable operator error."""
    if isinstance(value, LaunchPreset):
        return value
    normalized = str(value).strip().lower()
    try:
        return LaunchPreset(normalized)
    except ValueError:
        choices = ", ".join(preset.value for preset in LaunchPreset)
        raise ValueError(f"preset must be one of: {choices}") from None


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
    data_root = Path(settings.root_dir).expanduser().resolve()

    warnings: list[PostureWarning] = []
    if bind_exposure != "loopback" and not settings.public_direct:
        warnings.append(
            PostureWarning(
                code="non-loopback-without-public-direct",
                message=(
                    "Non-loopback bind is not protected by public-direct validation; "
                    "restrict firewall/NAT and enable TLS plus file-backed authentication "
                    "before sharing."
                ),
            )
        )
    if settings.preset is LaunchPreset.LOCAL_SECURE and (
        tls_mode == "disabled" or auth_mode == "disabled"
    ):
        warnings.append(
            PostureWarning(
                code="local-secure-weakened",
                message=(
                    "The local-secure preset was explicitly weakened; verify TLS and "
                    "authentication before sharing."
                ),
            )
        )
    if auth_mode == "generated":
        warnings.append(
            PostureWarning(
                code="generated-auth-requires-tty",
                message=(
                    "Generated authentication requires an interactive TTY; services, "
                    "containers, and CI must use --auth-file."
                ),
            )
        )
    if settings.preset is LaunchPreset.PUBLIC_DIRECT and not settings.public_direct:
        warnings.append(
            PostureWarning(
                code="public-direct-hardening-disabled",
                message=(
                    "The public-direct preset was explicitly disabled, so its strict "
                    "validation is not active."
                ),
            )
        )
    if settings.sslip and effective_host is None and not settings.public_ip:
        warnings.append(
            PostureWarning(
                code="sslip-hostname-pending",
                message=(
                    "The final sslip.io hostname is resolved during TLS startup; the "
                    "displayed URL is a bind target until then."
                ),
            )
        )

    return RuntimePosture(
        preset=settings.preset,
        effective_url=effective_url,
        exposure=bind_exposure,
        data_root=str(data_root),
        uploads_path=str(data_root / "uploads"),
        notes_path=str(data_root / "notes"),
        persistence="operator-managed",
        tls_mode=tls_mode,
        auth_mode=auth_mode,
        public_direct=settings.public_direct,
        public_direct_validated=settings.public_direct,
        max_upload_mb=settings.max_size_mb,
        body_admission_budget_mb=(
            settings.body_memory_budget_mb
            if settings.body_memory_budget_mb is not None
            else settings.max_size_mb * settings.workers
        ),
        workers=settings.workers,
        max_websocket_connections=(
            settings.max_websocket_connections
            if settings.max_websocket_connections is not None
            else max(0, settings.workers // 2)
        ),
        upload_storage_limit_mb=settings.upload_storage_limit_mb or None,
        upload_file_limit=settings.upload_file_limit or None,
        upload_reserve_free_mb=settings.upload_reserve_free_mb,
        upload_quota_externally_managed=settings.upload_quota_externally_managed,
        warnings=tuple(warnings),
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
    if settings.sslip and settings.public_ip:
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
    if settings.sslip:
        return "acme-sslip"
    if settings.letsencrypt:
        return "acme-domain"
    if settings.cert_file and settings.key_file:
        return "certificate-files"
    if settings.tls:
        return "self-signed"
    return "disabled"


def _auth_mode(
    settings: ServerSettings,
) -> Literal["disabled", "generated", "inline", "file"]:
    if settings.auth_file:
        return "file"
    if not settings.auth:
        return "disabled"
    if settings.auth == "random" or ":" not in settings.auth:
        return "generated"
    return "inline"


__all__ = [
    "BODY_ADMISSION_BUDGET_NOTE",
    "WEBSOCKET_WORKER_NOTE",
    "LaunchPreset",
    "PostureWarning",
    "RuntimePosture",
    "derive_runtime_posture",
    "parse_launch_preset",
]
