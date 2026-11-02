"""Compile operator profiles with host paths/ports to isolated backend settings."""

from __future__ import annotations

from pathlib import Path

from xferry.settings import ServerSettings

from .configuration import edit_ini
from .deployment import DeploymentSpec


def compile_profile(text: str, spec: DeploymentSpec) -> str:
    from xferry.settings import load_settings_text

    settings = load_settings_text(text, state_dir=spec.state_dir, config_path=spec.profile)
    settings.to_server_config()
    if Path(settings.files_dir or spec.files_dir).expanduser().absolute() != spec.files_dir:
        raise ValueError("profile files directory and deployment manifest disagree")
    if spec.backend == "docker":
        tls = settings.effective_tls_enabled()
        changes = {
            "files_dir": "/data/files",
            "auth_file": "/run/secrets/xferry_auth",
            "port": 8443 if tls else 8080,
            "host": "0.0.0.0",  # nosec B104 - container-only bind; host publication enforces access
            "acme_http_port": 8080 if settings.https_mode in {"auto", "domain"} else 80,
            "state_dir": "/data",
        }
        # The host enforces private publication; container must bind its interface.
        if not tls:
            changes["access"] = "lab"
    else:
        changes = {"files_dir": str(spec.state_dir / "files"), "state_dir": str(spec.state_dir)}
    runtime = edit_ini(text, changes)
    load_settings_text(
        runtime, state_dir=Path("/data") if spec.backend == "docker" else spec.state_dir
    ).to_server_config()
    return runtime


def public_url(settings: ServerSettings) -> str:
    tls = settings.effective_tls_enabled()
    host = settings.domain
    if not host and settings.public_ip:
        from xferry.security.tls import sslip_domain_for_ip

        host = sslip_domain_for_ip(settings.public_ip)
    if not host and tls and settings.allowed_hosts:
        # Match the certificate identity selected by service._endpoint without
        # importing the Linux service layer into this portable compiler.
        host = next(
            (
                item
                for item in settings.allowed_hosts
                if item not in {"127.0.0.1", "localhost", "::1"}
            ),
            settings.allowed_hosts[0],
        )
    # This comparison substitutes loopback in a URL; it never binds a socket.
    host = host or ("127.0.0.1" if settings.host in {"0.0.0.0", "::"} else settings.host)  # nosec B104
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    port = settings.port
    suffix = "" if port == (443 if tls else 80) else f":{port}"
    return f"{'https' if tls else 'http'}://{host}{suffix}/"
