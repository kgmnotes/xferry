"""Pure planning and preflight checks for managed XFerry VPS setup."""

from __future__ import annotations

from collections.abc import Callable
from typing import Literal

from xferry.security.tls import normalize_domain, sslip_domain_for_ip, validate_public_ipv4

from .model import (
    HostFacts,
    PreflightFailure,
    ResourceOverrides,
    ResourcePlan,
    SetupMode,
    SetupOptions,
    SetupPlan,
    SetupPreflight,
    SetupProbes,
)


def calculate_resources(facts: HostFacts, overrides: ResourceOverrides) -> ResourcePlan:
    """Calculate finite managed limits from host facts and explicit replacements."""
    if facts.ram_mib < 512:
        raise ValueError("managed setup requires at least 512 MiB RAM")

    automatic_body_budget = max(128, min(512, (facts.ram_mib // 4) // 16 * 16))
    automatic_reserve = max(512, min(1024, facts.disk_free_mib // 10))
    reserve = _nonnegative_override(overrides.reserve_mib, automatic_reserve, "disk reserve")
    automatic_storage = min(4096, (facts.disk_free_mib - reserve) * 70 // 100)
    if automatic_storage < 512 and overrides.upload_storage_mib is None:
        raise ValueError("managed setup requires at least 512 MiB calculated upload storage")

    body_budget = _positive_override(
        overrides.body_budget_mib, automatic_body_budget, "body budget"
    )
    max_upload = _positive_override(
        overrides.max_upload_mib, min(100, body_budget // 2), "maximum upload"
    )
    workers = _positive_override(
        overrides.workers, min(10, max(4, facts.cpu_count * 2 + 2)), "workers"
    )
    storage = _positive_override(overrides.upload_storage_mib, automatic_storage, "upload storage")
    return ResourcePlan(
        body_budget_mib=body_budget,
        max_upload_mib=max_upload,
        workers=workers,
        reserve_mib=reserve,
        upload_storage_mib=storage,
    )


def build_setup_plan(
    options: SetupOptions,
    facts: HostFacts,
    *,
    resolve_public_ip: Callable[[], str] | None = None,
) -> SetupPlan:
    """Build a complete setup plan without changing the host."""
    resources = calculate_resources(facts, options.resources)
    firewall_action: Literal["allow"] | None = "allow" if options.firewall_answer is True else None
    if options.mode is SetupMode.PRIVATE:
        return SetupPlan(
            layout=options.layout,
            facts=facts,
            resources=resources,
            mode=options.mode,
            bind_host="127.0.0.1",
            port=8080,
            acme_port=None,
            domain=None,
            public_ip=None,
            email=None,
            firewall_answer=options.firewall_answer,
            firewall_action=None,
            firewall_ports=(),
        )
    if options.mode is SetupMode.DOMAIN:
        domain = options.domain or ""
        if not domain.strip():
            raise ValueError("--domain requires a domain value")
        domain = normalize_domain(domain)
        return _public_plan(
            options,
            facts,
            resources,
            domain=domain,
            public_ip=None,
            firewall_action=firewall_action,
        )

    lookup = resolve_public_ip
    if options.public_ip is not None:
        public_ip = validate_public_ipv4(options.public_ip)
    elif lookup is not None:
        public_ip = validate_public_ipv4(lookup())
    else:
        from xferry.security.tls import resolve_public_ipv4

        public_ip = resolve_public_ipv4()
    return _public_plan(
        options,
        facts,
        resources,
        domain=sslip_domain_for_ip(public_ip),
        public_ip=public_ip,
        firewall_action=firewall_action,
    )


def check_setup_preflight(plan: SetupPlan, probes: SetupProbes) -> SetupPreflight:
    """Run all read-only setup blockers before a future executor can mutate state."""
    required_ports = (plan.port,) + ((plan.acme_port,) if plan.acme_port is not None else ())
    if probes.unsupported_managed_state_detected(plan.layout):
        from .managed_state import (
            UNSUPPORTED_MANAGED_STATE_CODE,
            UNSUPPORTED_MANAGED_STATE_INSTRUCTIONS,
        )

        return SetupPreflight(
            executable_ready=False,
            required_bind_ports=required_ports,
            unavailable_bind_ports=(),
            ufw_active=False,
            failures=(
                PreflightFailure(
                    UNSUPPORTED_MANAGED_STATE_CODE,
                    UNSUPPORTED_MANAGED_STATE_INSTRUCTIONS,
                ),
            ),
        )
    failures: list[PreflightFailure] = []
    executable_ready = probes.executable_is_ready(plan.layout.current_executable)
    unavailable_ports = tuple(
        port for port in required_ports if not probes.port_is_available(plan.bind_host, port)
    )
    try:
        ufw_active = probes.ufw_is_active()
    except OSError:
        ufw_active = False
        failures.append(
            PreflightFailure(
                "firewall-probe-failed",
                "UFW state could not be determined safely",
            )
        )
    if not plan.facts.is_supported:
        failures.append(
            PreflightFailure(
                "unsupported-platform",
                "managed setup requires supported OS, x86_64, and systemd",
            )
        )
    if not executable_ready:
        failures.append(
            PreflightFailure(
                "executable-missing",
                f"installed executable is not ready: {plan.layout.current_executable}",
            )
        )
    if not set(plan.firewall_ports) <= {80, 443}:
        failures.append(
            PreflightFailure(
                "invalid-firewall-port",
                "managed firewall ports must be limited to 80/tcp and 443/tcp",
            )
        )
    for port in unavailable_ports:
        failures.append(
            PreflightFailure("port-unavailable", f"required bind port is occupied: {port}")
        )
    if plan.mode is not SetupMode.PRIVATE and ufw_active:
        if plan.firewall_answer is False:
            failures.append(
                PreflightFailure(
                    "firewall-denied",
                    "active UFW policy was not approved for required ports",
                )
            )
        elif plan.firewall_answer is None:
            failures.append(
                PreflightFailure(
                    "firewall-consent-required",
                    "active UFW requires an explicit firewall answer",
                )
            )
    return SetupPreflight(
        executable_ready=executable_ready,
        required_bind_ports=required_ports,
        unavailable_bind_ports=unavailable_ports,
        ufw_active=ufw_active,
        failures=tuple(failures),
    )


def render_managed_config(plan: SetupPlan) -> str:
    """Render a complete, secret-free INI accepted by the settings loader."""
    server = [
        "[server]",
        f"host = {plan.bind_host}",
        f"port = {plan.port}",
        f"root_dir = {plan.layout.data_root}",
        f"workers = {plan.resources.workers}",
    ]
    if plan.mode is not SetupMode.PRIVATE:
        server.extend(("preset = public-direct", "public_direct = true"))
    common = server + [
        "",
        "[security]",
        f"auth_file = {plan.layout.auth_file}",
        "",
        "[limits]",
        f"max_size_mb = {plan.resources.max_upload_mib}",
        f"body_memory_budget_mb = {plan.resources.body_budget_mib}",
        f"upload_storage_limit_mb = {plan.resources.upload_storage_mib}",
        f"upload_reserve_free_mb = {plan.resources.reserve_mib}",
        "body_idle_timeout = 5",
        "body_timeout = 300",
        "stream_send_idle_timeout = 5",
        "stream_send_timeout = 300",
    ]
    if plan.mode is SetupMode.PRIVATE:
        return "\n".join(common) + "\n"
    public = [
        "[tls]",
        f"letsencrypt = {'false' if plan.mode is SetupMode.SSLIP else 'true'}",
        f"sslip = {'true' if plan.mode is SetupMode.SSLIP else 'false'}",
    ]
    if plan.mode is SetupMode.SSLIP:
        public.append(f"public_ip = {plan.public_ip}")
    else:
        public.append(f"domain = {plan.domain}")
    if plan.email:
        public.append(f"email = {plan.email}")
    public.extend(("acme_http_port = 80", ""))
    return "\n".join(common + [""] + public) + "\n"


def _public_plan(
    options: SetupOptions,
    facts: HostFacts,
    resources: ResourcePlan,
    *,
    domain: str,
    public_ip: str | None,
    firewall_action: Literal["allow"] | None,
) -> SetupPlan:
    return SetupPlan(
        layout=options.layout,
        facts=facts,
        resources=resources,
        mode=options.mode,
        # Public setup intentionally listens on all interfaces.
        bind_host="0.0.0.0",  # nosec B104
        port=443,
        acme_port=80,
        domain=domain,
        public_ip=public_ip,
        email=options.email,
        firewall_answer=options.firewall_answer,
        firewall_action=firewall_action,
        firewall_ports=(443, 80) if firewall_action is not None else (),
    )


def _positive_override(value: int | None, automatic: int, name: str) -> int:
    selected = automatic if value is None else value
    if selected < 1:
        raise ValueError(f"{name} must be at least 1 MiB")
    return selected


def _nonnegative_override(value: int | None, automatic: int, name: str) -> int:
    selected = automatic if value is None else value
    if selected < 0:
        raise ValueError(f"{name} must not be negative")
    return selected
