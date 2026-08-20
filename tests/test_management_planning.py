"""Behavioral tests for non-mutating managed VPS setup planning."""

from __future__ import annotations

import argparse
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from xferry.management.cli import main
from xferry.management.model import (
    HostFacts,
    ResourceOverrides,
    ResourcePlan,
    SetupMode,
    SetupOptions,
    SetupPreflight,
    SetupProbes,
)
from xferry.management.planning import (
    build_setup_plan,
    calculate_resources,
    check_setup_preflight,
    render_managed_config,
)
from xferry.management.platform import detect_host_facts
from xferry.settings import load_settings_file


def test_automatic_resources_for_1gib_two_cpu_host() -> None:
    """Changing any automatic sizing formula must change the selected limits."""
    facts = HostFacts(
        os_id="ubuntu",
        os_version="24.04",
        machine="x86_64",
        has_systemd=True,
        ram_mib=1024,
        cpu_count=2,
        disk_free_mib=8192,
    )

    assert calculate_resources(facts, ResourceOverrides()) == ResourcePlan(
        body_budget_mib=256,
        max_upload_mib=100,
        workers=6,
        reserve_mib=819,
        upload_storage_mib=4096,
    )


@pytest.mark.parametrize(
    ("ram_mib", "cpu_count", "disk_free_mib", "expected"),
    [
        (512, 1, 2048, ResourcePlan(128, 64, 4, 512, 1075)),
        (513, 4, 2048, ResourcePlan(128, 64, 10, 512, 1075)),
        (2047, 8, 2048, ResourcePlan(496, 100, 10, 512, 1075)),
        (4096, 3, 16384, ResourcePlan(512, 100, 8, 1024, 4096)),
    ],
)
def test_automatic_resources_round_and_clamp_host_capacity(
    ram_mib: int,
    cpu_count: int,
    disk_free_mib: int,
    expected: ResourcePlan,
) -> None:
    """Incorrect RAM rounding, clamps, worker bounds, or disk formulas must fail."""
    facts = _facts(ram_mib=ram_mib, cpu_count=cpu_count, disk_free_mib=disk_free_mib)

    assert calculate_resources(facts, ResourceOverrides()) == expected


@pytest.mark.parametrize(
    ("overrides", "expected"),
    [
        (ResourceOverrides(body_budget_mib=320), ResourcePlan(320, 100, 6, 819, 4096)),
        (ResourceOverrides(max_upload_mib=77), ResourcePlan(256, 77, 6, 819, 4096)),
        (ResourceOverrides(workers=9), ResourcePlan(256, 100, 9, 819, 4096)),
        (ResourceOverrides(reserve_mib=777), ResourcePlan(256, 100, 6, 777, 4096)),
        (ResourceOverrides(upload_storage_mib=700), ResourcePlan(256, 100, 6, 819, 700)),
    ],
)
def test_each_resource_override_replaces_only_its_selected_limit(
    overrides: ResourceOverrides, expected: ResourcePlan
) -> None:
    """Dropping an explicit resource override must not silently change its plan value."""
    assert calculate_resources(_facts(), overrides) == expected


@pytest.mark.parametrize(
    "facts",
    [
        HostFacts("ubuntu", "24.04", "x86_64", True, 511, 2, 8192),
        HostFacts("ubuntu", "24.04", "x86_64", True, 1024, 2, 1000),
    ],
)
def test_unusable_automatic_host_capacity_is_rejected_before_planning(facts: HostFacts) -> None:
    """Accepting an undersized RAM or automatic storage plan would permit unsafe setup."""
    with pytest.raises(ValueError):
        calculate_resources(facts, ResourceOverrides())


@pytest.mark.parametrize(
    ("os_release", "machine", "systemd", "supported"),
    [
        ('ID=ubuntu\nVERSION_ID="22.04"\n', "amd64", True, True),
        ('ID=ubuntu\nVERSION_ID="24.04"\n', "x86_64", True, True),
        ('ID=ubuntu\nVERSION_ID="26.04"\n', "x86_64", True, True),
        ('ID=debian\nVERSION_ID="12"\n', "x86_64", True, True),
        ('ID=debian\nVERSION_ID="11"\n', "x86_64", True, False),
        ('ID=ubuntu\nVERSION_ID="24.04"\n', "aarch64", True, False),
        ('ID=ubuntu\nVERSION_ID="24.04"\n', "x86_64", False, False),
    ],
)
def test_host_detection_normalizes_supported_platforms(
    os_release: str, machine: str, systemd: bool, supported: bool
) -> None:
    """Changing OS parsing, x86 normalization, or systemd detection must change support."""
    facts = detect_host_facts(
        os_release_text=os_release,
        machine=machine,
        has_systemd=systemd,
        page_size=1024 * 1024,
        physical_pages=1024,
        cpu_count=2,
        disk_free_bytes=8 * 1024 * 1024 * 1024,
    )

    assert facts.machine == ("x86_64" if machine == "amd64" else machine)
    assert facts.is_supported is supported


def test_host_detection_uses_the_existing_parent_for_a_clean_data_root(tmp_path: Path) -> None:
    """Probing an uncreated managed data root must use its existing filesystem ancestor."""
    data_root = tmp_path / "not-created" / "xferry"
    probed_paths: list[Path] = []

    def disk_usage(path: Path) -> SimpleNamespace:
        probed_paths.append(path)
        return SimpleNamespace(free=8192 * 1024 * 1024)

    facts = detect_host_facts(
        os_release_text='ID=ubuntu\nVERSION_ID="24.04"\n',
        machine="x86_64",
        has_systemd=True,
        page_size=1024 * 1024,
        physical_pages=1024,
        cpu_count=2,
        data_path=data_root,
        disk_usage=disk_usage,
    )

    assert facts.disk_free_mib == 8192
    assert probed_paths == [tmp_path]


def test_sslip_public_plan_resolves_a_validated_dash_form_domain() -> None:
    """Changing sslip resolution or public bind/ACME ports must change the public plan."""
    plan = build_setup_plan(
        SetupOptions(),
        _facts(),
        resolve_public_ip=lambda: "8.8.8.8",
    )

    assert plan.mode is SetupMode.SSLIP
    assert plan.domain == "8-8-8-8.sslip.io"
    assert plan.public_ip == "8.8.8.8"
    assert (plan.bind_host, plan.port, plan.acme_port) == ("0.0.0.0", 443, 80)


def test_explicit_domain_plan_uses_acme_without_public_ip_lookup() -> None:
    """Replacing the explicit-domain branch with sslip resolution would break this plan."""
    plan = build_setup_plan(
        SetupOptions(mode=SetupMode.DOMAIN, domain="files.example.com"),
        _facts(),
        resolve_public_ip=_unexpected_public_ip_lookup,
    )

    assert plan.mode is SetupMode.DOMAIN
    assert plan.domain == "files.example.com"
    assert plan.public_ip is None
    assert (plan.bind_host, plan.port, plan.acme_port) == ("0.0.0.0", 443, 80)


def test_private_plan_binds_loopback_without_acme_or_public_ip_lookup() -> None:
    """Exposing private mode or making an external lookup would break tunnel-only setup."""
    plan = build_setup_plan(
        SetupOptions(mode=SetupMode.PRIVATE),
        _facts(),
        resolve_public_ip=_unexpected_public_ip_lookup,
    )

    assert plan.domain is None
    assert plan.public_ip is None
    assert (plan.bind_host, plan.port, plan.acme_port) == ("127.0.0.1", 8080, None)


@pytest.mark.parametrize(
    ("options", "probe_builder", "failure_code"),
    [
        (SetupOptions(), lambda: _probes(executable=False), "executable-missing"),
        (SetupOptions(), lambda: _probes(available_ports=frozenset({80})), "port-unavailable"),
        (
            SetupOptions(firewall_answer=False),
            lambda: _probes(ufw_active=True),
            "firewall-denied",
        ),
        (SetupOptions(), lambda: _probes(ufw_active=True), "firewall-consent-required"),
    ],
)
def test_preflight_refuses_unsafe_public_setup_before_any_mutation(
    options: SetupOptions,
    probe_builder: Callable[[], SetupProbes],
    failure_code: str,
) -> None:
    """Missing executable, occupied ports, or UFW policy must block setup in preflight."""
    plan = build_setup_plan(options, _facts(), resolve_public_ip=lambda: "8.8.8.8")

    preflight = check_setup_preflight(plan, probe_builder())

    assert not preflight.ok
    assert preflight.required_bind_ports == (443, 80)
    assert failure_code in {failure.code for failure in preflight.failures}


def test_preflight_reports_all_read_only_boundary_observations() -> None:
    """Collapsing probes into failures would hide executable, ports, and UFW state from setup."""
    plan = build_setup_plan(SetupOptions(), _facts(), resolve_public_ip=lambda: "8.8.8.8")

    preflight = check_setup_preflight(
        plan,
        _probes(executable=False, available_ports=frozenset({80}), ufw_active=True),
    )

    assert preflight.executable_ready is False
    assert preflight.required_bind_ports == (443, 80)
    assert preflight.unavailable_bind_ports == (443,)
    assert preflight.ufw_active is True


def test_preflight_requires_explicit_firewall_consent_even_when_interactive() -> None:
    """Allowing active UFW without an answer would cross the mutation gate without consent."""
    plan = build_setup_plan(SetupOptions(), _facts(), resolve_public_ip=lambda: "8.8.8.8")

    preflight = check_setup_preflight(plan, _probes(ufw_active=True, interactive=True))

    assert not preflight.ok
    assert "firewall-consent-required" in {failure.code for failure in preflight.failures}


def test_approved_firewall_ports_are_carried_in_the_immutable_setup_plan() -> None:
    """Dropping explicit approved ports would leave the future executor without its action input."""
    plan = build_setup_plan(
        SetupOptions(firewall_answer=True),
        _facts(),
        resolve_public_ip=lambda: "8.8.8.8",
    )

    assert plan.firewall_action == "allow"
    assert plan.firewall_ports == (443, 80)
    assert check_setup_preflight(plan, _probes(ufw_active=True)).ok


def test_explicit_firewall_denial_blocks_active_ufw_setup() -> None:
    """Treating denial as consent would enter mutation against operator policy."""
    plan = build_setup_plan(
        SetupOptions(firewall_answer=False),
        _facts(),
        resolve_public_ip=lambda: "8.8.8.8",
    )

    preflight = check_setup_preflight(plan, _probes(ufw_active=True))

    assert not preflight.ok
    assert "firewall-denied" in {failure.code for failure in preflight.failures}


def test_reserve_override_is_subtracted_before_automatic_upload_storage() -> None:
    """Calculating storage before an override could overcommit the data filesystem."""
    assert calculate_resources(
        _facts(disk_free_mib=8192),
        ResourceOverrides(reserve_mib=6000),
    ) == ResourcePlan(256, 100, 6, 6000, 1534)


def test_large_reserve_with_insufficient_remaining_automatic_storage_is_rejected() -> None:
    """Allowing automatic storage below 512 MiB after an override could exceed available disk."""
    with pytest.raises(ValueError, match="calculated upload storage"):
        calculate_resources(
            _facts(disk_free_mib=8192),
            ResourceOverrides(reserve_mib=8000),
        )


def test_explicit_storage_can_accompany_an_explicit_large_reserve() -> None:
    """Discarding an explicit storage limit would ignore the operator's bounded plan."""
    assert calculate_resources(
        _facts(disk_free_mib=8192),
        ResourceOverrides(reserve_mib=7000, upload_storage_mib=600),
    ) == ResourcePlan(256, 100, 6, 7000, 600)


def test_rendered_public_config_loads_with_finite_security_limits(tmp_path: Path) -> None:
    """Removing public-direct auth, TLS, or finite quota limits must invalidate this config."""
    plan = build_setup_plan(SetupOptions(), _facts(), resolve_public_ip=lambda: "8.8.8.8")
    config_path = tmp_path / "xferry.ini"
    config_path.write_text(render_managed_config(plan), encoding="utf-8")

    settings = load_settings_file(config_path)

    assert settings.public_direct is True
    assert settings.sslip is True
    assert settings.auth_file == "/etc/xferry/auth"
    assert settings.port == 443
    assert settings.upload_storage_limit_mb == 4096
    assert settings.body_memory_budget_mb == 256


def test_rendered_private_config_loads_with_the_same_auth_and_quota_boundary(
    tmp_path: Path,
) -> None:
    """Weakening private config auth or finite limits must be caught by settings loading."""
    plan = build_setup_plan(SetupOptions(mode=SetupMode.PRIVATE), _facts())
    config_path = tmp_path / "xferry.ini"
    config_path.write_text(render_managed_config(plan), encoding="utf-8")

    settings = load_settings_file(config_path)

    assert settings.host == "127.0.0.1"
    assert settings.port == 8080
    assert settings.auth_file == "/etc/xferry/auth"
    assert settings.upload_storage_limit_mb == 4096
    assert settings.body_memory_budget_mb == 256
    assert settings.effective_tls_enabled() is False


def test_rendered_domain_config_loads_with_acme_domain_tls(tmp_path: Path) -> None:
    """Replacing the domain ACME configuration with an sslip-only form must fail this load."""
    plan = build_setup_plan(
        SetupOptions(mode=SetupMode.DOMAIN, domain="files.example.com"),
        _facts(),
    )
    config_path = tmp_path / "xferry.ini"
    config_path.write_text(render_managed_config(plan), encoding="utf-8")

    settings = load_settings_file(config_path)

    assert settings.letsencrypt is True
    assert settings.domain == "files.example.com"
    assert settings.sslip is False


@pytest.mark.parametrize(
    "domain",
    ["files.example.com\nInjected = true", "files.\x00example.com", "-bad.example", "bad..example"],
)
def test_domain_setup_rejects_controls_and_invalid_labels(domain: str) -> None:
    """Writing an invalid domain into INI or Host would enable injection or broken TLS."""
    with pytest.raises(ValueError, match="invalid domain"):
        build_setup_plan(
            SetupOptions(mode=SetupMode.DOMAIN, domain=domain),
            _facts(),
        )


def test_domain_setup_uses_canonical_idna_hostname() -> None:
    """Planning must use the same canonical hostname later used by ACME and health."""
    plan = build_setup_plan(
        SetupOptions(mode=SetupMode.DOMAIN, domain="BÜCHER.Example."),
        _facts(),
    )

    assert plan.domain == "xn--bcher-kva.example"
    assert "domain = xn--bcher-kva.example\n" in render_managed_config(plan)


def test_preflight_rejects_firewall_ports_outside_managed_public_set() -> None:
    """An in-process caller must not smuggle an arbitrary host port into UFW execution."""
    plan = build_setup_plan(
        SetupOptions(
            public_ip="8.8.8.8",
            firewall_answer=True,
        ),
        _facts(),
    )
    malformed = replace(plan, firewall_ports=(22, 443))

    preflight = check_setup_preflight(
        malformed,
        SetupProbes(
            executable_is_ready=lambda _path: True,
            port_is_available=lambda _host, _port: True,
            ufw_is_active=lambda: True,
        ),
    )

    assert [failure.code for failure in preflight.failures] == ["invalid-firewall-port"]


def test_setup_cli_accepts_one_mode_and_resource_override_shape(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Removing setup planning arguments would turn a valid dry run into usage failure."""
    from xferry.management import cli

    def prepare(args: argparse.Namespace) -> tuple[object, SetupPreflight]:
        assert args.private is True
        assert args.workers == 7
        assert args.dry_run is True
        plan = build_setup_plan(
            SetupOptions(
                mode=SetupMode.PRIVATE,
                resources=ResourceOverrides(workers=7),
            ),
            _facts(),
        )
        return plan, SetupPreflight(
            executable_ready=True,
            required_bind_ports=(8080,),
            unavailable_bind_ports=(),
            ufw_active=False,
        )

    monkeypatch.setattr(cli, "_prepare_setup_plan", prepare)

    assert main(["setup", "--private", "--workers", "7", "--dry-run"]) == 0
    output = capsys.readouterr().out
    assert "Dry run" in output
    assert "workers=7" in output


def test_setup_cli_rejects_mutually_exclusive_modes(capsys: pytest.CaptureFixture[str]) -> None:
    """Accepting public domain plus private mode would yield an ambiguous setup plan."""
    assert main(["setup", "--domain", "files.example.com", "--private"]) == 2
    assert "not allowed with argument" in capsys.readouterr().err


def _facts(*, ram_mib: int = 1024, cpu_count: int = 2, disk_free_mib: int = 8192) -> HostFacts:
    return HostFacts(
        os_id="ubuntu",
        os_version="24.04",
        machine="x86_64",
        has_systemd=True,
        ram_mib=ram_mib,
        cpu_count=cpu_count,
        disk_free_mib=disk_free_mib,
    )


def _probes(
    *,
    executable: bool = True,
    available_ports: frozenset[int] = frozenset({80, 443, 8080}),
    ufw_active: bool = False,
    interactive: bool = True,
) -> SetupProbes:
    def port_is_available(_host: str, port: int) -> bool:
        return port in available_ports

    return SetupProbes(
        executable_is_ready=lambda _path: executable,
        port_is_available=port_is_available,
        ufw_is_active=lambda: ufw_active,
        interactive=interactive,
    )


def _unexpected_public_ip_lookup() -> str:
    raise AssertionError("public IP lookup must not be used for this setup mode")
