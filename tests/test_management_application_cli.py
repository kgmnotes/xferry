"""Operator intent reaches one application boundary regardless of deployment backend."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import pytest

from xferry.config import __version__
from xferry.management import application, cli, instances, wizard
from xferry.management.deployment import (
    DeploymentSpec,
    ObservedState,
    OperationPlan,
    OperationResult,
)
from xferry.management.instances import Instance


class ApplicationProbe:
    def __init__(self, deployments: tuple[Instance, ...]) -> None:
        self.deployments = deployments
        self.calls: list[tuple[str, object, dict[str, object]]] = []
        self.state = "stopped"

    def resolve(self, identity: str | Instance | None = None) -> Instance:
        if isinstance(identity, Instance):
            return identity
        matching = tuple(i for i in self.deployments if identity is None or i.id == identity)
        if len(matching) != 1:
            raise ValueError("select one persistent deployment with --instance ID")
        return matching[0]

    def observe(self, instance: Instance) -> ObservedState:
        return ObservedState(self.state, instance.id, instance.backend)

    def operate(self, action: str, instance: Instance, **options: object) -> OperationResult:
        self.calls.append((action, instance.id, options))
        return OperationResult(0, f"{action} completed", state=self.observe(instance))

    def configure(self, instance: Instance, changes: dict[str, str], **options: object):
        self.calls.append(("configure", instance.id, {"changes": dict(changes), **options}))
        return OperationResult(0, "configuration validated", details={"diff": "reviewed diff"})

    def credentials(self, instance: Instance) -> OperationResult:
        self.calls.append(("credentials", instance.id, {}))
        return OperationResult(
            0,
            "credentials reset",
            credentials=SimpleNamespace(
                username="admin", password="samplePass234", url="https://example.test"
            ),
        )

    def doctor(self, instance: Instance, **options: object) -> OperationResult:
        self.calls.append(("doctor", instance.id, options))
        return OperationResult(0, "diagnostics completed", state=self.observe(instance))

    def setup(self, **options: object) -> OperationResult:
        self.calls.append(("setup", options.get("instance_id"), options))
        return OperationResult(
            0, "setup validated", plan=OperationPlan("setup", steps=("preview",))
        )


@pytest.fixture
def app_probe(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> ApplicationProbe:
    profile = tmp_path / "operator.ini"
    profile.write_text("[server]\nconfig_version = 1\naccess = private\n")
    deployment = Instance(str(uuid4()), "docker", profile, tmp_path / "manifest.json")
    spec = DeploymentSpec(
        deployment.id,
        "docker",
        profile,
        tmp_path / "files",
        tmp_path / "state",
        {"image": "ghcr.io/kgmnotes/xferry@sha256:" + "a" * 64},
        backend_options={
            "project": "xferry-probe",
            "state_storage": {
                "kind": "docker_volume",
                "name": "xferry-probe_xferry-data",
                "runtime_root": "/data",
            },
        },
    )
    deployment.manifest.write_text(json.dumps(spec.to_json()))
    probe = ApplicationProbe((deployment,))
    monkeypatch.setattr(application, "default_application", lambda: probe)
    monkeypatch.setattr(instances, "discover_instances", lambda: probe.deployments)
    monkeypatch.setattr(cli.sys.stdin, "isatty", lambda: False)
    monkeypatch.setattr(cli.os, "geteuid", lambda: 0)
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "user"))
    return probe


@pytest.fixture(params=["native", "docker"])
def real_app_probe(request, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    backend = request.param
    profile = tmp_path / "profile.ini"
    profile.write_text("[server]\nconfig_version = 1\naccess = private\n")
    spec = DeploymentSpec.new(
        backend,
        profile,
        tmp_path / "files",
        tmp_path / "state",
        {"version": __version__, "sha256": "a" * 64}
        if backend == "native"
        else {"image": "ghcr.io/kgmnotes/xferry@sha256:" + "a" * 64},
        backend_options={}
        if backend == "native"
        else {
            "project": "xferry-probe",
            "state_storage": {
                "kind": "docker_volume",
                "name": "xferry-probe_xferry-data",
                "runtime_root": "/data",
            },
        },
    )
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps(spec.to_json()))
    selected = Instance(spec.instance_id, spec.backend, profile, manifest)
    calls = []

    def operate(action, instance, **options):
        calls.append((action, instance.id, options))
        return OperationResult(0, "backend operation completed")

    # Only the backend boundary is replaced. Confirmation must be enforced by
    # the real application rather than simulated by the test double.
    adapter = SimpleNamespace(operate=operate)
    app = application.ManagementApplication(
        native_backend=adapter, compose_backend=adapter, effective_uid=lambda: 0
    )
    monkeypatch.setattr(application, "default_application", lambda: app)
    monkeypatch.setattr(instances, "discover_instances", lambda: (selected,))
    monkeypatch.setattr(cli.sys.stdin, "isatty", lambda: False)
    monkeypatch.setattr(cli.os, "geteuid", lambda: 0)
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "user"))
    return selected, calls


@pytest.mark.parametrize("backend", ["native", "docker"])
@pytest.mark.parametrize(
    "action", ["status", "start", "stop", "restart", "logs", "update", "rollback", "uninstall"]
)
def test_lifecycle_uses_instance_identity_and_shared_application(app_probe, backend, action):
    original = app_probe.deployments[0]
    selected = Instance(original.id, backend, original.config, original.manifest)
    app_probe.deployments = (selected,)
    arguments = [action, "--instance", selected.id]
    if action == "update":
        arguments += ["--to", __version__]
    assert cli.main(arguments) == 0
    assert app_probe.calls[0][:2] == (action, selected.id)


def test_persistent_config_and_credentials_use_same_application(app_probe, capsys):
    identity = app_probe.deployments[0].id
    assert cli.main(["config", "set", "--instance", identity, "port=443", "--dry-run"]) == 0
    assert app_probe.calls[-1] == (
        "configure",
        identity,
        {"changes": {"port": "443"}, "apply": False},
    )
    assert cli.main(["config", "set", "port=443", "--instance", identity]) == 0
    assert app_probe.calls[-1][2]["apply"] is True
    capsys.readouterr()
    assert cli.main(["credentials", "reset", "--instance", identity, "--json"]) == 0
    captured = capsys.readouterr()
    assert "samplePass234" not in captured.out
    assert "samplePass234" not in captured.err
    assert captured.err == ""
    assert json.loads(captured.out)["exit_code"] == 0


@pytest.mark.parametrize(
    "arguments,check_http", [([], False), (["--deep"], True), (["--deep", "--skip-network"], False)]
)
def test_docker_doctor_is_dispatched_with_honest_network_intent(app_probe, arguments, check_http):
    assert cli.main(["doctor", *arguments]) == 0
    assert app_probe.calls == [("doctor", app_probe.deployments[0].id, {"check_http": check_http})]


def test_explicit_foreground_profile_does_not_infer_backend_from_adjacent_files(app_probe):
    profile = app_probe.deployments[0].config
    profile.with_name(".xferry-deployment.json").write_text('{"backend":"docker"}')
    assert cli.main(["config", "set", "--config", str(profile), "port=18080"]) == 0
    assert "port = 18080" in profile.read_text()
    assert app_probe.calls == []


def test_multiple_instances_require_explicit_selection_in_scripts(app_probe, monkeypatch, capsys):
    first = app_probe.deployments[0]
    second = Instance(str(uuid4()), "docker", first.config, first.manifest)
    app_probe.deployments += (second,)
    assert cli.main(["status"]) == 2
    assert "--instance ID" in capsys.readouterr().err
    assert app_probe.calls == []
    monkeypatch.setattr(cli.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr("builtins.input", lambda _: "2")
    assert cli.main(["status"]) == 0
    assert app_probe.calls[0][1] == second.id


@pytest.mark.parametrize("answer", ["0", "3", "invalid"])
def test_invalid_instance_choice_never_acts(app_probe, monkeypatch, answer):
    first = app_probe.deployments[0]
    app_probe.deployments += (Instance(str(uuid4()), "docker", first.config, first.manifest),)
    monkeypatch.setattr(cli.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr("builtins.input", lambda _: answer)
    assert cli.main(["restart"]) == 2
    assert app_probe.calls == []


@pytest.mark.parametrize("backend", ["native", "docker"])
def test_setup_preserves_explicit_intent_without_prompting(
    app_probe, monkeypatch, tmp_path, backend
):
    monkeypatch.setattr("builtins.input", lambda _: pytest.fail("unexpected prompt"))
    assert (
        cli.main(
            [
                "setup",
                "--backend",
                backend,
                "--files-dir",
                str(tmp_path / "shared"),
                "--public-ip",
                "8.8.8.8",
                "--email",
                "ops@example.com",
                "--dry-run",
            ]
        )
        == 0
    )
    options = app_probe.calls[0][2]
    assert options["backend"] == backend and options["files_dir"] == tmp_path / "shared"
    assert options["public_ip"] == "8.8.8.8" and options["email"] == "ops@example.com"
    assert options["dry_run"] is True


def test_setup_resume_uses_instance_without_repeating_access_questions(app_probe, monkeypatch):
    monkeypatch.setattr(cli.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr("builtins.input", lambda _: "yes")
    identity = app_probe.deployments[0].id
    assert cli.main(["setup", "--backend", "docker", "--instance", identity]) == 0
    assert len(app_probe.calls) == 2
    assert [call[2]["dry_run"] for call in app_probe.calls] == [True, False]
    assert all(call[1] == identity for call in app_probe.calls)


@pytest.mark.parametrize(
    "state,action",
    [
        ("running", "config"),
        ("stopped", "start"),
        ("incomplete", "setup"),
        ("retained", "setup"),
        ("broken", "doctor"),
    ],
)
def test_menu_uses_observed_state(app_probe, monkeypatch, state, action):
    app_probe.state = state
    monkeypatch.setattr("builtins.input", lambda _: "1")
    dispatched = []
    assert wizard.menu("en", lambda argv: dispatched.append(argv) or 0) == 0
    assert dispatched[0][0] == action
    assert dispatched[0][-2:] == ["--instance", app_probe.deployments[0].id]


def test_menu_after_purge_offers_new_setup(app_probe, monkeypatch):
    app_probe.deployments = ()
    answers = iter(["1", "2"])
    monkeypatch.setattr("builtins.input", lambda _: next(answers))
    dispatched = []
    assert wizard.menu("en", lambda argv: dispatched.append(argv) or 0) == 0
    assert dispatched == [["setup", "--backend", "docker"]]


def test_purge_confirmation_follows_displayed_plan(real_app_probe, monkeypatch):
    selected, calls = real_app_probe
    monkeypatch.setattr(cli.sys.stdin, "isatty", lambda: True)

    def answer(_):
        assert calls == [
            (
                "uninstall",
                selected.id,
                {"purge": True, "confirmed": True, "dry_run": True},
            )
        ]
        return "yes"

    monkeypatch.setattr("builtins.input", answer)
    assert cli.main(["uninstall", "--instance", selected.id, "--purge"]) == 0
    assert calls[-1][2] == {"purge": True, "confirmed": True, "dry_run": False}


def test_interactive_purge_decline_dispatches_only_preview(real_app_probe, monkeypatch):
    selected, calls = real_app_probe
    monkeypatch.setattr(cli.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr("builtins.input", lambda _: "no")
    assert cli.main(["uninstall", "--instance", selected.id, "--purge"]) == 0
    assert calls == [
        ("uninstall", selected.id, {"purge": True, "confirmed": True, "dry_run": True})
    ]


def test_script_purge_without_yes_never_reaches_backend(real_app_probe, monkeypatch, capsys):
    selected, calls = real_app_probe
    monkeypatch.setattr("builtins.input", lambda _: pytest.fail("unexpected prompt"))
    assert cli.main(["uninstall", "--instance", selected.id, "--purge"]) == 2
    assert calls == []
    assert "--yes" in capsys.readouterr().err


@pytest.mark.parametrize("interactive", [False, True])
def test_explicit_purge_yes_does_not_prompt(real_app_probe, monkeypatch, interactive):
    selected, calls = real_app_probe
    monkeypatch.setattr(cli.sys.stdin, "isatty", lambda: interactive)
    monkeypatch.setattr("builtins.input", lambda _: pytest.fail("unexpected prompt"))
    assert cli.main(["uninstall", "--instance", selected.id, "--purge", "--yes"]) == 0
    assert calls == [
        ("uninstall", selected.id, {"purge": True, "confirmed": True, "dry_run": False})
    ]


def test_purge_dry_run_does_not_require_confirmation(real_app_probe, monkeypatch):
    selected, calls = real_app_probe
    monkeypatch.setattr("builtins.input", lambda _: pytest.fail("unexpected prompt"))
    assert cli.main(["uninstall", "--instance", selected.id, "--purge", "--dry-run"]) == 0
    assert calls == [
        ("uninstall", selected.id, {"purge": True, "confirmed": False, "dry_run": True})
    ]


def test_ordinary_uninstall_does_not_require_confirmation(real_app_probe, monkeypatch):
    selected, calls = real_app_probe
    monkeypatch.setattr("builtins.input", lambda _: pytest.fail("unexpected prompt"))
    assert cli.main(["uninstall", "--instance", selected.id]) == 0
    assert calls == [
        ("uninstall", selected.id, {"purge": False, "confirmed": False, "dry_run": False})
    ]


@pytest.mark.parametrize("language,wording", [("en", "or newer"), ("ru", "или новее")])
def test_deployment_floor_refusal_explains_supported_line_without_changing_json(
    capsys, language, wording
):
    from xferry.management.versions import MIN_DEPLOYMENT_RELEASE

    result = OperationResult(2, "unsupported_deployment_release")
    assert cli._render_application_result(result, json_output=False, language=language) == 2
    text = capsys.readouterr().err
    assert MIN_DEPLOYMENT_RELEASE in text and wording in text
    assert "unsupported_deployment_release" not in text
    assert cli._render_application_result(result, json_output=True, language=language) == 2
    assert json.loads(capsys.readouterr().out)["message"] == "unsupported_deployment_release"


@pytest.mark.parametrize(
    "arguments",
    [
        ["setup", "--docker"],
        ["uninstall", "--purge-data"],
        ["status", "--config", "/etc/xferry/xferry.ini"],
        ["config", "show", "--config", "file.ini", "--instance", "deployment-id"],
    ],
)
def test_removed_or_ambiguous_selectors_fail_before_application_calls(app_probe, arguments):
    assert cli.main(arguments) == 2
    assert app_probe.calls == []


def test_log_options_and_backend_exit_are_preserved(app_probe, monkeypatch):
    calls = []

    def logs(action, selected, **options):
        calls.append((action, selected.id, options))
        return OperationResult(7, "log stream ended")

    monkeypatch.setattr(app_probe, "operate", logs)
    assert cli.main(["logs", "--lines", "4", "--since", "yesterday", "--follow"]) == 7
    assert calls == [
        ("logs", app_probe.deployments[0].id, {"lines": 4, "since": "yesterday", "follow": True})
    ]


def test_russian_state_and_doctor_rendering_keeps_machine_json_stable(capsys):
    state = ObservedState("running", "deployment-id", "native", "not_checked")
    result = OperationResult(
        0,
        "Native diagnostics completed.",
        state=state,
        details={
            "checks": {
                "health": {"status": "healthy", "detail": "authenticated health check passed"}
            }
        },
    )
    assert cli._render_application_result(result, json_output=False, language="ru") == 0
    text = capsys.readouterr().out
    assert "состояние: работает" in text and "здоровье: не проверено" in text
    assert "Здоровье: исправно" in text
    assert "authenticated health check passed" not in text
    assert cli._render_application_result(result, json_output=True, language="ru") == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["state"]["state"] == "running"
    assert payload["state"]["health"] == "not_checked"


def test_firewall_consent_is_collected_once_before_setup_activation(app_probe, monkeypatch):
    options_seen = []

    def setup(**options):
        options_seen.append(dict(options))
        if options.get("firewall") is None:
            return OperationResult(
                2,
                "UFW consent required",
                details={"firewall_consent_required": True, "firewall_ports": [80, 443]},
            )
        return OperationResult(0, "setup ready")

    monkeypatch.setattr(app_probe, "setup", setup)
    monkeypatch.setattr(cli.sys.stdin, "isatty", lambda: True)
    answers = iter(["yes", "yes"])
    monkeypatch.setattr("builtins.input", lambda _: next(answers))
    assert cli.main(["setup", "--backend", "native", "--public-ip", "8.8.8.8"]) == 0
    assert [options["dry_run"] for options in options_seen] == [True, True, False]
    assert options_seen[1]["firewall"] is True and options_seen[2]["firewall"] is True


def test_persistent_wizard_previews_then_applies_with_original_text(app_probe, monkeypatch):
    selected = app_probe.deployments[0]
    before = selected.config.read_text()
    answers = iter(["2", "20", "9", "yes"])
    monkeypatch.setattr("builtins.input", lambda _: next(answers))
    assert wizard.configure(selected.config, "docker", "en", instance=selected) == 0
    assert [call[2]["apply"] for call in app_probe.calls] == [False, True]
    assert all(call[2]["expected_text"] == before for call in app_probe.calls)
    assert selected.config.read_text() == before


def test_explicit_docker_image_is_forwarded_without_a_release_version(app_probe):
    image = "registry.example/xferry@sha256:" + "a" * 64
    assert cli.main(["setup", "--backend", "docker", "--image", image, "--dry-run"]) == 0
    options = app_probe.calls[0][2]
    assert options["image"] == image and options["version"] is None


@pytest.mark.parametrize("extra", [[], ["--backend", "docker", "--to", __version__]])
def test_image_selection_rejects_native_or_conflicting_release_before_setup(app_probe, extra):
    image = "registry.example/xferry@sha256:" + "a" * 64
    assert cli.main(["setup", "--image", image, *extra]) == 2
    assert app_probe.calls == []


def test_advanced_output_creates_an_explicit_docker_bundle(app_probe, tmp_path, capsys):
    output = tmp_path / "second deployment"
    assert cli.main(["setup", "--backend", "docker", "--output", str(output), "--dry-run"]) == 0
    assert app_probe.calls[0][2]["output"] == output
    capsys.readouterr()
    assert cli.main(["setup", "--help"]) == 0
    assert "--output" not in capsys.readouterr().out
    assert cli.main(["setup", "--help-all"]) == 0
    assert "--output" in capsys.readouterr().out
    assert cli.main(["setup", "--output", str(output)]) == 2


@pytest.mark.parametrize("platform", ["linux", "darwin", "win32"])
def test_status_without_deployment_reports_absent_instead_of_usage_error(
    tmp_path, monkeypatch, capsys, platform
):
    app = application.ManagementApplication()
    monkeypatch.setattr(application, "default_application", lambda: app)
    monkeypatch.setattr(instances, "discover_instances", lambda: ())
    monkeypatch.setattr(application, "discover_instances", lambda: ())
    monkeypatch.setattr(cli.sys, "platform", platform)
    monkeypatch.setattr(cli, "_privileged", lambda *_: pytest.fail("absent status elevated"))
    assert cli.main(["status", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["exit_code"] == 0
    assert payload["state"]["state"] == "absent"
    assert payload["state"]["health"] == "not_checked"
    assert payload["state"]["instance_id"] is None
    assert cli.main(["status", "--instance", "unknown-deployment", "--json"]) == 2


def test_docker_config_reports_actual_volume_and_runtime_root(app_probe, capsys):
    assert (
        cli.main(["config", "show", "--all", "--instance", app_probe.deployments[0].id, "--json"])
        == 0
    )
    rows = json.loads(capsys.readouterr().out)
    row = next(row for row in rows if row["name"] == "state_dir")
    assert row["value"] == "Docker volume xferry-probe_xferry-data"
    assert row["runtime_value"] == "/data" and row["source"] == "deployment"
    assert row["read_only"] is True
    assert str(app_probe.deployments[0].config.parent / "state") not in row["value"]


@pytest.mark.parametrize("json_output", [False, True])
def test_credential_presentation_is_explicit_and_json_suppresses_both_streams(capsys, json_output):
    result = OperationResult(
        0,
        "setup complete",
        credentials=SimpleNamespace(
            username="operator", password="typedSecret234", url="https://example.test"
        ),
    )
    assert cli._render_application_result(result, json_output=json_output) == 0
    captured = capsys.readouterr()
    if json_output:
        assert "typedSecret234" not in captured.out + captured.err
        assert "operator" not in captured.out + captured.err
        assert json.loads(captured.out)["exit_code"] == 0
    else:
        assert captured.out.count("typedSecret234") == 1
        assert captured.err == ""
