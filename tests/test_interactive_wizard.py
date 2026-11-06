"""Interactive drafts reuse canonical setup and configuration boundaries."""

from __future__ import annotations

import argparse
from collections import deque
from contextlib import contextmanager
from types import SimpleNamespace

import pytest

from xferry.management import application, configuration, instances, interactive
from xferry.management.deployment import Credentials, ObservedState, OperationResult
from xferry.management.terminal import Back
from xferry.settings import load_settings_text


class ScriptedUI:
    enhanced = True
    language = "en"

    def __init__(self, *answers):
        self.answers = deque(answers)
        self.panels = []
        self.messages = []
        self.prompts = []
        self.selections = []
        self.invalid = []
        self.events = []
        self.progress_active = False

    def _answer(self):
        answer = self.answers.popleft()
        if isinstance(answer, BaseException):
            raise answer
        return answer

    def select(self, title, choices, default=None, **kwargs):
        self.prompts.append((title, default))
        self.selections.append((title, choices))
        answer = self._answer()
        if answer is None:
            answer = default
        if answer not in {choice.value for choice in choices}:
            answer = next((choice.value for choice in choices if choice.shortcut == answer), answer)
        assert answer in {choice.value for choice in choices}
        return answer

    def text(self, title, default="", *, validator=None, **kwargs):
        self.prompts.append((title, default))
        while True:
            answer = self._answer()
            error = validator(answer) if validator else None
            if error:
                self.invalid.append(error)
                continue
            return answer

    def confirm(self, title, default=False):
        self.prompts.append((title, default))
        answer = self._answer()
        assert isinstance(answer, bool)
        return answer

    def panel(self, title, rows, **kwargs):
        self.panels.append((title, list(rows)))

    def message(self, text, **kwargs):
        self.messages.append(text)

    @contextmanager
    def progress(self):
        self.progress_active = True
        try:
            yield self.events.append
        finally:
            self.progress_active = False


def setup_args(**overrides):
    options = {
        "backend": "native",
        "access": None,
        "files_dir": None,
        "domain": None,
        "public_ip": None,
        "explicit_options": frozenset(),
    }
    options.update(overrides)
    return argparse.Namespace(**options)


def profile(tmp_path):
    path = tmp_path / "profile.ini"
    path.write_text("[server]\nconfig_version = 1\naccess = private\n")
    return path


def test_setup_selects_backend_folder_and_private_access_without_creating_files(tmp_path):
    folder = tmp_path / "shared"
    args = setup_args()
    ui = ScriptedUI("docker", str(folder), "private")
    assert interactive.prepare_setup(args, "en", ui=ui)
    assert (args.backend, args.files_dir, args.access) == ("docker", str(folder), "private")
    assert not folder.exists()


def test_setup_back_preserves_previous_folder_answer(tmp_path):
    first, final = tmp_path / "first", tmp_path / "final"
    args = setup_args()
    ui = ScriptedUI("native", str(first), Back(), str(final), "private")
    assert interactive.prepare_setup(args, "en", ui=ui)
    folder_prompts = [
        default for title, default in ui.prompts if title == "Files folder on this host"
    ]
    assert folder_prompts[-1] == str(first)
    assert args.files_dir == str(final)
    assert not first.exists() and not final.exists()


def test_docker_setup_defaults_to_a_user_folder_without_requesting_root(tmp_path):
    args = setup_args()
    folder = str(configuration.default_files_dir())
    ui = ScriptedUI("docker", folder, "private")
    assert interactive.prepare_setup(args, "en", ui=ui)
    assert args.files_dir == folder
    assert folder != "/var/lib/xferry/files"
    assert ("Files folder on this host", folder) in ui.prompts
    assert not configuration.default_files_dir().exists()


@pytest.mark.parametrize("custom", [False, True])
def test_switching_backend_updates_only_an_automatic_folder_default(tmp_path, custom):
    native_default = str(configuration.default_files_dir(managed=True))
    docker_default = str(configuration.default_files_dir())
    initial_folder = str(tmp_path / "chosen") if custom else native_default
    expected_folder = initial_folder if custom else docker_default
    args = setup_args()
    ui = ScriptedUI("native", initial_folder, Back(), Back(), "docker", expected_folder, "private")
    assert interactive.prepare_setup(args, "en", ui=ui)
    folder_prompts = [
        default for title, default in ui.prompts if title == "Files folder on this host"
    ]
    assert folder_prompts[-1] == expected_folder
    assert args.files_dir == expected_folder


def test_setup_preserves_explicit_cli_options_and_asks_only_omitted_inputs(tmp_path):
    folder = str(tmp_path / "chosen")
    args = setup_args(
        backend="docker", files_dir=folder, explicit_options=frozenset({"--backend", "--files-dir"})
    )
    ui = ScriptedUI("domain", "Files.Example.COM")
    assert interactive.prepare_setup(args, "en", ui=ui)
    assert args.domain == "files.example.com"
    assert args.files_dir == folder and args.backend == "docker"
    assert len(ui.prompts) == 2


def test_setup_with_explicit_choices_never_repeats_questions(tmp_path):
    args = setup_args(
        backend="docker",
        files_dir=str(tmp_path),
        access="public",
        explicit_options=frozenset({"--backend", "--files-dir", "--access"}),
    )
    ui = ScriptedUI()
    assert interactive.prepare_setup(args, "en", ui=ui)
    assert ui.prompts == []


def test_setup_reprompts_invalid_directory_and_cancellation_does_not_create_it(tmp_path):
    existing_file = tmp_path / "file.txt"
    existing_file.write_text("keep")
    folder = tmp_path / "chosen"
    args = setup_args()
    ui = ScriptedUI("native", str(existing_file), str(folder), KeyboardInterrupt())
    assert not interactive.prepare_setup(args, "en", ui=ui)
    assert ui.invalid == ["Choose a directory, not a file."]
    assert not folder.exists() and existing_file.read_text() == "keep"


def test_failed_setup_review_offers_correction_without_installing(tmp_path):
    args = setup_args(files_dir=str(tmp_path), access="public")
    ui = ScriptedUI("edit")
    assert (
        interactive.review_setup(args, OperationResult(2, "TCP 443 is occupied"), "en", ui=ui)
        == "edit"
    )
    assert ui.messages == ["TCP 443 is occupied"]
    assert any(value == str(tmp_path) for _, value in ui.panels[0][1])


def test_config_validates_scalar_in_place_then_saves_the_corrected_value(tmp_path):
    path = profile(tmp_path)
    ui = ScriptedUI("max_size_mb", "invalid", "25", "save", True)
    assert interactive.configure(path, "portable", "en", ui=ui) == 0
    assert load_settings_text(path.read_text()).max_size_mb == 25
    assert any("integer" in error for error in ui.invalid)
    assert not ui.answers


def test_declining_review_retains_draft_until_cancel_without_writing(tmp_path):
    path = profile(tmp_path)
    before = path.read_text()
    ui = ScriptedUI("max_size_mb", "25", "save", False, "cancel")
    assert interactive.configure(path, "portable", "en", ui=ui) == 0
    assert path.read_text() == before
    assert any("max_size_mb = 25" in value for _, rows in ui.panels for _, value in rows)


def test_optional_files_folder_can_be_cleared_to_the_platform_default(tmp_path):
    path = profile(tmp_path)
    path.write_text(path.read_text() + f"files_dir = {tmp_path / 'old-files'}\n")
    ui = ScriptedUI("files_dir", "-", "save", True)
    assert interactive.configure(path, "portable", "en", ui=ui) == 0
    assert not ui.invalid
    assert str(tmp_path / "old-files") not in path.read_text()


def test_cross_field_error_blocks_save_and_allows_correction_without_losing_draft(tmp_path):
    path = profile(tmp_path)
    ui = ScriptedUI(
        "search",
        "cors_origin",
        "https://example.test/path",
        "save",
        "search",
        "cors_origin",
        "https://example.test",
        "save",
        True,
    )
    assert interactive.configure(path, "portable", "en", ui=ui) == 0
    assert load_settings_text(path.read_text()).cors_origin == "https://example.test"
    assert any("Correct the draft" in message for message in ui.messages)
    assert any(
        "cors_origin = https://example.test" in value for _, rows in ui.panels for _, value in rows
    )


def test_invalid_scalar_draft_stays_editable_if_a_widget_returns_invalid_input(tmp_path):
    class UncheckedUI(ScriptedUI):
        def text(self, title, default="", **kwargs):
            return self._answer()

    path = profile(tmp_path)
    ui = UncheckedUI("max_size_mb", "broken", "save", "max_size_mb", "25", "save", True)
    assert interactive.configure(path, "portable", "en", ui=ui) == 0
    assert load_settings_text(path.read_text()).max_size_mb == 25
    assert any("Correct the draft" in message for message in ui.messages)


def test_escaping_setting_edit_returns_to_editor_and_discards_no_other_draft(tmp_path):
    path = profile(tmp_path)
    ui = ScriptedUI("max_size_mb", "25", "files_dir", Back(), "save", True)
    assert interactive.configure(path, "portable", "en", ui=ui) == 0
    assert load_settings_text(path.read_text()).max_size_mb == 25


def test_escape_at_editor_root_leaves_file_unchanged(tmp_path):
    path = profile(tmp_path)
    before = path.read_text()
    assert interactive.configure(path, "portable", "en", ui=ScriptedUI(Back())) == 0
    assert path.read_text() == before


@pytest.mark.parametrize("interrupt", [False, True])
def test_managed_apply_restores_progress_observer_and_reports_interruption(
    tmp_path, monkeypatch, interrupt
):
    path = profile(tmp_path)
    marker = object()
    calls = []
    ui = ScriptedUI("max_size_mb", "25", "save", True)
    app = SimpleNamespace(progress=marker)

    def configure(instance, changes, *, apply, expected_text):
        calls.append((dict(changes), apply, expected_text))
        if apply:
            assert ui.progress_active and app.progress != marker
            if interrupt:
                raise KeyboardInterrupt
        return OperationResult(0, "Applied" if apply else "Valid")

    app.configure = configure
    monkeypatch.setattr(application, "default_application", lambda: app)
    assert interactive.configure(path, "managed", "en", ui=ui) == (130 if interrupt else 0)
    assert [apply for _, apply, _ in calls] == [False, True]
    assert calls[-1][0] == {"max_size_mb": "25"}
    assert app.progress is marker and not ui.progress_active
    if interrupt:
        assert any(
            "xferry status" in message and "xferry doctor" in message for message in ui.messages
        )
        assert not any("no changes made" in message for message in ui.messages)


def test_managed_password_action_requires_pending_settings_to_be_saved_first(tmp_path):
    path = profile(tmp_path)
    ui = ScriptedUI("max_size_mb", "25", "password", "cancel")
    assert interactive.configure(path, "managed", "en", ui=ui) == 0
    assert any("Save or cancel pending" in message for message in ui.messages)
    assert load_settings_text(path.read_text()).max_size_mb != 25


def test_managed_owned_settings_are_visible_but_not_editable(tmp_path):
    path = profile(tmp_path)
    ui = ScriptedUI("search", "state_dir", "cancel")
    assert interactive.configure(path, "managed", "en", ui=ui) == 0
    assert "Managed automatically by this deployment." in ui.messages


def test_root_menu_returns_after_action_and_can_exit(monkeypatch):
    monkeypatch.setattr(instances, "discover_instances", lambda: ())
    ui = ScriptedUI("help", "exit")
    commands = []
    assert interactive.menu("en", lambda command: commands.append(command) or 0, ui=ui) == 0
    assert commands == [["help"]]
    assert len([title for title, _ in ui.panels if title == "xferry"]) == 2


def test_multiple_servers_are_selected_before_action_and_observed_again(tmp_path, monkeypatch):
    first = instances.Instance("first", "docker", tmp_path / "one.ini", tmp_path / "one.json")
    second = instances.Instance("second", "docker", tmp_path / "two.ini", tmp_path / "two.json")
    monkeypatch.setattr(instances, "discover_instances", lambda: (first, second))
    app = SimpleNamespace(
        observe=lambda item: ObservedState("stopped" if item.id == "second" else "running")
    )
    monkeypatch.setattr(application, "default_application", lambda: app)
    ui = ScriptedUI("server", "second", "primary", "exit")
    commands = []
    assert interactive.menu("en", lambda command: commands.append(command) or 0, ui=ui) == 0
    assert commands == [["start", "--instance", "second"]]


def test_result_summary_keeps_literal_values_and_credentials_returned_by_application():
    ui = ScriptedUI()
    result = OperationResult(
        0,
        "Ready",
        details={"instance_id": "test"},
        credentials=Credentials("admin", "[red]literal[/red]", "https://files.example.com/"),
    )
    assert interactive.render_result(ui, result, files_dir="/srv/[share]") == 0
    rows = dict(ui.panels[0][1])
    assert rows["Files folder"] == "/srv/[share]"
    assert rows["Password"] == "[red]literal[/red]"
    assert rows["URL"] == "https://files.example.com/"


@pytest.mark.parametrize(
    "answers",
    [
        (Back(),),
        ("auto", Back()),
        ("domain", Back()),
        ("files", Back()),
        ("files", "/tmp/certificate.pem", Back()),
        ("files", "/tmp/certificate.pem", "/tmp/private.key", Back()),
    ],
)
def test_tls_subwizard_esc_discards_partial_mode_changes(answers):
    draft = {"https_mode": "domain", "domain": "old.example.com", "max_size_mb": "25"}
    before = draft.copy()
    with pytest.raises(Back):
        interactive._tls(ScriptedUI(*answers), draft, "managed")
    assert draft == before


@pytest.mark.parametrize(
    "mode,public,host,port",
    [
        ("off", False, "127.0.0.1", "8080"),
        ("self-signed", False, "127.0.0.1", "8080"),
        ("domain", True, "0.0.0.0", "443"),
    ],
)
def test_tls_mode_change_clears_incompatible_old_transport_settings(mode, public, host, port):
    draft = {
        "cert_file": "/old/cert",
        "key_file": "/old/key",
        "domain": "old.example.com",
        "public_ip": "8.8.4.4",
        "allowed_hosts": "old.example.com",
        "acme_server": "staging",
        "max_size_mb": "25",
    }
    ui = ScriptedUI(mode, *(("Files.Example.COM",) if mode == "domain" else ()))
    interactive._tls(ui, draft, "managed")
    assert (draft["access"], draft["host"], draft["port"]) == (
        "public" if public else "private",
        host,
        port,
    )
    assert draft["https_mode"] == mode and draft["max_size_mb"] == "25"
    assert (
        draft["cert_file"] == draft["key_file"] == draft["public_ip"] == draft["acme_server"] == ""
    )
    assert draft["domain"] == ("files.example.com" if mode == "domain" else "")
    assert draft["allowed_hosts"] == (
        "files.example.com" if public else "127.0.0.1 localhost" if mode == "off" else ""
    )


def test_tls_certificate_file_mode_keeps_hostnames_and_resolves_paths(tmp_path):
    cert, key = tmp_path / "cert.pem", tmp_path / "private.pem"
    draft = {"domain": "old.example.com", "public_ip": "8.8.4.4"}
    ui = ScriptedUI("files", str(cert), str(key), "files.example.com uploads.example.com")
    interactive._tls(ui, draft, "managed")
    assert (draft["cert_file"], draft["key_file"]) == (str(cert), str(key))
    assert draft["allowed_hosts"] == "files.example.com uploads.example.com"
    assert draft["domain"] == draft["public_ip"] == ""
    assert not cert.exists() and not key.exists()


@pytest.mark.parametrize(
    "target,provided,discover",
    [
        ("managed", "", True),
        ("docker", "", True),
        ("portable", "", False),
        ("managed", "8.8.8.8", False),
    ],
)
def test_auto_https_discovers_address_only_for_installed_target_when_needed(
    monkeypatch, target, provided, discover
):
    from xferry.security import tls

    calls = []
    monkeypatch.setattr(tls, "resolve_public_ipv4", lambda: calls.append("discover") or "8.8.8.8")
    draft = {}
    ui = ScriptedUI("auto", provided)
    interactive._tls(ui, draft, target)
    assert calls == (["discover"] if discover else [])
    assert draft["https_mode"] == "auto" and draft["access"] == "public"
    assert draft["public_ip"] == ("8.8.8.8" if discover else provided)
    assert not ui.progress_active


def test_auto_https_discovery_failure_keeps_original_draft_and_cleans_progress(monkeypatch):
    from xferry.security import tls

    def unavailable():
        raise ValueError("Public IPv4 discovery unavailable")

    monkeypatch.setattr(tls, "resolve_public_ipv4", unavailable)
    draft = {"https_mode": "off", "max_size_mb": "25"}
    ui = ScriptedUI("auto", "")
    with pytest.raises(ValueError, match="discovery unavailable"):
        interactive._tls(ui, draft, "managed")
    assert draft == {"https_mode": "off", "max_size_mb": "25"}
    assert not ui.progress_active
    assert [(event.stage, event.state) for event in ui.events] == [
        ("preflight", "running"),
        ("preflight", "failed"),
    ]


def test_setup_edit_answers_rejects_private_ip_then_accepts_manual_public_ip(tmp_path):
    args = setup_args()
    ui = ScriptedUI("docker", "", str(tmp_path / "files"), "auto", "127.0.0.1", "8.8.8.8")
    assert interactive.prepare_setup(args, "en", ui=ui, edit=True)
    assert args.access == "public" and args.public_ip == "8.8.8.8"
    assert len(ui.invalid) == 2
    assert not (tmp_path / "files").exists()


def test_initial_native_setup_automatic_address_needs_only_folder_and_access(tmp_path):
    args = setup_args(explicit_options=frozenset({"--backend"}))
    folder = tmp_path / "shared"
    ui = ScriptedUI(str(folder), "auto")
    assert interactive.prepare_setup(args, "en", ui=ui)
    assert args.backend == "native" and args.files_dir == str(folder)
    assert args.access == "public" and args.public_ip is None
    assert len(ui.prompts) == 2 and not ui.answers
    assert not folder.exists()


def test_setup_domain_rejects_missing_or_invalid_hostname_then_normalizes(tmp_path):
    args = setup_args(
        backend="docker",
        files_dir=str(tmp_path),
        explicit_options=frozenset({"--backend", "--files-dir"}),
    )
    ui = ScriptedUI("domain", "", "https://invalid.example/path", "FILES.EXAMPLE.COM")
    assert interactive.prepare_setup(args, "en", ui=ui)
    assert args.domain == "files.example.com" and len(ui.invalid) == 2


@pytest.mark.parametrize(
    "answer,expected", [(Back(), "edit"), (KeyboardInterrupt(), "cancel"), ("apply", "apply")]
)
def test_setup_review_keeps_plan_and_handles_navigation(answer, expected, tmp_path):
    from xferry.management.deployment import OperationPlan

    args = setup_args(backend="docker", access="private", files_dir=str(tmp_path))
    result = OperationResult(
        0,
        "Validated",
        plan=OperationPlan("setup", steps=("prepare configuration", "start and verify")),
    )
    ui = ScriptedUI(answer)
    assert interactive.review_setup(args, result, "en", ui=ui) == expected
    rows = dict(ui.panels[0][1])
    assert rows["Address"] == "127.0.0.1"
    assert rows["2"] == "start and verify"


def test_grouped_settings_edit_boolean_and_choice_controls_then_save(tmp_path):
    path = profile(tmp_path)
    ui = ScriptedUI(
        "encrypted_uploads", "true", "advanced", "server", "log_level", "debug", "save", True
    )
    assert interactive.configure(path, "portable", "en", ui=ui) == 0
    settings = load_settings_text(path.read_text())
    assert settings.encrypted_uploads is True and settings.log_level == "debug"


def test_search_updates_list_setting_preserving_a_readable_current_value(tmp_path):
    path = profile(tmp_path)
    path.write_text(path.read_text() + "\n[plugins]\nplugin_allowlist = example, another\n")
    ui = ScriptedUI("search", "plugin_allowlist", "another", "save", True)
    assert interactive.configure(path, "portable", "en", ui=ui) == 0
    assert load_settings_text(path.read_text()).plugin_allowlist == ("another",)
    assert ("plugin_allowlist", "example, another") in ui.prompts


@pytest.mark.parametrize(
    "field,invalid,valid",
    [
        ("port", "65536", "8081"),
        ("max_connections", "0", "32"),
        ("body_timeout", "inf", "15"),
        ("cors_origin", "https://bad.example\ninjected = true", "https://example.test"),
    ],
)
def test_setting_editor_rejects_out_of_range_nonfinite_and_multiline_values(
    tmp_path, field, invalid, valid
):
    path = profile(tmp_path)
    ui = ScriptedUI("search", field, invalid, valid, "save", True)
    assert interactive.configure(path, "portable", "en", ui=ui) == 0
    actual = getattr(load_settings_text(path.read_text()), field)
    assert actual == (
        float(valid)
        if isinstance(actual, float)
        else int(valid)
        if isinstance(actual, int)
        else valid
    )
    assert ui.invalid


@pytest.mark.parametrize(
    "target,scenario",
    [
        ("managed", "preview_failure"),
        ("docker", "decline"),
        ("managed", "apply_failure"),
        ("docker", "apply_exception"),
    ],
)
def test_installed_configuration_failure_or_decline_never_reports_success(
    tmp_path, monkeypatch, target, scenario
):
    path = profile(tmp_path)
    before = path.read_text()
    calls = []
    marker = object()
    app = SimpleNamespace(progress=marker)

    def configure(instance, changes, *, apply, expected_text):
        calls.append(apply)
        assert expected_text == before
        if not apply:
            return OperationResult(
                2 if scenario == "preview_failure" else 0,
                "Preview rejected" if scenario == "preview_failure" else "Validated",
            )
        if scenario == "apply_exception":
            raise OSError("Runtime restart failed")
        return OperationResult(
            1,
            "Previous configuration restored",
            details={
                "code": "restart_failed",
                "detail": "Health check failed",
                "next_actions": ["xferry doctor"],
            },
        )

    app.configure = configure
    monkeypatch.setattr(application, "default_application", lambda: app)
    answers = ["max_size_mb", "25", "save"]
    if scenario != "preview_failure":
        answers.append(scenario != "decline")
    if scenario != "apply_failure":
        answers.append("cancel")
    ui = ScriptedUI(*answers)
    assert interactive.configure(path, target, "en", ui=ui) == (
        1 if scenario == "apply_failure" else 0
    )
    assert calls == ([False] if scenario in {"preview_failure", "decline"} else [False, True])
    assert app.progress is marker and not ui.progress_active
    assert path.read_text() == before
    if scenario == "apply_failure":
        details = dict(ui.panels[-1][1])
        assert details["Code"] == "restart_failed" and details["Details"] == "Health check failed"
        assert details["Next action"] == "xferry doctor"
    elif scenario == "apply_exception":
        assert "Runtime restart failed" in ui.messages


@pytest.mark.parametrize(
    "target,confirm", [("portable", False), ("portable", True), ("managed", True), ("docker", True)]
)
def test_password_action_rotates_only_after_confirmation_and_restores_observer(
    tmp_path, monkeypatch, target, confirm
):
    path = profile(tmp_path)
    before = path.read_text()
    if target == "portable":
        ui = ScriptedUI("password", confirm, *(() if confirm else ("cancel",)))
        assert interactive.configure(path, target, "en", ui=ui) == 0
        if confirm:
            auth_path = tmp_path / "xferry.auth"
            credentials = auth_path.read_text().strip().split(":", 1)
            assert credentials[0] == "admin" and len(credentials[1]) == 12
            assert credentials[1] in dict(ui.panels[-1][1]).values()
        else:
            assert path.read_text() == before and not (tmp_path / "xferry.auth").exists()
        return
    marker = object()
    app = SimpleNamespace(progress=marker)
    calls = []

    def credentials(instance):
        calls.append(instance)
        assert app.progress is not marker
        return OperationResult(
            0,
            "Credentials updated",
            credentials=Credentials("admin", "new-password", "https://files.example.com/"),
        )

    app.credentials = credentials
    monkeypatch.setattr(application, "default_application", lambda: app)
    ui = ScriptedUI("password", True)
    assert interactive.configure(path, target, "en", ui=ui) == 0
    assert calls == [None] and app.progress is marker and not ui.progress_active
    assert dict(ui.panels[-1][1])["Password"] == "new-password"


def test_password_file_setting_cannot_be_edited_as_plain_text(tmp_path):
    path = profile(tmp_path)
    ui = ScriptedUI("search", "auth_file", "cancel")
    assert interactive.configure(path, "portable", "en", ui=ui) == 0
    assert "Use Password to generate credentials." in ui.messages


@pytest.mark.parametrize(
    "state,expected",
    [
        ("running", "config"),
        ("stopped", "start"),
        ("broken", "doctor"),
        ("retained", "setup"),
        ("incomplete", "setup"),
    ],
)
def test_primary_menu_uses_observed_state_and_routes_recovery(
    tmp_path, monkeypatch, state, expected
):
    item = instances.Instance(
        "chosen", "docker", tmp_path / "profile.ini", tmp_path / "manifest.json"
    )
    monkeypatch.setattr(instances, "discover_instances", lambda: (item,))
    monkeypatch.setattr(
        application,
        "default_application",
        lambda: SimpleNamespace(observe=lambda _: ObservedState(state)),
    )
    commands = []
    ui = ScriptedUI("primary", "exit")
    assert interactive.menu("en", lambda command: commands.append(command) or 0, ui=ui) == 0
    assert commands == [
        [
            expected,
            *(["--backend", "docker"] if expected == "setup" else []),
            "--instance",
            "chosen",
        ]
    ]


def test_main_menu_selects_instance_for_direct_status_action(tmp_path, monkeypatch):
    items = tuple(
        instances.Instance(name, "docker", tmp_path / f"{name}.ini", tmp_path / f"{name}.json")
        for name in ("one", "two")
    )
    monkeypatch.setattr(instances, "discover_instances", lambda: items)
    monkeypatch.setattr(
        application,
        "default_application",
        lambda: SimpleNamespace(observe=lambda _: ObservedState("running")),
    )
    commands = []
    ui = ScriptedUI("status", "two", "exit")
    assert interactive.menu("en", lambda command: commands.append(command) or 0, ui=ui) == 0
    assert commands == [["status", "--instance", "two"]]


@pytest.mark.parametrize("saved", [False, True])
def test_main_menu_foreground_action_uses_saved_profile_when_present(tmp_path, monkeypatch, saved):
    path = tmp_path / "saved.ini"
    if saved:
        path.write_text("[server]\nconfig_version=1\n")
    monkeypatch.setattr(instances, "discover_instances", lambda: ())
    monkeypatch.setattr(instances, "foreground_config", lambda: path)
    commands = []
    ui = ScriptedUI("run", "exit")
    assert interactive.menu("en", lambda command: commands.append(command) or 0, ui=ui) == 0
    assert commands == [["run", *(["--config", str(path)] if saved else [])]]


@pytest.mark.parametrize("answer", [Back(), KeyboardInterrupt(), EOFError()])
def test_main_menu_can_be_left_without_dispatch(monkeypatch, answer):
    monkeypatch.setattr(instances, "discover_instances", lambda: ())
    ui = ScriptedUI(answer)
    assert interactive.menu("en", lambda _: pytest.fail("unexpected operation"), ui=ui) == 0


def test_new_foreground_profile_can_be_created_without_starting_a_server(tmp_path):
    path = tmp_path / "new.ini"
    ui = ScriptedUI("save", True)
    assert interactive.configure(path, "portable", "en", ui=ui) == 0
    settings = load_settings_text(path.read_text())
    assert settings.access == "private" and settings.config_version == 1
    assert not configuration.default_files_dir().exists()


def test_missing_managed_profile_requires_setup_instead_of_creating_one(tmp_path):
    path = tmp_path / "missing.ini"
    with pytest.raises(ValueError, match="run xferry setup first"):
        interactive.configure(path, "managed", "en", ui=ScriptedUI())
    assert not path.exists()


def test_tls_editor_applies_private_transition_only_after_review(tmp_path):
    path = profile(tmp_path)
    ui = ScriptedUI("tls", "self-signed", "save", False, "tls", "off", "save", True)
    assert interactive.configure(path, "portable", "en", ui=ui) == 0
    settings = load_settings_text(path.read_text())
    assert settings.https_mode == "off" and settings.host == "127.0.0.1"
    assert settings.allowed_hosts == ("127.0.0.1", "localhost")


def test_docker_editor_reports_owned_volume_instead_of_internal_path(tmp_path):
    path = profile(tmp_path)
    item = SimpleNamespace(
        backend="docker",
        spec=SimpleNamespace(backend_options={"state_storage": {"name": "xferry-state-test"}}),
    )
    ui = ScriptedUI("search", "state_dir", "cancel")
    assert interactive.configure(path, "docker", "en", instance=item, ui=ui) == 0
    choices = next(choices for title, choices in ui.selections if title == "Find a setting")
    state_choice = next(choice for choice in choices if choice.value == "state_dir")
    assert "Docker volume xferry-state-test" in state_choice.label
    assert "Managed automatically by this deployment." in ui.messages


def test_back_from_server_selection_returns_to_main_menu_without_action(tmp_path, monkeypatch):
    items = tuple(
        instances.Instance(name, "docker", tmp_path / f"{name}.ini", tmp_path / f"{name}.json")
        for name in ("one", "two")
    )
    monkeypatch.setattr(instances, "discover_instances", lambda: items)
    ui = ScriptedUI("server", Back(), "exit")
    assert interactive.menu("en", lambda _: pytest.fail("unexpected action"), ui=ui) == 0


def test_result_error_summary_retains_state_and_actionable_sanitized_details():
    ui = ScriptedUI()
    result = OperationResult(
        3,
        "Service did not start",
        details={
            "code": "health_failed",
            "detail": "HTTPS readiness timed out",
            "next_actions": ["xferry status", "xferry doctor"],
        },
        state=ObservedState("broken"),
    )
    assert interactive.render_result(ui, result) == 3
    rows = ui.panels[-1][1]
    assert ("State", "broken") in rows and ("Details", "HTTPS readiness timed out") in rows
    assert ("Next action", "xferry doctor") in rows
    assert not any(label == "Password" for label, _ in rows)


def test_russian_configuration_keeps_navigation_and_validation_localized(tmp_path):
    path = profile(tmp_path)
    ui = ScriptedUI("max_size_mb", "25", "save", True)
    ui.language = "ru"
    assert interactive.configure(path, "portable", "ru", ui=ui) == 0
    assert any(title == "Проверка изменений" for title, _ in ui.panels)
    assert load_settings_text(path.read_text()).max_size_mb == 25


def test_first_editor_choice_opens_files_folder_and_keeps_it_selected(tmp_path):
    path = profile(tmp_path)
    before = path.read_text()
    new_folder = tmp_path / "shared"
    ui = ScriptedUI(None, str(new_folder), "cancel")
    assert interactive.configure(path, "portable", "en", ui=ui) == 0
    editor_defaults = [default for title, default in ui.prompts if title == "Change a setting"]
    assert editor_defaults == ["files_dir", "files_dir"]
    assert any(("Files folder", str(new_folder)) in rows for _, rows in ui.panels)
    assert path.read_text() == before and not new_folder.exists()


def test_editor_remembers_last_field_and_explicit_review_selection(tmp_path):
    path = profile(tmp_path)
    ui = ScriptedUI("max_size_mb", "25", "save", False, "cancel")
    assert interactive.configure(path, "portable", "en", ui=ui) == 0
    editor_defaults = [default for title, default in ui.prompts if title == "Change a setting"]
    assert editor_defaults == ["files_dir", "max_size_mb", "save"]


def test_legacy_numeric_choices_can_change_limit_and_review_without_arrow_navigation(tmp_path):
    path = profile(tmp_path)
    ui = ScriptedUI("2", "25", "9", True)
    assert interactive.configure(path, "portable", "en", ui=ui) == 0
    assert load_settings_text(path.read_text()).max_size_mb == 25
    choices = next(choices for title, choices in ui.selections if title == "Change a setting")
    assert {choice.shortcut: choice.value for choice in choices} == {
        "1": "files_dir",
        "2": "max_size_mb",
        "3": "upload_storage_limit_mb",
        "4": "upload_reserve_free_mb",
        "5": "encrypted_uploads",
        "6": "tls",
        "7": "advanced",
        "8": "password",
        "9": "save",
        "0": "cancel",
        "/": "search",
    }


def test_advanced_escape_walks_one_level_at_a_time_and_preserves_other_draft_changes(tmp_path):
    path = profile(tmp_path)
    before_connections = load_settings_text(path.read_text()).max_connections
    ui = ScriptedUI(
        "max_size_mb",
        "25",
        "advanced",
        "limits",
        "max_connections",
        Back(),
        Back(),
        Back(),
        "save",
        True,
    )
    assert interactive.configure(path, "portable", "en", ui=ui) == 0
    settings = load_settings_text(path.read_text())
    assert settings.max_size_mb == 25 and settings.max_connections == before_connections
    assert [default for title, default in ui.prompts if title == "Setting"] == [
        None,
        "max_connections",
    ]
    assert [default for title, default in ui.prompts if title == "Settings group"] == [
        None,
        "limits",
    ]


def test_back_from_settings_list_allows_another_group_to_be_chosen(tmp_path):
    path = profile(tmp_path)
    ui = ScriptedUI("advanced", "limits", Back(), "server", "log_level", "debug", "save", True)
    assert interactive.configure(path, "portable", "en", ui=ui) == 0
    assert load_settings_text(path.read_text()).log_level == "debug"
    assert [default for title, default in ui.prompts if title == "Settings group"] == [
        None,
        "limits",
    ]


def test_back_from_search_editor_returns_to_search_list_and_retains_prior_changes(tmp_path):
    path = profile(tmp_path)
    before_timeout = load_settings_text(path.read_text()).body_timeout
    ui = ScriptedUI(
        "max_size_mb", "25", "search", "body_timeout", Back(), "workers", "4", "save", True
    )
    assert interactive.configure(path, "portable", "en", ui=ui) == 0
    settings = load_settings_text(path.read_text())
    assert (settings.max_size_mb, settings.workers, settings.body_timeout) == (
        25,
        4,
        before_timeout,
    )
    assert [default for title, default in ui.prompts if title == "Find a setting"] == [
        None,
        "body_timeout",
    ]


def test_root_menu_retains_legacy_help_and_exit_shortcuts(monkeypatch):
    monkeypatch.setattr(instances, "discover_instances", lambda: ())
    ui = ScriptedUI("5", "0")
    commands = []
    assert interactive.menu("en", lambda command: commands.append(command) or 0, ui=ui) == 0
    assert commands == [["help"]]
