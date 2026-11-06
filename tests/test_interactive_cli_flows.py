"""Operator journeys cross the real dispatcher, review and apply boundaries."""

from __future__ import annotations

from collections import deque
from contextlib import contextmanager
from types import SimpleNamespace

import pytest

from xferry.config import __version__
from xferry.management import application, cli, instances, terminal, wizard
from xferry.management.deployment import Credentials, ObservedState, OperationPlan, OperationResult
from xferry.management.terminal import Back, TerminalUI


class JourneyUI:
    enhanced = True
    language = "en"

    def __init__(self):
        self.answers = deque()
        self.panels = []
        self.messages = []
        self.questions = []
        self.progress_active = False

    def answer(self):
        assert self.answers, "unexpected interactive question"
        answer = self.answers.popleft()
        if isinstance(answer, BaseException):
            raise answer
        return answer

    def select(self, title, choices, default=None, **kwargs):
        values = [choice.value for choice in choices]
        self.questions.append((title, values))
        answer = self.answer()
        assert answer in values
        return answer

    def text(self, title, default="", *, validator=None, **kwargs):
        self.questions.append((title, default))
        answer = self.answer()
        assert validator is None or validator(answer) is None
        return answer

    def confirm(self, title, default=False):
        self.questions.append((title, default))
        answer = self.answer()
        assert isinstance(answer, bool)
        return answer

    def panel(self, title, rows, **kwargs):
        self.panels.append((title, dict(rows)))

    def message(self, text, **kwargs):
        self.messages.append(text)

    @contextmanager
    def progress(self):
        assert not self.progress_active
        self.progress_active = True
        try:
            yield lambda event: None
        finally:
            self.progress_active = False


class JourneyApplication:
    def __init__(self, ui):
        self.ui = ui
        self.results = deque()
        self.calls = []
        self.previous_observer = object()
        self.progress = self.previous_observer

    def setup(self, **options):
        assert self.ui.progress_active
        assert self.progress is not self.previous_observer
        self.calls.append(options)
        assert self.results, "unexpected setup operation"
        result = self.results.popleft()
        if isinstance(result, BaseException):
            raise result
        return result


@pytest.fixture
def journey(monkeypatch):
    ui = JourneyUI()
    app = JourneyApplication(ui)

    def get_ui(language="en", *, plain=False):
        if plain:
            return TerminalUI(language, plain=True)
        ui.language = language
        return ui

    monkeypatch.setattr(terminal, "get_ui", get_ui)
    monkeypatch.setattr(application, "default_application", lambda: app)
    monkeypatch.setattr(cli.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(cli.sys.stdout, "isatty", lambda: True)
    monkeypatch.setattr(cli.os, "geteuid", lambda: 0)
    monkeypatch.setenv("TERM", "xterm-256color")
    return SimpleNamespace(ui=ui, app=app)


def docker_setup(folder):
    return ["setup", "--backend", "docker", "--access", "private", "--files-dir", str(folder)]


def test_successful_setup_returns_the_reviewed_server_and_one_time_credentials(journey, tmp_path):
    folder = tmp_path / "shared files"
    journey.ui.answers.extend(["apply"])
    journey.app.results.extend(
        [
            OperationResult(0, "Ready to install", plan=OperationPlan("setup", steps=("Start",))),
            OperationResult(
                0,
                "Docker server is healthy.",
                details={"instance_id": "new-server", "files_dir": str(folder)},
                credentials=Credentials("admin", "visible-once", "http://127.0.0.1:8080/"),
                state=ObservedState("running", "new-server", "docker", running=True),
            ),
        ]
    )

    assert cli.main(docker_setup(folder)) == 0

    assert [call["dry_run"] for call in journey.app.calls] == [True, False]
    applied = journey.app.calls[-1]
    assert (applied["backend"], applied["access"], applied["files_dir"]) == (
        "docker",
        "private",
        folder,
    )
    assert applied["version"] == __version__
    summary = journey.ui.panels[-1][1]
    assert summary["URL"] == "http://127.0.0.1:8080/"
    assert summary["Files folder"] == str(folder)
    assert summary["Deployment ID"] == "new-server"
    assert summary["State"] == "running"
    assert (summary["Username"], summary["Password"]) == ("admin", "visible-once")
    assert journey.app.progress is journey.app.previous_observer
    assert not journey.ui.progress_active and not journey.ui.answers
    assert not folder.exists()


def test_setup_failure_after_confirmation_is_not_rendered_as_success(journey, tmp_path):
    journey.ui.answers.extend(["apply"])
    journey.app.results.extend(
        [
            OperationResult(0, "Ready"),
            OperationResult(
                6,
                "Server did not become healthy; previous state restored.",
                details={"next_actions": ["Run xferry doctor"]},
            ),
        ]
    )

    assert cli.main(docker_setup(tmp_path / "files")) == 6

    title, summary = journey.ui.panels[-1]
    assert title == "Operation failed"
    assert "previous state restored" in summary["Result"]
    assert summary["Next action"] == "Run xferry doctor"
    assert "Password" not in summary
    assert journey.app.progress is journey.app.previous_observer


def test_setup_exception_restores_presentation_and_returns_an_operator_error(
    journey, tmp_path, capsys
):
    journey.ui.answers.append("apply")
    journey.app.results.extend(
        [OperationResult(0, "Valid plan"), ValueError("Selected image is unavailable")]
    )

    assert cli.main(docker_setup(tmp_path / "files")) == 2

    assert "Selected image is unavailable" in capsys.readouterr().err
    assert journey.app.progress is journey.app.previous_observer
    assert not journey.ui.progress_active
    assert not any(title == "Complete" for title, _ in journey.ui.panels)


def test_explicit_image_setup_uses_the_selected_digest_and_bundle_directory(journey, tmp_path):
    image = "registry.example.test/xferry@sha256:" + "a" * 64
    bundle = tmp_path / "deployment bundle"
    journey.ui.answers.append("apply")
    journey.app.results.extend([OperationResult(0, "Valid"), OperationResult(0, "Healthy")])

    assert (
        cli.main([*docker_setup(tmp_path / "files"), "--image", image, "--output", str(bundle)])
        == 0
    )

    applied = journey.app.calls[-1]
    assert applied["version"] is None
    assert applied["image"] == image
    assert applied["output"] == bundle
    assert not bundle.exists()


@pytest.mark.parametrize("first_exit_code", [0, 5])
def test_editing_a_review_revalidates_the_new_folder_before_installing(
    journey, tmp_path, first_exit_code
):
    initial = tmp_path / "original"
    revised = tmp_path / "corrected"
    journey.ui.answers.extend(["edit", "docker", str(revised), "private", "apply"])
    journey.app.results.extend(
        [
            OperationResult(first_exit_code, "Review the selected folder"),
            OperationResult(0, "Corrected plan is valid"),
            OperationResult(0, "Installed corrected plan", details={"files_dir": str(revised)}),
        ]
    )

    assert cli.main(docker_setup(initial)) == 0

    assert [(call["dry_run"], call["files_dir"]) for call in journey.app.calls] == [
        (True, initial),
        (True, revised),
        (False, revised),
    ]
    assert journey.ui.panels[-1][1]["Files folder"] == str(revised)
    if first_exit_code:
        assert "Review the selected folder" in journey.ui.messages
    assert not journey.ui.answers
    assert not initial.exists() and not revised.exists()


@pytest.mark.parametrize("exit_code", [0, 5])
def test_cancelling_a_real_plan_review_never_calls_apply(journey, tmp_path, exit_code):
    journey.ui.answers.extend(["cancel"])
    journey.app.results.append(OperationResult(exit_code, "Port 443 is occupied"))

    assert cli.main(docker_setup(tmp_path / "files")) == exit_code

    assert len(journey.app.calls) == 1 and journey.app.calls[0]["dry_run"]
    review_actions = journey.ui.questions[-1][1]
    assert ("apply" in review_actions) is (exit_code == 0)
    assert journey.app.progress is journey.app.previous_observer


def test_back_from_the_first_edit_question_cancels_without_applying(journey, tmp_path):
    journey.ui.answers.extend(["edit", Back()])
    journey.app.results.append(OperationResult(0, "Valid plan"))

    assert cli.main(docker_setup(tmp_path / "files")) == 0

    assert [call["dry_run"] for call in journey.app.calls] == [True]
    assert not journey.ui.answers


@pytest.mark.parametrize("cancel", [Back(), EOFError(), KeyboardInterrupt()])
def test_cancelling_the_initial_questions_does_not_probe_or_request_sudo(
    journey, monkeypatch, cancel
):
    journey.ui.answers.append(cancel)
    monkeypatch.setattr(cli.os, "geteuid", lambda: 1000)
    monkeypatch.setattr(cli, "_privileged", lambda *args: pytest.fail("unexpected sudo"))

    assert cli.main(["setup"]) == 0

    assert not journey.app.calls


@pytest.mark.parametrize("language", ["en", "ru"])
@pytest.mark.parametrize("approved", [False, True])
def test_firewall_consent_precedes_review_and_activation(journey, tmp_path, language, approved):
    journey.ui.answers.append(approved)
    journey.app.results.append(
        OperationResult(
            2,
            "Firewall consent required",
            details={"firewall_consent_required": True, "firewall_ports": [80, 443]},
        )
    )
    if approved:
        journey.ui.answers.append("apply")
        journey.app.results.extend([OperationResult(0, "Valid"), OperationResult(0, "Healthy")])

    assert (
        cli.main(
            [
                "--lang",
                language,
                "setup",
                "--backend",
                "native",
                "--access",
                "public",
                "--files-dir",
                str(tmp_path / "files"),
            ]
        )
        == 0
    )

    assert "80/tcp" in journey.ui.questions[0][0]
    assert "443/tcp" in journey.ui.questions[0][0]
    assert journey.app.calls[0]["firewall"] is None
    if approved:
        assert [call["dry_run"] for call in journey.app.calls] == [True, True, False]
        assert all(call["firewall"] is True for call in journey.app.calls[1:])
    else:
        assert len(journey.app.calls) == 1
    assert not journey.ui.answers


def test_firewall_consent_uses_public_ports_when_backend_omits_port_details(journey, tmp_path):
    journey.ui.answers.append(False)
    journey.app.results.append(
        OperationResult(2, "Consent required", details={"firewall_consent_required": True})
    )

    assert cli.main(docker_setup(tmp_path / "files")) == 0

    assert "80/tcp" in journey.ui.questions[0][0] and "443/tcp" in journey.ui.questions[0][0]
    assert len(journey.app.calls) == 1


def test_changing_docker_to_native_hands_edited_answers_to_sudo_without_local_apply(
    journey, monkeypatch, tmp_path
):
    folder = tmp_path / "native files"
    journey.ui.answers.extend(["edit", "native", str(folder), "private"])
    journey.app.results.append(OperationResult(0, "Docker preview"))
    monkeypatch.setattr(cli.os, "geteuid", lambda: 1000)
    forwarded = []

    def privileged(arguments, context):
        parsed = cli._command_parser("setup", context.translator).parse_args(arguments[1:])
        forwarded.append((parsed, context.language.code))
        return 23

    monkeypatch.setattr(cli, "_privileged", privileged)

    assert cli.main(["--lang", "ru", *docker_setup(tmp_path / "docker files")]) == 23

    parsed, language = forwarded[0]
    assert (parsed.backend, parsed.access, parsed.files_dir, language) == (
        "native",
        "private",
        str(folder),
        "ru",
    )
    assert [call["dry_run"] for call in journey.app.calls] == [True]
    assert not journey.ui.answers


def test_native_questions_collect_a_domain_before_forwarding_the_plan_to_sudo(
    journey, monkeypatch, tmp_path
):
    folder = tmp_path / "shared files"
    journey.ui.answers.extend(["native", str(folder), "domain", "Files.Example.COM"])
    monkeypatch.setattr(cli.os, "geteuid", lambda: 1000)
    forwarded = []

    def privileged(arguments, context):
        forwarded.append(cli._command_parser("setup", context.translator).parse_args(arguments[1:]))
        return 19

    monkeypatch.setattr(cli, "_privileged", privileged)

    assert cli.main(["setup", "--email", "operator@example.test", "--to", "0.5.1"]) == 19

    plan = forwarded[0]
    assert (plan.backend, plan.files_dir, plan.access, plan.domain) == (
        "native",
        str(folder),
        "public",
        "files.example.com",
    )
    assert (plan.email, plan.to) == ("operator@example.test", "0.5.1")
    assert not journey.app.calls and not journey.ui.answers
    assert not folder.exists()


def test_plain_setup_collects_missing_choices_and_declining_review_does_not_install(
    journey, monkeypatch, tmp_path, capsys
):
    folder = tmp_path / "plain files"
    answers = iter([str(folder), "3", "no"])
    monkeypatch.setattr("builtins.input", lambda title: next(answers))
    calls = []
    monkeypatch.setattr(
        application,
        "default_application",
        lambda: SimpleNamespace(
            setup=lambda **options: calls.append(options) or OperationResult(0, "Plan is valid")
        ),
    )

    assert cli.main(["--plain", "setup", "--backend", "docker"]) == 0

    assert len(calls) == 1 and calls[0]["dry_run"]
    assert (calls[0]["access"], calls[0]["files_dir"]) == ("private", folder)
    assert "Plan is valid" in capsys.readouterr().out
    assert not journey.ui.questions
    assert not folder.exists()


def test_reinstall_selected_instance_skips_new_setup_questions(journey, tmp_path):
    folder = tmp_path / "retained files"
    journey.ui.answers.append("apply")
    journey.app.results.extend(
        [
            OperationResult(0, "Retained deployment validated", details={"files_dir": str(folder)}),
            OperationResult(
                0,
                "Existing deployment resumed",
                details={"files_dir": str(folder), "instance_id": "existing"},
            ),
        ]
    )

    assert cli.main(["setup", "--backend", "docker", "--instance", "existing"]) == 0

    assert len(journey.ui.questions) == 1
    assert all(call["instance_id"] == "existing" for call in journey.app.calls)
    assert journey.ui.panels[-1][1]["Files folder"] == str(folder)


@pytest.mark.parametrize("choice", ["second", Back()])
def test_instance_selection_dispatches_only_the_selected_server_or_cancels(
    journey, monkeypatch, tmp_path, choice, capsys
):
    first = instances.Instance("first", "docker", tmp_path / "first.ini", tmp_path / "first.json")
    second = instances.Instance(
        "second", "docker", tmp_path / "second.ini", tmp_path / "second.json"
    )
    monkeypatch.setattr(instances, "discover_instances", lambda: (first, second))
    journey.ui.answers.append(choice)
    operated = []

    def resolve(identity):
        assert identity == "second"
        return second

    monkeypatch.setattr(journey.app, "resolve", resolve, raising=False)
    monkeypatch.setattr(
        journey.app,
        "operate",
        lambda action, selected, **options: (
            operated.append((action, selected)) or OperationResult(0, "Selected server is running")
        ),
        raising=False,
    )

    assert cli.main(["--lang", "ru", "status"]) == 0

    if isinstance(choice, Back):
        assert not operated
        assert "Selected server" not in capsys.readouterr().out
    else:
        assert operated == [("status", second)]
        assert "Selected server is running" in capsys.readouterr().out


@pytest.mark.parametrize("plain", [False, True])
def test_menu_dispatch_preserves_language_and_plain_preference_for_the_configurator(
    journey, monkeypatch, tmp_path, plain
):
    calls = []
    path = tmp_path / "profile.ini"

    def menu(language, dispatch, **options):
        calls.append(("menu", language, options.get("plain", False)))
        return dispatch(["config", "--config", str(path)])

    def configure(selected, target, language, **options):
        calls.append(("config", language, options.get("plain", False)))
        assert selected == path and target == "portable"
        assert options["dispatch"](["help", "setup"]) == 0
        return 17

    monkeypatch.setattr(wizard, "menu", menu)
    monkeypatch.setattr(wizard, "configure", configure)

    assert cli.main(["--lang", "ru", *(["--plain"] if plain else [])]) == 17

    assert calls == [("menu", "ru", plain), ("config", "ru", plain)]
