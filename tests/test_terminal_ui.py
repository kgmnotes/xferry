"""Keyboard journeys and terminal presentation boundaries."""

from __future__ import annotations

import io
import json
import subprocess
import sys
import threading
from contextlib import contextmanager

import pytest

from xferry.management import terminal
from xferry.management.progress import ProgressEvent
from xferry.management.terminal import Back, Choice, TerminalUI


@contextmanager
def keyboard_ui(monkeypatch, keys, language="en", output=None):
    from prompt_toolkit.application import create_app_session
    from prompt_toolkit.input import create_pipe_input
    from prompt_toolkit.output import DummyOutput

    monkeypatch.setattr(terminal, "_interactive_available", lambda: True)
    with (
        create_pipe_input() as pipe,
        create_app_session(input=pipe, output=output or DummyOutput()),
    ):
        pipe.send_text(keys)
        yield TerminalUI(language)


def test_import_and_plain_output_do_not_initialize_terminal_libraries():
    source = (
        "import json,sys; from xferry.management.terminal import get_ui; "
        "get_ui(plain=True).panel('Server', [('Files', '/srv/share')]); "
        "print(json.dumps([n for n in sys.modules if n == 'rich' or n == 'prompt_toolkit']))"
    )
    result = subprocess.run(
        [sys.executable, "-c", source], check=True, capture_output=True, text=True
    )
    assert json.loads(result.stdout.splitlines()[-1]) == []
    assert "\x1b" not in result.stdout


@pytest.mark.parametrize(
    ("stdin_tty", "stdout_tty", "term", "plain", "expected"),
    [
        (True, True, "xterm-256color", False, True),
        (True, True, "dumb", False, False),
        (True, True, "xterm", True, False),
        (False, True, "xterm", False, False),
        (True, False, "xterm", False, False),
    ],
)
def test_terminal_capabilities(monkeypatch, stdin_tty, stdout_tty, term, plain, expected):
    monkeypatch.setattr(sys.stdin, "isatty", lambda: stdin_tty)
    monkeypatch.setattr(sys.stdout, "isatty", lambda: stdout_tty)
    monkeypatch.setenv("TERM", term)
    assert terminal.get_ui(plain=plain).enhanced is expected


def test_arrow_selection_retains_accepted_answer(monkeypatch, capsys):
    choices = [Choice("native", "Linux service"), Choice("docker", "Docker")]
    with keyboard_ui(monkeypatch, "\x1b[B\r") as ui:
        assert ui.select("Run as", choices, default="native") == "docker"
    assert "Run as: Docker" in capsys.readouterr().out


def test_search_filters_choices_by_description(monkeypatch):
    choices = [Choice("files", "Files folder"), Choice("quota", "Storage", "Total quota")]
    with keyboard_ui(monkeypatch, "quota\r") as ui:
        assert ui.select("Settings", choices, searchable=True) == "quota"


def test_search_can_recover_from_no_matches(monkeypatch):
    with keyboard_ui(monkeypatch, "wrong\r\x01\x0bfiles\r") as ui:
        assert ui.select("Setting", [Choice("files", "Files")], searchable=True) == "files"


@pytest.mark.parametrize("widget", ["select", "text"])
@pytest.mark.parametrize(("keys", "exception"), [("\x1b", Back), ("\x03", KeyboardInterrupt)])
def test_back_and_cancel_leave_widgets(monkeypatch, widget, keys, exception):
    with keyboard_ui(monkeypatch, keys) as ui, pytest.raises(exception):
        if widget == "select":
            ui.select("Action", [Choice("continue", "Continue")])
        else:
            ui.text("Folder", default="/srv/share")


def test_field_validation_keeps_user_in_field_until_valid(monkeypatch):
    checked = []

    def validate(value):
        checked.append(value)
        return None if value.isdigit() else "Enter a whole number."

    with keyboard_ui(monkeypatch, "bad\r\x01\x0b25\r") as ui:
        assert ui.text("Limit", validator=validate) == "25"
    assert "bad" in checked
    assert checked[-1] == "25"


@pytest.mark.parametrize(("keys", "expected"), [("25\r", "25"), ("\r", "100")])
def test_typing_replaces_current_number_and_enter_keeps_it(monkeypatch, keys, expected):
    checked = []

    def validate(value):
        checked.append(value)
        return None if value.isdigit() else "Enter a whole number."

    with keyboard_ui(monkeypatch, keys) as ui:
        assert ui.text("Limit", "100", validator=validate) == expected
    assert checked[-1] == expected


def test_empty_input_validates_effective_default_and_can_be_corrected(monkeypatch):
    checked = []

    def validate(value):
        checked.append(value)
        return None if value.isdigit() else "Enter a whole number."

    with keyboard_ui(monkeypatch, "\r25\r") as ui:
        assert ui.text("Limit", "invalid", validator=validate) == "25"
    assert "invalid" in checked
    assert checked[-1] == "25"


def test_typing_a_path_replaces_current_folder(monkeypatch):
    with keyboard_ui(monkeypatch, "/srv/new-share\r") as ui:
        assert ui.text("Files folder", "/var/lib/xferry/files", path=True) == "/srv/new-share"


@pytest.mark.parametrize(("keys", "expected"), [("2\r", "docker"), ("2\x1b[A\r", "native")])
def test_supplied_shortcut_selects_row_and_enter_activates(monkeypatch, keys, expected):
    choices = [
        Choice("native", "Linux service", shortcut="1"),
        Choice("docker", "Docker", shortcut="2"),
    ]
    with keyboard_ui(monkeypatch, keys) as ui:
        assert ui.select("Run as", choices) == expected


def test_numeric_search_is_not_intercepted_by_shortcut(monkeypatch):
    choices = [Choice("port", "Port 2", shortcut="1"), Choice("other", "Other", shortcut="2")]
    with keyboard_ui(monkeypatch, "2\r") as ui:
        assert ui.select("Find setting", choices, searchable=True) == "port"


def test_last_selected_row_and_overflow_cue_are_visible_in_short_terminal(monkeypatch):
    import prompt_toolkit.application
    from prompt_toolkit.application import create_app_session
    from prompt_toolkit.data_structures import Size
    from prompt_toolkit.input import create_pipe_input
    from prompt_toolkit.output import DummyOutput

    class ShortOutput(DummyOutput):
        def get_size(self):
            return Size(rows=10, columns=60)

    original_application = prompt_toolkit.application.Application
    snapshots = []
    next_keys = iter(("\x1b[F", "\r"))
    with create_pipe_input() as pipe, create_app_session(input=pipe, output=ShortOutput()):

        def application(*args, **kwargs):
            app = original_application(*args, **kwargs)

            def capture(rendered):
                screen = rendered.renderer.last_rendered_screen
                if screen is not None and not rendered.is_done:
                    snapshots.append(
                        [
                            "".join(screen.data_buffer[row][col].char for col in range(60))
                            for row in range(10)
                        ]
                    )
                    key = next(next_keys, None)
                    if key is not None:
                        pipe.send_text(key)

            app.after_render += capture
            return app

        monkeypatch.setattr(prompt_toolkit.application, "Application", application)
        monkeypatch.setattr(terminal, "_interactive_available", lambda: True)
        choices = [
            Choice(str(i), f"Setting {i}", "Description of the selected setting " * 3)
            for i in range(12)
        ]
        choices[-1] = Choice("11", "Setting 11", choices[-1].description, shortcut="9")
        assert TerminalUI().select("Settings for the selected server " * 3, choices) == "11"

    assert any(
        any("> [9] Setting 11" in line for line in frame)
        and any("More above" in line for line in frame)
        for frame in snapshots
    ), snapshots
    assert any(any("Key selects" in line for line in frame) for frame in snapshots)


def test_secret_input_is_not_echoed_in_history(monkeypatch, capsys):
    with keyboard_ui(monkeypatch, "not-a-real-password\r") as ui:
        assert ui.text("Password", secret=True) == "not-a-real-password"
    assert "not-a-real-password" not in capsys.readouterr().out


def test_secret_default_can_be_kept_without_displaying_it(monkeypatch, capsys):
    with keyboard_ui(monkeypatch, "\r") as ui:
        assert ui.text("Password", "not-a-real-password", secret=True) == "not-a-real-password"
    assert "not-a-real-password" not in capsys.readouterr().out


def test_plain_menu_retries_invalid_selection(monkeypatch, capsys):
    answers = iter(("invalid", "9", "2"))
    monkeypatch.setattr("builtins.input", lambda _: next(answers))
    ui = terminal.get_ui(plain=True)
    assert ui.select("Mode", [Choice("one", "One"), Choice("two", "Two")]) == "two"
    output = capsys.readouterr().out
    assert "Choose a listed number." in output
    assert "\x1b" not in output


def test_plain_field_retries_validation_and_preserves_default(monkeypatch):
    answers = iter(("bad", ""))
    monkeypatch.setattr("builtins.input", lambda _: next(answers))
    assert (
        terminal.get_ui(plain=True).text(
            "Limit", "25", validator=lambda value: None if value.isdigit() else "Invalid number"
        )
        == "25"
    )


def test_no_color_keeps_keyboard_navigation(monkeypatch, capsys):
    monkeypatch.setenv("NO_COLOR", "1")
    with keyboard_ui(monkeypatch, "\x1b[B\r") as ui:
        assert ui.enhanced
        assert ui.select("Action", [Choice("yes", "Yes"), Choice("no", "No")]) == "no"
        assert not ui._style().get_attrs_for_style_str("class:selected").color
    assert "\x1b[3" not in capsys.readouterr().out


def test_panels_render_user_content_literally_and_fit_narrow_terminal(monkeypatch):
    from rich.console import Console

    monkeypatch.setattr(terminal, "_interactive_available", lambda: True)
    output = io.StringIO()
    ui = TerminalUI()
    ui._console_instance = Console(file=output, width=50, color_system=None)
    ui.panel(
        "Server", [("Files", "[red]/srv/share[/red]\x1b[2J"), ("URL", "https://files.example.com")]
    )
    rendered = output.getvalue()
    assert "[red]/srv/share[/red]" in rendered
    assert "https://files.example.com" in rendered
    assert "\x1b" not in rendered
    assert all(len(line) <= 50 for line in rendered.splitlines())


def test_progress_tracks_nested_and_repeated_stages_without_claiming_success(monkeypatch):
    from rich.console import Console

    monkeypatch.setattr(terminal, "_interactive_available", lambda: True)
    output = io.StringIO()
    ui = TerminalUI()
    ui._console_instance = Console(file=output, width=100, color_system=None)
    current_thread = threading.current_thread()
    with ui.progress() as observe:
        assert threading.current_thread() is current_thread
        observe(ProgressEvent("apply_config", "running"))
        observe(ProgressEvent("restart", "running"))
        observe(ProgressEvent("restart", "done"))
        observe(ProgressEvent("apply_config", "failed"))
        observe(ProgressEvent("restore", "running"))
        observe(ProgressEvent("restore", "done"))
        observe(ProgressEvent("restart", "running"))
        observe(ProgressEvent("restart", "done"))
        observe(ProgressEvent("never-show-this-secret", "running"))
    rendered = output.getvalue()
    assert "Failed" in rendered
    assert "Applying configuration changes" in rendered
    assert rendered.count("Restarting the server") == 2
    assert "Restoring the previous configuration" in rendered
    assert "never-show-this-secret" not in rendered


def test_progress_restores_cursor_on_keyboard_interrupt(monkeypatch):
    from rich.console import Console

    monkeypatch.setattr(terminal, "_interactive_available", lambda: True)
    output = io.StringIO()
    ui = TerminalUI()
    ui._console_instance = Console(file=output, width=100, force_terminal=True)
    with pytest.raises(KeyboardInterrupt), ui.progress() as observe:
        observe(ProgressEvent("wait_ready", "running"))
        raise KeyboardInterrupt
    assert "\x1b[?25h" in output.getvalue()
    assert "Failed" in output.getvalue()


def test_progress_presentation_failure_does_not_abort_operation(monkeypatch):
    from rich.live import Live

    monkeypatch.setattr(terminal, "_interactive_available", lambda: True)
    calls = []

    def fail_refresh(self):
        raise OSError("terminal disconnected")

    monkeypatch.setattr(Live, "refresh", fail_refresh)
    with TerminalUI().progress() as observe:
        observe(ProgressEvent("prepare", "running"))
        calls.append("operation still runs")
    assert calls == ["operation still runs"]


def test_progress_initialization_failure_does_not_abort_operation(monkeypatch):
    from rich.live import Live

    monkeypatch.setattr(terminal, "_interactive_available", lambda: True)

    def fail_init(self, *args, **kwargs):
        raise OSError("terminal disconnected")

    monkeypatch.setattr(Live, "__init__", fail_init)
    completed = False
    with TerminalUI().progress() as observe:
        observe(ProgressEvent("start", "running"))
        completed = True
    assert completed


def test_plain_progress_does_not_change_redirected_output(capsys):
    with terminal.get_ui(plain=True).progress() as observe:
        observe(ProgressEvent("prepare", "running"))
        observe(ProgressEvent("prepare", "done"))
    assert capsys.readouterr().out == ""


def test_plain_progress_reports_nested_stages_and_elapsed_time_without_controls(
    monkeypatch, capsys
):
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True)
    monkeypatch.setenv("TERM", "dumb")
    now = [10.0]
    monkeypatch.setattr(terminal.time, "monotonic", lambda: now[0])
    with terminal.get_ui(plain=True).progress() as observe:
        observe(ProgressEvent("apply_config", "running"))
        observe(ProgressEvent("restart", "running"))
        now[0] = 12.5
        observe(ProgressEvent("restart", "done"))
        observe(ProgressEvent("apply_config", "failed"))
        observe(ProgressEvent("restart", "running"))
        now[0] = 13.0
        observe(ProgressEvent("restart", "done"))
        observe(ProgressEvent("never-show-this-secret", "running"))
    rendered = capsys.readouterr().out
    assert rendered.splitlines() == [
        "Running: Applying configuration changes",
        "Running: Restarting the server",
        "Done: Restarting the server (2.5s)",
        "Failed: Applying configuration changes (2.5s)",
        "Running: Restarting the server",
        "Done: Restarting the server (0.5s)",
    ]
    assert "\x1b" not in rendered


def test_plain_progress_marks_interrupted_stage_failed(monkeypatch, capsys):
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True)
    with pytest.raises(KeyboardInterrupt), terminal.get_ui(plain=True).progress() as observe:
        observe(ProgressEvent("wait_ready", "running"))
        raise KeyboardInterrupt
    rendered = capsys.readouterr().out
    assert "Running: Waiting for HTTPS and server readiness" in rendered
    assert "Failed: Waiting for HTTPS and server readiness" in rendered
    assert "Done:" not in rendered and "\x1b" not in rendered


def test_plain_progress_output_failure_does_not_abort_operation(monkeypatch):
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True)

    def disconnected(*_args, **_kwargs):
        raise OSError("terminal disconnected")

    monkeypatch.setattr("builtins.print", disconnected)
    completed = False
    with terminal.get_ui(plain=True).progress() as observe:
        observe(ProgressEvent("prepare", "running"))
        observe(ProgressEvent("prepare", "done"))
        completed = True
    assert completed
