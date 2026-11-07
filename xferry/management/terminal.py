"""Optional terminal presentation for interactive management journeys.

Importing this module does not import or initialize either terminal library.
Operations provide fixed progress identifiers; presentation never observes secrets.
"""

from __future__ import annotations

import os
import re
import sys
import time
from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from prompt_toolkit.formatted_text import StyleAndTextTuples
    from prompt_toolkit.key_binding import KeyBindings
    from prompt_toolkit.key_binding.key_processor import KeyPressEvent
    from prompt_toolkit.layout.containers import AnyContainer
    from prompt_toolkit.styles import Style
    from rich.console import Console

    from .progress import ProgressEvent, ProgressObserver


class Back(Exception):
    """Return to the preceding question without discarding the draft."""


@dataclass(frozen=True)
class Choice:
    value: str
    label: str
    description: str = ""
    shortcut: str | None = None


_ESCAPE = re.compile(r"\x1b(?:\][^\x07\x1b]*(?:\x07|\x1b\\)|\[[0-?]*[ -/]*[@-~]|[@-_])")
_STAGE_LABELS = {
    "preflight": ("Checking the system and network", "Проверка системы и сети"),
    "download": ("Downloading the runtime or image", "Загрузка runtime или образа"),
    "verify": ("Verifying the signed runtime", "Проверка подписанного runtime"),
    "install": ("Installing the runtime", "Установка runtime"),
    "prepare": ("Preparing files and configuration", "Подготовка файлов и конфигурации"),
    "start": ("Starting the server", "Запуск сервера"),
    "wait_ready": ("Waiting for HTTPS and server readiness", "Ожидание HTTPS и готовности сервера"),
    "validate_config": ("Checking the configuration", "Проверка конфигурации"),
    "apply_config": ("Applying configuration changes", "Применение настроек"),
    "restart": ("Restarting the server", "Перезапуск сервера"),
    "restore": ("Restoring the previous configuration", "Восстановление прежней конфигурации"),
}


def _safe(value: str) -> str:
    """Keep literal content while removing terminal control sequences."""
    value = _ESCAPE.sub("", value)
    return "".join(char for char in value if char.isprintable() or char in "\n\t")


def _interactive_available() -> bool:
    return bool(sys.stdin.isatty() and sys.stdout.isatty() and os.environ.get("TERM", "") != "dumb")


class TerminalUI:
    def __init__(self, language: str = "en", *, plain: bool = False) -> None:
        self.language = language
        self.enhanced = not plain and _interactive_available()
        self._console_instance: Console | None = None

    def _text(self, english: str, russian: str) -> str:
        return russian if self.language == "ru" else english

    @property
    def _console(self) -> Console:
        if self._console_instance is None:
            from rich.console import Console

            self._console_instance = Console(
                file=sys.stdout,
                no_color="NO_COLOR" in os.environ,
                highlight=False,
                markup=False,
                emoji=False,
            )
        return self._console_instance

    def _style(self) -> Style:
        from prompt_toolkit.styles import Style

        colored = "NO_COLOR" not in os.environ
        return Style.from_dict(
            {
                "title": "bold ansigreen" if colored else "bold",
                "selected": "bold ansigreen" if colored else "bold reverse",
                "hint": "ansicyan" if colored else "",
                "error": "ansired" if colored else "bold",
            }
        )

    def _keys(self, allow_back: bool) -> KeyBindings:
        from prompt_toolkit.key_binding import KeyBindings

        keys = KeyBindings()

        @keys.add("c-c", eager=True)
        def cancel(event: KeyPressEvent) -> None:
            event.app.exit(exception=KeyboardInterrupt())

        @keys.add("c-d", eager=True)
        def eof(event: KeyPressEvent) -> None:
            event.app.exit(exception=EOFError())

        if allow_back:

            @keys.add("escape", eager=True)
            def back(event: KeyPressEvent) -> None:
                event.app.exit(exception=Back())

        return keys

    def _key_hint(self, allow_back: bool, *, select: bool = False) -> str:
        if select:
            hint = self._text("Up/Down choose | Enter continue", "Вверх/Вниз выбор | Enter далее")
        else:
            hint = self._text("Enter continue", "Enter далее")
        if allow_back:
            hint += self._text(" | Esc back", " | Esc назад")
        return hint + self._text(" | Ctrl+C cancel", " | Ctrl+C отмена")

    def select(
        self,
        title: str,
        choices: Sequence[Choice],
        default: str | None = None,
        *,
        allow_back: bool = True,
        searchable: bool = False,
    ) -> str:
        if not choices:
            raise ValueError("at least one choice is required")
        if not self.enhanced:
            return self._plain_select(title, choices, default, allow_back=allow_back)

        from prompt_toolkit.application import Application, get_app
        from prompt_toolkit.buffer import Buffer
        from prompt_toolkit.data_structures import Point
        from prompt_toolkit.layout import HSplit, Layout, ScrollOffsets, VSplit, Window
        from prompt_toolkit.layout.controls import BufferControl, FormattedTextControl
        from prompt_toolkit.layout.dimension import Dimension
        from prompt_toolkit.utils import get_cwidth

        selected = next((i for i, item in enumerate(choices) if item.value == default), 0)
        query = Buffer(multiline=False)

        def filtered() -> list[Choice]:
            needle = query.text.casefold()
            return [
                item
                for item in choices
                if needle in f"{item.label} {item.description} {item.value}".casefold()
            ]

        def changed(_: Buffer) -> None:
            nonlocal selected
            selected = 0

        query.on_text_changed += changed

        shortcuts: dict[str, int] = {}
        if not searchable:
            for index, item in enumerate(choices):
                if item.shortcut is not None:
                    if (
                        len(item.shortcut) != 1
                        or not item.shortcut.isprintable()
                        or item.shortcut.isspace()
                        or item.shortcut in shortcuts
                    ):
                        raise ValueError("choice shortcuts must be unique printable characters")
                    shortcuts[item.shortcut] = index

        key_hint = self._key_hint(allow_back, select=True)
        if shortcuts:
            key_hint = self._text("Key selects | ", "Клавиша выбирает | ") + key_hint

        def line_count(text: str, columns: int) -> int:
            return sum(
                max(1, (get_cwidth(line) + columns - 1) // columns) for line in text.split("\n")
            )

        def dimensions() -> tuple[int, int, int, int]:
            size = get_app().output.get_size()
            rows, columns = max(4, size.rows), max(1, size.columns)
            title_limit = 3 if rows >= 16 else 2 if rows >= 8 else 1
            title_height = min(title_limit, line_count(_safe(title), columns))
            hint_height = min(2 if rows >= 8 else 1, line_count(key_hint, columns))
            items = filtered()
            description_text = items[selected].description if items else ""
            description_limit = 3 if rows >= 16 else 1 if rows >= 10 else 0
            description_height = (
                min(description_limit, line_count(_safe(description_text), columns))
                if description_text
                else 0
            )
            # Keep one row for the overflow indicator and one for the shell cursor.
            available = rows - title_height - hint_height - description_height - 2
            if searchable:
                available -= 1
            return title_height, hint_height, description_height, max(1, available)

        def options() -> StyleAndTextTuples:
            items = filtered()
            if not items:
                return [("class:hint", self._text("No matches", "Нет совпадений"))]
            fragments: StyleAndTextTuples = []
            for index, item in enumerate(items):
                active = index == selected
                label = _safe(item.label).replace("\n", " ")
                shortcut = f"[{item.shortcut}] " if item.shortcut in shortcuts else ""
                ending = "\n" if index + 1 < len(items) else ""
                fragments.append(
                    (
                        "class:selected" if active else "",
                        f"{'>' if active else ' '} {shortcut}{label}{ending}",
                    )
                )
            return fragments

        def description() -> StyleAndTextTuples:
            items = filtered()
            text = items[selected].description if items else ""
            return [("class:hint", _safe(text))]

        keys = self._keys(allow_back)

        @keys.add("up", eager=True)
        def up(event: KeyPressEvent) -> None:
            nonlocal selected
            selected = (selected - 1) % max(1, len(filtered()))

        @keys.add("down", eager=True)
        def down(event: KeyPressEvent) -> None:
            nonlocal selected
            selected = (selected + 1) % max(1, len(filtered()))

        @keys.add("enter", eager=True)
        def accept(event: KeyPressEvent) -> None:
            items = filtered()
            if items:
                event.app.exit(result=items[selected].value)

        def bind_shortcut(key: str, index: int) -> None:
            @keys.add(key, eager=True)
            def choose(event: KeyPressEvent) -> None:
                nonlocal selected
                selected = index

        for shortcut, index in shortcuts.items():
            bind_shortcut(shortcut, index)

        @keys.add("pageup", eager=True)
        def page_up(event: KeyPressEvent) -> None:
            nonlocal selected
            selected = max(0, selected - dimensions()[3])

        @keys.add("pagedown", eager=True)
        def page_down(event: KeyPressEvent) -> None:
            nonlocal selected
            selected = max(0, min(len(filtered()) - 1, selected + dimensions()[3]))

        if not searchable:

            @keys.add("home", eager=True)
            def first(event: KeyPressEvent) -> None:
                nonlocal selected
                selected = 0

            @keys.add("end", eager=True)
            def last(event: KeyPressEvent) -> None:
                nonlocal selected
                selected = max(0, len(filtered()) - 1)

        menu = Window(
            FormattedTextControl(
                options,
                focusable=True,
                show_cursor=False,
                get_cursor_position=lambda: Point(x=0, y=selected),
            ),
            height=lambda: Dimension(
                min=1, preferred=min(len(filtered()) or 1, dimensions()[3]), max=dimensions()[3]
            ),
            dont_extend_height=True,
            wrap_lines=True,
            scroll_offsets=ScrollOffsets(top=0, bottom=0),
        )

        def overflow() -> StyleAndTextTuples:
            items = filtered()
            if not items:
                return []
            info = menu.render_info
            visible = info.displayed_lines if info is not None else []
            cues = []
            if visible and min(visible) > 0:
                cues.append(self._text("More above", "Ещё выше"))
            if visible and max(visible) < len(items) - 1:
                cues.append(self._text("More below", "Ещё ниже"))
            suffix = " | " + " / ".join(cues) if cues else ""
            return [("class:hint", f"{selected + 1}/{len(items)}{suffix}")]

        body: list[AnyContainer] = [
            Window(
                FormattedTextControl([("class:title", _safe(title))]),
                height=lambda: dimensions()[0],
                wrap_lines=True,
            ),
            menu,
            Window(FormattedTextControl(overflow), height=1, wrap_lines=True),
            Window(
                FormattedTextControl(description),
                height=lambda: dimensions()[2],
                wrap_lines=True,
            ),
        ]
        focused: Any = menu
        if searchable:
            search = Window(BufferControl(query), height=1)
            body.append(
                VSplit(
                    [
                        Window(
                            FormattedTextControl(self._text("Search: ", "Поиск: ")),
                            width=8,
                            height=1,
                        ),
                        search,
                    ],
                    height=1,
                )
            )
            focused = search
        body.append(
            Window(
                FormattedTextControl([("class:hint", key_hint)]),
                height=lambda: dimensions()[1],
                wrap_lines=True,
            )
        )
        app: Application[str] = Application(
            layout=Layout(HSplit(body), focused_element=focused),
            key_bindings=keys,
            style=self._style(),
            full_screen=False,
            erase_when_done=True,
        )
        app.ttimeoutlen = 0.1
        result = app.run()
        label = next(item.label for item in choices if item.value == result)
        self.message(f"{title}: {label}")
        return result

    def _plain_select(
        self, title: str, choices: Sequence[Choice], default: str | None, *, allow_back: bool
    ) -> str:
        print(_safe(title))
        for index, item in enumerate(choices, 1):
            print(f"  {index}. {_safe(item.label)}")
            if item.description:
                print(f"     {_safe(item.description)}")
        if allow_back:
            print(self._text("  0. Back", "  0. Назад"))
        default_index = next(
            (str(i) for i, item in enumerate(choices, 1) if item.value == default), "1"
        )
        while True:
            value = (
                input(f"{self._text('Choice', 'Выбор')} [{default_index}]: ").strip()
                or default_index
            )
            if allow_back and value == "0":
                raise Back()
            if value.isdigit() and 1 <= int(value) <= len(choices):
                return choices[int(value) - 1].value
            self.message(
                self._text("Choose a listed number.", "Выберите номер из списка."), kind="error"
            )

    def text(
        self,
        title: str,
        default: str = "",
        *,
        hint: str = "",
        validator: Callable[[str], str | None] | None = None,
        path: bool = False,
        secret: bool = False,
        allow_back: bool = True,
    ) -> str:
        if not self.enhanced:
            if hint:
                self.message(hint)
            while True:
                label = (
                    _safe(title) + (f" [{_safe(default)}]" if default and not secret else "") + ": "
                )
                if secret:
                    from getpass import getpass

                    value = getpass(label)
                else:
                    value = input(label)
                value = value.strip() or default
                error = validator(value) if validator else None
                if error is None:
                    return value
                self.message(error, kind="error")

        from prompt_toolkit import PromptSession
        from prompt_toolkit.completion import PathCompleter
        from prompt_toolkit.validation import Validator

        field_validator: Validator | None = None
        if validator is not None:
            from prompt_toolkit.document import Document
            from prompt_toolkit.validation import ValidationError

            validate_value = validator

            class FieldValidator(Validator):
                def validate(self, document: Document) -> None:
                    error = validate_value(document.text.strip() or default)
                    if error is not None:
                        raise ValidationError(
                            cursor_position=len(document.text), message=_safe(error)
                        )

            field_validator = FieldValidator()
        session: PromptSession[str] = PromptSession(
            style=self._style(),
            key_bindings=self._keys(allow_back),
            completer=PathCompleter(expanduser=True) if path else None,
            validator=field_validator,
            is_password=secret,
            reserve_space_for_menu=3 if path else 0,
        )
        session.app.ttimeoutlen = 0.1
        if hint:
            self.message(hint)
        placeholder: StyleAndTextTuples | None = None
        if default and not secret:
            placeholder = [
                (
                    "class:hint",
                    _safe(default)
                    + self._text(" (Enter keeps current)", " (Enter оставляет текущее)"),
                )
            ]
        value = session.prompt(
            [
                ("class:hint", self._key_hint(allow_back) + "\n"),
                ("class:title", _safe(title) + ": "),
            ],
            placeholder=placeholder,
        )
        return value.strip() or default

    def confirm(self, title: str, default: bool = False) -> bool:
        return (
            self.select(
                title,
                [Choice("yes", self._text("Yes", "Да")), Choice("no", self._text("No", "Нет"))],
                "yes" if default else "no",
            )
            == "yes"
        )

    def panel(self, title: str, rows: Sequence[tuple[str, str]], *, subtitle: str = "") -> None:
        if not self.enhanced:
            print(_safe(title))
            for label, value in rows:
                print(f"{_safe(label)}: {_safe(value)}")
            if subtitle:
                print(_safe(subtitle))
            return
        from rich.panel import Panel
        from rich.table import Table
        from rich.text import Text

        table = Table.grid(padding=(0, 2), expand=False)
        table.add_column(style="cyan", no_wrap=False)
        table.add_column(overflow="fold")
        for label, value in rows:
            table.add_row(Text(_safe(label)), Text(_safe(value)))
        self._console.print(
            Panel(
                table,
                title=Text(_safe(title)),
                subtitle=Text(_safe(subtitle)),
                border_style="green",
            )
        )

    def message(self, text: str, *, kind: str = "info") -> None:
        if not self.enhanced:
            print(_safe(text))
            return
        from rich.text import Text

        style = {"error": "red", "success": "green", "warning": "yellow"}.get(kind, "")
        self._console.print(Text(_safe(text), style=style))

    @contextmanager
    def _plain_progress(self) -> Iterator[ProgressObserver]:
        """Print bounded stage transitions without terminal controls or background work."""
        if not (sys.stdin.isatty() and sys.stdout.isatty()):
            yield lambda event: None
            return
        active: list[tuple[str, float]] = []
        usable = True

        def observe(event: ProgressEvent) -> None:
            nonlocal usable
            if not usable or event.stage not in _STAGE_LABELS:
                return
            label = _STAGE_LABELS[event.stage][self.language == "ru"]
            if event.state == "running":
                active.append((event.stage, time.monotonic()))
                line = f"{self._text('Running', 'Выполняется')}: {label}"
            else:
                index = next(
                    (i for i in range(len(active) - 1, -1, -1) if active[i][0] == event.stage),
                    None,
                )
                if index is None:
                    return
                _, started = active.pop(index)
                elapsed = time.monotonic() - started
                status = (
                    self._text("Done", "Готово")
                    if event.state == "done"
                    else self._text("Failed", "Ошибка")
                )
                line = f"{status}: {label} ({elapsed:.1f}s)"
            try:
                print(line, flush=True)
            except Exception:
                usable = False

        try:
            yield observe
        finally:
            from .progress import ProgressEvent

            for stage, _started in tuple(reversed(active)):
                observe(ProgressEvent(stage, "failed"))

    @contextmanager
    def progress(self) -> Iterator[ProgressObserver]:
        if not self.enhanced:
            with self._plain_progress() as observer:
                yield observer
            return
        from rich.live import Live
        from rich.spinner import Spinner
        from rich.table import Table
        from rich.text import Text

        rows: list[dict[str, Any]] = []

        def render() -> Table:
            table = Table.grid(padding=(0, 1))
            for row in rows:
                status = row["state"]
                indicator: Any = row["spinner"]
                if status != "running":
                    indicator = Text(
                        self._text("OK", "Готово")
                        if status == "done"
                        else self._text("Failed", "Ошибка"),
                        style="green" if status == "done" else "red",
                    )
                elapsed = (row.get("end") or time.monotonic()) - row["start"]
                table.add_row(indicator, Text(row["label"]), Text(f"{elapsed:.1f}s"))
            return table

        live: Live | None = None
        usable = True
        try:
            live = Live(
                get_renderable=render,
                console=self._console,
                refresh_per_second=8,
                redirect_stdout=False,
                redirect_stderr=False,
            )
            live.start(refresh=True)
        except Exception:
            usable = False

        def observe(event: ProgressEvent) -> None:
            nonlocal usable
            if not usable or live is None or event.stage not in _STAGE_LABELS:
                return
            try:
                if event.state == "running":
                    labels = _STAGE_LABELS[event.stage]
                    rows.append(
                        {
                            "stage": event.stage,
                            "label": labels[self.language == "ru"],
                            "state": "running",
                            "start": time.monotonic(),
                            "spinner": Spinner("dots", style="cyan"),
                        }
                    )
                else:
                    row = next(
                        (
                            row
                            for row in reversed(rows)
                            if row["stage"] == event.stage and row["state"] == "running"
                        ),
                        None,
                    )
                    if row is not None:
                        row.update(state=event.state, end=time.monotonic())
                live.refresh()
            except Exception:
                usable = False
                with suppress(Exception):
                    live.stop()

        try:
            yield observe
        finally:
            for row in rows:
                if row["state"] == "running":
                    row.update(state="failed", end=time.monotonic())
            if live is not None:
                with suppress(Exception):
                    live.stop()
            with suppress(Exception):
                self._console.show_cursor(True)


def get_ui(language: str = "en", *, plain: bool = False) -> TerminalUI:
    return TerminalUI(language, plain=plain)
