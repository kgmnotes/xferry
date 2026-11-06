"""Keyboard-driven operator journeys over the existing management application."""

from __future__ import annotations

import argparse
import math
import os
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import TYPE_CHECKING, cast

from xferry.settings import SettingsError, load_settings_text
from xferry.settings_schema import SETTING_SPEC_BY_NAME

from .configuration import (
    change_configuration,
    configuration_diff,
    default_files_dir,
    describe_settings,
    edit_ini,
    reset_portable_password,
    resolve_with_origins,
    state_for_config,
)
from .terminal import Back, Choice, TerminalUI, get_ui

if TYPE_CHECKING:
    from .deployment import OperationResult
    from .instances import Instance

_PATH_FIELDS = frozenset({"files_dir", "state_dir", "cert_file", "key_file"})


def _t(language: str, english: str, russian: str) -> str:
    return russian if language == "ru" else english


def _folder_error(value: str, language: str = "en") -> str | None:
    if not value.strip():
        return _t(language, "Choose a files folder.", "Выберите папку файлов.")
    try:
        candidate = Path(value).expanduser()
        if candidate.exists() and not candidate.is_dir():
            return _t(language, "Choose a directory, not a file.", "Выберите папку, а не файл.")
        candidate.resolve()
    except (OSError, ValueError, RuntimeError):
        return _t(language, "This folder path cannot be used.", "Этот путь к папке недоступен.")
    return None


def _domain_error(value: str, language: str = "en") -> str | None:
    from xferry.security.tls import normalize_domain

    if not value.strip():
        return _t(language, "A domain is required.", "Укажите домен.")
    try:
        normalize_domain(value)
    except ValueError as error:
        return str(error)
    return None


def _ip_error(value: str) -> str | None:
    from xferry.security.tls import validate_public_ipv4

    if not value.strip():
        return None
    try:
        validate_public_ipv4(value)
    except ValueError as error:
        return str(error)
    return None


def prepare_setup(
    args: argparse.Namespace,
    language: str,
    *,
    ui: TerminalUI | None = None,
    edit: bool = False,
) -> bool:
    """Collect a reversible setup draft; backend preflight remains authoritative."""
    terminal = ui or get_ui(language)
    original_explicit = frozenset(getattr(args, "explicit_options", ()))
    explicit = frozenset() if edit else original_explicit
    steps = [
        name
        for name in ("backend", "files_dir", "access")
        if f"--{name.replace('_', '-')}" not in explicit
    ]
    if "--domain" in explicit or "--public-ip" in explicit:
        steps = [step for step in steps if step != "access"]
    mode = (
        "domain"
        if getattr(args, "domain", None)
        else "private"
        if getattr(args, "access", None) == "private"
        else "auto"
    )
    index = 0
    try:
        while True:
            detail = "domain" if mode == "domain" else "public_ip" if mode == "auto" else None
            current_steps = [*steps]
            if (
                detail
                and (detail != "public_ip" or edit)
                and (edit or f"--{detail.replace('_', '-')}" not in explicit)
                and "access" in steps
            ):
                current_steps.append(detail)
            if index >= len(current_steps):
                return True
            step = current_steps[index]
            title = _t(
                language,
                f"Set up server · {index + 1}/{len(current_steps)}",
                f"Установка сервера · {index + 1}/{len(current_steps)}",
            )
            terminal.panel(
                title,
                [],
                subtitle=_t(
                    language,
                    "Answers remain editable until you confirm the installation.",
                    "Ответы можно изменить до подтверждения установки.",
                ),
            )
            try:
                if step == "backend":
                    previous_default = getattr(args, "_wizard_files_dir_default", None)
                    args.backend = terminal.select(
                        _t(language, "Run as", "Способ запуска"),
                        [
                            Choice(
                                "native",
                                _t(language, "Linux service", "Служба Linux"),
                                "systemd",
                                shortcut="1",
                            ),
                            Choice(
                                "docker",
                                "Docker",
                                _t(
                                    language,
                                    "Docker Engine and Compose required",
                                    "Нужны Docker Engine и Compose",
                                ),
                                shortcut="2",
                            ),
                        ],
                        default=getattr(args, "backend", None) or "native",
                    )
                    if (
                        previous_default is not None
                        and getattr(args, "files_dir", None) == previous_default
                    ):
                        args.files_dir = str(default_files_dir(managed=args.backend != "docker"))
                        args._wizard_files_dir_default = args.files_dir
                elif step == "files_dir":
                    automatic_folder = str(default_files_dir(managed=args.backend != "docker"))
                    value = terminal.text(
                        _t(language, "Files folder on this host", "Папка файлов на этой машине"),
                        getattr(args, "files_dir", None) or automatic_folder,
                        hint=_t(
                            language,
                            "Existing files are shared; uploads and deletion use this folder.",
                            "Существующие файлы доступны для скачивания; "
                            "загрузка и удаление используют эту папку.",
                        ),
                        validator=lambda value: _folder_error(value, language),
                        path=True,
                    )
                    args.files_dir = str(Path(value).expanduser().resolve())
                    args._wizard_files_dir_default = (
                        args.files_dir
                        if args.files_dir == automatic_folder
                        and "--files-dir" not in original_explicit
                        else None
                    )
                elif step == "access":
                    mode = terminal.select(
                        _t(language, "Access and HTTPS", "Доступ и HTTPS"),
                        [
                            Choice(
                                "auto",
                                _t(
                                    language,
                                    "Public HTTPS, automatic address",
                                    "Публичный HTTPS, автоматический адрес",
                                ),
                                _t(
                                    language,
                                    "Trusted TLS and Basic Auth; no domain needed",
                                    "Доверенный TLS и Basic Auth; свой домен не нужен",
                                ),
                                shortcut="1",
                            ),
                            Choice(
                                "domain",
                                _t(
                                    language,
                                    "Public HTTPS, own domain",
                                    "Публичный HTTPS, свой домен",
                                ),
                                shortcut="2",
                            ),
                            Choice(
                                "private",
                                _t(language, "Private access", "Приватный доступ"),
                                "127.0.0.1",
                                shortcut="3",
                            ),
                        ],
                        default=mode,
                    )
                    args.access = "private" if mode == "private" else "public"
                    if mode != "domain":
                        args.domain = None
                    if mode != "auto":
                        args.public_ip = None
                elif step == "domain":
                    from xferry.security.tls import normalize_domain

                    args.domain = normalize_domain(
                        terminal.text(
                            _t(language, "Domain", "Домен"),
                            getattr(args, "domain", None) or "",
                            hint=_t(
                                language,
                                "DNS must point at this server; TCP 80 and 443 must be reachable.",
                                "DNS должен указывать на сервер; "
                                "TCP 80 и 443 должны быть доступны.",
                            ),
                            validator=lambda value: _domain_error(value, language),
                        )
                    )
                elif step == "public_ip":
                    args.public_ip = (
                        terminal.text(
                            _t(language, "Public IPv4", "Публичный IPv4"),
                            getattr(args, "public_ip", None) or "",
                            hint=_t(
                                language,
                                "Leave empty to detect automatically. "
                                "TCP 80 and 443 must be reachable.",
                                "Оставьте пустым для автоопределения. "
                                "TCP 80 и 443 должны быть доступны.",
                            ),
                            validator=_ip_error,
                        )
                        or None
                    )
                index += 1
            except Back:
                if index:
                    index -= 1
                else:
                    return False
    except (EOFError, KeyboardInterrupt):
        terminal.message(_t(language, "Cancelled; no changes made.", "Отменено; изменений нет."))
        return False


def review_setup(
    args: argparse.Namespace,
    preview: object,
    language: str,
    *,
    ui: TerminalUI | None = None,
) -> str:
    terminal = ui or get_ui(language)
    result = cast("OperationResult", preview)
    public = getattr(args, "access", None) != "private"
    host = getattr(args, "domain", None) or getattr(args, "public_ip", None)
    rows = [
        (_t(language, "Run as", "Способ запуска"), str(args.backend)),
        (
            _t(language, "Files folder", "Папка файлов"),
            str(
                getattr(args, "files_dir", None)
                or result.details.get(
                    "files_dir", default_files_dir(managed=args.backend != "docker")
                )
            ),
        ),
        (
            _t(language, "Address", "Адрес"),
            result.url
            or str(
                host or _t(language, "Automatic sslip.io address", "Автоматический адрес sslip.io")
            )
            if public
            else "127.0.0.1",
        ),
        (
            "HTTPS",
            _t(language, "Trusted TLS on port 443", "Доверенный TLS, порт 443")
            if public
            else _t(language, "Private HTTP", "Приватный HTTP"),
        ),
        (
            _t(language, "Authentication", "Аутентификация"),
            _t(language, "Generated Basic Auth credentials", "Сгенерированные данные Basic Auth")
            if public
            else _t(language, "Private access", "Приватный доступ"),
        ),
    ]
    if result.plan:
        rows.extend((str(index), step) for index, step in enumerate(result.plan.steps, 1))
    terminal.panel(_t(language, "Review installation", "Проверка установки"), rows)
    if result.exit_code:
        terminal.message(result.message, kind="error")
    choices = (
        []
        if result.exit_code
        else [Choice("apply", _t(language, "Install", "Установить"), shortcut="1")]
    )
    choices += [
        Choice("edit", _t(language, "Edit answers", "Изменить ответы"), shortcut="2"),
        Choice("cancel", _t(language, "Cancel", "Отмена"), shortcut="0"),
    ]
    try:
        return terminal.select(
            _t(language, "Next action", "Следующее действие"),
            choices,
            default="edit" if result.exit_code else "apply",
        )
    except Back:
        return "edit"
    except (EOFError, KeyboardInterrupt):
        return "cancel"


def render_result(ui: TerminalUI, result: OperationResult, *, files_dir: str | None = None) -> int:
    """Render only sanitized result fields, with credentials explicitly returned once."""
    language = ui.language
    rows: list[tuple[str, str]] = [(_t(language, "Result", "Результат"), result.message)]
    for name, labels in (
        ("code", ("Code", "Код")),
        ("detail", ("Details", "Подробности")),
    ):
        value = result.details.get(name)
        if isinstance(value, str) and value:
            rows.append((_t(language, *labels), value))
    if result.state is not None:
        rows.append((_t(language, "State", "Состояние"), result.state.state))
    url = result.url or (result.credentials.url if result.credentials else None)
    if url:
        rows.append(("URL", url))
    folder = files_dir or result.details.get("files_dir")
    if folder:
        rows.append((_t(language, "Files folder", "Папка файлов"), str(folder)))
    instance_id = result.details.get("instance_id")
    if instance_id:
        rows.append((_t(language, "Deployment ID", "ID установки"), str(instance_id)))
    if result.credentials is not None:
        rows += [
            (_t(language, "Username", "Имя пользователя"), result.credentials.username),
            (_t(language, "Password", "Пароль"), result.credentials.password),
        ]
    actions = result.details.get("next_actions", ())
    if isinstance(actions, Sequence) and not isinstance(actions, str):
        rows.extend((_t(language, "Next action", "Далее"), str(action)) for action in actions)
    ui.panel(
        _t(language, "Complete", "Готово")
        if not result.exit_code
        else _t(language, "Operation failed", "Ошибка операции"),
        rows,
    )
    if result.credentials:
        ui.message(
            _t(
                language,
                "Save these credentials. Open the URL to upload and download files.",
                "Сохраните данные входа. Откройте URL для загрузки и скачивания файлов.",
            )
        )
    return result.exit_code


def menu(
    language: str, dispatch: Callable[[list[str]], int], *, ui: TerminalUI | None = None
) -> int:
    from .application import default_application
    from .instances import discover_instances, foreground_config

    terminal = ui or get_ui(language)
    selected_id: str | None = None
    try:
        while True:
            found = discover_instances()
            selected = next((item for item in found if item.id == selected_id), None)
            if selected is None and len(found) == 1:
                selected = found[0]
            state = default_application().observe(selected).state if selected else "absent"
            rows: list[tuple[str, str]] = [(_t(language, "State", "Состояние"), state)]
            if selected:
                rows += [
                    (_t(language, "Server", "Сервер"), selected.id),
                    (_t(language, "Run as", "Способ запуска"), selected.backend),
                ]
            elif len(found) > 1:
                rows = [(_t(language, "Servers", "Серверы"), str(len(found)))]
            terminal.panel("xferry", rows)
            labels = {
                "absent": ("Set up a server", "Установить сервер"),
                "running": ("Manage running server", "Настроить работающий сервер"),
                "stopped": ("Start installed server", "Запустить установленный сервер"),
                "incomplete": ("Recover installation", "Восстановить установку"),
                "retained": (
                    "Reinstall with retained data",
                    "Переустановить с сохранёнными данными",
                ),
                "broken": ("Diagnose installation", "Диагностика установки"),
            }
            primary = (
                _t(language, "Manage installed server", "Управлять установленным сервером")
                if len(found) > 1 and selected is None
                else _t(language, *labels[state])
            )
            choices = [Choice("primary", primary, shortcut="1")]
            if len(found) > 1:
                choices.insert(
                    0,
                    Choice("server", _t(language, "Choose server", "Выбрать сервер"), shortcut="6"),
                )
            choices += [
                Choice("run", _t(language, "Run once", "Запустить разово"), shortcut="2"),
                Choice("config", _t(language, "Settings", "Настройки"), shortcut="3"),
                Choice("status", _t(language, "Status", "Состояние"), shortcut="4"),
                Choice("help", _t(language, "Help", "Справка"), shortcut="5"),
                Choice("exit", _t(language, "Exit", "Выход"), shortcut="0"),
            ]
            try:
                try:
                    action = terminal.select(
                        _t(language, "Action", "Действие"),
                        choices,
                        default="server" if len(found) > 1 and selected is None else "primary",
                    )
                except Back:
                    return 0
                if action == "exit":
                    return 0
                if action == "server" or (
                    selected is None
                    and len(found) > 1
                    and action in {"primary", "config", "status"}
                ):
                    selected_id = terminal.select(
                        _t(language, "Choose server", "Выберите сервер"),
                        [
                            Choice(item.id, item.id, f"{item.backend} · {item.config}")
                            for item in found
                        ],
                        searchable=True,
                    )
                    if action == "server":
                        continue
                    selected = next(item for item in found if item.id == selected_id)
                    state = default_application().observe(selected).state
                selection = ["--instance", selected.id] if selected else []
                if action == "primary":
                    if state in {"retained", "incomplete"} and selected:
                        command = ["setup", "--backend", selected.backend, *selection]
                    else:
                        command = [
                            {"running": "config", "stopped": "start", "broken": "doctor"}.get(
                                state, "setup"
                            ),
                            *selection,
                        ]
                elif action == "run":
                    saved = foreground_config()
                    command = ["run", *(["--config", str(saved)] if saved.is_file() else [])]
                else:
                    command = [action, *selection]
                dispatch(command)
            except Back:
                continue
    except (EOFError, KeyboardInterrupt):
        terminal.message(_t(language, "Cancelled.", "Отменено."))
        return 0


def _scalar_error(name: str, value: str, language: str = "en") -> str | None:
    if "\n" in value or "\r" in value or "\x00" in value:
        return _t(
            language,
            "Values must occupy one INI line.",
            "Значение должно занимать одну строку INI.",
        )
    try:
        spec = SETTING_SPEC_BY_NAME[name]
        settings = load_settings_text(
            edit_ini("[server]\nconfig_version = 1\n", {name: value}), validate=False
        )
        scalar = getattr(settings, name)
        if spec.value_kind in {"integer", "optional_integer", "number"} and scalar is not None:
            if isinstance(scalar, float) and not math.isfinite(scalar):
                return _t(language, "Enter a finite value.", "Введите конечное число.")
            if spec.cli and spec.cli.minimum is not None and scalar < spec.cli.minimum:
                return f"Minimum: {spec.cli.minimum}"
            if spec.cli and spec.cli.maximum is not None and scalar > spec.cli.maximum:
                return f"Maximum: {spec.cli.maximum}"
        if name == "files_dir" and value:
            return _folder_error(value, language)
    except (OSError, ValueError) as error:
        return str(error)
    return None


def _format(value: object, name: str = "") -> str:
    if value is None:
        return ""
    if isinstance(value, list):
        return (", " if name == "plugin_allowlist" else " ").join(str(item) for item in value)
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def _edit_setting(
    ui: TerminalUI, row: Mapping[str, object], changes: dict[str, str], target: str
) -> None:
    language = ui.language
    name = str(row["name"])
    spec = SETTING_SPEC_BY_NAME[name]
    if name == "auth_file" or spec.redaction == "secret":
        ui.message(
            _t(
                language,
                "Use Password to generate credentials.",
                "Используйте пункт «Пароль» для генерации данных входа.",
            )
        )
        return
    if name == "config_version" or (name == "state_dir" and target != "portable"):
        ui.message(
            _t(
                language,
                "Managed automatically by this deployment.",
                "Управляется установкой автоматически.",
            )
        )
        return
    current = changes.get(name, _format(row["value"], name))
    ui.panel(
        name,
        [
            (_t(language, "Description", "Описание"), str(row["description"])),
            (_t(language, "Allowed values", "Допустимые значения"), str(row["constraints"])),
            (_t(language, "Example", "Пример"), str(row["example"])),
        ],
    )
    if spec.value_kind == "boolean":
        value = ui.select(
            name,
            [
                Choice("true", _t(language, "Enabled", "Включено")),
                Choice("false", _t(language, "Disabled", "Выключено")),
            ],
            default="true" if current.lower() in {"true", "1", "yes", "on"} else "false",
        )
    elif spec.value_kind == "choice" and spec.cli:
        value = ui.select(
            name, [Choice(value, value) for value in spec.cli.choices], default=current
        )
    else:
        value = ui.text(
            name,
            current,
            hint=_t(
                language,
                "Enter a new value; '-' clears an optional value.",
                "Введите значение; '-' очищает необязательный параметр.",
            ),
            path=name in _PATH_FIELDS,
            validator=lambda value: _scalar_error(name, "" if value == "-" else value, language),
        )
        value = "" if value == "-" else value
    if name in _PATH_FIELDS and value:
        value = str(Path(value).expanduser().resolve())
    changes[name] = value


def _advanced(
    ui: TerminalUI,
    rows: list[dict[str, object]],
    changes: dict[str, str],
    target: str,
    *,
    search: bool = False,
) -> None:
    language = ui.language
    groups = list(dict.fromkeys(str(row["group"]) for row in rows))
    selected_group: str | None = None
    selected_name: str | None = None
    while True:
        if search:
            matching = rows
        else:
            group = ui.select(
                _t(language, "Settings group", "Группа настроек"),
                [Choice(name, name) for name in groups],
                default=selected_group,
            )
            if group != selected_group:
                selected_name = None
            selected_group = group
            matching = [row for row in rows if row["group"] == group]
        while True:
            try:
                name = ui.select(
                    _t(language, "Find a setting", "Найти параметр")
                    if search
                    else _t(language, "Setting", "Параметр"),
                    [
                        Choice(
                            str(row["name"]),
                            f"{row['name']} = {_format(row['value'], str(row['name']))}",
                            str(row["description"]),
                        )
                        for row in matching
                    ],
                    default=selected_name,
                    searchable=True,
                )
            except Back:
                if search:
                    raise
                break
            selected_name = name
            try:
                _edit_setting(
                    ui, next(row for row in matching if row["name"] == name), changes, target
                )
            except Back:
                continue
            return


def _tls(ui: TerminalUI, changes: dict[str, str], target: str) -> None:
    language = ui.language
    modes = [
        Choice(
            "auto",
            _t(
                language, "Public HTTPS, automatic address", "Публичный HTTPS, автоматический адрес"
            ),
            shortcut="1",
        ),
        Choice(
            "domain",
            _t(language, "Public HTTPS, own domain", "Публичный HTTPS, свой домен"),
            shortcut="2",
        ),
        Choice("off", _t(language, "Private HTTP", "Приватный HTTP"), shortcut="3"),
    ]
    if target != "docker":
        modes += [
            Choice(
                "files",
                _t(language, "HTTPS with certificate files", "HTTPS с готовыми сертификатами"),
                shortcut="4",
            ),
            Choice(
                "self-signed",
                _t(
                    language,
                    "Private self-signed HTTPS",
                    "Приватный HTTPS с самоподписанным сертификатом",
                ),
                shortcut="5",
            ),
        ]
    mode = ui.select(
        _t(language, "Access and HTTPS", "Доступ и HTTPS"),
        modes,
        default=changes.get("https_mode", "auto"),
    )
    selected = dict.fromkeys(
        (
            "cert_file",
            "key_file",
            "domain",
            "public_ip",
            "allowed_hosts",
            "email",
            "acme_server",
            "acme_http_address",
        ),
        "",
    )
    public = mode in {"auto", "domain", "files"}
    selected.update(
        access="public" if public else "private",
        # The operator explicitly selected the public preset above.
        host="0.0.0.0" if public else "127.0.0.1",  # nosec B104
        port="443" if public else "8080",
        https_mode=mode,
        acme_http_port="80",
    )  # nosec B104
    if mode == "auto":
        address = ui.text(
            _t(language, "Public IPv4", "Публичный IPv4"),
            changes.get("public_ip", ""),
            hint=_t(
                language,
                "Leave empty to detect automatically.",
                "Оставьте пустым для автоопределения.",
            ),
            validator=_ip_error,
        )
        if not address and target != "portable":
            from xferry.security.tls import resolve_public_ipv4

            from .progress import ProgressEvent

            with ui.progress() as observer:
                observer(ProgressEvent("preflight", "running"))
                try:
                    address = resolve_public_ipv4()
                except BaseException:
                    observer(ProgressEvent("preflight", "failed"))
                    raise
                observer(ProgressEvent("preflight", "done"))
        selected["public_ip"] = address
    elif mode == "domain":
        from xferry.security.tls import normalize_domain

        selected["domain"] = normalize_domain(
            ui.text(
                _t(language, "Domain", "Домен"), changes.get("domain", ""), validator=_domain_error
            )
        )
        selected["allowed_hosts"] = selected["domain"]
    elif mode == "files":
        selected["cert_file"] = str(
            Path(
                ui.text(
                    _t(language, "Certificate file", "Файл сертификата"),
                    changes.get("cert_file", ""),
                    path=True,
                )
            )
            .expanduser()
            .resolve()
        )
        selected["key_file"] = str(
            Path(
                ui.text(
                    _t(language, "Private key file", "Файл закрытого ключа"),
                    changes.get("key_file", ""),
                    path=True,
                )
            )
            .expanduser()
            .resolve()
        )
        selected["allowed_hosts"] = ui.text(
            _t(language, "Certificate hostnames", "Имена хостов сертификата"),
            changes.get("allowed_hosts", ""),
        )
    elif mode == "off":
        selected["allowed_hosts"] = "127.0.0.1 localhost"
    changes.update(selected)


def configure(
    path: Path,
    target: str,
    language: str,
    *,
    instance: Instance | None = None,
    ui: TerminalUI | None = None,
) -> int:
    """Edit a draft in memory, validate it, then apply via the canonical API."""
    terminal = ui or get_ui(language)
    before = path.read_text(encoding="utf-8") if path.exists() else ""
    if not before and target == "managed":
        raise SettingsError("no managed configuration exists; run xferry setup first")
    changes: dict[str, str] = (
        {} if before else {"access": "private", "files_dir": str(default_files_dir())}
    )
    last_valid = edit_ini(before, changes)
    applying = False
    basic = {
        "files_dir": ("Files folder", "Папка файлов"),
        "max_size_mb": ("HTTP request size limit", "Максимальный размер HTTP-запроса"),
        "upload_storage_limit_mb": ("Total storage limit", "Общая квота"),
        "upload_reserve_free_mb": ("Free space reserve", "Резерв места"),
        "encrypted_uploads": ("Encrypted uploads", "Зашифрованные передачи"),
    }
    last_action = "files_dir"
    try:
        while True:
            environment = dict(os.environ) if target == "portable" else {}
            error = None
            try:
                candidate = edit_ini(before, changes)
                settings, _ = resolve_with_origins(
                    candidate,
                    env=environment,
                    config_path=path,
                    state_dir=state_for_config(path, target),
                )
                settings.to_server_config()
                rows = describe_settings(
                    candidate,
                    env=environment,
                    all_settings=True,
                    config_path=path,
                    state_dir=state_for_config(path, target),
                )
                last_valid = candidate
            except ValueError as failure:
                error = str(failure)
                candidate = last_valid
                settings, _ = resolve_with_origins(
                    last_valid,
                    env=environment,
                    config_path=path,
                    state_dir=state_for_config(path, target),
                )
                rows = describe_settings(
                    last_valid,
                    env=environment,
                    all_settings=True,
                    config_path=path,
                    state_dir=state_for_config(path, target),
                )
                for row in rows:
                    if str(row["name"]) in changes:
                        row["value"] = changes[str(row["name"])]
            if instance:
                from .cli import _annotate_deployment_rows

                _annotate_deployment_rows(rows, instance)
            posture = settings.runtime_posture()
            summary = [
                ("URL", posture.effective_url),
                ("HTTPS", posture.tls_mode),
                (_t(language, "Authentication", "Аутентификация"), posture.auth_mode),
                (
                    _t(language, "Files folder", "Папка файлов"),
                    changes.get("files_dir") or posture.uploads_path,
                ),
                (_t(language, "Pending changes", "Несохранённые изменения"), str(len(changes))),
            ]
            if changes:
                summary.append(
                    (_t(language, "Changed fields", "Изменённые параметры"), ", ".join(changes))
                )
            terminal.panel(_t(language, "Server settings", "Настройки сервера"), summary)
            if error:
                terminal.message(error, kind="error")
            choices = [
                Choice(
                    name,
                    _t(language, *labels),
                    _format(next(row["value"] for row in rows if row["name"] == name), name),
                    shortcut=str(shortcut),
                )
                for shortcut, (name, labels) in enumerate(basic.items(), 1)
            ]
            choices += [
                Choice("tls", "HTTPS", shortcut="6"),
                Choice(
                    "advanced",
                    _t(language, "Settings by group", "Настройки по группам"),
                    shortcut="7",
                ),
                Choice(
                    "search",
                    _t(language, "Search all settings", "Поиск всех настроек"),
                    shortcut="/",
                ),
                Choice("password", _t(language, "Password", "Пароль"), shortcut="8"),
                Choice(
                    "save", _t(language, "Review and apply", "Проверить и применить"), shortcut="9"
                ),
                Choice("cancel", _t(language, "Cancel", "Отмена"), shortcut="0"),
            ]
            try:
                try:
                    action = terminal.select(
                        _t(language, "Change a setting", "Изменить настройку"),
                        choices,
                        default=last_action,
                    )
                except Back:
                    return 0
                last_action = action
                if action == "cancel":
                    return 0
                if action in basic:
                    _edit_setting(
                        terminal,
                        next(row for row in rows if row["name"] == action),
                        changes,
                        target,
                    )
                elif action == "tls":
                    _tls(terminal, changes, target)
                elif action in {"advanced", "search"}:
                    _advanced(terminal, rows, changes, target, search=action == "search")
                elif action == "password":
                    if changes and target != "portable":
                        terminal.message(
                            _t(
                                language,
                                "Save or cancel pending settings before resetting credentials.",
                                "Сначала сохраните или отмените изменения настроек.",
                            )
                        )
                        continue
                    if not terminal.confirm(
                        _t(
                            language,
                            "Generate a password and save pending settings? "
                            "A running installed server will restart.",
                            "Сгенерировать пароль и сохранить настройки? "
                            "Работающий установленный сервер перезапустится.",
                        )
                    ):
                        continue
                    applying = True
                    if target == "portable":
                        result_password = reset_portable_password(path, changes=changes)
                        terminal.panel(
                            _t(language, "Credentials", "Данные входа"),
                            [
                                (_t(language, "Result", "Результат"), result_password.message),
                                (
                                    _t(language, "Username", "Имя пользователя"),
                                    result_password.username or "",
                                ),
                                (
                                    _t(language, "Password", "Пароль"),
                                    result_password.password or "",
                                ),
                            ],
                        )
                        return result_password.exit_code
                    from .application import default_application

                    app = default_application()
                    with terminal.progress() as observer:
                        previous = getattr(app, "progress", None)
                        app.progress = observer
                        try:
                            result = app.credentials(instance)
                        finally:
                            app.progress = previous
                    return render_result(terminal, result)
                elif action == "save":
                    if error:
                        terminal.message(
                            _t(
                                language,
                                "Correct the draft before saving.",
                                "Исправьте настройки перед сохранением.",
                            ),
                            kind="error",
                        )
                        continue
                    if target == "portable":
                        preview = change_configuration(path, changes, target=target, dry_run=True)
                        terminal.panel(
                            _t(language, "Review changes", "Проверка изменений"),
                            [("INI", preview.diff or _t(language, "No changes", "Нет изменений"))],
                        )
                        if not terminal.confirm(
                            _t(language, "Save this configuration?", "Сохранить настройки?")
                        ):
                            continue
                        applying = True
                        saved = change_configuration(path, changes, target=target)
                        terminal.message(
                            saved.message, kind="success" if not saved.exit_code else "error"
                        )
                        return saved.exit_code
                    from .application import default_application

                    app = default_application()
                    preview_result = app.configure(
                        instance, changes, apply=False, expected_text=before
                    )
                    terminal.panel(
                        _t(language, "Review changes", "Проверка изменений"),
                        [
                            ("INI", configuration_diff(before, candidate)),
                            (_t(language, "Result", "Результат"), preview_result.message),
                        ],
                    )
                    if preview_result.exit_code or not terminal.confirm(
                        _t(language, "Apply these changes?", "Применить изменения?")
                    ):
                        continue
                    applying = True
                    with terminal.progress() as observer:
                        previous = getattr(app, "progress", None)
                        app.progress = observer
                        try:
                            result = app.configure(
                                instance, changes, apply=True, expected_text=before
                            )
                        finally:
                            app.progress = previous
                    return render_result(terminal, result, files_dir=changes.get("files_dir"))
            except Back:
                continue
            except (OSError, ValueError) as failure:
                applying = False
                terminal.message(str(failure), kind="error")
    except (EOFError, KeyboardInterrupt):
        terminal.message(
            _t(
                language,
                "Operation interrupted. Check xferry status and xferry doctor before continuing.",
                "Операция прервана. Проверьте xferry status и xferry doctor перед продолжением.",
            )
            if applying
            else _t(language, "Cancelled; no changes made.", "Отменено; изменения не сохранены."),
            kind="error" if applying else "info",
        )
        return 130 if applying else 0
