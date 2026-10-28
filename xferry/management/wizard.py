"""Small terminal journeys built on the same configuration and deployment APIs."""

from __future__ import annotations

import argparse
import json
import os
from collections.abc import Callable
from pathlib import Path

from xferry.settings import SettingsError

from .configuration import (
    change_configuration,
    default_files_dir,
    describe_settings,
    edit_ini,
    reset_portable_password,
    resolve_with_origins,
    state_for_config,
)


def _text(language: str, english: str, russian: str) -> str:
    return russian if language == "ru" else english


def prompt(label: str, default: str = "") -> str:
    value = input(f"{label}{f' [{default}]' if default else ''}: ").strip()
    return value or default


def confirm(language: str, description: str = "") -> bool:
    if description:
        print(description)
    answer = input(_text(language, "Apply these changes? [y/N] ", "Применить изменения? [y/N] "))
    return answer.strip().casefold() in {"y", "yes", "д", "да"}


def prepare_setup(args: argparse.Namespace, language: str) -> bool:
    """Ask only essential inputs; validation still belongs to setup planning."""
    print(_text(language, "Set up the server on this host.", "Настройка сервера на этой машине."))
    if not args.files_dir:
        args.files_dir = str(
            Path(
                prompt(
                    _text(language, "Files folder on this host", "Папка файлов на этой машине"),
                    str(default_files_dir(managed=True)),
                )
            )
            .expanduser()
            .resolve()
        )
    print(
        _text(
            language,
            "Existing files will be available for downloading; uploads are saved in this folder.",
            "Существующие файлы доступны для скачивания; новые загрузки сохранятся в этой папке.",
        )
    )
    print(
        _text(
            language,
            "1. Public HTTPS, automatic address\n2. Public HTTPS, own domain\n3. Private access",
            "1. Публичный HTTPS, автоматический адрес\n"
            "2. Публичный HTTPS, свой домен\n3. Приватный доступ",
        )
    )
    choice = prompt(_text(language, "Access", "Доступ"), "1")
    if choice == "2":
        args.domain = prompt(_text(language, "Domain", "Домен"))
        if not args.domain:
            raise SettingsError("a domain is required")
    elif choice == "3":
        args.private = True
    elif choice != "1":
        raise SettingsError("choose 1, 2 or 3")
    return True


def menu(language: str, dispatch: Callable[[list[str]], int]) -> int:
    from .instances import discover_instances, foreground_config

    installed = bool(discover_instances())
    first = (
        _text(language, "Start installed server", "Запустить установленный сервер")
        if installed
        else _text(language, "Set up a server", "Установить сервер")
    )
    print(_text(language, "XFerry — server on this host", "XFerry — сервер на этой машине"))
    print(f"1. {first}")
    print(
        _text(
            language,
            "2. Run once\n3. Settings\n4. Status\n5. Help\n0. Exit",
            "2. Запустить разово\n3. Настройки\n4. Состояние\n5. Справка\n0. Выход",
        )
    )
    try:
        choice = prompt(_text(language, "Action", "Действие"), "1" if installed else "2")
        if choice == "0":
            return 0
        if choice == "1":
            if installed:
                return dispatch(["start"])
            print(_text(language, "1. Linux service\n2. Docker", "1. Служба Linux\n2. Docker"))
            mode = prompt(_text(language, "Run as", "Способ запуска"), "1")
            if mode not in {"1", "2"}:
                raise SettingsError("choose 1 or 2")
            return dispatch(["setup", *(["--docker"] if mode == "2" else [])])
        if choice == "2":
            saved = foreground_config()
            return dispatch(["run", *(["--config", str(saved)] if saved.is_file() else [])])
        if choice == "3":
            return dispatch(["config"])
        if choice == "4":
            return dispatch(["status"])
        if choice == "5":
            return dispatch(["help"])
        raise SettingsError("unknown menu action")
    except (EOFError, KeyboardInterrupt):
        print(_text(language, "Cancelled.", "Отменено."))
        return 0


def _edit_setting(
    changes: dict[str, str], rows: list[dict[str, object]], name: str, language: str
) -> None:
    row = next(row for row in rows if row["name"] == name)
    print(row["description"])
    print(_text(language, "Example", "Пример") + f": {row['example']}")
    print(_text(language, "Allowed values", "Допустимые значения") + f": {row['constraints']}")
    raw = row["value"]
    if isinstance(raw, list):
        current = (", " if name == "plugin_allowlist" else " ").join(str(item) for item in raw)
    else:
        current = str(raw) if raw is not None else ""
    current = changes.get(name, current)
    value = prompt(_text(language, "New value (- clears)", "Новое значение (- очистить)"), current)
    if value == "-":
        value = ""
    if name == "files_dir" and value:
        value = str(Path(value).expanduser().resolve())
    changes[name] = value


def _tls_changes(changes: dict[str, str], language: str, target: str = "portable") -> None:
    print(
        _text(
            language,
            "1. Public HTTPS, automatic address\n2. Public HTTPS, own domain\n3. Private HTTP",
            "1. Публичный HTTPS, автоматический адрес\n"
            "2. Публичный HTTPS, свой домен\n3. Приватный HTTP",
        )
    )
    if target != "docker":
        print(
            _text(
                language,
                "4. HTTPS with certificate files\n5. Private self-signed HTTPS",
                "4. HTTPS с готовыми сертификатами\n"
                "5. Приватный HTTPS с самоподписанным сертификатом",
            )
        )
    choice = prompt(_text(language, "Access", "Доступ"), "1")
    selected = {
        "cert_file": "",
        "key_file": "",
        "domain": "",
        "public_ip": "",
        "allowed_hosts": "",
        "email": "",
        "acme_server": "",
        "acme_http_address": "",
    }
    if choice in {"1", "2", "4"}:
        selected.update(
            access="public",
            # explicit public access selection.
            host="0.0.0.0",  # nosec B104
            port="8443",
        )
    elif choice in {"3", "5"}:
        selected.update(
            access="lab" if target == "docker" else "private",
            # Private Docker binds inside the container and publishes on host loopback.
            host="0.0.0.0" if target == "docker" else "127.0.0.1",  # nosec B104
            port="8080",
        )
    else:
        raise SettingsError("choose one of the listed access modes")
    if choice == "1":
        selected["https_mode"] = "auto"
        selected["acme_http_port"] = "8080" if target == "docker" else "80"
        address = prompt(
            _text(
                language, "Public IPv4 (Enter: automatic)", "Публичный IPv4 (Enter: автоматически)"
            )
        )
        if address:
            selected["public_ip"] = address
        elif target in {"managed", "docker"}:
            from xferry.security.tls import resolve_public_ipv4

            selected["public_ip"] = resolve_public_ipv4()
    elif choice == "2":
        domain = prompt(_text(language, "Domain", "Домен"))
        if not domain:
            raise SettingsError("a domain is required")
        selected.update(
            https_mode="domain",
            domain=domain,
            allowed_hosts=domain,
            acme_http_port="8080" if target == "docker" else "80",
        )
    elif choice == "3":
        selected.update(https_mode="off", acme_http_port="80", allowed_hosts="127.0.0.1 localhost")
    elif choice == "4" and target != "docker":
        selected.update(https_mode="files", acme_http_port="80")
        selected["cert_file"] = str(Path(prompt("Certificate file")).expanduser().resolve())
        selected["key_file"] = str(Path(prompt("Private key file")).expanduser().resolve())
        selected["allowed_hosts"] = prompt(
            _text(language, "Certificate hostnames", "Имена хостов сертификата")
        )
    elif choice == "5" and target != "docker":
        selected.update(https_mode="self-signed", acme_http_port="80")
    else:
        raise SettingsError("choose one of the listed access modes")
    changes.update(selected)


def _advanced(changes: dict[str, str], rows: list[dict[str, object]], language: str) -> None:
    groups = list(dict.fromkeys(str(row["group"]) for row in rows))
    print(_text(language, "Choose a settings group:", "Выберите группу настроек:"))
    for index, group in enumerate(groups, 1):
        print(f"{index}. {group}")
    answer = prompt(_text(language, "Group number (Enter: back)", "Номер группы (Enter: назад)"))
    if not answer:
        return
    if not answer.isdigit() or not 1 <= int(answer) <= len(groups):
        raise SettingsError("choose a listed group number")
    matching = [row for row in rows if row["group"] == groups[int(answer) - 1]]
    for index, row in enumerate(matching, 1):
        print(f"{index}. {row['name']} = {row['value']}\n   {row['description']}")
    answer = prompt(
        _text(language, "Setting number (Enter: back)", "Номер параметра (Enter: назад)")
    )
    if not answer:
        return
    if not answer.isdigit() or not 1 <= int(answer) <= len(matching):
        raise SettingsError("choose a listed setting number")
    name = str(matching[int(answer) - 1]["name"])
    if name == "auth_file":
        print(
            _text(
                language,
                "Use Password to generate credentials.",
                "Используйте пункт «Пароль» для генерации учётных данных.",
            )
        )
        return
    _edit_setting(changes, rows, name, language)


def configure(
    path: Path,
    target: str,
    language: str,
    *,
    dispatch: Callable[[list[str]], int] | None = None,
) -> int:
    text = path.read_text(encoding="utf-8") if path.exists() else ""
    # Initial portable setup explicitly selects stable directories; old run and
    # explicit legacy configuration retain their original root/uploads layout.
    changes: dict[str, str] = {}
    if not text:
        if target == "managed":
            raise SettingsError("no managed configuration exists; run xferry setup first")
        changes = {
            "access": "private",
            "files_dir": str(default_files_dir()),
        }
    last_valid = edit_ini(text, changes)
    try:
        while True:
            environment = dict(os.environ) if target == "portable" else {}
            draft_error = None
            try:
                candidate = edit_ini(text, changes)
                rows = describe_settings(
                    candidate,
                    env=environment,
                    all_settings=True,
                    config_path=path,
                    state_dir=state_for_config(path, target),
                )
                settings, _origins = resolve_with_origins(
                    candidate,
                    env=environment,
                    config_path=path,
                    state_dir=state_for_config(path, target),
                )
                last_valid = candidate
            except ValueError as error:
                draft_error = str(error)
                print(
                    _text(language, "Draft needs correction: ", "Нужно исправить: ") + draft_error
                )
                rows = describe_settings(
                    last_valid,
                    env=environment,
                    all_settings=True,
                    config_path=path,
                    state_dir=state_for_config(path, target),
                )
                settings, _origins = resolve_with_origins(
                    last_valid,
                    env=environment,
                    config_path=path,
                    state_dir=state_for_config(path, target),
                )
                for row in rows:
                    name = str(row["name"])
                    if name in changes:
                        row["value"] = changes[name]
                        row["source"] = "draft"
            posture = settings.runtime_posture()
            visible_folder = changes.get("files_dir", posture.uploads_path)
            if target == "managed" and "files_dir" not in changes:
                from .managed_files import managed_files_path
                from .model import ManagedLayout

                visible_folder = str(managed_files_path(ManagedLayout()))
            elif target == "docker" and "files_dir" not in changes:
                document = json.loads(
                    (path.parent / ".xferry-deployment.json").read_text(encoding="utf-8")
                )
                visible_folder = str(document["files_dir"])
            for row in rows:
                if row["name"] == "files_dir":
                    row["value"] = visible_folder
            preview_url = posture.effective_url
            if target == "docker":
                if settings.access == "public":
                    hostname = settings.domain
                    if not hostname and settings.public_ip:
                        from xferry.security.tls import sslip_domain_for_ip

                        hostname = sslip_domain_for_ip(settings.public_ip)
                    preview_url = (
                        f"https://{hostname}" if hostname else "Automatic public HTTPS address"
                    )
                else:
                    preview_url = "http://127.0.0.1:8080"
            print(f"\nURL: {preview_url}\nHTTPS: {posture.tls_mode}\nAuth: {posture.auth_mode}")
            print(_text(language, "Files folder", "Папка файлов") + f": {visible_folder}")
            print(
                _text(
                    language,
                    "1. Files folder\n2. HTTP request size limit\n3. Total storage limit\n"
                    "4. Free space reserve\n5. Encrypted uploads\n6. HTTPS\n"
                    "7. Advanced settings\n8. Password\n9. Save and apply\n0. Cancel",
                    "1. Папка файлов\n2. Максимальный размер HTTP-запроса\n3. Общая квота\n"
                    "4. Резерв места\n5. Зашифрованные передачи\n6. HTTPS\n"
                    "7. Все настройки\n8. Пароль\n9. Сохранить и применить\n0. Отмена",
                )
            )
            choice = prompt(_text(language, "Action", "Действие"), "9")
            basic = {
                "1": "files_dir",
                "2": "max_size_mb",
                "3": "upload_storage_limit_mb",
                "4": "upload_reserve_free_mb",
                "5": "encrypted_uploads",
            }
            if choice == "0":
                return 0
            if choice in basic:
                _edit_setting(changes, rows, basic[choice], language)
            elif choice in {"6", "7"}:
                try:
                    if choice == "6":
                        _tls_changes(changes, language, target)
                    else:
                        _advanced(changes, rows, language)
                except ValueError as error:
                    print(error)
            elif choice == "8":
                if changes and target != "portable":
                    print(
                        _text(
                            language,
                            "Save or cancel pending settings before resetting credentials.",
                            "Сначала сохраните или отмените изменения настроек.",
                        )
                    )
                    continue
                if not confirm(
                    language,
                    _text(
                        language,
                        "Generate a 12-character password and save pending settings? "
                        "A running installed server will restart.",
                        "Сгенерировать пароль из 12 символов и сохранить настройки? "
                        "Работающий установленный сервер перезапустится.",
                    ),
                ):
                    continue
                if target == "managed" and dispatch is not None:
                    return dispatch(["credentials", "reset"])
                if target == "docker":
                    from .docker_deploy import deploy_docker

                    password_result = deploy_docker(path.parent, reset_credentials=True)
                elif target == "portable":
                    try:
                        portable_password_result = reset_portable_password(path, changes=changes)
                    except ValueError as error:
                        print(error)
                        continue
                    print(portable_password_result.message)
                    if (
                        portable_password_result.exit_code == 0
                        and portable_password_result.password
                    ):
                        print(
                            f"Credentials: {portable_password_result.username}:"
                            f"{portable_password_result.password}"
                        )
                    return portable_password_result.exit_code
                else:
                    raise SettingsError("managed password changes require the management CLI")
                print(password_result.message)
                if password_result.exit_code == 0 and password_result.password:
                    print(f"Credentials: {password_result.username}:{password_result.password}")
                return password_result.exit_code
            elif choice == "9":
                if draft_error:
                    print(
                        _text(
                            language,
                            "Correct the draft before saving.",
                            "Исправьте настройки перед сохранением.",
                        )
                    )
                    continue
                if target == "docker":
                    from .docker_deploy import default_files_directory, deploy_docker

                    folder = changes.pop("files_dir", None)
                    if not confirm(
                        language,
                        json.dumps(changes, ensure_ascii=False, indent=2)
                        + (f"\nFiles: {folder}" if folder else ""),
                    ):
                        return 0
                    docker_result = deploy_docker(
                        path.parent,
                        files_dir=(Path(folder) if folder else default_files_directory())
                        if folder is not None
                        else None,
                        settings_changes=changes,
                    )
                    print(docker_result.message)
                    if docker_result.exit_code == 0 and docker_result.url:
                        print(f"URL: {docker_result.url}\nFiles: {docker_result.files_dir}")
                    return docker_result.exit_code
                try:
                    result = change_configuration(
                        path,
                        changes,
                        target=target,
                        apply=target == "managed",
                        confirm=lambda diff: confirm(language, diff),
                    )
                except SettingsError as error:
                    print(error)
                    continue
                print(result.message)
                return result.exit_code
    except (EOFError, KeyboardInterrupt):
        print(_text(language, "Cancelled; no changes made.", "Отменено; изменения не сохранены."))
        return 0


def docker_wizard(output: Path, language: str, *, dry_run: bool = False) -> int:
    from .docker_deploy import default_files_directory, deploy_docker

    files = (
        Path(
            prompt(
                _text(language, "Files folder on this host", "Папка файлов на этой машине"),
                str(default_files_directory()),
            )
        )
        .expanduser()
        .resolve()
    )
    print(
        _text(
            language,
            "1. Automatic HTTPS address\n2. Own domain\n3. Private access",
            "1. Автоматический адрес HTTPS\n2. Свой домен\n3. Приватный доступ",
        )
    )
    choice = prompt(_text(language, "Access", "Доступ"), "1")
    if choice not in {"1", "2", "3"}:
        raise SettingsError("choose 1, 2 or 3")
    domain = prompt(_text(language, "Domain", "Домен")) if choice == "2" else None
    if choice == "2" and not domain:
        raise SettingsError("a domain is required")
    summary = f"Docker\nFiles: {files}\nConfiguration: {output}\nAccess: {domain or choice}"
    if not dry_run and not confirm(language, summary):
        return 0
    result = deploy_docker(
        output, files_dir=files, domain=domain, private=choice == "3", dry_run=dry_run
    )
    print(result.message)
    if result.exit_code == 0:
        if result.url:
            print(f"URL: {result.url}")
        print(_text(language, "Files folder", "Папка файлов") + f": {result.files_dir}")
        if result.password:
            print(f"Credentials: {result.username}:{result.password}")
    return result.exit_code
