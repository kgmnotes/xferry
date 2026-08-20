"""Small, dependency-free localization helpers for management commands."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from .versions import SUPPORTED_RELEASE_MAJOR


@dataclass(frozen=True)
class LanguageSelection:
    """The selected language and the source that selected it."""

    code: str
    source: str


_ENVIRONMENT_LANGUAGE_KEYS = ("XFERRY_LANG", "LC_ALL", "LC_MESSAGES", "LANGUAGE", "LANG")

_MESSAGES: dict[str, dict[str, str]] = {
    "en": {
        "root_description": "Manage an installed XFerry service or run the server with xferry run.",
        "commands_heading": "Management commands:",
        "maintenance_heading": "Optional maintenance:",
        "examples_heading": "Examples:",
        "root_examples": (
            "  xferry run --preset local\n"
            "  sudo xferry setup\n"
            "  sudo xferry status\n"
            "  xferry examples"
        ),
        "all_examples": (
            "  xferry run --preset local\n"
            "  sudo xferry setup\n"
            "  sudo xferry status\n"
            "  xferry logs\n"
            "  sudo xferry start\n"
            "  sudo xferry stop\n"
            "  sudo xferry restart\n"
            "  sudo xferry doctor\n"
            "  sudo xferry credentials reset\n"
            "  xferry examples\n"
            "  sudo xferry uninstall"
        ),
        "command_example": "Example: {example}",
        "not_implemented": "The '{command}' command is not implemented yet.",
        "help_command": "Show this help or help for one management command.",
        "help_option": "Show this help and exit.",
        "examples_command": "Print copy-paste management command examples.",
        "command_run": "Run the XFerry server.",
        "command_setup": "Install and configure the managed XFerry service.",
        "command_status": "Show the managed service status.",
        "command_logs": "Show managed service logs.",
        "command_start": "Start the managed service.",
        "command_stop": "Stop the managed service.",
        "command_restart": "Restart the managed service.",
        "command_doctor": "Check the managed installation.",
        "command_credentials": "Manage service credentials.",
        "command_update": "Optionally update a long-lived installation from the verified channel.",
        "command_rollback": "Restore a verified release on a long-lived installation.",
        "command_uninstall": "Remove the managed installation safely.",
        "command_examples": "Print copy-paste management command examples.",
        "service_status_text": (
            "Installation: {installation}; configuration: {config}; enabled: {enabled}; "
            "service: {service}; health: {health}"
        ),
        "service_action_done": "Managed service {action} completed.",
        "service_action_failed": "Managed service {action} failed.",
        "doctor_check_text": "Doctor {name}: {status} ({detail})",
        "operation_failure": "Management operation failed.",
        "purge_prompt": (
            "Permanently delete XFerry config, data, credentials, and ACME state? [y/N] "
        ),
        "usage_error": "usage error",
    },
    "ru": {
        "root_description": (
            "Управляйте установленной службой XFerry или запускайте сервер через xferry run."
        ),
        "commands_heading": "Команды управления:",
        "maintenance_heading": "Необязательное обслуживание:",
        "examples_heading": "Примеры:",
        "root_examples": (
            "  xferry run --preset local\n"
            "  sudo xferry setup\n"
            "  sudo xferry status\n"
            "  xferry examples"
        ),
        "all_examples": (
            "  xferry run --preset local\n"
            "  sudo xferry setup\n"
            "  sudo xferry status\n"
            "  xferry logs\n"
            "  sudo xferry start\n"
            "  sudo xferry stop\n"
            "  sudo xferry restart\n"
            "  sudo xferry doctor\n"
            "  sudo xferry credentials reset\n"
            "  xferry examples\n"
            "  sudo xferry uninstall"
        ),
        "command_example": "Пример: {example}",
        "not_implemented": "Команда '{command}' пока не реализована.",
        "help_command": "Показать эту справку или справку по команде управления.",
        "help_option": "Показать эту справку и выйти.",
        "examples_command": "Показать готовые к копированию примеры команд управления.",
        "command_run": "Запустить сервер XFerry.",
        "command_setup": "Установить и настроить управляемую службу XFerry.",
        "command_status": "Показать состояние управляемой службы.",
        "command_logs": "Показать журналы управляемой службы.",
        "command_start": "Запустить управляемую службу.",
        "command_stop": "Остановить управляемую службу.",
        "command_restart": "Перезапустить управляемую службу.",
        "command_doctor": "Проверить управляемую установку.",
        "command_credentials": "Управлять учётными данными службы.",
        "command_update": (
            "При необходимости обновить долгоживущую установку из проверенного канала."
        ),
        "command_rollback": "Восстановить проверенный выпуск долгоживущей установки.",
        "command_uninstall": "Безопасно удалить управляемую установку.",
        "command_examples": "Показать готовые к копированию примеры команд управления.",
        "service_status_text": (
            "Установка: {installation}; конфигурация: {config}; включена: {enabled}; "
            "служба: {service}; здоровье: {health}"
        ),
        "service_action_done": "Операция службы {action} выполнена.",
        "service_action_failed": "Операция службы {action} не выполнена.",
        "doctor_check_text": "Проверка {name}: {status} ({detail})",
        "operation_failure": "Операция управления не выполнена.",
        "purge_prompt": (
            "Безвозвратно удалить настройки, данные, учётные данные и состояние ACME XFerry? [y/N] "
        ),
        "usage_error": "ошибка использования",
    },
}

_RELEASE_TEXT: dict[str, dict[str, str]] = {
    "en": {
        "update_complete": "XFerry {version} was verified and activated.",
        "update_dry_run": "XFerry {version} passed update verification; no managed state changed.",
        "rollback_complete": "XFerry rolled back to verified release {version}.",
        "rollback_dry_run": (
            "XFerry {version} passed rollback verification; no managed state changed."
        ),
        "uninstall_complete": (
            "XFerry runtime files were removed; config, data, and ACME state were preserved."
        ),
        "uninstall_dry_run": "Uninstall dry run completed; no managed state changed.",
        "purge_complete": "XFerry runtime, config, data, credentials, and ACME state were removed.",
        "purge_confirmation_required": "Data purge requires explicit confirmation or --yes.",
        "release_requires_root": "This release operation requires root.",
        "invalid_release_version": "The release version is invalid.",
        "release_platform_unsupported": "The release platform does not match this host.",
        "release_download_failed": "The release download failed.",
        "release_manifest_invalid": "The release manifest is invalid.",
        "release_manifest_mismatch": "The release manifest does not match the requested version.",
        "release_integrity_failed": "The release size or checksum verification failed.",
        "candidate_config_invalid": "The candidate cannot load the managed configuration.",
        "candidate_restart_failed": (
            "The candidate service failed to restart; the previous release was restored."
        ),
        "candidate_unhealthy": (
            "The candidate service was unhealthy; the previous release was restored."
        ),
        "candidate_state_restore_failed": (
            "The candidate could not restore the prior stopped state; "
            "the previous release was restored."
        ),
        "restore_incomplete": "The release operation failed and restoration is incomplete.",
        "rollback_target_unverified": (
            "The requested rollback target is not a verified installed release."
        ),
        "release_operation_locked": "Another managed operation is in progress.",
        "release_lock_unsafe": "The managed operation lock is unsafe.",
        "unsupported_release_major": (
            "XFerry maintenance accepts only {supported_major}.x releases; {version} "
            "requires a separately approved release line."
        ),
        "unsupported_managed_state": (
            "Unsupported or ambiguous XFerry managed state was detected and preserved; "
            "no changes were made. Back up its configuration and data, remove it with its "
            "original tooling, then install XFerry in a clean environment."
        ),
        "managed_installation_invalid": "The managed release layout is invalid.",
        "managed_config_unavailable": "The managed configuration or credentials are unavailable.",
        "installed_release_conflict": "The installed release conflicts with verified metadata.",
        "release_switch_failed": "The active release switch failed.",
        "release_url_unsafe": "The release URL is unsafe.",
        "staging_path_unsafe": "The release staging path is unsafe.",
        "uninstall_path_unsafe": "An uninstall path is unsafe.",
        "uninstall_service_failed": "The managed service could not be disabled.",
        "uninstall_reload_failed": "systemd could not reload after uninstall.",
        "uninstall_failed": "The managed uninstall failed.",
        "release_operation_failed": "The release operation failed.",
    },
    "ru": {
        "update_complete": "XFerry {version} проверен и активирован.",
        "update_dry_run": "XFerry {version} прошёл проверку обновления; состояние не изменено.",
        "rollback_complete": "XFerry возвращён к проверенному выпуску {version}.",
        "rollback_dry_run": "XFerry {version} прошёл проверку отката; состояние не изменено.",
        "uninstall_complete": "Файлы запуска XFerry удалены; настройки, данные и ACME сохранены.",
        "uninstall_dry_run": "Проверка удаления завершена; состояние не изменено.",
        "purge_complete": "XFerry, настройки, данные, учётные данные и состояние ACME удалены.",
        "purge_confirmation_required": "Удаление данных требует подтверждения или --yes.",
        "release_requires_root": "Для этой операции с выпуском нужны права root.",
        "invalid_release_version": "Недопустимая версия выпуска.",
        "release_platform_unsupported": "Платформа выпуска не соответствует этому серверу.",
        "release_download_failed": "Не удалось загрузить выпуск.",
        "release_manifest_invalid": "Манифест выпуска недействителен.",
        "release_manifest_mismatch": "Манифест не соответствует запрошенной версии.",
        "release_integrity_failed": "Проверка размера или контрольной суммы не пройдена.",
        "candidate_config_invalid": "Новая версия не может загрузить управляемую конфигурацию.",
        "candidate_restart_failed": "Новая служба не запустилась; предыдущий выпуск восстановлен.",
        "candidate_unhealthy": "Новая служба неисправна; предыдущий выпуск восстановлен.",
        "candidate_state_restore_failed": (
            "Новая служба не восстановила остановленное состояние; предыдущий выпуск восстановлен."
        ),
        "restore_incomplete": "Операция не выполнена, восстановление завершено не полностью.",
        "rollback_target_unverified": "Версия для отката не установлена или не проверена.",
        "release_operation_locked": "Выполняется другая управляемая операция.",
        "release_lock_unsafe": "Файл блокировки управляемых операций небезопасен.",
        "unsupported_release_major": (
            "Обслуживание XFerry принимает только выпуски {supported_major}.x; для {version} "
            "требуется отдельно утверждённая линия выпусков."
        ),
        "unsupported_managed_state": (
            "Обнаружено неподдерживаемое или неоднозначное управляемое состояние XFerry; "
            "оно сохранено, изменения не внесены. Создайте резервную копию его настроек и данных, "
            "удалите его исходными инструментами, затем установите XFerry в чистом окружении."
        ),
        "managed_installation_invalid": "Структура управляемых выпусков недействительна.",
        "managed_config_unavailable": "Управляемые настройки или учётные данные недоступны.",
        "installed_release_conflict": (
            "Установленный выпуск не совпадает с проверенными метаданными."
        ),
        "release_switch_failed": "Не удалось переключить активный выпуск.",
        "release_url_unsafe": "Небезопасный адрес выпуска.",
        "staging_path_unsafe": "Небезопасный путь подготовки выпуска.",
        "uninstall_path_unsafe": "Небезопасный путь удаления.",
        "uninstall_service_failed": "Не удалось отключить управляемую службу.",
        "uninstall_reload_failed": "Не удалось обновить состояние systemd после удаления.",
        "uninstall_failed": "Не удалось удалить управляемую установку.",
        "release_operation_failed": "Операция с выпуском не выполнена.",
    },
}

_MANAGED_TEXT: dict[str, dict[str, dict[str, str]]] = {
    "en": {
        "action": {"start": "start", "stop": "stop", "restart": "restart"},
        "check": {
            "privilege": "Privilege",
            "platform": "Platform",
            "installation": "Installation",
            "configuration": "Configuration",
            "service": "Service",
            "network": "Network",
            "health": "Health",
        },
        "detail": {
            "managed diagnostics require root": "managed diagnostics require root",
            "supported platform": "supported platform",
            "unsupported platform": "unsupported platform",
            "managed executable present": "managed executable present",
            "managed executable missing": "managed executable missing",
            "configuration valid": "configuration valid",
            "configuration unavailable": "configuration unavailable",
            "service active": "service active",
            "service inactive": "service inactive",
            "service failed": "service failed",
            "service unknown": "service unknown",
            "network checks skipped": "network checks skipped",
            "authenticated health check skipped": "authenticated health check skipped",
            "endpoint unavailable": "endpoint unavailable",
            "endpoint reachable": "endpoint reachable",
            "endpoint unreachable": "endpoint unreachable",
            "credentials unavailable": "credentials unavailable",
            "authenticated health check passed": "authenticated health check passed",
            "authenticated health check failed": "authenticated health check failed",
            "TLS verification failed": "TLS verification failed",
            "connection failed": "connection failed",
        },
        "status": {"required": "required"},
    },
    "ru": {
        "action": {"start": "запуск", "stop": "остановка", "restart": "перезапуск"},
        "check": {
            "privilege": "Права",
            "platform": "Платформа",
            "installation": "Установка",
            "configuration": "Конфигурация",
            "service": "Служба",
            "network": "Сеть",
            "health": "Здоровье",
        },
        "detail": {
            "managed diagnostics require root": "для управляемой диагностики нужны права root",
            "supported platform": "поддерживаемая платформа",
            "unsupported platform": "неподдерживаемая платформа",
            "managed executable present": "управляемый исполняемый файл найден",
            "managed executable missing": "управляемый исполняемый файл отсутствует",
            "configuration valid": "конфигурация корректна",
            "configuration unavailable": "конфигурация недоступна",
            "service active": "служба активна",
            "service inactive": "служба неактивна",
            "service failed": "ошибка службы",
            "service unknown": "состояние службы неизвестно",
            "network checks skipped": "сетевые проверки пропущены",
            "authenticated health check skipped": "аутентифицированная проверка пропущена",
            "endpoint unavailable": "конечная точка недоступна",
            "endpoint reachable": "конечная точка доступна",
            "endpoint unreachable": "конечная точка недоступна",
            "credentials unavailable": "учётные данные недоступны",
            "authenticated health check passed": "аутентифицированная проверка пройдена",
            "authenticated health check failed": "аутентифицированная проверка не пройдена",
            "TLS verification failed": "проверка TLS не пройдена",
            "connection failed": "соединение не установлено",
        },
        "status": {
            "required": "требуются",
            "supported": "поддерживается",
            "unsupported": "не поддерживается",
            "installed": "установлена",
            "missing": "отсутствует",
            "valid": "корректна",
            "invalid": "некорректна",
            "enabled": "включена",
            "disabled": "выключена",
            "active": "активна",
            "inactive": "неактивна",
            "failed": "ошибка",
            "unknown": "неизвестно",
            "reachable": "доступна",
            "unreachable": "недоступна",
            "unavailable": "недоступна",
            "skipped": "пропущена",
            "healthy": "исправно",
            "unhealthy": "неисправно",
        },
    },
}


def _language_code(value: str) -> str:
    """Return the supported language for a locale value."""
    return "ru" if value.casefold().startswith("ru") else "en"


def _explicit_language(argv: Sequence[str]) -> str | None:
    """Return the first global --lang value, if one was supplied."""
    for index, token in enumerate(argv):
        if token == "--lang":
            if index + 1 < len(argv):
                return argv[index + 1]
            return None
        if token.startswith("--lang="):
            return token.split("=", 1)[1]
    return None


def resolve_language(argv: Sequence[str], env: Mapping[str, str]) -> LanguageSelection:
    """Resolve the management language using the documented precedence order."""
    explicit = _explicit_language(argv)
    if explicit is not None:
        return LanguageSelection(code=_language_code(explicit), source="--lang")

    for key in _ENVIRONMENT_LANGUAGE_KEYS:
        value = env.get(key)
        if value:
            return LanguageSelection(code=_language_code(value), source=key)
    return LanguageSelection(code="en", source="default")


class Translator:
    """Translate the small management CLI catalog."""

    def __init__(self, language: str | LanguageSelection) -> None:
        self.language = (
            language.code if isinstance(language, LanguageSelection) else _language_code(language)
        )

    def get(self, key: str, **values: object) -> str:
        """Return a localized message formatted with ``values``."""
        return _MESSAGES[self.language][key].format(**values)

    def managed_text(self, kind: str, value: str) -> str:
        """Translate bounded human-facing managed-service values without changing JSON enums."""
        return _MANAGED_TEXT[self.language].get(kind, {}).get(value, value)

    def release_text(self, message: str, *, version: str | None = None) -> str:
        """Translate a stable release result code without exposing exception text."""
        template = _RELEASE_TEXT[self.language].get(
            message,
            _MESSAGES[self.language]["operation_failure"],
        )
        return template.format(
            version=version or "",
            supported_major=SUPPORTED_RELEASE_MAJOR,
        )
