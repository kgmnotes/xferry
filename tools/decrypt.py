#!/usr/bin/env python3
"""
Утилита для XOR шифрования/расшифровки файлов.

Использование:
    python decrypt.py <файл> <пароль> [опции]

Примеры:
    # Расшифровать файл
    python decrypt.py uploads/abc123.bin mypassword

    # Расшифровать и сохранить в указанный файл
    python decrypt.py uploads/abc123.bin mypassword -o decrypted.txt

    # Зашифровать файл
    python decrypt.py secret.txt mypassword -e -o secret.enc

    # Расшифровать все файлы в директории
    python decrypt.py uploads/ mypassword --all
"""

import sys
from pathlib import Path

# Добавляем корень проекта в путь
sys.path.insert(0, str(Path(__file__).parent.parent))

from xferry.security.crypto import xor_decrypt_file, xor_encrypt_file


def format_size(size: int) -> str:
    """Форматирование размера файла."""
    for unit in ["B", "KB", "MB", "GB"]:
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"


def process_file(
    input_path: str,
    password: str,
    output_path: str | None = None,
    encrypt: bool = False,
    quiet: bool = False,
) -> bool:
    """
    Обработка одного файла.

    Args:
        input_path: Путь к входному файлу
        password: Пароль для шифрования/расшифровки
        output_path: Путь для выходного файла (опционально)
        encrypt: True для шифрования, False для расшифровки
        quiet: Тихий режим (без вывода)

    Returns:
        True если успешно
    """
    input_file = Path(input_path)

    if not input_file.exists():
        print(f"Ошибка: файл не найден: {input_path}", file=sys.stderr)
        return False

    if not input_file.is_file():
        print(f"Ошибка: не является файлом: {input_path}", file=sys.stderr)
        return False

    # Определяем выходной путь
    if output_path:
        output_file = Path(output_path)
    else:
        suffix = ".enc" if encrypt else ".dec"
        output_file = input_file.with_suffix(input_file.suffix + suffix)

    # Выполняем операцию
    try:
        if encrypt:
            size = xor_encrypt_file(str(input_file), str(output_file), password)
            operation = "Зашифрован"
        else:
            size = xor_decrypt_file(str(input_file), str(output_file), password)
            operation = "Расшифрован"

        if not quiet:
            print(f"{operation}: {input_file.name} -> {output_file.name} ({format_size(size)})")

        return True

    except Exception as e:
        print(f"Ошибка обработки {input_file.name}: {e}", file=sys.stderr)
        return False


def process_directory(
    dir_path: str, password: str, encrypt: bool = False, pattern: str = "*", quiet: bool = False
) -> tuple[int, int]:
    """
    Обработка всех файлов в директории.

    Args:
        dir_path: Путь к директории
        password: Пароль
        encrypt: True для шифрования
        pattern: Glob-паттерн для фильтрации файлов
        quiet: Тихий режим

    Returns:
        (успешно, ошибок)
    """
    directory = Path(dir_path)

    if not directory.is_dir():
        print(f"Ошибка: не является директорией: {dir_path}", file=sys.stderr)
        return 0, 1

    success = 0
    errors = 0

    for file in directory.glob(pattern):
        if file.is_file():
            if process_file(str(file), password, encrypt=encrypt, quiet=quiet):
                success += 1
            else:
                errors += 1

    return success, errors


def print_help():
    """Вывод справки."""
    print(__doc__)
    print("Опции:")
    print("  -o, --output FILE   Выходной файл (по умолчанию: добавляет .dec/.enc)")
    print("  -e, --encrypt       Режим шифрования (по умолчанию: расшифровка)")
    print("  -a, --all           Обработать все файлы в директории")
    print("  -p, --pattern PAT   Паттерн файлов для --all (по умолчанию: *)")
    print("  -q, --quiet         Тихий режим")
    print("  -h, --help          Показать справку")
    print()
    print("Примечание:")
    print("  XOR шифрование симметрично - та же команда шифрует и расшифровывает.")
    print("  Флаг -e влияет только на суффикс выходного файла (.enc вместо .dec).")


def main():
    """Точка входа."""
    if len(sys.argv) < 2 or "-h" in sys.argv or "--help" in sys.argv:
        print_help()
        sys.exit(0)

    if len(sys.argv) < 3:
        print("Ошибка: укажите файл и пароль", file=sys.stderr)
        print("Использование: python decrypt.py <файл> <пароль> [опции]")
        sys.exit(1)

    input_path = sys.argv[1]
    password = sys.argv[2]

    # Парсинг опций
    output_path = None
    encrypt = False
    process_all = False
    pattern = "*"
    quiet = False

    i = 3
    while i < len(sys.argv):
        arg = sys.argv[i]
        if arg in ("-o", "--output") and i + 1 < len(sys.argv):
            output_path = sys.argv[i + 1]
            i += 2
        elif arg in ("-e", "--encrypt"):
            encrypt = True
            i += 1
        elif arg in ("-a", "--all"):
            process_all = True
            i += 1
        elif arg in ("-p", "--pattern") and i + 1 < len(sys.argv):
            pattern = sys.argv[i + 1]
            i += 2
        elif arg in ("-q", "--quiet"):
            quiet = True
            i += 1
        else:
            i += 1

    # Выполнение
    if process_all or Path(input_path).is_dir():
        success, errors = process_directory(
            input_path, password, encrypt=encrypt, pattern=pattern, quiet=quiet
        )
        if not quiet:
            print(f"\nОбработано: {success} успешно, {errors} ошибок")
        sys.exit(0 if errors == 0 else 1)
    else:
        success = process_file(
            input_path, password, output_path=output_path, encrypt=encrypt, quiet=quiet
        )
        sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
