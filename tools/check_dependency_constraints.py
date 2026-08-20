"""Verify that installed third-party distributions are pinned in constraints."""

from __future__ import annotations

import argparse
import importlib.metadata as metadata
import re
import sys
from pathlib import Path

_NAME_RE = re.compile(r"[-_.]+")


def _normalize_name(name: str) -> str:
    return _NAME_RE.sub("-", name).lower()


def _constraint_pins(path: Path) -> dict[str, str]:
    pins: dict[str, str] = {}
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line or line.startswith(("-", "--")):
            continue
        package, separator, version = line.partition("==")
        if separator:
            pins[_normalize_name(package.strip())] = version.strip()
    return pins


def _installed_versions() -> dict[str, str]:
    versions: dict[str, str] = {}
    for dist in metadata.distributions():
        name = dist.metadata.get("Name")
        if name:
            versions[_normalize_name(name)] = dist.version
    return versions


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Check that installed packages are represented in a constraints file.",
    )
    parser.add_argument(
        "--constraints",
        default="constraints/ci.txt",
        type=Path,
        help="Pinned constraints file to check against.",
    )
    parser.add_argument(
        "--ignore",
        action="append",
        default=["xferry"],
        help="Installed distribution name to ignore; may be passed multiple times.",
    )
    args = parser.parse_args(argv)

    constrained = _constraint_pins(args.constraints)
    ignored = {_normalize_name(name) for name in args.ignore}
    installed = _installed_versions()
    audited = {name: version for name, version in installed.items() if name not in ignored}
    missing = sorted(set(audited) - set(constrained))
    mismatched = sorted(
        (name, installed_version, constrained[name])
        for name, installed_version in audited.items()
        if name in constrained and installed_version != constrained[name]
    )

    if missing:
        print(
            f"Installed distributions are missing from {args.constraints}: {', '.join(missing)}",
            file=sys.stderr,
        )
        print(
            "Add pins for these packages to the constraints file, or ignore only "
            "repository-local editable packages.",
            file=sys.stderr,
        )
        return 1

    if mismatched:
        print(
            f"Installed distributions do not match pins in {args.constraints}:",
            file=sys.stderr,
        )
        for name, installed_version, constrained_version in mismatched:
            print(
                f"  {name}: installed {installed_version}, pinned {constrained_version}",
                file=sys.stderr,
            )
        return 1

    print(f"Installed distributions match pins in {args.constraints}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
