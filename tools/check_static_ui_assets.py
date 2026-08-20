#!/usr/bin/env python3
"""Validate packaged static UI assets and bundled JavaScript syntax."""

from __future__ import annotations

import argparse
import fnmatch
import importlib.resources
import shutil
import subprocess
import sys
import zipfile
from collections.abc import Iterable
from html.parser import HTMLParser
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10 fallback
    import tomli as tomllib


DATA_PACKAGE = "xferry.data"
INDEX_RESOURCE = "index.html"
STATIC_PREFIX = "/static/"


class StaticAssetParser(HTMLParser):
    """Collect local static scripts and stylesheets from index.html."""

    def __init__(self) -> None:
        super().__init__()
        self.asset_paths: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr_map = dict(attrs)
        urls: list[str | None] = []
        if tag == "script":
            urls.append(attr_map.get("src"))
        elif tag == "img":
            urls.append(attr_map.get("src"))
        elif tag == "link":
            rel_tokens = set((attr_map.get("rel") or "").lower().split())
            if rel_tokens & {"stylesheet", "icon", "shortcut icon"}:
                urls.append(attr_map.get("href"))

        urls.extend((attr_map.get("data-theme-dark"), attr_map.get("data-theme-light")))
        for url in urls:
            normalized = normalize_local_static_path(url)
            if normalized is not None:
                self.asset_paths.append(normalized)


def normalize_local_static_path(url: str | None) -> str | None:
    """Return a package-relative static path for same-origin static assets."""
    if not url or not url.startswith("/") or url.startswith("//"):
        return None

    path = url.split("?", 1)[0].split("#", 1)[0]
    if not path.startswith(STATIC_PREFIX):
        return None

    return path.lstrip("/")


def collect_index_static_assets(index_html: str) -> list[str]:
    """Return de-duplicated local static assets referenced by index.html."""
    parser = StaticAssetParser()
    parser.feed(index_html)
    return list(dict.fromkeys(parser.asset_paths))


def read_pyproject_package_data(repo_root: Path) -> list[str]:
    """Read setuptools package-data patterns for the xferry package."""
    pyproject_path = repo_root / "pyproject.toml"
    with pyproject_path.open("rb") as pyproject_file:
        pyproject = tomllib.load(pyproject_file)

    patterns = pyproject["tool"]["setuptools"]["package-data"]["xferry"]
    if not isinstance(patterns, list):
        raise TypeError("tool.setuptools.package-data.xferry must be a list")

    return [str(pattern) for pattern in patterns]


def is_package_data_tracked(resource_path: str, patterns: Iterable[str]) -> bool:
    """Return True when pyproject package-data includes the resource path."""
    data_path = f"data/{resource_path}"
    return any(fnmatch.fnmatchcase(data_path, pattern) for pattern in patterns)


def check_source_tree(repo_root: Path, failures: list[str]) -> list[str]:
    """Validate source-tree assets and package-data patterns."""
    data_root = repo_root / "xferry" / "data"
    index_path = data_root / INDEX_RESOURCE
    if not index_path.is_file():
        failures.append(f"Missing source index resource: {index_path}")
        return []

    index_html = index_path.read_text(encoding="utf-8")
    asset_paths = collect_index_static_assets(index_html)
    if not asset_paths:
        failures.append("index.html does not reference any local static UI assets")

    package_patterns = read_pyproject_package_data(repo_root)
    for resource_path in [INDEX_RESOURCE, *asset_paths]:
        source_path = data_root / resource_path
        if not source_path.is_file():
            failures.append(f"Missing source UI asset: {source_path}")
            continue
        if source_path.stat().st_size == 0:
            failures.append(f"Empty source UI asset: {source_path}")
        if not is_package_data_tracked(resource_path, package_patterns):
            failures.append(f"UI asset is not covered by package-data: data/{resource_path}")

    return asset_paths


def join_traversable(root: object, resource_path: str) -> object:
    """Join a slash-delimited resource path against an importlib Traversable."""
    current = root
    for part in resource_path.split("/"):
        current = current.joinpath(part)  # type: ignore[attr-defined]
    return current


def check_importlib_resources(asset_paths: Iterable[str], failures: list[str]) -> None:
    """Validate assets through importlib.resources instead of raw paths."""
    try:
        resources_root = importlib.resources.files(DATA_PACKAGE)
    except (ModuleNotFoundError, AttributeError) as exc:
        failures.append(f"Could not open {DATA_PACKAGE} resources: {exc}")
        return

    for resource_path in [INDEX_RESOURCE, *asset_paths]:
        resource = join_traversable(resources_root, resource_path)
        if not resource.is_file():  # type: ignore[attr-defined]
            failures.append(f"Missing importlib resource: {DATA_PACKAGE}/{resource_path}")
            continue
        if not resource.read_bytes():  # type: ignore[attr-defined]
            failures.append(f"Empty importlib resource: {DATA_PACKAGE}/{resource_path}")


def discover_bundled_javascript(repo_root: Path) -> list[Path]:
    """Return bundled static JavaScript files that should parse cleanly."""
    static_root = repo_root / "xferry" / "data" / "static"
    return sorted(path for path in static_root.glob("**/*.js") if path.is_file())


def run_node_syntax_check(repo_root: Path, failures: list[str]) -> None:
    """Run node --check over bundled JavaScript assets."""
    node = shutil.which("node")
    if node is None:
        failures.append("node is required for bundled JavaScript syntax checks")
        return

    js_paths = discover_bundled_javascript(repo_root)
    if not js_paths:
        failures.append("No bundled JavaScript files found under xferry/data/static")
        return

    for js_path in js_paths:
        completed = subprocess.run(
            [node, "--check", str(js_path)],
            cwd=repo_root,
            check=False,
            capture_output=True,
            text=True,
        )
        if completed.returncode != 0:
            output = (completed.stderr or completed.stdout).strip()
            failures.append(f"JavaScript syntax check failed for {js_path}: {output}")


def expand_wheel_args(wheel_args: Iterable[str]) -> list[Path]:
    """Expand wheel path/glob arguments."""
    wheels: list[Path] = []
    for wheel_arg in wheel_args:
        candidate = Path(wheel_arg)
        has_glob = any(char in candidate.name for char in "*?[")
        matches = sorted(candidate.parent.glob(candidate.name)) if has_glob else []
        if matches:
            wheels.extend(matches)
        else:
            wheels.append(candidate)
    return wheels


def check_wheel(wheel_path: Path, failures: list[str]) -> None:
    """Validate packaged UI assets inside a built wheel."""
    if not wheel_path.is_file():
        failures.append(f"Wheel not found: {wheel_path}")
        return

    try:
        with zipfile.ZipFile(wheel_path) as wheel:
            index_name = f"xferry/data/{INDEX_RESOURCE}"
            try:
                index_html = wheel.read(index_name).decode("utf-8")
            except KeyError:
                failures.append(f"Wheel is missing {index_name}: {wheel_path}")
                return

            for resource_path in [INDEX_RESOURCE, *collect_index_static_assets(index_html)]:
                wheel_name = f"xferry/data/{resource_path}"
                try:
                    payload = wheel.read(wheel_name)
                except KeyError:
                    failures.append(f"Wheel is missing {wheel_name}: {wheel_path}")
                    continue
                if not payload:
                    failures.append(f"Wheel contains empty UI asset {wheel_name}: {wheel_path}")
    except zipfile.BadZipFile as exc:
        failures.append(f"Invalid wheel {wheel_path}: {exc}")


def build_parser() -> argparse.ArgumentParser:
    """Build the command-line parser."""
    parser = argparse.ArgumentParser(
        description="Validate static UI package data and JavaScript syntax."
    )
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
        help="Repository root to validate.",
    )
    parser.add_argument(
        "--wheel",
        action="append",
        default=[],
        help="Optional built wheel path or glob to inspect for packaged UI assets.",
    )
    parser.add_argument(
        "--wheel-only",
        action="store_true",
        help="Only inspect --wheel artifacts; do not import or validate the source tree.",
    )
    parser.add_argument(
        "--skip-node-check",
        action="store_true",
        help="Skip node --check for environments that only inspect packaged resources.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """CLI entry point."""
    args = build_parser().parse_args(argv)
    repo_root = args.repo_root.resolve()
    failures: list[str] = []
    wheel_paths = expand_wheel_args(args.wheel)

    if args.wheel_only and not wheel_paths:
        failures.append("--wheel-only requires at least one --wheel path or glob")

    if not args.wheel_only:
        sys.path.insert(0, str(repo_root))
        asset_paths = check_source_tree(repo_root, failures)
        check_importlib_resources(asset_paths, failures)
        if not args.skip_node_check:
            run_node_syntax_check(repo_root, failures)

    for wheel_path in wheel_paths:
        check_wheel(wheel_path, failures)

    if failures:
        for failure in failures:
            print(f"ERROR: {failure}", file=sys.stderr)
        return 1

    print("Static UI asset checks passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
