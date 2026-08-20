#!/usr/bin/env python3
"""Run a minimal browser smoke against a live temporary xferry instance."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

REPO_ROOT = Path(__file__).resolve().parents[1]

PLAYWRIGHT_CLI_PACKAGE = "@playwright/cli@0.1.9"
SMOKE_MODES = (
    "first-run",
    "basic-upload-profiles",
    "ui-contracts",
    "http-errors",
    "recovery",
    "request-matrix",
    "advanced",
    "advanced-constructor-profiles",
    "advanced-session",
    "files",
    "smuggle",
    "notepad",
    "mobile",
    "full",
)


def _find_free_port() -> int:
    """Reserve an ephemeral port and return it."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _path_is_under(path: Path, parent: Path) -> bool:
    """Return True when *path* is equal to or below *parent*."""
    path = path.resolve()
    parent = parent.resolve()
    return path == parent or path.is_relative_to(parent)


def _remove_repo_import_paths() -> None:
    """Remove checkout paths so installed-artifact smoke cannot import local packages."""
    filtered: list[str] = []
    for entry in sys.path:
        entry_path = Path(entry).resolve() if entry else Path.cwd().resolve()
        if _path_is_under(entry_path, REPO_ROOT):
            continue
        filtered.append(entry)
    sys.path[:] = filtered


def _load_server_class(*, installed_package: bool) -> tuple[type[Any], Path]:
    """Import XFerryServer from source or from the installed package."""
    if installed_package:
        _remove_repo_import_paths()
    elif str(REPO_ROOT) not in sys.path:
        sys.path.insert(0, str(REPO_ROOT))

    from xferry import XFerryServer

    module = sys.modules[XFerryServer.__module__]
    module_path = Path(getattr(module, "__file__", "")).resolve()
    if installed_package and _path_is_under(module_path, REPO_ROOT):
        raise RuntimeError(
            "Installed-package browser smoke imported xferry from the source checkout: "
            f"{module_path}"
        )
    return XFerryServer, module_path


class _LiveServer:
    """Manage a short-lived server instance for browser smoke checks."""

    def __init__(
        self,
        server_cls: type[Any],
        root_dir: Path,
        *,
        disable_ecdh: bool = False,
    ) -> None:
        from xferry.server_config import LoggingConfig, ServerConfig

        self.server = server_cls(
            ServerConfig(
                host="127.0.0.1",
                port=_find_free_port(),
                root_dir=root_dir,
                logging=LoggingConfig(quiet=True),
            )
        )
        if disable_ecdh:
            self.server._ecdh_manager = None
        self.port = self.server.port
        self._thread = threading.Thread(target=self.server.start, daemon=True)

    def start(self) -> None:
        self._thread.start()
        for _ in range(100):
            time.sleep(0.05)
            if self.server.running:
                return
        raise RuntimeError("Server did not start in time")

    def stop(self) -> None:
        self.server.stop()
        try:
            with socket.create_connection(("127.0.0.1", self.port), timeout=0.2):
                pass
        except OSError:
            pass
        self._thread.join(timeout=3.0)


def _playwright_command() -> list[str]:
    """Return the preferred Playwright CLI invocation."""
    env_pwcli = os.environ.get("PWCLI")
    if env_pwcli:
        pwcli_path = Path(env_pwcli).expanduser()
        if pwcli_path.exists():
            return ["bash", str(pwcli_path)]

    codex_home = Path(os.environ.get("CODEX_HOME", Path.home() / ".codex")).expanduser()
    bundled_pwcli = codex_home / "skills" / "playwright" / "scripts" / "playwright_cli.sh"
    if bundled_pwcli.exists():
        return ["bash", str(bundled_pwcli)]

    if shutil.which("npx"):
        return ["npx", "--yes", "--package", PLAYWRIGHT_CLI_PACKAGE, "playwright-cli"]

    raise RuntimeError("Playwright CLI not found; install Node.js/npm or set PWCLI")


def _run_playwright(
    base_cmd: list[str],
    session: str,
    *args: str,
    cwd: Path,
) -> str:
    """Run a Playwright CLI command and return stdout."""
    completed = subprocess.run(
        [*base_cmd, f"-s={session}", *args],
        cwd=cwd,
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        message = completed.stderr.strip() or completed.stdout.strip() or "unknown playwright error"
        raise RuntimeError(message)
    outputs = [stream.strip() for stream in (completed.stdout, completed.stderr) if stream.strip()]
    return "\n".join(outputs)


def _write_cli_config(config_path: Path) -> None:
    """Write a minimal headless Playwright CLI config."""
    config = {
        "browser": {
            "launchOptions": {"headless": True},
            "contextOptions": {"viewport": {"width": 1440, "height": 1024}},
        }
    }
    config_path.write_text(json.dumps(config, indent=2), encoding="utf-8")


def _parse_playwright_json(output: str) -> dict[str, object]:
    """Extract the trailing JSON object from Playwright CLI output."""
    for line in reversed([item.strip() for item in output.splitlines() if item.strip()]):
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(payload, dict):
            return payload
    raise RuntimeError(f"Playwright CLI did not return a JSON object. Raw output: {output!r}")


def normalize_target_url(value: str) -> str:
    """Validate and normalize an external browser-smoke target root URL."""
    candidate = value.strip()
    if not candidate:
        raise ValueError("--target-url must not be empty")
    parsed = urlsplit(candidate)
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        raise ValueError("--target-url must be an absolute http:// or https:// URL")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("--target-url must not contain credentials")
    if parsed.query or parsed.fragment:
        raise ValueError("--target-url must not contain a query string or fragment")
    if parsed.path not in {"", "/"}:
        raise ValueError("--target-url must point to the server root path")
    try:
        _ = parsed.port
    except ValueError as exc:
        raise ValueError(f"--target-url has an invalid port: {exc}") from exc
    return urlunsplit((parsed.scheme.lower(), parsed.netloc, "/", "", ""))


def _render_smoke_source(
    template: str,
    *,
    base_url: str,
    unavailable_url: str,
    external_target: bool,
    smoke_mode: str,
    artifact_dir: Path,
    upload_fixture: Path,
    unicode_upload_fixture: Path,
    opsec_upload_url_boundary_fixture: Path,
    opsec_upload_fixture: Path,
    opsec_upload_boundary_fixture: Path,
    opsec_upload_large_fixture: Path,
) -> str:
    """Render the Playwright script with explicit, JSON-encoded inputs."""
    replacements = {
        "__XFERRY_BASE_URL__": base_url,
        "__XFERRY_UNAVAILABLE_URL__": unavailable_url,
        "__XFERRY_EXTERNAL_TARGET__": external_target,
        "__XFERRY_SMOKE_MODE__": smoke_mode,
        "__XFERRY_ARTIFACT_DIR__": str(artifact_dir),
        "__XFERRY_UPLOAD_FILE__": str(upload_fixture),
        "__XFERRY_UNICODE_UPLOAD_FILE__": str(unicode_upload_fixture),
        "__XFERRY_OPSEC_UPLOAD_URL_BOUNDARY_FILE__": str(opsec_upload_url_boundary_fixture),
        "__XFERRY_OPSEC_UPLOAD_FILE__": str(opsec_upload_fixture),
        "__XFERRY_OPSEC_UPLOAD_BOUNDARY_FILE__": str(opsec_upload_boundary_fixture),
        "__XFERRY_OPSEC_UPLOAD_LARGE_FILE__": str(opsec_upload_large_fixture),
    }
    rendered = template
    for placeholder, replacement in replacements.items():
        if rendered.count(placeholder) != 1:
            raise RuntimeError(f"Browser smoke template must contain {placeholder} exactly once")
        rendered = rendered.replace(placeholder, json.dumps(replacement), 1)
    return rendered


def run_browser_smoke(
    *,
    installed_package: bool = False,
    mode: str = "full",
    target_url: str | None = None,
    artifacts_dir: str | Path | None = None,
) -> dict[str, object]:
    """Drive one semantic browser journey against a local or external server."""
    if mode not in SMOKE_MODES:
        raise ValueError(f"--mode must be one of: {', '.join(SMOKE_MODES)}")
    if installed_package and target_url is not None:
        raise ValueError("--installed-package cannot be combined with --target-url")

    smoke_mode = mode
    normalized_target = normalize_target_url(target_url) if target_url is not None else None
    server_cls: type[Any] | None = None
    server_module_path: Path | None = None
    if normalized_target is None:
        server_cls, server_module_path = _load_server_class(installed_package=installed_package)

    smoke_script = REPO_ROOT / "tools" / "browser_smoke.playwright.js"
    playwright = _playwright_command()
    session = f"xferry-smoke-{os.getpid()}-{int(time.time())}"
    resolved_artifacts_dir = (
        (
            Path(artifacts_dir)
            if artifacts_dir is not None
            else REPO_ROOT / "output" / "playwright" / "browser-smoke" / smoke_mode
        )
        .expanduser()
        .resolve()
    )
    resolved_artifacts_dir.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="xferry-browser-smoke-") as tmpdir:
        temp_root = Path(tmpdir)
        normal_root = temp_root / "normal"
        unavailable_root = temp_root / "notepad-unavailable"
        normal_root.mkdir(parents=True, exist_ok=True)
        unavailable_root.mkdir(parents=True, exist_ok=True)
        unicode_fetch_fixture = normal_root / "uploads" / "кириллица #1.bin"
        unicode_fetch_fixture.parent.mkdir(parents=True, exist_ok=True)
        unicode_fetch_fixture.write_bytes(b"custom FETCH filename regression\n")
        work_dir = temp_root / "playwright"
        work_dir.mkdir(parents=True, exist_ok=True)
        config_path = work_dir / "cli.config.json"
        local_smoke_script = work_dir / smoke_script.name
        external_target = normalized_target is not None
        if external_target:
            unique_suffix = f"{os.getpid()}-{int(time.time() * 1000)}"
            upload_filename = f"browser-smoke-upload-{unique_suffix}.txt"
            unicode_upload_filename = f"browser-smoke-unicode-{unique_suffix}-кириллица-имя.bin"
        else:
            upload_filename = "browser-smoke-upload.txt"
            unicode_upload_filename = "кириллица-имя.bin"
        upload_fixture = work_dir / upload_filename
        unicode_upload_fixture = work_dir / unicode_upload_filename
        opsec_upload_url_boundary_fixture = (
            work_dir / "browser-smoke-opsec-url-no-switch-boundary.bin"
        )
        opsec_upload_fixture = work_dir / "browser-smoke-opsec-auto-switch-small.bin"
        opsec_upload_boundary_fixture = work_dir / "browser-smoke-opsec-no-switch-boundary.bin"
        opsec_upload_large_fixture = work_dir / "browser-smoke-opsec-auto-switch-large.bin"
        _write_cli_config(config_path)
        upload_fixture.write_text("browser smoke upload\n", encoding="utf-8")
        unicode_upload_fixture.write_bytes(b"custom FETCH filename regression\n")
        opsec_upload_url_boundary_fixture.write_bytes(b"U" * 1125)
        opsec_upload_fixture.write_bytes(b"A" * 1126)
        opsec_upload_boundary_fixture.write_bytes(b"C" * 18000)
        opsec_upload_large_fixture.write_bytes(b"B" * 18001)

        live: _LiveServer | None = None
        unavailable_live: _LiveServer | None = None
        try:
            if normalized_target is None:
                if server_cls is None:
                    raise RuntimeError("Local browser smoke did not resolve a server class")
                live = _LiveServer(server_cls, normal_root)
                live.start()
                if smoke_mode in {"notepad", "full"}:
                    unavailable_live = _LiveServer(
                        server_cls,
                        unavailable_root,
                        disable_ecdh=True,
                    )
            if unavailable_live is not None:
                unavailable_live.start()
            if normalized_target is not None:
                url = normalized_target
            else:
                if live is None:
                    raise RuntimeError("Local browser smoke did not start a server")
                url = f"http://127.0.0.1:{live.port}/"
            unavailable_url = (
                f"http://127.0.0.1:{unavailable_live.port}/" if unavailable_live is not None else ""
            )
            smoke_source = _render_smoke_source(
                smoke_script.read_text(encoding="utf-8"),
                base_url=url,
                unavailable_url=unavailable_url,
                external_target=external_target,
                smoke_mode=smoke_mode,
                artifact_dir=resolved_artifacts_dir,
                upload_fixture=upload_fixture,
                unicode_upload_fixture=unicode_upload_fixture,
                opsec_upload_url_boundary_fixture=opsec_upload_url_boundary_fixture,
                opsec_upload_fixture=opsec_upload_fixture,
                opsec_upload_boundary_fixture=opsec_upload_boundary_fixture,
                opsec_upload_large_fixture=opsec_upload_large_fixture,
            )
            local_smoke_script.write_text(smoke_source, encoding="utf-8")
            _run_playwright(
                playwright,
                session,
                "open",
                "about:blank",
                "--config",
                str(config_path),
                cwd=REPO_ROOT,
            )
            try:
                raw_output = _run_playwright(
                    playwright,
                    session,
                    "--raw",
                    "run-code",
                    "--filename",
                    str(local_smoke_script),
                    cwd=REPO_ROOT,
                )
                result = _parse_playwright_json(raw_output)
            except Exception as exc:
                failure_path = resolved_artifacts_dir / f"{smoke_mode}-failure.log"
                failure_path.write_text(f"[{smoke_mode}] {exc}\n", encoding="utf-8")
                raise RuntimeError(f"[{smoke_mode}] {exc}") from exc
            result["serverModulePath"] = (
                str(server_module_path) if server_module_path is not None else None
            )
            result["smokeMode"] = smoke_mode
            result["targetUrl"] = url
            result["externalTarget"] = normalized_target is not None
            result["artifactsDir"] = str(resolved_artifacts_dir)
            (resolved_artifacts_dir / f"{smoke_mode}-result.json").write_text(
                json.dumps(result, indent=2) + "\n",
                encoding="utf-8",
            )
            return result
        finally:
            try:
                _run_playwright(playwright, session, "close", cwd=REPO_ROOT)
            except Exception:
                pass
            if unavailable_live is not None:
                unavailable_live.stop()
            if live is not None:
                live.stop()


def main(argv: list[str] | None = None) -> int:
    """CLI entry point."""
    parser = argparse.ArgumentParser(description="Run the xferry browser smoke flow")
    parser.add_argument(
        "--installed-package",
        action="store_true",
        help="Import xferry from the active environment instead of the source checkout.",
    )
    parser.add_argument(
        "--mode",
        choices=SMOKE_MODES,
        default="full",
        help="Semantic browser journey to execute (default: full aggregate).",
    )
    parser.add_argument(
        "--target-url",
        help="Run against an existing HTTP(S) server without starting a local server.",
    )
    parser.add_argument(
        "--artifacts-dir",
        help=(
            "Directory for result/failure diagnostics "
            "(default: output/playwright/browser-smoke/<mode>)."
        ),
    )
    args = parser.parse_args(argv)

    try:
        result = run_browser_smoke(
            installed_package=args.installed_package,
            mode=args.mode,
            target_url=args.target_url,
            artifacts_dir=args.artifacts_dir,
        )
    except Exception as exc:
        print(f"Browser smoke failed: {exc}", file=sys.stderr)
        return 1

    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
