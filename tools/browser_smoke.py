#!/usr/bin/env python3
"""Run isolated browser journeys or a scoped smoke against an external xferry."""

from __future__ import annotations

import argparse
import base64
import json
import os
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlsplit, urlunsplit
from uuid import uuid4

REPO_ROOT = Path(__file__).resolve().parents[1]

PLAYWRIGHT_CLI_PACKAGE = "@playwright/cli@0.1.23"
MAX_PLAYWRIGHT_DIAGNOSTIC_CHARS = 65536
BROWSER_NAMES = ("chromium", "firefox", "webkit")
CROSS_BROWSER_MODES = frozenset(
    {
        "first-run",
        "basic-upload-profiles",
        "request-matrix",
        "files",
        "notepad",
        "encrypted-compatibility",
    }
)
SMOKE_MODES = (
    "first-run",
    "basic-upload-profiles",
    "encrypted-transfer",
    "encrypted-compatibility",
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
                encrypted_uploads=True,
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
    """Use the CI-pinned CLI unless an operator explicitly supplies a wrapper."""
    env_pwcli = os.environ.get("PWCLI")
    if env_pwcli:
        pwcli_path = Path(env_pwcli).expanduser()
        if pwcli_path.exists():
            return ["bash", str(pwcli_path)]

    if shutil.which("npx"):
        return ["npx", "--yes", "--package", PLAYWRIGHT_CLI_PACKAGE, "playwright-cli"]

    raise RuntimeError("Playwright CLI not found; install Node.js/npm or set PWCLI")


def _run_playwright(
    base_cmd: list[str],
    session: str,
    *args: str,
    cwd: Path,
    local_target: bool = False,
) -> str:
    """Run a Playwright CLI command and return stdout."""
    environment = None
    if local_target:
        # Keep package-download proxies available to npx, but do not send the
        # temporary loopback server through an inherited browser/system proxy.
        environment = os.environ.copy()
        bypass = ",".join(
            dict.fromkeys(
                entry.strip()
                for value in (
                    environment.get("NO_PROXY", ""),
                    environment.get("no_proxy", ""),
                    "localhost,127.0.0.1,::1",
                )
                for entry in value.split(",")
                if entry.strip()
            )
        )
        environment["NO_PROXY"] = bypass
        environment["no_proxy"] = bypass
        if environment.get("PLAYWRIGHT_MCP_PROXY_SERVER"):
            environment["PLAYWRIGHT_MCP_PROXY_BYPASS"] = ",".join(
                filter(None, (environment.get("PLAYWRIGHT_MCP_PROXY_BYPASS"), bypass))
            )
    completed = subprocess.run(
        [*base_cmd, f"-s={session}", *args],
        cwd=cwd,
        check=False,
        capture_output=True,
        text=True,
        env=environment,
    )
    if completed.returncode != 0:
        message = completed.stderr.strip() or completed.stdout.strip() or "unknown playwright error"
        raise RuntimeError(_sanitize_browser_diagnostic(message))
    outputs = [stream.strip() for stream in (completed.stdout, completed.stderr) if stream.strip()]
    return "\n".join(outputs)


def _configured_browser_proxy() -> dict[str, str] | None:
    """Translate configured proxy userinfo into protected Playwright options."""
    raw = (
        os.environ.get("PLAYWRIGHT_MCP_PROXY_SERVER")
        or os.environ.get("HTTPS_PROXY")
        or os.environ.get("https_proxy")
        or os.environ.get("HTTP_PROXY")
        or os.environ.get("http_proxy")
    )
    if not raw:
        return None
    try:
        parsed = urlsplit(raw)
        if parsed.scheme not in {"http", "https", "socks5"} or not parsed.hostname:
            raise ValueError
        if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
            raise ValueError
        host = parsed.hostname
        host = f"[{host}]" if ":" in host else host
        port = parsed.port
        server = f"{parsed.scheme}://{host}" + (f":{port}" if port else "")
        options = {"server": server}
        if parsed.username is not None:
            options["username"] = unquote(parsed.username)
        if parsed.password is not None:
            options["password"] = unquote(parsed.password)
        bypass = (
            os.environ.get("PLAYWRIGHT_MCP_PROXY_BYPASS")
            or os.environ.get("NO_PROXY")
            or os.environ.get("no_proxy")
        )
        if bypass:
            options["bypass"] = bypass
        if any(
            any(ord(char) < 32 or ord(char) == 127 for char in value) for value in options.values()
        ):
            raise ValueError
        return options
    except (ValueError, UnicodeError):
        raise ValueError("configured browser proxy URL is invalid") from None


def _credential_origin(value: str) -> str:
    parsed = urlsplit(normalize_target_url(value))
    assert parsed.hostname is not None
    host = parsed.hostname.encode("idna").decode("ascii")
    host = f"[{host}]" if ":" in host else host
    port = parsed.port
    suffix = f":{port}" if port and port != {"https": 443, "http": 80}[parsed.scheme] else ""
    return f"{parsed.scheme}://{host}{suffix}"


def _sanitize_browser_diagnostic(value: str) -> str:
    secrets: set[str] = set()
    for key in (
        "PLAYWRIGHT_MCP_PROXY_SERVER",
        "HTTPS_PROXY",
        "https_proxy",
        "HTTP_PROXY",
        "http_proxy",
    ):
        raw = os.environ.get(key)
        if not raw:
            continue
        try:
            parsed = urlsplit(raw)
            if parsed.username is not None or parsed.password is not None:
                secrets.add(raw)
            for part in (parsed.username, parsed.password):
                if part:
                    secrets.update((part, unquote(part)))
        except ValueError:
            continue
    auth_path = os.environ.get("XFERRY_BROWSER_AUTH_FILE")
    if auth_path:
        try:
            credentials = _read_browser_credentials(Path(auth_path))
            pair = credentials["username"] + ":" + credentials["password"]
            secrets.update(
                (pair, credentials["password"], base64.b64encode(pair.encode()).decode())
            )
        except (OSError, ValueError):
            pass
    for secret in tuple(secrets):
        secrets.add(json.dumps(secret, ensure_ascii=True)[1:-1])
        secrets.add(json.dumps(secret, ensure_ascii=False)[1:-1])
    for secret in sorted(secrets, key=len, reverse=True):
        value = value.replace(secret, "[redacted]")
    return value


def _read_browser_credentials(path: Path) -> dict[str, str]:
    """Read one protected user:password line without following a file link."""
    original = path.lstat()
    if not stat.S_ISREG(original.st_mode):
        raise ValueError("browser auth file must be a regular file without links")
    descriptor = os.open(
        path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    )
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or (metadata.st_dev, metadata.st_ino) != (original.st_dev, original.st_ino)
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) not in {0o400, 0o600}
            or metadata.st_uid != getattr(os, "getuid", lambda: metadata.st_uid)()
            or metadata.st_size > 4096
        ):
            raise ValueError(
                "browser auth file must be owned, private (0400 or 0600), regular and unlinked"
            )
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            value = stream.read(4097)
    finally:
        os.close(descriptor)
    try:
        line = value.decode("utf-8")
    except UnicodeError:
        raise ValueError("browser auth file must contain one UTF-8 user:password line") from None
    line = line.removesuffix("\n").removesuffix("\r")
    username, delimiter, password = line.partition(":")
    if (
        len(value) > 4096
        or not delimiter
        or not username
        or not password
        or any(ord(character) < 32 or ord(character) == 127 for character in line)
    ):
        raise ValueError("browser auth file must contain one user:password line")
    return {"username": username, "password": password}


def _write_cli_config(
    config_path: Path,
    *,
    browser: str = "chromium",
    local_target: bool = False,
    auth_file: Path | None = None,
    auth_origin: str | None = None,
) -> None:
    """Write a minimal headless Playwright CLI config."""
    launch_options: dict[str, object] = {"headless": True}
    if browser == "chromium":
        launch_options["channel"] = "chromium"
    elif browser == "firefox" and local_target:
        launch_options["firefoxUserPrefs"] = {"network.proxy.type": 0}
    if not local_target:
        proxy = _configured_browser_proxy()
        if proxy is not None:
            launch_options["proxy"] = proxy
    context_options: dict[str, object] = {"viewport": {"width": 1440, "height": 1024}}
    if auth_file is not None:
        if local_target or not auth_origin:
            raise ValueError("browser authentication requires an explicit external origin")
        credentials = _read_browser_credentials(auth_file)
        context_options["httpCredentials"] = {
            **credentials,
            "origin": _credential_origin(auth_origin),
        }
    config = {
        "browser": {
            "browserName": browser,
            "launchOptions": launch_options,
            "contextOptions": context_options,
        }
    }
    config_path.write_text(json.dumps(config, indent=2), encoding="utf-8")
    config_path.chmod(0o600)


def _parse_playwright_json(output: str) -> dict[str, object]:
    """Extract a known journey receipt, never JSON embedded in a CLI error."""
    lines = [item.strip() for item in output.splitlines() if item.strip()]
    diagnostic = output[:MAX_PLAYWRIGHT_DIAGNOSTIC_CHARS]
    if "### Error" in lines:
        raise RuntimeError(f"Playwright CLI reported an error. Raw output: {diagnostic!r}")
    for line in reversed(lines):
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(payload, dict) and payload.get("journey") in SMOKE_MODES:
            return payload
    raise RuntimeError(
        f"Playwright CLI did not return a browser-smoke journey receipt. Raw output: {diagnostic!r}"
    )


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


def _run_single_journey(
    *,
    installed_package: bool = False,
    mode: str = "full",
    target_url: str | None = None,
    artifacts_dir: str | Path | None = None,
    browser: str = "chromium",
) -> dict[str, object]:
    """Drive one isolated journey; ``full`` here is the original cross-tool composite."""
    smoke_mode = mode
    normalized_target = normalize_target_url(target_url) if target_url is not None else None
    server_cls: type[Any] | None = None
    server_module_path: Path | None = None
    if normalized_target is None:
        server_cls, server_module_path = _load_server_class(installed_package=installed_package)

    smoke_script = REPO_ROOT / "tools" / "browser_smoke.playwright.js"
    playwright = _playwright_command()
    session = f"xferry-smoke-{browser}-{os.getpid()}-{uuid4().hex}"
    default_artifacts = REPO_ROOT / "output" / "playwright" / "browser-smoke"
    if browser != "chromium":
        default_artifacts /= browser
    resolved_artifacts_dir = (
        (Path(artifacts_dir) if artifacts_dir is not None else default_artifacts / smoke_mode)
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
        browser_auth = os.environ.get("XFERRY_BROWSER_AUTH_FILE") if external_target else None
        _write_cli_config(
            config_path,
            browser=browser,
            local_target=not external_target,
            auth_file=Path(browser_auth) if browser_auth else None,
            auth_origin=normalized_target.rstrip("/") if normalized_target else None,
        )
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
                local_target=not external_target,
            )
            raw_output = ""
            try:
                raw_output = _run_playwright(
                    playwright,
                    session,
                    "--raw",
                    "run-code",
                    "--filename",
                    str(local_smoke_script),
                    cwd=REPO_ROOT,
                    local_target=not external_target,
                )
                result = _parse_playwright_json(raw_output)
                if result.get("journey") != smoke_mode:
                    raise RuntimeError(
                        f"Browser smoke returned journey {result.get('journey')!r}, "
                        f"expected {smoke_mode!r}"
                    )
            except Exception as exc:
                failure_path = resolved_artifacts_dir / f"{smoke_mode}-failure.log"
                safe_error = _sanitize_browser_diagnostic(str(exc))[
                    :MAX_PLAYWRIGHT_DIAGNOSTIC_CHARS
                ]
                failure_path.write_text(
                    f"[{smoke_mode}] {safe_error}\n",
                    encoding="utf-8",
                )
                if raw_output:
                    (resolved_artifacts_dir / f"{smoke_mode}-cli-output.log").write_text(
                        _sanitize_browser_diagnostic(raw_output)[:MAX_PLAYWRIGHT_DIAGNOSTIC_CHARS],
                        encoding="utf-8",
                    )
                raise RuntimeError(
                    f"[{browser}][{smoke_mode}] {_sanitize_browser_diagnostic(str(exc))}"
                ) from None
            result["serverModulePath"] = (
                str(server_module_path) if server_module_path is not None else None
            )
            result["smokeMode"] = smoke_mode
            result["browserName"] = browser
            result["status"] = "passed"
            target_scope = "external" if external_target else "local"
            journey_scope = "cross-tool-composite" if smoke_mode == "full" else "single-journey"
            result["executionScope"] = f"{target_scope}-{journey_scope}"
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
                _run_playwright(
                    playwright,
                    session,
                    "close",
                    cwd=REPO_ROOT,
                    local_target=not external_target,
                )
            except Exception:
                pass
            if unavailable_live is not None:
                unavailable_live.stop()
            if live is not None:
                live.stop()


def run_browser_smoke(
    *,
    installed_package: bool = False,
    mode: str = "full",
    target_url: str | None = None,
    artifacts_dir: str | Path | None = None,
    browser: str = "chromium",
) -> dict[str, object]:
    """Run a named journey or the full isolated local aggregate.

    Local ``full`` runs the original cross-tool composite and every named mode in
    separate temporary server roots and browser sessions, preserving all receipts
    and collecting failures before failing closed. With ``target_url``, ``full``
    runs only the original composite: it does not broaden mutations on an existing
    server, and its available-journey names are not aggregate completion evidence.
    """
    if mode not in SMOKE_MODES:
        raise ValueError(f"--mode must be one of: {', '.join(SMOKE_MODES)}")
    if browser not in BROWSER_NAMES:
        raise ValueError(f"--browser must be one of: {', '.join(BROWSER_NAMES)}")
    if browser != "chromium" and mode not in CROSS_BROWSER_MODES:
        raise ValueError(
            f"--mode {mode} requires Chromium; {browser} supports: "
            f"{', '.join(sorted(CROSS_BROWSER_MODES))}"
        )
    if installed_package and target_url is not None:
        raise ValueError("--installed-package cannot be combined with --target-url")
    normalized_target = normalize_target_url(target_url) if target_url is not None else None
    if mode != "full" or normalized_target is not None:
        return _run_single_journey(
            installed_package=installed_package,
            mode=mode,
            target_url=normalized_target,
            artifacts_dir=artifacts_dir,
            browser=browser,
        )

    resolved_artifacts_dir = (
        (
            Path(artifacts_dir)
            if artifacts_dir is not None
            else REPO_ROOT / "output" / "playwright" / "browser-smoke" / "full"
        )
        .expanduser()
        .resolve()
    )
    resolved_artifacts_dir.mkdir(parents=True, exist_ok=True)
    journeys = ("full", *(name for name in SMOKE_MODES if name != "full"))
    results: dict[str, dict[str, object]] = {}
    failures: dict[str, str] = {}
    started = time.monotonic()
    for journey in journeys:
        journey_artifacts = resolved_artifacts_dir / ("composite" if journey == "full" else journey)
        journey_artifacts.mkdir(parents=True, exist_ok=True)
        try:
            result = _run_single_journey(
                installed_package=installed_package,
                mode=journey,
                target_url=None,
                artifacts_dir=journey_artifacts,
                browser=browser,
            )
            if result.get("journey") != journey or result.get("status") != "passed":
                raise RuntimeError(
                    f"Expected passing journey {journey!r}; got "
                    f"journey={result.get('journey')!r}, status={result.get('status')!r}"
                )
            results[journey] = result
        except Exception as exc:
            failures[journey] = str(exc)
            (journey_artifacts / f"{journey}-failure.log").write_text(
                f"[{journey}] {exc}\n", encoding="utf-8"
            )

    # Keep the original composite's fields for callers, but only mark journeys
    # complete when that invocation actually returned a passing receipt.
    aggregate: dict[str, object] = dict(results.get("full", {}))
    aggregate.update(
        journey="full",
        smokeMode="full",
        status="failed" if failures else "passed",
        executionScope="isolated-local-aggregate",
        externalTarget=False,
        installedPackage=installed_package,
        browserName=browser,
        artifactsDir=str(resolved_artifacts_dir),
        expectedJourneys=list(journeys),
        completedJourneys=list(results),
        aggregateJourneys=[name for name in results if name != "full"],
        journeyResults=results,
        failures=failures,
        durationMs=round((time.monotonic() - started) * 1000),
    )
    (resolved_artifacts_dir / "full-result.json").write_text(
        json.dumps(aggregate, indent=2) + "\n", encoding="utf-8"
    )
    if failures:
        detail = "; ".join(f"[{name}] {error}" for name, error in failures.items())
        (resolved_artifacts_dir / "full-failure.log").write_text(
            f"[full aggregate] {detail}\n", encoding="utf-8"
        )
        raise RuntimeError(f"[full aggregate] {len(failures)} journey(s) failed: {detail}")
    return aggregate


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
        help=(
            "Semantic browser journey (default: full). Local full runs the cross-tool "
            "composite plus every named journey in isolation; external full runs only "
            "the original cross-tool composite."
        ),
    )
    parser.add_argument(
        "--browser",
        choices=BROWSER_NAMES,
        default="chromium",
        help="Browser engine (default: chromium); full is Chromium-only.",
    )
    parser.add_argument(
        "--target-url",
        help=(
            "Run against an existing HTTP(S) server without starting a local server. "
            "Full is scoped to the original composite, not all independent journeys."
        ),
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
            browser=args.browser,
        )
    except Exception as exc:
        print(f"Browser smoke failed: {exc}", file=sys.stderr)
        return 1

    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
