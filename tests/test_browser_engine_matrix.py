"""Browser-engine selection and honest capability-gated smoke contracts."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

from tools import browser_smoke


@pytest.fixture(autouse=True)
def isolated_browser_proxy_environment(monkeypatch):
    for key in (
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "http_proxy",
        "https_proxy",
        "PLAYWRIGHT_MCP_PROXY_SERVER",
        "PLAYWRIGHT_MCP_PROXY_BYPASS",
        "NO_PROXY",
        "no_proxy",
    ):
        monkeypatch.delenv(key, raising=False)


@pytest.mark.parametrize("engine", browser_smoke.BROWSER_NAMES)
@pytest.mark.parametrize("target_url", [None, "http://127.0.0.1:9876/"])
def test_engine_selection_reaches_cli_and_receipt(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, engine: str, target_url: str | None
) -> None:
    opened: dict[str, object] = {}
    sessions: list[str] = []
    local_calls: list[bool] = []

    class FakeLiveServer:
        port = 9876

        def __init__(self, *_args: object, **_kwargs: object) -> None:
            pass

        def start(self) -> None:
            pass

        def stop(self) -> None:
            pass

    def run_cli(
        _command: list[str], session: str, *args: str, cwd: Path, local_target: bool
    ) -> str:
        del cwd
        sessions.append(session)
        local_calls.append(local_target)
        if "open" in args:
            config = Path(args[args.index("--config") + 1])
            opened.update(json.loads(config.read_text(encoding="utf-8")))
        if "run-code" in args:
            return json.dumps({"journey": "first-run"})
        return ""

    monkeypatch.setattr(browser_smoke, "_playwright_command", lambda: ["test-playwright"])
    monkeypatch.setattr(browser_smoke, "_run_playwright", run_cli)
    monkeypatch.setattr(browser_smoke, "_LiveServer", FakeLiveServer)
    monkeypatch.setattr(
        browser_smoke, "_load_server_class", lambda **_kwargs: (object, tmp_path / "server.py")
    )
    artifacts = tmp_path / engine
    result = browser_smoke.run_browser_smoke(
        browser=engine,
        mode="first-run",
        target_url=target_url,
        artifacts_dir=artifacts,
    )

    expected_launch: dict[str, object] = {"headless": True}
    if engine == "chromium":
        expected_launch["channel"] = "chromium"
    elif engine == "firefox" and target_url is None:
        expected_launch["firefoxUserPrefs"] = {"network.proxy.type": 0}
    assert opened["browser"] == {
        "browserName": engine,
        "launchOptions": expected_launch,
        "contextOptions": {"viewport": {"width": 1440, "height": 1024}},
    }
    assert local_calls == [target_url is None] * 3
    assert all(f"xferry-smoke-{engine}-" in session for session in sessions)
    assert result["browserName"] == engine
    assert result["status"] == "passed"
    receipt = json.loads((artifacts / "first-run-result.json").read_text(encoding="utf-8"))
    assert receipt == result


@pytest.mark.parametrize("local_target", [True, False])
def test_loopback_bypass_preserves_package_proxies_and_external_configuration(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, local_target: bool
) -> None:
    monkeypatch.setenv("HTTP_PROXY", "http://package-proxy.invalid:8080")
    monkeypatch.setenv("HTTPS_PROXY", "http://package-proxy.invalid:8080")
    monkeypatch.setenv("NO_PROXY", ".internal.invalid,localhost")
    monkeypatch.setenv("no_proxy", ".lowercase.invalid")
    monkeypatch.setenv("PLAYWRIGHT_MCP_PROXY_SERVER", "http://browser-proxy.invalid:8080")
    monkeypatch.setenv("PLAYWRIGHT_MCP_PROXY_BYPASS", ".browser.invalid")
    original = os.environ.copy()
    captured: dict[str, object] = {}

    def run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        captured.update(kwargs)
        return subprocess.CompletedProcess(command, 0, stdout="ok", stderr="")

    monkeypatch.setattr(browser_smoke.subprocess, "run", run)
    assert (
        browser_smoke._run_playwright(
            ["npx"], "test", "open", cwd=tmp_path, local_target=local_target
        )
        == "ok"
    )
    environment = captured["env"]
    if local_target:
        assert isinstance(environment, dict)
        for key in ("HTTP_PROXY", "HTTPS_PROXY", "PLAYWRIGHT_MCP_PROXY_SERVER"):
            assert environment[key] == original[key]
        expected_bypass = ".internal.invalid,localhost,.lowercase.invalid,127.0.0.1,::1"
        assert environment["NO_PROXY"] == environment["no_proxy"] == expected_bypass
        assert environment["PLAYWRIGHT_MCP_PROXY_BYPASS"] == f".browser.invalid,{expected_bypass}"
    else:
        assert environment is None
    assert os.environ == original

    config_path = tmp_path / "cli.config.json"
    browser_smoke._write_cli_config(config_path, browser="webkit", local_target=local_target)
    serialized = config_path.read_text("utf-8")
    assert "package-proxy" not in serialized
    if local_target:
        assert "browser-proxy" not in serialized
    else:
        proxy = json.loads(serialized)["browser"]["launchOptions"]["proxy"]
        assert proxy["server"] == "http://browser-proxy.invalid:8080"
    assert '"env"' not in serialized


@pytest.mark.parametrize("engine", ["firefox", "webkit"])
@pytest.mark.parametrize("mode", ["full", "encrypted-transfer", "advanced"])
def test_unsupported_combinations_fail_before_starting_anything(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, engine: str, mode: str
) -> None:
    def forbidden(**_kwargs: object) -> None:
        pytest.fail("unsupported engine/mode started a server or browser")

    monkeypatch.setattr(browser_smoke, "_run_single_journey", forbidden)
    artifacts = tmp_path / "must-not-exist"
    with pytest.raises(ValueError, match="requires Chromium"):
        browser_smoke.run_browser_smoke(browser=engine, mode=mode, artifacts_dir=artifacts)
    assert not artifacts.exists()


def test_unknown_browser_is_not_silently_replaced() -> None:
    with pytest.raises(ValueError, match="--browser"):
        browser_smoke.run_browser_smoke(browser="safari", mode="first-run")


@pytest.mark.parametrize("engine", ["firefox", "webkit"])
def test_default_artifacts_separate_browser_engines(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, engine: str
) -> None:
    template = browser_smoke.REPO_ROOT / "tools" / "browser_smoke.playwright.js"
    (tmp_path / "tools").mkdir()
    (tmp_path / "tools" / template.name).write_text(template.read_text("utf-8"), "utf-8")
    monkeypatch.setattr(browser_smoke, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(browser_smoke, "_playwright_command", lambda: ["test-playwright"])
    monkeypatch.setattr(
        browser_smoke,
        "_run_playwright",
        lambda _cmd, _session, *args, **_kwargs: (
            '{"journey":"encrypted-compatibility"}' if "run-code" in args else ""
        ),
    )
    result = browser_smoke.run_browser_smoke(
        browser=engine,
        mode="encrypted-compatibility",
        target_url="http://127.0.0.1:9876/",
    )
    assert result["artifactsDir"] == str(
        tmp_path / "output" / "playwright" / "browser-smoke" / engine / "encrypted-compatibility"
    )


def test_engine_cli_forwards_selection(monkeypatch: pytest.MonkeyPatch) -> None:
    received: dict[str, object] = {}

    def fake_run(**kwargs: object) -> dict[str, object]:
        received.update(kwargs)
        return {"status": "passed", "browserName": kwargs["browser"]}

    monkeypatch.setattr(browser_smoke, "run_browser_smoke", fake_run)
    assert browser_smoke.main(["--browser", "webkit", "--mode", "files"]) == 0
    assert received["browser"] == "webkit"
    assert received["mode"] == "files"


def test_browser_matrix_is_required_for_reusable_release_ci() -> None:
    ci = (browser_smoke.REPO_ROOT / ".github" / "workflows" / "ci.yml").read_text("utf-8")
    matrix = ci.split("\n  browser-matrix:", 1)[1].split("\n  scie-verify:", 1)[0]
    assert "browser: [firefox, webkit]" in matrix
    assert "candidate-gates" not in matrix
    assert "if: always()" in matrix
    assert "fail-fast: false" in matrix
    assert "--browser" in matrix
    for mode in browser_smoke.CROSS_BROWSER_MODES:
        assert mode in matrix


@pytest.mark.parametrize("mode", [0o400, 0o600])
def test_external_basic_auth_is_private_and_bound_to_requested_origin(tmp_path, mode):
    auth = tmp_path / "operator.auth"
    auth.write_text("admin:keyboard2345\n")
    auth.chmod(mode)
    config = tmp_path / "cli.config.json"
    browser_smoke._write_cli_config(
        config, auth_file=auth, auth_origin="https://files.example.test"
    )
    document = json.loads(config.read_text())
    context = document["browser"]["contextOptions"]
    assert context["httpCredentials"] == {
        "username": "admin",
        "password": "keyboard2345",
        "origin": "https://files.example.test",
    }
    assert config.stat().st_mode & 0o777 == 0o600
    assert "ignoreHTTPSErrors" not in context


@pytest.mark.parametrize(
    "value", ["admin:secret\nextra", "admin:secret\n\n", "admin:", ":secret", "admin:bad\x00value"]
)
def test_browser_auth_rejects_malformed_lines_without_echo(tmp_path, value):
    auth = tmp_path / "operator.auth"
    auth.write_text(value)
    auth.chmod(0o600)
    with pytest.raises(ValueError) as error:
        browser_smoke._read_browser_credentials(auth)
    assert "secret" not in str(error.value)
    assert "bad" not in str(error.value)


@pytest.mark.parametrize("kind", ["symlink", "hardlink", "public"])
def test_browser_auth_rejects_linked_or_public_secret(tmp_path, kind):
    secret = tmp_path / "secret"
    secret.write_text("admin:keyboard2345\n")
    secret.chmod(0o600)
    auth = tmp_path / "auth"
    if kind == "symlink":
        auth.symlink_to(secret)
    elif kind == "hardlink":
        auth.hardlink_to(secret)
    else:
        secret.chmod(0o644)
        auth = secret
    with pytest.raises((OSError, ValueError)):
        browser_smoke._read_browser_credentials(auth)


@pytest.mark.parametrize("local,origin", [(True, "https://files.example.test"), (False, None)])
def test_browser_auth_requires_explicit_external_origin(tmp_path, local, origin):
    auth = tmp_path / "operator.auth"
    auth.write_text("admin:keyboard2345\n")
    auth.chmod(0o600)
    with pytest.raises(ValueError, match="external origin"):
        browser_smoke._write_cli_config(
            tmp_path / "cli.json", local_target=local, auth_file=auth, auth_origin=origin
        )


@pytest.mark.parametrize(
    "target,origin",
    [
        ("http://files.example.test:80/", "http://files.example.test"),
        ("https://files.example.test:443/", "https://files.example.test"),
        ("https://FILES.example.test:8443/", "https://files.example.test:8443"),
        ("https://[::1]:443/", "https://[::1]"),
    ],
)
def test_http_auth_origin_matches_browser_default_port_normalization(target, origin):
    assert browser_smoke._credential_origin(target) == origin


def test_external_browser_proxy_uses_decoded_credentials_in_private_config(tmp_path, monkeypatch):
    monkeypatch.setenv("HTTPS_PROXY", "http://actor%40proxy:p%40ss%3Aword@proxy.example:9691")
    config = tmp_path / "cli.json"
    browser_smoke._write_cli_config(config)
    document = json.loads(config.read_text())
    proxy = document["browser"]["launchOptions"]["proxy"]
    assert proxy == {
        "server": "http://proxy.example:9691",
        "username": "actor@proxy",
        "password": "p@ss:word",
    }
    assert config.stat().st_mode & 0o777 == 0o600
    assert "ignoreHTTPSErrors" not in document["browser"]["contextOptions"]
    assert "actor%40proxy" not in proxy["server"] and "p%40ss" not in proxy["server"]


def test_browser_proxy_errors_and_diagnostics_do_not_disclose_userinfo(monkeypatch):
    raw = "http://actor%40proxy:p%40ss%3Aword@proxy.example:9691"
    monkeypatch.setenv("HTTPS_PROXY", raw)
    message = browser_smoke._sanitize_browser_diagnostic(
        raw + " actor@proxy p@ss:word p%40ss%3Aword"
    )
    assert "actor" not in message and "word" not in message
    monkeypatch.setenv("HTTPS_PROXY", "http://actor:secret@proxy.example:not-a-port")
    with pytest.raises(ValueError) as error:
        browser_smoke._configured_browser_proxy()
    assert "secret" not in str(error.value) and "actor" not in str(error.value)


def test_browser_diagnostics_redact_json_escaped_proxy_password(monkeypatch):
    monkeypatch.setenv("HTTPS_PROXY", "http://actor:private%5Cproxy%22value@proxy.example:9691")
    rendered = json.dumps({"password": 'private\\proxy"value'})
    safe = browser_smoke._sanitize_browser_diagnostic(rendered)
    assert "private" not in safe and "proxy\\\\" not in safe
