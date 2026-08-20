from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

import pytest

from tools import browser_smoke
from xferry.server_config import ServerConfig

REPO_ROOT = Path(__file__).resolve().parents[1]
EXPECTED_MODES = (
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


def _workflow_job(workflow: str, job_name: str) -> str:
    lines = workflow.splitlines()
    marker = f"  {job_name}:"
    try:
        start = lines.index(marker)
    except ValueError as exc:
        raise AssertionError(f"workflow job {job_name!r} is missing") from exc

    end = len(lines)
    for index in range(start + 1, len(lines)):
        line = lines[index]
        if len(line) - len(line.lstrip()) == 2 and line.endswith(":"):
            end = index
            break
    return "\n".join(lines[start:end])


def test_browser_smoke_exposes_independent_journeys() -> None:
    assert browser_smoke.SMOKE_MODES == EXPECTED_MODES


def test_browser_issue_checkpoint_accepts_only_exact_unavailable_notepad_501() -> None:
    """The unavailable checkpoint may consume one exact Chromium 501 issue only."""
    node_script = r"""
const fs = require("node:fs");

const source = fs.readFileSync(process.argv[1], "utf8");
const start = source.indexOf("  function isExpectedConsoleIssue(issue) {");
const end = source.indexOf("  async function assertNoBrowserIssues", start);
if (start < 0 || end < 0) {
  throw new Error("browser issue classifier block is missing");
}
const loadClassifier = new Function(`
${source.slice(start, end)}
return { getUnexpectedBrowserIssues };
`);
const { getUnexpectedBrowserIssues } = loadClassifier();

const unavailableOrigin = "http://127.0.0.1:45843";
const expectedUnavailableUrl = `${unavailableOrigin}/notes/key`;
const exact501 = {
  kind: "console",
  message: "Failed to load resource: the server responded with a status of 501 (Not Implemented)",
  url: expectedUnavailableUrl,
};
const allowed = { since: 0, expectedUnavailableNotepadUrl: expectedUnavailableUrl };
const missing404 = {
  kind: "console",
  message: "Failed to load resource: the server responded with a status of 404 (Not Found)",
  url: `${unavailableOrigin}/missing-browser-smoke.txt`,
};

function assertUnexpectedCount(label, issues, options, expected) {
  const actual = getUnexpectedBrowserIssues(issues, options).length;
  if (actual !== expected) {
    throw new Error(`${label}: expected ${expected} unexpected issue(s), got ${actual}`);
  }
}

assertUnexpectedCount("known missing-file 404 remains accepted", [missing404], {}, 0);
assertUnexpectedCount("501 rejected outside unavailable checkpoint", [exact501], {}, 1);
assertUnexpectedCount("exact unavailable 501 accepted", [exact501], allowed, 0);
assertUnexpectedCount("page error rejected", [{ ...exact501, kind: "pageerror" }], allowed, 1);
const wrongStatus = {
  ...exact501,
  message: exact501.message.replace(
    "501 (Not Implemented)",
    "500 (Internal Server Error)"
  ),
};
assertUnexpectedCount(
  "other status rejected",
  [wrongStatus],
  allowed,
  1
);
assertUnexpectedCount(
  "other path rejected",
  [{ ...exact501, url: `${unavailableOrigin}/notes/list` }],
  allowed,
  1
);
assertUnexpectedCount(
  "query-bearing path rejected",
  [{ ...exact501, url: `${expectedUnavailableUrl}?unexpected=1` }],
  allowed,
  1
);
assertUnexpectedCount(
  "normal-server origin rejected",
  [{ ...exact501, url: "http://127.0.0.1:55047/notes/key" }],
  allowed,
  1
);
assertUnexpectedCount(
  "unrelated 501 rejected",
  [{ ...exact501, message: "Unrelated application error 501" }],
  allowed,
  1
);
assertUnexpectedCount(
  "transport failure rejected",
  [{ ...exact501, message: "Failed to load resource: net::ERR_CONNECTION_REFUSED" }],
  allowed,
  1
);
assertUnexpectedCount(
  "checkpoint excludes earlier issue",
  [{ ...exact501, url: "http://127.0.0.1:55047/notes/key" }, exact501],
  { ...allowed, since: 1 },
  0
);
assertUnexpectedCount(
  "additional console error rejected",
  [exact501, { kind: "console", message: "extra error", url: expectedUnavailableUrl }],
  allowed,
  1
);
assertUnexpectedCount("duplicate expected 501 rejected", [exact501, exact501], allowed, 2);
"""
    completed = subprocess.run(
        [
            "node",
            "-e",
            node_script,
            str(REPO_ROOT / "tools/browser_smoke.playwright.js"),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr or completed.stdout


def test_unavailable_notepad_navigation_scopes_browser_issue_checkpoints() -> None:
    script = (REPO_ROOT / "tools/browser_smoke.playwright.js").read_text(encoding="utf-8")

    assert script.count("const unavailableIssueCheckpoint = browserIssues.length;") == 2
    assert script.count("since: unavailableIssueCheckpoint") == 2
    expected_url = (
        'expectedUnavailableNotepadUrl: `${String(unavailableUrl).replace(/\\/+$/, "")}/notes/key`'
    )
    assert script.count(expected_url) == 2

    non_full_start = script.index('if (smokeMode !== "full") {')
    non_full_end = script.index("const happyPath = await runHappyPath();", non_full_start)
    non_full_branch = script[non_full_start:non_full_end]
    full_start = script.index(
        "const unavailableIssueCheckpoint = browserIssues.length;", non_full_end
    )
    full_end = script.index("return {", script.index('"full unavailable path"', full_start))
    full_branch = script[full_start:full_end]

    for branch, label in (
        (non_full_branch, "notepad unavailable path"),
        (full_branch, "full unavailable path"),
    ):
        checkpoint = branch.index("const unavailableIssueCheckpoint = browserIssues.length;")
        navigation = branch.index(
            'await page.goto(unavailableUrl, { waitUntil: "domcontentloaded" });'
        )
        unavailable_path = branch.index("const unavailablePath = await runUnavailablePath();")
        issue_assertion = branch.index(f'await assertNoBrowserIssues("{label}", {{')

        assert checkpoint < navigation < unavailable_path < issue_assertion
        assert branch.count("since: unavailableIssueCheckpoint") == 1
        assert branch.count(expected_url) == 1


def test_notepad_smoke_uses_canonical_error_and_lost_ack_frames() -> None:
    """Keep the live Notepad probes aligned with canonical HTTP/WS envelopes."""
    script = (REPO_ROOT / "tools/browser_smoke.playwright.js").read_text(encoding="utf-8")
    error_probe = script.split("async function assertNotepadSaveErrorSurfacesDetail", 1)[1].split(
        "async function clickNoteByTitle", 1
    )[0]
    lost_ack = script.split("async function assertWsLostAckRetryIsIdempotent", 1)[1].split(
        "async function clearNotesViaUiAndAssert", 1
    )[0]

    assert 'String(url).endsWith("/notes?action=save")' in error_probe
    assert 'code: "payload_too_large"' in error_probe
    assert "message: targetDetail" in error_probe
    assert 'field: "data"' in error_probe
    assert 'details: { scope: "note", limit_bytes: 1048576 }' in error_probe
    assert "JSON.stringify({ error:" in error_probe
    assert "JSON.stringify({ error: targetDetail, status: 413 })" not in error_probe

    for expected in (
        'msg.action === "save"',
        "msg.request_id",
        "msg.result",
        "msg.result.note",
    ):
        assert expected in lost_ack
    for removed in ("msg.type", "msg.success", "msg.opId"):
        assert removed not in lost_ack
    for removed in (
        "clientPublicKey",
        "sessionId",
        "createIfMissing",
        "noteId",
        "opId",
        "X-Session-Id",
    ):
        assert removed not in script


def test_notepad_smoke_exercises_ws_load_selected_delete_and_clear() -> None:
    """The WS journey must observe every destructive/read action, not only save."""
    script = (REPO_ROOT / "tools/browser_smoke.playwright.js").read_text(encoding="utf-8")
    recorder_start = script.index("async function installNotepadWsActionRecorder() {")
    recorder_end = script.index("async function createAutosavedNote", recorder_start)
    recorder = script[recorder_start:recorder_end]
    for expected in (
        "window.__xferryNotepadWsActions",
        'direction: "sent"',
        'direction: "received"',
        "inputKeys",
        "request_id",
        "Object.keys(msg).sort()",
    ):
        assert expected in recorder

    journey = script.split("async function runNotepadJourney() {", 1)[1].split(
        "async function runMobileJourney", 1
    )[0]
    full_path = script.split("async function runHappyPath() {", 1)[1].split(
        "async function runUnavailablePath", 1
    )[0]
    for branch, label in ((journey, "isolated"), (full_path, "full")):
        assert "installNotepadWsActionRecorder" in branch, label
        assert "assertNotepadWsActionCoverage" in branch, label
        assert "deleteSelectedNoteViaUiAndAssert" in branch, label
        assert "clearNotesViaUiAndAssert" in branch, label
    for expected in (
        '"load"',
        '"delete"',
        '"clear"',
        "sentCounts.load",
        "sentCounts.delete",
        "sentCounts.clear",
        "receivedCounts.load",
        "receivedCounts.delete",
        "receivedCounts.clear",
    ):
        assert expected in script


def test_live_server_constructs_a_single_server_config_with_smoke_values(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Catches browser smoke using removed XFerryServer keyword construction."""
    captured: list[ServerConfig] = []

    class ConfigOnlyServer:
        def __init__(self, config: ServerConfig) -> None:
            captured.append(config)
            self.port = config.port

        def start(self) -> None:
            pass

        def stop(self) -> None:
            pass

    monkeypatch.setattr(browser_smoke, "_find_free_port", lambda: 49152)

    live = browser_smoke._LiveServer(ConfigOnlyServer, tmp_path)

    assert len(captured) == 1
    config = captured[0]
    assert config.host == "127.0.0.1"
    assert config.port == 49152
    assert config.root_dir == tmp_path
    assert config.logging.quiet is True
    assert live.port == 49152


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("http://127.0.0.1:8080", "http://127.0.0.1:8080/"),
        ("https://example.test/", "https://example.test/"),
        (" HTTP://localhost:9000/ ", "http://localhost:9000/"),
    ],
)
def test_target_url_is_normalized(value: str, expected: str) -> None:
    assert browser_smoke.normalize_target_url(value) == expected


@pytest.mark.parametrize(
    "value",
    [
        "",
        "localhost:8080",
        "ftp://example.test/",
        "http://user:password@example.test/",
        "http://example.test/subpath",
        "http://example.test/?mode=smoke",
        "http://example.test/#upload",
        "http://example.test:99999/",
    ],
)
def test_target_url_rejects_ambiguous_or_secret_bearing_values(value: str) -> None:
    with pytest.raises(ValueError, match="target-url"):
        browser_smoke.normalize_target_url(value)


def test_external_target_does_not_import_or_start_a_server(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    calls: list[tuple[str, ...]] = []

    def fail_load_server_class(*, installed_package: bool) -> tuple[type[object], Path]:
        raise AssertionError(f"external target imported server: {installed_package}")

    class ForbiddenLiveServer:
        def __init__(self, *args: object, **kwargs: object) -> None:
            raise AssertionError(f"external target started server: {args!r} {kwargs!r}")

    def fake_run_playwright(
        base_cmd: list[str],
        session: str,
        *args: str,
        cwd: Path,
    ) -> str:
        del base_cmd, session, cwd
        calls.append(args)
        if "run-code" not in args:
            return ""
        script_path = Path(args[args.index("--filename") + 1])
        rendered = script_path.read_text(encoding="utf-8")
        assert "__XFERRY_" not in rendered
        assert 'const baseUrl = "http://127.0.0.1:9876/";' in rendered
        assert "const externalTarget = true;" in rendered
        assert 'const smokeMode = "first-run";' in rendered
        assert "const unicodeUploadFilePath = " in rendered
        return json.dumps(
            {
                "journey": "first-run",
                "durationMs": 1234,
                "deletedFile": "browser-smoke-upload.txt",
            }
        )

    monkeypatch.setattr(browser_smoke, "_load_server_class", fail_load_server_class)
    monkeypatch.setattr(browser_smoke, "_LiveServer", ForbiddenLiveServer)
    monkeypatch.setattr(browser_smoke, "_playwright_command", lambda: ["fake-playwright"])
    monkeypatch.setattr(browser_smoke, "_run_playwright", fake_run_playwright)

    artifacts = tmp_path / "artifacts"
    result = browser_smoke.run_browser_smoke(
        mode="first-run",
        target_url="http://127.0.0.1:9876",
        artifacts_dir=artifacts,
    )

    assert result["externalTarget"] is True
    assert result["serverModulePath"] is None
    assert result["targetUrl"] == "http://127.0.0.1:9876/"
    assert result["smokeMode"] == "first-run"
    assert any("run-code" in call for call in calls)
    recorded = json.loads((artifacts / "first-run-result.json").read_text(encoding="utf-8"))
    assert recorded == result


def test_external_target_failure_is_labeled_and_persisted(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    def fake_run_playwright(
        base_cmd: list[str],
        session: str,
        *args: str,
        cwd: Path,
    ) -> str:
        del base_cmd, session, cwd
        if "run-code" in args:
            raise RuntimeError("semantic outcome missing")
        return ""

    monkeypatch.setattr(browser_smoke, "_playwright_command", lambda: ["fake-playwright"])
    monkeypatch.setattr(browser_smoke, "_run_playwright", fake_run_playwright)
    artifacts = tmp_path / "artifacts"

    with pytest.raises(RuntimeError, match=r"\[files\].*semantic outcome missing"):
        browser_smoke.run_browser_smoke(
            mode="files",
            target_url="http://127.0.0.1:9876/",
            artifacts_dir=artifacts,
        )

    failure = (artifacts / "files-failure.log").read_text(encoding="utf-8")
    assert "[files]" in failure
    assert "semantic outcome missing" in failure


def test_installed_package_and_external_target_are_mutually_exclusive() -> None:
    with pytest.raises(ValueError, match="cannot be combined"):
        browser_smoke.run_browser_smoke(
            installed_package=True,
            mode="first-run",
            target_url="http://127.0.0.1:8080/",
        )


def test_playwright_dispatcher_owns_every_mode_and_failure_artifacts() -> None:
    script = (REPO_ROOT / "tools/browser_smoke.playwright.js").read_text(encoding="utf-8")

    for mode in EXPECTED_MODES[:-1]:
        assert f'"{mode}"' in script
    assert "aggregateJourneys = Object.keys(namedJourneys)" in script
    assert "runHappyPath()" in script
    assert "runUnavailablePath()" in script
    assert "page.screenshot({" in script
    assert "${smokeMode}-failure.png" in script


def test_advanced_smoke_uses_per_tab_session_and_canonical_send() -> None:
    script = (REPO_ROOT / "tools/browser_smoke.playwright.js").read_text(encoding="utf-8")

    assert '"advanced-session": runAdvancedSessionJourney' in script
    assert "waitForAdvancedSessionReady" in script
    assert 'service("advanced-session")' in script
    assert '"X-XFerry-Advanced-Session"' in script
    assert 'parsedBody.encryption === "none"' in script
    assert "tokenAbsentFromDom" in script
    assert "tokenAbsentFromPreview" in script
    assert "tokenAbsentFromInspectorState" in script
    assert "tokenAbsentFromStorage" in script
    assert "tokenAbsentFromUrl" in script
    assert "tokenAbsentFromLogs" in script
    assert "/_xferry/advanced-routing" not in script
    assert "advanced-routing-race" not in script


def test_files_external_target_uses_targeted_cleanup_contract() -> None:
    script = (REPO_ROOT / "tools/browser_smoke.playwright.js").read_text(encoding="utf-8")

    assert "const externalTarget = __XFERRY_EXTERNAL_TARGET__;" in script
    assert "const unicodeUploadFilePath = __XFERRY_UNICODE_UPLOAD_FILE__;" in script
    assert "await uploadViaDom(unicodeUploadName, unicodeUploadFilePath);" in script
    assert 'cleanupMode = "targeted";' in script
    assert "await clearUploadsViaUiAndAssertSummaryPersistence();" in script
    assert "deletedArtifacts.push(unicodeUploadName);" in script
    assert "deletedArtifacts.push(uploadName);" in script
    assert "smugglePopupUrl," in script


def test_files_clear_browser_contract_uses_strict_target_and_real_request() -> None:
    """Catches Files clear drifting from the backend's strict boolean grammar."""
    script = (REPO_ROOT / "tools/browser_smoke.playwright.js").read_text(encoding="utf-8")

    assert 'clearRequestTarget !== "/uploads?clear=true"' in script
    assert "state.clearTargets.push(search);" in script
    assert 'search !== "?clear=true"' in script
    assert 'target !== "?clear=true"' in script


def test_smuggle_popup_cleanup_is_scoped_and_finally_guarded() -> None:
    script = (REPO_ROOT / "tools/browser_smoke.playwright.js").read_text(encoding="utf-8")

    assert "async function openSmuggleArtifactPopupAndAssert(" in script
    assert "async function assertNoLingeringSmugglePopupPages(" in script
    assert (
        "async function assertSmuggleArtifactPopupCompletes(popup, expectedName, options = {}) {"
        in script
    )
    assert "await assertNoLingeringSmugglePopupPages(" in script
    assert "await popup.close().catch(() => {});" in script

    helper_start = script.index(
        "async function assertSmuggleArtifactPopupCompletes(popup, expectedName, options = {}) {"
    )
    modal_helper_start = script.index(
        "async function smuggleViaModalAndAssert(name, encryption, options = {}) {"
    )
    helper_body = script[helper_start:modal_helper_start]
    assert "try {" in helper_body
    assert "} finally {" in helper_body
    assert "expectedContent = null" in helper_body
    assert "download.createReadStream()" in helper_body
    assert "TextDecoder" not in helper_body
    assert 'popup.locator("#smugglePassword")' in helper_body
    assert 'popup.locator("#downloadBtn")' in helper_body
    assert 'document.getElementById("smugglePasswordStatus")' in helper_body
    assert 'popup.locator("#p")' not in helper_body
    assert 'document.getElementById("m")' not in helper_body


def test_smuggle_popup_completion_accepts_known_localized_success_prefixes() -> None:
    """Catches the full smoke RU manual-start artifact status timing out."""
    script = (REPO_ROOT / "tools/browser_smoke.playwright.js").read_text(encoding="utf-8")
    helper_start = script.index(
        "async function assertSmuggleArtifactPopupCompletes(popup, expectedName, options = {}) {"
    )
    modal_helper_start = script.index(
        "async function smuggleViaModalAndAssert(name, encryption, options = {}) {"
    )
    helper_body = script[helper_start:modal_helper_start]

    assert "`Downloaded: ${expectedName}`" in helper_body
    assert "`Скачано: ${expectedName}`" in helper_body
    assert '"Download started"' in helper_body
    assert "acceptedSafeBuilderStatuses.includes(safeStatus.textContent)" in helper_body
    assert "safeStatus.textContent.includes(targetName)" not in helper_body


def test_full_smoke_checks_smuggle_and_file_details_as_independent_workflows() -> None:
    """Catches an accidental dependency between SMUGGLE state and Files details."""
    script = (REPO_ROOT / "tools/browser_smoke.playwright.js").read_text(encoding="utf-8")
    happy_path = script.split("async function runHappyPath() {", 1)[1].split(
        "async function runUnavailablePath() {", 1
    )[0]

    assert "const smugglePopupUrl = await smuggleViaServerFilesAndAssert(uploadName);" in happy_path
    assert 'const xorSmuggle = await smuggleViaModalAndAssert(uploadName, "xor");' in happy_path
    assert "const infoPath = await infoViaServerFilesAndAssert(uploadName);" in happy_path
    assert happy_path.index("const xorSmuggle") < happy_path.index("const infoPath")


def test_mobile_files_snapshot_serializes_automatic_browse_before_explicit_uploads_browse() -> None:
    """Catches the mobile geometry snapshot sampling a later automatic browse loading state."""
    script = (REPO_ROOT / "tools/browser_smoke.playwright.js").read_text(encoding="utf-8")
    start = script.index("async function assertMobileLayoutSnapshot(timeout = 10000) {")
    end = script.index("async function runFirstRunJourney() {", start)
    mobile_snapshot = script[start:end]

    generation_capture = (
        "const filesBrowseGenerationBeforeTabSwitch = await page.evaluate(() => (\n"
        '      window.XferryApp.getState("files").browseGeneration\n'
        "    ));"
    )
    automatic_browse_wait = (
        '"mobile Files automatic browse settles before explicit /uploads browse"'
    )
    files_tab_switch = 'await page.locator("#tab-files").click();'
    explicit_path_fill = 'await page.locator("#browsePathInput").fill("/uploads");'
    explicit_browse_click = 'await page.getByRole("button", { name: /^(Обзор|Browse)/ }).click();'

    assert generation_capture in mobile_snapshot
    assert automatic_browse_wait in mobile_snapshot
    assert explicit_path_fill in mobile_snapshot
    assert explicit_browse_click in mobile_snapshot
    assert mobile_snapshot.index(generation_capture) < mobile_snapshot.index(files_tab_switch)
    assert mobile_snapshot.index(files_tab_switch) < mobile_snapshot.index(automatic_browse_wait)
    assert mobile_snapshot.index(automatic_browse_wait) < mobile_snapshot.index(explicit_path_fill)
    assert mobile_snapshot.index(explicit_path_fill) < mobile_snapshot.index(explicit_browse_click)

    automatic_wait = mobile_snapshot[
        mobile_snapshot.index(automatic_browse_wait) : mobile_snapshot.index(explicit_path_fill)
    ]
    assert "state.browseGeneration > previousGeneration" in automatic_wait
    assert 'list?.dataset.browsePhase === "complete"' in automatic_wait
    assert 'list.getAttribute("aria-busy") === "false"' in automatic_wait
    assert 'status?.dataset.browsePhase === "complete"' in automatic_wait

    explicit_wait = mobile_snapshot[
        mobile_snapshot.index(explicit_browse_click) : mobile_snapshot.index(
            "const mobileFilesHeader = await page.evaluate",
            mobile_snapshot.index(explicit_browse_click),
        )
    ]
    assert 'pathInput?.value === "/uploads"' in explicit_wait
    assert 'list?.dataset.browsePhase === "complete"' in explicit_wait
    assert 'list.getAttribute("aria-busy") === "false"' in explicit_wait
    assert "visibleRows.length > 0" in explicit_wait
    assert "headerRect.width > 0" in explicit_wait
    assert "headerRect.height > 0" in explicit_wait


def test_full_smoke_locale_snapshots_use_exact_smuggle_labels_and_nonempty_actions() -> None:
    """The full locale oracle must match each localized Files action exactly."""
    script = (REPO_ROOT / "tools/browser_smoke.playwright.js").read_text(encoding="utf-8")
    happy_path = script.split("async function runHappyPath() {", 1)[1].split(
        "async function runUnavailablePath() {", 1
    )[0]
    labels = re.findall(r'smuggleActionLabelText: "([^"]+)"', happy_path)

    assert labels == ["HTML Smuggling", "HTML smuggling", "HTML Smuggling"]

    helper_start = script.index("async function assertLocaleSnapshot({")
    helper_end = script.index("async function waitForFilesSummaryText", helper_start)
    helper = script[helper_start:helper_end]
    assert (
        "return buttons.length > 0 && buttons.every((button) => "
        "button.textContent.trim() === expectedText);" in helper
    )


def test_full_smoke_advanced_request_export_oracle_proves_redaction_without_payload() -> None:
    """The full-only Advanced export must assert the safe redacted body shape."""
    script = (REPO_ROOT / "tools/browser_smoke.playwright.js").read_text(encoding="utf-8")
    journey_start = script.index(
        "async function uploadOpsecViaUiAndAssertMethodStable(fixturePath) {"
    )
    journey_end = script.index("async function createAutosavedNote", journey_start)
    journey = script[journey_start:journey_end]
    export_start = journey.index('await assertExchangeDownload(\n      "opsecRequestArea"')
    export_end = journey.index("    );", export_start) + len("    );")
    export_assertion = journey[export_start:export_end]

    assert '"data":"[redacted]"' in export_assertion
    assert "CHECKDATA ${opsecPreviewPath} HTTP/1.1" in export_assertion
    assert "'Content-Type: application/json'" in export_assertion
    assert "'X-XFerry-No-Gzip: 1'" in export_assertion
    assert '"encoding":"base64"' in export_assertion
    assert '"encryption":"none"' in export_assertion
    assert '["QUFBQUFBQUFB"]' in export_assertion
    assert '["[redacted]"' not in export_assertion


def test_smuggle_modal_helper_uses_canonical_builder_result() -> None:
    """The modal helper consumes the canonical SMUGGLE builder result for every cipher."""
    script = (REPO_ROOT / "tools/browser_smoke.playwright.js").read_text(encoding="utf-8")
    helper_signature = "async function smuggleViaModalAndAssert(name, encryption, options = {}) {"
    start = script.index(helper_signature)
    end = script.index("async function assertSmuggleDialogKeyboardContract", start)
    helper = script[start:end]

    assert "__smuggleResult?.encrypted" not in helper
    assert 'await chooseSmuggleCombobox("smuggleEncryption", encryption);' in helper
    assert 'await chooseSmuggleCombobox("smugglePreset", "card_manual");' in helper
    assert "manualStart: !passwordExpected" in helper
    assert "builder?.schema_version === 1" in helper
    assert "builder?.mode === expectedMode" in helper
    assert "builder?.encryption === encryption" in helper
    assert 'password: builder?.password || ""' in helper


def test_smuggle_mode_exercises_real_none_xor_and_aes_artifacts() -> None:
    """The isolated journey protects the browser-to-artifact SMUGGLE boundary."""
    script = (REPO_ROOT / "tools/browser_smoke.playwright.js").read_text(encoding="utf-8")
    start = script.index("async function runSmuggleJourney() {")
    end = script.index("async function runAdvancedSessionJourney()", start)
    journey = script[start:end]

    assert 'for (const encryption of ["none", "xor", "aes"])' in journey
    assert "await smuggleViaModalAndAssert(uploadName, encryption, {" in journey
    assert 'mode: "simple"' in journey
    assert 'smuggleViaModalAndAssert(uploadName, "aes", {' in journey
    assert 'mode: "constructor"' in journey
    assert "browser smoke upload\\n" in journey
    assert '"smuggle": runSmuggleJourney' in script

    request_assertion_start = script.index("function assertCapturedSmuggleRequestUrl(")
    request_assertion_end = script.index("async function", request_assertion_start + 1)
    request_assertion = script[request_assertion_start:request_assertion_end]
    for expected in (
        'params.get("mode") === expectedMode',
        'params.get("encryption") === expectedEncryption',
        'params.has("encrypt")',
        'params.has("use_constructor")',
        'params.has("b64")',
    ):
        assert expected in request_assertion
    assert "new URL(" not in request_assertion
    assert "URLSearchParams" not in request_assertion


def test_workflows_gate_source_wheel_image_and_preserve_diagnostics() -> None:
    ci = (REPO_ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    release = (REPO_ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")

    assert "Compact source and wheel browser journeys" in ci
    assert ci.count("--mode first-run") >= 2
    assert "--mode ui-contracts" in ci
    assert ci.count("--target-url") >= 3
    assert "xferry-browser-wheel-venv/bin/xferry" in ci
    assert "python -m xferry \\\n            run \\\n            --host 127.0.0.1" in ci
    assert (
        'xferry-browser-wheel-venv/bin/xferry" \\\n'
        "              run \\\n"
        "              --host 127.0.0.1"
    ) in ci
    assert "Full browser aggregate on main" in ci
    assert "--mode full" in ci
    assert "Upload browser journey diagnostics" in ci
    assert "if: always()" in ci

    build = _workflow_job(release, "build")
    image_verify = _workflow_job(release, "image-verify")
    publish_ghcr = _workflow_job(release, "publish-ghcr")

    assert "Installed wheel external first-run" in build
    assert "--mode first-run" in build
    assert "--target-url" in build
    assert "Installed wheel full browser aggregate" in build
    assert "--installed-package" in build
    assert "--mode full" in build
    assert "Upload wheel browser diagnostics" in build
    assert (
        'xferry-wheel-smoke/bin/xferry" \\\n              run \\\n              --host 127.0.0.1'
    ) in build

    assert "Hardened local image lifecycle smoke" in image_verify
    assert "--browser-first-run" in image_verify
    assert "Upload image browser diagnostics" in image_verify
    assert "docker/login-action" not in image_verify
    assert "docker/login-action@v3" in publish_ghcr
