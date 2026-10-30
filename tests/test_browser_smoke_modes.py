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


def test_browser_smoke_exposes_independent_journeys() -> None:
    assert browser_smoke.SMOKE_MODES == EXPECTED_MODES


def test_browser_cli_defaults_to_ci_pin_even_when_an_ambient_wrapper_exists(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("PWCLI", raising=False)
    monkeypatch.setattr(Path, "exists", lambda self: str(self).endswith("playwright_cli.sh"))
    monkeypatch.setattr(browser_smoke.shutil, "which", lambda name: "/usr/bin/npx")

    assert browser_smoke._playwright_command() == [
        "npx",
        "--yes",
        "--package",
        "@playwright/cli@0.1.9",
        "playwright-cli",
    ]


def test_browser_cli_preserves_an_explicit_wrapper_override(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    wrapper = tmp_path / "custom-browser-cli.sh"
    wrapper.write_text("#!/bin/sh\n", encoding="utf-8")
    monkeypatch.setenv("PWCLI", str(wrapper))
    monkeypatch.setattr(browser_smoke.shutil, "which", lambda name: None)

    assert browser_smoke._playwright_command() == ["bash", str(wrapper)]


@pytest.mark.parametrize(
    "output",
    [
        '{"journey":"full","happyPath":{}}',
        '### Result\n{"journey":"full"}\n{"unrelated":"diagnostic"}',
    ],
)
def test_browser_cli_parser_accepts_only_known_journey_receipts(output: str) -> None:
    assert browser_smoke._parse_playwright_json(output)["journey"] == "full"


@pytest.mark.parametrize(
    "output",
    [
        '{"data":"[redacted]","encryption":"none"}',
        '{"journey":"unknown"}',
        '### Error\nError: actual composite failure\n{"data":"[redacted]"}',
        '{"journey":"full"}\n### Error\nError: later failure',
    ],
)
def test_browser_cli_parser_rejects_error_frames_and_unrelated_json(output: str) -> None:
    with pytest.raises(RuntimeError, match="Playwright CLI"):
        browser_smoke._parse_playwright_json(output)


def test_encrypted_download_expectation_uses_the_browser_encoder_realm() -> None:
    node_script = r"""
const fs = require("node:fs");
const vm = require("node:vm");
const { TextEncoder: BrowserTextEncoder } = require("node:util");
const source = fs.readFileSync(process.argv[1], "utf8");
const start = source.indexOf("  async function runEncryptedTransferJourney() {");
const end = source.indexOf("    const encryptedRequests = [];", start);
if (start < 0 || end < 0) throw new Error("actual encrypted initializer missing");
let browserCalls = 0;
const sandbox = {
  fixtureName: () => "browser-smoke-upload.txt",
  uploadFilePath: "/fixture/browser-smoke-upload.txt",
  page: { evaluate: async callback => {
    browserCalls += 1;
    return vm.runInNewContext(`(${callback.toString()})()`, {
      TextEncoder: BrowserTextEncoder,
    });
  } },
};
if (vm.runInNewContext("typeof TextEncoder", sandbox) !== "undefined") {
  throw new Error("driver unexpectedly has an ambient encoder");
}
(async () => {
  const bytes = await vm.runInNewContext(
    `${source.slice(start, end)} return expectedDownload; }
runEncryptedTransferJourney();`, sandbox
  );
  const expected = Array.from(Buffer.from("browser smoke upload\n", "utf8"));
  if (browserCalls !== 1 || JSON.stringify(bytes) !== JSON.stringify(expected)) {
    throw new Error("actual initializer did not preserve exact browser UTF-8 bytes");
  }
  if (vm.runInNewContext("typeof TextEncoder", sandbox) !== "undefined") {
    throw new Error("browser encoder leaked into driver globals");
  }
})().catch(error => { console.error(error); process.exitCode = 1; });
"""
    completed = subprocess.run(
        ["node", "-e", node_script, str(REPO_ROOT / "tools/browser_smoke.playwright.js")],
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr


def test_encrypted_transfer_smoke_uses_real_ui_and_streaming_file_picker() -> None:
    """The browser journey must cross the real upload, unlock, and client-download UI."""
    script = (REPO_ROOT / "tools/browser_smoke.playwright.js").read_text(encoding="utf-8")

    start = script.index("async function runEncryptedTransferJourney() {")
    end = script.index("async function", start + 1)
    journey = script[start:end]
    assert '"encrypted-transfer": runEncryptedTransferJourney' in script
    assert 'page.locator("#encryptedFileInput").setInputFiles(uploadFilePath)' in journey
    assert 'page.locator("#encryptedUploadStartBtn").click()' in journey
    assert 'page.locator("#encryptedUnlockPasswordInput")' in journey
    assert 'data-encrypted-action="download-client"' in journey
    assert "showSaveFilePicker" in journey
    assert "createWritable" in journey
    assert "downloadedBytes" in journey
    assert 'requestPathname(request).includes("/_xferry/encrypted-")' in journey
    assert "const encryptedUploadName = fixtureName(uploadFilePath);" in journey
    assert "entry.name === targetName" in journey
    assert "[fileId, encryptedUploadName]" in journey
    assert 'entry.name === "browser-smoke-upload.txt"' not in journey


def test_home_tool_entry_oracle_accepts_only_exact_resolved_capability_tabs() -> None:
    """Run the real browser predicate for enabled and disabled encrypted fixtures."""
    node_script = r"""
const fs = require("node:fs");

const source = fs.readFileSync(process.argv[1], "utf8");
const contractStart = source.indexOf("  const topTabContract = [");
const contractEnd = source.indexOf("  const topTabLabels =", contractStart);
const helperStart = source.indexOf("  async function assertHomeToolEntryState(");
const helperEnd = source.indexOf("  async function assertHeroResponsePanelState(", helperStart);
if ([contractStart, contractEnd, helperStart, helperEnd].some(index => index < 0)) {
  throw new Error("home tool entry contract/helper is missing");
}
const contractSource = source.slice(contractStart, contractEnd);
const contract = new Function(`${contractSource}\nreturn topTabContract;`)();
const loadHelper = new Function("window", "document", "waitForPageCondition", `
${contractSource}
${source.slice(helperStart, helperEnd)}
return assertHomeToolEntryState;
`);

async function assertFixture(label, options, expected) {
  const enabled = options.enabled ?? true;
  const state = options.noState ? undefined : {
    enabled,
    capabilityStatus: options.capabilityStatus ?? (enabled ? "valid" : "disabled"),
  };
  const tabs = contract.map(tab => ({
    id: tab.id,
    dataset: { tabTarget: tab.target },
    hidden: Boolean(tab.optional && !enabled),
  }));
  if (options.mutateTabs) options.mutateTabs(tabs);
  const document = {
    querySelectorAll(selector) {
      if (selector === ".nav-card") return options.navCards ? [{}] : [];
      if (selector === '.tab[role="tab"][data-tab-target]') return tabs;
      throw new Error(`Unexpected selector: ${selector}`);
    },
  };
  const window = { XferryApp: { getState: workflow => {
    if (workflow !== "encrypted-transfer") throw new Error(`Unexpected workflow: ${workflow}`);
    return state;
  } } };
  let observed;
  let calls = 0;
  const helper = loadHelper(window, document, async (_label, predicate, arg, timeout) => {
    calls += 1;
    if (timeout !== 10000) throw new Error("home tool entry timeout changed");
    observed = predicate(arg);
  });
  await helper();
  if (calls !== 1 || observed !== expected) {
    throw new Error(`${label}: expected ${expected}, got ${observed} (${calls} calls)`);
  }
}

async function main() {
  await assertFixture("enabled capability shows six ordered tabs", {}, true);
  await assertFixture("disabled capability shows five ordered tabs", { enabled: false }, true);
  for (const capabilityStatus of ["pending", "invalid", "unavailable"]) {
    await assertFixture(`${capabilityStatus} cannot pass as hidden`, {
      enabled: false, capabilityStatus,
    }, false);
  }
  await assertFixture("missing workflow state rejected", { noState: true }, false);
  await assertFixture("valid capability cannot claim disabled", {
    enabled: false, capabilityStatus: "valid",
  }, false);
  await assertFixture("disabled capability cannot claim enabled", {
    enabled: true, capabilityStatus: "disabled",
  }, false);
  await assertFixture("missing required tab rejected", {
    mutateTabs: tabs => tabs.splice(2, 1),
  }, false);
  await assertFixture("missing hidden optional tab rejected", {
    enabled: false, mutateTabs: tabs => tabs.splice(1, 1),
  }, false);
  for (const hidden of [false, true]) {
    await assertFixture(`extra ${hidden ? "hidden" : "visible"} tab rejected`, {
      mutateTabs: tabs => tabs.push({ id: "tab-extra", dataset: { tabTarget: "extra" }, hidden }),
    }, false);
  }
  await assertFixture("reordered tabs rejected", {
    mutateTabs: tabs => { [tabs[2], tabs[3]] = [tabs[3], tabs[2]]; },
  }, false);
  await assertFixture("hidden required tab rejected", {
    mutateTabs: tabs => { tabs[2].hidden = true; },
  }, false);
  await assertFixture("enabled large-files tab must be visible", {
    mutateTabs: tabs => { tabs[1].hidden = true; },
  }, false);
  await assertFixture("disabled large-files tab must be hidden", {
    enabled: false, mutateTabs: tabs => { tabs[1].hidden = false; },
  }, false);
  await assertFixture("wrong tab id rejected", {
    mutateTabs: tabs => { tabs[2].id = "tab-other"; },
  }, false);
  await assertFixture("wrong tab target rejected", {
    mutateTabs: tabs => { tabs[2].dataset.tabTarget = "other"; },
  }, false);
  await assertFixture("duplicate home nav-card rejected", { navCards: true }, false);
}
main().catch(error => { console.error(error); process.exitCode = 1; });
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


def test_request_batch_issue_filter_requires_exact_locale_and_semantic_state() -> None:
    """Execute the actual predicate without depending on a previous journey's locale."""
    node_script = r"""
const fs = require("node:fs");
const source = fs.readFileSync(process.argv[1], "utf8");
const start = source.indexOf("  async function assertRequestBatchIssuesFilter(");
const end = source.indexOf("  async function assertRequestMethodButtonBatchState(", start);
if (start < 0 || end < 0) throw new Error("request batch issue-filter helper is missing");
const loadHelper = new Function("document", "waitForPageCondition", `
${source.slice(start, end)}
return assertRequestBatchIssuesFilter;
`);

async function assertFixture(label, options, expected) {
  const empty = options.noEmpty ? null : {
    textContent: options.emptyText ?? "All methods completed without issues.",
  };
  const summary = {
    dataset: {
      batchFilter: options.filter ?? "issues",
      batchVisibleCount: String(options.visibleCount ?? 0),
    },
    querySelector: selector => {
      if (selector !== ".request-batch-summary__empty") throw new Error(`Unexpected: ${selector}`);
      return empty;
    },
  };
  const document = {
    documentElement: { lang: options.lang ?? "en" },
    getElementById: id => {
      if (id === "requestBatchIssuesOnlyToggle") return { checked: options.checked ?? true };
      if (id === "requestBatchSummary") return summary;
      throw new Error(`Unexpected id: ${id}`);
    },
    querySelectorAll: selector => {
      if (selector !== "#requestBatchSummary .request-batch-summary__row") {
        throw new Error(`Unexpected selector: ${selector}`);
      }
      return Array.from({ length: options.rowCount ?? 0 }, () => ({}));
    },
  };
  let observed;
  const helper = loadHelper(document, async (_label, predicate, arg) => {
    observed = predicate(arg);
  });
  await helper(options.expectAll
    ? { checked: false, filter: "all", visibleCount: 0 }
    : { checked: true, filter: "issues", visibleCount: 0, expectNoIssues: true });
  if (observed !== expected) throw new Error(`${label}: expected ${expected}, got ${observed}`);
}

async function main() {
  await assertFixture("isolated English default", {}, true);
  await assertFixture("Russian composite", {
    lang: "ru", emptyText: "Все методы отработали без ошибок.",
  }, true);
  for (const lang of ["de", "en-US", "", "__proto__"]) {
    await assertFixture(`unknown locale ${lang}`, { lang }, false);
  }
  await assertFixture("English text in Russian UI", { lang: "ru" }, false);
  await assertFixture("Russian text in English UI", {
    emptyText: "Все методы отработали без ошибок.",
  }, false);
  await assertFixture("extra empty-state text", {
    emptyText: "All methods completed without issues. Extra text",
  }, false);
  await assertFixture("missing empty state", { noEmpty: true }, false);
  await assertFixture("wrong toggle", { checked: false }, false);
  await assertFixture("wrong filter", { filter: "all" }, false);
  await assertFixture("wrong visible count", { visibleCount: 1 }, false);
  await assertFixture("residual row", { rowCount: 1 }, false);
  await assertFixture("cleared all filter", {
    expectAll: true, checked: false, filter: "all", noEmpty: true,
  }, true);
  await assertFixture("cleared filter cannot retain empty state", {
    expectAll: true, checked: false, filter: "all",
  }, false);
}
main().catch(error => { console.error(error); process.exitCode = 1; });
"""
    completed = subprocess.run(
        ["node", "-e", node_script, str(REPO_ROOT / "tools/browser_smoke.playwright.js")],
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr or completed.stdout


def test_recovery_adapters_use_exact_basic_request_targets_not_storage_paths() -> None:
    """Execute the real adapter setups and their network/HTTP fixture declarations."""
    node_script = r"""
const fs = require("node:fs");
const source = fs.readFileSync(process.argv[1], "utf8");
const start = source.indexOf("  async function runRecoveryJourney() {");
const end = source.indexOf("  async function runFilesJourney() {", start);
if (start < 0 || end < 0) throw new Error("recovery journey is missing");
const journey = source.slice(start, end);
const firstMarker = "    const basicInitial = await page.evaluate(async () => {";
const firstStart = journey.indexOf(firstMarker) + firstMarker.length;
const firstEnd = journey.indexOf('      app.invoke("upload", "set-method"', firstStart);
const mainMarker = "    const recovery = await page.evaluate(async () => {";
const mainStart = journey.indexOf(mainMarker) + mainMarker.length;
const mainEnd = journey.indexOf("      const waitForUploadIdle =", mainStart);
const fixtureDeclarations = [...journey.matchAll(
  /      uploadFailureFixtures\.set\([\s\S]+?\n      \}\);/g
)].map(match => match[0]).join("\n");
if (firstEnd < 0 || mainEnd < 0 ||
    fixtureDeclarations.split("uploadFailureFixtures.set").length !== 4) {
  throw new Error("recovery adapter setup/three failure fixtures are missing");
}
function loadAdapter(setup, suffix) {
  let adapter;
  const http = { "set-adapter": next => { adapter = next; return () => {}; } };
  const window = { XferryApp: { service: name => {
    if (name !== "http") throw new Error(`Unexpected service: ${name}`);
    return http;
  } } };
  const state = new Function("window", "location", `${setup}\n${suffix}`)(
    window, { href: "http://127.0.0.1:9876/" }
  );
  return { adapter, state };
}
async function assertRejected(adapter, method, path) {
  try {
    await adapter(method, path);
  } catch (error) {
    if (error.message.includes("Unexpected recovery request:")) return;
    throw error;
  }
  throw new Error(`Unexpected recovery request was accepted: ${method} ${path}`);
}
async function main() {
  const initial = loadAdapter(journey.slice(firstStart, firstEnd), "return { calls };");
  const response = await initial.adapter("POST", "/upload/single-403.txt");
  const payload = await response.json();
  if (response.status !== 403 || response.statusText !== "Forbidden" ||
      payload.error.code !== "forbidden") {
    throw new Error("single upload fixture lost its real 403");
  }
  if (initial.state.calls[0].path !== "/upload/single-403.txt") throw new Error("wrong receipt");
  for (const [method, path] of [
    ["GET", "/upload/single-403.txt"], ["PUT", "/upload/single-403.txt"],
    ["POST", "/uploads/single-403.txt"], ["POST", "/upload/single-403.txt-extra"],
    ["POST", "/wrong?next=/upload/single-403.txt"],
  ]) await assertRejected(initial.adapter, method, path);

  const mainAdapter = loadAdapter(journey.slice(mainStart, mainEnd), `
${fixtureDeclarations}
return {
  uploadCalls, advancedRequests,
  fixturePaths: [...uploadFailureFixtures.keys()],
  enableAdvancedSuccess: () => { advancedRetryShouldSucceed = true; },
};
`);
  if (mainAdapter.state.fixturePaths.join(",") !==
      "/upload/status-zero.txt,/upload/status-mixed-zero.txt,/upload/status-mixed-forbidden.txt") {
    throw new Error("network/HTTP fixture keys still use storage routes");
  }
  for (const [path, message] of [
    ["/upload/status-zero.txt", "offline status zero"],
    ["/upload/status-mixed-zero.txt", "mixed offline"],
  ]) {
    let failed = false;
    try { await mainAdapter.adapter("POST", path); }
    catch (error) { failed = error.message === message; }
    if (!failed) throw new Error(`network failure fixture not selected: ${path}`);
  }
  const mixed403 = await mainAdapter.adapter("POST", "/upload/status-mixed-forbidden.txt");
  if (mixed403.status !== 403 || (await mixed403.json()).error.message !== "mixed forbidden") {
    throw new Error("mixed HTTP failure fixture not selected");
  }
  for (const path of [
    "/upload/single-403.txt", "/upload/all-failed-a.txt", "/upload/all-failed-b.txt",
  ]) {
    if ((await mainAdapter.adapter("POST", path)).status !== 403) {
      throw new Error(`lost 403: ${path}`);
    }
  }
  for (const [method, path] of [
    ["GET", "/upload/all-failed-a.txt"], ["PUT", "/upload/status-zero.txt"],
    ["POST", "/uploads/status-zero.txt"], ["POST", "/upload/unexpected.txt"],
    ["POST", "/upload/all-failed-a.txt-extra"],
  ]) await assertRejected(mainAdapter.adapter, method, path);
  await mainAdapter.adapter("POST", "/upload/all-failed-a.txt");
  const retryPath = mainAdapter.state.uploadCalls.at(-1);
  const retryOracles = [...journey.matchAll(
    /recovery\.(?:retryOnlyCalls|retryCardOnlyCalls)\.join\(","\) !== "([^"]+)"/g
  )].map(match => match[1]);
  if (retryOracles.length !== 2 || retryOracles.some(path => path !== retryPath)) {
    throw new Error("retry oracles disagree with the actual basic request receipt");
  }
  mainAdapter.state.enableAdvancedSuccess();
  const advanced = await mainAdapter.adapter("CHECKDATA", "/advanced/retry-succeeded");
  if ((await advanced.json()).file.path !== "/uploads/retry-succeeded.bin") {
    throw new Error("stored-file response route must remain under /uploads");
  }
}
main().catch(error => { console.error(error); process.exitCode = 1; });
"""
    completed = subprocess.run(
        ["node", "-e", node_script, str(REPO_ROOT / "tools/browser_smoke.playwright.js")],
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr or completed.stdout


def test_http_error_fixtures_wait_for_current_successful_files_browse() -> None:
    """The synthetic card must not race the real automatic browse that closes old cards."""
    script = (REPO_ROOT / "tools/browser_smoke.playwright.js").read_text(encoding="utf-8")
    journey = script.split("async function runHttpErrorsJourney() {", 1)[1].split(
        "async function runRecoveryJourney() {", 1
    )[0]
    ready_call = "await activateFilesAndWaitForSettledBrowse();"
    assert journey.count(ready_call) == 2
    assert journey.index(ready_call) < journey.index("const truncation = await page.evaluate")
    assert journey.rindex(ready_call) < journey.index("window.__xferryHttpErrorOriginalXhr =")

    node_script = r"""
const fs = require("node:fs");
const source = fs.readFileSync(process.argv[1], "utf8");
const start = source.indexOf("  async function activateFilesAndWaitForSettledBrowse() {");
const end = source.indexOf("  async function clearUploadsViaUiAndAssertSummaryPersistence(", start);
if (start < 0 || end < 0) throw new Error("Files activation lifecycle helper is missing");
const loadHelper = new Function(
  "window", "document", "page", "waitForTabState", "waitForPageCondition", `
${source.slice(start, end)}
return activateFilesAndWaitForSettledBrowse;
`);
async function assertFixture(label, options, expected) {
  let generation = 8;
  const window = { XferryApp: { getState: workflow => {
    if (workflow !== "files") throw new Error(`Unexpected workflow: ${workflow}`);
    return { browseGeneration: generation };
  } } };
  const list = {
    dataset: { browsePhase: options.listPhase ?? "complete", stale: options.stale ?? "false" },
    getAttribute: name => {
      if (name !== "aria-busy") throw new Error(`Unexpected attribute: ${name}`);
      return options.busy ?? "false";
    },
  };
  const document = {
    getElementById: id => {
      if (id === "filesBrowseStatus") return options.noStatus ? null : {
        dataset: { browsePhase: options.statusPhase ?? "complete" },
      };
      if (id === "serverFiles") return options.noList ? null : list;
      throw new Error(`Unexpected id: ${id}`);
    },
    querySelector: selector => {
      if (selector !== "#filesHttpErrorHost .http-error-card") {
        throw new Error(`Unexpected selector: ${selector}`);
      }
      return options.errorCard ? {} : null;
    },
  };
  const page = {
    evaluate: callback => callback(),
    locator: selector => {
      if (selector !== "#tab-files") throw new Error(`Unexpected locator: ${selector}`);
      return { click: async () => { generation = options.generation ?? 9; } };
    },
  };
  let observed;
  const helper = loadHelper(window, document, page, async (tab, options) => {
    if (tab !== "files" || !options.focused) throw new Error("Files activation/focus changed");
  }, async (_label, predicate, arg, timeout) => {
    if (arg[0] !== 8 || timeout !== 15000) throw new Error("generation/timeout contract changed");
    observed = predicate(arg);
  });
  await helper();
  if (observed !== expected) throw new Error(`${label}: expected ${expected}, got ${observed}`);
}
async function main() {
  await assertFixture("current successful browse settled", {}, true);
  for (const [label, options] of [
    ["old success before scheduled browse", { generation: 8 }],
    ["invalid generation", { generation: 8.5 }],
    ["loading status", { statusPhase: "loading" }],
    ["failed status", { statusPhase: "error" }],
    ["loading list", { listPhase: "loading" }],
    ["busy list", { busy: "true" }],
    ["disabled stale actions", { stale: "true" }],
    ["existing error card", { errorCard: true }],
    ["missing list", { noList: true }],
    ["missing status", { noStatus: true }],
  ]) await assertFixture(label, options, false);
}
main().catch(error => { console.error(error); process.exitCode = 1; });
"""
    completed = subprocess.run(
        ["node", "-e", node_script, str(REPO_ROOT / "tools/browser_smoke.playwright.js")],
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr or completed.stdout


def test_successful_runtime_files_browse_closes_the_previous_error_card() -> None:
    """Execute the real validated-success branch, preserving its legitimate card cleanup."""
    node_script = r"""
const fs = require("node:fs");
const source = fs.readFileSync(process.argv[1], "utf8");
const start = source.indexOf("        filesState.lastSuccessfulPath = path;");
const end = source.indexOf("        return true;", start) + "        return true;".length;
if (start < 0 || end <= start) throw new Error("Files browse success branch is missing");
const runSuccess = new Function(
  "filesState", "path", "info", "setFilesListActionsDisabled", "renderServerFiles", "httpErrors",
  "formatFilesBrowseSummary", "setFilesBrowseStatus", "suppressLiveAnnouncements",
  "announceLiveRegion", "response", source.slice(start, end)
);
for (const contents of [[], [{ name: "a.txt" }]]) {
  const filesState = {};
  let cardPresent = true;
  let actionsDisabled = true;
  let settled = false;
  const result = runSuccess(
    filesState, "/uploads", { entry: { kind: "directory" }, contents,
      page: { total_items: contents.length } },
    disabled => { actionsDisabled = disabled; },
    (items, path, options) => {
      if (path !== "/uploads" || items.length !== contents.length || actionsDisabled) {
        throw new Error("successful list was not enabled before rendering");
      }
      if (options.phase !== (contents.length ? "complete" : "empty")) {
        throw new Error("wrong list phase");
      }
    },
    { close: host => {
      if (host !== "filesHttpErrorHost") throw new Error("wrong error-card host");
      cardPresent = false;
    } },
    () => "Files loaded",
    (message, options) => {
      if (cardPresent || options.phase !== "complete" || options.busy) {
        throw new Error("successful browse must clear the card before reporting ready");
      }
      settled = true;
    },
    false,
    (region, text) => {
      if (region !== "filesResponseAreaLive" || text !== "INFO /uploads 200 OK") {
        throw new Error("successful INFO receipt changed");
      }
    },
    { status: 200, statusText: "OK" }
  );
  if (result !== true || !settled || cardPresent || actionsDisabled) {
    throw new Error("successful browse lifecycle is incomplete");
  }
}
"""
    completed = subprocess.run(
        ["node", "-e", node_script, str(REPO_ROOT / "xferry/data/static/ui/files.js")],
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr or completed.stdout


def test_file_menu_clean_state_and_cancel_focus_oracle_observe_without_hiding() -> None:
    """The browser must detect leaked menus, not hide them before testing other rows."""
    script = (REPO_ROOT / "tools/browser_smoke.playwright.js").read_text(encoding="utf-8")
    disclosure = script.split("async function assertFileDisclosureInteractions(", 1)[1].split(
        "async function chooseSmuggleCombobox(", 1
    )[0]
    precondition = 'await assertFileActionMenusClosed("file disclosure interactions start'
    assert disclosure.index(precondition) < disclosure.index("await firstSummary.click();")
    combobox = script.split("async function assertSmuggleSearchableComboboxContract(", 1)[1].split(
        "async function assertSmuggleReservedEncodingAndModeState(", 1
    )[0]
    assert combobox.index('page.locator("#smuggleCancelBtn").click()') < combobox.index(
        "await assertFileActionMenusClosed("
    )
    assert combobox.index('modal.waitFor({ state: "detached"') < combobox.index(
        "await assertFileActionMenusClosed("
    )

    node_script = r"""
const fs = require("node:fs");
const source = fs.readFileSync(process.argv[1], "utf8");
const start = source.indexOf("  async function assertFileActionMenusClosed(");
const end = source.indexOf("  async function assertFileDisclosureInteractions(", start);
if (start < 0 || end < 0) throw new Error("file-menu lifecycle oracle is missing");
const loadHelper = new Function("document", "waitForPageCondition", `
${source.slice(start, end)}
return assertFileActionMenusClosed;
`);
async function assertFixture(label, options, expected) {
  const path = encodeURIComponent("/uploads/a.txt");
  const menu = { open: options.openCount > 0, querySelector: selector => {
    if (selector !== `[data-file-action="smuggle"][data-path="${path}"]`) {
      throw new Error(`Unexpected selector: ${selector}`);
    }
    return options.wrongFile ? null : {};
  } };
  const document = {
    activeElement: options.noFocus ? null : {
      matches: selector => {
        if (selector !== ".file-row__more > summary") throw new Error(`Unexpected: ${selector}`);
        return !options.wrongFocus;
      },
      closest: selector => {
        if (selector !== ".file-row__more") throw new Error(`Unexpected: ${selector}`);
        return menu;
      },
    },
    querySelectorAll: selector => {
      if (selector !== "#serverFiles .file-row__more[open]") {
        throw new Error(`Unexpected: ${selector}`);
      }
      return Array.from({ length: options.openCount ?? 0 }, () => menu);
    },
  };
  let observed;
  const helper = loadHelper(document, async (_label, predicate, arg) => {
    observed = predicate(arg);
  });
  await helper(label, options.precondition ? null : path);
  if (observed !== expected) throw new Error(`${label}: expected ${expected}, got ${observed}`);
  if (menu.open !== (options.openCount > 0)) throw new Error("oracle hid the leaked menu");
}
async function main() {
  await assertFixture("closed menus after cancel and correct summary focus", {}, true);
  await assertFixture("closed precondition needs no focus", {
    precondition: true, noFocus: true,
  }, true);
  await assertFixture("precondition rejects leaked menu", {
    precondition: true, openCount: 1,
  }, false);
  await assertFixture("cancel rejects leaked menu", { openCount: 1 }, false);
  await assertFixture("cancel rejects missing focus", { noFocus: true }, false);
  await assertFixture("cancel rejects action-button focus", { wrongFocus: true }, false);
  await assertFixture("cancel rejects another row summary", { wrongFile: true }, false);
}
main().catch(error => { console.error(error); process.exitCode = 1; });
"""
    completed = subprocess.run(
        ["node", "-e", node_script, str(REPO_ROOT / "tools/browser_smoke.playwright.js")],
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr or completed.stdout


def test_mobile_menu_closed_and_inflow_guards_preserve_strict_geometry() -> None:
    """Execute the exact closed/open guards, allowing only intended expanded wrapping."""
    source = (REPO_ROOT / "tools/browser_smoke.playwright.js").read_text(encoding="utf-8")
    assert source.index("const closedActionLayout =") < source.index(
        'await mobileDisclosure.locator(":scope > summary").click();'
    )
    assert 'await assertFileMenuContainedInRow(mobileFileName, "mobile compact explorer"' in source
    node_script = r"""
const fs = require("node:fs");
const source = fs.readFileSync(process.argv[1], "utf8");
function guard(name, endMarker) {
  const prefix = name === "closedActionLayout" ? "!" : "";
  const start = source.indexOf(`    if (\n      ${prefix}${name}.`);
  const end = source.indexOf(endMarker, start);
  if (start < 0 || end < 0) throw new Error(`missing actual ${name} guard`);
  return new Function(name, source.slice(start, end));
}
const closedGuard = guard("closedActionLayout", "    const closedRowHeight =");
const openGuard = guard("fileActionLayout", "    await page.screenshot({");
const closed = {
  controlsAligned: true, controlsMeetTouchTarget: true,
  hasOverflow: false, documentOverflow: false,
};
const expanded = {
  beforeHeight: 100, afterHeight: 300, secondaryPosition: "static",
  panelMatchesActionArea: true, panelBelowActionRow: true,
  hasOverflow: false, documentOverflow: false,
  actionRects: [{ width: 44, height: 44 }],
};
function expectRejected(check, fixture, label) {
  try { check(fixture); } catch { return; }
  throw new Error(`${label} was accepted`);
}
closedGuard(closed);
openGuard(expanded);
for (const key of ["controlsAligned", "controlsMeetTouchTarget"]) {
  expectRejected(closedGuard, { ...closed, [key]: false }, key);
}
for (const key of ["hasOverflow", "documentOverflow"]) {
  expectRejected(closedGuard, { ...closed, [key]: true }, `closed ${key}`);
  expectRejected(openGuard, { ...expanded, [key]: true }, `expanded ${key}`);
}
for (const key of ["panelMatchesActionArea", "panelBelowActionRow"]) {
  expectRejected(openGuard, { ...expanded, [key]: false }, key);
}
expectRejected(openGuard, { ...expanded, secondaryPosition: "absolute" }, "overlay");
expectRejected(openGuard, { ...expanded, afterHeight: 100 }, "no reserved row height");
expectRejected(openGuard, { ...expanded, actionRects: [] }, "missing menu controls");
for (const key of ["width", "height"]) {
  expectRejected(openGuard, {
    ...expanded, actionRects: [{ width: 44, height: 44, [key]: 43 }],
  }, `undersized ${key}`);
}
"""
    completed = subprocess.run(
        ["node", "-e", node_script, str(REPO_ROOT / "tools/browser_smoke.playwright.js")],
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stderr or completed.stdout


def test_file_disclosure_pointer_lifecycle_runs_at_desktop_and_mobile_sizes() -> None:
    """Keep the original pointer transition and restore viewport even after failure."""
    script = (REPO_ROOT / "tools/browser_smoke.playwright.js").read_text(encoding="utf-8")
    interaction = script.split("async function assertFileDisclosureInteractionsAtViewport(", 1)[
        1
    ].split("async function chooseSmuggleCombobox(", 1)[0]
    first_click = "await firstSummary.click();"
    second_click = "await secondSummary.click();"
    first_geometry = "await assertFileMenuContainedInRow(firstName, viewportLabel);"
    second_geometry = "await assertFileMenuContainedInRow(secondName, viewportLabel);"
    assert interaction.index(first_click) < interaction.index(first_geometry)
    assert interaction.index(first_geometry) < interaction.index(second_click)
    assert interaction.index(second_click) < interaction.index(second_geometry)
    assert "secondSummary.focus()" not in interaction
    assert "secondSummary.press(" not in interaction
    assert "force:" not in interaction
    assert "open = false" not in interaction
    assert "Escape closes file disclosure and keeps summary focus" in interaction
    assert (
        "clicking another row control closes the open file disclosure without details"
        in interaction
    )
    assert "clicking outside the file list closes the open disclosure" in interaction

    node_script = r"""
const fs = require("node:fs");
const source = fs.readFileSync(process.argv[1], "utf8");
const start = source.indexOf("  async function assertFileDisclosureInteractions(");
const end = source.indexOf("  async function assertFileDisclosureInteractionsAtViewport(", start);
if (start < 0 || end < 0) throw new Error("responsive disclosure lifecycle wrapper is missing");
const loadWrapper = new Function("page", "assertFileDisclosureInteractionsAtViewport", `
${source.slice(start, end)}
return assertFileDisclosureInteractions;
`);
async function check(failOnMobile) {
  const original = { width: 1100, height: 900 };
  const changes = [];
  const runs = [];
  let viewport = original;
  const page = {
    viewportSize: () => viewport,
    setViewportSize: async next => { changes.push(next); viewport = next; },
  };
  const wrapper = loadWrapper(page, async (firstName, secondName, label) => {
    if (firstName !== "a.txt" || secondName !== "b.txt") {
      throw new Error("fixture identity changed");
    }
    runs.push({ label, ...viewport });
    if (failOnMobile && label === "mobile") throw new Error("mobile geometry failed");
  });
  let failure;
  try { await wrapper("a.txt", "b.txt"); } catch (error) { failure = error.message; }
  if (JSON.stringify(runs) !== JSON.stringify([
    { label: "desktop", width: 1440, height: 1024 },
    { label: "mobile", width: 390, height: 844 },
  ])) throw new Error(`wrong viewport coverage: ${JSON.stringify(runs)}`);
  if (changes.length !== 3 || viewport !== original) throw new Error("viewport was not restored");
  if (failure !== (failOnMobile ? "mobile geometry failed" : undefined)) {
    throw new Error("responsive failure was swallowed or invented");
  }
}
Promise.resolve().then(() => check(false)).then(() => check(true))
  .catch(error => { console.error(error); process.exitCode = 1; });
"""
    completed = subprocess.run(
        ["node", "-e", node_script, str(REPO_ROOT / "tools/browser_smoke.playwright.js")],
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr or completed.stdout


def test_file_menu_geometry_oracle_rejects_row_control_and_viewport_overlap() -> None:
    """Execute the real geometry predicate without changing or hiding any menu."""
    node_script = r"""
const fs = require("node:fs");
const source = fs.readFileSync(process.argv[1], "utf8");
const start = source.indexOf("  async function assertFileMenuContainedInRow(");
const end = source.indexOf("  async function assertFileDisclosureInteractions(", start);
if (start < 0 || end < 0) throw new Error("file-menu geometry oracle is missing");
const loadHelper = new Function(
  "page", "window", "document", "waitForPageCondition", "getComputedStyle", `
${source.slice(start, end)}
return assertFileMenuContainedInRow;
`);
function rect(left, top, right, bottom) {
  return { left, top, right, bottom, width: right - left, height: bottom - top };
}
async function assertFixture(label, options, expected) {
  const width = options.mobile ? 390 : 800;
  const height = options.mobile ? 844 : 600;
  const path = encodeURIComponent(options.storedPath ?? "/uploads/a.txt");
  const actionSelector = `#serverFiles [data-file-action="smuggle"][data-path="${path}"]`;
  const panelRect = options.panelRect ?? rect(20, 100, width - 30, 400);
  const row = { getBoundingClientRect: () => options.rowRect ?? rect(10, 10, width - 20, 420) };
  const panel = { getBoundingClientRect: () => panelRect };
  const menu = {
    open: !options.closed,
    closest: selector => {
      if (selector !== ".uploaded-file--file") throw new Error(`Unexpected: ${selector}`);
      return row;
    },
    querySelector: selector => {
      if (selector !== ":scope > .file-row__actions-secondary") {
        throw new Error(`Unexpected: ${selector}`);
      }
      return panel;
    },
  };
  const otherRow = { className: options.directory ? "uploaded-file--dir" : "uploaded-file--file",
    querySelectorAll: selector => {
    const expected = ".file-row__more > summary, .file-select, " +
      ".file-row__action-main, [data-file-details-trigger]";
    if (selector !== expected) {
      throw new Error(`Unexpected controls: ${selector}`);
    }
    return [{ getBoundingClientRect: () => options.coveredControl
      ? rect(30, 120, 74, 164) : rect(30, 440, 74, 484) }];
  } };
  const document = {
    documentElement: { clientWidth: width, scrollWidth: options.documentWidth ?? width },
    body: { scrollWidth: options.bodyWidth ?? width },
    querySelector: selector => {
      if (selector !== actionSelector) throw new Error(`Unexpected action: ${selector}`);
      return options.noAction ? null : { closest: target => {
        if (target !== ".file-row__more") throw new Error(`Unexpected: ${target}`);
        return menu;
      } };
    },
    querySelectorAll: selector => {
      if (selector === "#serverFiles .uploaded-file--file" && options.directory) {
        return [row];
      }
      if (selector !== "#serverFiles .uploaded-file") {
        throw new Error(`Unexpected: ${selector}`);
      }
      return [row, otherRow];
    },
  };
  let scrolls = 0;
  const locator = {
    first() { return this; },
    locator(selector) {
      if (![
        "xpath=ancestor::details[1]", ":scope > .file-row__actions-secondary",
      ].includes(selector)) {
        throw new Error(`Unexpected locator: ${selector}`);
      }
      return this;
    },
    async scrollIntoViewIfNeeded(options) {
      if (options.timeout !== 10000) throw new Error("geometry timeout changed");
      scrolls += 1;
    },
  };
  const page = { locator: selector => {
    if (selector !== actionSelector) throw new Error(`Unexpected locator: ${selector}`);
    return locator;
  } };
  let observed;
  const helper = loadHelper(page, { innerHeight: height }, document,
    async (_label, predicate, arg, timeout) => {
      if (timeout !== 10000) throw new Error("geometry timeout changed");
      observed = predicate(arg);
    },
    (element) => {
      if (element !== panel) throw new Error("wrong style target");
      return { position: options.position ?? "static" };
    }
  );
  await helper("a.txt", options.mobile ? "mobile" : "desktop", 10000, options.storedPath);
  if (observed !== expected) throw new Error(`${label}: expected ${expected}, got ${observed}`);
  if (scrolls !== 1 || menu.open !== !options.closed) {
    throw new Error("oracle changed menu state");
  }
}
async function main() {
  await assertFixture("desktop in-flow menu", {}, true);
  await assertFixture("mobile in-flow menu", { mobile: true }, true);
  await assertFixture("exact non-uploads fixture path", {
    storedPath: "/compact-contract/a.txt",
  }, true);
  await assertFixture("unicode fixture path", {
    storedPath: "/compact-contract/кириллица #1.bin",
  }, true);
  await assertFixture("absolute panel with artificial row space", { position: "absolute" }, false);
  await assertFixture("panel extends below its row", {
    rowRect: rect(10, 10, 780, 350),
  }, false);
  await assertFixture("panel extends above its row", {
    rowRect: rect(10, 150, 780, 420),
  }, false);
  await assertFixture("panel extends beyond row width", {
    rowRect: rect(50, 10, 600, 420),
  }, false);
  await assertFixture("panel covers another row control", { coveredControl: true }, false);
  await assertFixture("panel covers directory row control", {
    directory: true, coveredControl: true,
  }, false);
  await assertFixture("document horizontal overflow", { documentWidth: 802 }, false);
  await assertFixture("body horizontal overflow", { bodyWidth: 802 }, false);
  await assertFixture("panel extends beyond viewport width", {
    rowRect: rect(10, 10, 1000, 420), panelRect: rect(20, 100, 900, 400),
  }, false);
  await assertFixture("panel extends below viewport", {
    rowRect: rect(10, 10, 780, 750), panelRect: rect(20, 100, 770, 700),
  }, false);
  await assertFixture("hidden panel", { panelRect: rect(20, 100, 20, 400) }, false);
  await assertFixture("closed menu", { closed: true }, false);
  await assertFixture("missing action", { noAction: true }, false);
}
main().catch(error => { console.error(error); process.exitCode = 1; });
"""
    completed = subprocess.run(
        ["node", "-e", node_script, str(REPO_ROOT / "tools/browser_smoke.playwright.js")],
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr or completed.stdout


def test_files_overflow_contract_executes_inflow_geometry_and_exact_semantics() -> None:
    """Execute the UI journey's actual predicate for every locale/size/style."""
    source = (REPO_ROOT / "tools/browser_smoke.playwright.js").read_text(encoding="utf-8")
    contract = source.split("async function assertFileOverflowMenuContract(", 1)[1].split(
        "const responsiveStates =", 1
    )[0]
    assert contract.index("const closedGeometry =") < contract.index("details.open = true;")
    assert contract.index("if (!valid)") < contract.index("await assertFileMenuContainedInRow(")
    assert "`/compact-contract/${longName}`" in contract
    node_script = r"""
const fs = require("node:fs");
const source = fs.readFileSync(process.argv[1], "utf8");
const helperStart = source.indexOf("    async function assertFileOverflowMenuContract(");
const start = source.indexOf("      const actionOrder = menu.actions.map", helperStart);
const end = source.indexOf("      if (!valid) {", start);
if (helperStart < 0 || start < 0 || end < 0) throw new Error("UI overflow predicate missing");
const predicate = new Function("menu", "expected", "width", "longName",
  source.slice(start, end) + "\nreturn Boolean(valid);");
const name = "long-name.txt";
const copy = {
  en: {
    trigger: "More actions",
    actions: [["decrypt-xor", "Download with XOR decryption"],
      ["smuggle", "HTML smuggling"], ["delete", "Delete file"]],
    xorHint: "Format not recognized; try only if XOR was used",
  },
  ru: {
    trigger: "Дополнительные действия",
    actions: [["decrypt-xor", "Скачать с XOR-расшифровкой"],
      ["smuggle", "HTML Smuggling"], ["delete", "Удалить файл"]],
    xorHint: "Формат не распознан: пробуйте, только если использовался XOR.",
  },
};
function rect(left, top, right, bottom) {
  return { left, top, right, bottom, width: right-left, height: bottom-top };
}
function fixture(width, locale, theme) {
  const mobile = width <= 640;
  const expected = copy[locale];
  const panel = mobile ? rect(38,250,352,500) : rect(1100,180,1380,430);
  const top = panel.top + 10;
  const danger = theme === "light" ? "rgb(153, 27, 27)" : "rgb(255, 107, 114)";
  return {
    closedGeometry: {
      menuClosed: true, rowHeight: 80, controlsAligned: true, controlsMeetTouchTarget: true,
    },
    triggerText: "⋮", triggerName: `${expected.trigger}: ${name}`,
    triggerRect: mobile ? rect(308,198,352,242) : rect(1336,132,1380,176),
    panelRect: panel,
    actions: expected.actions.map(([action,text], index) => ({
      action, text,
      rect: rect(panel.left+9, top+[0,98,159][index], panel.right-9, top+[54,142,203][index]),
    })),
    separator: {semantic:true,rect:rect(panel.left+9,top+150,panel.right-9,top+151)},
    downloadRect: mobile ? rect(38,132,352,176) : rect(986,132,1090,176),
    actionsRect: mobile ? rect(38,132,352,500) : rect(700,132,1380,430),
    rowRect: mobile ? rect(27,120,363,520) : rect(40,120,1400,450),
    panelPosition: "static", panelColumns: 1,
    neutralStyle: {color:"neutral",borderColor:"neutral-border"},
    xorAction: {caution:true,describedBy:"xor-hint",color:"caution",borderColor:"caution-border"},
    xorHint: {id:"xor-hint",text:expected.xorHint,
      rect:rect(panel.left+9,top+60,panel.right-9,top+90)},
    deleteStyle: {color:danger,borderColor:danger},
    accentDangerStyle: {color:danger,borderColor:danger},
    listOverflow:false,rowOverflow:false,documentOverflow:false,
    removedInfoActionCount:0,compact:mobile,
  };
}
const negatives = {
  "overlay": m=>{m.panelPosition="absolute";},
  "menu already open": m=>{m.closedGeometry.menuClosed=false;},
  "closed misalignment": m=>{m.closedGeometry.controlsAligned=false;},
  "closed undersized controls": m=>{m.closedGeometry.controlsMeetTouchTarget=false;},
  "no reserved height": m=>{m.rowRect.height=m.closedGeometry.rowHeight;},
  "columns": m=>{m.panelColumns=2;},
  "outside row left": m=>{m.rowRect.left=m.panelRect.left+2;},
  "outside row right": m=>{m.rowRect.right=m.panelRect.right-2;},
  "outside row top": m=>{m.rowRect.top=m.panelRect.top+2;},
  "outside row bottom": m=>{m.rowRect.bottom=m.panelRect.bottom-2;},
  "panel covers More": m=>{m.triggerRect.bottom=m.panelRect.top+2;},
  "panel covers Download": m=>{m.downloadRect.bottom=m.panelRect.top+2;},
  "trigger text": m=>{m.triggerText="?";},
  "trigger label": m=>{m.triggerName="More actions: another.txt";},
  "old INFO action": m=>{m.removedInfoActionCount=1;},
  "action order": m=>{m.actions.reverse();},
  "missing action": m=>{m.actions.pop();},
  "extra action": m=>{m.actions.push({...m.actions[2],action:"info"});},
  "wrong action copy": m=>{m.actions[0].text="wrong locale";},
  "nonvertical items": m=>{m.actions[1].rect.top=m.actions[0].rect.bottom-2;},
  "undersized item width": m=>{m.actions[0].rect.width=43;},
  "undersized item height": m=>{m.actions[0].rect.height=43;},
  "unequal item widths": m=>{m.actions[1].rect.width-=2;},
  "item outside left": m=>{m.actions[0].rect.left=m.panelRect.left-2;},
  "item outside right": m=>{m.actions[0].rect.right=m.panelRect.right+2;},
  "undersized More width": m=>{m.triggerRect.width=43;},
  "undersized More height": m=>{m.triggerRect.height=43;},
  "missing XOR action": m=>{m.xorAction=null;},
  "not caution": m=>{m.xorAction.caution=false;},
  "unlinked XOR hint": m=>{m.xorAction.describedBy="another-hint";},
  "missing XOR hint": m=>{m.xorHint=null;},
  "wrong XOR copy": m=>{m.xorHint.text="wrong locale";},
  "XOR hint outside left": m=>{m.xorHint.rect.left=m.panelRect.left-2;},
  "XOR hint outside right": m=>{m.xorHint.rect.right=m.panelRect.right+2;},
  "missing separator": m=>{m.separator=null;},
  "nonsemantic separator": m=>{m.separator.semantic=false;},
  "separator above Smuggle": m=>{m.separator.rect.top=m.actions[1].rect.bottom-2;},
  "separator below Delete": m=>{m.separator.rect.bottom=m.actions[2].rect.top+2;},
  "wrong danger color": m=>{m.deleteStyle.color="not-accent";},
  "wrong danger border": m=>{m.deleteStyle.borderColor="not-accent";},
  "neutral danger": m=>{m.neutralStyle={...m.deleteStyle};},
  "missing danger style": m=>{m.deleteStyle=null;},
  "list overflow": m=>{m.listOverflow=true;},
  "row overflow": m=>{m.rowOverflow=true;},
  "document overflow": m=>{m.documentOverflow=true;},
};
for(const width of [1440,390]) for(const locale of ["ru","en"])
for(const theme of ["dark","light"]) {
  const menu=fixture(width,locale,theme);
  if(!predicate(menu,copy[locale],width,name)) throw new Error(`valid ${width}/${locale}/${theme}`);
  for(const [label,change] of Object.entries(negatives)) {
    const candidate=structuredClone(menu);
    change(candidate);
    let accepted;
    try {accepted=predicate(candidate,copy[locale],width,name);} catch {accepted=false;}
    if(accepted) throw new Error(`accepted ${label} ${width}/${locale}/${theme}`);
  }
  const wrongWidth=structuredClone(menu);
  if(width<=640) {
    wrongWidth.actionsRect.left-=2;
    wrongWidth.actionsRect.width+=2;
  } else {wrongWidth.panelRect.width=278;}
  if(predicate(wrongWidth,copy[locale],width,name)) {
    throw new Error("wrong responsive width accepted");
  }
  if(width<=640) {
    const neutralXor=structuredClone(menu);
    neutralXor.xorAction.color=menu.neutralStyle.color;
    neutralXor.xorAction.borderColor=menu.neutralStyle.borderColor;
    if(predicate(neutralXor,copy[locale],width,name)) {
      throw new Error("neutral mobile XOR accepted");
    }
  }
}
"""
    completed = subprocess.run(
        ["node", "-e", node_script, str(REPO_ROOT / "tools/browser_smoke.playwright.js")],
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stderr or completed.stdout


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
    assert config.encrypted_uploads is True
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
        local_target: bool = False,
    ) -> str:
        del base_cmd, session, cwd, local_target
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


def test_browser_smoke_opens_with_the_installed_chromium_distribution(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    opened_config: dict[str, object] = {}

    def fake_run_playwright(
        base_cmd: list[str],
        session: str,
        *args: str,
        cwd: Path,
        local_target: bool = False,
    ) -> str:
        del base_cmd, session, cwd, local_target
        if "open" in args:
            config_path = Path(args[args.index("--config") + 1])
            opened_config.update(json.loads(config_path.read_text(encoding="utf-8")))
        if "run-code" in args:
            return json.dumps({"journey": "first-run"})
        return ""

    monkeypatch.setattr(browser_smoke, "_playwright_command", lambda: ["fake-playwright"])
    monkeypatch.setattr(browser_smoke, "_run_playwright", fake_run_playwright)

    browser_smoke.run_browser_smoke(
        mode="first-run",
        target_url="http://127.0.0.1:9876/",
        artifacts_dir=tmp_path / "artifacts",
    )

    browser = opened_config["browser"]
    assert isinstance(browser, dict)
    assert browser["browserName"] == "chromium"
    launch_options = browser["launchOptions"]
    assert isinstance(launch_options, dict)
    assert launch_options["channel"] == "chromium"
    assert launch_options["headless"] is True


def test_external_target_failure_is_labeled_and_persisted(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    def fake_run_playwright(
        base_cmd: list[str],
        session: str,
        *args: str,
        cwd: Path,
        local_target: bool = False,
    ) -> str:
        del base_cmd, session, cwd, local_target
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


def test_browser_cli_failure_preserves_bounded_original_output(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    raw = '### Error\nError: actual composite failure\n{"data":"' + "x" * 1000 + '"}'

    def fake_run_playwright(
        base_cmd: list[str],
        session: str,
        *args: str,
        cwd: Path,
        local_target: bool = False,
    ) -> str:
        del base_cmd, session, cwd, local_target
        return raw if "run-code" in args else ""

    monkeypatch.setattr(browser_smoke, "MAX_PLAYWRIGHT_DIAGNOSTIC_CHARS", 64)
    monkeypatch.setattr(browser_smoke, "_playwright_command", lambda: ["fake-playwright"])
    monkeypatch.setattr(browser_smoke, "_run_playwright", fake_run_playwright)
    artifacts = tmp_path / "artifacts"

    with pytest.raises(RuntimeError, match="actual composite failure"):
        browser_smoke.run_browser_smoke(
            mode="files",
            target_url="http://127.0.0.1:9876/",
            artifacts_dir=artifacts,
        )

    assert (artifacts / "files-cli-output.log").read_text(encoding="utf-8") == raw[:64]
    assert len((artifacts / "files-failure.log").read_text(encoding="utf-8")) <= 73
    assert not (artifacts / "files-result.json").exists()


def test_installed_package_and_external_target_are_mutually_exclusive() -> None:
    with pytest.raises(ValueError, match="cannot be combined"):
        browser_smoke.run_browser_smoke(
            installed_package=True,
            mode="first-run",
            target_url="http://127.0.0.1:8080/",
        )


@pytest.mark.parametrize("installed_package", [False, True])
def test_local_full_runs_composite_and_all_named_journeys_in_isolation(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    installed_package: bool,
) -> None:
    """Exercise real orchestration/temp roots/session setup without a browser."""
    roots: list[Path] = []
    started: list[Path] = []
    stopped: list[Path] = []
    sessions: list[str] = []
    configs: list[Path] = []
    modes: list[str] = []
    artifact_paths: list[Path] = []
    import_flags: list[bool] = []
    module_path = tmp_path / "installed" / "xferry" / "server.py"

    def fake_load_server_class(*, installed_package: bool) -> tuple[type[object], Path]:
        import_flags.append(installed_package)
        return object, module_path

    class FakeLiveServer:
        def __init__(
            self,
            server_cls: type[object],
            root_dir: Path,
            *,
            disable_ecdh: bool = False,
        ) -> None:
            assert server_cls is object
            assert root_dir.exists()
            assert disable_ecdh == (root_dir.name == "notepad-unavailable")
            self.root_dir = root_dir
            roots.append(root_dir)
            self.port = 49000 + len(roots)

        def start(self) -> None:
            started.append(self.root_dir)

        def stop(self) -> None:
            stopped.append(self.root_dir)

    def fake_run_playwright(
        base_cmd: list[str],
        session: str,
        *args: str,
        cwd: Path,
        local_target: bool = False,
    ) -> str:
        del base_cmd, cwd, local_target
        if "open" in args:
            sessions.append(session)
            configs.append(Path(args[args.index("--config") + 1]))
        if "run-code" not in args:
            return ""
        script_path = Path(args[args.index("--filename") + 1])
        script = script_path.read_text(encoding="utf-8")
        mode_match = re.search(r"const smokeMode = (.*);", script)
        artifact_match = re.search(r"const artifactDir = (.*);", script)
        assert mode_match is not None
        assert artifact_match is not None
        mode = json.loads(mode_match.group(1))
        modes.append(mode)
        artifact_paths.append(Path(json.loads(artifact_match.group(1))))
        return json.dumps({"journey": mode, "observedMode": mode})

    monkeypatch.setattr(browser_smoke, "_load_server_class", fake_load_server_class)
    monkeypatch.setattr(browser_smoke, "_LiveServer", FakeLiveServer)
    monkeypatch.setattr(browser_smoke, "_playwright_command", lambda: ["fake-playwright"])
    monkeypatch.setattr(browser_smoke, "_run_playwright", fake_run_playwright)
    artifacts = tmp_path / "artifacts"

    result = browser_smoke.run_browser_smoke(
        installed_package=installed_package,
        artifacts_dir=artifacts,
    )

    expected = ["full", *EXPECTED_MODES[:-1]]
    assert modes == expected
    assert len(set(sessions)) == len(expected)
    assert len(set(configs)) == len(expected)
    assert len(set(roots)) == len(expected) + 2  # composite and notepad unavailable servers
    assert set(started) == set(stopped) == set(roots)
    assert import_flags == [installed_package] * len(expected)
    assert artifact_paths == [
        artifacts / ("composite" if mode == "full" else mode) for mode in expected
    ]
    assert result["status"] == "passed"
    assert result["executionScope"] == "isolated-local-aggregate"
    assert result["externalTarget"] is False
    assert result["installedPackage"] is installed_package
    assert result["expectedJourneys"] == expected
    assert result["completedJourneys"] == expected
    assert result["aggregateJourneys"] == list(EXPECTED_MODES[:-1])
    assert result["failures"] == {}
    receipts = result["journeyResults"]
    assert isinstance(receipts, dict)
    for mode, artifact_path in zip(expected, artifact_paths, strict=True):
        receipt = json.loads((artifact_path / f"{mode}-result.json").read_text(encoding="utf-8"))
        assert receipt == receipts[mode]
        assert receipt["status"] == "passed"
        assert receipt["journey"] == receipt["observedMode"] == mode
        assert receipt["serverModulePath"] == str(module_path)
        assert receipt["artifactsDir"] == str(artifact_path)
    assert json.loads((artifacts / "full-result.json").read_text(encoding="utf-8")) == result


@pytest.mark.parametrize("composite_fails", [False, True])
def test_local_full_collects_all_failures_without_fabricating_completions(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    composite_fails: bool,
) -> None:
    calls: list[str] = []

    def fake_single_journey(
        *,
        installed_package: bool,
        mode: str,
        target_url: str | None,
        artifacts_dir: str | Path | None,
        browser: str,
    ) -> dict[str, object]:
        assert browser == "chromium"
        assert installed_package is False
        assert target_url is None
        assert Path(artifacts_dir).is_dir()
        calls.append(mode)
        if mode in {"first-run", "notepad"} or (composite_fails and mode == "full"):
            raise RuntimeError(f"semantic failure in {mode}")
        if mode == "advanced-session":
            return {"journey": mode, "status": "failed"}
        if mode == "files":
            return {"journey": "first-run", "status": "passed", "token": "do-not-log-this-token"}
        return {"journey": mode, "status": "passed"}

    monkeypatch.setattr(browser_smoke, "_run_single_journey", fake_single_journey)
    artifacts = tmp_path / "artifacts"
    # A stale successful receipt must not survive a failing aggregate rerun.
    artifacts.mkdir()
    (artifacts / "full-result.json").write_text('{"status": "passed"}', encoding="utf-8")

    with pytest.raises(RuntimeError, match=r"\[full aggregate\].*journey\(s\) failed") as exc:
        browser_smoke.run_browser_smoke(artifacts_dir=artifacts)

    expected = ["full", *EXPECTED_MODES[:-1]]
    failed = {"first-run", "notepad", "advanced-session", "files"}
    if composite_fails:
        failed.add("full")
    assert calls == expected
    receipt = json.loads((artifacts / "full-result.json").read_text(encoding="utf-8"))
    assert receipt["status"] == "failed"
    assert set(receipt["failures"]) == failed
    assert receipt["expectedJourneys"] == expected
    assert receipt["completedJourneys"] == [mode for mode in expected if mode not in failed]
    assert receipt["aggregateJourneys"] == [
        mode for mode in EXPECTED_MODES[:-1] if mode not in failed
    ]
    assert set(receipt["journeyResults"]) == set(expected) - failed
    for mode in failed:
        artifact_dir = artifacts / ("composite" if mode == "full" else mode)
        assert f"[{mode}]" in (artifact_dir / f"{mode}-failure.log").read_text(encoding="utf-8")
        assert f"[{mode}]" in str(exc.value)
    assert "semantic failure in notepad" in (artifacts / "full-failure.log").read_text(
        encoding="utf-8"
    )
    assert "do-not-log-this-token" not in str(exc.value)
    assert "do-not-log-this-token" not in (artifacts / "full-result.json").read_text(
        encoding="utf-8"
    )


def test_external_full_remains_one_composite_not_a_local_aggregate(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    modes: list[str] = []

    def fail_load_server_class(*, installed_package: bool) -> tuple[type[object], Path]:
        raise AssertionError(f"external composite imported server: {installed_package}")

    def fake_run_playwright(
        base_cmd: list[str],
        session: str,
        *args: str,
        cwd: Path,
        local_target: bool = False,
    ) -> str:
        del base_cmd, session, cwd, local_target
        if "run-code" not in args:
            return ""
        script_path = Path(args[args.index("--filename") + 1])
        rendered = script_path.read_text(encoding="utf-8")
        mode_match = re.search(r"const smokeMode = (.*);", rendered)
        assert mode_match is not None
        modes.append(json.loads(mode_match.group(1)))
        assert "const externalTarget = true;" in rendered
        assert 'const unavailableUrl = "";' in rendered
        return json.dumps(
            {
                "journey": "full",
                "happyPath": {"crossTool": "observed"},
                "availableJourneys": list(EXPECTED_MODES[:-1]),
            }
        )

    monkeypatch.setattr(browser_smoke, "_load_server_class", fail_load_server_class)
    monkeypatch.setattr(browser_smoke, "_playwright_command", lambda: ["fake-playwright"])
    monkeypatch.setattr(browser_smoke, "_run_playwright", fake_run_playwright)
    artifacts = tmp_path / "artifacts"

    result = browser_smoke.run_browser_smoke(
        target_url="http://127.0.0.1:9876",
        artifacts_dir=artifacts,
    )

    assert modes == ["full"]
    assert result["status"] == "passed"
    assert result["executionScope"] == "external-cross-tool-composite"
    assert result["externalTarget"] is True
    assert result["happyPath"] == {"crossTool": "observed"}
    assert result["availableJourneys"] == list(EXPECTED_MODES[:-1])
    for aggregate_field in ("aggregateJourneys", "completedJourneys", "journeyResults"):
        assert aggregate_field not in result
    assert json.loads((artifacts / "full-result.json").read_text(encoding="utf-8")) == result
    assert list(artifacts.iterdir()) == [artifacts / "full-result.json"]


def test_browser_smoke_cli_help_explains_local_and_external_full_scopes(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as exc:
        browser_smoke.main(["--help"])
    assert exc.value.code == 0
    help_text = " ".join(capsys.readouterr().out.split())
    assert "every named journey in isolation" in help_text
    assert "external full runs only" in help_text
    assert "not all independent journeys" in help_text


def test_playwright_dispatcher_owns_every_mode_and_failure_artifacts() -> None:
    script = (REPO_ROOT / "tools/browser_smoke.playwright.js").read_text(encoding="utf-8")

    for mode in EXPECTED_MODES[:-1]:
        assert f'"{mode}"' in script
    assert "availableJourneys = Object.keys(namedJourneys)" in script
    assert "aggregateJourneys" not in script
    assert "runHappyPath()" in script
    assert "runUnavailablePath()" in script
    assert "page.screenshot({" in script
    assert "${smokeMode}-failure.png" in script


def test_first_run_upload_preview_waits_for_the_default_upload_endpoint() -> None:
    """The first-run oracle must follow the basic uploader's /upload request target."""
    script = (REPO_ROOT / "tools/browser_smoke.playwright.js").read_text(encoding="utf-8")
    preview_wait = script.split('"upload request preview ready before send"', 1)[1].split(
        "10000", 1
    )[0]

    assert '["/upload"]' in preview_wait
    assert '["/uploads"]' not in preview_wait


def test_first_run_upload_download_assertion_uses_the_default_upload_endpoint() -> None:
    """The downloaded request oracle must expect the request the basic uploader sends."""
    script = (REPO_ROOT / "tools/browser_smoke.playwright.js").read_text(encoding="utf-8")
    upload_helper = script.split("async function uploadViaDom", 1)[1].split(
        "async function clearUploadsViaUiAndAssertSummaryPersistence", 1
    )[0]

    assert '"POST /upload HTTP/1.1"' in upload_helper
    assert '"POST /uploads HTTP/1.1"' not in upload_helper


def test_full_upload_default_summary_oracle_requires_exact_request_line() -> None:
    """Execute the full-only predicate against the canonical default and stale paths."""
    node_script = r"""
const fs = require("node:fs");
const source = fs.readFileSync(process.argv[1], "utf8");
const start = source.indexOf("  async function assertUploadHelpUx() {");
const end = source.indexOf("  async function uploadOpsecViaUiAndAssertMethodStable(", start);
if (start < 0 || end < 0) throw new Error("upload default summary helper is missing");
const loadHelper = new Function(
  "document", "waitForTabState", "waitForPageCondition", "assertVisibleUploadMethodComposer", `
${source.slice(start, end)}
return assertUploadHelpUx;
`);

async function assertRequestLine(requestLine, expected) {
  const fields = {
    "request-line": requestLine,
    "body-kind": "multipart/form-data, file field",
    mime: "application/octet-stream",
    "filename-source": "Multipart part filename",
  };
  const summary = {
    getClientRects: () => [{}],
    querySelector(selector) {
      const key = selector.match(/^\[data-upload-summary="([a-z-]+)"\]$/)?.[1];
      if (!Object.hasOwn(fields, key)) throw new Error(`Unexpected summary selector: ${selector}`);
      return { textContent: fields[key] };
    },
  };
  const profiles = ["multipart", "raw-url", "raw-header", "raw-generated"].map(
    (profile, index) => ({
      dataset: { uploadProfile: profile },
      tabIndex: index === 0 ? 0 : -1,
      getAttribute: name => {
        if (name !== "aria-checked") throw new Error(`Unexpected attribute: ${name}`);
        return String(index === 0);
      },
    })
  );
  const document = {
    getElementById: id => id === "uploadRequestSummary" ? summary : null,
    querySelector: () => null,
    querySelectorAll: selector => {
      if (selector !== "#uploadProfileGroup [data-upload-profile]") {
        throw new Error(`Unexpected selector: ${selector}`);
      }
      return profiles;
    },
  };
  let observed;
  let calls = 0;
  const helper = loadHelper(document, async () => {}, async (_label, predicate) => {
    calls += 1;
    observed = predicate();
  }, async () => {});
  await helper();
  if (calls !== 1 || observed !== expected) {
    throw new Error(`${JSON.stringify(requestLine)}: expected ${expected}, got ${observed}`);
  }
}

async function main() {
  await assertRequestLine("POST /upload", true);
  for (const requestLine of [
    "POST /uploads", "POST /upload-extra", "POST /upload/", "PUT /upload",
    "POST /other", "extra POST /upload", "POST /upload extra", "",
  ]) {
    await assertRequestLine(requestLine, false);
  }
}
main().catch(error => { console.error(error); process.exitCode = 1; });
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


def test_delete_contract_waits_for_automatic_browse_before_explicit_browse() -> None:
    """Catches the delete smoke racing its explicit browse with tab auto-browse."""
    script = (REPO_ROOT / "tools/browser_smoke.playwright.js").read_text(encoding="utf-8")
    start = script.index("async function assertFilesDeleteTargetEncodingContract(")
    end = script.index("async function assertFilesInfoLastResultWinsContract(", start)
    delete_contract = script[start:end]

    settled_browse = "await activateFilesAndWaitForSettledBrowse();"
    explicit_path_fill = 'await page.locator("#browsePathInput").fill("/delete-wire-contract");'
    explicit_browse_click = 'await page.locator("#browseBtn").click();'

    assert settled_browse in delete_contract
    assert delete_contract.index(settled_browse) < delete_contract.index(explicit_path_fill)
    assert delete_contract.index(explicit_path_fill) < delete_contract.index(explicit_browse_click)


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


def test_full_smoke_checkdata_preview_requires_current_session_and_plan() -> None:
    """Reject the stale pre-session path before exporting or sending CHECKDATA."""
    node_script = r"""
const assert = require("node:assert/strict");
const fs = require("node:fs");
const source = fs.readFileSync(process.argv[1], "utf8");
const start = source.indexOf("  async function waitForCheckdataRequestPreview(noGzip) {");
const end = source.indexOf("  async function uploadOpsecViaUiAndAssertMethodStable(", start);
assert.ok(start >= 0 && end > start, "actual CHECKDATA preview readiness helper missing");
const load = new Function("window", "document", "waitForPageCondition", `
${source.slice(start, end)}
return waitForCheckdataRequestPreview;
`);
async function check(label, patch, expected) {
  const state = {
    sessionActive: true, previewPlanReady: true, previewPending: false,
    previewPlanIdentity: 7, previewSequence: 7, previewSessionExpiresAt: "expiry-current",
    ...patch.state,
  };
  const session = {
    active: true, phase: "active", prefix: "/advanced", expires_at: "expiry-current",
    ...patch.session,
  };
  const noGzip = patch.noGzip ?? true;
  const text = patch.text ?? "CHECKDATA /advanced/token HTTP/1.1\n" +
    "Content-Type: application/json\n" + (noGzip ? "X-XFerry-No-Gzip: 1\n" : "");
  const path = (text.match(/^CHECKDATA\s+(\/[^\s]+)\s+HTTP\/1\.1/) || [])[1] || "";
  const area = { innerText: text, dataset: {
    exchangePhase: patch.phase ?? "ready", exchangePath: patch.areaPath ?? path,
  } };
  const window = { XferryApp: {
    getState: name => { assert.equal(name, "advanced"); return state; },
    service: name => {
      if (name === "inspector") return { getInspectorState: scope => {
        assert.equal(scope, "opsec");
        return { request: { method: "CHECKDATA", path, ...patch.request } };
      } };
      assert.equal(name, "advanced-session");
      return { getSnapshot: () => session };
    },
  } };
  const document = {
    getElementById: id => {
      if (id === "opsecRequestArea") return area;
      assert.equal(id, "opsecUploadBtn");
      return { disabled: patch.uploadDisabled ?? false };
    },
    querySelector: selector => {
      assert.equal(selector, '[data-exchange-download-area="opsecRequestArea"]');
      return { disabled: patch.downloadDisabled ?? false };
    },
  };
  let calls = 0;
  const helper = load(window, document, async (label, predicate, args) => {
    calls += 1;
    assert.equal(Boolean(predicate(args)), expected, label);
  });
  await helper(noGzip);
  assert.equal(calls, 1, label);
}
(async () => {
  await check("current canonical preview", {}, true);
  await check("current default no-gzip preview", { noGzip: false }, true);
  await check("valid root session prefix", { session: { prefix: "/" },
    text: "CHECKDATA /token HTTP/1.1\nContent-Type: application/json\n" +
      "X-XFerry-No-Gzip: 1" }, true);
  for (const [label, patch] of [
    ["inactive session", { session: { active: false } }],
    ["checking session", { session: { phase: "checking" } }],
    ["inactive workflow", { state: { sessionActive: false } }],
    ["pending preview", { state: { previewPending: true } }],
    ["invalid plan", { state: { previewPlanReady: false } }],
    ["old plan identity", { state: { previewPlanIdentity: 6 } }],
    ["old session plan", { state: { previewSessionExpiresAt: "expiry-old" } }],
    ["no session prefix", { session: { prefix: null } }],
    ["stale unprefixed path", { text: "CHECKDATA /token HTTP/1.1\n" +
      "Content-Type: application/json\nX-XFerry-No-Gzip: 1" }],
    ["wrong prefix boundary", { text: "CHECKDATA /advanced-other/token HTTP/1.1\n" +
      "Content-Type: application/json\nX-XFerry-No-Gzip: 1" }],
    ["wrong method", { text: "POST /advanced/token HTTP/1.1\n" +
      "Content-Type: application/json\nX-XFerry-No-Gzip: 1" }],
    ["missing content type", { text: "CHECKDATA /advanced/token HTTP/1.1\n" +
      "X-XFerry-No-Gzip: 1" }],
    ["missing canonical header", { text: "CHECKDATA /advanced/token HTTP/1.1\n" +
      "Content-Type: application/json" }],
    ["unexpected canonical header", { noGzip: false,
      text: "CHECKDATA /advanced/token HTTP/1.1\nContent-Type: application/json\n" +
        "X-XFerry-No-Gzip: 1" }],
    ["legacy header", { text: "CHECKDATA /advanced/token HTTP/1.1\n" +
      "Content-Type: application/json\nX-XFerry-No-Gzip: 1\nX-Exphttp-No-Gzip: 1" }],
    ["pending inspector", { phase: "sending" }],
    ["inspector path drift", { request: { path: "/advanced/old-token" } }],
    ["inspector method drift", { request: { method: "POST" } }],
    ["DOM path drift", { areaPath: "/advanced/old-token" }],
    ["disabled download", { downloadDisabled: true }],
    ["disabled upload", { uploadDisabled: true }],
  ]) await check(label, patch, false);
})().catch(error => { console.error(error); process.exitCode = 1; });
"""
    completed = subprocess.run(
        ["node", "-e", node_script, str(REPO_ROOT / "tools/browser_smoke.playwright.js")],
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stderr or completed.stdout

    script = (REPO_ROOT / "tools/browser_smoke.playwright.js").read_text(encoding="utf-8")
    journey = script.split(
        "async function uploadOpsecViaUiAndAssertMethodStable(fixturePath) {", 1
    )[1].split("async function installNotepadWsActionRecorder()", 1)[0]
    initial = journey.index("await waitForCheckdataRequestPreview(false);")
    updated = journey.index("await waitForCheckdataRequestPreview(true);")
    capture = journey.index("const opsecPreviewPath = await page.evaluate")
    export = journey.index('await assertExchangeDownload(\n      "opsecRequestArea"')
    send = journey.index('await page.locator("#opsecUploadBtn").click();')
    assert initial < updated < capture < export < send
    assert journey.count("await waitForAdvancedSessionReady();") == 2
    assert "await waitForAdvancedSessionReady();" in journey[:initial]
    assert "await waitForAdvancedSessionReady();" in journey[initial:updated]
    assert "[opsecPreviewPath]" in journey[send:]


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


def test_ci_gates_source_wheel_image_and_preserves_diagnostics() -> None:
    ci = (REPO_ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")

    assert "Compact source and wheel browser journeys" in ci
    assert ci.count("--mode first-run") >= 2
    assert "--mode ui-contracts" in ci
    assert ci.count("--target-url") >= 3
    assert "xferry-browser-wheel-venv/bin/xferry" in ci
    assert "python -m xferry \\\n            run \\\n            --host 127.0.0.1" in ci
    assert (
        'xferry-browser-wheel-venv/bin/xferry" \\\n'
        "                run \\\n"
        "                --host 127.0.0.1"
    ) in ci
    assert 'if [ "${CANDIDATE_GATES}" != "true" ]; then' in ci
    full_step = ci.split("- name: Full browser aggregate before release acceptance", 1)[1].split(
        "\n      - ", 1
    )[0]
    assert "\n        if:" not in full_step
    assert "--mode full" in full_step
    assert "Upload browser journey diagnostics" in ci
    assert "if: always()" in ci


def test_request_panel_demo_smoke_uses_unique_requests_and_server_canonical_paths() -> None:
    """Exercise the smoke oracle with a server-renamed file for every demo method."""
    script = r"""
const assert = require('node:assert/strict');
const fs = require('node:fs');
const source = fs.readFileSync(process.argv[1], 'utf8');
const start = source.indexOf('  async function captureRequestPanelDemoUpload(');
const end = source.indexOf('  async function triggerRequestMethod(', start);
assert.ok(start >= 0 && end > start, 'actual request-panel demo helpers missing');
const load = new Function(
  'page', 'requestPathname', 'triggerRequestMethod', 'waitForRequestPanelResponse',
  'waitForValue', 'waitForRequestPreview', 'waitForLiveRegionText',
  `${source.slice(start, end)}; return { captureRequestPanelDemoUpload,
    runRequestPanelMethodScenario };`
);
async function check(method, invalidPath = undefined) {
  const slug = method.toLowerCase();
  const uploadMethod = ['POST', 'PUT', 'PATCH', 'NONE'].includes(method) ? method : 'POST';
  const requestedName = `request-panel-${slug}-${'a'.repeat(24)}.txt`;
  const canonicalPath = `/uploads/server-selected-${slug}.txt`;
  const finalPath = uploadMethod === method ? '/' : canonicalPath;
  const expectedStatus = uploadMethod === method ? 201 : 200;
  let captures = 0;
  let triggers = 0;
  let inputChecks = 0;
  const candidate = (patch = {}) => ({
    request: () => ({
      method: () => patch.method || uploadMethod,
      url: () => `http://example.test${patch.path || '/'}`,
      headers: () => ({ 'x-file-name': patch.name || requestedName }),
    }),
    json: async () => ({ file: { path: invalidPath ?? canonicalPath } }),
    status: () => 201,
  });
  const page = {
    waitForResponse: async (predicate, { timeout }) => {
      captures += 1;
      assert.equal(timeout, 15000);
      for (const patch of [
        { method: 'INFO' }, { method: 'DELETE' }, { path: '/uploads/existing.txt' },
        { name: `request-panel-${slug}.txt` },
        { name: `request-panel-${slug}-${'a'.repeat(23)}.txt` },
        { name: `request-panel-other-${'a'.repeat(24)}.txt` },
      ]) assert.equal(predicate(candidate(patch)), false);
      assert.equal(predicate(candidate()), true);
      return candidate();
    },
    locator: selector => ({
      fill: async value => {
        assert.equal(selector, '#pathInput');
        assert.equal(value, '/uploads/existing-user-file.txt');
      },
      innerText: async () => {
        if (selector === '#responseArea') return `"path": "${canonicalPath}"`;
        assert.equal(selector, '#requestPreviewArea');
        return `${method} ${finalPath} HTTP/1.1\nX-File-Name: ${requestedName}`;
      },
    }),
  };
  const helpers = load(
    page,
    request => new URL(request.url()).pathname,
    async observed => { assert.equal(observed, method); triggers += 1; },
    async (observed, status, path) => {
      assert.equal(observed, method); assert.equal(status, expectedStatus);
      assert.equal(path, finalPath);
    },
    async (selector, value) => {
      assert.equal(selector, '#pathInput'); assert.equal(value, canonicalPath); inputChecks += 1;
    },
    async (observed, path) => { assert.equal(observed, method); assert.equal(path, finalPath); },
    async (selector, text) => {
      assert.equal(selector, 'responseAreaLive');
      assert.equal(text, `${method} ${finalPath} ${expectedStatus}`);
    },
  );
  const action = () => helpers.runRequestPanelMethodScenario({
    method, demoSlug: slug, initialPath: '/uploads/existing-user-file.txt',
    expectedRequestPath: uploadMethod === method ? '/' : '$demoPath',
    expectedPathInput: '$demoPath', expectedStatus,
    responseIncludes: ['"path": "$demoPath"'],
    previewIncludes: uploadMethod === method ? ['X-File-Name: $requestedDemoName'] : [],
  });
  if (invalidPath !== undefined) {
    await assert.rejects(action, /invalid canonical path/);
    return;
  }
  const result = await action();
  assert.equal(result.pathInput, canonicalPath);
  assert.equal(result.path, finalPath);
  assert.equal(captures, 1);
  assert.equal(triggers, 1);
  assert.equal(inputChecks, 1);
}
(async () => {
  for (const method of ['POST', 'PUT', 'PATCH', 'NONE', 'DELETE', 'FETCH', 'SMUGGLE']) {
    await check(method);
  }
  for (const path of ['', '/uploads/', '/private/file.txt']) await check('POST', path);
})().catch(error => { console.error(error); process.exitCode = 1; });
"""
    result = subprocess.run(
        ["node", "-e", script, str(REPO_ROOT / "tools/browser_smoke.playwright.js")],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr or result.stdout


def test_clear_confirmation_smoke_matches_both_locales_and_keeps_scopes_distinct() -> None:
    """The real clear oracles must accept the current UI warning for each scope."""
    core = (REPO_ROOT / "xferry/data/static/ui/core.js").read_text(encoding="utf-8")
    messages: dict[str, list[str]] = {"clearUploadsConfirm": [], "notepadClearConfirm": []}
    for key, value in re.findall(
        r'^\s*(clearUploadsConfirm|notepadClearConfirm): ("(?:\\.|[^"\\])*"),$',
        core,
        re.MULTILINE,
    ):
        messages[key].append(json.loads(value))
    assert {key: len(value) for key, value in messages.items()} == {
        "clearUploadsConfirm": 2,
        "notepadClearConfirm": 2,
    }
    script = r"""
const assert = require('node:assert/strict');
const fs = require('node:fs');
const source = fs.readFileSync(process.argv[1], 'utf8');
const messages = JSON.parse(process.argv[2]);
const start = source.indexOf('  async function confirmFilesFolderClear(');
const end = source.indexOf('  async function assertSharedDialogRoleContract(', start);
assert.ok(start >= 0 && end > start, 'scoped clear confirmation helpers missing');
const patterns = [];
const helpers = new Function('confirmAppDialog', `${source.slice(start, end)}
  return { confirmFilesFolderClear, confirmNotesClear };`
)(async (pattern, timeout) => { assert.equal(timeout, 10000); patterns.push(pattern); });
(async () => {
  await helpers.confirmFilesFolderClear();
  await helpers.confirmNotesClear();
  for (const message of messages.clearUploadsConfirm) {
    assert.equal(patterns[0].test(message), true);
    assert.equal(patterns[1].test(message), false);
  }
  for (const message of messages.notepadClearConfirm) {
    assert.equal(patterns[1].test(message), true);
    assert.equal(patterns[0].test(message), false);
  }
  for (const oldPath of ['/uploads/', '/notes/']) {
    assert.equal(patterns[0].test(oldPath), false);
    assert.equal(patterns[1].test(oldPath), false);
  }
})().catch(error => { console.error(error); process.exitCode = 1; });
"""
    result = subprocess.run(
        [
            "node",
            "-e",
            script,
            str(REPO_ROOT / "tools/browser_smoke.playwright.js"),
            json.dumps(messages),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr or result.stdout
