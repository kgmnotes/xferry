from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]

NODE_READINESS_FIXTURE = r"""
const assert = require("node:assert/strict");
const fs = require("node:fs");
const source = fs.readFileSync(process.argv[1], "utf8");
const { kind, changes, expected, name } = JSON.parse(process.argv[2]);
const path = `/uploads/${name}`;
const encoded = encodeURIComponent(path);
const events = [];
const results = [];
let committed = false;
let generation = kind === "browse" ? 7 : 9;
let inputPath = "/";
const options = () => committed ? changes : {};
const window = { XferryApp: { getState: workflow => {
  assert.equal(workflow, "files");
  const opts = options();
  if (opts.noState) return null;
  return {
    browseGeneration: opts.noGeneration ? undefined : generation,
    selectedCount: opts.noCount ? undefined : (committed ? (opts.count ?? 1) : 0),
  };
} } };
const node = prefix => ({
  getClientRects: () => options()[`${prefix}Invisible`] ? [] : [{}],
});
const filename = { get textContent() { return options().wrongName ? `${name}-suffix` : name; } };
const row = {
  classList: { contains: value => {
    if (value === "is-selected") return committed && !options().unselectedRow;
    if (value === "uploaded-file--file") return !options().directoryRow;
    throw new Error(`Unexpected row class: ${value}`);
  } },
  querySelector: selector => {
    assert.equal(selector, ".file-name");
    return options().noFilename ? null : filename;
  },
};
const closestRow = selector => {
  assert.equal(selector, ".uploaded-file--file");
  return options().noRow || options().directoryRow ? null : row;
};
const anchor = { closest: closestRow };
const checkbox = {
  closest: closestRow,
  get checked() { return committed && !options().unchecked; },
  get disabled() { return Boolean(options().checkboxDisabled); },
};
function query(selector) {
  const opts = options();
  if (selector === "#filesHttpErrorHost .http-error-card") return opts.errorCard ? {} : null;
  const match = selector.match(/\[data-path="([^"]+)"\]/);
  const actualPath = opts.wrongEncodedPath ? encodeURIComponent(`${path}-other`) : encoded;
  if (!match || match[1] !== actualPath) return null;
  if (selector.includes("[data-file-details-trigger]")) return opts.noAnchor ? null : anchor;
  if (selector.includes("[data-file-select]")) return opts.noCheckbox ? null : checkbox;
  throw new Error(`Unexpected query: ${selector}`);
}
const list = {
  get dataset() { return {
    browsePhase: options().listPhase ?? "complete", stale: options().stale ?? "false",
  }; },
  getAttribute: attribute => {
    assert.equal(attribute, "aria-busy");
    return options().busy ?? "false";
  },
  querySelector: query,
  innerText: name,
  textContent: name,
};
const bar = node("bar");
Object.defineProperty(bar, "hidden", { get: () => Boolean(options().barHidden) });
const button = node("button");
Object.defineProperties(button, {
  hidden: { get: () => Boolean(options().buttonHidden) },
  disabled: { get: () => Boolean(options().buttonDisabled) },
  dataset: { get: () => ({ count: options().buttonCount ?? "1" }) },
});
const document = {
  querySelector: query,
  getElementById: id => {
    const opts = options();
    switch (id) {
      case "browsePathInput": return opts.noPath ? null : {
        value: opts.wrongPath ? "/elsewhere" : inputPath,
      };
      case "filesBrowseStatus": return opts.noStatus ? null : {
        dataset: { browsePhase: opts.statusPhase ?? "complete" },
      };
      case "serverFiles": return opts.noList ? null : list;
      case "filesSelectionBar": return opts.noBar ? null : bar;
      case "deleteSelectedUploadsBtn": return opts.noButton ? null : button;
      default: throw new Error(`Unexpected element id: ${id}`);
    }
  },
};
const page = {
  evaluate: callback => { events.push("capture"); return callback(); },
  locator: selector => ({
    click: async () => {
      assert.equal(selector, "#tab-files");
      events.push("tab"); // Its delayed automatic browse has not started yet.
    },
    fill: async value => {
      assert.equal(selector, "#browsePathInput");
      assert.ok(events.includes("auto-settled"), "fill raced delayed activation browse");
      assert.equal(value, "/uploads");
      inputPath = value;
      events.push("fill");
    },
    check: async () => {
      assert.equal(selector, `#serverFiles [data-file-select][data-path="${encoded}"]`);
      assert.equal(events.at(-1), "capture", "capture generation before selecting the row");
      committed = true;
      generation = changes.generation ?? 9;
      events.push("check");
    },
  }),
  getByRole: (role, opts) => ({ click: async () => {
    assert.equal(role, "button");
    assert.ok(opts.name.test("Browse"));
    assert.deepEqual(events.slice(-2), ["capture", "fill"]);
    assert.ok(events.includes("auto-settled"), "explicit browse raced delayed activation");
    committed = true;
    generation = changes.generation ?? 9;
    events.push("browse");
  } }),
};
async function waitForPageCondition(_label, predicate, arg, timeout) {
  if (kind === "browse" && !committed) {
    assert.equal(timeout, 15000);
    assert.equal(predicate(arg), false, "old success must not satisfy activation fence");
    generation = 8; // The real delayed activation browse now commits.
    assert.equal(predicate(arg), true);
    events.push("auto-settled");
  } else {
    assert.equal(timeout, 10000);
    results.push(Boolean(predicate(arg)));
  }
}
const dependencies = ["window", "document", "page", "waitForPageCondition"];
const values = [window, document, page, waitForPageCondition];
let body;
if (kind === "browse") {
  const start = source.indexOf("  async function browseUploadsAndAssert(name) {");
  const end = source.indexOf("  async function waitForRequestPanelResponse(", start);
  const activation = source.indexOf("  async function activateFilesAndWaitForSettledBrowse() {");
  const activationEnd = source.indexOf(
    "  async function clearUploadsViaUiAndAssertSummaryPersistence(", activation
  );
  assert.ok(start >= 0 && end > start && activation >= 0 && activationEnd > activation);
  body = source.slice(start, end) + source.slice(activation, activationEnd);
  dependencies.push("waitForTabState");
  values.push(async (tab, opts) => {
    assert.equal(tab, "files"); assert.equal(opts.focused, true);
  });
} else {
  const start = source.indexOf("  async function deleteSelectedUploadViaUiAndAssert(path) {");
  const end = source.indexOf(
    "    await page.evaluate(() => {\n" +
      "      const previous = window.__filesBulkDeleteToastFocusContract;",
    start
  );
  assert.ok(start >= 0 && end > start);
  body = source.slice(start, end) + "\n  }\n";
  dependencies.push("browseUploadsAndAssert");
  values.push(async target => {
    assert.equal(target, name);
    inputPath = "/uploads";
    events.push("browse-ready");
  });
}
const functionName = kind === "browse"
  ? "browseUploadsAndAssert" : "deleteSelectedUploadViaUiAndAssert";
const helper = new Function(...dependencies, `${body}\nreturn ${functionName};`)(...values);
helper(kind === "browse" ? name : path).then(() => {
  assert.deepEqual(results, [expected], "one combined predicate must decide current readiness");
}).catch(error => { console.error(error); process.exitCode = 1; });
"""


def _assert_readiness(kind: str, changes: dict[str, object], expected: bool, name: str) -> None:
    completed = subprocess.run(
        [
            "node",
            "-e",
            NODE_READINESS_FIXTURE,
            str(REPO_ROOT / "tools/browser_smoke.playwright.js"),
            json.dumps({"kind": kind, "changes": changes, "expected": expected, "name": name}),
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert completed.returncode == 0, completed.stderr or completed.stdout


@pytest.mark.parametrize("name", ["browser-smoke-upload.txt", "данные \"точно\" 'one' #+%.txt"])
def test_upload_browse_consumes_delayed_activation_before_exact_current_browse(name: str) -> None:
    """Execute both real helpers; generic browsing must not require delete capability."""
    _assert_readiness("browse", {"noCheckbox": True}, True, name)


COMMON_NOT_READY = [
    pytest.param({"noState": True}, id="missing-state"),
    pytest.param({"noGeneration": True}, id="missing-generation"),
    pytest.param({"generation": 9.5}, id="fractional-generation"),
    pytest.param({"generation": "9"}, id="string-generation"),
    pytest.param({"wrongPath": True}, id="wrong-browse-path"),
    pytest.param({"statusPhase": "loading"}, id="loading-status"),
    pytest.param({"statusPhase": "error"}, id="failed-status"),
    pytest.param({"listPhase": "loading"}, id="loading-list"),
    pytest.param({"busy": "true"}, id="busy-list"),
    pytest.param({"stale": "true"}, id="stale-list"),
    pytest.param({"errorCard": True}, id="error-card"),
    pytest.param({"noPath": True}, id="missing-path-input"),
    pytest.param({"noStatus": True}, id="missing-status"),
    pytest.param({"noList": True}, id="missing-list"),
    pytest.param({"wrongEncodedPath": True}, id="wrong-exact-encoded-target"),
    pytest.param({"directoryRow": True}, id="directory-not-file"),
    pytest.param({"noRow": True}, id="missing-file-row"),
]


@pytest.mark.parametrize(
    "changes",
    [
        *COMMON_NOT_READY,
        pytest.param({"generation": 8}, id="old-success-same-generation"),
        pytest.param({"noAnchor": True}, id="missing-details-anchor"),
        pytest.param({"wrongName": True}, id="filename-substring-is-not-exact"),
        pytest.param({"noFilename": True}, id="missing-filename"),
    ],
)
def test_upload_browse_rejects_false_ready_listing(changes: dict[str, object]) -> None:
    _assert_readiness("browse", changes, False, "данные \"точно\" 'one' #+%.txt")


@pytest.mark.parametrize("name", ["browser-smoke-upload.txt", "данные \"точно\" 'one' #+%.txt"])
def test_bulk_delete_waits_for_committed_exact_row_selection(name: str) -> None:
    """Execute the real selection prefix, before focus-listener installation or deletion."""
    _assert_readiness("selection", {}, True, name)


@pytest.mark.parametrize(
    "changes",
    [
        *COMMON_NOT_READY,
        pytest.param({"generation": 10}, id="generation-changed-after-selection"),
        pytest.param({"count": 0}, id="selection-lost"),
        pytest.param({"count": 2}, id="multiple-selected"),
        pytest.param({"count": "1"}, id="string-selected-count"),
        pytest.param({"noCount": True}, id="missing-selected-count"),
        pytest.param({"noCheckbox": True}, id="missing-checkbox"),
        pytest.param({"unchecked": True}, id="unchecked-checkbox"),
        pytest.param({"checkboxDisabled": True}, id="disabled-checkbox"),
        pytest.param({"unselectedRow": True}, id="unselected-row"),
        pytest.param({"noBar": True}, id="missing-selection-bar"),
        pytest.param({"barHidden": True}, id="hidden-selection-bar"),
        pytest.param({"barInvisible": True}, id="invisible-selection-bar"),
        pytest.param({"noButton": True}, id="missing-delete-button"),
        pytest.param({"buttonHidden": True}, id="hidden-delete-button"),
        pytest.param({"buttonInvisible": True}, id="invisible-delete-button"),
        pytest.param({"buttonDisabled": True}, id="disabled-delete-button"),
        pytest.param({"buttonCount": "0"}, id="mismatched-delete-count"),
        pytest.param({"buttonCount": 1}, id="non-string-delete-count"),
    ],
)
def test_bulk_delete_rejects_false_ready_selection(changes: dict[str, object]) -> None:
    _assert_readiness("selection", changes, False, "данные \"точно\" 'one' #+%.txt")
