"""Large file navigation, public DOM and localized storage guidance contracts."""

from __future__ import annotations

import json
import subprocess
from html.parser import HTMLParser
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
UI_ROOT = REPO_ROOT / "xferry" / "data" / "static" / "ui"


class _PanelParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.stack: list[tuple[str, str]] = []
        self.elements: dict[str, dict[str, str | None]] = {}
        self.panels: dict[str, str] = {}

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = dict(attrs)
        element_id = attributes.get("id") or ""
        if element_id:
            self.elements[element_id] = attributes
            self.panels[element_id] = next(
                (item_id for _, item_id in reversed(self.stack) if item_id.endswith("-tab")),
                "",
            )
        if tag not in {"input", "img", "br", "hr", "meta", "link", "source", "wbr"}:
            self.stack.append((tag, element_id))

    def handle_endtag(self, tag: str) -> None:
        for index in range(len(self.stack) - 1, -1, -1):
            if self.stack[index][0] == tag:
                del self.stack[index:]
                break


def test_large_files_are_a_separate_accessible_workspace() -> None:
    parser = _PanelParser()
    parser.feed((REPO_ROOT / "xferry" / "data" / "index.html").read_text(encoding="utf-8"))

    tab = parser.elements["tab-large-files"]
    assert tab["role"] == "tab"
    assert tab["aria-controls"] == "large-files-tab"
    assert tab["data-tab-target"] == "large-files"
    assert "hidden" in tab
    assert parser.elements["large-files-tab"]["aria-labelledby"] == "tab-large-files"
    assert parser.panels["encryptedTransferPanel"] == "large-files-tab"
    assert "multiple" in parser.elements["encryptedFileInput"]
    for element_id in (
        "encryptedQueueList",
        "encryptedProgressPercent",
        "encryptedProgressBytes",
        "encryptedProgressSpeed",
        "encryptedProgressEta",
        "encryptedCacheRegion",
        "encryptedCacheList",
        "encryptedCacheSize",
        "encryptedCacheClearBtn",
        "encryptedBrowserSupport",
    ):
        assert parser.panels[element_id] == "large-files-tab"
    for list_id in ("encryptedQueueList", "encryptedCacheList"):
        attributes = parser.elements[list_id]
        assert attributes["role"] == "list"
        assert attributes["aria-labelledby"] in parser.elements


def test_large_files_navigation_fails_closed_and_falls_back_when_disabled() -> None:
    """A stale/malformed discovery response never enables a sensitive workspace."""
    script = r"""
const fs = require('node:fs');
const vm = require('node:vm');
const source = fs.readFileSync(process.argv[1], 'utf8');
const start = source.indexOf('function getVisibleToolTabs()');
const end = source.indexOf('function refreshServerMethodBoundControls()', start);
const tab = target => ({
  hidden: target === 'large-files', disabled: false,
  dataset: { tabTarget: target }, attributes: {},
  setAttribute(name, value) { this.attributes[name] = value; },
});
const tabs = [tab('upload'), tab('large-files'), tab('files')];
let active = tabs[0];
const switches = [];
const context = {
  serverDiscoveryStatus: 'pending', serverEncryptedUploadCapabilities: null,
  document: {
    querySelectorAll() { return tabs; },
    querySelector() { return active; },
    getElementById(id) { return tabs.find(item => `tab-${item.dataset.tabTarget}` === id); },
  },
  switchTab(target, button) { switches.push(target); active = button; },
};
vm.createContext(context);
vm.runInContext(source.slice(start, end), context);
const valid = {
  browser_decryption: true, chunk_size: 8 * 1024 * 1024, enabled: true,
  max_plaintext_size: 2 * 1024 * 1024 * 1024, parallel_chunks: 2,
  server_decryption: true, version: 1,
};
const malformed = [
  null, {enabled: false}, {enabled: true}, [],
  {...valid, extra: true}, {...valid, enabled: 1}, {...valid, version: 2},
  {...valid, chunk_size: 1024}, {...valid, parallel_chunks: 3},
  {...valid, browser_decryption: 1}, {...valid, server_decryption: null},
  {...valid, max_plaintext_size: -1}, {...valid, max_plaintext_size: 1.1},
];
const observations = [];
for (const discovery of ['pending', 'unavailable', 'ready']) {
  context.serverDiscoveryStatus = discovery;
  for (const capability of [...malformed, valid]) {
    context.serverEncryptedUploadCapabilities = capability;
    context.refreshToolEntrypoints();
    observations.push({
      discovery, valid: capability === valid,
      hidden: tabs[1].hidden, disabled: tabs[1].disabled,
      ariaHidden: tabs[1].attributes['aria-hidden'],
      ordinaryVisible: tabs[0].hidden === false && tabs[2].hidden === false,
    });
  }
}
context.serverDiscoveryStatus = 'pending';
context.serverEncryptedUploadCapabilities = valid;
vm.runInContext('pendingLargeFilesHashRoute = true;', context);
context.refreshToolEntrypoints();
const deferredHashStayedPending = switches.length === 0 && active === tabs[0];
context.serverDiscoveryStatus = 'ready';
context.refreshToolEntrypoints();
context.serverEncryptedUploadCapabilities = {enabled: false};
context.refreshToolEntrypoints();
process.stdout.write(JSON.stringify({observations, switches, deferredHashStayedPending}));
"""
    completed = subprocess.run(
        ["node", "-e", script, str(UI_ROOT / "core.js")],
        cwd=REPO_ROOT,
        capture_output=True,
        check=False,
        text=True,
    )
    assert completed.returncode == 0, completed.stderr
    result = json.loads(completed.stdout)
    for observation in result["observations"]:
        expected_hidden = not (observation["discovery"] == "ready" and observation["valid"])
        assert observation["hidden"] is expected_hidden
        assert observation["disabled"] is expected_hidden
        assert observation["ariaHidden"] == str(expected_hidden).lower()
        assert observation["ordinaryVisible"] is True
    assert result["deferredHashStayedPending"] is True
    assert result["switches"] == ["large-files", "upload"]
