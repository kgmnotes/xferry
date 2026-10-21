"""Executable checks for secondary file-action disclosure lifecycle."""

from __future__ import annotations

import re
import subprocess
from pathlib import Path


def test_file_action_menu_reserves_its_row_space_on_desktop_and_mobile() -> None:
    css = (Path(__file__).resolve().parents[1] / "xferry/data/static/ui/features.css").read_text()
    for selector in (
        ".file-row__more .file-row__actions-secondary",
        ".uploaded-file--file .file-row__more .file-row__actions-secondary",
    ):
        match = re.search(re.escape(selector) + r"\s*\{([^}]+)\}", css)
        assert match is not None
        declarations = match[1]
        assert "position: static;" in declarations
        assert "width: 100%;" in declarations
        assert "max-width: 100%;" in declarations
        assert "position: absolute;" not in declarations
    assert "flex: 0 1 min(280px, 100%);" in css
    mobile_open = re.search(
        re.escape(".uploaded-file--file .file-row__more[open]") + r"\s*\{([^}]+)\}", css
    )
    assert mobile_open is not None
    assert "flex: 0 1 100%;" in mobile_open[1]
    # Native details groups its non-summary content into an anonymous grid item.
    # A second summary-only column would narrow that content by 44px.
    assert "grid-template-columns: minmax(0, 1fr);" in mobile_open[1]
    assert "grid-template-columns: minmax(0, 1fr) 44px;" not in mobile_open[1]
    mobile_summary = re.search(
        re.escape(".uploaded-file--file .file-row__more[open] > summary") + r"\s*\{([^}]+)\}",
        css,
    )
    assert mobile_summary is not None
    assert "grid-column: 1;" in mobile_summary[1]


def test_secondary_file_actions_close_menu_before_dispatch_and_keep_focus_origin() -> None:
    script = r"""
const fs = require("node:fs");
const source = fs.readFileSync(process.argv[1], "utf8");
const start = source.indexOf(
  "        const actionBtn = e.target.closest('[data-file-action][data-path]');"
);
const end = source.indexOf("    });\n\n    serverFilesEl.addEventListener('change'", start);
if (start < 0 || end < 0) throw new Error("delegated file-action handler missing");
const dispatch = new Function(
  "e", "filesState", "isFileDownloadSupported", "isSmuggleSupported", "isFileDeleteSupported",
  "downloadFile", "showXorDecryptDialog", "app", "deleteFile", "browsePathInput", "browseDirectory",
  source.slice(start, end)
);

for (const action of ["download", "decrypt-xor", "smuggle", "delete"]) {
  for (const inMenu of [true, false]) {
    for (const disabled of [true, false]) {
      const summary = { identity: "more-summary" };
      const disclosure = { open: true, querySelector(selector) {
        if (selector !== "summary") throw new Error("wrong focus-origin selector");
        return summary;
      } };
      const actionButton = {
        dataset: { fileAction: action, path: "%2Fuploads%2Fa.txt" },
        closest(selector) {
          if (selector !== ".file-row__more") throw new Error("wrong disclosure selector");
          return inMenu ? disclosure : null;
        },
      };
      let calls = 0;
      function activate(path, origin) {
        calls += 1;
        if (path !== "/uploads/a.txt") throw new Error("stored-file path changed");
        if (inMenu && disclosure.open) throw new Error(`${action}: menu open during dispatch`);
        if (action !== "download" && origin !== (inMenu ? summary : actionButton)) {
          throw new Error(`${action}: focus origin not preserved`);
        }
      }
      dispatch(
        { target: { closest: () => actionButton } }, { listActionsDisabled: disabled },
        () => true, () => true, () => true, activate, activate,
        { invoke(workflow, command, path, origin) {
          if (workflow !== "smuggle" || command !== "show-dialog") throw new Error("wrong command");
          activate(path, origin);
        } }, activate, {}, () => { throw new Error("unexpected directory action"); }
      );
      if (calls !== (disabled ? 0 : 1)) throw new Error("disabled action dispatch mismatch");
      if (inMenu && disclosure.open !== disabled) throw new Error("menu lifecycle mismatch");
    }
  }
}
"""
    result = subprocess.run(
        [
            "node",
            "-e",
            script,
            str(Path(__file__).resolve().parents[1] / "xferry/data/static/ui/files.js"),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr or result.stdout
