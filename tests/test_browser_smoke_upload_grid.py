from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]

NODE_GRID_FIXTURE = r"""
const assert = require("node:assert/strict");
const fs = require("node:fs");
const source = fs.readFileSync(process.argv[1], "utf8");
const options = JSON.parse(process.argv[2]);
const probeStart = source.indexOf("  function probeUploadTargetPathGrid(");
const helperStart = source.indexOf("  async function assertMobileUploadTargetPathGrid(");
const helperEnd = source.indexOf("  async function assertResponsiveUploadSummaryAndActions(");
assert.ok(probeStart >= 0 && helperStart > probeStart && helperEnd > helperStart,
  "actual visible upload-grid probe/helper is missing");
const events = [];
const details = { open: options.kind === "helper" ? false :
  !options.hidden && !options.closedWithGeometry };
const targets = ["/", "/upload", "/api", "/file"];
let groupBounds = { left: 44, top: 600, width: 302, height: 96 };
let bounds = targets.map((target, index) => ({
  left: 44 + index % 2 * 155,
  top: 600 + Math.floor(index / 2) * 52,
  width: 147,
  height: 44,
}));
let actualTargets = [...targets];
let clipped = -1;
const scenario = options.scenario || "valid";
switch (scenario) {
  case "valid": break;
  case "missing-button": bounds.pop(); actualTargets.pop(); break;
  case "extra-button": bounds.push({ left: 44, top: 704, width: 147, height: 44 });
    actualTargets.push("/other"); break;
  case "wrong-target": actualTargets[2] = "/wrong"; break;
  case "duplicate-target": actualTargets[2] = "/upload"; break;
  case "wrong-label": break;
  case "one-row": bounds = targets.map((_, index) => ({
    left: 44 + index * 77, top: 600, width: 71, height: 44,
  })); break;
  case "one-column": groupBounds.height = 200; bounds = targets.map((_, index) => ({
    left: 44, top: 600 + index * 52, width: 302, height: 44,
  })); break;
  case "three-plus-one": bounds = targets.map((_, index) => ({
    left: 44 + (index < 3 ? index : 0) * 103,
    top: index < 3 ? 600 : 652, width: 95, height: 44,
  })); break;
  case "row-misaligned": bounds[1].top += 3; break;
  case "column-misaligned": bounds[2].left += 3; break;
  case "columns-overlap": bounds[0].width = 159; bounds[2].width = 159; break;
  case "rows-overlap": bounds[2].top = 640; bounds[3].top = 640; break;
  case "button-overflow": bounds[3].width = 205; break;
  case "vertical-overflow": bounds[2].top = 704; bounds[3].top = 704; break;
  case "group-overflow": groupBounds.left = -4; groupBounds.width = 394; break;
  case "clipped-label": clipped = 1; break;
  case "short-button": bounds.forEach(rect => { rect.height = 43; }); break;
  case "narrow-button": bounds[0].width = 43; bounds[2].width = 43; break;
  case "fractional-touch-size": bounds.forEach(rect => { rect.height = 43.999; }); break;
  case "subpixel-alignment": bounds[1].top += 0.5; break;
  case "zero-width": bounds.forEach(rect => { rect.width = 0; }); break;
  default: throw new Error(`Unknown scenario: ${scenario}`);
}
const rect = (value, visible = true) => {
  const actual = visible ? value : { left: 0, top: 0, width: 0, height: 0 };
  return { ...actual, right: actual.left + actual.width, bottom: actual.top + actual.height,
    x: actual.left, y: actual.top, toJSON() { return { ...actual }; } };
};
const hasLayout = () => (details.open || options.closedWithGeometry) && !options.hidden;
const buttons = bounds.map((value, index) => ({
  dataset: { uploadTargetPath: actualTargets[index] },
  textContent: scenario === "wrong-label" && index === 2 ? "/wrong" : actualTargets[index],
  hidden: false,
  disabled: false,
  getBoundingClientRect: () => rect(value, hasLayout()),
  getClientRects: () => hasLayout() ? [rect(value)] : [],
  get clientWidth() { return hasLayout() ? value.width : 0; },
  get scrollWidth() { return hasLayout() ? value.width + (clipped === index ? 10 : 0) : 0; },
  getAttribute: name => {
    if (name === "data-upload-target-path") return actualTargets[index];
    if (name === "aria-hidden") return null;
    throw new Error(`Unexpected button attribute: ${name}`);
  },
}));
const group = {
  hidden: false,
  getBoundingClientRect: () => rect(groupBounds, hasLayout()),
  getClientRects: () => hasLayout() ? [rect(groupBounds)] : [],
  querySelectorAll: selector => {
    assert.equal(selector, "[data-upload-target-path]");
    return buttons;
  },
  closest: selector => {
    assert.equal(selector, "#uploadAdvancedControls");
    return details;
  },
};
const document = {
  documentElement: { clientWidth: 390, scrollWidth: 390 },
  getElementById: id => {
    if (id === "uploadTargetPathGroup") return options.noGroup ? null : group;
    if (id === "uploadAdvancedControls") return details;
    throw new Error(`Unexpected DOM id: ${id}`);
  },
};
const getComputedStyle = () => ({
  display: "grid", visibility: "visible",
  gridTemplateColumns: options.template || "147px 147px",
});
const summarySelector = "#uploadAdvancedControls > summary";
const page = {
  locator: selector => {
    if (selector === summarySelector) return {
      click: async () => {
        details.open = !details.open;
        events.push(details.open ? "open" : "close");
      },
    };
    if (selector === "#uploadTargetPathGroup") return {
      waitFor: async ({ state }) => {
        assert.ok(["visible", "hidden"].includes(state));
        assert.equal(details.open, state === "visible",
          "visibility must follow the real Advanced disclosure state");
        events.push(state);
      },
    };
    throw new Error(`Unexpected locator: ${selector}; only Advanced controls may be opened`);
  },
  evaluate: async (callback, arg) => {
    assert.equal(details.open, true, "collapsed zero-size controls must not be measured");
    events.push("measure");
    return callback(arg);
  },
  goto: async () => assert.fail("a layout failure must not be hidden by navigation"),
  reload: async () => assert.fail("a layout failure must not be hidden by reload"),
};
const runtime = new Function("document", "getComputedStyle", "innerWidth", "page", `
${source.slice(probeStart, helperEnd)}
return {probe: probeUploadTargetPathGrid, check: assertMobileUploadTargetPathGrid};
`)(document, getComputedStyle, 390, page);
(async () => {
  if (options.kind === "helper") {
    assert.equal(details.open, false);
    if (options.expected) {
      const result = await runtime.check();
      assert.equal(result.valid, true);
    } else {
      await assert.rejects(runtime.check(), /grid|Grid|target|Target/);
    }
    assert.equal(details.open, false, "the Advanced disclosure must be collapsed again");
    assert.deepEqual(events, ["open", "visible", "measure", "close", "hidden"]);
    return;
  }
  const result = runtime.probe();
  assert.equal(result.valid, options.expected,
    `unexpected grid verdict for ${scenario}: ${JSON.stringify(result)}`);
  if (options.expected) {
    assert.equal(result.columns, 2);
    assert.equal(result.rows, 2);
    assert.equal(result.labelsFit, true);
    assert.equal(result.template, options.template || "147px 147px");
  } else if (options.hidden || options.noGroup || options.closedWithGeometry) {
    assert.equal(result.visible, false);
    assert.equal(result.labelsFit, false, "unavailable labels cannot count as visibly fitting");
    if (options.closedWithGeometry) {
      assert.equal(result.advancedOpen, false);
      assert.equal(result.columns, 2);
      assert.equal(result.rows, 2);
      assert.equal(result.aligned, true);
      assert.equal(result.contained, true);
      assert.ok(result.buttons.every(button => button.width > 0 && button.height > 0),
        "the closed Advanced fixture must keep healthy nonzero browser layout boxes");
    }
  }
})().catch(error => { console.error(error); process.exitCode = 1; });
"""


def _assert_upload_grid(**options: object) -> None:
    result = subprocess.run(
        [
            "node",
            "-e",
            NODE_GRID_FIXTURE,
            str(REPO_ROOT / "tools/browser_smoke.playwright.js"),
            json.dumps(options),
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 0, result.stderr or result.stdout


@pytest.mark.parametrize(
    "template",
    ["147px 147px", "repeat(2, minmax(0px, 1fr))", "repeat(2,minmax(0px,1fr))"],
)
def test_visible_upload_grid_uses_geometry_instead_of_css_serialization(template: str) -> None:
    _assert_upload_grid(kind="probe", template=template, expected=True)


@pytest.mark.parametrize(
    "scenario",
    [
        "missing-button",
        "extra-button",
        "wrong-target",
        "duplicate-target",
        "wrong-label",
        "one-row",
        "one-column",
        "three-plus-one",
        "row-misaligned",
        "column-misaligned",
        "columns-overlap",
        "rows-overlap",
        "button-overflow",
        "vertical-overflow",
        "group-overflow",
        "clipped-label",
        "short-button",
        "narrow-button",
        "zero-width",
    ],
)
def test_visible_upload_grid_rejects_broken_control_layout(scenario: str) -> None:
    _assert_upload_grid(kind="probe", scenario=scenario, expected=False)


def test_visible_upload_grid_rejects_collapsed_zero_size_controls() -> None:
    _assert_upload_grid(kind="probe", hidden=True, expected=False)


def test_upload_grid_rejects_closed_advanced_even_with_nonzero_button_rectangles() -> None:
    _assert_upload_grid(kind="probe", closedWithGeometry=True, expected=False)


def test_visible_upload_grid_rejects_missing_group() -> None:
    _assert_upload_grid(kind="probe", noGroup=True, expected=False)


@pytest.mark.parametrize("scenario", ["fractional-touch-size", "subpixel-alignment"])
def test_visible_upload_grid_accepts_browser_subpixel_rounding(scenario: str) -> None:
    _assert_upload_grid(kind="probe", scenario=scenario, expected=True)


@pytest.mark.parametrize("scenario,expected", [("valid", True), ("clipped-label", False)])
def test_upload_grid_helper_opens_measures_and_restores_only_advanced_controls(
    scenario: str, expected: bool
) -> None:
    _assert_upload_grid(kind="helper", scenario=scenario, expected=expected)
