from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]

NODE_SPA_FIXTURE = r"""
const assert = require("node:assert/strict");
const fs = require("node:fs");
const source = fs.readFileSync(process.argv[1], "utf8");
const options = JSON.parse(process.argv[2]);
const requirementStart = source.indexOf("  const spaRuntimeRequirements =");
const probeStart = source.indexOf("  function probeSpaReadiness(");
const waitStart = source.indexOf("  async function waitForSpaReady(");
const helperEnd = source.indexOf("  async function installClipboardMock(", waitStart);
assert.ok(requirementStart >= 0 && probeStart > requirementStart && waitStart > probeStart &&
  helperEnd > waitStart, "actual SPA runtime readiness helpers are missing");
const helperSource = source.slice(requirementStart, helperEnd);
const events = [];
const window = {};
const document = { readyState: "complete" };
const browserIssues = [];
const recentNetworkFailures = [];
let runtime;
let pollCalls = 0;

function setApp(changes = {}) {
  if (changes.noApp) {
    delete window.XferryApp;
    return;
  }
  const services = Object.fromEntries(runtime.requirements.services.map(name => [name, ["api"]]));
  const workflows = Object.fromEntries(runtime.requirements.workflows.map(name => [name, ["run"]]));
  if (changes.emptyRegistry) {
    for (const name of Object.keys(services)) delete services[name];
    for (const name of Object.keys(workflows)) delete workflows[name];
  }
  if (changes.missingService) delete services[changes.missingService];
  if (changes.missingWorkflow) delete workflows[changes.missingWorkflow];
  const app = {
    describe: () => {
      if (changes.describeThrows) throw new Error("registry probe failed");
      return { services, workflows };
    },
    hasWorkflow: name => Object.hasOwn(workflows, name),
  };
  if (changes.noDescribe) delete app.describe;
  // There is no app.ready promise/property in the product's public API.
  Object.defineProperty(app, "ready", {
    get() { throw new Error("readiness must not invent an app.ready API"); },
  });
  window.XferryApp = app;
}

const locator = selector => ({
  first() { return this; },
  waitFor: async state => { events.push({ event: "static-shell", selector, state }); },
});
const page = {
  waitForLoadState: async state => {
    assert.equal(state, "domcontentloaded");
    events.push({ event: "domcontentloaded" });
  },
  locator,
  waitForFunction: async (predicate, arg, timing) => {
    pollCalls += 1;
    assert.equal(timing.timeout, 37);
    const initial = predicate(arg);
    events.push({ event: "runtime-poll", ready: initial });
    if (options.kind === "transition") {
      assert.equal(initial, false, "static HTML must not complete readiness before registration");
      setApp();
      assert.equal(predicate(arg), true, "registered runtime must complete the same predicate");
      events.push({ event: "runtime-registered" });
      return;
    }
    if (!initial) throw new Error("page.waitForFunction: Timeout 37ms exceeded");
  },
  evaluate: async (callback, arg) => callback(arg),
  goto: async () => assert.fail("a failed bootstrap must not be hidden by another navigation"),
  reload: async () => assert.fail("a failed bootstrap must not be hidden by a reload"),
  waitForTimeout: async () => {
    assert.fail("runtime registration must use polling without fixed sleep");
  },
};
runtime = new Function(
  "window", "document", "page", "browserIssues", "recentNetworkFailures",
  `${helperSource}\nreturn {probe: probeSpaReadiness, wait: waitForSpaReady,
    requirements: spaRuntimeRequirements};`
)(window, document, page, browserIssues, recentNetworkFailures);
setApp(options.changes);

(async () => {
  if (options.kind === "probe") {
    const ready = runtime.probe(runtime.requirements);
    assert.equal(ready, options.expected);
    const detail = runtime.probe({ ...runtime.requirements, describe: true });
    assert.equal(detail.ready, options.expected);
    if (options.changes?.noApp) assert.equal(detail.hasApp, false);
    if (options.changes?.missingService) {
      assert.ok(detail.missingServices.includes(options.changes.missingService));
      assert.ok(!detail.registeredServices.includes(options.changes.missingService));
    }
    if (options.changes?.missingWorkflow) {
      assert.ok(detail.missingWorkflows.includes(options.changes.missingWorkflow));
      assert.ok(!detail.registeredWorkflows.includes(options.changes.missingWorkflow));
    }
    if (options.changes?.describeThrows) {
      assert.match(detail.registryError, /registry probe failed/);
    }
    if (options.expected) {
      assert.deepEqual(detail.missingServices, []);
      assert.deepEqual(detail.missingWorkflows, []);
    }
    return;
  }

  if (options.kind === "diagnostic") {
    const url = `https://example.test/static/ui/${options.asset}`;
    recentNetworkFailures.push({ url, error: options.networkError, resourceType: "script" });
    browserIssues.push({
      kind: "pageerror", message: `Service is not registered: ${options.changes.missingService}`,
      url: "https://example.test/", lineNumber: 0, columnNumber: 0,
    });
    await assert.rejects(runtime.wait(37), error => {
      assert.match(error.message, /runtime|SPA|Spa|spa/);
      assert.ok(error.message.includes(options.asset), "failed script name must be diagnosed");
      assert.ok(error.message.includes(options.networkError), "transport error must be diagnosed");
      assert.ok(error.message.includes("missingServices"), "missing services must be diagnosed");
      assert.ok(error.message.includes(options.changes.missingService));
      assert.ok(error.message.includes("missingWorkflows"));
      assert.ok(error.message.includes(options.changes.missingWorkflow));
      return true;
    });
  } else {
    await runtime.wait(37);
    assert.equal(events.at(-1).event,
      options.kind === "transition" ? "runtime-registered" : "runtime-poll");
  }
  assert.equal(pollCalls, 1, "readiness should use one predicate rather than retrying the journey");
  assert.ok(events.some(event => event.event === "static-shell"));
})().catch(error => { console.error(error); process.exitCode = 1; });
"""


def _assert_spa_readiness(**options: object) -> None:
    completed = subprocess.run(
        [
            "node",
            "-e",
            NODE_SPA_FIXTURE,
            str(REPO_ROOT / "tools/browser_smoke.playwright.js"),
            json.dumps(options),
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert completed.returncode == 0, completed.stderr or completed.stdout


@pytest.mark.parametrize(
    "changes",
    [
        pytest.param({"noApp": True}, id="no-application"),
        pytest.param({"emptyRegistry": True}, id="static-shell-only"),
        pytest.param({"noDescribe": True}, id="missing-runtime-registry"),
        pytest.param({"describeThrows": True}, id="failed-registry-probe"),
    ],
)
def test_spa_readiness_rejects_visible_shell_without_registered_runtime(
    changes: dict[str, object],
) -> None:
    _assert_spa_readiness(kind="probe", changes=changes, expected=False)


@pytest.mark.parametrize(
    "service",
    [
        "core",
        "http",
        "inspector",
        "dialogs",
        "notifications",
        "http-errors",
        "advanced-session",
        "advanced-compiler",
    ],
)
def test_spa_readiness_requires_each_runtime_service(service: str) -> None:
    _assert_spa_readiness(kind="probe", changes={"missingService": service}, expected=False)


@pytest.mark.parametrize(
    "workflow",
    ["upload", "requests", "advanced", "files", "notepad", "smuggle", "encrypted-transfer"],
)
def test_spa_readiness_requires_each_runtime_workflow(workflow: str) -> None:
    _assert_spa_readiness(kind="probe", changes={"missingWorkflow": workflow}, expected=False)


def test_spa_readiness_accepts_complete_registration_without_inventing_app_ready() -> None:
    _assert_spa_readiness(kind="probe", changes={}, expected=True)
    _assert_spa_readiness(kind="complete", changes={})


def test_spa_readiness_waits_for_registration_instead_of_accepting_static_shell() -> None:
    _assert_spa_readiness(kind="transition", changes={"emptyRegistry": True})


@pytest.mark.parametrize(
    ("asset", "network_error", "missing_service"),
    [
        ("core.js", "net::ERR_CONNECTION_RESET", "core"),
        ("opsec.js", "net::ERR_PROXY_CONNECTION_FAILED", "inspector"),
    ],
)
def test_spa_readiness_diagnoses_asset_transport_and_missing_dependencies_without_retry(
    asset: str, network_error: str, missing_service: str
) -> None:
    _assert_spa_readiness(
        kind="diagnostic",
        changes={"missingService": missing_service, "missingWorkflow": "advanced"},
        asset=asset,
        networkError=network_error,
    )


def test_script_diagnostics_capture_transport_and_http_failures_without_false_positives() -> None:
    """Execute the real event handlers so script failures retain their failure class."""
    node_script = r"""
const assert = require("node:assert/strict");
const fs = require("node:fs");
const source = fs.readFileSync(process.argv[1], "utf8");
const start = source.indexOf("  const recentNetworkFailures = [];");
const end = source.indexOf("  const rootUrl =", start);
assert.ok(start >= 0 && end > start, "actual transport diagnostic recorder is missing");
const listeners = new Map();
const page = { on: (name, listener) => listeners.set(name, listener) };
const failures = new Function("page", `${source.slice(start, end)}
return recentNetworkFailures;`)(page);
const request = (url, resourceType, errorText) => ({
  url: () => url,
  resourceType: () => resourceType,
  failure: () => errorText === null ? null : { errorText },
});
const response = (url, resourceType, status) => ({
  url: () => url,
  status: () => status,
  request: () => request(url, resourceType, null),
});
listeners.get("requestfailed")(
  request("https://example.test/static/ui/core.js", "script", "net::ERR_CONNECTION_RESET")
);
listeners.get("requestfailed")(
  request("https://example.test/static/ui/opsec.js", "script", "net::ERR_PROXY_CONNECTION_FAILED")
);
for (const status of [401, 407, 503]) {
  listeners.get("response")(
    response(`https://example.test/static/ui/dependency-${status}.js`, "script", status)
  );
}
const expected = [
  ["core.js", "script", "net::ERR_CONNECTION_RESET"],
  ["opsec.js", "script", "net::ERR_PROXY_CONNECTION_FAILED"],
  ["dependency-401.js", "script", "HTTP 401"],
  ["dependency-407.js", "script", "HTTP 407"],
  ["dependency-503.js", "script", "HTTP 503"],
];
assert.deepEqual(failures.map(item => [item.url.split("/").pop(), item.resourceType, item.error]),
  expected);
listeners.get("response")(response("https://example.test/static/ui/app.js", "script", 200));
listeners.get("response")(response("https://example.test/static/ui/logo.svg", "image", 404));
assert.equal(failures.length, expected.length,
  "successful scripts and an unrelated HTTP image error must not be failed scripts");
for (let index = 0; index < 25; index += 1) {
  listeners.get("requestfailed")(
    request(`https://example.test/probe-${index}.js`, "script", "net::ERR_FAILED")
  );
}
assert.equal(failures.length, 20, "transport diagnostics must have a bounded history");
assert.ok(failures[0].url.endsWith("probe-5.js"));
assert.ok(failures.at(-1).url.endsWith("probe-24.js"));
"""
    completed = subprocess.run(
        ["node", "-e", node_script, str(REPO_ROOT / "tools/browser_smoke.playwright.js")],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert completed.returncode == 0, completed.stderr or completed.stdout
