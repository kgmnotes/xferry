"""Cooperative Requests cancellation preserves completed logical operations."""

import subprocess
from pathlib import Path

import pytest

SOURCE = Path(__file__).resolve().parents[1] / "xferry/data/static/ui/requests.js"

HARNESS = r"""
const fs = require('node:fs');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const source = fs.readFileSync(process.argv[1], 'utf8');
const scenario = process.argv[2];
const noop = () => {};
const calls = [];
const notices = [];
const errors = [];
globalThis.window = { crypto: require('node:crypto').webcrypto };
globalThis.document = { activeElement: null, body: {} };
globalThis.requestBatchStopBtnEl = {};
globalThis.requestRunAllBtnEl = {};
globalThis.requestTechnicalDetailsEl = {};
globalThis.requestBatchDetailsEl = {};
globalThis.requestBatchIssuesOnlyToggleEl = {};
globalThis.requestBatchExportBtnEl = {};
globalThis.responseAreaEl = {};
globalThis.pathInputEl = { value: '/index.html' };
globalThis.SERVER_URL = 'http://localhost';
globalThis.requestPanelPrepMethods = new Set(['DELETE', 'FETCH', 'SMUGGLE']);
globalThis.requestBatchInitialPaths = {};
globalThis.requestState = {
    busy: false, batchRunning: false, batchPlanMethods: [], preview: {},
    execution: { kind: 'all', phase: 'idle', completed: 0, total: 0, stopRequested: false },
    batchRun: { phase: 'idle', completed: 0, total: 0, results: [], selectedExchangeId: '' },
};
globalThis.t = value => value;
globalThis.parseJsonSafe = JSON.parse;
globalThis.app = { getState: () => ({ enabled: true, status: 'valid', capabilities: {} }) };
globalThis.isServerMethodSupported = () => true;
globalThis.resolveStableRequestTriggerElement = value => value;
globalThis.cloneRequestPreviewState = value => structuredClone(value);
globalThis.createRequestPreviewModel = (method, path) => ({ method, path });
globalThis.createRequestExchangeSnapshot = () => ({ id: `exchange-${calls.length}` });
globalThis.focusElementWithoutScroll = element => { document.activeElement = element; };
globalThis.announceLiveRegion = (region, text) => notices.push({ region, text });
globalThis.syncRequestControlState = () => updateRequestBatchStopButtonState();
for (const name of [
    'renderRequestBatchSummary', 'setResponseAreaState', 'renderRequestProgress',
    'setRequestPreviewPreparing', 'setRequestPreviewModel', 'setRequestPreviewResult',
    'renderRequestSuccess', 'renderRequestError', 'renderRequestPreview',
    'updateRequestBatchExportButtonState', 'updateRequestBatchRerunIssuesButtonState',
]) globalThis[name] = noop;
globalThis.httpErrors = {
    close: noop,
    show: options => {
        errors.push(options);
        // The visible Retry callback must not start a second request in a batch.
        void options.retry();
    },
};
globalThis.buildRequestExecutionResult = (method, path, result) => ({
    method, path, expectedStatus: '200 OK', actualStatus: result?.status || 'error',
    checkState: result?.kind !== 'response' ? 'failed' : result.status < 400 ? 'match' : 'mismatch',
    checkLabel: '', checkTone: '',
});
function load(name) {
    const match = new RegExp(`^(?:async )?function ${name}\\(`, 'm').exec(source);
    assert.ok(match, `missing function ${name}`);
    const end = source.indexOf('\n}', match.index) + 2;
    vm.runInThisContext(source.slice(match.index, end), { filename: name });
}
for (const name of [
    'normalizeRequestPath', 'setRequestPathValue', 'setRequestButtonsBusy',
    'setRequestBatchBusy', 'openRequestBatchDetails', 'getRequestBatchExecution',
    'getUnrunRequestBatchMethods', 'updateRequestBatchStopButtonState', 'stopRequestBatch',
    'executeRequestBatch', 'getRequestBatchPlan', 'countRequestBatchResults',
    'createRequestBatchAttempt', 'getRequestBatchAttempts', 'getRequestBatchCheckLabel',
    'buildRequestBatchResult', 'getRequestBatchStatusText', 'buildRequestBatchReport',
    'clearRequestBatchRun', 'updateRequestBatchResult', 'isRequestBatchIssue',
    'getRequestBatchIssueResults', 'getRequestBatchEmptyText', 'rerunRequestBatchIssues',
    'buildDemoFilename', 'buildDemoUploadPath', 'buildDemoUploadBody',
    'getCanonicalUploadPath', 'createRequestPanelDemoFile', 'buildRequestScenario',
    'isRequestPanelSmuggleStateReady', 'sendRequest', 'executeRequestScenario',
    'runAllRequestMethods',
]) load(name);
const response = (status = 200) => ({
    status, statusText: status === 200 ? 'OK' : 'Error', ok: status < 400, headers: {},
    text: async () => JSON.stringify({ file: { path: '/uploads/server-renamed-demo.txt' } }),
});
const deferred = () => {
    let resolve, reject;
    const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
    return { promise, resolve, reject };
};
const flush = () => new Promise(resolve => setImmediate(resolve));
function methods(...names) {
    globalThis.requestMethodButtons = names.map(method => ({ dataset: { requestMethod: method } }));
}
function transport(handler) {
    globalThis.sendCustomRequest = async (method, url, body, headers) => {
        calls.push({ method, url, body, headers });
        return handler(calls.length, method);
    };
}
async function stopAndTryConflictingActions() {
    document.activeElement = requestBatchStopBtnEl;
    stopRequestBatch();
    stopRequestBatch();
    assert.equal(requestState.execution.phase, 'stopping');
    assert.equal(requestBatchStopBtnEl.disabled, true);
    clearRequestBatchRun();
    await sendRequest('HEAD');
    await runAllRequestMethods();
    await rerunRequestBatchIssues();
}
(async () => {
    if (scenario === 'partial' || scenario === 'timeout') {
        methods('GET', 'HEAD', 'PING');
        const pending = deferred();
        transport(() => pending.promise);
        const running = runAllRequestMethods();
        await flush();
        await stopAndTryConflictingActions();
        assert.equal(calls.length, 1);
        if (scenario === 'timeout') pending.reject(new Error('timeout'));
        else pending.resolve(response());
        await running;
        const report = buildRequestBatchReport();
        assert.equal(report.phase, 'stopped');
        assert.equal(report.completed, 1);
        assert.equal(report.total, 3);
        assert.equal(report.results.length, 1);
        assert.deepEqual(report.unrunMethods, ['HEAD', 'PING']);
        assert.deepEqual(report.execution, {
            kind: 'all', phase: 'stopped', completed: 1, total: 3,
        });
        assert.equal(report.results[0].attempts.length, 1);
        assert.equal(requestState.busy, false);
        assert.equal(requestState.batchRunning, false);
        assert.equal(requestBatchStopBtnEl.hidden, true);
        assert.equal(document.activeElement, requestRunAllBtnEl);
        assert.equal(calls.length, 1);
        if (scenario === 'timeout') assert.equal(report.results[0].checkState, 'failed');
        else assert.match(getRequestBatchEmptyText(), /requestBatchNoIssuesPartial/);
        transport(() => response());
        await runAllRequestMethods();
        assert.equal(buildRequestBatchReport().phase, 'complete');
        assert.equal(buildRequestBatchReport().results.length, 3);
        assert.deepEqual(buildRequestBatchReport().unrunMethods, []);
        assert.equal(requestState.execution.stopRequested, false);
    } else if (['DELETE', 'FETCH', 'SMUGGLE'].includes(scenario)) {
        methods(scenario, 'GET');
        const prep = deferred();
        transport(index => index === 1 ? prep.promise : response());
        const running = runAllRequestMethods();
        await flush();
        assert.deepEqual(calls.map(call => call.method), ['POST']);
        await stopAndTryConflictingActions();
        prep.resolve(response(201));
        await running;
        assert.deepEqual(calls.map(call => call.method), ['POST', scenario]);
        assert.equal(calls[1].url, 'http://localhost/uploads/server-renamed-demo.txt');
        assert.equal(buildRequestBatchReport().results[0].path, '/uploads/server-renamed-demo.txt');
        assert.equal(buildRequestBatchReport().completed, 1);
        assert.equal(buildRequestBatchReport().phase, 'stopped');
    } else if (scenario === 'issues') {
        methods('GET', 'HEAD', 'PING');
        transport(() => response(500));
        await runAllRequestMethods();
        assert.equal(calls.length, 3); // Retry callbacks did not start parallel sends.
        const before = buildRequestBatchReport();
        const pending = deferred();
        transport(() => pending.promise);
        const running = rerunRequestBatchIssues();
        await flush();
        await stopAndTryConflictingActions();
        pending.resolve(response());
        await running;
        const report = buildRequestBatchReport();
        assert.equal(calls.length, 4);
        assert.equal(report.phase, 'complete');
        assert.equal(report.total, 3);
        assert.equal(report.completed, 3);
        assert.equal(report.results.length, 3);
        assert.deepEqual(report.execution, {
            kind: 'issues', phase: 'stopped', completed: 1, total: 3,
        });
        assert.equal(report.results[0].attempts.length, 2);
        assert.deepEqual(report.results.slice(1), before.results.slice(1));
        assert.deepEqual(report.unrunMethods, []);
    } else if (scenario === 'last') {
        methods('GET');
        const pending = deferred();
        transport(() => pending.promise);
        const running = runAllRequestMethods();
        await flush();
        stopRequestBatch();
        pending.resolve(response());
        await running;
        assert.equal(buildRequestBatchReport().phase, 'complete');
        assert.equal(buildRequestBatchReport().execution.phase, 'complete');
    } else {
        throw new Error(`Unknown scenario: ${scenario}`);
    }
})().catch(error => { process.stderr.write(error.stack); process.exitCode = 1; });
"""


@pytest.mark.parametrize(
    "scenario", ["partial", "timeout", "DELETE", "FETCH", "SMUGGLE", "issues", "last"]
)
def test_cooperative_batch_stop(scenario: str) -> None:
    result = subprocess.run(
        ["node", "-e", HARNESS, str(SOURCE), scenario],
        capture_output=True,
        text=True,
        check=False,
        timeout=15,
    )
    assert result.returncode == 0, result.stderr
