"""Request examples must never delete an existing file while preparing a demo."""

import json
import subprocess
from pathlib import Path


def test_demo_preparation_creates_unique_files_and_uses_the_returned_path() -> None:
    source = Path(__file__).resolve().parents[1] / "xferry/data/static/ui/requests.js"
    script = r"""
const fs = require('node:fs');
const source = fs.readFileSync(process.argv[1], 'utf8');
globalThis.window = { crypto: require('node:crypto').webcrypto };
globalThis.SERVER_URL = 'http://127.0.0.1:8080';
globalThis.parseJsonSafe = JSON.parse;
function load(start, end) {
    const offset = source.indexOf(start);
    return (0, eval)(`(${source.slice(offset, source.indexOf(end, offset)).trim()})`);
}
globalThis.buildDemoFilename = load('function buildDemoFilename', 'function buildDemoUploadPath');
globalThis.buildDemoUploadPath = load(
    'function buildDemoUploadPath',
    'function buildDemoUploadBody',
);
globalThis.buildDemoUploadBody = load(
    'function buildDemoUploadBody',
    'function getCanonicalUploadPath',
);
globalThis.getCanonicalUploadPath = load(
    'function getCanonicalUploadPath',
    'async function createRequestPanelDemoFile',
);
globalThis.createRequestPanelDemoFile = load(
    'async function createRequestPanelDemoFile',
    'function isRequestPanelSmuggleUploadPath',
);
const buildRequestScenario = load(
    'async function buildRequestScenario',
    'function isRequestPanelSmuggleStateReady',
);
const calls = [];
globalThis.sendCustomRequest = async (method, url, body, headers) => {
    calls.push({ method, url, filename: headers['X-File-Name'] });
    return {
        ok: true,
        text: async () => JSON.stringify({ file: { path: '/uploads/server-selected.txt' } }),
    };
};
(async () => {
    const first = await buildRequestScenario('POST', '/uploads/request-panel-post.txt');
    const second = await buildRequestScenario('POST', '/uploads/request-panel-post.txt');
    const callsBeforeDeleteDemo = calls.length;
    const deletion = await buildRequestScenario('DELETE', '/uploads/existing-user-file.txt');
    process.stdout.write(JSON.stringify({
        first: first.headers['X-File-Name'], second: second.headers['X-File-Name'],
        callsBeforeDeleteDemo, calls, deletionPath: deletion.path,
    }));
})().catch(error => { process.stderr.write(error.stack); process.exitCode = 1; });
"""
    result = subprocess.run(
        ["node", "-e", script, str(source)], capture_output=True, text=True, check=False
    )
    assert result.returncode == 0, result.stderr
    data = json.loads(result.stdout)
    assert data["first"] != data["second"]
    assert data["first"].startswith("request-panel-post-")
    assert data["callsBeforeDeleteDemo"] == 0
    assert [call["method"] for call in data["calls"]] == ["POST"]
    assert data["deletionPath"] == "/uploads/server-selected.txt"
