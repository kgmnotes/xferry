from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
EXPECTED_DOWNLOAD = list(b"browser smoke upload\n")


@pytest.mark.parametrize(
    ("variable", "error_prefix"),
    [
        pytest.param("downloadedBytes", "Client-side", id="client"),
        pytest.param("serverDownloadedBytes", "Server-side", id="server"),
    ],
)
@pytest.mark.parametrize(
    ("downloaded_bytes", "should_reject"),
    [
        pytest.param(EXPECTED_DOWNLOAD, False, id="exact-ascii-fixture"),
        pytest.param(
            [EXPECTED_DOWNLOAD[0] ^ 1, *EXPECTED_DOWNLOAD[1:]], True, id="one-byte-mutation"
        ),
        pytest.param(EXPECTED_DOWNLOAD[:-1], True, id="truncated"),
        pytest.param([*EXPECTED_DOWNLOAD, 0], True, id="extended"),
        pytest.param(
            [EXPECTED_DOWNLOAD[1], EXPECTED_DOWNLOAD[0], *EXPECTED_DOWNLOAD[2:]],
            True,
            id="reordered",
        ),
        pytest.param([str(byte) for byte in EXPECTED_DOWNLOAD], True, id="string-typed-bytes"),
    ],
)
def test_encrypted_download_guard_requires_exact_fixture_bytes(
    variable: str,
    error_prefix: str,
    downloaded_bytes: list[int] | list[str],
    should_reject: bool,
) -> None:
    """Execute each real journey guard without running the browser workflow."""
    node_script = r"""
const assert = require("node:assert/strict");
const fs = require("node:fs");
const [sourcePath, variable, errorPrefix, fixtureJSON] = process.argv.slice(1);
const { bytes, shouldReject } = JSON.parse(fixtureJSON);
const source = fs.readFileSync(sourcePath, "utf8");
const start = source.indexOf("  async function runEncryptedTransferJourney() {");
const end = source.indexOf("\n  async function ", start + 1);
assert.ok(start >= 0 && end > start, "actual encrypted journey is missing");
const guardPattern = new RegExp(
  String.raw`^      if \(JSON\.stringify\(${variable}\) !== ` +
  String.raw`JSON\.stringify\(expectedDownload\)\) \{[\s\S]*?^      \}`,
  "gm"
);
const guards = [...source.slice(start, end).matchAll(guardPattern)];
assert.equal(guards.length, 1, `expected exactly one actual ${variable} guard`);
const guard = new Function(variable, "expectedDownload", guards[0][0]);
const expectedDownload = Array.from(Buffer.from("browser smoke upload\n", "ascii"));
if (shouldReject) {
  assert.throws(() => guard(bytes, expectedDownload), {
    name: "Error",
    message: `${errorPrefix} decrypted bytes differ: ${JSON.stringify(bytes)}`,
  });
} else {
  assert.doesNotThrow(() => guard(bytes, expectedDownload));
}
"""
    completed = subprocess.run(
        [
            "node",
            "-e",
            node_script,
            str(REPO_ROOT / "tools/browser_smoke.playwright.js"),
            variable,
            error_prefix,
            json.dumps({"bytes": downloaded_bytes, "shouldReject": should_reject}),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
