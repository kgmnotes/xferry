"""Browser-side EUF v1 crypto and encrypted-transfer workflow tests."""

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
UI_ROOT = REPO_ROOT / "xferry" / "data" / "static" / "ui"


def _run_node(script: str, *paths: Path) -> subprocess.CompletedProcess[str]:
    if paths and paths[0].name == "encrypted-transfer.js":
        install = """
const { installTransferServices } = require('./tests/encrypted_workflow_harness.js');
const transferServices = installTransferServices(
  app, require('node:path').dirname(process.argv[1]),
  typeof transferFixtureOptions === 'undefined' ? {} : transferFixtureOptions
);
"""
        script = script.replace(
            "vm.runInThisContext(fs.readFileSync(process.argv[1], 'utf8')",
            install + "vm.runInThisContext(fs.readFileSync(process.argv[1], 'utf8')",
            1,
        )
    return subprocess.run(
        ["node", "-e", script, *(str(path) for path in paths)],
        cwd=REPO_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )


def test_browser_crypto_matches_independent_euf_v1_vectors() -> None:
    """Wrong KDF labels, AAD layout, nonces, or metadata JSON break Python interop."""
    script = r"""
const fs = require('node:fs');
const vm = require('node:vm');
const nodeCrypto = require('node:crypto');

const services = new Map();
const app = {
  registerService(name, api) {
    services.set(name, Object.freeze({ ...api }));
  },
};
const context = {
  window: { XferryApp: app },
  crypto: nodeCrypto.webcrypto,
  TextEncoder,
  TextDecoder,
  Uint8Array,
  ArrayBuffer,
  DataView,
  atob,
  btoa,
};
vm.runInNewContext(fs.readFileSync(process.argv[1], 'utf8'), context, {
  filename: process.argv[1],
});

function hex(value) {
  return Buffer.from(value).toString('hex');
}

(async () => {
  const codec = services.get('encrypted-transfer-crypto');
  if (!codec) throw new Error('encrypted-transfer-crypto service was not registered');

  const manifest = {
    version: 1,
    fileId: '00112233445566778899aabbccddeeff',
    plaintextSize: 20,
    chunkSize: 8 * 1024 * 1024,
    chunkCount: 1,
    salt: Uint8Array.from({ length: 16 }, (_value, index) => index),
    noncePrefix: Uint8Array.from({ length: 8 }, (_value, index) => 0xa0 + index),
  };
  const keys = await codec.deriveKeys(
    'correct horse battery staple',
    manifest.salt,
    manifest.fileId
  );
  const metadata = {
    name: 'report.txt',
    content_type: 'text/plain',
    last_modified_ms: 1720000000123,
  };
  const plaintext = new TextEncoder().encode('0123456789abcdefghij');
  const encryptedMetadata = await codec.encryptMetadata(metadata, keys.contentKey, manifest);
  const encryptedChunk = await codec.encryptChunk(plaintext, keys.contentKey, manifest, 0);
  const resumeMac = await codec.computeResumeMac(plaintext, keys.resumeKey, manifest, 0);
  const decryptedMetadata = await codec.decryptMetadata(
    encryptedMetadata,
    keys.contentKey,
    { ...manifest, encryptedMetadata }
  );
  const decryptedChunk = await codec.decryptChunk(
    encryptedChunk,
    keys.contentKey,
    manifest,
    0
  );
  const tampered = encryptedChunk.slice();
  tampered[0] ^= 1;

  process.stdout.write(JSON.stringify({
    contentKey: hex(keys.contentKey),
    resumeKey: hex(keys.resumeKey),
    metadataAad: hex(codec.buildMetadataAad(manifest)),
    chunkAad: hex(codec.buildChunkAad(manifest, 0, plaintext.byteLength)),
    encryptedMetadata: hex(encryptedMetadata),
    encryptedChunk: hex(encryptedChunk),
    resumeMac: hex(resumeMac),
    decryptedMetadata,
    decryptedChunk: new TextDecoder().decode(decryptedChunk),
    tamperedChunk: await codec.decryptChunk(tampered, keys.contentKey, manifest, 0),
    base64url: codec.encodeBase64Url(Uint8Array.from([0xfb, 0xff, 0x00])),
  }));
})().catch(error => {
  process.stderr.write(String(error.stack || error));
  process.exitCode = 1;
});
"""

    completed = _run_node(script, UI_ROOT / "encrypted-transfer-crypto.js")

    assert completed.returncode == 0, completed.stderr
    assert json.loads(completed.stdout) == {
        "contentKey": "705dbd0114261bde4c7c288d8d03c4ccc02fcc345393fd1540d74312728272a7",
        "resumeKey": "b59df99ac6b971eba4cb05fa3bc444152a30ca025a3abaa6c131aa16e8348e73",
        "metadataAad": (
            "5846455252592d455546312d4d45544100"
            "00112233445566778899aabbccddeeff"
            "00000000000000140080000000000001"
        ),
        "chunkAad": (
            "5846455252592d455546312d4348554e4b00"
            "00112233445566778899aabbccddeeff"
            "00000000000000140080000000000001"
            "0000000000000014"
        ),
        "encryptedMetadata": (
            "c9419088375171101e8744899f32bad858d280dad0b3a268f364d9df86d0bd36"
            "b65bc8ba828cdb4ca0a1cce53debe06cef4a82f3e089a6c42b2fb0babb6ea5e"
            "484713f9b3c165355385edc1ba52904f30840b85fab544fb4d1db8ef391c8c900d439"
        ),
        "encryptedChunk": (
            "6cdb3b6906e069eae77291067f066f9fdbb39f55d5e684ddb01ae8b19b43244d36eea649"
        ),
        "resumeMac": "12d418de7276b55498b8c45cae1f6e703a38d5411ce6577128e5102427d60da6",
        "decryptedMetadata": {
            "name": "report.txt",
            "content_type": "text/plain",
            "last_modified_ms": 1_720_000_000_123,
        },
        "decryptedChunk": "0123456789abcdefghij",
        "tamperedChunk": None,
        "base64url": "-_8A",
    }


def test_encrypted_transfer_ui_fails_closed_until_exact_ping_capability() -> None:
    """Malformed, disabled, or pending capability data must keep the workflow hidden."""
    script = r"""
const fs = require('node:fs');
const vm = require('node:vm');

const workflows = new Map();
const listeners = new Map();
let coreState = {
  serverDiscoveryStatus: 'pending',
  encryptedUploadCapabilities: null,
};
const panel = {
  hidden: false,
  attributes: new Map(),
  setAttribute(name, value) { this.attributes.set(name, String(value)); },
  removeAttribute(name) { this.attributes.delete(name); },
};
const core = {
  t: key => key,
  formatSize: value => `${value} B`,
  serverUrl: '',
  announceLiveRegion() {},
  getState: () => coreState,
};
const app = {
  events: {
    SERVER_METHODS_CHANGED: 'server.methods.changed',
    LOCALE_CHANGED: 'locale.changed',
  },
  service(name) {
    if (name === 'core') return core;
    if (name === 'encrypted-transfer-crypto') return { chunkSize: 8 * 1024 * 1024 };
    if (name === 'notifications') return { show() {}, update() {}, dismiss() {} };
    if (name === 'dialogs') return { confirm: async () => false, notice: async () => {} };
    throw new Error(`Unexpected service: ${name}`);
  },
  registerWorkflow(name, definition) { workflows.set(name, definition); },
  on(name, listener) {
    const group = listeners.get(name) || [];
    group.push(listener);
    listeners.set(name, group);
  },
  getState(name) { return workflows.get(name).getState(); },
};
globalThis.window = { XferryApp: app };
globalThis.document = {
  getElementById(id) { return id === 'encryptedTransferPanel' ? panel : null; },
  querySelectorAll() { return []; },
};
globalThis.indexedDB = undefined;
globalThis.fetch = async () => { throw new Error('fetch must not run during capability sync'); };
vm.runInThisContext(fs.readFileSync(process.argv[1], 'utf8'), { filename: process.argv[1] });

function refresh(status, capabilities) {
  coreState = {
    serverDiscoveryStatus: status,
    encryptedUploadCapabilities: capabilities,
  };
  for (const listener of listeners.get(app.events.SERVER_METHODS_CHANGED) || []) {
    listener({});
  }
  return {
    state: app.getState('encrypted-transfer'),
    hidden: panel.hidden,
    ariaHidden: panel.attributes.get('aria-hidden') || null,
  };
}

const valid = {
  enabled: true,
  version: 1,
  max_plaintext_size: 2147483648,
  chunk_size: 8388608,
  parallel_chunks: 2,
  browser_decryption: true,
  server_decryption: true,
};
const wrongParallelism = { ...valid, parallel_chunks: 3 };
const extraField = { ...valid, future_flag: true };

process.stdout.write(JSON.stringify({
  initial: { state: app.getState('encrypted-transfer'), hidden: panel.hidden },
  valid: refresh('ready', valid),
  disabled: refresh('ready', { enabled: false }),
  wrongParallelism: refresh('ready', wrongParallelism),
  extraField: refresh('ready', extraField),
  unavailable: refresh('unavailable', null),
}));
"""

    completed = _run_node(script, UI_ROOT / "encrypted-transfer.js")

    assert completed.returncode == 0, completed.stderr
    observed = json.loads(completed.stdout)
    assert {
        key: observed["initial"]["state"][key] for key in ("enabled", "capabilityStatus", "phase")
    } == {
        "enabled": False,
        "capabilityStatus": "pending",
        "phase": "idle",
    }
    assert observed["initial"]["hidden"] is True
    assert {
        key: observed["valid"]["state"][key] for key in ("enabled", "capabilityStatus", "phase")
    } == {
        "enabled": True,
        "capabilityStatus": "valid",
        "phase": "idle",
    }
    assert observed["valid"]["hidden"] is False
    assert observed["valid"]["ariaHidden"] == "false"
    for key, status in (
        ("disabled", "disabled"),
        ("wrongParallelism", "invalid"),
        ("extraField", "invalid"),
        ("unavailable", "unavailable"),
    ):
        assert {
            state_key: observed[key]["state"][state_key]
            for state_key in ("enabled", "capabilityStatus", "phase")
        } == {
            "enabled": False,
            "capabilityStatus": status,
            "phase": "idle",
        }
        assert observed[key]["hidden"] is True
        assert observed[key]["ariaHidden"] == "true"


def test_encrypted_transfer_ui_loads_remote_lists_when_it_first_becomes_available() -> None:
    """A fresh page must not claim that the encrypted store is empty before refreshing it."""
    script = r"""
const fs = require('node:fs');
const vm = require('node:vm');

const CHUNK_SIZE = 8 * 1024 * 1024;
const FILE_ID = '00112233445566778899aabbccddeeff';
const workflows = new Map();
const fetchCalls = [];
const capability = {
  enabled: true,
  version: 1,
  max_plaintext_size: 2147483648,
  chunk_size: CHUNK_SIZE,
  parallel_chunks: 2,
  browser_decryption: true,
  server_decryption: true,
};
const record = {
  id: FILE_ID,
  version: 1,
  plaintext_size: 5,
  ciphertext_size: 21,
  chunk_size: CHUNK_SIZE,
  chunk_count: 1,
  salt: Buffer.alloc(16, 1).toString('base64url'),
  nonce_prefix: Buffer.alloc(8, 2).toString('base64url'),
  encrypted_metadata: Buffer.alloc(32, 3).toString('base64url'),
  status: 'complete',
  received_chunks: [{
    index: 0,
    resume_mac: Buffer.alloc(32, 4).toString('base64url'),
  }],
  created_at: 1,
  updated_at: 2,
};
const panel = {
  hidden: true,
  setAttribute() {},
};
const refreshButton = {
  disabled: true,
  addEventListener() {},
};
const core = {
  t: key => key,
  formatSize: String,
  serverUrl: '',
  announceLiveRegion() {},
  getState: () => ({
    serverDiscoveryStatus: 'ready',
    encryptedUploadCapabilities: capability,
  }),
};
const app = {
  events: {
    SERVER_METHODS_CHANGED: 'server.methods.changed',
    LOCALE_CHANGED: 'locale.changed',
  },
  service(name) {
    if (name === 'core') return core;
    if (name === 'encrypted-transfer-crypto') {
      return {
        chunkSize: CHUNK_SIZE,
        decodeBase64Url: value => new Uint8Array(Buffer.from(value, 'base64url')),
      };
    }
    if (name === 'notifications') return { show() {}, update() {}, dismiss() {} };
    if (name === 'dialogs') return { confirm: async () => false, notice: async () => {} };
    throw new Error(`Unexpected service: ${name}`);
  },
  registerWorkflow(name, definition) { workflows.set(name, definition); },
  on() {},
  getState(name) { return workflows.get(name).getState(); },
};
globalThis.window = { XferryApp: app };
globalThis.document = {
  getElementById(id) {
    if (id === 'encryptedTransferPanel') return panel;
    if (id === 'encryptedRefreshBtn') return refreshButton;
    return null;
  },
  querySelectorAll: () => [],
};
globalThis.indexedDB = undefined;
globalThis.fetch = async url => {
  fetchCalls.push(url);
  if (url.endsWith('/encrypted-uploads')) {
    return { ok: true, status: 200, json: async () => ({ encrypted_uploads: [] }) };
  }
  if (url.endsWith('/encrypted-files')) {
    return { ok: true, status: 200, json: async () => ({ encrypted_files: [record] }) };
  }
  throw new Error(`Unexpected URL: ${url}`);
};

vm.runInThisContext(fs.readFileSync(process.argv[1], 'utf8'), { filename: process.argv[1] });

(async () => {
  for (let attempt = 0; attempt < 10; attempt += 1) {
    if (app.getState('encrypted-transfer').encryptedFiles.length === 1) break;
    await new Promise(resolve => setImmediate(resolve));
  }
  process.stdout.write(JSON.stringify({
    fetchCalls,
    state: app.getState('encrypted-transfer'),
  }));
})().catch(error => {
  process.stderr.write(String(error.stack || error));
  process.exitCode = 1;
});
"""

    completed = _run_node(script, UI_ROOT / "encrypted-transfer.js")

    assert completed.returncode == 0, completed.stderr
    observed = json.loads(completed.stdout)
    assert observed["fetchCalls"] == [
        "/_xferry/encrypted-uploads",
        "/_xferry/encrypted-files",
    ]
    assert observed["state"]["partialUploads"] == []
    assert observed["state"]["encryptedFiles"] == [
        {
            "id": "00112233445566778899aabbccddeeff",
            "plaintextSize": 5,
            "chunkCount": 1,
            "unlocked": False,
            "name": "",
            "contentType": "",
            "lastModifiedMs": None,
        }
    ]


def test_core_retains_encrypted_upload_capability_from_ping() -> None:
    """Dropping the PING field in core would keep the encrypted UI permanently hidden."""
    script = r"""
const fs = require('node:fs');
const vm = require('node:vm');

const services = new Map();
const emitted = [];
const capability = {
  enabled: true,
  version: 1,
  max_plaintext_size: 2147483648,
  chunk_size: 8388608,
  parallel_chunks: 2,
  browser_decryption: true,
  server_decryption: true,
};
const app = {
  events: {
    LOCALE_CHANGED: 'locale.changed',
    SERVER_METHODS_CHANGED: 'server.methods.changed',
    WORKSPACE_CHANGED: 'workspace.changed',
  },
  service(name) {
    if (name === 'http') {
      return {
        request: async () => ({
          ok: true,
          status: 200,
          text: async () => JSON.stringify({
            supported_methods: ['GET', 'PING'],
            method_groups: { request: ['GET', 'PING'] },
            encrypted_uploads: capability,
          }),
        }),
      };
    }
    return services.get(name);
  },
  registerService(name, api) { services.set(name, api); },
  emit(name, detail) { emitted.push([name, detail]); },
};
const nullElement = null;
globalThis.localStorage = { getItem: () => null, setItem() {} };
globalThis.location = { hash: '' };
globalThis.navigator = {};
globalThis.document = {
  documentElement: {
    lang: '',
    getAttribute: () => null,
    setAttribute() {},
    removeAttribute() {},
  },
  body: { appendChild() {} },
  activeElement: null,
  getElementById: () => nullElement,
  querySelector: () => nullElement,
  querySelectorAll: () => [],
  addEventListener() {},
  createElement: () => ({
    textContent: '',
    innerHTML: '',
    style: {},
    setAttribute() {},
    appendChild() {},
    remove() {},
  }),
};
globalThis.window = {
  XferryApp: app,
  addEventListener() {},
};
vm.runInThisContext(fs.readFileSync(process.argv[1], 'utf8'), { filename: process.argv[1] });

(async () => {
  const core = services.get('core');
  await core.checkServer();
  process.stdout.write(JSON.stringify({
    capability: core.getState().encryptedUploadCapabilities,
    eventCapability: emitted
      .filter(([name]) => name === app.events.SERVER_METHODS_CHANGED)
      .at(-1)?.[1]?.encryptedUploadCapabilities,
  }));
})().catch(error => {
  process.stderr.write(String(error.stack || error));
  process.exitCode = 1;
});
"""

    completed = _run_node(script, UI_ROOT / "core.js")

    assert completed.returncode == 0, completed.stderr
    assert json.loads(completed.stdout) == {
        "capability": {
            "enabled": True,
            "version": 1,
            "max_plaintext_size": 2_147_483_648,
            "chunk_size": 8_388_608,
            "parallel_chunks": 2,
            "browser_decryption": True,
            "server_decryption": True,
        },
        "eventCapability": {
            "enabled": True,
            "version": 1,
            "max_plaintext_size": 2_147_483_648,
            "chunk_size": 8_388_608,
            "parallel_chunks": 2,
            "browser_decryption": True,
            "server_decryption": True,
        },
    }


def test_large_upload_slices_file_limits_parallelism_and_persists_no_secrets() -> None:
    """Whole-file reads, unbounded PUTs, or secret persistence would break the 2 GiB design."""
    script = r"""
const fs = require('node:fs');
const vm = require('node:vm');

const CHUNK_SIZE = 8 * 1024 * 1024;
const workflows = new Map();
const listeners = new Map();
const persisted = [];
const deletedProgress = [];
const transferFixtureOptions = {
  onWrite: record => persisted.push(record),
  onDelete: id => deletedProgress.push(id),
};
const fetchCalls = [];
const pendingChunks = [];
const sliceCalls = [];
let activeChunks = 0;
let maxActiveChunks = 0;
let randomCall = 0;

globalThis.indexedDB = undefined;

const capability = {
  enabled: true,
  version: 1,
  max_plaintext_size: 2147483648,
  chunk_size: CHUNK_SIZE,
  parallel_chunks: 2,
  browser_decryption: true,
  server_decryption: true,
};
const core = {
  t: key => key,
  formatSize: value => `${value} B`,
  serverUrl: '',
  announceLiveRegion() {},
  getState: () => ({
    serverDiscoveryStatus: 'ready',
    encryptedUploadCapabilities: capability,
  }),
};
const codec = {
  chunkSize: CHUNK_SIZE,
  randomBytes(length) {
    randomCall += 1;
    return Uint8Array.from({ length }, (_value, index) => (randomCall * 16 + index) & 0xff);
  },
  encodeBase64Url(value) {
    return Buffer.from(value).toString('base64url');
  },
  async deriveKeys() {
    return { contentKey: new Uint8Array(32).fill(0x41), resumeKey: new Uint8Array(32).fill(0x52) };
  },
  async encryptMetadata() { return new Uint8Array(16).fill(0x6d); },
  async encryptChunk(_plaintext, _key, _manifest, index) {
    return Uint8Array.from([index, 0xc0]);
  },
  async computeResumeMac(_plaintext, _key, _manifest, index) {
    return new Uint8Array(32).fill(index + 1);
  },
};
const app = {
  events: {
    SERVER_METHODS_CHANGED: 'server.methods.changed',
    LOCALE_CHANGED: 'locale.changed',
  },
  service(name) {
    if (name === 'core') return core;
    if (name === 'encrypted-transfer-crypto') return codec;
    if (name === 'notifications') return { show() {}, update() {}, dismiss() {} };
    if (name === 'dialogs') return { confirm: async () => false, notice: async () => {} };
    throw new Error(`Unexpected service: ${name}`);
  },
  registerWorkflow(name, definition) { workflows.set(name, definition); },
  on(name, listener) {
    const group = listeners.get(name) || [];
    group.push(listener);
    listeners.set(name, group);
  },
  invoke(name, command, ...args) { return workflows.get(name).commands[command](...args); },
  getState(name) { return workflows.get(name).getState(); },
};
const panel = { hidden: true, setAttribute() {} };
globalThis.document = {
  getElementById(id) { return id === 'encryptedTransferPanel' ? panel : null; },
  querySelectorAll() { return []; },
};
globalThis.window = { XferryApp: app };

function response(payload, status = 200) {
  return {
    ok: status >= 200 && status < 300,
    status,
    statusText: status === 201 ? 'Created' : 'OK',
    headers: new Headers({ 'Content-Type': 'application/json' }),
    json: async () => payload,
    text: async () => JSON.stringify(payload),
  };
}

globalThis.fetch = async (url, options = {}) => {
  fetchCalls.push({ url, options });
  if (/\/chunks\/\d+$/.test(url)) {
    activeChunks += 1;
    maxActiveChunks = Math.max(maxActiveChunks, activeChunks);
    return new Promise((resolve, reject) => {
      const index = Number(url.split('/').pop());
      const entry = {
        index,
        resolve() {
          activeChunks -= 1;
          resolve(response({ encrypted_chunk: { index, stored: true } }, 201));
        },
        reject,
      };
      pendingChunks.push(entry);
    });
  }
  if (url.endsWith('/complete')) {
    return response({ encrypted_file: { status: 'complete', completed: true } });
  }
  if (options.method === 'PUT') {
    const body = JSON.parse(options.body);
    const id = url.split('/').pop();
    return response({
      encrypted_upload: {
        id,
        ...body,
        ciphertext_size: body.plaintext_size + body.chunk_count * 16,
        status: 'partial',
        received_chunks: [],
        created_at: 1,
        updated_at: 1,
      },
    }, 201);
  }
  throw new Error(`Unexpected fetch: ${options.method || 'GET'} ${url}`);
};

const file = {
  name: 'two-gig-ready.bin',
  type: 'application/octet-stream',
  size: CHUNK_SIZE * 3 - 7,
  lastModified: 1720000000123,
  arrayBuffer() { throw new Error('whole-file arrayBuffer() must never be called'); },
  slice(start, end) {
    sliceCalls.push([start, end]);
    return { arrayBuffer: async () => new Uint8Array(end - start).fill(sliceCalls.length).buffer };
  },
};

vm.runInThisContext(fs.readFileSync(process.argv[1], 'utf8'), { filename: process.argv[1] });

async function waitFor(predicate) {
  for (let attempt = 0; attempt < 100; attempt += 1) {
    if (predicate()) return;
    await new Promise(resolve => setImmediate(resolve));
  }
  throw new Error('Timed out waiting for upload state');
}

(async () => {
  const upload = app.invoke('encrypted-transfer', 'start', {
    file,
    password: 'correct horse battery staple',
  });
  await waitFor(() => pendingChunks.length === 2);
  pendingChunks[0].resolve();
  await waitFor(() => pendingChunks.length === 3);
  pendingChunks[1].resolve();
  pendingChunks[2].resolve();
  await upload;

  const createCall = fetchCalls.find(call => (
    call.options.method === 'PUT' && !call.url.includes('/chunks/')
  ));
  const chunkCalls = fetchCalls.filter(call => call.url.includes('/chunks/'));
  const createBody = JSON.parse(createCall.options.body);
  process.stdout.write(JSON.stringify({
    maxActiveChunks,
    sliceCalls,
    chunkIndexes: chunkCalls.map(call => Number(call.url.split('/').pop())),
    chunkHeaders: chunkCalls.map(call => ({ ...call.options.headers })),
    createBody,
    persisted,
    deletedProgress,
    state: app.getState('encrypted-transfer'),
  }));
})().catch(error => {
  process.stderr.write(String(error.stack || error));
  process.exitCode = 1;
});
"""

    completed = _run_node(script, UI_ROOT / "encrypted-transfer.js")

    assert completed.returncode == 0, completed.stderr
    observed = json.loads(completed.stdout)
    assert observed["maxActiveChunks"] == 2
    assert observed["sliceCalls"] == [
        [0, 8_388_608],
        [8_388_608, 16_777_216],
        [16_777_216, 25_165_817],
    ]
    assert observed["chunkIndexes"] == [0, 1, 2]
    assert all(
        headers
        == {
            "Content-Type": "application/octet-stream",
            "X-XFerry-Chunk-MAC": expected_mac,
        }
        for headers, expected_mac in zip(
            observed["chunkHeaders"],
            (
                "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE",
                "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI",
                "AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM",
            ),
            strict=True,
        )
    )
    assert observed["createBody"] == {
        "version": 1,
        "plaintext_size": 25_165_817,
        "chunk_size": 8_388_608,
        "chunk_count": 3,
        "salt": "ICEiIyQlJicoKSorLC0uLw",
        "nonce_prefix": "MDEyMzQ1Njc",
        "encrypted_metadata": "bW1tbW1tbW1tbW1tbW1tbQ",
    }
    assert observed["persisted"]
    assert all(
        set(record)
        <= {
            "id",
            "schemaVersion",
            "manifest",
            "attemptedMacs",
            "receivedIndexes",
            "status",
            "updatedAt",
        }
        for record in observed["persisted"]
    )
    assert all(
        not ({"password", "contentKey", "resumeKey", "name", "encryptedMetadata"} & set(record))
        for record in observed["persisted"]
    )
    assert all(record["schemaVersion"] == 2 for record in observed["persisted"])
    assert any(len(record["attemptedMacs"]) == 3 for record in observed["persisted"])
    assert observed["deletedProgress"] == ["101112131415161718191a1b1c1d1e1f"]
    assert observed["state"]["phase"] == "complete"


def test_upload_pause_resume_and_cancel_preserve_or_delete_remote_state() -> None:
    """Pause must retain resumable chunks, while cancel aborts work and deletes the partial."""
    script = r"""
const fs = require('node:fs');
const vm = require('node:vm');

const CHUNK_SIZE = 8 * 1024 * 1024;
const workflows = new Map();
const pending = [];
const calls = [];
const remoteRecords = new Map();
let immediateChunks = false;
let randomSeed = 0;
const capability = {
  enabled: true, version: 1, max_plaintext_size: 2147483648,
  chunk_size: CHUNK_SIZE, parallel_chunks: 2,
  browser_decryption: true, server_decryption: true,
};
const codec = {
  chunkSize: CHUNK_SIZE,
  randomBytes(length) {
    randomSeed += 1;
    return new Uint8Array(length).fill(randomSeed);
  },
  encodeBase64Url: value => Buffer.from(value).toString('base64url'),
  decodeBase64Url: value => new Uint8Array(Buffer.from(value, 'base64url')),
  deriveKeys: async () => ({
    contentKey: new Uint8Array(32).fill(1),
    resumeKey: new Uint8Array(32).fill(2),
  }),
  encryptMetadata: async () => new Uint8Array(16).fill(3),
  encryptChunk: async (_bytes, _key, _manifest, index) => Uint8Array.from([index]),
  computeResumeMac: async (_bytes, _key, _manifest, index) => new Uint8Array(32).fill(index),
};
const app = {
  events: { SERVER_METHODS_CHANGED: 'server.methods.changed', LOCALE_CHANGED: 'locale.changed' },
  service(name) {
    if (name === 'core') return {
      t: key => key,
      formatSize: String,
      serverUrl: '',
      announceLiveRegion() {},
      getState: () => ({
        serverDiscoveryStatus: 'ready', encryptedUploadCapabilities: capability,
      }),
    };
    if (name === 'encrypted-transfer-crypto') return codec;
    if (name === 'notifications') return { show() {}, update() {}, dismiss() {} };
    if (name === 'dialogs') return { confirm: async () => true, notice: async () => {} };
    throw new Error(`Unexpected service: ${name}`);
  },
  registerWorkflow(name, definition) { workflows.set(name, definition); },
  on() {},
  invoke(name, command, ...args) { return workflows.get(name).commands[command](...args); },
  getState(name) { return workflows.get(name).getState(); },
};
const startButton = { disabled: false };
globalThis.window = { XferryApp: app };
globalThis.document = {
  getElementById: id => id === 'encryptedUploadStartBtn' ? startButton : null,
  querySelectorAll: () => [],
};
globalThis.indexedDB = undefined;

function response(payload, status = 200) {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: async () => payload,
  };
}
function createRecord(url, body) {
  const id = url.split('/').pop();
  return {
    encrypted_upload: {
      id, ...body, ciphertext_size: body.plaintext_size + body.chunk_count * 16,
      status: 'partial', received_chunks: [], created_at: 1, updated_at: 1,
    },
  };
}
globalThis.fetch = async (url, options = {}) => {
  calls.push([options.method || 'GET', url]);
  if (url.includes('/chunks/')) {
    const index = Number(url.split('/').pop());
    if (immediateChunks) {
      const id = url.split('/').at(-3);
      const record = remoteRecords.get(id);
      record.received_chunks = record.received_chunks.filter(chunk => chunk.index !== index);
      record.received_chunks.push({ index, resume_mac: options.headers['X-XFerry-Chunk-MAC'] });
      return response({ encrypted_chunk: { index, stored: true } }, 201);
    }
    return new Promise((resolve, reject) => {
      const abort = () => reject(new DOMException('paused', 'AbortError'));
      if (options.signal?.aborted) return abort();
      options.signal?.addEventListener('abort', abort, { once: true });
      pending.push({ index, resolve, reject });
    });
  }
  if (url.endsWith('/complete')) {
    return response({ encrypted_file: { status: 'complete', completed: true } });
  }
  if (options.method === 'DELETE') {
    remoteRecords.delete(url.split('/').pop());
    return response({ deleted_encrypted_upload: { id: url.split('/').pop() } });
  }
  if (options.method === 'PUT') {
    const created = createRecord(url, JSON.parse(options.body));
    remoteRecords.set(created.encrypted_upload.id, created.encrypted_upload);
    return response(created, 201);
  }
  if ((options.method || 'GET') === 'GET' && remoteRecords.has(url.split('/').pop())) {
    return response({ encrypted_upload: structuredClone(remoteRecords.get(url.split('/').pop())) });
  }
  throw new Error(`Unexpected request: ${options.method || 'GET'} ${url}`);
};

function file(name, chunks) {
  return {
    name,
    type: 'application/octet-stream',
    size: CHUNK_SIZE * chunks,
    lastModified: 1,
    slice: (start, end) => ({
      arrayBuffer: async () => new Uint8Array(end - start).fill(1).buffer,
    }),
  };
}
const overlappingRecord = {
  id: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
  version: 1,
  plaintext_size: 0,
  ciphertext_size: 0,
  chunk_size: CHUNK_SIZE,
  chunk_count: 0,
  salt: Buffer.alloc(16, 4).toString('base64url'),
  nonce_prefix: Buffer.alloc(8, 5).toString('base64url'),
  encrypted_metadata: Buffer.alloc(16, 3).toString('base64url'),
  status: 'partial',
  received_chunks: [],
  created_at: 1,
  updated_at: 1,
};
async function waitFor(predicate) {
  for (let attempt = 0; attempt < 100; attempt += 1) {
    if (predicate()) return;
    await new Promise(resolve => setImmediate(resolve));
  }
  throw new Error('wait timed out');
}

vm.runInThisContext(fs.readFileSync(process.argv[1], 'utf8'), { filename: process.argv[1] });

(async () => {
  const firstRun = app.invoke('encrypted-transfer', 'start', {
    file: file('pause.bin', 3), password: 'correct horse battery staple',
  });
  await waitFor(() => pending.length === 2);
  await app.invoke('encrypted-transfer', 'pause');
  const pausedResult = await firstRun;
  const pausedState = app.getState('encrypted-transfer');
  const startDisabledWhilePaused = startButton.disabled;

  immediateChunks = true;
  let overlappingResumeError = '';
  try {
    await app.invoke('encrypted-transfer', 'resume', {
      record: overlappingRecord,
      file: file('remote-overlap.bin', 0),
      password: 'correct horse battery staple',
    });
  } catch (error) {
    overlappingResumeError = String(error?.message || error || '');
  }
  const stateAfterOverlappingResume = app.getState('encrypted-transfer');
  let overlappingStartError = '';
  try {
    await app.invoke('encrypted-transfer', 'start', {
      file: file('overlap.bin', 1), password: 'correct horse battery staple',
    });
  } catch (error) {
    overlappingStartError = String(error?.message || error || '');
  }
  const stateAfterOverlappingStart = app.getState('encrypted-transfer');
  const resumedResult = await app.invoke('encrypted-transfer', 'resume');
  const resumedState = app.getState('encrypted-transfer');

  immediateChunks = false;
  const secondRun = app.invoke('encrypted-transfer', 'start', {
    file: file('cancel.bin', 1), password: 'correct horse battery staple',
  });
  await waitFor(() => pending.length === 3);
  const activeId = app.getState('encrypted-transfer').activeId;
  const cancelResult = await app.invoke('encrypted-transfer', 'cancel');
  const canceledRunResult = await secondRun;
  const canceledState = app.getState('encrypted-transfer');

  process.stdout.write(JSON.stringify({
    pausedResult,
    pausedState,
    startDisabledWhilePaused,
    overlappingResumeError,
    stateAfterOverlappingResume,
    overlappingStartError,
    stateAfterOverlappingStart,
    resumedResult,
    resumedState,
    activeId,
    cancelResult,
    canceledRunResult,
    canceledState,
    deleteCalls: calls.filter(([method]) => method === 'DELETE'),
  }));
})().catch(error => {
  process.stderr.write(String(error.stack || error));
  process.exitCode = 1;
});
"""

    completed = _run_node(script, UI_ROOT / "encrypted-transfer.js")

    assert completed.returncode == 0, completed.stderr
    observed = json.loads(completed.stdout)
    assert observed["pausedResult"]["status"] == "paused"
    assert observed["pausedState"]["phase"] == "paused"
    assert observed["pausedState"]["activeId"]
    assert observed["startDisabledWhilePaused"] is True
    assert "already active" in observed["overlappingResumeError"]
    assert observed["stateAfterOverlappingResume"]["phase"] == "paused"
    assert (
        observed["stateAfterOverlappingResume"]["activeId"] == observed["pausedState"]["activeId"]
    )
    assert "already active" in observed["overlappingStartError"]
    assert observed["stateAfterOverlappingStart"]["phase"] == "paused"
    assert observed["stateAfterOverlappingStart"]["activeId"] == observed["pausedState"]["activeId"]
    assert observed["resumedResult"]["status"] == "complete"
    assert observed["resumedState"]["phase"] == "complete"
    assert observed["cancelResult"] == {"id": observed["activeId"], "status": "canceled"}
    assert observed["canceledRunResult"] == {
        "id": observed["activeId"],
        "status": "canceled",
    }
    assert observed["canceledState"]["phase"] == "canceled"
    assert observed["canceledState"]["activeId"] is None
    assert observed["deleteCalls"] == [
        ["DELETE", f"/_xferry/encrypted-uploads/{observed['activeId']}"]
    ]


def test_remote_resume_reselects_file_and_recomputes_acknowledged_macs() -> None:
    """A same-sized different file must be rejected before missing chunks are uploaded."""
    script = r"""
const fs = require('node:fs');
const vm = require('node:vm');

const CHUNK_SIZE = 8 * 1024 * 1024;
const FILE_ID = '00112233445566778899aabbccddeeff';
const workflows = new Map();
const calls = [];
const sliceCalls = [];
const capability = {
  enabled: true, version: 1, max_plaintext_size: 2147483648,
  chunk_size: CHUNK_SIZE, parallel_chunks: 2,
  browser_decryption: true, server_decryption: true,
};
const encryptedMetadata = new Uint8Array(16).fill(0x44);
const codec = {
  chunkSize: CHUNK_SIZE,
  randomBytes: () => { throw new Error('resume must reuse manifest randomness'); },
  encodeBase64Url: value => Buffer.from(value).toString('base64url'),
  decodeBase64Url: value => new Uint8Array(Buffer.from(value, 'base64url')),
  deriveKeys: async () => ({
    contentKey: new Uint8Array(32).fill(1), resumeKey: new Uint8Array(32).fill(2),
  }),
  encryptMetadata: async () => { throw new Error('resuming must never re-encrypt metadata'); },
  decryptMetadata: async () => ({
    name: 'resume.bin', content_type: 'application/octet-stream', last_modified_ms: 123,
  }),
  encryptChunk: async (_bytes, _key, _manifest, index) => Uint8Array.from([index]),
  computeResumeMac: async (bytes) => new Uint8Array(32).fill(bytes[0]),
};
const app = {
  events: { SERVER_METHODS_CHANGED: 'server.methods.changed', LOCALE_CHANGED: 'locale.changed' },
  service(name) {
    if (name === 'core') return {
      t: key => key, formatSize: String, serverUrl: '', announceLiveRegion() {},
      getState: () => ({
        serverDiscoveryStatus: 'ready', encryptedUploadCapabilities: capability,
      }),
    };
    if (name === 'encrypted-transfer-crypto') return codec;
    if (name === 'notifications') return { show() {}, update() {}, dismiss() {} };
    if (name === 'dialogs') return { confirm: async () => true, notice: async () => {} };
    throw new Error(`Unexpected service: ${name}`);
  },
  registerWorkflow(name, definition) { workflows.set(name, definition); },
  on() {},
  invoke(name, command, ...args) { return workflows.get(name).commands[command](...args); },
  getState(name) { return workflows.get(name).getState(); },
};
globalThis.window = { XferryApp: app };
globalThis.document = { getElementById: () => null, querySelectorAll: () => [] };
globalThis.indexedDB = undefined;

function response(payload, status = 200) {
  return { ok: status >= 200 && status < 300, status, json: async () => payload };
}
const record = {
  id: FILE_ID,
  version: 1,
  plaintext_size: CHUNK_SIZE * 2,
  ciphertext_size: CHUNK_SIZE * 2 + 32,
  chunk_size: CHUNK_SIZE,
  chunk_count: 2,
  salt: Buffer.alloc(16, 0x11).toString('base64url'),
  nonce_prefix: Buffer.alloc(8, 0x22).toString('base64url'),
  encrypted_metadata: Buffer.from(encryptedMetadata).toString('base64url'),
  status: 'partial',
  received_chunks: [{ index: 0, resume_mac: Buffer.alloc(32, 7).toString('base64url') }],
  created_at: 1,
  updated_at: 2,
};
const transferFixtureOptions = {
  uploads: new Map([[FILE_ID, {
    id: FILE_ID,
    schemaVersion: 2,
    manifest: {
      id: FILE_ID, version: record.version, plaintext_size: record.plaintext_size,
      chunk_size: record.chunk_size, chunk_count: record.chunk_count,
      salt: record.salt, nonce_prefix: record.nonce_prefix,
      encrypted_metadata: record.encrypted_metadata,
    },
    attemptedMacs: { 0: Buffer.alloc(32, 7).toString('base64url') },
    receivedIndexes: [0], status: 'partial', updatedAt: Date.now(),
  }]]),
};
globalThis.fetch = async (url, options = {}) => {
  calls.push([options.method || 'GET', url]);
  if (url.includes('/chunks/1')) {
    return response({ encrypted_chunk: { index: 1, stored: true } }, 201);
  }
  if (url.endsWith('/complete')) {
    return response({ encrypted_file: { status: 'complete', completed: true } });
  }
  if ((options.method || 'GET') === 'GET' && url.endsWith(FILE_ID)) {
    return response({ encrypted_upload: record });
  }
  throw new Error(`Unexpected request: ${options.method || 'GET'} ${url}`);
};

function selectedFile(marker) {
  return {
    name: 'resume.bin', type: 'application/octet-stream',
    size: CHUNK_SIZE * 2, lastModified: 123,
    arrayBuffer() { throw new Error('whole-file read'); },
    slice(start, end) {
      sliceCalls.push([marker, start, end]);
      return { arrayBuffer: async () => new Uint8Array(end - start).fill(marker).buffer };
    },
  };
}

vm.runInThisContext(fs.readFileSync(process.argv[1], 'utf8'), { filename: process.argv[1] });

(async () => {
  let mismatch = '';
  try {
    await app.invoke('encrypted-transfer', 'resume', {
      record, file: selectedFile(8), password: 'correct horse battery staple',
    });
  } catch (error) {
    mismatch = error.message;
  }
  const callsAfterMismatch = calls.length;
  const result = await app.invoke('encrypted-transfer', 'resume', {
    record, file: selectedFile(7), password: 'correct horse battery staple',
  });
  process.stdout.write(JSON.stringify({
    mismatch,
    callsAfterMismatch,
    result,
    calls,
    sliceCalls,
    state: app.getState('encrypted-transfer'),
  }));
})().catch(error => {
  process.stderr.write(String(error.stack || error));
  process.exitCode = 1;
});
"""

    completed = _run_node(script, UI_ROOT / "encrypted-transfer.js")

    assert completed.returncode == 0, completed.stderr
    observed = json.loads(completed.stdout)
    assert "does not match" in observed["mismatch"]
    assert observed["callsAfterMismatch"] == 1
    assert observed["result"] == {"id": "00112233445566778899aabbccddeeff", "status": "complete"}
    assert observed["calls"] == [
        ["GET", "/_xferry/encrypted-uploads/00112233445566778899aabbccddeeff"],
        ["GET", "/_xferry/encrypted-uploads/00112233445566778899aabbccddeeff"],
        ["PUT", "/_xferry/encrypted-uploads/00112233445566778899aabbccddeeff/chunks/1"],
        ["POST", "/_xferry/encrypted-uploads/00112233445566778899aabbccddeeff/complete"],
    ]
    assert observed["sliceCalls"] == [
        [8, 0, 8_388_608],
        [7, 0, 8_388_608],
        [7, 8_388_608, 16_777_216],
    ]
    assert observed["state"]["phase"] == "complete"


def test_encrypted_file_list_unlocks_metadata_without_exposing_keys_in_state() -> None:
    """Listing stays opaque until a password authenticates metadata; keys remain memory-private."""
    script = r"""
const fs = require('node:fs');
const vm = require('node:vm');

const CHUNK_SIZE = 8 * 1024 * 1024;
const FILE_ID = '00112233445566778899aabbccddeeff';
const workflows = new Map();
let idbOpened = false;
const capability = {
  enabled: true, version: 1, max_plaintext_size: 2147483648,
  chunk_size: CHUNK_SIZE, parallel_chunks: 2,
  browser_decryption: true, server_decryption: true,
};
const codec = {
  chunkSize: CHUNK_SIZE,
  decodeBase64Url: value => new Uint8Array(Buffer.from(value, 'base64url')),
  encodeBase64Url: value => Buffer.from(value).toString('base64url'),
  deriveKeys: async password => ({
    contentKey: new Uint8Array(32).fill(password === 'correct horse battery staple' ? 7 : 9),
    resumeKey: new Uint8Array(32).fill(2),
  }),
  decryptMetadata: async (_ciphertext, key) => key[0] === 7 ? {
    name: 'private report.pdf',
    content_type: 'application/pdf',
    last_modified_ms: 1720000000123,
  } : null,
};
const app = {
  events: { SERVER_METHODS_CHANGED: 'server.methods.changed', LOCALE_CHANGED: 'locale.changed' },
  service(name) {
    if (name === 'core') return {
      t: key => key, formatSize: String, serverUrl: '', announceLiveRegion() {},
      getState: () => ({
        serverDiscoveryStatus: 'ready', encryptedUploadCapabilities: capability,
      }),
    };
    if (name === 'encrypted-transfer-crypto') return codec;
    if (name === 'notifications') return { show() {}, update() {}, dismiss() {} };
    if (name === 'dialogs') return { confirm: async () => true, notice: async () => {} };
    throw new Error(`Unexpected service: ${name}`);
  },
  registerWorkflow(name, definition) { workflows.set(name, definition); },
  on() {},
  invoke(name, command, ...args) { return workflows.get(name).commands[command](...args); },
  getState(name) { return workflows.get(name).getState(); },
};
globalThis.window = { XferryApp: app };
globalThis.document = { getElementById: () => null, querySelectorAll: () => [] };
globalThis.indexedDB = {
  open() { idbOpened = true; throw new Error('unexpected IndexedDB open'); },
};

const record = {
  id: FILE_ID, version: 1, plaintext_size: 5, ciphertext_size: 21,
  chunk_size: CHUNK_SIZE, chunk_count: 1,
  salt: Buffer.alloc(16, 1).toString('base64url'),
  nonce_prefix: Buffer.alloc(8, 2).toString('base64url'),
  encrypted_metadata: Buffer.alloc(32, 3).toString('base64url'),
  status: 'complete', received_chunks: [{
    index: 0, resume_mac: Buffer.alloc(32, 4).toString('base64url'),
  }], created_at: 1, updated_at: 2,
};
globalThis.fetch = async (url, options = {}) => {
  if ((options.method || 'GET') !== 'GET') throw new Error('only list GET is expected');
  if (url.endsWith('/encrypted-uploads')) {
    return { ok: true, status: 200, json: async () => ({ encrypted_uploads: [] }) };
  }
  if (url.endsWith('/encrypted-files')) {
    return { ok: true, status: 200, json: async () => ({ encrypted_files: [record] }) };
  }
  throw new Error(`Unexpected URL: ${url}`);
};

vm.runInThisContext(fs.readFileSync(process.argv[1], 'utf8'), { filename: process.argv[1] });

(async () => {
  await app.invoke('encrypted-transfer', 'refresh');
  const lockedState = app.getState('encrypted-transfer');
  let wrongPassword = '';
  try {
    await app.invoke('encrypted-transfer', 'unlock', {
      id: FILE_ID, password: 'wrong password is long enough',
    });
  } catch (error) {
    wrongPassword = error.message;
  }
  const metadata = await app.invoke('encrypted-transfer', 'unlock', {
    id: FILE_ID, password: 'correct horse battery staple',
  });
  process.stdout.write(JSON.stringify({
    lockedState,
    wrongPassword,
    metadata,
    unlockedState: app.getState('encrypted-transfer'),
    idbOpened,
  }));
})().catch(error => {
  process.stderr.write(String(error.stack || error));
  process.exitCode = 1;
});
"""

    completed = _run_node(script, UI_ROOT / "encrypted-transfer.js")

    assert completed.returncode == 0, completed.stderr
    observed = json.loads(completed.stdout)
    assert observed["lockedState"]["partialUploads"] == []
    assert observed["lockedState"]["encryptedFiles"] == [
        {
            "id": "00112233445566778899aabbccddeeff",
            "plaintextSize": 5,
            "chunkCount": 1,
            "unlocked": False,
            "name": "",
            "contentType": "",
            "lastModifiedMs": None,
        }
    ]
    assert "password" in observed["wrongPassword"].lower()
    assert observed["metadata"] == {
        "name": "private report.pdf",
        "content_type": "application/pdf",
        "last_modified_ms": 1_720_000_000_123,
    }
    assert observed["unlockedState"]["encryptedFiles"] == [
        {
            "id": "00112233445566778899aabbccddeeff",
            "plaintextSize": 5,
            "chunkCount": 1,
            "unlocked": True,
            "name": "private report.pdf",
            "contentType": "application/pdf",
            "lastModifiedMs": 1_720_000_000_123,
        }
    ]
    assert observed["idbOpened"] is False
    serialized = json.dumps(observed["unlockedState"])
    for secret_name in ("contentKey", "resumeKey", "password", "encrypted_metadata", "salt"):
        assert secret_name not in serialized


def test_client_download_streams_decryption_and_aborts_partial_file_on_tamper() -> None:
    """Client download must authenticate each streamed chunk and abort, never close, on failure."""
    script = r"""
const fs = require('node:fs');
const vm = require('node:vm');

const CHUNK_SIZE = 8 * 1024 * 1024;
const FILE_ID = '00112233445566778899aabbccddeeff';
const workflows = new Map();
let tampered = false;
const writers = [];
const capability = {
  enabled: true, version: 1, max_plaintext_size: 2147483648,
  chunk_size: CHUNK_SIZE, parallel_chunks: 2,
  browser_decryption: true, server_decryption: true,
};
const codec = {
  chunkSize: CHUNK_SIZE,
  decodeBase64Url: value => new Uint8Array(Buffer.from(value, 'base64url')),
  encodeBase64Url: value => Buffer.from(value).toString('base64url'),
  deriveKeys: async () => ({
    contentKey: new Uint8Array(32).fill(7), resumeKey: new Uint8Array(32),
  }),
  decryptMetadata: async () => ({
    name: 'streamed.bin', content_type: 'application/octet-stream', last_modified_ms: 1,
  }),
  decryptChunk: async ciphertext => ciphertext[0] === 0xff
    ? null
    : Uint8Array.from([10, 20, 30, 40, 50]),
};
const app = {
  events: { SERVER_METHODS_CHANGED: 'server.methods.changed', LOCALE_CHANGED: 'locale.changed' },
  service(name) {
    if (name === 'core') return {
      t: key => key, formatSize: String, serverUrl: '', announceLiveRegion() {},
      getState: () => ({
        serverDiscoveryStatus: 'ready', encryptedUploadCapabilities: capability,
      }),
    };
    if (name === 'encrypted-transfer-crypto') return codec;
    if (name === 'notifications') return { show() {}, update() {}, dismiss() {} };
    if (name === 'dialogs') return { confirm: async () => true, notice: async () => {} };
    throw new Error(`Unexpected service: ${name}`);
  },
  registerWorkflow(name, definition) { workflows.set(name, definition); },
  on() {},
  invoke(name, command, ...args) { return workflows.get(name).commands[command](...args); },
};
globalThis.window = { XferryApp: app };
globalThis.document = { getElementById: () => null, querySelectorAll: () => [] };
globalThis.indexedDB = undefined;

const record = {
  id: FILE_ID, version: 1, plaintext_size: 5, ciphertext_size: 21,
  chunk_size: CHUNK_SIZE, chunk_count: 1,
  salt: Buffer.alloc(16, 1).toString('base64url'),
  nonce_prefix: Buffer.alloc(8, 2).toString('base64url'),
  encrypted_metadata: Buffer.alloc(32, 3).toString('base64url'),
  status: 'complete', received_chunks: [{
    index: 0, resume_mac: Buffer.alloc(32, 4).toString('base64url'),
  }], created_at: 1, updated_at: 2,
};
function jsonResponse(payload) {
  return { ok: true, status: 200, json: async () => payload };
}
function dataResponse() {
  const bytes = new Uint8Array(21).fill(0x42);
  if (tampered) bytes[0] = 0xff;
  return {
    ok: true,
    status: 200,
    body: new ReadableStream({
      start(controller) {
        controller.enqueue(bytes.slice(0, 3));
        controller.enqueue(bytes.slice(3, 17));
        controller.enqueue(bytes.slice(17));
        controller.close();
      },
    }),
    arrayBuffer() { throw new Error('whole response buffering is forbidden'); },
    blob() { throw new Error('blob buffering is forbidden'); },
  };
}
globalThis.fetch = async url => {
  if (url.endsWith('/encrypted-uploads')) return jsonResponse({ encrypted_uploads: [] });
  if (url.endsWith('/encrypted-files')) return jsonResponse({ encrypted_files: [record] });
  if (url.endsWith(`/${FILE_ID}/chunks/0`)) return dataResponse();
  throw new Error(`Unexpected URL: ${url}`);
};
function fileHandle() {
  const events = [];
  const writer = {
    events,
    async write(value) { events.push(['write', Array.from(value)]); },
    async close() { events.push(['close']); },
    async abort(error) { events.push(['abort', error?.message || String(error)]); },
  };
  writers.push(writer);
  return { createWritable: async () => writer };
}

vm.runInThisContext(fs.readFileSync(process.argv[1], 'utf8'), { filename: process.argv[1] });

(async () => {
  await app.invoke('encrypted-transfer', 'refresh');
  await app.invoke('encrypted-transfer', 'unlock', {
    id: FILE_ID, password: 'correct horse battery staple',
  });
  const success = await app.invoke('encrypted-transfer', 'download-client', {
    id: FILE_ID, fileHandle: fileHandle(),
  });
  tampered = true;
  await app.invoke('encrypted-transfer', 'unlock', {
    id: FILE_ID, password: 'correct horse battery staple',
  });
  let failure = '';
  try {
    await app.invoke('encrypted-transfer', 'download-client', {
      id: FILE_ID, fileHandle: fileHandle(),
    });
  } catch (error) {
    failure = error.message;
  }
  process.stdout.write(JSON.stringify({ success, failure, writers: writers.map(w => w.events) }));
})().catch(error => {
  process.stderr.write(String(error.stack || error));
  process.exitCode = 1;
});
"""

    completed = _run_node(script, UI_ROOT / "encrypted-transfer.js")

    assert completed.returncode == 0, completed.stderr
    observed = json.loads(completed.stdout)
    assert observed["success"] == {
        "id": "00112233445566778899aabbccddeeff",
        "status": "downloaded",
    }
    assert observed["writers"][0] == [["write", [10, 20, 30, 40, 50]], ["close"]]
    assert "integrity" in observed["failure"].lower()
    assert observed["writers"][1][0][0] == "abort"
    assert all(event[0] != "close" for event in observed["writers"][1])


def test_server_decrypt_requires_confirmation_sends_only_key_and_aborts_on_network_error() -> None:
    """Server decrypt is opt-in per action and a failed stream must not leave a partial file."""
    script = r"""
const fs = require('node:fs');
const vm = require('node:vm');

const CHUNK_SIZE = 8 * 1024 * 1024;
const FILE_ID = '00112233445566778899aabbccddeeff';
const workflows = new Map();
const confirmations = [];
const decryptRequests = [];
const writers = [];
const sequence = [];
let confirmNext = false;
let failNetwork = false;
const capability = {
  enabled: true, version: 1, max_plaintext_size: 2147483648,
  chunk_size: CHUNK_SIZE, parallel_chunks: 2,
  browser_decryption: true, server_decryption: true,
};
const codec = {
  chunkSize: CHUNK_SIZE,
  decodeBase64Url: value => new Uint8Array(Buffer.from(value, 'base64url')),
  encodeBase64Url: value => Buffer.from(value).toString('base64url'),
  deriveKeys: async () => ({
    contentKey: new Uint8Array(32).fill(7), resumeKey: new Uint8Array(32),
  }),
  decryptMetadata: async () => ({
    name: 'server-stream.bin', content_type: 'application/octet-stream', last_modified_ms: 1,
  }),
};
const dialogs = {
  async confirm(options) {
    confirmations.push({ title: options.title, message: options.message });
    return confirmNext;
  },
  async notice() {},
};
const app = {
  events: { SERVER_METHODS_CHANGED: 'server.methods.changed', LOCALE_CHANGED: 'locale.changed' },
  service(name) {
    if (name === 'core') return {
      t: key => key, formatSize: String, serverUrl: '', announceLiveRegion() {},
      getState: () => ({
        serverDiscoveryStatus: 'ready', encryptedUploadCapabilities: capability,
      }),
    };
    if (name === 'encrypted-transfer-crypto') return codec;
    if (name === 'notifications') return { show() {}, update() {}, dismiss() {} };
    if (name === 'dialogs') return dialogs;
    throw new Error(`Unexpected service: ${name}`);
  },
  registerWorkflow(name, definition) { workflows.set(name, definition); },
  on() {},
  invoke(name, command, ...args) { return workflows.get(name).commands[command](...args); },
};
globalThis.window = { XferryApp: app };
globalThis.document = { getElementById: () => null, querySelectorAll: () => [] };
globalThis.indexedDB = undefined;

const record = {
  id: FILE_ID, version: 1, plaintext_size: 4, ciphertext_size: 20,
  chunk_size: CHUNK_SIZE, chunk_count: 1,
  salt: Buffer.alloc(16, 1).toString('base64url'),
  nonce_prefix: Buffer.alloc(8, 2).toString('base64url'),
  encrypted_metadata: Buffer.alloc(32, 3).toString('base64url'),
  status: 'complete', received_chunks: [{
    index: 0, resume_mac: Buffer.alloc(32, 4).toString('base64url'),
  }], created_at: 1, updated_at: 2,
};
function jsonResponse(payload) {
  return { ok: true, status: 200, json: async () => payload };
}
globalThis.fetch = async (url, options = {}) => {
  if (url.endsWith('/encrypted-uploads')) return jsonResponse({ encrypted_uploads: [] });
  if (url.endsWith('/encrypted-files')) return jsonResponse({ encrypted_files: [record] });
  if (url.endsWith(`/${FILE_ID}/decrypt`)) {
    sequence.push('decrypt-request');
    decryptRequests.push({
      method: options.method,
      headers: { ...options.headers },
      body: JSON.parse(options.body),
    });
    return {
      ok: true,
      status: 200,
      body: new ReadableStream({
        start(controller) {
          controller.enqueue(Uint8Array.from([1, 2]));
          if (failNetwork) {
            controller.error(new Error('network broke'));
          } else {
            controller.enqueue(Uint8Array.from([3, 4]));
            controller.close();
          }
        },
      }),
    };
  }
  throw new Error(`Unexpected URL: ${url}`);
};
function fileHandle() {
  const events = [];
  const writer = {
    events,
    async write(value) { events.push(['write', Array.from(value)]); },
    async close() { events.push(['close']); },
    async abort(error) { events.push(['abort', error?.message || String(error)]); },
  };
  writers.push(writer);
  return { createWritable: async () => {
    sequence.push('writable-opened');
    return writer;
  } };
}

vm.runInThisContext(fs.readFileSync(process.argv[1], 'utf8'), { filename: process.argv[1] });

(async () => {
  await app.invoke('encrypted-transfer', 'refresh');
  await app.invoke('encrypted-transfer', 'unlock', {
    id: FILE_ID, password: 'correct horse battery staple',
  });
  const denied = await app.invoke('encrypted-transfer', 'download-server', {
    id: FILE_ID, fileHandle: fileHandle(),
  });
  confirmNext = true;
  const success = await app.invoke('encrypted-transfer', 'download-server', {
    id: FILE_ID, fileHandle: fileHandle(),
  });
  failNetwork = true;
  await app.invoke('encrypted-transfer', 'unlock', {
    id: FILE_ID, password: 'correct horse battery staple',
  });
  let failure = '';
  try {
    await app.invoke('encrypted-transfer', 'download-server', {
      id: FILE_ID, fileHandle: fileHandle(),
    });
  } catch (error) {
    failure = error.message;
  }
  process.stdout.write(JSON.stringify({
    denied, success, failure, confirmations, decryptRequests, sequence,
    writers: writers.map(writer => writer.events),
  }));
})().catch(error => {
  process.stderr.write(String(error.stack || error));
  process.exitCode = 1;
});
"""

    completed = _run_node(script, UI_ROOT / "encrypted-transfer.js")

    assert completed.returncode == 0, completed.stderr
    observed = json.loads(completed.stdout)
    assert observed["denied"] is False
    assert len(observed["confirmations"]) == 3
    assert len(observed["decryptRequests"]) == 2
    assert observed["sequence"] == [
        "writable-opened",
        "decrypt-request",
        "writable-opened",
        "decrypt-request",
    ]
    expected_key = "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc"
    assert all(
        request
        == {
            "method": "POST",
            "headers": {"Content-Type": "application/json"},
            "body": {"content_key": expected_key},
        }
        for request in observed["decryptRequests"]
    )
    assert observed["success"] == {
        "id": "00112233445566778899aabbccddeeff",
        "status": "downloaded",
    }
    assert observed["writers"][0] == []  # confirmation was declined before opening it
    assert observed["writers"][1] == [
        ["write", [1, 2]],
        ["write", [3, 4]],
        ["close"],
    ]
    assert "network broke" in observed["failure"]
    assert observed["writers"][2][-1][0] == "abort"
    assert all(event[0] != "close" for event in observed["writers"][2])


def test_encrypted_transfer_panel_is_accessible_capability_gated_and_loaded_in_order() -> None:
    """The browser workflow needs labelled controls while remaining hidden before PING."""
    html = (REPO_ROOT / "xferry" / "data" / "index.html").read_text(encoding="utf-8")
    core_js = (UI_ROOT / "core.js").read_text(encoding="utf-8")

    panel = html.split('id="encryptedTransferPanel"', 1)[1].split('<section id="opsec-tab"', 1)[0]
    panel_opening = panel.split(">", 1)[0]
    assert re.search(r"\bhidden\b", panel_opening)
    assert 'aria-hidden="true"' in panel_opening
    assert 'aria-labelledby="encryptedTransferTitle"' in panel
    assert 'id="encryptedTransferTitle"' in panel
    assert "<label" in panel and 'for="encryptedFileInput"' in panel
    assert 'id="encryptedFileInput"' in panel
    assert 'for="encryptedPasswordInput"' in panel
    assert 'id="encryptedPasswordInput"' in panel
    assert 'autocomplete="new-password"' in panel
    assert 'for="encryptedPasswordConfirmInput"' in panel
    assert 'id="encryptedPasswordConfirmInput"' in panel
    assert 'id="encryptedUploadStartBtn"' in panel
    assert 'id="encryptedUploadPauseBtn"' in panel
    assert 'id="encryptedUploadResumeBtn"' in panel
    assert 'id="encryptedUploadCancelBtn"' in panel
    assert 'id="encryptedUploadProgress"' in panel
    assert 'id="encryptedTransferStatus" role="status" aria-live="polite"' in panel
    assert 'id="encryptedPartialList" role="list"' in panel
    assert 'id="encryptedFileList" role="list"' in panel
    assert 'id="encryptedResumeForm"' in panel and "hidden" in panel
    assert 'id="encryptedUnlockForm"' in panel and "hidden" in panel

    scripts = re.findall(r'<script src="(/static/ui/[^"?]+\.js)"></script>', html)
    assert scripts.index("/static/ui/requests.js") < scripts.index(
        "/static/ui/encrypted-transfer-crypto.js"
    )
    assert scripts.index("/static/ui/encrypted-transfer-crypto.js") < scripts.index(
        "/static/ui/encrypted-transfer.js"
    )
    assert scripts.index("/static/ui/encrypted-transfer.js") < scripts.index("/static/ui/app.js")

    locale_keys = {
        "encryptedTransferTitle",
        "encryptedTransferDescription",
        "encryptedFileLabel",
        "encryptedPasswordLabel",
        "encryptedPasswordConfirmLabel",
        "encryptedUploadStart",
        "encryptedUploadPause",
        "encryptedUploadResume",
        "encryptedUploadCancel",
        "encryptedPartialTitle",
        "encryptedFilesTitle",
        "encryptedRefresh",
        "encryptedUnlock",
        "encryptedClientDownload",
        "encryptedServerDownload",
    }
    for locale in ("ru", "en"):
        locale_block = core_js.split(f"{locale}: {{", 1)[1]
        if locale == "ru":
            locale_block = locale_block.split("\n    },\n    en: {", 1)[0]
        else:
            locale_block = locale_block.split("\n    }\n};", 1)[0]
        keys = set(re.findall(r"^\s*([A-Za-z][A-Za-z0-9_]*):", locale_block, re.MULTILINE))
        assert keys >= locale_keys


def test_encrypted_transfer_layout_has_bounded_lists_and_mobile_actions() -> None:
    """Large transfer controls must remain usable without making the upload page unbounded."""
    css = (UI_ROOT / "features.css").read_text(encoding="utf-8")

    assert ".encrypted-transfer__fields" in css
    assert "grid-template-columns: repeat(3, minmax(0, 1fr));" in css
    assert ".encrypted-transfer__list" in css
    assert "max-block-size:" in css.split(".encrypted-transfer__list {", 1)[1].split("}", 1)[0]
    mobile = css.split("@media (max-width: 640px)", 1)[1]
    assert ".encrypted-transfer__fields" in mobile
    assert ".encrypted-transfer__actions" in mobile
    assert "grid-template-columns: minmax(0, 1fr);" in mobile
