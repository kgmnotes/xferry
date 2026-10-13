'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const http = require('node:http');
const { setTimeout: sleep } = require('node:timers/promises');
const services = new Map();
globalThis.window = { XferryApp: { registerService(name, service) { services.set(name, service); } } };

function load(name) {
    const filename = path.join(__dirname, '../xferry/data/static/ui', `${name}.js`);
    assert.ok(fs.existsSync(filename), `Missing required service: ${name}`);
    vm.runInThisContext(fs.readFileSync(filename, 'utf8'), { filename });
    return services.get(name);
}

async function withServer(handler, test) {
    const server = http.createServer(handler);
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    try { await test(`http://127.0.0.1:${server.address().port}`); }
    finally {
        server.closeAllConnections();
        await new Promise(resolve => server.close(resolve));
    }
}

const fast = { stallMs: 250, retryBaseMs: 1, maxDelayMs: 2, random: () => 0.5 };
const id = '0123456789abcdef0123456789abcdef';
const secondId = 'fedcba9876543210fedcba9876543210';
const manifest = {
    version: 1, plaintext_size: 20, chunk_size: 8388608, chunk_count: 1,
    salt: 'AAAAAAAAAAAAAAAAAAAAAA', nonce_prefix: 'AAAAAAAAAAA',
    encrypted_metadata: 'AAAAAAAAAAAAAAAAAAAAAA',
};
const upload = () => ({
    id, schemaVersion: 2, manifest, attemptedMacs: { 0: 'A'.repeat(43) },
    receivedIndexes: [], status: 'paused', updatedAt: Date.now(),
});
const download = (fileId = id) => ({
    id: fileId, schemaVersion: 2, manifest, cachedIndexes: [],
    status: 'paused', updatedAt: Date.now(), ciphertext_size: 36,
});

function installBrowserStorage() {
    const maps = new Map();
    const storage = { maps, abortNext: false, completed: 0, strict: [], files: new Map() };
    function transaction(name, mode, options) {
        const source = maps.get(name);
        const staged = new Map(source);
        const tx = { error: null, objectStore() { return {
            get(key) { return request(() => structuredClone(staged.get(key))); },
            getAll() { return request(() => [...staged.values()].map(value => structuredClone(value))); },
            put(record) { return request(() => { staged.set(record.id, structuredClone(record)); return record.id; }); },
            delete(key) { return request(() => staged.delete(key)); },
        }; } };
        if (mode === 'readwrite') storage.strict.push(options);
        let outstanding = 0;
        let completion;
        function request(operation) {
            outstanding += 1;
            clearTimeout(completion);
            const req = {};
            setTimeout(() => {
                try { req.result = operation(); req.onsuccess?.(); }
                catch (error) { req.error = error; req.onerror?.(); }
                outstanding -= 1;
                if (!outstanding) completion = setTimeout(() => {
                    if (storage.abortNext && mode === 'readwrite') {
                        storage.abortNext = false;
                        tx.error = new Error('simulated commit failure');
                        tx.onabort?.();
                    } else {
                        if (mode === 'readwrite') maps.set(name, staged);
                        storage.completed += 1;
                        tx.oncomplete?.();
                    }
                }, 12);
            }, 0);
            return req;
        }
        return tx;
    }
    const db = {
        objectStoreNames: { contains: name => maps.has(name) },
        createObjectStore(name) { maps.set(name, new Map()); }, transaction, close() {},
    };
    globalThis.indexedDB = { open() {
        const req = {};
        setTimeout(() => { req.result = db; req.onupgradeneeded?.(); req.onsuccess?.(); }, 0);
        return req;
    } };
    function directory(prefix = '') {
        return {
            async getDirectoryHandle(name, options = {}) {
                const next = `${prefix}${name}/`;
                if (!storage.files.has(next)) {
                    if (!options.create) throw new DOMException('Missing directory', 'NotFoundError');
                    storage.files.set(next, null);
                }
                return directory(next);
            },
            async getFileHandle(name, options = {}) {
                const key = `${prefix}${name}`;
                if (!storage.files.has(key)) {
                    if (!options.create) throw new DOMException('Missing file', 'NotFoundError');
                    storage.files.set(key, new Uint8Array());
                }
                return {
                    kind: 'file', name,
                    async getFile() {
                        if (storage.disappearNext) {
                            storage.disappearNext = false;
                            storage.files.delete(key);
                            throw new DOMException('File was removed in another tab', 'NotFoundError');
                        }
                        if (!storage.files.has(key)) throw new DOMException('Missing file', 'NotFoundError');
                        const bytes = storage.files.get(key).slice();
                        return { size: bytes.length, lastModified: storage.modified?.get(key) || Date.now(), async arrayBuffer() { return bytes.buffer; } };
                    },
                    async createWritable() {
                        let bytes;
                        return {
                            async write(value) { bytes = new Uint8Array(value).slice(); },
                            async close() { await sleep(12); storage.files.set(key, bytes); },
                            async abort() {},
                        };
                    },
                };
            },
            async removeEntry(name, options = {}) {
                const key = `${prefix}${name}`;
                const folder = `${key}/`;
                if (!storage.files.has(key) && !storage.files.has(folder)) {
                    throw new DOMException('Missing entry', 'NotFoundError');
                }
                storage.files.delete(key);
                if (options.recursive) {
                    for (const stored of storage.files.keys()) if (stored.startsWith(folder)) storage.files.delete(stored);
                }
            },
            async *entries() {
                const names = new Set();
                for (const key of storage.files.keys()) {
                    if (!key.startsWith(prefix)) continue;
                    const suffix = key.slice(prefix.length);
                    const name = suffix.split('/')[0];
                    if (!name || names.has(name)) continue;
                    names.add(name);
                    const kind = suffix.includes('/') ? 'directory' : 'file';
                    yield [name, { kind, ...(kind === 'directory' ? directory(`${prefix}${name}/`) : await this.getFileHandle(name)) }];
                }
            },
        };
    }
    const locks = new Set();
    Object.defineProperty(globalThis, 'navigator', { configurable: true, value: {
        onLine: true,
        storage: {
            async getDirectory() { return directory(); },
            async estimate() { return { quota: 1024 * 1024, usage: 0 }; },
            async persist() { return true; },
        },
        locks: { async request(name, options, callback) {
            if (locks.has(name)) return callback(null);
            locks.add(name);
            try { return await callback({ name }); } finally { locks.delete(name); }
        } },
    } });
    return storage;
}

const scenarios = {
    async network_retries() {
        const service = load('encrypted-transfer-network');
        let attempts = 0;
        const waits = [];
        await withServer((req, res) => {
            attempts += 1;
            if (attempts === 1) { res.writeHead(429, { 'Retry-After': '0.04' }); res.end('{"error":{"code":"busy"}}'); }
            else if (attempts === 2) { res.writeHead(503); res.end('{}'); }
            else { res.writeHead(200); res.end('{"ok":true}'); }
        }, async url => {
            // This scenario tests HTTP policy, not a 250 ms wall-clock deadline.
            // Starting Node's real HTTP client can exceed that under contention.
            assert.deepEqual(await service.requestJson(url, {}, { ...fast, stallMs: 5000, onWait: item => waits.push(item) }), { ok: true });
        });
        assert.equal(attempts, 3);
        assert.ok(waits[0].delayMs >= 40, 'Retry-After must override the short backoff');
        assert.equal(waits.length, 2);
    },
    async network_terminal() {
        const service = load('encrypted-transfer-network');
        for (const status of [401, 403, 404, 409, 413]) {
            let attempts = 0;
            await withServer((req, res) => {
                attempts += 1; res.writeHead(status); res.end('{"error":{"code":"quota","message":"cannot transfer"}}');
            }, async url => {
                await assert.rejects(service.requestJson(url, {}, { ...fast, stallMs: 5000 }),
                    error => error.status === status && error.code === 'quota');
            });
            assert.equal(attempts, 1);
        }
    },
    async network_stalls() {
        const service = load('encrypted-transfer-network');
        for (const bodyStall of [false, true]) {
            let attempts = 0;
            await withServer((req, res) => {
                attempts += 1;
                if (attempts === 1) {
                    if (bodyStall) { res.writeHead(200); res.write('{'); }
                    return;
                }
                res.end('{"ok":true}');
            }, async url => {
                assert.deepEqual(await service.requestJson(url, {}, fast), { ok: true });
            });
            assert.equal(attempts, 2, 'both header and JSON-body stalls must retry');
        }
    },
    async network_chunk_bounds() {
        const service = load('encrypted-transfer-network');
        let attempts = 0;
        const progress = [];
        await withServer((req, res) => {
            attempts += 1;
            if (attempts === 1) { res.end(Buffer.from([1, 2])); return; }
            res.write(Buffer.from([1, 2])); setTimeout(() => res.end(Buffer.from([3, 4])), 5);
        }, async url => {
            assert.deepEqual([...await service.readChunk(url, 4, { ...fast, onProgress: item => progress.push(item.loaded) })], [1, 2, 3, 4]);
        });
        assert.equal(attempts, 2, 'a truncated body must be retried');
        assert.ok(progress.includes(4));
        await withServer((req, res) => res.end(Buffer.from([1, 2, 3, 4, 5])), async url => {
            await assert.rejects(service.readChunk(url, 4, fast), error => error.code === 'integrity');
        });
        await assert.rejects(service.readChunk('/unused', 8388625, fast), error => error.code === 'integrity');
    },
    async network_cancellation() {
        const service = load('encrypted-transfer-network');
        const controller = new AbortController();
        let attempts = 0;
        await withServer((req, res) => { attempts += 1; res.writeHead(503, { 'Retry-After': '20' }); res.end('{}'); }, async url => {
            const pending = service.requestJson(url, {}, { ...fast, signal: controller.signal, onWait: () => controller.abort() });
            await assert.rejects(pending, error => error.name === 'AbortError');
            await sleep(15);
        });
        assert.equal(attempts, 1, 'cancellation must suppress subsequent attempts');
        const events = new EventTarget();
        window.addEventListener = events.addEventListener.bind(events);
        window.removeEventListener = events.removeEventListener.bind(events);
        Object.defineProperty(globalThis, 'navigator', { configurable: true, value: { onLine: false } });
        const offlineController = new AbortController();
        const pending = service.requestJson('/offline', {}, { ...fast, signal: offlineController.signal });
        offlineController.abort();
        await assert.rejects(pending, error => error.name === 'AbortError');
    },
    async network_xhr() {
        const service = load('encrypted-transfer-network');
        const progress = [];
        class Xhr {
            constructor() { this.upload = new EventTarget(); this.responseText = '{"accepted":true}'; this.status = 200; }
            open(method, url) { assert.equal(method, 'PUT'); }
            setRequestHeader() {}
            getResponseHeader() { return null; }
            send(body) {
                assert.equal(body.byteLength, 36);
                const event = new Event('progress');
                Object.assign(event, { loaded: 36, total: 36, lengthComputable: true });
                this.upload.dispatchEvent(event);
                setTimeout(() => this.onload(), 0);
            }
            abort() { this.onabort?.(); }
        }
        globalThis.XMLHttpRequest = Xhr;
        assert.deepEqual(await service.uploadChunk('/chunk', { method: 'PUT', body: new Uint8Array(36) }, { ...fast, onProgress: item => progress.push(item.loaded) }), { accepted: true });
        assert.deepEqual(progress, [36]);
    },
    async network_active_cancel() {
        const service = load('encrypted-transfer-network');
        const controller = new AbortController();
        let attempts = 0;
        await withServer((req, res) => { attempts += 1; res.writeHead(200); res.write(Buffer.from([1, 2])); }, async url => {
            await assert.rejects(service.readChunk(url, 4, {
                ...fast, signal: controller.signal, onProgress: () => controller.abort(),
            }), error => error.name === 'AbortError');
            await sleep(15);
        });
        assert.equal(attempts, 1, 'canceling a pending body read cannot start a retry');
        class Xhr {
            constructor() { this.upload = new EventTarget(); }
            open() {}
            setRequestHeader() {}
            send() { setTimeout(() => controller2.abort(), 5); }
            abort() { this.onabort?.(); }
        }
        const controller2 = new AbortController();
        globalThis.XMLHttpRequest = Xhr;
        await assert.rejects(service.uploadChunk('/chunk', { body: new Uint8Array(36) }, {
            ...fast, signal: controller2.signal,
        }), error => error.name === 'AbortError');
    },
    async network_progress_watchdog() {
        const service = load('encrypted-transfer-network');
        let attempts = 0;
        await withServer((req, res) => {
            attempts += 1;
            res.write(Buffer.from([1]));
            setTimeout(() => res.write(Buffer.from([2])), 150);
            setTimeout(() => res.write(Buffer.from([3])), 300);
            setTimeout(() => res.end(Buffer.from([4])), 450);
        }, async url => {
            assert.deepEqual([...await service.readChunk(url, 4, fast)], [1, 2, 3, 4]);
        });
        assert.equal(attempts, 1, 'ongoing byte progress resets the inactivity watchdog');
    },
    async network_empty_progress_watchdog() {
        const service = load('encrypted-transfer-network');
        let attempts = 0;
        let canceled = false;
        globalThis.fetch = async () => {
            attempts += 1;
            let reads = 0;
            const empty = attempts === 1;
            return { ok: true, body: { getReader() { return {
                async read() {
                    reads += 1;
                    if (empty && reads < 5) { await sleep(20); return { done: false, value: new Uint8Array() }; }
                    if ((empty && reads === 5) || (!empty && reads === 1)) return { done: false, value: new Uint8Array([1, 2, 3, 4]) };
                    return { done: true };
                },
                async cancel() { canceled = true; }, releaseLock() {},
            }; } } };
        };
        assert.deepEqual([...await service.readChunk('/chunk', 4, { ...fast, stallMs: 30 })], [1, 2, 3, 4]);
        assert.equal(attempts, 2, 'zero-byte events do not count as network progress');
        assert.equal(canceled, true);
    },
    async network_offline_recovery() {
        const service = load('encrypted-transfer-network');
        const events = new EventTarget();
        window.addEventListener = events.addEventListener.bind(events);
        window.removeEventListener = events.removeEventListener.bind(events);
        Object.defineProperty(globalThis, 'navigator', { configurable: true, value: { onLine: false } });
        let attempts = 0;
        const waits = [];
        await withServer((req, res) => { attempts += 1; res.end('{"ok":true}'); }, async url => {
            const pending = service.requestJson(url, {}, { ...fast, onWait: value => waits.push(value) });
            await sleep(10);
            assert.equal(attempts, 0, 'no requests are sent while the browser knows it is offline');
            navigator.onLine = true;
            events.dispatchEvent(new Event('online'));
            assert.deepEqual(await pending, { ok: true });
        });
        assert.equal(attempts, 1);
        assert.equal(waits[0].offline, true);
    },
    async persistence_durable() {
        const storage = installBrowserStorage();
        const service = load('encrypted-transfer-persistence');
        const record = { ...upload(), password: 'should-not-save', contentKey: 'secret', name: 'secret.txt' };
        const started = Date.now();
        await service.saveUpload(record);
        assert.ok(Date.now() - started >= 10, 'request success alone does not mean the journal committed');
        assert.ok(storage.completed > 0);
        assert.equal(storage.strict[0].durability, 'strict');
        const saved = await service.getUpload(id);
        assert.equal(saved.attemptedMacs[0], 'A'.repeat(43));
        assert.equal(saved.manifest.encrypted_metadata, manifest.encrypted_metadata);
        assert.equal(saved.password, undefined);
        assert.equal(saved.contentKey, undefined);
        assert.equal(saved.name, undefined);
        assert.equal((await service.listUploads()).length, 1);
        await service.removeUpload(id);
        assert.equal(await service.getUpload(id), null);
    },
    async persistence_abort() {
        const storage = installBrowserStorage();
        const service = load('encrypted-transfer-persistence');
        storage.abortNext = true;
        await assert.rejects(service.saveUpload(upload()), /simulated commit failure/);
        assert.equal(await service.getUpload(id), null, 'aborted records cannot authorize encryption');
    },
    async persistence_ciphertext() {
        const storage = installBrowserStorage();
        const service = load('encrypted-transfer-persistence');
        await service.prepareDownload(download());
        assert.equal(await service.readCachedChunk(id, 0), null);
        await service.writeCachedChunk(id, 0, new Uint8Array(36).fill(123));
        const bytes = await service.readCachedChunk(id, 0);
        assert.deepEqual([...bytes], Array(36).fill(123));
        assert.equal((await service.getDownload(id)).cachedIndexes[0], 0);
        assert.equal((await service.cacheStats()).bytes, 36);
        await assert.rejects(service.writeCachedChunk(id, 0, new Uint8Array(35)), error => error.code === 'integrity');
        await assert.rejects(service.writeCachedChunk('../escape', 0, new Uint8Array(36)), TypeError);
        assert.ok([...storage.files.keys()].every(key => key.startsWith('xferry-encrypted-downloads-v1/')));
        await service.removeCachedChunk(id, 0);
        assert.equal(await service.readCachedChunk(id, 0), null);
        assert.deepEqual((await service.getDownload(id)).cachedIndexes, []);
    },
    async persistence_quota() {
        installBrowserStorage();
        const service = load('encrypted-transfer-persistence');
        navigator.storage.estimate = async () => ({ quota: 35, usage: 0 });
        await assert.rejects(service.prepareDownload(download()), error => error.code === 'quota');
        assert.equal(await service.getDownload(id), null);
        navigator.storage.estimate = async () => ({ quota: 100, usage: 0 });
        await service.prepareDownload(download());
        await service.writeCachedChunk(id, 0, new Uint8Array(36));
        navigator.storage.estimate = async () => ({ quota: 36, usage: 36 });
        await service.prepareDownload(download());
        assert.equal((await service.cacheStats()).bytes, 36, 'existing ciphertext is not charged twice');
    },
    async persistence_cleanup() {
        const storage = installBrowserStorage();
        const service = load('encrypted-transfer-persistence');
        await service.prepareDownload(download());
        await service.writeCachedChunk(id, 0, new Uint8Array(36));
        await service.saveDownload({ ...await service.getDownload(id), updatedAt: Date.now() - 8 * 86400000 });
        await service.prepareDownload(download(secondId));
        await service.writeCachedChunk(secondId, 0, new Uint8Array(36));
        const unrelated = 'different-feature/data.bin';
        storage.files.set(unrelated, new Uint8Array([99]));
        await service.cleanupDownloads({ activeIds: [id] });
        assert.ok(await service.getDownload(id), 'active stale downloads must survive cleanup');
        await service.cleanupDownloads({ activeIds: [] });
        assert.equal(await service.getDownload(id), null);
        assert.ok(await service.getDownload(secondId));
        assert.ok(storage.files.has(unrelated), 'only the module-owned directory can be cleared');
        await service.removeDownload(secondId);
        assert.equal((await service.cacheStats()).bytes, 0);
    },
    async persistence_locks() {
        installBrowserStorage();
        const service = load('encrypted-transfer-persistence');
        let release;
        const first = service.withLock(id, () => new Promise(resolve => { release = resolve; }));
        await sleep(1);
        await assert.rejects(service.withLock(id, async () => 2), error => error.code === 'busy');
        release(1);
        assert.equal(await first, 1);
        assert.equal(await service.withLock(id, async () => 2), 2);
        navigator.locks = undefined;
        await assert.rejects(service.withLock(id, async () => 3), error => error.code === 'unsupported');
    },
    async persistence_unavailable() {
        globalThis.indexedDB = undefined;
        const service = load('encrypted-transfer-persistence');
        assert.equal(service.available(), false);
        await assert.rejects(service.saveUpload(upload()), error => error.code === 'unsupported');
        await assert.rejects(service.prepareDownload(download()), error => error.code === 'unsupported');
    },
    async persistence_manifest_conflict() {
        installBrowserStorage();
        const service = load('encrypted-transfer-persistence');
        await service.prepareDownload(download());
        await service.writeCachedChunk(id, 0, new Uint8Array(36));
        const resumed = await service.prepareDownload(download());
        assert.deepEqual(resumed.cachedIndexes, [0], 'preparing a resumed download preserves existing chunks');
        await assert.rejects(service.prepareDownload({ ...download(), manifest: {
            ...manifest, encrypted_metadata: 'AQAAAAAAAAAAAAAAAAAAAA',
        } }), error => error.code === 'conflict');
        assert.equal((await service.cacheStats()).bytes, 36);
    },
    async persistence_corrupt_cache() {
        const storage = installBrowserStorage();
        const service = load('encrypted-transfer-persistence');
        await service.prepareDownload(download());
        await service.writeCachedChunk(id, 0, new Uint8Array(36));
        storage.files.set(`xferry-encrypted-downloads-v1/${id}/0.bin`, new Uint8Array(35));
        navigator.storage.estimate = async () => ({ quota: 36, usage: 35 });
        await assert.rejects(service.prepareDownload(download()), error => error.code === 'quota',
            'invalid cached bytes do not reduce the space needed for a complete verified chunk');
        assert.equal(await service.readCachedChunk(id, 0), null, 'wrong-size files cannot become plaintext output');
        assert.deepEqual((await service.getDownload(id)).cachedIndexes, []);
        assert.equal((await service.cacheStats()).bytes, 0);
    },
    async persistence_orphan_recovery() {
        const storage = installBrowserStorage();
        const service = load('encrypted-transfer-persistence');
        await service.prepareDownload(download());
        // Simulate a crash after OPFS close but before the IndexedDB index commit.
        storage.files.set(`xferry-encrypted-downloads-v1/${id}/0.bin`, new Uint8Array(36));
        const stats = await service.cacheStats();
        assert.equal(stats.bytes, 36);
        await service.prepareDownload(download());
        assert.deepEqual((await service.getDownload(id)).cachedIndexes, [0]);
        const prefix = `xferry-encrypted-downloads-v1/${secondId}/`;
        storage.files.set(prefix, null);
        storage.files.set(`${prefix}0.bin`, new Uint8Array(36));
        storage.modified = new Map([[`${prefix}0.bin`, Date.now() - 8 * 86400000]]);
        await service.cleanupDownloads();
        assert.equal((await service.cacheStats()).bytes, 36, 'expired orphan ciphertext is removed without touching active valid records');
    },
    async persistence_stats_readonly() {
        const storage = installBrowserStorage();
        const service = load('encrypted-transfer-persistence');
        await service.prepareDownload(download());
        storage.files.set(`xferry-encrypted-downloads-v1/${id}/0.bin`, new Uint8Array(36));
        const writesBefore = storage.strict.length;
        assert.equal((await service.cacheStats()).bytes, 36);
        assert.deepEqual((await service.getDownload(id)).cachedIndexes, [],
            'background statistics must not overwrite an active writer journal');
        assert.equal(storage.strict.length, writesBefore);
        await service.withLock(id, () => service.prepareDownload(download()));
        assert.deepEqual((await service.getDownload(id)).cachedIndexes, [0],
            'recovery occurs only when preparing the exclusively locked download');
    },
    async persistence_stats_concurrent_delete() {
        const storage = installBrowserStorage();
        const service = load('encrypted-transfer-persistence');
        await service.prepareDownload(download());
        await service.writeCachedChunk(id, 0, new Uint8Array(36));
        storage.disappearNext = true;
        assert.equal((await service.cacheStats()).bytes, 0,
            'removing a cache entry in another tab cannot break statistics');
    },
};

(async () => {
    assert.equal(typeof scenarios[process.argv[2]], 'function', 'unknown scenario');
    await scenarios[process.argv[2]]();
})().catch(error => { console.error(error.stack || error); process.exitCode = 1; });
