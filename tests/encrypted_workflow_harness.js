'use strict';

// External browser-storage boundary for workflow tests. The persistence service
// has its own tests against transactional IndexedDB/OPFS implementations.
function installTransferServices(app, uiRoot, options = {}) {
    const fs = require('node:fs');
    const vm = require('node:vm');
    const services = new Map();
    const originalService = app.service.bind(app);
    const uploads = options.uploads || new Map();
    const downloads = options.downloads || new Map();
    const chunks = options.chunks || new Map();
    const locks = new Set();
    app.service = name => services.has(name) ? services.get(name) : originalService(name);
    app.registerService = (name, value) => services.set(name, value);
    const copy = value => value == null ? value : structuredClone(value);
    const persistence = {
        available: () => true,
        async saveUpload(record) {
            if (options.failDurability) throw new Error('journal transaction failed');
            uploads.set(record.id, copy(record));
            options.onWrite?.(copy(record));
        },
        async getUpload(id) { return copy(uploads.get(id) || null); },
        async listUploads() { return [...uploads.values()].map(copy); },
        async removeUpload(id) { uploads.delete(id); options.onDelete?.(id); },
        async saveDownload(record) { downloads.set(record.id, copy(record)); },
        async getDownload(id) { return copy(downloads.get(id) || null); },
        async listDownloads() { return [...downloads.values()].map(copy); },
        async prepareDownload(record) {
            const previous = downloads.get(record.id);
            if (previous && JSON.stringify(previous.manifest) !== JSON.stringify(record.manifest)) {
                throw new Error('cached manifest conflicts with file');
            }
            const current = { ...copy(record), cachedIndexes: previous?.cachedIndexes || [] };
            downloads.set(record.id, current);
            return copy(current);
        },
        async writeCachedChunk(id, index, bytes) {
            chunks.set(`${id}/${index}`, bytes.slice());
            const record = downloads.get(id);
            record.cachedIndexes = [...new Set([...record.cachedIndexes, index])];
            record.updatedAt = Date.now();
        },
        async readCachedChunk(id, index) { return chunks.get(`${id}/${index}`)?.slice() || null; },
        async removeCachedChunk(id, index) {
            chunks.delete(`${id}/${index}`);
            const record = downloads.get(id);
            if (record) record.cachedIndexes = record.cachedIndexes.filter(value => value !== index);
        },
        async removeDownload(id) {
            downloads.delete(id);
            for (const key of chunks.keys()) if (key.startsWith(`${id}/`)) chunks.delete(key);
        },
        async cleanupDownloads() {},
        async cacheStats() {
            let bytes = 0;
            const files = [...downloads.values()].map(record => {
                const size = [...chunks].filter(([key]) => key.startsWith(`${record.id}/`))
                    .reduce((total, [, value]) => total + value.byteLength, 0);
                bytes += size;
                return { id: record.id, bytes: size, updatedAt: record.updatedAt };
            });
            return { bytes, files };
        },
        async withLock(id, operation) {
            if (locks.has(id)) throw Object.assign(new Error('file already active in another tab'), { code: 'busy' });
            locks.add(id);
            try { return await operation(); } finally { locks.delete(id); }
        },
    };
    services.set('encrypted-transfer-persistence', persistence);
    const networkPath = `${uiRoot}/encrypted-transfer-network.js`;
    if (fs.existsSync(networkPath)) {
        vm.runInThisContext(fs.readFileSync(networkPath, 'utf8'), { filename: networkPath });
        const network = services.get('encrypted-transfer-network');
        const fast = context => ({ retryBaseMs: 2, maxDelayMs: 4, stallMs: 1000, random: () => 0.5, ...context });
        services.set('encrypted-transfer-network', {
            ...network,
            requestJson: (url, config, context) => network.requestJson(url, config, fast(context)),
            uploadChunk: (url, config, context) => network.uploadChunk(url, config, fast(context)),
            readChunk: (url, length, context) => network.readChunk(url, length, fast(context)),
        });
    }
    return { uploads, downloads, chunks, persistence };
}

module.exports = { installTransferServices };
