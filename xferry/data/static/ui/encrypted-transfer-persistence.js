(function initializeEncryptedTransferPersistence(app) {
    'use strict';

    const databaseName = 'xferry-encrypted-transfers-v1';
    const cacheDirectoryName = 'xferry-encrypted-downloads-v1';
    const maxChunkSize = 8 * 1024 * 1024;
    const defaultCacheAge = 7 * 24 * 60 * 60 * 1000;
    let databasePromise;

    function storageError(message, code) {
        return Object.assign(new Error(message), { code });
    }

    function available() {
        return typeof indexedDB !== 'undefined' && typeof indexedDB.open === 'function';
    }

    function validateId(id) {
        if (typeof id !== 'string' || !/^[0-9a-f]{32}$/.test(id)) {
            throw new TypeError('Encrypted transfer ID is invalid');
        }
        return id;
    }

    function validateIndex(index, manifest) {
        if (!Number.isSafeInteger(index) || index < 0 || (manifest && index >= manifest.chunk_count)) {
            throw new TypeError('Encrypted transfer chunk index is invalid');
        }
        return index;
    }

    function canonicalBase64(value, length, field) {
        if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+$/.test(value) || value.length % 4 === 1) {
            throw new TypeError(`${field} must be encoded ciphertext data`);
        }
        let decoded;
        try { decoded = atob(value.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat(-value.length & 3)); }
        catch (_error) { throw new TypeError(`${field} is invalid`); }
        const encoded = btoa(decoded).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
        if (encoded !== value || (length !== undefined && decoded.length !== length)) {
            throw new TypeError(`${field} is invalid`);
        }
        return decoded.length;
    }

    function safeManifest(value) {
        if (!value || value.version !== 1 || value.chunk_size !== maxChunkSize
            || !Number.isSafeInteger(value.plaintext_size) || value.plaintext_size < 0
            || value.chunk_count !== Math.ceil(value.plaintext_size / maxChunkSize)) {
            throw new TypeError('Encrypted transfer manifest is invalid');
        }
        canonicalBase64(value.salt, 16, 'salt');
        canonicalBase64(value.nonce_prefix, 8, 'nonce_prefix');
        const metadataLength = canonicalBase64(value.encrypted_metadata, undefined, 'encrypted_metadata');
        if (metadataLength < 16 || metadataLength > 4112) throw new TypeError('Encrypted metadata is invalid');
        return {
            version: 1, plaintext_size: value.plaintext_size, chunk_size: maxChunkSize,
            chunk_count: value.chunk_count, salt: value.salt, nonce_prefix: value.nonce_prefix,
            encrypted_metadata: value.encrypted_metadata,
        };
    }

    function safeIndexes(value, manifest) {
        if (value === undefined) return [];
        if (!Array.isArray(value)) throw new TypeError('Encrypted transfer chunk indexes are invalid');
        return [...new Set(value.map(index => validateIndex(index, manifest)))].sort((a, b) => a - b);
    }

    function timestamp(value) {
        return Number.isFinite(value) && value >= 0 ? value : Date.now();
    }

    function safeRecord(record, kind) {
        validateId(record?.id);
        const manifest = safeManifest(record.manifest);
        const common = {
            id: record.id, schemaVersion: 2, manifest,
            status: typeof record.status === 'string' ? record.status : 'paused',
            updatedAt: timestamp(record.updatedAt),
        };
        if (kind === 'uploads') {
            if (record.schemaVersion !== 2 || !record.attemptedMacs || Array.isArray(record.attemptedMacs)) {
                throw new TypeError('Durable upload journal is invalid');
            }
            const attemptedMacs = {};
            for (const [rawIndex, mac] of Object.entries(record.attemptedMacs)) {
                const index = Number(rawIndex);
                validateIndex(index, manifest);
                if (String(index) !== rawIndex) throw new TypeError('Upload journal index is invalid');
                canonicalBase64(mac, 32, 'resume_mac');
                attemptedMacs[index] = mac;
            }
            return { ...common, attemptedMacs, receivedIndexes: safeIndexes(record.receivedIndexes, manifest) };
        }
        const ciphertextSize = manifest.plaintext_size + manifest.chunk_count * 16;
        if (!Number.isSafeInteger(ciphertextSize)
            || (record.ciphertext_size !== undefined && record.ciphertext_size !== ciphertextSize)) {
            throw new TypeError('Download ciphertext length is invalid');
        }
        return {
            ...common, ciphertext_size: ciphertextSize,
            cachedIndexes: safeIndexes(record.cachedIndexes, manifest),
        };
    }

    async function openDatabase() {
        if (!available()) throw storageError('Durable browser storage is unavailable', 'unsupported');
        if (!databasePromise) {
            databasePromise = new Promise((resolve, reject) => {
                const request = indexedDB.open(databaseName, 2);
                request.onupgradeneeded = () => {
                    for (const name of ['uploads', 'downloads']) {
                        if (!request.result.objectStoreNames.contains(name)) {
                            request.result.createObjectStore(name, { keyPath: 'id' });
                        }
                    }
                };
                request.onerror = () => reject(request.error || storageError('Browser storage could not be opened', 'storage'));
                request.onblocked = () => reject(storageError('Close older transfer tabs to upgrade browser storage', 'busy'));
                request.onsuccess = () => {
                    const database = request.result;
                    database.onversionchange = () => { database.close(); databasePromise = undefined; };
                    resolve(database);
                };
            });
        }
        try { return await databasePromise; }
        catch (error) { databasePromise = undefined; throw error; }
    }

    async function perform(storeName, mode, action) {
        const database = await openDatabase();
        return new Promise((resolve, reject) => {
            let transaction;
            try {
                if (mode === 'readwrite') {
                    try { transaction = database.transaction(storeName, mode, { durability: 'strict' }); }
                    catch (error) {
                        if (error instanceof TypeError) transaction = database.transaction(storeName, mode);
                        else throw error;
                    }
                } else transaction = database.transaction(storeName, mode);
            } catch (error) { reject(error); return; }
            let value;
            let requestError;
            // Request success does not authorize reuse of a nonce. Only commit does.
            transaction.oncomplete = () => resolve(value);
            transaction.onabort = () => reject(transaction.error || requestError || storageError('Browser storage transaction aborted', 'storage'));
            transaction.onerror = () => { requestError = transaction.error; };
            try {
                const request = action(transaction.objectStore(storeName));
                request.onsuccess = () => { value = request.result; };
                request.onerror = () => { requestError = request.error; };
            } catch (error) {
                try { transaction.abort(); } catch (_ignored) { /* Already inactive. */ }
                reject(error);
            }
        });
    }

    async function saveUpload(record) {
        const safe = safeRecord(record, 'uploads');
        await perform('uploads', 'readwrite', store => store.put(safe));
        return safe;
    }

    async function getUpload(id) {
        validateId(id);
        const record = await perform('uploads', 'readonly', store => store.get(id));
        if (!record) return null;
        // v1 journals contain only confirmed indexes and cannot authorize resume.
        if (record.schemaVersion !== 2) return {
            id, schemaVersion: 1, receivedIndexes: Array.isArray(record.receivedIndexes) ? record.receivedIndexes : [],
            status: typeof record.status === 'string' ? record.status : 'paused', updatedAt: timestamp(record.updatedAt),
        };
        return safeRecord(record, 'uploads');
    }

    async function listUploads() {
        const records = await perform('uploads', 'readonly', store => store.getAll());
        const results = [];
        for (const record of records) results.push(await getUpload(record.id));
        return results;
    }

    async function removeUpload(id) {
        validateId(id);
        await perform('uploads', 'readwrite', store => store.delete(id));
    }

    async function saveDownload(record) {
        const safe = safeRecord(record, 'downloads');
        await perform('downloads', 'readwrite', store => store.put(safe));
        return safe;
    }

    async function getDownload(id) {
        validateId(id);
        const record = await perform('downloads', 'readonly', store => store.get(id));
        return record ? safeRecord(record, 'downloads') : null;
    }

    async function listDownloads() {
        return (await perform('downloads', 'readonly', store => store.getAll()))
            .map(record => safeRecord(record, 'downloads'));
    }

    async function cacheRoot(create = false) {
        if (!globalThis.navigator?.storage?.getDirectory) {
            throw storageError('Private browser file storage is unavailable', 'unsupported');
        }
        const root = await navigator.storage.getDirectory();
        try { return await root.getDirectoryHandle(cacheDirectoryName, { create }); }
        catch (error) { if (error?.name === 'NotFoundError') return null; throw error; }
    }

    async function cacheDirectory(id, create = false) {
        validateId(id);
        const root = await cacheRoot(create);
        if (!root) return null;
        try { return await root.getDirectoryHandle(id, { create }); }
        catch (error) { if (error?.name === 'NotFoundError') return null; throw error; }
    }

    function expectedChunkLength(manifest, index) {
        validateIndex(index, manifest);
        return Math.min(manifest.chunk_size, manifest.plaintext_size - index * manifest.chunk_size) + 16;
    }

    function sameManifest(first, second) {
        return JSON.stringify(first) === JSON.stringify(second);
    }

    async function inspectCache(directory, manifest) {
        let bytes = 0;
        let newest = 0;
        const validIndexes = [];
        if (directory) {
            try {
                for await (const [name, entry] of directory.entries()) {
                    if (entry.kind !== 'file' || !/^(0|[1-9][0-9]*)\.bin$/.test(name)) continue;
                    const index = Number(name.slice(0, -4));
                    if (!Number.isSafeInteger(index) || index < 0) continue;
                    let file;
                    try { file = await entry.getFile(); }
                    catch (error) { if (error?.name === 'NotFoundError') continue; throw error; }
                    newest = Math.max(newest, file.lastModified || 0);
                    if (file.size < 16 || file.size > maxChunkSize + 16) continue;
                    bytes += file.size;
                    if (manifest && index < manifest.chunk_count
                        && file.size === expectedChunkLength(manifest, index)) validIndexes.push(index);
                }
            } catch (error) {
                // Another tab may remove the directory while statistics iterate
                // it. A transient snapshot is fine; no journal is rewritten.
                if (error?.name !== 'NotFoundError') throw error;
            }
        }
        validIndexes.sort((a, b) => a - b);
        return { bytes, newest, validIndexes };
    }

    async function prepareDownload(record) {
        if (!available() || !globalThis.navigator?.storage?.getDirectory
            || !navigator.storage.estimate) {
            throw storageError('Resumable downloads require durable private browser storage', 'unsupported');
        }
        const safe = safeRecord(record, 'downloads');
        const previous = await getDownload(safe.id);
        if (previous && !sameManifest(previous.manifest, safe.manifest)) {
            throw storageError('Cached download has different encryption parameters', 'conflict');
        }
        // Called by the workflow while holding this ID's transfer lock. Reconcile
        // a crash after file close and before the index commit at this boundary,
        // never from background cache statistics in another tab.
        const cachedFiles = await inspectCache(await cacheDirectory(safe.id), safe.manifest);
        // Invalid or unrelated bytes occupy quota but do not replace a missing
        // complete chunk. Count only the recovered, correctly-sized files.
        const cached = cachedFiles.validIndexes.reduce(
            (sum, index) => sum + expectedChunkLength(safe.manifest, index), 0
        );
        const estimate = await navigator.storage.estimate();
        const needed = Math.max(0, safe.ciphertext_size - cached);
        if (Number.isFinite(estimate.quota) && Number.isFinite(estimate.usage)
            && estimate.quota - estimate.usage < needed) {
            throw storageError('Insufficient space for encrypted download cache', 'quota');
        }
        // Persistent-storage permission is best effort; denial is not a guarantee
        // of eviction and must not prevent a transfer with adequate space.
        try { await navigator.storage.persist?.(); } catch (_error) { /* Optional browser permission. */ }
        await cacheDirectory(safe.id, true);
        return saveDownload({ ...safe, cachedIndexes: cachedFiles.validIndexes });
    }

    async function readCachedChunk(id, index) {
        validateId(id);
        validateIndex(index);
        const record = await getDownload(id);
        if (!record) return null;
        const expectedLength = expectedChunkLength(record.manifest, index);
        const directory = await cacheDirectory(id);
        if (!directory) return null;
        try {
            const handle = await directory.getFileHandle(`${index}.bin`);
            const file = await handle.getFile();
            if (file.size !== expectedLength) {
                await removeCachedChunk(id, index);
                return null;
            }
            return new Uint8Array(await file.arrayBuffer());
        } catch (error) { if (error?.name === 'NotFoundError') return null; throw error; }
    }

    async function writeCachedChunk(id, index, ciphertext) {
        validateId(id);
        validateIndex(index);
        const record = await getDownload(id);
        if (!record) throw storageError('Download cache was not prepared', 'storage');
        const expectedLength = expectedChunkLength(record.manifest, index);
        if (!(ciphertext instanceof Uint8Array) || ciphertext.byteLength !== expectedLength) {
            throw storageError('Ciphertext chunk length is invalid', 'integrity');
        }
        const directory = await cacheDirectory(id, true);
        let writer;
        try {
            const file = await directory.getFileHandle(`${index}.bin`, { create: true });
            writer = await file.createWritable();
            await writer.write(ciphertext);
            await writer.close();
        } catch (error) {
            try { await writer?.abort?.(); } catch (_ignored) { /* Best effort after write failure. */ }
            if (error?.name === 'QuotaExceededError') throw storageError('Encrypted download cache is full', 'quota');
            throw error;
        }
        await saveDownload({ ...record, cachedIndexes: [...new Set([...record.cachedIndexes, index])], updatedAt: Date.now() });
    }

    async function removeCachedChunk(id, index) {
        validateId(id);
        validateIndex(index);
        const directory = await cacheDirectory(id);
        if (directory) {
            try { await directory.removeEntry(`${index}.bin`); }
            catch (error) { if (error?.name !== 'NotFoundError') throw error; }
        }
        const record = await getDownload(id);
        if (record) await saveDownload({ ...record, cachedIndexes: record.cachedIndexes.filter(value => value !== index) });
    }

    async function removeDownload(id) {
        validateId(id);
        const root = await cacheRoot();
        if (root) {
            try { await root.removeEntry(id, { recursive: true }); }
            catch (error) { if (error?.name !== 'NotFoundError') throw error; }
        }
        await perform('downloads', 'readwrite', store => store.delete(id));
    }

    async function cacheStats() {
        const records = new Map((await listDownloads()).map(record => [record.id, record]));
        const root = await cacheRoot();
        const files = [];
        const found = new Set();
        if (root) {
            for await (const [id, handle] of root.entries()) {
                if (handle.kind !== 'directory' || !/^[0-9a-f]{32}$/.test(id)) continue;
                found.add(id);
                const record = records.get(id);
                const { bytes, newest } = await inspectCache(handle);
                files.push({ id, bytes, updatedAt: record?.updatedAt ?? (newest || Date.now()) });
            }
        }
        for (const record of records.values()) {
            if (found.has(record.id)) continue;
            files.push({ id: record.id, bytes: 0, updatedAt: record.updatedAt });
        }
        return { bytes: files.reduce((sum, file) => sum + file.bytes, 0), files };
    }

    async function withLock(id, action) {
        validateId(id);
        if (!globalThis.navigator?.locks?.request) {
            throw storageError('This browser cannot prevent concurrent transfer tabs', 'unsupported');
        }
        return navigator.locks.request(`xferry-encrypted-transfer-${id}`, { mode: 'exclusive', ifAvailable: true }, lock => {
            if (!lock) throw storageError('This transfer is active in another tab', 'busy');
            return action();
        });
    }

    async function cleanupDownloads({ activeIds = [], maxAgeMs = defaultCacheAge } = {}) {
        const active = new Set(activeIds.map(validateId));
        const stats = await cacheStats();
        const cutoff = Date.now() - maxAgeMs;
        for (const file of stats.files) {
            if (active.has(file.id) || file.updatedAt >= cutoff) continue;
            try {
                await withLock(file.id, async () => {
                    // Recheck activity after lock acquisition to avoid deleting a
                    // transfer that refreshed its metadata in a different tab.
                    const record = await getDownload(file.id);
                    if (!record || record.updatedAt < cutoff) await removeDownload(file.id);
                });
            } catch (error) { if (error?.code !== 'busy') throw error; }
        }
        return cacheStats();
    }

    app.registerService('encrypted-transfer-persistence', {
        available, saveUpload, getUpload, listUploads, removeUpload,
        saveDownload, getDownload, listDownloads, removeDownload,
        prepareDownload, readCachedChunk, writeCachedChunk, removeCachedChunk,
        cacheStats, cleanupDownloads, withLock,
    });
})(window.XferryApp);
