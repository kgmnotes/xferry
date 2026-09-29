(function initializeEncryptedTransfer(app) {
    'use strict';

    const cryptoCodec = app.service('encrypted-transfer-crypto');
    const core = app.service('core');
    const notifications = app.service('notifications');
    const dialogs = app.service('dialogs');
    const panel = document.getElementById('encryptedTransferPanel');
    const uploadForm = document.getElementById('encryptedUploadForm');
    const fileInput = document.getElementById('encryptedFileInput');
    const passwordInput = document.getElementById('encryptedPasswordInput');
    const passwordConfirmInput = document.getElementById('encryptedPasswordConfirmInput');
    const startButton = document.getElementById('encryptedUploadStartBtn');
    const pauseButton = document.getElementById('encryptedUploadPauseBtn');
    const resumeButton = document.getElementById('encryptedUploadResumeBtn');
    const cancelButton = document.getElementById('encryptedUploadCancelBtn');
    const progressElement = document.getElementById('encryptedUploadProgress');
    const statusElement = document.getElementById('encryptedTransferStatus');
    const refreshButton = document.getElementById('encryptedRefreshBtn');
    const partialList = document.getElementById('encryptedPartialList');
    const encryptedFileList = document.getElementById('encryptedFileList');
    const resumeForm = document.getElementById('encryptedResumeForm');
    const resumeIdOutput = document.getElementById('encryptedResumeId');
    const resumeFileInput = document.getElementById('encryptedResumeFileInput');
    const resumePasswordInput = document.getElementById('encryptedResumePasswordInput');
    const resumeDismissButton = document.getElementById('encryptedResumeDismissBtn');
    const unlockForm = document.getElementById('encryptedUnlockForm');
    const unlockIdOutput = document.getElementById('encryptedUnlockId');
    const unlockPasswordInput = document.getElementById('encryptedUnlockPasswordInput');
    const unlockDismissButton = document.getElementById('encryptedUnlockDismissBtn');
    const progressDatabaseName = 'xferry-encrypted-transfers-v1';
    const progressStoreName = 'uploads';
    const capabilityKeys = Object.freeze([
        'browser_decryption',
        'chunk_size',
        'enabled',
        'max_plaintext_size',
        'parallel_chunks',
        'server_decryption',
        'version',
    ]);
    const transferState = {
        enabled: false,
        capabilityStatus: 'pending',
        capability: null,
        phase: 'idle',
        activeSession: null,
        partialUploads: [],
        encryptedFiles: [],
        unlockedFiles: new Map(),
        progressReceived: 0,
        progressTotal: 0,
        selectedResumeId: '',
        selectedUnlockId: '',
        lastError: '',
    };
    let progressDatabasePromise = null;

    function hasExactKeys(value, expectedKeys) {
        return Object.keys(value).sort().join(',') === [...expectedKeys].sort().join(',');
    }

    function validateCapability(rawCapability) {
        if (
            rawCapability
            && typeof rawCapability === 'object'
            && !Array.isArray(rawCapability)
            && hasExactKeys(rawCapability, ['enabled'])
            && rawCapability.enabled === false
        ) {
            return { status: 'disabled', capability: null };
        }
        if (
            !rawCapability
            || typeof rawCapability !== 'object'
            || Array.isArray(rawCapability)
            || !hasExactKeys(rawCapability, capabilityKeys)
            || rawCapability.enabled !== true
            || rawCapability.version !== 1
            || !Number.isSafeInteger(rawCapability.max_plaintext_size)
            || rawCapability.max_plaintext_size < 0
            || rawCapability.chunk_size !== cryptoCodec.chunkSize
            || rawCapability.parallel_chunks !== 2
            || typeof rawCapability.browser_decryption !== 'boolean'
            || typeof rawCapability.server_decryption !== 'boolean'
        ) {
            return { status: 'invalid', capability: null };
        }
        return { status: 'valid', capability: Object.freeze({ ...rawCapability }) };
    }

    function renderCapabilityState() {
        if (!panel) {
            return;
        }
        panel.hidden = !transferState.enabled;
        panel.setAttribute('aria-hidden', String(!transferState.enabled));
        renderTransferState();
    }

    function statusMessage() {
        if (transferState.lastError) {
            return `${core.t('encryptedStatusError')}: ${transferState.lastError}`;
        }
        if (transferState.phase === 'preparing') {
            return core.t('encryptedStatusPreparing');
        }
        if (transferState.phase === 'uploading') {
            return core.t('encryptedStatusUploading')
                .replace('{0}', String(transferState.progressReceived))
                .replace('{1}', String(transferState.progressTotal));
        }
        if (transferState.phase === 'paused' || transferState.phase === 'pausing') {
            return core.t('encryptedStatusPaused');
        }
        if (transferState.phase === 'complete') {
            return core.t('encryptedStatusComplete');
        }
        if (transferState.phase === 'canceled' || transferState.phase === 'canceling') {
            return core.t('encryptedStatusCanceled');
        }
        return core.t('encryptedStatusIdle');
    }

    function createActionButton(labelKey, action, fileId, className = 'btn-ghost btn--sm') {
        const button = document.createElement('button');
        button.type = 'button';
        button.className = className;
        button.textContent = core.t(labelKey);
        button.dataset.encryptedAction = action;
        button.dataset.encryptedId = fileId;
        return button;
    }

    function createEmptyListItem(messageKey) {
        const item = document.createElement('p');
        item.className = 'encrypted-transfer__empty';
        item.textContent = core.t(messageKey);
        return item;
    }

    function renderPartialUploads() {
        if (!partialList) {
            return;
        }
        partialList.replaceChildren();
        if (transferState.partialUploads.length === 0) {
            partialList.appendChild(createEmptyListItem('encryptedNoPartialUploads'));
            return;
        }
        transferState.partialUploads.forEach(record => {
            const item = document.createElement('article');
            item.className = 'encrypted-transfer__item';
            item.setAttribute('role', 'listitem');

            const id = document.createElement('p');
            id.className = 'encrypted-transfer__item-id';
            id.textContent = record.id;
            const meta = document.createElement('p');
            meta.className = 'encrypted-transfer__item-meta';
            meta.textContent = `${core.formatSize(record.plaintext_size)} · ${record.received_chunks.length}/${record.chunk_count}`;
            const actions = document.createElement('div');
            actions.className = 'encrypted-transfer__item-actions';
            actions.append(
                createActionButton('encryptedResumeAction', 'resume-remote', record.id, 'btn-info btn--sm'),
                createActionButton('encryptedCancelRemote', 'cancel-remote', record.id, 'btn-danger btn--sm')
            );
            item.append(id, meta, actions);
            partialList.appendChild(item);
        });
    }

    function renderEncryptedFiles() {
        if (!encryptedFileList) {
            return;
        }
        encryptedFileList.replaceChildren();
        if (transferState.encryptedFiles.length === 0) {
            encryptedFileList.appendChild(createEmptyListItem('encryptedNoFiles'));
            return;
        }
        transferState.encryptedFiles.forEach(record => {
            const unlocked = transferState.unlockedFiles.get(record.id);
            const item = document.createElement('article');
            item.className = 'encrypted-transfer__item';
            item.setAttribute('role', 'listitem');

            const name = document.createElement('p');
            name.className = 'encrypted-transfer__item-name';
            name.textContent = unlocked?.metadata?.name || core.t('encryptedUnlockTitle');
            const id = document.createElement('p');
            id.className = 'encrypted-transfer__item-id';
            id.textContent = record.id;
            const meta = document.createElement('p');
            meta.className = 'encrypted-transfer__item-meta';
            meta.textContent = core.formatSize(record.plaintext_size);
            const actions = document.createElement('div');
            actions.className = 'encrypted-transfer__item-actions';
            if (!unlocked) {
                actions.appendChild(
                    createActionButton('encryptedUnlock', 'unlock', record.id, 'btn-info btn--sm')
                );
            } else {
                actions.appendChild(
                    createActionButton(
                        'encryptedClientDownload',
                        'download-client',
                        record.id,
                        'btn-download btn--sm'
                    )
                );
                if (transferState.capability?.server_decryption) {
                    actions.appendChild(
                        createActionButton(
                            'encryptedServerDownload',
                            'download-server',
                            record.id,
                            'btn-ghost btn--sm'
                        )
                    );
                }
            }
            item.append(name, id, meta, actions);
            encryptedFileList.appendChild(item);
        });
    }

    function renderTransferState() {
        const phase = transferState.phase;
        const busy = ['preparing', 'uploading', 'pausing', 'canceling', 'downloading'].includes(phase);
        if (panel) {
            panel.setAttribute('aria-busy', String(busy));
            if (panel.dataset) {
                panel.dataset.transferPhase = phase;
            }
        }
        if (startButton) {
            startButton.disabled = busy || !transferState.enabled;
        }
        if (pauseButton) {
            pauseButton.disabled = phase !== 'uploading';
        }
        if (resumeButton) {
            resumeButton.disabled = phase !== 'paused';
        }
        if (cancelButton) {
            cancelButton.disabled = !transferState.activeSession;
        }
        if (refreshButton) {
            refreshButton.disabled = busy || !transferState.enabled;
        }
        if (progressElement) {
            const total = transferState.progressTotal;
            const value = total > 0
                ? Math.round((transferState.progressReceived / total) * 100)
                : (phase === 'complete' ? 100 : 0);
            progressElement.value = value;
            progressElement.textContent = `${value}%`;
        }
        if (statusElement) {
            statusElement.textContent = statusMessage();
        }
        if (resumeForm) {
            resumeForm.hidden = !transferState.selectedResumeId;
        }
        if (resumeIdOutput) {
            resumeIdOutput.textContent = transferState.selectedResumeId;
        }
        if (unlockForm) {
            unlockForm.hidden = !transferState.selectedUnlockId;
        }
        if (unlockIdOutput) {
            unlockIdOutput.textContent = transferState.selectedUnlockId;
        }
        renderPartialUploads();
        renderEncryptedFiles();
    }

    function syncCapability() {
        const coreState = core.getState();
        if (coreState.serverDiscoveryStatus === 'pending') {
            transferState.enabled = false;
            transferState.capabilityStatus = 'pending';
            transferState.capability = null;
        } else if (coreState.serverDiscoveryStatus !== 'ready') {
            transferState.enabled = false;
            transferState.capabilityStatus = 'unavailable';
            transferState.capability = null;
        } else {
            const result = validateCapability(coreState.encryptedUploadCapabilities);
            transferState.enabled = result.status === 'valid';
            transferState.capabilityStatus = result.status;
            transferState.capability = result.capability;
        }
        renderCapabilityState();
    }

    function encodeFileId(bytes) {
        return Array.from(bytes, value => value.toString(16).padStart(2, '0')).join('');
    }

    function requestResult(request) {
        return new Promise((resolve, reject) => {
            request.onsuccess = () => resolve(request.result);
            request.onerror = () => reject(request.error || new Error('IndexedDB request failed'));
        });
    }

    async function openProgressDatabase() {
        if (typeof indexedDB === 'undefined') {
            return null;
        }
        if (!progressDatabasePromise) {
            progressDatabasePromise = new Promise((resolve, reject) => {
                const request = indexedDB.open(progressDatabaseName, 1);
                request.onupgradeneeded = () => {
                    const database = request.result;
                    if (!database.objectStoreNames.contains(progressStoreName)) {
                        database.createObjectStore(progressStoreName, { keyPath: 'id' });
                    }
                };
                request.onsuccess = () => resolve(request.result);
                request.onerror = () => reject(
                    request.error || new Error('Encrypted upload progress database failed')
                );
            });
        }
        try {
            return await progressDatabasePromise;
        } catch (error) {
            progressDatabasePromise = null;
            return null;
        }
    }

    async function persistProgress(session, status = 'uploading') {
        const database = await openProgressDatabase();
        if (!database) {
            return;
        }
        const transaction = database.transaction(progressStoreName, 'readwrite');
        await requestResult(transaction.objectStore(progressStoreName).put({
            id: session.manifest.fileId,
            receivedIndexes: Array.from(session.receivedIndexes).sort((left, right) => left - right),
            status,
            updatedAt: Date.now(),
        }));
    }

    async function deleteProgress(fileId) {
        const database = await openProgressDatabase();
        if (!database) {
            return;
        }
        const transaction = database.transaction(progressStoreName, 'readwrite');
        await requestResult(transaction.objectStore(progressStoreName).delete(fileId));
    }

    async function parseJsonResponse(response) {
        let payload;
        try {
            payload = await response.json();
        } catch (error) {
            throw new Error(`Encrypted transfer returned invalid JSON (HTTP ${response.status || 0})`);
        }
        if (!response.ok) {
            const message = typeof payload?.error?.message === 'string'
                ? payload.error.message
                : `Encrypted transfer failed (HTTP ${response.status || 0})`;
            throw new Error(message);
        }
        return payload;
    }

    async function requestJson(path, options = {}) {
        const response = await fetch(`${core.serverUrl}${path}`, {
            credentials: 'same-origin',
            cache: 'no-store',
            ...options,
        });
        return parseJsonResponse(response);
    }

    function createManifest(file) {
        const fileId = encodeFileId(cryptoCodec.randomBytes(16));
        return {
            version: 1,
            fileId,
            plaintextSize: file.size,
            chunkSize: cryptoCodec.chunkSize,
            chunkCount: Math.ceil(file.size / cryptoCodec.chunkSize),
            salt: cryptoCodec.randomBytes(16),
            noncePrefix: cryptoCodec.randomBytes(8),
        };
    }

    function createManifestPayload(manifest) {
        return {
            version: manifest.version,
            plaintext_size: manifest.plaintextSize,
            chunk_size: manifest.chunkSize,
            chunk_count: manifest.chunkCount,
            salt: cryptoCodec.encodeBase64Url(manifest.salt),
            nonce_prefix: cryptoCodec.encodeBase64Url(manifest.noncePrefix),
            encrypted_metadata: cryptoCodec.encodeBase64Url(manifest.encryptedMetadata),
        };
    }

    async function createRemoteUpload(session) {
        const payload = createManifestPayload(session.manifest);
        const result = await requestJson(
            `/_xferry/encrypted-uploads/${session.manifest.fileId}`,
            {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload),
            }
        );
        if (result?.encrypted_upload?.id !== session.manifest.fileId) {
            throw new Error('Encrypted upload create response is invalid');
        }
    }

    async function uploadChunk(session, index, signal) {
        const start = index * session.manifest.chunkSize;
        const end = Math.min(session.file.size, start + session.manifest.chunkSize);
        const plaintext = new Uint8Array(await session.file.slice(start, end).arrayBuffer());
        const [ciphertext, resumeMac] = await Promise.all([
            cryptoCodec.encryptChunk(plaintext, session.contentKey, session.manifest, index),
            cryptoCodec.computeResumeMac(plaintext, session.resumeKey, session.manifest, index),
        ]);
        plaintext.fill(0);
        const encodedMac = cryptoCodec.encodeBase64Url(resumeMac);
        const result = await requestJson(
            `/_xferry/encrypted-uploads/${session.manifest.fileId}/chunks/${index}`,
            {
                method: 'PUT',
                headers: {
                    'Content-Type': 'application/octet-stream',
                    'X-XFerry-Chunk-MAC': encodedMac,
                },
                body: ciphertext,
                signal,
            }
        );
        if (result?.encrypted_chunk?.index !== index) {
            throw new Error('Encrypted chunk response is invalid');
        }
        session.receivedIndexes.add(index);
        transferState.progressReceived = session.receivedIndexes.size;
        renderTransferState();
        await persistProgress(session);
    }

    async function uploadPendingChunks(session) {
        const queue = Array.from(
            { length: session.manifest.chunkCount },
            (_value, index) => index
        ).filter(index => !session.receivedIndexes.has(index));
        let queueOffset = 0;
        session.controller = new AbortController();

        async function worker() {
            while (queueOffset < queue.length) {
                const index = queue[queueOffset];
                queueOffset += 1;
                await uploadChunk(session, index, session.controller.signal);
            }
        }

        const workerCount = Math.min(2, queue.length);
        await Promise.all(Array.from({ length: workerCount }, () => worker()));
    }

    async function completeRemoteUpload(session) {
        const payload = await requestJson(
            `/_xferry/encrypted-uploads/${session.manifest.fileId}/complete`,
            { method: 'POST' }
        );
        if (payload?.encrypted_file?.status !== 'complete') {
            throw new Error('Encrypted upload completion response is invalid');
        }
    }

    async function startUpload(options = {}) {
        if (!transferState.enabled || !transferState.capability) {
            throw new Error('Encrypted uploads are not available');
        }
        const file = options.file;
        if (!file || !Number.isSafeInteger(file.size) || file.size < 0) {
            throw new TypeError('A browser File is required');
        }
        if (file.size > transferState.capability.max_plaintext_size) {
            throw new RangeError('File exceeds the encrypted upload size limit');
        }

        transferState.phase = 'preparing';
        transferState.lastError = '';
        transferState.progressReceived = 0;
        transferState.progressTotal = Math.ceil(file.size / cryptoCodec.chunkSize);
        renderTransferState();
        const manifest = createManifest(file);
        const keys = await cryptoCodec.deriveKeys(options.password, manifest.salt, manifest.fileId);
        manifest.encryptedMetadata = await cryptoCodec.encryptMetadata(
            {
                name: file.name || 'download',
                content_type: file.type || '',
                last_modified_ms: Number.isSafeInteger(file.lastModified) ? file.lastModified : 0,
            },
            keys.contentKey,
            manifest
        );
        const session = {
            file,
            manifest,
            contentKey: keys.contentKey,
            resumeKey: keys.resumeKey,
            receivedIndexes: new Set(),
            controller: null,
            stopIntent: '',
        };
        transferState.activeSession = session;

        try {
            await createRemoteUpload(session);
            await persistProgress(session);
            transferState.phase = 'uploading';
            renderTransferState();
            await uploadPendingChunks(session);
            await completeRemoteUpload(session);
            await deleteProgress(manifest.fileId);
            if (typeof session.resumeKey?.fill === 'function') {
                session.resumeKey.fill(0);
            }
            transferState.phase = 'complete';
            transferState.activeSession = null;
            renderTransferState();
            notifications.show({
                id: 'encrypted-transfer-upload',
                tone: 'success',
                message: core.t('encryptedUploadComplete'),
                timeoutMs: 5000,
            });
            return { id: manifest.fileId, status: 'complete' };
        } catch (error) {
            if (session.stopIntent === 'pause') {
                transferState.phase = 'paused';
                renderTransferState();
                return { id: manifest.fileId, status: 'paused' };
            }
            if (session.stopIntent === 'cancel') {
                return { id: manifest.fileId, status: 'canceled' };
            }
            transferState.phase = 'error';
            transferState.lastError = String(error?.message || error || '');
            renderTransferState();
            notifications.show({
                id: 'encrypted-transfer-upload',
                tone: 'error',
                message: core.t('encryptedUploadFailed'),
                timeoutMs: null,
            });
            throw error;
        }
    }

    async function pauseUpload() {
        const session = transferState.activeSession;
        if (!session || !['preparing', 'uploading'].includes(transferState.phase)) {
            return false;
        }
        session.stopIntent = 'pause';
        transferState.phase = 'pausing';
        session.controller?.abort();
        renderTransferState();
        return { id: session.manifest.fileId, status: 'paused' };
    }

    function bytesEqual(leftValue, rightValue) {
        const left = leftValue instanceof Uint8Array ? leftValue : new Uint8Array(leftValue);
        const right = rightValue instanceof Uint8Array ? rightValue : new Uint8Array(rightValue);
        let difference = left.byteLength ^ right.byteLength;
        const length = Math.max(left.byteLength, right.byteLength);
        for (let index = 0; index < length; index += 1) {
            difference |= (left[index % (left.byteLength || 1)] || 0)
                ^ (right[index % (right.byteLength || 1)] || 0);
        }
        return difference === 0;
    }

    function manifestFromRecord(record, expectedStatus = 'partial') {
        if (
            !record
            || typeof record !== 'object'
            || Array.isArray(record)
            || !/^[0-9a-f]{32}$/.test(String(record.id || ''))
            || record.version !== 1
            || !Number.isSafeInteger(record.plaintext_size)
            || record.plaintext_size < 0
            || record.chunk_size !== cryptoCodec.chunkSize
            || record.chunk_count !== Math.ceil(record.plaintext_size / record.chunk_size)
            || record.status !== expectedStatus
            || !Array.isArray(record.received_chunks)
        ) {
            throw new TypeError('Encrypted upload record is invalid');
        }
        const salt = cryptoCodec.decodeBase64Url(record.salt, 'salt');
        const noncePrefix = cryptoCodec.decodeBase64Url(record.nonce_prefix, 'nonce_prefix');
        const encryptedMetadata = cryptoCodec.decodeBase64Url(
            record.encrypted_metadata,
            'encrypted_metadata'
        );
        if (
            salt.byteLength !== 16
            || noncePrefix.byteLength !== 8
            || encryptedMetadata.byteLength < 16
            || encryptedMetadata.byteLength > 4112
        ) {
            throw new TypeError('Encrypted upload record is invalid');
        }
        const received = new Map();
        record.received_chunks.forEach(chunk => {
            if (
                !chunk
                || typeof chunk !== 'object'
                || !Number.isInteger(chunk.index)
                || chunk.index < 0
                || chunk.index >= record.chunk_count
                || received.has(chunk.index)
            ) {
                throw new TypeError('Encrypted upload record is invalid');
            }
            const resumeMac = cryptoCodec.decodeBase64Url(chunk.resume_mac, 'resume_mac');
            if (resumeMac.byteLength !== 32) {
                throw new TypeError('Encrypted upload record is invalid');
            }
            received.set(chunk.index, resumeMac);
        });
        return {
            manifest: {
                version: 1,
                fileId: record.id,
                plaintextSize: record.plaintext_size,
                chunkSize: record.chunk_size,
                chunkCount: record.chunk_count,
                salt,
                noncePrefix,
                encryptedMetadata,
            },
            received,
        };
    }

    function clearUnlockedFiles() {
        transferState.unlockedFiles.forEach(entry => entry.contentKey?.fill?.(0));
        transferState.unlockedFiles.clear();
    }

    async function refreshEncryptedLists() {
        if (!transferState.enabled) {
            return { partialUploads: [], encryptedFiles: [] };
        }
        const [uploadPayload, filePayload] = await Promise.all([
            requestJson('/_xferry/encrypted-uploads'),
            requestJson('/_xferry/encrypted-files'),
        ]);
        if (
            !Array.isArray(uploadPayload?.encrypted_uploads)
            || !Array.isArray(filePayload?.encrypted_files)
        ) {
            throw new Error('Encrypted file list response is invalid');
        }
        uploadPayload.encrypted_uploads.forEach(record => manifestFromRecord(record, 'partial'));
        filePayload.encrypted_files.forEach(record => manifestFromRecord(record, 'complete'));
        clearUnlockedFiles();
        transferState.partialUploads = [...uploadPayload.encrypted_uploads];
        transferState.encryptedFiles = [...filePayload.encrypted_files];
        renderTransferState();
        return {
            partialUploads: [...transferState.partialUploads],
            encryptedFiles: [...transferState.encryptedFiles],
        };
    }

    async function unlockEncryptedFile(options = {}) {
        const fileId = String(options.id || '');
        const record = transferState.encryptedFiles.find(item => item.id === fileId);
        if (!record) {
            throw new Error('Encrypted file was not found');
        }
        const { manifest } = manifestFromRecord(record, 'complete');
        const keys = await cryptoCodec.deriveKeys(options.password, manifest.salt, manifest.fileId);
        keys.resumeKey?.fill?.(0);
        const metadata = await cryptoCodec.decryptMetadata(
            manifest.encryptedMetadata,
            keys.contentKey,
            manifest
        );
        if (!metadata) {
            keys.contentKey?.fill?.(0);
            throw new Error('Password did not unlock this encrypted file');
        }
        const previous = transferState.unlockedFiles.get(fileId);
        previous?.contentKey?.fill?.(0);
        transferState.unlockedFiles.set(fileId, {
            record,
            manifest,
            metadata,
            contentKey: keys.contentKey,
        });
        renderTransferState();
        return { ...metadata };
    }

    function safeSuggestedName(value) {
        return String(value || 'download')
            .replace(/[\x00-\x1f\x7f/\\]/g, '-')
            .trim() || 'download';
    }

    async function selectWritableFile(entry, providedHandle) {
        const handle = providedHandle || (
            typeof window.showSaveFilePicker === 'function'
                ? await window.showSaveFilePicker({
                    suggestedName: safeSuggestedName(entry.metadata.name),
                })
                : null
        );
        if (!handle || typeof handle.createWritable !== 'function') {
            throw new Error('File System Access API is required for streaming download');
        }
        return handle;
    }

    async function readExactStreamBytes(reader, streamState, byteLength) {
        const output = new Uint8Array(byteLength);
        let offset = 0;
        while (offset < byteLength) {
            if (streamState.pending.byteLength > 0) {
                const take = Math.min(byteLength - offset, streamState.pending.byteLength);
                output.set(streamState.pending.subarray(0, take), offset);
                offset += take;
                streamState.pending = streamState.pending.slice(take);
                continue;
            }
            const { value, done } = await reader.read();
            if (done) {
                throw new Error('Encrypted download ended before all chunks arrived');
            }
            streamState.pending = value instanceof Uint8Array
                ? value
                : new Uint8Array(value);
        }
        return output;
    }

    async function requireStreamEnd(reader, streamState) {
        if (streamState.pending.byteLength > 0) {
            throw new Error('Encrypted download contains trailing bytes');
        }
        const { value, done } = await reader.read();
        if (!done || (value && value.byteLength > 0)) {
            throw new Error('Encrypted download contains trailing bytes');
        }
    }

    async function abortWritable(writable, error) {
        if (typeof writable?.abort === 'function') {
            try {
                await writable.abort(error);
            } catch (abortError) {
                // Preserve the integrity or network error that caused the abort.
            }
        }
    }

    async function downloadClientSide(options = {}) {
        const fileId = String(options.id || '');
        const entry = transferState.unlockedFiles.get(fileId);
        if (!entry) {
            throw new Error('Unlock the encrypted file before downloading it');
        }
        if (!transferState.capability?.browser_decryption) {
            throw new Error('Browser decryption is not available');
        }
        const handle = await selectWritableFile(entry, options.fileHandle);
        const response = await fetch(
            `${core.serverUrl}/_xferry/encrypted-files/${fileId}/data`,
            { credentials: 'same-origin', cache: 'no-store' }
        );
        if (!response.ok || !response.body || typeof response.body.getReader !== 'function') {
            throw new Error(`Encrypted download failed (HTTP ${response.status || 0})`);
        }
        const writable = await handle.createWritable();
        const reader = response.body.getReader();
        const streamState = { pending: new Uint8Array(0) };
        transferState.phase = 'downloading';
        transferState.lastError = '';
        renderTransferState();
        try {
            for (let index = 0; index < entry.manifest.chunkCount; index += 1) {
                const plaintextLength = Math.min(
                    entry.manifest.chunkSize,
                    entry.manifest.plaintextSize - index * entry.manifest.chunkSize
                );
                const ciphertext = await readExactStreamBytes(
                    reader,
                    streamState,
                    plaintextLength + 16
                );
                const plaintext = await cryptoCodec.decryptChunk(
                    ciphertext,
                    entry.contentKey,
                    entry.manifest,
                    index
                );
                ciphertext.fill(0);
                if (!plaintext) {
                    throw new Error(`Encrypted download integrity check failed at chunk ${index}`);
                }
                await writable.write(plaintext);
                plaintext.fill?.(0);
            }
            await requireStreamEnd(reader, streamState);
            await writable.close();
            transferState.phase = 'complete';
            renderTransferState();
            return { id: fileId, status: 'downloaded' };
        } catch (error) {
            transferState.phase = 'error';
            transferState.lastError = String(error?.message || error || '');
            renderTransferState();
            try {
                await reader.cancel(error);
            } catch (cancelError) {
                // The writable abort below is the user-visible cleanup boundary.
            }
            await abortWritable(writable, error);
            throw error;
        }
    }

    async function streamResponseToWritable(response, writable) {
        const reader = response.body.getReader();
        try {
            while (true) {
                const { value, done } = await reader.read();
                if (done) {
                    break;
                }
                if (value?.byteLength) {
                    await writable.write(value);
                }
            }
            await writable.close();
        } catch (error) {
            try {
                await reader.cancel(error);
            } catch (cancelError) {
                // Preserve the network or filesystem error that interrupted the stream.
            }
            await abortWritable(writable, error);
            throw error;
        }
    }

    async function downloadServerSide(options = {}) {
        const fileId = String(options.id || '');
        const entry = transferState.unlockedFiles.get(fileId);
        if (!entry) {
            throw new Error('Unlock the encrypted file before downloading it');
        }
        if (!transferState.capability?.server_decryption) {
            throw new Error('Server-side decryption is not available for this connection');
        }
        const confirmed = await dialogs.confirm({
            title: core.t('encryptedServerDecryptConfirmTitle'),
            message: core.t('encryptedServerDecryptConfirmMessage'),
            confirmLabel: core.t('encryptedServerDecryptConfirmAction'),
            confirmClassName: 'btn-danger',
            triggerEl: options.triggerEl || null,
        });
        if (!confirmed) {
            return false;
        }

        const handle = await selectWritableFile(entry, options.fileHandle);
        const writable = await handle.createWritable();
        transferState.phase = 'downloading';
        transferState.lastError = '';
        renderTransferState();
        let streamStarted = false;
        try {
            const response = await fetch(
                `${core.serverUrl}/_xferry/encrypted-files/${fileId}/decrypt`,
                {
                    method: 'POST',
                    credentials: 'same-origin',
                    cache: 'no-store',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        content_key: cryptoCodec.encodeBase64Url(entry.contentKey),
                    }),
                }
            );
            if (!response.ok || !response.body || typeof response.body.getReader !== 'function') {
                throw new Error(`Server-side decrypt failed (HTTP ${response.status || 0})`);
            }
            streamStarted = true;
            await streamResponseToWritable(response, writable);
            transferState.phase = 'complete';
            renderTransferState();
            return { id: fileId, status: 'downloaded' };
        } catch (error) {
            if (!streamStarted) {
                await abortWritable(writable, error);
            }
            transferState.phase = 'error';
            transferState.lastError = String(error?.message || error || '');
            renderTransferState();
            throw error;
        }
    }

    function snapshotPartialUploads() {
        return transferState.partialUploads.map(record => ({
            id: record.id,
            plaintextSize: record.plaintext_size,
            chunkCount: record.chunk_count,
            receivedCount: record.received_chunks.length,
        }));
    }

    function snapshotEncryptedFiles() {
        return transferState.encryptedFiles.map(record => {
            const unlocked = transferState.unlockedFiles.get(record.id);
            return {
                id: record.id,
                plaintextSize: record.plaintext_size,
                chunkCount: record.chunk_count,
                unlocked: Boolean(unlocked),
                name: unlocked?.metadata?.name || '',
                contentType: unlocked?.metadata?.content_type || '',
                lastModifiedMs: unlocked?.metadata?.last_modified_ms ?? null,
            };
        });
    }

    async function resumeRemoteUpload(options) {
        if (!transferState.enabled || !transferState.capability) {
            throw new Error('Encrypted uploads are not available');
        }
        const file = options?.file;
        const { manifest, received } = manifestFromRecord(options?.record);
        if (!file || file.size !== manifest.plaintextSize) {
            throw new Error('Selected file does not match encrypted upload');
        }
        transferState.phase = 'preparing';
        transferState.lastError = '';
        transferState.progressReceived = received.size;
        transferState.progressTotal = manifest.chunkCount;
        renderTransferState();
        const keys = await cryptoCodec.deriveKeys(options.password, manifest.salt, manifest.fileId);
        try {
            const encryptedMetadata = await cryptoCodec.encryptMetadata(
                {
                    name: file.name || 'download',
                    content_type: file.type || '',
                    last_modified_ms: Number.isSafeInteger(file.lastModified)
                        ? file.lastModified
                        : 0,
                },
                keys.contentKey,
                manifest
            );
            if (!bytesEqual(encryptedMetadata, manifest.encryptedMetadata)) {
                throw new Error('Selected file does not match encrypted upload');
            }

            for (const [index, expectedMac] of received) {
                const start = index * manifest.chunkSize;
                const end = Math.min(file.size, start + manifest.chunkSize);
                const plaintext = new Uint8Array(await file.slice(start, end).arrayBuffer());
                const actualMac = await cryptoCodec.computeResumeMac(
                    plaintext,
                    keys.resumeKey,
                    manifest,
                    index
                );
                plaintext.fill(0);
                if (!bytesEqual(actualMac, expectedMac)) {
                    throw new Error('Selected file does not match encrypted upload');
                }
            }
        } catch (error) {
            keys.contentKey?.fill?.(0);
            keys.resumeKey?.fill?.(0);
            transferState.phase = 'idle';
            transferState.lastError = String(error?.message || error || '');
            renderTransferState();
            throw error;
        }

        const session = {
            file,
            manifest,
            contentKey: keys.contentKey,
            resumeKey: keys.resumeKey,
            receivedIndexes: new Set(received.keys()),
            controller: null,
            stopIntent: '',
        };
        transferState.activeSession = session;
        try {
            await createRemoteUpload(session);
            await persistProgress(session);
            transferState.phase = 'uploading';
            renderTransferState();
            await uploadPendingChunks(session);
            await completeRemoteUpload(session);
            await deleteProgress(session.manifest.fileId);
            session.resumeKey?.fill?.(0);
            transferState.phase = 'complete';
            transferState.activeSession = null;
            renderTransferState();
            return { id: session.manifest.fileId, status: 'complete' };
        } catch (error) {
            if (session.stopIntent === 'pause') {
                transferState.phase = 'paused';
                renderTransferState();
                return { id: session.manifest.fileId, status: 'paused' };
            }
            if (session.stopIntent === 'cancel') {
                return { id: session.manifest.fileId, status: 'canceled' };
            }
            transferState.phase = 'error';
            transferState.lastError = String(error?.message || error || '');
            renderTransferState();
            throw error;
        }
    }

    async function resumeUpload(options = null) {
        if (options?.record) {
            return resumeRemoteUpload(options);
        }
        const session = transferState.activeSession;
        if (!session || !['paused', 'pausing'].includes(transferState.phase)) {
            throw new Error('There is no paused encrypted upload');
        }
        session.stopIntent = '';
        transferState.phase = 'uploading';
        transferState.lastError = '';
        renderTransferState();
        try {
            await uploadPendingChunks(session);
            await completeRemoteUpload(session);
            await deleteProgress(session.manifest.fileId);
            if (typeof session.resumeKey?.fill === 'function') {
                session.resumeKey.fill(0);
            }
            transferState.phase = 'complete';
            transferState.activeSession = null;
            renderTransferState();
            return { id: session.manifest.fileId, status: 'complete' };
        } catch (error) {
            if (session.stopIntent === 'pause') {
                transferState.phase = 'paused';
                renderTransferState();
                return { id: session.manifest.fileId, status: 'paused' };
            }
            if (session.stopIntent === 'cancel') {
                return { id: session.manifest.fileId, status: 'canceled' };
            }
            transferState.phase = 'error';
            transferState.lastError = String(error?.message || error || '');
            renderTransferState();
            throw error;
        }
    }

    async function cancelUpload() {
        const session = transferState.activeSession;
        if (!session) {
            return false;
        }
        const fileId = session.manifest.fileId;
        session.stopIntent = 'cancel';
        transferState.phase = 'canceling';
        session.controller?.abort();
        renderTransferState();
        await requestJson(`/_xferry/encrypted-uploads/${fileId}`, { method: 'DELETE' });
        await deleteProgress(fileId);
        if (typeof session.contentKey?.fill === 'function') {
            session.contentKey.fill(0);
        }
        if (typeof session.resumeKey?.fill === 'function') {
            session.resumeKey.fill(0);
        }
        if (transferState.activeSession === session) {
            transferState.activeSession = null;
        }
        transferState.phase = 'canceled';
        transferState.progressReceived = 0;
        transferState.progressTotal = 0;
        renderTransferState();
        return { id: fileId, status: 'canceled' };
    }

    async function cancelRemoteUpload(options = {}) {
        const fileId = String(options.id || '');
        if (!/^[0-9a-f]{32}$/.test(fileId)) {
            throw new TypeError('Encrypted upload id is invalid');
        }
        if (transferState.activeSession?.manifest.fileId === fileId) {
            return cancelUpload();
        }
        if (!transferState.partialUploads.some(record => record.id === fileId)) {
            throw new Error('Encrypted upload was not found');
        }
        await requestJson(`/_xferry/encrypted-uploads/${fileId}`, { method: 'DELETE' });
        await deleteProgress(fileId);
        transferState.partialUploads = transferState.partialUploads.filter(
            record => record.id !== fileId
        );
        if (transferState.selectedResumeId === fileId) {
            transferState.selectedResumeId = '';
        }
        transferState.phase = 'canceled';
        renderTransferState();
        return { id: fileId, status: 'canceled' };
    }

    function reportUiError(error) {
        transferState.phase = 'error';
        transferState.lastError = String(error?.message || error || core.t('encryptedActionFailed'));
        renderTransferState();
        notifications.show({
            id: 'encrypted-transfer-action',
            tone: 'error',
            message: `${core.t('encryptedActionFailed')}: ${transferState.lastError}`,
            timeoutMs: null,
        });
    }

    async function refreshFromUi() {
        transferState.lastError = '';
        try {
            await refreshEncryptedLists();
        } catch (error) {
            reportUiError(error);
        }
    }

    function hideResumeForm() {
        transferState.selectedResumeId = '';
        if (resumeFileInput) resumeFileInput.value = '';
        if (resumePasswordInput) resumePasswordInput.value = '';
        renderTransferState();
    }

    function hideUnlockForm() {
        transferState.selectedUnlockId = '';
        if (unlockPasswordInput) unlockPasswordInput.value = '';
        renderTransferState();
    }

    if (uploadForm) {
        uploadForm.addEventListener('submit', event => {
            event.preventDefault();
            const file = fileInput?.files?.[0] || null;
            const password = passwordInput?.value ?? '';
            if (password !== (passwordConfirmInput?.value ?? '')) {
                reportUiError(new Error(core.t('encryptedPasswordMismatch')));
                passwordConfirmInput?.focus();
                return;
            }
            void (async () => {
                try {
                    await startUpload({ file, password });
                    if (fileInput) fileInput.value = '';
                    if (passwordInput) passwordInput.value = '';
                    if (passwordConfirmInput) passwordConfirmInput.value = '';
                    await refreshEncryptedLists();
                } catch (error) {
                    reportUiError(error);
                }
            })();
        });
    }

    pauseButton?.addEventListener('click', () => {
        void pauseUpload().catch(reportUiError);
    });
    resumeButton?.addEventListener('click', () => {
        void resumeUpload().then(refreshEncryptedLists).catch(reportUiError);
    });
    cancelButton?.addEventListener('click', () => {
        void (async () => {
            const confirmed = await dialogs.confirm({
                title: core.t('encryptedCancelConfirmTitle'),
                message: core.t('encryptedCancelConfirmMessage'),
                confirmLabel: core.t('encryptedUploadCancel'),
                confirmClassName: 'btn-danger',
                triggerEl: cancelButton,
            });
            if (confirmed) {
                await cancelUpload();
                await refreshEncryptedLists();
            }
        })().catch(reportUiError);
    });
    refreshButton?.addEventListener('click', () => {
        void refreshFromUi();
    });

    partialList?.addEventListener('click', event => {
        const button = event.target.closest('[data-encrypted-action][data-encrypted-id]');
        if (!button) return;
        const fileId = button.dataset.encryptedId || '';
        if (button.dataset.encryptedAction === 'resume-remote') {
            transferState.selectedResumeId = fileId;
            transferState.selectedUnlockId = '';
            renderTransferState();
            resumeFileInput?.focus();
            return;
        }
        if (button.dataset.encryptedAction === 'cancel-remote') {
            void (async () => {
                const confirmed = await dialogs.confirm({
                    title: core.t('encryptedCancelConfirmTitle'),
                    message: core.t('encryptedCancelConfirmMessage'),
                    confirmLabel: core.t('encryptedCancelRemote'),
                    confirmClassName: 'btn-danger',
                    triggerEl: button,
                });
                if (confirmed) {
                    await cancelRemoteUpload({ id: fileId });
                }
            })().catch(reportUiError);
        }
    });

    resumeForm?.addEventListener('submit', event => {
        event.preventDefault();
        const record = transferState.partialUploads.find(
            item => item.id === transferState.selectedResumeId
        );
        const file = resumeFileInput?.files?.[0] || null;
        const password = resumePasswordInput?.value ?? '';
        void resumeUpload({ record, file, password })
            .then(async () => {
                hideResumeForm();
                await refreshEncryptedLists();
            })
            .catch(reportUiError);
    });
    resumeDismissButton?.addEventListener('click', hideResumeForm);

    encryptedFileList?.addEventListener('click', event => {
        const button = event.target.closest('[data-encrypted-action][data-encrypted-id]');
        if (!button) return;
        const fileId = button.dataset.encryptedId || '';
        const action = button.dataset.encryptedAction;
        if (action === 'unlock') {
            transferState.selectedUnlockId = fileId;
            transferState.selectedResumeId = '';
            renderTransferState();
            unlockPasswordInput?.focus();
        } else if (action === 'download-client') {
            void downloadClientSide({ id: fileId, triggerEl: button }).catch(reportUiError);
        } else if (action === 'download-server') {
            void downloadServerSide({ id: fileId, triggerEl: button }).catch(reportUiError);
        }
    });

    unlockForm?.addEventListener('submit', event => {
        event.preventDefault();
        const fileId = transferState.selectedUnlockId;
        const password = unlockPasswordInput?.value ?? '';
        void unlockEncryptedFile({ id: fileId, password })
            .then(() => {
                hideUnlockForm();
            })
            .catch(reportUiError);
    });
    unlockDismissButton?.addEventListener('click', hideUnlockForm);

    syncCapability();
    app.on(app.events.SERVER_METHODS_CHANGED, syncCapability);
    app.on(app.events.LOCALE_CHANGED, renderTransferState);
    renderTransferState();

    app.registerWorkflow('encrypted-transfer', {
        commands: {
            start: startUpload,
            pause: pauseUpload,
            resume: resumeUpload,
            cancel: cancelUpload,
            'cancel-remote': cancelRemoteUpload,
            refresh: refreshEncryptedLists,
            unlock: unlockEncryptedFile,
            'download-client': downloadClientSide,
            'download-server': downloadServerSide,
        },
        getState: () => ({
            enabled: transferState.enabled,
            capabilityStatus: transferState.capabilityStatus,
            phase: transferState.phase,
            activeId: transferState.activeSession?.manifest.fileId || null,
            progressReceived: transferState.progressReceived,
            progressTotal: transferState.progressTotal,
            partialUploads: snapshotPartialUploads(),
            encryptedFiles: snapshotEncryptedFiles(),
        }),
    });
})(window.XferryApp);
