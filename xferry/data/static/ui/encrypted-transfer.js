(function initializeEncryptedTransfer(app) {
    'use strict';

    const cryptoCodec = app.service('encrypted-transfer-crypto');
    const core = app.service('core');
    const notifications = app.service('notifications');
    const dialogs = app.service('dialogs');
    const persistence = app.service('encrypted-transfer-persistence');
    const network = app.service('encrypted-transfer-network');
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
    const queueList = document.getElementById('encryptedQueueList');
    const cacheList = document.getElementById('encryptedCacheList');
    const cacheClearButton = document.getElementById('encryptedCacheClearBtn');
    const dropZone = document.getElementById('encryptedFileDropZone');
    const rows = { queue: new Map(), cache: new Map() };
    let partialRenderKey = '';
    let filesRenderKey = '';
    let queueRun = null;
    const deletionTasks = new Map();
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
        direction: 'upload',
        bytesDone: 0,
        bytesTotal: 0,
        startedAt: 0,
        pendingDeletes: new Set(),
        cacheFiles: [],
        cacheBytes: 0,
        queue: [],
        queuePreparing: false,
        storage: null,
    };

    function hasExactKeys(value, expectedKeys) {
        return Object.keys(value).sort().join(',') === [...expectedKeys].sort().join(',');
    }

    function validateCapability(rawCapability) {
        if (
            rawCapability &&
            typeof rawCapability === 'object' &&
            !Array.isArray(rawCapability) &&
            hasExactKeys(rawCapability, ['enabled']) &&
            rawCapability.enabled === false
        ) {
            return { status: 'disabled', capability: null };
        }
        if (
            !rawCapability ||
            typeof rawCapability !== 'object' ||
            Array.isArray(rawCapability) ||
            !hasExactKeys(rawCapability, capabilityKeys) ||
            rawCapability.enabled !== true ||
            rawCapability.version !== 1 ||
            !Number.isSafeInteger(rawCapability.max_plaintext_size) ||
            rawCapability.max_plaintext_size < 0 ||
            rawCapability.chunk_size !== cryptoCodec.chunkSize ||
            rawCapability.parallel_chunks !== 2 ||
            typeof rawCapability.browser_decryption !== 'boolean' ||
            typeof rawCapability.server_decryption !== 'boolean'
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
        const extraStatuses = {
            downloading: 'encryptedStatusDownloading',
            verifying: 'encryptedStatusVerifying',
            'waiting-network': 'encryptedStatusWaitingNetwork',
            saving: 'encryptedStatusSaving',
            finalizing: 'encryptedStatusFinalizing',
            'pending-delete': 'encryptedStatusPendingDelete',
            canceling: 'encryptedStatusDeleting',
        };
        if (extraStatuses[transferState.phase]) return core.t(extraStatuses[transferState.phase]);
        if (transferState.phase === 'uploading') {
            return core
                .t('encryptedStatusUploading')
                .replace('{0}', String(transferState.progressReceived))
                .replace('{1}', String(transferState.progressTotal));
        }
        if (transferState.phase === 'paused' || transferState.phase === 'pausing') {
            return core.t(
                transferState.direction === 'download'
                    ? 'encryptedStatusPausedDownload'
                    : 'encryptedStatusPaused',
            );
        }
        if (transferState.phase === 'complete') {
            return core.t(
                transferState.direction === 'download'
                    ? 'encryptedStatusDownloadComplete'
                    : 'encryptedStatusComplete',
            );
        }
        if (transferState.phase === 'canceled' || transferState.phase === 'canceling') {
            return core.t(
                transferState.direction === 'download'
                    ? 'encryptedStatusCanceledDownload'
                    : 'encryptedStatusCanceled',
            );
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
        button.disabled = Boolean(transferState.activeSession);
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
        const key = JSON.stringify([
            transferState.partialUploads,
            [...transferState.pendingDeletes],
            Boolean(transferState.activeSession),
            core.t('encryptedResumeAction'),
        ]);
        if (key === partialRenderKey) return;
        partialRenderKey = key;
        partialList.replaceChildren();
        if (transferState.partialUploads.length === 0) {
            partialList.appendChild(createEmptyListItem('encryptedNoPartialUploads'));
            return;
        }
        transferState.partialUploads.forEach((record) => {
            const item = document.createElement('article');
            item.className = 'encrypted-transfer__item';
            item.setAttribute('role', 'listitem');

            const id = document.createElement('p');
            id.className = 'encrypted-transfer__item-name';
            id.textContent = `${record.id.slice(0, 8)}…${record.id.slice(-4)}`;
            const meta = document.createElement('p');
            meta.className = 'encrypted-transfer__item-meta';
            meta.textContent = `${core.formatSize(record.plaintext_size)} · ${record.received_chunks.length}/${record.chunk_count}`;
            if (transferState.pendingDeletes.has(record.id))
                meta.textContent += ` · ${core.t('encryptedStatusPendingDelete')}`;
            const actions = document.createElement('div');
            actions.className = 'encrypted-transfer__item-actions';
            if (!transferState.pendingDeletes.has(record.id)) {
                actions.append(
                    createActionButton(
                        'encryptedResumeAction',
                        'resume-remote',
                        record.id,
                        'btn-info btn--sm',
                    ),
                    createActionButton(
                        'encryptedCancelRemote',
                        'cancel-remote',
                        record.id,
                        'btn-danger btn--sm',
                    ),
                    createActionButton('encryptedNewSession', 'new-session', record.id),
                );
            }
            item.append(id, meta, actions, createFileDetails(record));
            partialList.appendChild(item);
        });
    }

    function renderEncryptedFiles() {
        if (!encryptedFileList) {
            return;
        }
        const key = JSON.stringify([
            snapshotEncryptedFiles(),
            Boolean(transferState.activeSession),
            core.t('encryptedClientDownload'),
            transferState.capability?.server_decryption,
        ]);
        if (key === filesRenderKey) return;
        filesRenderKey = key;
        encryptedFileList.replaceChildren();
        if (transferState.encryptedFiles.length === 0) {
            encryptedFileList.appendChild(createEmptyListItem('encryptedNoFiles'));
            return;
        }
        transferState.encryptedFiles.forEach((record) => {
            const unlocked = transferState.unlockedFiles.get(record.id);
            const item = document.createElement('article');
            item.className = 'encrypted-transfer__item';
            item.setAttribute('role', 'listitem');

            const name = document.createElement('p');
            name.className = 'encrypted-transfer__item-name';
            name.textContent = unlocked?.metadata?.name || core.t('encryptedFileLocked');
            const meta = document.createElement('p');
            meta.className = 'encrypted-transfer__item-meta';
            meta.textContent = core.formatSize(record.plaintext_size);
            const actions = document.createElement('div');
            actions.className = 'encrypted-transfer__item-actions';
            if (!unlocked) {
                actions.appendChild(
                    createActionButton('encryptedUnlock', 'unlock', record.id, 'btn-info btn--sm'),
                );
            } else {
                actions.appendChild(
                    createActionButton(
                        'encryptedClientDownload',
                        'download-client',
                        record.id,
                        'btn-download btn--sm',
                    ),
                );
                if (transferState.capability?.server_decryption) {
                    const advanced = document.createElement('details');
                    advanced.className = 'encrypted-transfer__item-details';
                    const summary = document.createElement('summary');
                    summary.textContent = core.t('encryptedAdvancedActions');
                    advanced.append(
                        summary,
                        createActionButton(
                            'encryptedServerDownload',
                            'download-server',
                            record.id,
                            'btn-ghost btn--sm',
                        ),
                    );
                    actions.appendChild(advanced);
                }
            }
            item.append(name, meta, actions, createFileDetails(record));
            encryptedFileList.appendChild(item);
        });
    }

    function createFileDetails(record) {
        const details = document.createElement('details');
        details.className = 'encrypted-transfer__item-details';
        const summary = document.createElement('summary');
        summary.textContent = core.t('encryptedFileDetails');
        const id = document.createElement('p');
        id.className = 'encrypted-transfer__item-id';
        id.textContent = record.id;
        details.append(summary, id, createActionButton('encryptedCopyId', 'copy-id', record.id));
        if (Number.isFinite(record.created_at)) {
            const created = document.createElement('p');
            created.className = 'encrypted-transfer__item-meta';
            created.textContent = `${core.t('encryptedCreatedAt')}: ${new Date(record.created_at * 1000).toLocaleString(core.getState().lang || undefined)}`;
            details.appendChild(created);
        }
        return details;
    }

    async function copyFileId(fileId) {
        if (core.writeTextToClipboard) await core.writeTextToClipboard(fileId);
        else await navigator.clipboard.writeText(fileId);
        notifications.show({
            id: 'encrypted-copy-id',
            tone: 'success',
            message: core.t('encryptedIdCopied'),
            timeoutMs: 3000,
        });
    }

    function renderTransferState() {
        const phase = transferState.phase;
        const busy = Boolean(transferState.activeSession) && !['paused', 'error'].includes(phase);
        if (panel) {
            panel.setAttribute('aria-busy', String(busy));
            if (panel.dataset) {
                panel.dataset.transferPhase = phase;
            }
        }
        if (startButton) {
            startButton.disabled =
                busy || Boolean(transferState.activeSession) || !transferState.enabled;
        }
        const limit = transferState.storage?.max_plaintext_size ??
            transferState.capability?.max_plaintext_size;
        const fileHint = document.getElementById('encryptedFileHint');
        if (fileHint && limit != null) fileHint.textContent = core.t('encryptedFileLimitHint')
            .replace('{0}', core.formatSize(limit));
        const capacityHint = document.getElementById('encryptedCapacityHint');
        if (capacityHint) {
            capacityHint.hidden = !transferState.storage;
            if (transferState.storage) capacityHint.textContent = core.t('encryptedCapacitySummary')
                .replace('{0}', core.formatSize(transferState.storage.available_bytes))
                .replace('{1}', transferState.storage.remaining_files == null ? '-' :
                    String(transferState.storage.remaining_files));
        }
        const selected = Array.from(fileInput?.files || []);
        const selectionError = selected.length ? selectedCapacityError(selected) : '';
        const selectionHint = document.getElementById('encryptedSelectionHint');
        if (selectionHint) {
            selectionHint.hidden = !selectionError;
            selectionHint.textContent = selectionError;
        }
        if (selectionError && startButton) startButton.disabled = true;
        if (pauseButton) {
            pauseButton.disabled =
                transferState.queuePreparing ||
                ![
                    'uploading',
                    'preparing',
                    'verifying',
                    'downloading',
                    'saving',
                    'waiting-network',
                ].includes(phase) ||
                transferState.activeSession?.kind === 'server-download';
            pauseButton.hidden =
                !transferState.activeSession || ['paused', 'error'].includes(phase);
        }
        if (resumeButton) {
            resumeButton.disabled =
                !['paused', 'error'].includes(phase) || !transferState.activeSession;
            resumeButton.hidden =
                !transferState.activeSession || !['paused', 'error'].includes(phase);
        }
        if (cancelButton) {
            cancelButton.disabled = !transferState.activeSession;
            cancelButton.hidden = !transferState.activeSession;
        }
        if (refreshButton) {
            refreshButton.disabled = Boolean(transferState.activeSession) || !transferState.enabled;
        }
        if (progressElement) {
            const total = transferState.bytesTotal;
            const value =
                total > 0
                    ? Math.min(100, Math.floor((transferState.bytesDone / total) * 100))
                    : phase === 'complete'
                      ? 100
                      : 0;
            progressElement.value = value;
            progressElement.textContent = `${value}%`;
        }
        const percent = document.getElementById('encryptedProgressPercent');
        if (percent) percent.textContent = `${progressElement?.value || 0}%`;
        const bytes = document.getElementById('encryptedProgressBytes');
        if (bytes)
            bytes.textContent = `${core.formatSize(transferState.bytesDone)} / ${core.formatSize(transferState.bytesTotal)}`;
        const seconds = Math.max(0.001, (Date.now() - transferState.startedAt) / 1000);
        const speed = transferState.startedAt && busy ? transferState.bytesDone / seconds : 0;
        const speedOutput = document.getElementById('encryptedProgressSpeed');
        if (speedOutput) speedOutput.textContent = speed ? `${core.formatSize(speed)}/s` : '-';
        const etaOutput = document.getElementById('encryptedProgressEta');
        if (etaOutput)
            etaOutput.textContent = speed
                ? formatDuration((transferState.bytesTotal - transferState.bytesDone) / speed)
                : '-';
        const support = document.getElementById('encryptedBrowserSupport');
        if (support) {
            support.hidden = browserSupported();
            support.textContent = browserSupported() ? '' : core.t('encryptedBrowserUnsupported');
            if (startButton && !browserSupported()) startButton.disabled = true;
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
        const retentionHint = document.getElementById('encryptedRetentionHint');
        if (retentionHint && transferState.incompleteTtlSeconds != null) {
            retentionHint.hidden = false;
            retentionHint.textContent = core
                .t('encryptedRetentionPolicy')
                .replace('{0}', String(transferState.incompleteTtlSeconds / 86400));
        }
        renderPartialUploads();
        renderEncryptedFiles();
        renderQueue();
        renderCache();
    }

    function applyStorageSnapshot(raw) {
        // Older servers omit this additive field; their atomic admission still
        // applies. If a new server supplies it, malformed limits fail closed.
        if (raw === undefined) { transferState.storage = null; return; }
        const required = ['used_bytes', 'disk_free_bytes', 'reserved_free_bytes',
            'available_bytes', 'file_count', 'max_plaintext_size',
            'configured_max_plaintext_size', 'technical_max_plaintext_size'];
        const optional = ['quota_bytes', 'file_limit', 'remaining_files'];
        if (!raw || typeof raw !== 'object' || Array.isArray(raw) ||
            required.some(key => !Number.isSafeInteger(raw[key]) || raw[key] < 0) ||
            optional.some(key => raw[key] !== null &&
                (!Number.isSafeInteger(raw[key]) || raw[key] < 0)) ||
            raw.max_plaintext_size > raw.configured_max_plaintext_size ||
            raw.configured_max_plaintext_size > raw.technical_max_plaintext_size) {
            throw new Error('Encrypted storage capacity response is invalid');
        }
        transferState.storage = { ...raw };
    }

    function selectedCapacityError(files) {
        const storage = transferState.storage;
        if (storage?.remaining_files != null && files.length > storage.remaining_files)
            return core.t('encryptedQuotaFilesExceeded');
        const maximum = storage?.max_plaintext_size ?? transferState.capability?.max_plaintext_size;
        if (files.some(file => file.size > maximum)) return core.t('encryptedQuotaFileTooLarge')
            .replace('{0}', core.formatSize(maximum));
        const ciphertextSize = files.reduce((sum, file) =>
            sum + file.size + Math.ceil(file.size / cryptoCodec.chunkSize) * 16, 0);
        if (!Number.isSafeInteger(ciphertextSize) ||
            (storage && ciphertextSize > storage.available_bytes))
            return core.t('encryptedQuotaBytesExceeded');
        return '';
    }

    function transferErrorMessage(error) {
        if (error?.code === 'storage_quota_exceeded') {
            const key = {bytes:'encryptedQuotaBytesExceeded', files:'encryptedQuotaFilesExceeded',
                free_space:'encryptedQuotaFreeSpaceExceeded'}[error?.details?.reason];
            if (key) return core.t(key);
        }
        return String(error?.message || error || core.t('encryptedActionFailed'));
    }

    function browserSupported() {
        return (
            persistence.available() &&
            Boolean(
                globalThis.navigator?.locks?.request &&
                    globalThis.navigator?.storage?.getDirectory &&
                    window.showSaveFilePicker &&
                    globalThis.crypto?.subtle,
            )
        );
    }

    function formatDuration(seconds) {
        const value = Math.max(0, Math.ceil(seconds));
        const hours = Math.floor(value / 3600);
        const minutes = Math.floor((value % 3600) / 60);
        return `${hours ? `${hours}:` : ''}${String(minutes).padStart(2, '0')}:${String(value % 60).padStart(2, '0')}`;
    }

    function renderRows(list, map, records, emptyKey, update) {
        if (!list) return;
        const ids = records.map((record) => record.id);
        const oldIds = [...map.keys()];
        const changed = ids.join(',') !== oldIds.join(',');
        for (const id of oldIds) if (!ids.includes(id)) map.delete(id);
        const elements = records.map((record) => {
            if (!map.has(record.id)) {
                const item = document.createElement('article');
                item.className = 'encrypted-transfer__item';
                item.setAttribute('role', 'listitem');
                const header = document.createElement('div');
                header.className = 'encrypted-transfer__item-header';
                const title = document.createElement('p');
                title.className = 'encrypted-transfer__item-name';
                const status = document.createElement('span');
                status.className = 'encrypted-transfer__item-status';
                const meta = document.createElement('p');
                meta.className = 'encrypted-transfer__item-meta';
                const progress = document.createElement('progress');
                progress.className = 'encrypted-transfer__item-progress';
                progress.max = 100;
                const actions = document.createElement('div');
                actions.className = 'encrypted-transfer__item-actions';
                header.append(title, status);
                item.append(header, meta, progress, actions);
                map.set(record.id, { item, title, status, meta, progress, actions });
            }
            const row = map.get(record.id);
            update(row, record);
            return row.item;
        });
        if (changed || !records.length)
            list.replaceChildren(...(elements.length ? elements : [createEmptyListItem(emptyKey)]));
    }

    function renderQueue() {
        renderRows(
            queueList,
            rows.queue,
            transferState.queue,
            'encryptedQueueEmpty',
            (row, record) => {
                row.title.textContent = record.name;
                const states = {
                    queued: 'encryptedQueueWaiting',
                    preparing: 'encryptedStatusPreparing',
                    uploading: 'encryptedQueueUploading',
                    paused: 'encryptedStatusPaused',
                    complete: 'encryptedStatusComplete',
                    error: 'encryptedStatusError',
                    canceled: 'encryptedStatusCanceled',
                };
                row.status.textContent = core
                    .t(states[record.status] || 'encryptedQueueWaiting')
                    .replace('{0}', '')
                    .replace('{1}', '');
                row.meta.textContent = `${core.formatSize(record.bytesDone || 0)} / ${core.formatSize(record.size)}`;
                row.progress.value = record.size
                    ? Math.min(100, Math.floor(((record.bytesDone || 0) / record.size) * 100))
                    : record.status === 'complete'
                      ? 100
                      : 0;
                row.progress.setAttribute('aria-label', record.name);
                if (!row.remove) {
                    row.remove = createActionButton(
                        'encryptedUploadCancel',
                        'queue-remove',
                        record.id,
                        'btn-ghost btn--sm',
                    );
                    row.actions.appendChild(row.remove);
                }
                row.remove.hidden = !['queued', 'preparing'].includes(record.status);
                row.remove.disabled = transferState.queuePreparing;
                row.remove.textContent = core.t('encryptedUploadCancel');
            },
        );
    }

    function syncCapability() {
        const wasEnabled = transferState.enabled;
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
        if (!wasEnabled && transferState.enabled && refreshButton) {
            void refreshFromUi();
        }
    }

    function encodeFileId(bytes) {
        return Array.from(bytes, (value) => value.toString(16).padStart(2, '0')).join('');
    }

    function persistProgress(session, status = 'uploading') {
        // Serialize readwrite transactions across both chunk workers. A failed
        // transaction is fatal: encryption must never outrun the nonce journal.
        session.journalWrite = (session.journalWrite || Promise.resolve()).then(() =>
            persistence.saveUpload({
                id: session.manifest.fileId,
                schemaVersion: 2,
                manifest: createManifestPayload(session.manifest),
                attemptedMacs: { ...session.attemptedMacs },
                receivedIndexes: [...session.receivedIndexes].sort((a, b) => a - b),
                status,
                updatedAt: Date.now(),
            }),
        );
        return session.journalWrite;
    }

    const deleteProgress = (fileId) => persistence.removeUpload(fileId);

    function networkContext(session, extra = {}) {
        return {
            signal: session?.controller?.signal,
            onWait() {
                if (!session?.stopIntent && session === transferState.activeSession) {
                    transferState.phase = 'waiting-network';
                    renderTransferState();
                }
            },
            ...extra,
        };
    }

    async function requestJson(path, options = {}, session = null) {
        // 4096 records with maximum private metadata fit within 32 MiB. Keep
        // the stricter default for individual records and error responses.
        const list = path === '/_xferry/encrypted-uploads' || path === '/_xferry/encrypted-files';
        return network.requestJson(`${core.serverUrl}${path}`, options, networkContext(session,
            list ? { jsonLimitBytes: 32 * 1024 * 1024 } : {}));
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
            },
            session,
        );
        if (result?.encrypted_upload?.id !== session.manifest.fileId) {
            throw new Error('Encrypted upload create response is invalid');
        }
    }

    async function uploadChunk(session, index, signal) {
        const start = index * session.manifest.chunkSize;
        const end = Math.min(session.file.size, start + session.manifest.chunkSize);
        const plaintext = new Uint8Array(await session.file.slice(start, end).arrayBuffer());
        let ciphertext;
        let encodedMac;
        try {
            if (plaintext.byteLength !== end - start)
                throw new Error('Selected file could not be read completely');
            const resumeMac = await cryptoCodec.computeResumeMac(
                plaintext,
                session.resumeKey,
                session.manifest,
                index,
            );
            encodedMac = cryptoCodec.encodeBase64Url(resumeMac);
            if (session.attemptedMacs[index] && session.attemptedMacs[index] !== encodedMac) {
                throw new Error(
                    'Selected file does not match encrypted upload; start a new session',
                );
            }
            session.attemptedMacs[index] = encodedMac;
            await persistProgress(session);
            signal.throwIfAborted();
            ciphertext = await cryptoCodec.encryptChunk(
                plaintext,
                session.contentKey,
                session.manifest,
                index,
            );
        } finally {
            plaintext.fill(0);
        }
        signal.throwIfAborted();
        const result = await network.uploadChunk(
            `${core.serverUrl}/_xferry/encrypted-uploads/${session.manifest.fileId}/chunks/${index}`,
            {
                method: 'PUT',
                headers: {
                    'Content-Type': 'application/octet-stream',
                    'X-XFerry-Chunk-MAC': encodedMac,
                },
                body: ciphertext,
                signal,
            },
            networkContext(session, {
                onProgress({ loaded }) {
                    session.inFlight.set(index, Math.min(end - start, loaded));
                    updateUploadProgress(session);
                },
            }),
        );
        if (result?.encrypted_chunk?.index !== index) {
            throw new Error('Encrypted chunk response is invalid');
        }
        session.receivedIndexes.add(index);
        session.inFlight.delete(index);
        updateUploadProgress(session);
        await persistProgress(session);
    }

    async function uploadPendingChunks(session) {
        const queue = Array.from(
            { length: session.manifest.chunkCount },
            (_value, index) => index,
        ).filter((index) => !session.receivedIndexes.has(index));
        let queueOffset = 0;

        async function worker() {
            while (queueOffset < queue.length && !session.controller.signal.aborted) {
                const index = queue[queueOffset];
                queueOffset += 1;
                try {
                    await uploadChunk(session, index, session.controller.signal);
                } catch (error) {
                    session.controller.abort();
                    throw error;
                }
            }
        }

        const workerCount = Math.min(2, queue.length);
        const results = await Promise.allSettled(
            Array.from({ length: workerCount }, () => worker()),
        );
        const failure =
            results.find(
                (result) => result.status === 'rejected' && result.reason?.name !== 'AbortError',
            ) || results.find((result) => result.status === 'rejected');
        if (failure) throw failure.reason;
        session.controller.signal.throwIfAborted();
    }

    async function completeRemoteUpload(session) {
        const payload = await requestJson(
            `/_xferry/encrypted-uploads/${session.manifest.fileId}/complete`,
            { method: 'POST' },
            session,
        );
        if (payload?.encrypted_file?.status !== 'complete') {
            throw new Error('Encrypted upload completion response is invalid');
        }
    }

    function requireNoActiveUpload() {
        if (transferState.activeSession) {
            throw new Error('An encrypted upload is already active');
        }
    }

    function updateUploadProgress(session) {
        transferState.progressReceived = session.receivedIndexes.size;
        transferState.bytesDone =
            [...session.receivedIndexes].reduce(
                (sum, index) =>
                    sum +
                    Math.min(
                        session.manifest.chunkSize,
                        session.manifest.plaintextSize - index * session.manifest.chunkSize,
                    ),
                0,
            ) + [...session.inFlight.values()].reduce((sum, value) => sum + value, 0);
        if (!session.stopIntent) transferState.phase = 'uploading';
        if (session.queueEntry) {
            session.queueEntry.bytesDone = transferState.bytesDone;
            session.queueEntry.status = 'uploading';
        }
        renderTransferState();
    }

    function releaseSessionKeys(session) {
        session.contentKey?.fill?.(0);
        session.resumeKey?.fill?.(0);
        session.file = null;
    }

    function newSession(file, manifest) {
        return {
            file,
            manifest,
            receivedIndexes: new Set(),
            attemptedMacs: {},
            inFlight: new Map(),
            controller: new AbortController(),
            stopIntent: '',
            kind: 'upload',
        };
    }

    function beginProgress(session, direction = 'upload') {
        transferState.activeSession = session;
        transferState.direction = direction;
        transferState.phase = 'preparing';
        transferState.lastError = '';
        transferState.progressReceived = 0;
        transferState.progressTotal = session.manifest.chunkCount;
        transferState.bytesDone = 0;
        transferState.bytesTotal = session.manifest.plaintextSize;
        transferState.startedAt = Date.now();
        renderTransferState();
    }

    async function runUpload(session, prepare) {
        session.run = persistence.withLock(session.manifest.fileId, async () => {
            let prepared = !prepare;
            try {
                if (prepare) await prepare();
                prepared = true;
                session.controller.signal.throwIfAborted();
                await persistProgress(session);
                if (!session.remoteExists) {
                    await createRemoteUpload(session);
                    session.remoteExists = true;
                }
                updateUploadProgress(session);
                if (!session.remoteCompleted) {
                    await uploadPendingChunks(session);
                    transferState.phase = 'finalizing';
                    renderTransferState();
                    await completeRemoteUpload(session);
                }
                await deleteProgress(session.manifest.fileId);
                releaseSessionKeys(session);
                if (session.queueEntry) {
                    session.queueEntry.status = 'complete';
                    session.queueEntry.bytesDone = session.queueEntry.size;
                    session.queueEntry.file = null;
                }
                transferState.phase = 'complete';
                transferState.activeSession = null;
                renderTransferState();
                return { id: session.manifest.fileId, status: 'complete' };
            } catch (error) {
                session.controller.abort();
                session.inFlight.clear();
                session.journalWrite = null;
                if (session.stopIntent) {
                    transferState.phase = session.stopIntent === 'pause' ? 'paused' : 'canceling';
                    if (session.manifest.encryptedMetadata)
                        await persistProgress(
                            session,
                            session.stopIntent === 'cancel' ? 'pending-delete' : 'paused',
                        );
                    if (session.queueEntry)
                        session.queueEntry.status =
                            session.stopIntent === 'pause' ? 'paused' : 'canceled';
                    renderTransferState();
                    return {
                        id: session.manifest.fileId,
                        status: session.stopIntent === 'pause' ? 'paused' : 'canceled',
                    };
                }
                transferState.phase = 'error';
                transferState.lastError = transferErrorMessage(error);
                if (session.queueEntry) session.queueEntry.status = 'error';
                if (!prepared) {
                    releaseSessionKeys(session);
                    transferState.activeSession = null;
                }
                renderTransferState();
                throw error;
            }
        });
        // withLock can reject before invoking the body (another tab/unsupported).
        try {
            return await session.run;
        } catch (error) {
            if (error?.code === 'busy' || error?.code === 'unsupported') {
                releaseSessionKeys(session);
                transferState.activeSession = null;
                transferState.phase = 'error';
                transferState.lastError = error.message;
                renderTransferState();
            }
            throw error;
        }
    }

    async function startUpload(options = {}) {
        if (!transferState.enabled || !transferState.capability) {
            throw new Error('Encrypted uploads are not available');
        }
        requireNoActiveUpload();
        const file = options.file;
        if (!file || !Number.isSafeInteger(file.size) || file.size < 0) {
            throw new TypeError('A browser File is required');
        }
        if (file.size > transferState.capability.max_plaintext_size) {
            throw new RangeError('File exceeds the encrypted upload size limit');
        }

        const manifest = createManifest(file);
        const session = newSession(file, manifest);
        // Claim the workflow synchronously, before PBKDF2 or any storage await.
        beginProgress(session);
        return runUpload(session, async () => {
            const keys =
                options.keys ||
                (await cryptoCodec.deriveKeys(options.password, manifest.salt, manifest.fileId));
            session.contentKey = keys.contentKey;
            session.resumeKey = keys.resumeKey;
            session.controller.signal.throwIfAborted();
            manifest.encryptedMetadata = await cryptoCodec.encryptMetadata(
                {
                    name: file.name || 'download',
                    content_type: file.type || '',
                    last_modified_ms: Number.isSafeInteger(file.lastModified)
                        ? file.lastModified
                        : 0,
                },
                keys.contentKey,
                manifest,
            );
        });
    }

    async function enqueueUploads({ files, password } = {}) {
        if (!transferState.enabled || !transferState.capability)
            throw new Error('Encrypted uploads are not available');
        requireNoActiveUpload();
        if (queueRun || transferState.queuePreparing)
            throw new Error('An encrypted queue is already active');
        const selected = Array.from(files || []);
        if (!selected.length) throw new Error('Select at least one file');
        selected.forEach((file) => {
            if (
                !Number.isSafeInteger(file.size) ||
                file.size < 0
            ) {
                throw new RangeError('File exceeds the encrypted upload size limit');
            }
        });
        transferState.queue = selected.map((file) => {
            const manifest = createManifest(file);
            return {
                id: manifest.fileId,
                name: file.name || 'download',
                size: file.size,
                file,
                manifest,
                status: 'queued',
                bytesDone: 0,
            };
        });
        const preparation = newSession(selected[0], transferState.queue[0].manifest);
        preparation.kind = 'queue-preparing';
        transferState.queuePreparing = true;
        beginProgress(preparation);
        // Retain derived keys, never password strings, in the queued records.
        // No plaintext/ciphertext chunk buffers are prepared ahead of a file.
        preparation.run = (async () => {
            try {
                const payload = await requestJson('/_xferry/encrypted-uploads', {
                    signal: preparation.controller.signal,
                });
                preparation.controller.signal.throwIfAborted();
                applyStorageSnapshot(payload?.storage);
                renderTransferState();
                const admissionError = selectedCapacityError(selected);
                if (admissionError) throw new RangeError(admissionError);
                for (const entry of transferState.queue) {
                    preparation.controller.signal.throwIfAborted();
                    entry.status = 'preparing';
                    renderQueue();
                    entry.keys = await cryptoCodec.deriveKeys(
                        password,
                        entry.manifest.salt,
                        entry.id,
                    );
                    entry.status = 'queued';
                    renderQueue();
                }
                preparation.controller.signal.throwIfAborted();
            } catch (error) {
                for (const entry of transferState.queue) {
                    entry.keys?.contentKey.fill?.(0);
                    entry.keys?.resumeKey.fill?.(0);
                    entry.file = null;
                    entry.status = 'canceled';
                }
                if (!preparation.stopIntent) throw error;
            } finally {
                password = null;
                transferState.queuePreparing = false;
            }
        })();
        try {
            await preparation.run;
        } catch (error) {
            transferState.activeSession = null;
            reportUiError(error);
            throw error;
        }
        if (preparation.stopIntent) {
            transferState.activeSession = null;
            transferState.phase = 'canceled';
            renderTransferState();
            return { status: 'canceled' };
        }
        transferState.activeSession = null;
        return driveQueue();
    }

    function driveQueue() {
        if (queueRun) return queueRun;
        queueRun = (async () => {
            for (const entry of transferState.queue) {
                if (entry.status !== 'queued') continue;
                const session = newSession(entry.file, entry.manifest);
                session.queueEntry = entry;
                beginProgress(session);
                const result = await runUpload(session, async () => {
                    session.contentKey = entry.keys.contentKey;
                    session.resumeKey = entry.keys.resumeKey;
                    session.manifest.encryptedMetadata = await cryptoCodec.encryptMetadata(
                        {
                            name: entry.file.name || 'download',
                            content_type: entry.file.type || '',
                            last_modified_ms: Number.isSafeInteger(entry.file.lastModified)
                                ? entry.file.lastModified
                                : 0,
                        },
                        session.contentKey,
                        session.manifest,
                    );
                });
                if (result.status !== 'complete') return result;
            }
            return { status: 'complete' };
        })().finally(() => {
            queueRun = null;
        });
        return queueRun;
    }

    async function pauseUpload() {
        const session = transferState.activeSession;
        if (session?.kind === 'server-download' || session?.kind === 'queue-preparing')
            return false;
        if (
            !session ||
            ![
                'preparing',
                'uploading',
                'verifying',
                'downloading',
                'saving',
                'finalizing',
                'waiting-network',
            ].includes(transferState.phase)
        ) {
            return false;
        }
        session.stopIntent = 'pause';
        transferState.phase = 'pausing';
        session.controller?.abort();
        renderTransferState();
        await session.run;
        return { id: session.manifest.fileId, status: 'paused' };
    }

    function manifestFromRecord(record, expectedStatus = 'partial') {
        if (
            !record ||
            typeof record !== 'object' ||
            Array.isArray(record) ||
            !/^[0-9a-f]{32}$/.test(String(record.id || '')) ||
            record.version !== 1 ||
            !Number.isSafeInteger(record.plaintext_size) ||
            record.plaintext_size < 0 ||
            record.chunk_size !== cryptoCodec.chunkSize ||
            record.chunk_count !== Math.ceil(record.plaintext_size / record.chunk_size) ||
            record.status !== expectedStatus ||
            !Array.isArray(record.received_chunks)
        ) {
            throw new TypeError('Encrypted upload record is invalid');
        }
        const salt = cryptoCodec.decodeBase64Url(record.salt, 'salt');
        const noncePrefix = cryptoCodec.decodeBase64Url(record.nonce_prefix, 'nonce_prefix');
        const encryptedMetadata = cryptoCodec.decodeBase64Url(
            record.encrypted_metadata,
            'encrypted_metadata',
        );
        if (
            salt.byteLength !== 16 ||
            noncePrefix.byteLength !== 8 ||
            encryptedMetadata.byteLength < 16 ||
            encryptedMetadata.byteLength > 4112
        ) {
            throw new TypeError('Encrypted upload record is invalid');
        }
        const received = new Map();
        record.received_chunks.forEach((chunk) => {
            if (
                !chunk ||
                typeof chunk !== 'object' ||
                !Number.isInteger(chunk.index) ||
                chunk.index < 0 ||
                chunk.index >= record.chunk_count ||
                received.has(chunk.index)
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
        transferState.unlockedFiles.forEach((entry) => entry.contentKey?.fill?.(0));
        transferState.unlockedFiles.clear();
    }

    async function refreshEncryptedLists() {
        if (transferState.activeSession)
            throw new Error('Wait for the active transfer before refreshing files');
        if (!transferState.enabled) {
            return { partialUploads: [], encryptedFiles: [] };
        }
        const [uploadPayload, filePayload] = await Promise.all([
            requestJson('/_xferry/encrypted-uploads'),
            requestJson('/_xferry/encrypted-files'),
        ]);
        if (transferState.activeSession)
            return {
                partialUploads: [...transferState.partialUploads],
                encryptedFiles: [...transferState.encryptedFiles],
            };
        if (
            !Array.isArray(uploadPayload?.encrypted_uploads) ||
            !Array.isArray(filePayload?.encrypted_files)
        ) {
            throw new Error('Encrypted file list response is invalid');
        }
        uploadPayload.encrypted_uploads.forEach((record) => manifestFromRecord(record, 'partial'));
        filePayload.encrypted_files.forEach((record) => manifestFromRecord(record, 'complete'));
        applyStorageSnapshot(uploadPayload.storage);
        clearUnlockedFiles();
        transferState.partialUploads = [...uploadPayload.encrypted_uploads];
        transferState.encryptedFiles = [...filePayload.encrypted_files];
        if (Number.isSafeInteger(uploadPayload.incomplete_ttl_seconds)) {
            transferState.incompleteTtlSeconds = uploadPayload.incomplete_ttl_seconds;
        }
        renderTransferState();
        return {
            partialUploads: [...transferState.partialUploads],
            encryptedFiles: [...transferState.encryptedFiles],
        };
    }

    async function unlockEncryptedFile(options = {}) {
        if (transferState.activeSession)
            throw new Error('Wait for the active transfer before unlocking another file');
        const fileId = String(options.id || '');
        const record = transferState.encryptedFiles.find((item) => item.id === fileId);
        if (!record) {
            throw new Error('Encrypted file was not found');
        }
        const { manifest } = manifestFromRecord(record, 'complete');
        const keys = await cryptoCodec.deriveKeys(options.password, manifest.salt, manifest.fileId);
        keys.resumeKey?.fill?.(0);
        const metadata = await cryptoCodec.decryptMetadata(
            manifest.encryptedMetadata,
            keys.contentKey,
            manifest,
        );
        if (!metadata) {
            keys.contentKey?.fill?.(0);
            throw new Error('Password did not unlock this encrypted file');
        }
        if (transferState.activeSession) {
            keys.contentKey?.fill?.(0);
            throw new Error('Wait for the active transfer before unlocking another file');
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
        return (
            String(value || 'download')
                .replace(/[\x00-\x1f\x7f/\\]/g, '-')
                .trim() || 'download'
        );
    }

    async function selectWritableFile(entry, providedHandle) {
        const handle =
            providedHandle ||
            (typeof window.showSaveFilePicker === 'function'
                ? await window.showSaveFilePicker({
                      suggestedName: safeSuggestedName(entry.metadata.name),
                  })
                : null);
        if (!handle || typeof handle.createWritable !== 'function') {
            throw new Error('File System Access API is required for streaming download');
        }
        return handle;
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
        requireNoActiveUpload();
        const fileId = String(options.id || '');
        const entry = transferState.unlockedFiles.get(fileId);
        if (!entry) {
            throw new Error('Unlock the encrypted file before downloading it');
        }
        if (!transferState.capability?.browser_decryption) {
            throw new Error('Browser decryption is not available');
        }
        const session = {
            kind: 'download',
            manifest: entry.manifest,
            controller: new AbortController(),
            stopIntent: '',
        };
        beginProgress(session, 'download');
        session.run = persistence.withLock(fileId, async () => {
            let writable;
            try {
                const handle = await selectWritableFile(entry, options.fileHandle);
                await persistence.prepareDownload({
                    id: fileId,
                    manifest: createManifestPayload(entry.manifest),
                    status: 'downloading',
                    updatedAt: Date.now(),
                });
                session.controller.signal.throwIfAborted();
                writable = await handle.createWritable();
                for (let index = 0; index < entry.manifest.chunkCount; index += 1) {
                    session.controller.signal.throwIfAborted();
                    const length = Math.min(
                        entry.manifest.chunkSize,
                        entry.manifest.plaintextSize - index * entry.manifest.chunkSize,
                    );
                    let ciphertext = await persistence.readCachedChunk(fileId, index);
                    let plaintext;
                    try {
                        if (ciphertext) {
                            plaintext = await cryptoCodec.decryptChunk(
                                ciphertext,
                                entry.contentKey,
                                entry.manifest,
                                index,
                            );
                            if (!plaintext) {
                                ciphertext.fill(0);
                                ciphertext = null;
                                await persistence.removeCachedChunk(fileId, index);
                            }
                        }
                        if (!plaintext) {
                            transferState.phase = 'downloading';
                            renderTransferState();
                            ciphertext = await network.readChunk(
                                `${core.serverUrl}/_xferry/encrypted-files/${fileId}/chunks/${index}`,
                                length + 16,
                                networkContext(session, {
                                    onProgress({ loaded }) {
                                        transferState.phase = 'downloading';
                                        transferState.bytesDone = Math.min(
                                            entry.manifest.plaintextSize,
                                            index * entry.manifest.chunkSize +
                                                Math.min(length, loaded),
                                        );
                                        renderTransferState();
                                    },
                                }),
                            );
                            plaintext = await cryptoCodec.decryptChunk(
                                ciphertext,
                                entry.contentKey,
                                entry.manifest,
                                index,
                            );
                            if (!plaintext)
                                throw new Error(
                                    `Encrypted download integrity check failed at chunk ${index}`,
                                );
                            session.controller.signal.throwIfAborted();
                            await persistence.writeCachedChunk(fileId, index, ciphertext);
                        }
                        session.controller.signal.throwIfAborted();
                        transferState.phase = 'saving';
                        renderTransferState();
                        await writable.write(plaintext);
                        transferState.progressReceived = index + 1;
                        transferState.bytesDone = Math.min(
                            entry.manifest.plaintextSize,
                            (index + 1) * entry.manifest.chunkSize,
                        );
                        renderTransferState();
                    } finally {
                        ciphertext?.fill?.(0);
                        plaintext?.fill?.(0);
                    }
                }
                session.controller.signal.throwIfAborted();
                transferState.phase = 'finalizing';
                renderTransferState();
                await writable.close();
                writable = null;
                try {
                    await persistence.removeDownload(fileId);
                } catch (error) {
                    notifications.show({
                        id: 'encrypted-cache-cleanup',
                        tone: 'error',
                        message: core.t('encryptedCacheCleanupFailed'),
                        timeoutMs: null,
                    });
                }
                entry.contentKey.fill?.(0);
                transferState.unlockedFiles.delete(fileId);
                transferState.activeSession = null;
                transferState.phase = 'complete';
                await refreshCache();
                renderTransferState();
                return { id: fileId, status: 'downloaded' };
            } catch (error) {
                await abortWritable(writable, error);
                const saved = await persistence.getDownload(fileId);
                if (saved)
                    await persistence.saveDownload({
                        ...saved,
                        status: session.stopIntent === 'pause' ? 'paused' : 'error',
                        updatedAt: Date.now(),
                    });
                transferState.phase =
                    session.stopIntent === 'pause'
                        ? 'paused'
                        : session.stopIntent === 'cancel'
                          ? 'canceling'
                          : 'error';
                transferState.lastError = session.stopIntent
                    ? ''
                    : String(error?.message || error || '');
                await refreshCache();
                renderTransferState();
                if (session.stopIntent)
                    return {
                        id: fileId,
                        status: session.stopIntent === 'pause' ? 'paused' : 'canceled',
                    };
                throw error;
            }
        });
        try {
            return await session.run;
        } catch (error) {
            transferState.phase = 'error';
            transferState.lastError = error.message;
            transferState.activeSession = null;
            renderTransferState();
            throw error;
        }
    }

    async function refreshCache() {
        const stats = await persistence.cacheStats();
        transferState.cacheBytes = stats.bytes;
        transferState.cacheFiles = stats.files;
        renderCache();
        return stats;
    }

    function renderCache() {
        const output = document.getElementById('encryptedCacheSize');
        if (output) output.textContent = core.formatSize(transferState.cacheBytes);
        if (cacheClearButton)
            cacheClearButton.disabled =
                Boolean(transferState.activeSession) || !transferState.cacheFiles.length;
        renderRows(
            cacheList,
            rows.cache,
            transferState.cacheFiles,
            'encryptedCacheEmpty',
            (row, record) => {
                row.title.textContent = `${record.id.slice(0, 8)}…${record.id.slice(-4)}`;
                row.status.textContent = core.t('encryptedStatusPaused');
                row.meta.textContent = core.formatSize(record.bytes);
                row.progress.hidden = true;
                if (!row.resume) {
                    row.resume = createActionButton(
                        'encryptedCacheResume',
                        'resume-cache',
                        record.id,
                        'btn-info btn--sm',
                    );
                    row.remove = createActionButton(
                        'encryptedCacheRemove',
                        'remove-cache',
                        record.id,
                        'btn-ghost btn--sm',
                    );
                    row.actions.append(row.resume, row.remove);
                }
                row.resume.textContent = core.t('encryptedCacheResume');
                row.remove.textContent = core.t('encryptedCacheRemove');
                row.resume.disabled = row.remove.disabled = Boolean(transferState.activeSession);
            },
        );
    }

    async function clearDownloadCache(options = {}) {
        if (transferState.activeSession)
            throw new Error('Pause the transfer before clearing its cache');
        const files = options.id
            ? [{ id: String(options.id) }]
            : (await persistence.cacheStats()).files;
        for (const file of files)
            await persistence.withLock(file.id, () => persistence.removeDownload(file.id));
        await refreshCache();
        return { cleared: files.length };
    }

    async function showCachedDownload(fileId) {
        if (transferState.activeSession) throw new Error('Wait for the active transfer');
        const cached = await persistence.getDownload(fileId);
        if (!cached) throw new Error('Cached download manifest is unavailable');
        if (!transferState.encryptedFiles.some((record) => record.id === fileId)) {
            transferState.encryptedFiles.push({
                id: fileId,
                ...cached.manifest,
                status: 'complete',
                received_chunks: [],
            });
        }
        transferState.selectedUnlockId = fileId;
        transferState.selectedResumeId = '';
        renderTransferState();
        unlockPasswordInput?.focus();
    }

    function removeQueuedFile(options = {}) {
        if (transferState.queuePreparing) throw new Error('Wait for key preparation to finish');
        const entry = transferState.queue.find((record) => record.id === String(options.id));
        if (!entry || entry.status !== 'queued')
            throw new Error('Only a waiting file can be removed from the queue');
        entry.keys?.contentKey.fill?.(0);
        entry.keys?.resumeKey.fill?.(0);
        entry.file = null;
        entry.status = 'canceled';
        renderQueue();
        return { id: entry.id, status: 'canceled' };
    }

    async function restoreLocalState() {
        if (!persistence.available()) return;
        try {
            if (globalThis.navigator?.storage?.getDirectory) {
                await persistence.cleanupDownloads({
                    activeIds: transferState.activeSession
                        ? [transferState.activeSession.manifest.fileId]
                        : [],
                });
                await refreshCache();
            }
            const records = await persistence.listUploads();
            records
                .filter((record) => record.status === 'pending-delete')
                .forEach((record) => transferState.pendingDeletes.add(record.id));
            renderTransferState();
            retryPendingDeletes();
        } catch (error) {
            const support = document.getElementById('encryptedBrowserSupport');
            if (support) {
                support.hidden = false;
                support.textContent = core.t('encryptedCacheUnavailable');
            }
        }
    }

    function retryPendingDeletes() {
        if (!transferState.enabled) return;
        for (const id of transferState.pendingDeletes)
            void deleteRemoteUpload(id).catch(reportUiError);
    }

    async function streamResponseToWritable(response, writable, session) {
        const reader = response.body.getReader();
        let rejectAbort;
        const canceled = new Promise((_, reject) => {
            rejectAbort = reject;
        });
        canceled.catch(() => {});
        const onAbort = () => rejectAbort(session.controller.signal.reason);
        session.controller.signal.addEventListener('abort', onAbort, { once: true });
        try {
            while (true) {
                session.controller.signal.throwIfAborted();
                const { value, done } = await Promise.race([reader.read(), canceled]);
                if (done) {
                    break;
                }
                if (value?.byteLength) {
                    session.resetWatchdog();
                    await writable.write(value);
                    transferState.bytesDone += value.byteLength;
                    transferState.progressReceived = Math.min(
                        session.manifest.chunkCount,
                        Math.floor(transferState.bytesDone / session.manifest.chunkSize),
                    );
                    renderTransferState();
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
        } finally {
            session.controller.signal.removeEventListener('abort', onAbort);
            reader.releaseLock?.();
        }
    }

    async function downloadServerSide(options = {}) {
        requireNoActiveUpload();
        const fileId = String(options.id || '');
        const entry = transferState.unlockedFiles.get(fileId);
        if (!entry) {
            throw new Error('Unlock the encrypted file before downloading it');
        }
        if (!transferState.capability?.server_decryption) {
            throw new Error('Server-side decryption is not available for this connection');
        }
        const session = {
            kind: 'server-download',
            manifest: entry.manifest,
            controller: new AbortController(),
            stopIntent: '',
        };
        beginProgress(session, 'download');
        session.run = persistence.withLock(fileId, async () => {
            let writable;
            let streamStarted = false;
            let watchdog;
            session.resetWatchdog = () => {
                clearTimeout(watchdog);
                watchdog = setTimeout(
                    () => session.controller.abort(new Error('Server decrypt transfer stalled')),
                    30000,
                );
                watchdog.unref?.();
            };
            try {
                const confirmed = await dialogs.confirm({
                    title: core.t('encryptedServerDecryptConfirmTitle'),
                    message: core.t('encryptedServerDecryptConfirmMessage'),
                    confirmLabel: core.t('encryptedServerDecryptConfirmAction'),
                    confirmClassName: 'btn-danger',
                    triggerEl: options.triggerEl || null,
                });
                if (!confirmed) {
                    transferState.phase = 'idle';
                    return false;
                }
                const handle = await selectWritableFile(entry, options.fileHandle);
                session.controller.signal.throwIfAborted();
                writable = await handle.createWritable();
                transferState.phase = 'downloading';
                renderTransferState();
                session.resetWatchdog();
                const response = await fetch(
                    `${core.serverUrl}/_xferry/encrypted-files/${fileId}/decrypt`,
                    {
                        method: 'POST',
                        credentials: 'same-origin',
                        cache: 'no-store',
                        signal: session.controller.signal,
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({
                            content_key: cryptoCodec.encodeBase64Url(entry.contentKey),
                        }),
                    },
                );
                if (
                    !response.ok ||
                    !response.body ||
                    typeof response.body.getReader !== 'function'
                ) {
                    throw new Error(`Server-side decrypt failed (HTTP ${response.status || 0})`);
                }
                streamStarted = true;
                await streamResponseToWritable(response, writable, session);
                entry.contentKey.fill?.(0);
                transferState.unlockedFiles.delete(fileId);
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
            } finally {
                clearTimeout(watchdog);
            }
        });
        try {
            return await session.run;
        } finally {
            transferState.activeSession = null;
            renderTransferState();
        }
    }

    function snapshotPartialUploads() {
        return transferState.partialUploads.map((record) => ({
            id: record.id,
            plaintextSize: record.plaintext_size,
            chunkCount: record.chunk_count,
            receivedCount: record.received_chunks.length,
        }));
    }

    function snapshotEncryptedFiles() {
        return transferState.encryptedFiles.map((record) => {
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
        requireNoActiveUpload();
        const file = options?.file;
        const initial = manifestFromRecord(options?.record);
        const manifest = initial.manifest;
        if (!file || file.size !== manifest.plaintextSize) {
            throw new Error('Selected file does not match encrypted upload');
        }
        const session = newSession(file, manifest);
        beginProgress(session);
        return runUpload(session, async () => {
            const journal = await persistence.getUpload(manifest.fileId);
            if (
                !journal ||
                journal.schemaVersion !== 2 ||
                !journal.attemptedMacs ||
                journal.status === 'pending-delete'
            ) {
                throw new Error(
                    'Safe resume journal is missing; start a new session with a new ID',
                );
            }
            if (!sameManifest(journal.manifest, createManifestPayload(manifest))) {
                throw new Error(
                    'Resume journal does not match encrypted upload; start a new session',
                );
            }
            session.attemptedMacs = { ...journal.attemptedMacs };
            const keys = await cryptoCodec.deriveKeys(
                options.password,
                manifest.salt,
                manifest.fileId,
            );
            session.contentKey = keys.contentKey;
            session.resumeKey = keys.resumeKey;
            const metadata = await cryptoCodec.decryptMetadata(
                manifest.encryptedMetadata,
                keys.contentKey,
                manifest,
            );
            if (
                !metadata ||
                metadata.name !== (file.name || 'download') ||
                metadata.content_type !== (file.type || '') ||
                metadata.last_modified_ms !==
                    (Number.isSafeInteger(file.lastModified) ? file.lastModified : 0)
            ) {
                throw new Error('Selected file does not match encrypted upload');
            }
            await reconcileUpload(session);
        });
    }

    function sameManifest(left, right) {
        const fields = [
            'version',
            'plaintext_size',
            'chunk_size',
            'chunk_count',
            'salt',
            'nonce_prefix',
            'encrypted_metadata',
        ];
        return Boolean(left && right) && fields.every((field) => left[field] === right[field]);
    }

    async function reconcileUpload(session) {
        // The lock protects a run, not the lifetime of a paused tab. Another
        // tab may have attempted extra chunks since this session last ran.
        const journal = await persistence.getUpload(session.manifest.fileId);
        if (!journal || journal.schemaVersion !== 2 || journal.status === 'pending-delete') {
            throw new Error('Safe resume journal is missing; start a new session');
        }
        if (!sameManifest(journal.manifest, createManifestPayload(session.manifest))) {
            throw new Error('Resume journal does not match encrypted upload');
        }
        session.attemptedMacs = { ...journal.attemptedMacs };
        let payload;
        try {
            payload = await requestJson(
                `/_xferry/encrypted-uploads/${session.manifest.fileId}`,
                {},
                session,
            );
        } catch (error) {
            if (error?.status !== 404) throw error;
            let completed;
            try {
                completed = await requestJson(
                    `/_xferry/encrypted-files/${session.manifest.fileId}`,
                    {},
                    session,
                );
            } catch (completedError) {
                if (
                    completedError?.status === 404 &&
                    !session.remoteExists &&
                    Object.keys(session.attemptedMacs).length === 0
                ) {
                    // Retry the same immutable metadata ciphertext only when
                    // no content nonce has ever been attempted.
                    return;
                }
                if (completedError?.status === 404) {
                    throw new Error('Upload expired or was removed; start a new session');
                }
                throw completedError;
            }
            const parsed = manifestFromRecord(completed?.encrypted_file, 'complete');
            if (!sameManifest(createManifestPayload(parsed.manifest), journal.manifest)) {
                throw new Error('Completed file does not match upload journal');
            }
            session.remoteCompleted = true;
            session.remoteExists = true;
            session.receivedIndexes = new Set(
                Array.from({ length: session.manifest.chunkCount }, (_, index) => index),
            );
            return;
        }
        const { manifest, received } = manifestFromRecord(payload?.encrypted_upload);
        if (
            !sameManifest(createManifestPayload(manifest), createManifestPayload(session.manifest))
        ) {
            throw new Error('Server manifest does not match resume journal');
        }
        for (const [index, mac] of received) {
            if (session.attemptedMacs[index] !== cryptoCodec.encodeBase64Url(mac)) {
                throw new Error(
                    'Server block does not match safe resume journal; start a new session',
                );
            }
        }
        transferState.phase = 'verifying';
        renderTransferState();
        for (const [rawIndex, encodedMac] of Object.entries(session.attemptedMacs)) {
            session.controller.signal.throwIfAborted();
            const index = Number(rawIndex);
            if (
                !Number.isInteger(index) ||
                index < 0 ||
                index >= manifest.chunkCount ||
                String(index) !== rawIndex ||
                cryptoCodec.decodeBase64Url(encodedMac).byteLength !== 32
            ) {
                throw new Error('Resume journal is invalid; start a new session');
            }
            const start = index * manifest.chunkSize;
            const end = Math.min(session.file.size, start + manifest.chunkSize);
            const plaintext = new Uint8Array(await session.file.slice(start, end).arrayBuffer());
            try {
                const mac = await cryptoCodec.computeResumeMac(
                    plaintext,
                    session.resumeKey,
                    manifest,
                    index,
                );
                if (
                    plaintext.byteLength !== end - start ||
                    cryptoCodec.encodeBase64Url(mac) !== encodedMac
                ) {
                    throw new Error(
                        'Selected file does not match encrypted upload; start a new session',
                    );
                }
            } finally {
                plaintext.fill(0);
            }
        }
        session.receivedIndexes = new Set(received.keys());
        session.remoteExists = true;
    }

    async function resumeUpload(options = null) {
        if (options?.record) return resumeRemoteUpload(options);
        const session = transferState.activeSession;
        if (!session || !['paused', 'error'].includes(transferState.phase)) {
            throw new Error('There is no paused encrypted upload');
        }
        if (session.kind === 'download') {
            // A new destination is selected on every replay; no file handles persist.
            transferState.activeSession = null;
            return downloadClientSide({ id: session.manifest.fileId });
        }
        if (!session.contentKey || !session.manifest.encryptedMetadata) {
            releaseSessionKeys(session);
            transferState.activeSession = null;
            throw new Error('Upload preparation did not finish; start a new session');
        }
        session.stopIntent = '';
        session.controller = new AbortController();
        session.inFlight.clear();
        transferState.lastError = '';
        const result = await runUpload(session, () => reconcileUpload(session));
        if (result.status === 'complete' && session.queueEntry) return driveQueue();
        return result;
    }

    async function cancelUpload() {
        const session = transferState.activeSession;
        if (!session) return false;
        const fileId = session.manifest.fileId;
        session.stopIntent = 'cancel';
        session.controller.abort();
        transferState.phase = 'canceling';
        renderTransferState();
        await session.run?.catch(() => {});
        if (session.kind === 'queue-preparing') return { status: 'canceled' };
        if (session.kind === 'server-download') {
            transferState.unlockedFiles.get(fileId)?.contentKey?.fill?.(0);
            transferState.unlockedFiles.delete(fileId);
            transferState.activeSession = null;
            transferState.phase = 'canceled';
            renderTransferState();
            return { id: fileId, status: 'canceled' };
        }
        if (session.kind === 'download') {
            await persistence.withLock(fileId, () => persistence.removeDownload(fileId));
            transferState.unlockedFiles.get(fileId)?.contentKey?.fill?.(0);
            transferState.unlockedFiles.delete(fileId);
            releaseSessionKeys(session);
            transferState.activeSession = null;
            transferState.phase = 'canceled';
            await refreshCache();
            renderTransferState();
            return { id: fileId, status: 'canceled' };
        }
        for (const entry of transferState.queue) {
            if (entry.status === 'queued') {
                entry.keys?.contentKey.fill?.(0);
                entry.keys?.resumeKey.fill?.(0);
                entry.file = null;
                entry.status = 'canceled';
            }
        }
        if (!session.manifest.encryptedMetadata) {
            releaseSessionKeys(session);
            transferState.activeSession = null;
            transferState.phase = 'canceled';
            renderTransferState();
            return { id: fileId, status: 'canceled' };
        }
        // A paused/error run has already released its lock. Read the latest
        // journal again; a different tab may have attempted additional nonces.
        await persistence.withLock(fileId, async () => {
            const journal = await persistence.getUpload(fileId);
            await persistence.saveUpload({
                ...(journal?.schemaVersion === 2
                    ? journal
                    : {
                          id: fileId,
                          schemaVersion: 2,
                          manifest: createManifestPayload(session.manifest),
                          attemptedMacs: { ...session.attemptedMacs },
                          receivedIndexes: [...session.receivedIndexes],
                      }),
                status: 'pending-delete',
                updatedAt: Date.now(),
            });
        });
        releaseSessionKeys(session);
        if (session.queueEntry) {
            session.queueEntry.status = 'canceled';
            session.queueEntry.file = null;
        }
        transferState.activeSession = null;
        if (!transferState.partialUploads.some((record) => record.id === fileId)) {
            transferState.partialUploads.push({
                id: fileId,
                ...createManifestPayload(session.manifest),
                status: 'partial',
                received_chunks: [...session.receivedIndexes].map((index) => ({
                    index,
                    resume_mac: session.attemptedMacs[index],
                })),
            });
        }
        return deleteRemoteUpload(fileId);
    }

    async function deleteRemoteUpload(fileId) {
        if (deletionTasks.has(fileId)) return deletionTasks.get(fileId);
        const task = performRemoteDelete(fileId).finally(() => deletionTasks.delete(fileId));
        deletionTasks.set(fileId, task);
        return task;
    }

    async function performRemoteDelete(fileId) {
        transferState.pendingDeletes.add(fileId);
        transferState.phase = 'pending-delete';
        renderTransferState();
        try {
            await persistence.withLock(fileId, () =>
                requestJson(`/_xferry/encrypted-uploads/${fileId}`, { method: 'DELETE' }),
            );
        } catch (error) {
            if (error?.status !== 404) throw error;
        }
        await deleteProgress(fileId);
        transferState.pendingDeletes.delete(fileId);
        transferState.partialUploads = transferState.partialUploads.filter(
            (record) => record.id !== fileId,
        );
        if (!transferState.activeSession) transferState.phase = 'canceled';
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
        if (!transferState.partialUploads.some((record) => record.id === fileId)) {
            throw new Error('Encrypted upload was not found');
        }
        await persistence.withLock(fileId, async () => {
            const journal = await persistence.getUpload(fileId);
            const record = transferState.partialUploads.find((item) => item.id === fileId);
            await persistence.saveUpload({
                ...(journal?.schemaVersion === 2
                    ? journal
                    : {
                          id: fileId,
                          schemaVersion: 2,
                          manifest: createManifestPayload(manifestFromRecord(record).manifest),
                          attemptedMacs: {},
                          receivedIndexes: [],
                      }),
                status: 'pending-delete',
                updatedAt: Date.now(),
            });
        });
        if (transferState.selectedResumeId === fileId) {
            transferState.selectedResumeId = '';
        }
        return deleteRemoteUpload(fileId);
    }

    function reportUiError(error) {
        if (transferState.activeSession && !['error', 'paused'].includes(transferState.phase)) {
            notifications.show({
                id: 'encrypted-transfer-action',
                tone: 'error',
                message: transferErrorMessage(error),
                timeoutMs: 5000,
            });
            return;
        }
        transferState.phase = 'error';
        transferState.lastError = transferErrorMessage(error);
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
            await refreshCache();
            retryPendingDeletes();
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
        uploadForm.addEventListener('submit', (event) => {
            event.preventDefault();
            const files = Array.from(fileInput?.files || []);
            const password = passwordInput?.value ?? '';
            if (password !== (passwordConfirmInput?.value ?? '')) {
                reportUiError(new Error(core.t('encryptedPasswordMismatch')));
                passwordConfirmInput?.focus();
                return;
            }
            if (passwordInput) passwordInput.value = '';
            if (passwordConfirmInput) passwordConfirmInput.value = '';
            void (async () => {
                try {
                    const result = await enqueueUploads({ files, password });
                    if (result.status !== 'complete') return;
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
    fileInput?.addEventListener('change', renderTransferState);

    pauseButton?.addEventListener('click', () => {
        void pauseUpload().catch(reportUiError);
    });
    resumeButton?.addEventListener('click', () => {
        void resumeUpload()
            .then((result) => {
                if (result.status === 'complete') return refreshEncryptedLists();
            })
            .catch(reportUiError);
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

    partialList?.addEventListener('click', (event) => {
        const button = event.target.closest('[data-encrypted-action][data-encrypted-id]');
        if (!button) return;
        const fileId = button.dataset.encryptedId || '';
        if (button.dataset.encryptedAction === 'copy-id') {
            void copyFileId(fileId).catch(reportUiError);
            return;
        }
        if (button.dataset.encryptedAction === 'new-session') {
            hideResumeForm();
            fileInput?.focus();
            return;
        }
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

    resumeForm?.addEventListener('submit', (event) => {
        event.preventDefault();
        const record = transferState.partialUploads.find(
            (item) => item.id === transferState.selectedResumeId,
        );
        const file = resumeFileInput?.files?.[0] || null;
        const password = resumePasswordInput?.value ?? '';
        if (resumePasswordInput) resumePasswordInput.value = '';
        void resumeUpload({ record, file, password })
            .then(async (result) => {
                hideResumeForm();
                if (result.status === 'complete') await refreshEncryptedLists();
            })
            .catch(reportUiError);
    });
    resumeDismissButton?.addEventListener('click', hideResumeForm);

    encryptedFileList?.addEventListener('click', (event) => {
        const button = event.target.closest('[data-encrypted-action][data-encrypted-id]');
        if (!button) return;
        const fileId = button.dataset.encryptedId || '';
        const action = button.dataset.encryptedAction;
        if (action === 'copy-id') {
            void copyFileId(fileId).catch(reportUiError);
        } else if (action === 'unlock') {
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

    unlockForm?.addEventListener('submit', (event) => {
        event.preventDefault();
        const fileId = transferState.selectedUnlockId;
        const password = unlockPasswordInput?.value ?? '';
        if (unlockPasswordInput) unlockPasswordInput.value = '';
        void unlockEncryptedFile({ id: fileId, password })
            .then(() => {
                hideUnlockForm();
            })
            .catch(reportUiError);
    });
    unlockDismissButton?.addEventListener('click', hideUnlockForm);

    queueList?.addEventListener('click', (event) => {
        const button = event.target.closest('[data-encrypted-action="queue-remove"]');
        if (!button) return;
        try {
            removeQueuedFile({ id: button.dataset.encryptedId });
        } catch (error) {
            reportUiError(error);
        }
    });
    cacheList?.addEventListener('click', (event) => {
        const button = event.target.closest('[data-encrypted-action][data-encrypted-id]');
        if (!button) return;
        if (button.dataset.encryptedAction === 'resume-cache') {
            void showCachedDownload(button.dataset.encryptedId).catch(reportUiError);
        } else if (button.dataset.encryptedAction === 'remove-cache') {
            void clearDownloadCache({ id: button.dataset.encryptedId }).catch(reportUiError);
        }
    });
    cacheClearButton?.addEventListener('click', () => {
        void clearDownloadCache().catch(reportUiError);
    });
    for (const name of ['dragenter', 'dragover'])
        dropZone?.addEventListener(name, (event) => {
            event.preventDefault();
            dropZone.classList.add('is-dragover');
        });
    for (const name of ['dragleave', 'drop'])
        dropZone?.addEventListener(name, (event) => {
            event.preventDefault();
            dropZone.classList.remove('is-dragover');
            if (
                name === 'drop' &&
                event.dataTransfer?.files &&
                fileInput &&
                !transferState.activeSession
            ) {
                fileInput.files = event.dataTransfer.files;
                renderTransferState();
            }
        });
    window.addEventListener?.('online', retryPendingDeletes);

    syncCapability();
    app.on(app.events.SERVER_METHODS_CHANGED, syncCapability);
    app.on(app.events.LOCALE_CHANGED, renderTransferState);
    renderTransferState();

    app.registerWorkflow('encrypted-transfer', {
        commands: {
            start: startUpload,
            enqueue: enqueueUploads,
            'queue-remove': removeQueuedFile,
            pause: pauseUpload,
            resume: resumeUpload,
            cancel: cancelUpload,
            'cancel-remote': cancelRemoteUpload,
            refresh: refreshEncryptedLists,
            unlock: unlockEncryptedFile,
            'download-client': downloadClientSide,
            'download-server': downloadServerSide,
            'clear-download-cache': clearDownloadCache,
            'show-cached-download': showCachedDownload,
        },
        getState: () => ({
            enabled: transferState.enabled,
            capabilityStatus: transferState.capabilityStatus,
            phase: transferState.phase,
            activeId: transferState.activeSession?.manifest.fileId || null,
            progressReceived: transferState.progressReceived,
            progressTotal: transferState.progressTotal,
            direction: transferState.direction,
            bytesDone: transferState.bytesDone,
            bytesTotal: transferState.bytesTotal,
            pendingDeletes: [...transferState.pendingDeletes],
            cacheBytes: transferState.cacheBytes,
            cacheFiles: transferState.cacheFiles.map((record) => ({ ...record })),
            queue: transferState.queue.map((entry) => ({
                id: entry.id,
                name: entry.name,
                size: entry.size,
                status: entry.status,
                bytesDone: entry.bytesDone,
            })),
            incompleteTtlSeconds: transferState.incompleteTtlSeconds ?? null,
            storage: transferState.storage ? { ...transferState.storage } : null,
            lastError: transferState.lastError,
            partialUploads: snapshotPartialUploads(),
            encryptedFiles: snapshotEncryptedFiles(),
        }),
    });
    void restoreLocalState();
})(window.XferryApp);
