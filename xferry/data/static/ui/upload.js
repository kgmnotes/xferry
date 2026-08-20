(function initializeUpload(app) {
    'use strict';

const {
    t,
    escapeHtml: esc,
    formatSize,
    serverUrl: SERVER_URL,
    announceLiveRegion,
    bindDropZoneKeyboardTrigger,
    isServerMethodInGroup,
    focusElementWithoutScroll,
    switchWorkspace: switchTab,
} = app.service('core');
const {
    binaryTextPreviewLimit: exchangeBinaryTextPreviewLimit,
    buildRawMessage: buildExchangeRawMessage,
    buildRawMessageForExport: buildExchangeRawMessageForExport,
    createBinaryBody: createExchangeBinaryBody,
    createHttpResponseMessage: createExchangeHttpResponseMessage,
    createPreviewBody: createExchangePreviewBody,
    createTextBody: createExchangeTextBody,
    setInspector: setExchangeInspector,
    setSummaryActions: setToolSummaryActions,
    withNoGzipHeader: withUiNoGzipHeader,
} = app.service('inspector');
const dialogs = app.service('dialogs');
const httpErrors = app.service('http-errors');

function sendCustomRequest(...args) {
    return app.service('http').request(...args);
}

// ===== Загрузка файлов =====
const uploadState = {
    method: 'POST',
    profile: 'multipart',
    previewSequence: 0,
    files: [],
    renderFileListRAF: null,
    actionPhase: 'idle',
    routing: {
        phase: 'ready',
        snapshot: null,
        error: '',
        blockedReason: '',
        sendBlockedReason: '',
        compareBlockedReason: '',
    },
    compareResults: [],
};
let activeBasicUploadErrorFile = null;
const basicUploadProfiles = Object.freeze(['multipart', 'raw-url', 'raw-header']);
const uploadBodyPreviewReadLimit = (typeof exchangeBinaryTextPreviewLimit === 'number'
    ? exchangeBinaryTextPreviewLimit
    : 512) + 1;
const uploadMethodButtons = Array.from(document.querySelectorAll('.upload-method-btn[data-upload-method]'));
const uploadProfileButtons = Array.from(document.querySelectorAll('.upload-profile-btn[data-upload-profile]'));

function getUploadByteView(bodyBytes) {
    if (!bodyBytes) {
        return null;
    }
    if (bodyBytes instanceof Uint8Array) {
        return bodyBytes;
    }
    if (bodyBytes instanceof ArrayBuffer) {
        return new Uint8Array(bodyBytes);
    }
    if (ArrayBuffer.isView(bodyBytes)) {
        return new Uint8Array(bodyBytes.buffer, bodyBytes.byteOffset, bodyBytes.byteLength);
    }
    throw new TypeError('Basic upload body bytes must be an ArrayBuffer or typed array');
}

function compileBasicUploadRequest(state, file, bodyBytes = null) {
    const profile = basicUploadProfiles.includes(state?.profile)
        ? state.profile
        : 'multipart';
    const method = String(state?.method || 'POST').toUpperCase();
    const filename = String(file?.name || 'upload.bin');
    const encodedFilename = encodeURIComponent(filename);
    const fileMime = String(file?.type || '') || 'application/octet-stream';
    const byteView = getUploadByteView(bodyBytes);
    const bodySize = byteView?.byteLength ?? Number(file?.size || 0);

    let pathname = '/uploads';
    let body = bodyBytes || file;
    let wireHeaders = {};
    let traceHeaders = {};
    let mime = fileMime;
    let bodyKind = 'raw';
    let filenameSource = 'url';

    if (profile === 'multipart') {
        const form = new FormData();
        const multipartFile = fileMime === file?.type
            ? file
            : new File([file], filename, {
                type: fileMime,
                lastModified: Number(file?.lastModified || Date.now()),
            });
        form.append('file', multipartFile, filename);
        body = form;
        bodyKind = 'multipart';
        filenameSource = 'part';
        wireHeaders = withUiNoGzipHeader({});
        traceHeaders = withUiNoGzipHeader({
            'Content-Type': 'multipart/form-data; boundary=<browser-generated>',
            'Content-Length': '<browser-generated>',
        });
    } else if (profile === 'raw-url') {
        pathname = `/uploads/${encodedFilename}`;
        wireHeaders = withUiNoGzipHeader({
            'Content-Type': fileMime,
        });
        traceHeaders = {
            ...wireHeaders,
            'Content-Length': String(bodySize),
        };
    } else {
        mime = 'application/octet-stream';
        filenameSource = 'header';
        wireHeaders = withUiNoGzipHeader({
            'Content-Type': 'application/octet-stream',
            'X-File-Name': encodedFilename,
        });
        traceHeaders = {
            ...wireHeaders,
            'Content-Length': String(bodySize),
        };
    }

    const requestUrl = new URL(pathname, SERVER_URL || location.href).toString();
    const requestExchange = {
        transport: 'http',
        method,
        path: pathname,
        headers: traceHeaders,
        body: createExchangeBinaryBody({
            filename,
            contentType: mime,
            size: bodySize,
            bytes: byteView,
            label: bodyKind,
        }),
        exportFilenameBase: 'xferry-upload-request',
        sensitive: true,
    };

    return Object.freeze({
        profile,
        method,
        pathname,
        requestUrl,
        body,
        wireHeaders: Object.freeze({ ...wireHeaders }),
        traceHeaders: Object.freeze({ ...traceHeaders }),
        mime,
        bodyKind,
        filenameSource,
        requestExchange,
    });
}

function setUploadMethod(method, btn, options = {}) {
    const { focusButton = false } = options;
    if (
        typeof isServerMethodInGroup === 'function'
        && !isServerMethodInGroup(method, 'upload')
    ) {
        return;
    }
    uploadState.method = method;

    let activeButton = btn || null;
    uploadMethodButtons.forEach(button => {
        const isActive = button.dataset.uploadMethod === method;
        button.classList.toggle('active', isActive);
        button.setAttribute('aria-checked', String(isActive));
        button.setAttribute('tabindex', isActive ? '0' : '-1');
        if (isActive) {
            activeButton = button;
        }
    });

    const hint = document.getElementById('uploadMethodHint');
    if (hint) hint.textContent = method;

    refreshUploadRequestPreview();
    refreshUploadActionState();

    if (focusButton) {
        focusElementWithoutScroll(activeButton);
    }
}

function setUploadProfile(profile, btn, options = {}) {
    const { focusButton = false } = options;
    if (!basicUploadProfiles.includes(profile)) {
        return;
    }
    uploadState.profile = profile;

    let activeButton = btn || null;
    uploadProfileButtons.forEach(button => {
        const isActive = button.dataset.uploadProfile === profile;
        button.classList.toggle('active', isActive);
        button.setAttribute('aria-checked', String(isActive));
        button.setAttribute('tabindex', isActive ? '0' : '-1');
        if (isActive) {
            activeButton = button;
        }
    });

    refreshUploadRequestPreview();
    refreshUploadActionState();
    if (focusButton) {
        focusElementWithoutScroll(activeButton);
    }
}

const dropZone = document.getElementById('dropZone');
const fileInput = document.getElementById('fileInput');
const fileList = document.getElementById('fileList');
const uploadBtn = document.getElementById('uploadBtn');
const uploadCompareBtn = document.getElementById('uploadCompareBtn');
const uploadCompareResults = document.getElementById('uploadCompareResults');
const uploadRequestSummary = document.getElementById('uploadRequestSummary');
const uploadResponseAreaEl = document.getElementById('uploadResponseArea');
const uploadSelectionState = document.getElementById('uploadSelectionState');
const uploadSummaryEl = document.querySelector('[data-tool-summary-scope="upload"]');
const uploadSummaryFields = Object.freeze({
    requestLine: document.querySelector('[data-upload-summary="request-line"]'),
    bodyKind: document.querySelector('[data-upload-summary="body-kind"]'),
    mime: document.querySelector('[data-upload-summary="mime"]'),
    filenameSource: document.querySelector('[data-upload-summary="filename-source"]'),
});

if (uploadRequestSummary && window.matchMedia('(max-width: 640px)').matches) {
    uploadRequestSummary.open = false;
}

function getUploadPlaceholderFile() {
    return new File([], 'upload.bin', { type: 'application/octet-stream' });
}

function getUploadSummaryFile() {
    return getUploadPendingFiles()[0]?.file || getUploadPlaceholderFile();
}

function getUploadProfileLabel(profile) {
    const labels = {
        multipart: t('uploadProfileMultipart'),
        'raw-url': t('uploadProfileRawUrl'),
        'raw-header': t('uploadProfileRawHeader'),
    };
    return labels[profile] || profile;
}

function getUploadBodyKindLabel(bodyKind) {
    return bodyKind === 'multipart' ? t('uploadBodyKindMultipart') : t('uploadBodyKindRaw');
}

function getUploadFilenameSourceLabel(source) {
    const labels = {
        part: t('uploadFilenameSourcePart'),
        url: t('uploadFilenameSourceUrl'),
        header: t('uploadFilenameSourceHeader'),
    };
    return labels[source] || source;
}

function refreshUploadLiveSummary() {
    const plan = compileBasicUploadRequest(uploadState, getUploadSummaryFile());
    if (uploadSummaryFields.requestLine) {
        uploadSummaryFields.requestLine.textContent = `${plan.method} ${plan.pathname}`;
    }
    if (uploadSummaryFields.bodyKind) {
        uploadSummaryFields.bodyKind.textContent = getUploadBodyKindLabel(plan.bodyKind);
    }
    if (uploadSummaryFields.mime) {
        uploadSummaryFields.mime.textContent = plan.mime;
    }
    if (uploadSummaryFields.filenameSource) {
        uploadSummaryFields.filenameSource.textContent = getUploadFilenameSourceLabel(plan.filenameSource);
    }
}

function hasSupportedUploadMethod() {
    return uploadMethodButtons.some(button => (
        typeof isServerMethodInGroup !== 'function'
        || isServerMethodInGroup(button.dataset.uploadMethod || '', 'upload')
    ));
}

function getBasicActionPlans(action = 'send') {
    const pendingFiles = getUploadPendingFiles();
    if (action === 'compare') {
        const file = pendingFiles[0]?.file;
        if (!file) {
            return [];
        }
        return basicUploadProfiles.map(profile => compileBasicUploadRequest({
            method: uploadState.method,
            profile,
        }, file));
    }
    return pendingFiles.map(fileData => compileBasicUploadRequest(uploadState, fileData.file));
}

function getRoutingBlockReason(_plans, _snapshot = uploadState.routing.snapshot) {
    return '';
}

function renderUploadRoutingGuard() {
    const sendBlockedReason = getRoutingBlockReason(getBasicActionPlans('send'));
    const compareBlockedReason = getRoutingBlockReason(getBasicActionPlans('compare'));
    const blockedReason = sendBlockedReason || compareBlockedReason;
    uploadState.routing.blockedReason = blockedReason;
    uploadState.routing.sendBlockedReason = sendBlockedReason;
    uploadState.routing.compareBlockedReason = compareBlockedReason;
    return {
        send: sendBlockedReason,
        compare: compareBlockedReason,
    };
}

function refreshUploadActionState() {
    const enabled = hasSupportedUploadMethod();
    const pendingCount = getUploadPendingFiles().length;
    const busy = !['idle', 'confirming'].includes(uploadState.actionPhase);
    const routingBlocks = renderUploadRoutingGuard();

    uploadMethodButtons.forEach(button => {
        const method = button.dataset.uploadMethod || '';
        const methodSupported = typeof isServerMethodInGroup !== 'function'
            || isServerMethodInGroup(method, 'upload');
        button.disabled = busy || !enabled || !methodSupported;
    });
    uploadProfileButtons.forEach(button => {
        button.disabled = busy || !enabled;
    });
    if (fileInput) fileInput.disabled = busy || !enabled;
    if (dropZone) {
        dropZone.classList.toggle('is-disabled', busy || !enabled);
        dropZone.setAttribute('aria-disabled', String(busy || !enabled));
        dropZone.setAttribute('tabindex', busy || !enabled ? '-1' : '0');
    }
    if (uploadBtn) {
        uploadBtn.disabled = busy || Boolean(routingBlocks.send) || !enabled || pendingCount === 0;
    }
    if (uploadCompareBtn) {
        uploadCompareBtn.disabled = (
            busy
            || Boolean(routingBlocks.compare)
            || !enabled
            || pendingCount !== 1
        );
    }
}

function refreshUploadMethodAvailability() {
    const enabled = hasSupportedUploadMethod();

    if (
        enabled
        && typeof isServerMethodInGroup === 'function'
        && !isServerMethodInGroup(uploadState.method, 'upload')
    ) {
        const nextButton = uploadMethodButtons.find(button => {
            const method = button.dataset.uploadMethod || '';
            return isServerMethodInGroup(method, 'upload');
        });
        if (nextButton?.dataset.uploadMethod) {
            setUploadMethod(nextButton.dataset.uploadMethod, nextButton);
        }
    }
    refreshUploadActionState();
}

function getUploadSelectionText() {
    if (uploadState.files.length === 0) {
        return t('uploadSelectionIdle');
    }

    if (uploadState.files.length === 1) {
        const selectedFile = uploadState.files[0];
        return `${t('selectedLabel')}: ${selectedFile.name} (${formatSize(selectedFile.size)})`;
    }

    const totalSize = uploadState.files.reduce((total, file) => total + file.size, 0);
    return `${t('selectedFilesCount')}: ${uploadState.files.length} (${formatSize(totalSize)})`;
}

function refreshUploadSelectionLocale() {
    if (uploadSelectionState) {
        uploadSelectionState.textContent = getUploadSelectionText();
    }

    if (dropZone) {
        dropZone.classList.toggle('has-selection', uploadState.files.length > 0);
    }
}

function syncUploadWorkspaceSelectionState() {
    refreshUploadRequestPreview();
}

function getUploadPendingFiles() {
    return uploadState.files.filter(fileData => fileData.status === 'pending');
}

function buildUploadExchangeLog(entries, side = 'request', options = {}) {
    const { exportLog = false } = options;
    const messages = entries
        .map(entry => side === 'response' ? entry.response : entry.request)
        .filter(Boolean);

    return messages.map((message, index) => {
        const text = exportLog
            ? (message.exportText || buildExchangeRawMessageForExport(message, side))
            : (message.rawText || buildExchangeRawMessage(message, side));
        if (messages.length <= 1) {
            return text;
        }

        const label = side === 'response' ? 'RESPONSE' : 'REQUEST';
        return `--- ${label} ${index + 1}/${messages.length} ---\n${text}`;
    }).join('\n\n');
}

function buildUploadRequestInspectorModel(entries) {
    if (entries.length === 0) {
        return {
            phase: 'empty',
            emptyText: t('exchangeRequestEmpty'),
        };
    }

    const logText = buildUploadExchangeLog(entries, 'request');
    if (entries.length === 1) {
        return {
            ...entries[0].request,
            exportText: logText,
            exportFilenameBase: 'xferry-upload-request',
            sensitive: true,
        };
    }

    return {
        transport: 'http',
        method: uploadState.method,
        path: '/{multiple-files}',
        rawText: logText,
        exportText: logText,
        exportFilenameBase: 'xferry-upload-requests',
        sensitive: true,
        body: createExchangePreviewBody({
            label: t('selectedFilesCount'),
            size: entries.reduce((total, entry) => total + (entry.fileData?.size || 0), 0),
            text: entries.map(entry => `${entry.fileData.name} (${formatSize(entry.fileData.size)})`).join('\n'),
        }),
    };
}

function getUploadPendingSignature() {
    return getUploadPendingFiles()
        .map(fileData => `${fileData.name}:${fileData.size}:${fileData.status}`)
        .join('|');
}

async function readUploadBodyPreviewBuffer(fileData) {
    const file = fileData?.file;
    if (!file?.slice || !file?.arrayBuffer) {
        return null;
    }

    const previewBlob = file.slice(0, uploadBodyPreviewReadLimit);
    return previewBlob.arrayBuffer();
}

async function refreshUploadRequestPreviewBodySamples(sequence, signature) {
    try {
        const pendingFiles = getUploadPendingFiles();
        const entries = await Promise.all(pendingFiles.map(async (fileData) => {
            const previewBuffer = await readUploadBodyPreviewBuffer(fileData);
            const request = compileBasicUploadRequest(
                uploadState,
                fileData.file,
                previewBuffer
            ).requestExchange;
            return { fileData, request };
        }));

        if (sequence !== uploadState.previewSequence || signature !== getUploadPendingSignature()) {
            return;
        }

        setExchangeInspector('upload', {
            phase: 'ready',
            request: buildUploadRequestInspectorModel(entries),
            response: {
                phase: 'empty',
                emptyText: t('exchangeResponseEmpty'),
            },
        });
    } catch (error) {
        console.warn('Upload request body preview failed:', error);
    }
}

function refreshUploadRequestPreview() {
    const sequence = ++uploadState.previewSequence;
    refreshUploadLiveSummary();
    if (uploadState.files.length === 0) {
        setExchangeInspector('upload', {
            phase: 'empty',
            request: {
                phase: 'empty',
                emptyText: t('exchangeRequestEmpty'),
            },
            response: {
                phase: 'empty',
                emptyText: t('exchangeResponseEmpty'),
            },
        });
        if (typeof setToolSummaryActions === 'function') {
            setToolSummaryActions('upload', '');
        }
        return;
    }

    const entries = getUploadPendingFiles().map(fileData => {
        const request = compileBasicUploadRequest(uploadState, fileData.file).requestExchange;
        return { fileData, request };
    });
    const request = buildUploadRequestInspectorModel(entries);
    setExchangeInspector('upload', {
        phase: 'ready',
        request,
        response: {
            phase: 'empty',
            emptyText: t('exchangeResponseEmpty'),
        },
    });
    void refreshUploadRequestPreviewBodySamples(sequence, getUploadPendingSignature());
}

uploadMethodButtons.forEach(button => {
    button.addEventListener('click', () => {
        const method = button.dataset.uploadMethod;
        if (method) {
            setUploadMethod(method, button);
        }
    });

    button.addEventListener('keydown', (event) => {
        const currentIndex = uploadMethodButtons.indexOf(button);
        if (currentIndex === -1) {
            return;
        }

        let nextIndex;
        if (event.key === 'ArrowRight') {
            nextIndex = (currentIndex + 1) % uploadMethodButtons.length;
        } else if (event.key === 'ArrowLeft') {
            nextIndex = (currentIndex - 1 + uploadMethodButtons.length) % uploadMethodButtons.length;
        } else if (event.key === 'Home') {
            nextIndex = 0;
        } else if (event.key === 'End') {
            nextIndex = uploadMethodButtons.length - 1;
        } else {
            return;
        }

        event.preventDefault();
        const nextButton = uploadMethodButtons[nextIndex];
        const method = nextButton?.dataset.uploadMethod;
        if (method) {
            setUploadMethod(method, nextButton, { focusButton: true });
        }
    });
});

uploadProfileButtons.forEach(button => {
    button.addEventListener('click', () => {
        const profile = button.dataset.uploadProfile;
        if (profile) {
            setUploadProfile(profile, button);
        }
    });

    button.addEventListener('keydown', (event) => {
        const currentIndex = uploadProfileButtons.indexOf(button);
        if (currentIndex === -1) {
            return;
        }

        let nextIndex;
        if (event.key === 'ArrowRight' || event.key === 'ArrowDown') {
            nextIndex = (currentIndex + 1) % uploadProfileButtons.length;
        } else if (event.key === 'ArrowLeft' || event.key === 'ArrowUp') {
            nextIndex = (currentIndex - 1 + uploadProfileButtons.length) % uploadProfileButtons.length;
        } else if (event.key === 'Home') {
            nextIndex = 0;
        } else if (event.key === 'End') {
            nextIndex = uploadProfileButtons.length - 1;
        } else {
            return;
        }

        event.preventDefault();
        const nextButton = uploadProfileButtons[nextIndex];
        const profile = nextButton?.dataset.uploadProfile;
        if (profile) {
            setUploadProfile(profile, nextButton, { focusButton: true });
        }
    });
});

if (uploadBtn) {
    uploadBtn.addEventListener('click', () => {
        void uploadAllFiles();
    });
}
if (uploadCompareBtn) {
    uploadCompareBtn.addEventListener('click', () => {
        void compareBasicUploadProfiles();
    });
}

if (fileList) {
    fileList.addEventListener('click', (e) => {
        const detailsBtn = e.target.closest('[data-upload-error-details-index]');
        if (detailsBtn) {
            const index = Number(detailsBtn.dataset.uploadErrorDetailsIndex);
            if (!Number.isNaN(index)) {
                showBasicUploadError(uploadState.files[index], detailsBtn);
            }
            return;
        }

        const retryBtn = e.target.closest('[data-upload-retry-index]');
        if (retryBtn) {
            const index = Number(retryBtn.dataset.uploadRetryIndex);
            if (!Number.isNaN(index)) {
                void retryBasicUpload(uploadState.files[index], retryBtn);
            }
            return;
        }

        const removeBtn = e.target.closest('[data-remove-index]');
        if (!removeBtn) return;

        const index = Number(removeBtn.dataset.removeIndex);
        if (!Number.isNaN(index)) {
            removeFile(index);
        }
    });
}

if (uploadResponseAreaEl) {
    uploadResponseAreaEl.addEventListener('click', (e) => {
        const actionBtn = e.target.closest('[data-upload-response-action]');
        if (!actionBtn) return;

        handleUploadResultAction(actionBtn);
    });
}

if (uploadSummaryEl) {
    uploadSummaryEl.addEventListener('click', (e) => {
        const actionBtn = e.target.closest('[data-upload-response-action]');
        if (!actionBtn) return;

        handleUploadResultAction(actionBtn);
    });
}

function openUploadTraceDetails() {
    const traceDetails = document.querySelector('[data-tool-trace-scope="upload"]');
    if (!traceDetails) {
        return;
    }

    traceDetails.open = true;
    focusElementWithoutScroll(traceDetails.querySelector('summary'));
}

function handleUploadResultAction(actionBtn) {
    if (!actionBtn) {
        return;
    }

    if (actionBtn.dataset.uploadResponseAction === 'view-files') {
        const browseInput = document.getElementById('browsePathInput');
        if (browseInput) {
            browseInput.value = '/uploads';
        }
        switchTab('files', document.getElementById('tab-files'), { focusTabButton: true });
    } else if (actionBtn.dataset.uploadResponseAction === 'show-trace') {
        openUploadTraceDetails();
    }
}

// Drag & Drop
if (dropZone && fileInput) {
    bindDropZoneKeyboardTrigger(dropZone, fileInput);

    dropZone.addEventListener('dragover', (e) => {
        e.preventDefault();
        dropZone.classList.add('dragover');
    });

    dropZone.addEventListener('dragleave', () => {
        dropZone.classList.remove('dragover');
    });

    dropZone.addEventListener('drop', (e) => {
        e.preventDefault();
        dropZone.classList.remove('dragover');
        handleFiles(e.dataTransfer.files);
    });

    fileInput.addEventListener('change', () => {
        handleFiles(fileInput.files);
        fileInput.value = '';
    });
}

if (uploadMethodButtons.length > 0) {
    const initialButton = uploadMethodButtons.find(button => button.classList.contains('active')) || uploadMethodButtons[0];
    const initialMethod = initialButton?.dataset.uploadMethod;
    if (initialMethod) {
        setUploadMethod(initialMethod, initialButton);
    }
}
if (uploadProfileButtons.length > 0) {
    const initialButton = uploadProfileButtons.find(button => button.classList.contains('active'))
        || uploadProfileButtons[0];
    const initialProfile = initialButton?.dataset.uploadProfile;
    if (initialProfile) {
        setUploadProfile(initialProfile, initialButton);
    }
}

function handleFiles(files) {
    if (!hasSupportedUploadMethod()) {
        return;
    }

    for (const file of files) {
        const existing = uploadState.files.find(f => f.name === file.name && f.size === file.size);
        if (!existing) {
            uploadState.files.push({
                file: file,
                name: file.name,
                size: file.size,
                status: 'pending',
                progress: 0
            });
        } else if (existing.status === 'error') {
            existing.file = file;
            existing.status = 'pending';
            existing.progress = 0;
            delete existing.serverPath;
            delete existing.error;
            delete existing.errorDetails;
            delete existing.retryContext;
        }
    }
    renderFileList();
    refreshUploadSelectionLocale();
    syncUploadWorkspaceSelectionState();
    refreshUploadActionState();
}

function scheduleRenderFileList() {
    if (!uploadState.renderFileListRAF) {
        uploadState.renderFileListRAF = requestAnimationFrame(() => {
            uploadState.renderFileListRAF = null;
            renderFileList();
        });
    }
}

function renderFileList() {
    if (!fileList) {
        return;
    }
    const fragment = document.createDocumentFragment();
    uploadState.files.forEach((fileData, index) => {
        const item = document.createElement('div');
        item.className = 'file-item';
        item.dataset.testid = `file-item-${index}`;

        const info = document.createElement('div');
        info.className = 'file-info';
        const name = document.createElement('span');
        name.className = 'file-name';
        name.textContent = fileData.name;
        info.appendChild(name);
        const size = document.createElement('span');
        size.className = 'file-size';
        size.textContent = formatSize(fileData.size);
        info.appendChild(size);
        item.appendChild(info);

        const aside = document.createElement('div');
        aside.className = 'queue-item__aside';
        const status = document.createElement('span');
        status.className = `file-status ${fileData.status}`;
        status.textContent = getStatusText(fileData.status);
        aside.appendChild(status);
        if (fileData.status === 'pending' || fileData.status === 'error') {
            const remove = document.createElement('button');
            remove.type = 'button';
            remove.className = 'btn-ghost btn--sm queue-item__remove';
            remove.dataset.removeIndex = String(index);
            remove.title = t('queueRemoveLabel');
            remove.setAttribute('aria-label', t('queueRemoveLabel'));
            remove.textContent = '✕';
            aside.appendChild(remove);
        }
        if (fileData.status === 'error') {
            const details = document.createElement('button');
            details.type = 'button';
            details.className = 'btn-ghost btn--sm';
            details.dataset.uploadErrorDetailsIndex = String(index);
            details.title = t('queueDetailsLabel');
            details.setAttribute('aria-label', t('queueDetailsLabel'));
            details.textContent = t('httpErrorDetails');
            aside.appendChild(details);

            const retry = document.createElement('button');
            retry.type = 'button';
            retry.className = 'btn-info btn--sm';
            retry.dataset.uploadRetryIndex = String(index);
            retry.title = t('queueRetryLabel');
            retry.setAttribute('aria-label', t('queueRetryLabel'));
            retry.textContent = t('httpErrorRetry');
            aside.appendChild(retry);
        }
        item.appendChild(aside);
        fragment.appendChild(item);

        if (fileData.status === 'uploading') {
            const progress = document.createElement('div');
            progress.className = 'progress-bar';
            const fill = document.createElement('div');
            fill.className = 'progress-fill';
            const percentage = Math.max(0, Math.min(100, Number(fileData.progress) || 0));
            fill.style.width = `${percentage}%`;
            progress.appendChild(fill);
            fragment.appendChild(progress);
        }
    });
    fileList.replaceChildren(fragment);
}

function getStatusText(status) {
    const statusMap = {
        'pending': t('statusPending'),
        'uploading': t('statusUploading'),
        'success': t('statusSuccess'),
        'error': t('statusError')
    };
    return statusMap[status] || status;
}

function removeFile(index) {
    const [fileData] = uploadState.files.splice(index, 1);
    if (fileData?.status === 'error') {
        invalidateBasicUploadError(fileData);
    }
    renderFileList();
    refreshUploadSelectionLocale();
    syncUploadWorkspaceSelectionState();
    refreshUploadActionState();
}

function copyResponseHeaders(headers) {
    if (headers instanceof Headers) {
        return Object.freeze(Object.fromEntries(headers.entries()));
    }
    return Object.freeze({ ...(headers || {}) });
}

function createBasicUploadErrorDetails(plan, response, text) {
    return Object.freeze({
        method: plan?.method || uploadState.method,
        path: plan?.pathname || '',
        status: Number(response?.status || 0),
        statusText: response?.statusText || t('error'),
        headers: copyResponseHeaders(response?.headers),
        body: String(text || ''),
    });
}

function createBasicUploadNetworkErrorDetails(plan, error) {
    return Object.freeze({
        method: plan?.method || uploadState.method,
        path: plan?.pathname || '',
        status: 0,
        statusText: error?.message || String(error),
        headers: Object.freeze({}),
        body: error?.message || String(error),
    });
}

function createBasicUploadRetryContext(fileData, requestState = uploadState) {
    return Object.freeze({
        file: fileData.file,
        name: fileData.name,
        size: fileData.size,
        requestState: Object.freeze({
            method: requestState.method,
            profile: requestState.profile,
        }),
    });
}

function resolveBasicUploadErrorOrigin(fileData, fallback = null) {
    if (fallback?.isConnected && !fallback.disabled) {
        return fallback;
    }
    const index = uploadState.files.indexOf(fileData);
    if (index >= 0) {
        return fileList?.querySelector(`[data-upload-error-details-index="${index}"]`)
            || fileList?.querySelector(`[data-upload-retry-index="${index}"]`)
            || uploadBtn;
    }
    return uploadBtn;
}

function showBasicUploadError(fileData, origin = null) {
    if (!fileData?.errorDetails) {
        return null;
    }
    const retryContext = fileData.retryContext;
    const resolvedOrigin = resolveBasicUploadErrorOrigin(fileData, origin);
    activeBasicUploadErrorFile = fileData;
    return httpErrors.show({
        host: 'uploadHttpErrorHost',
        origin: resolvedOrigin,
        ...fileData.errorDetails,
        retry: retryContext
            ? () => retryBasicUpload(fileData, resolvedOrigin, retryContext)
            : undefined,
    });
}

function invalidateBasicUploadError(fileData) {
    if (!fileData) {
        return;
    }
    if (activeBasicUploadErrorFile === fileData) {
        httpErrors.close('uploadHttpErrorHost', { restore: false });
        activeBasicUploadErrorFile = null;
    }
    delete fileData.error;
    delete fileData.errorDetails;
    delete fileData.retryContext;
    fileData.file = null;
}

async function ensureBasicUploadRoute(plans) {
    void plans;
    return true;
}

async function beginBasicUploadTransport(state, file, bodyBytes, onProgress = null) {
    const plan = compileBasicUploadRequest(state, file, bodyBytes);
    const responsePromise = sendCustomRequest(
        plan.method,
        plan.requestUrl,
        plan.body,
        plan.wireHeaders,
        onProgress
    );
    return {
        blockedReason: '',
        plan,
        snapshot: null,
        responsePromise,
    };
}

function announceBasicUploadRoutingBlock(blockedReason) {
    uploadState.routing.blockedReason = blockedReason;
    announceLiveRegion(
        'uploadResponseAreaLive',
        t(blockedReason === 'conflict' ? 'uploadRoutingConflict' : 'uploadRoutingUnknown')
    );
}

function parseUploadJson(text) {
    try {
        const value = JSON.parse(text);
        return value && typeof value === 'object' && !Array.isArray(value) ? value : null;
    } catch (error) {
        return null;
    }
}

function createUploadNetworkErrorExchange(plan, error) {
    const errorText = `${t('error')}: ${error?.message || String(error)}`;
    return {
        transport: 'http',
        method: plan?.method || uploadState.method,
        path: plan?.pathname || '',
        phase: 'error',
        summaryText: error?.message || String(error),
        status: 0,
        statusText: t('error'),
        body: createExchangeTextBody(errorText),
        rawText: errorText,
        exportText: errorText,
        exportFilenameBase: 'xferry-upload-response',
    };
}

function renderUploadCompletion(results, exchangeEntries, lastRequestExchange) {
    const successCount = results.filter(result => result.success).length;
    const failCount = results.length - successCount;
    const singleSuccessfulResult = results.length === 1 && results[0].success ? results[0] : null;
    const firstFailure = results.find(result => !result.success) || null;
    const firstHttpFailure = results.find(result => !result.success && Number(result.status) > 0) || null;
    const failureStatusText = Array.from(new Map(
        results.filter(result => !result.success && result.status)
            .map(result => [result.status, result.statusText || t('error')])
    ).entries()).map(([status, statusText], index) => (
        index === 0 ? statusText : `${status} ${statusText}`
    )).join(', ');
    const resultText = results.map(result => {
        if (result.success) {
            return `✓ ${result.name} -> ${result.path}`;
        }
        const status = result.status
            ? `${result.status} ${result.statusText || t('error')}`.trim()
            : (result.statusText || t('error'));
        return `✗ ${result.name}: ${status}${result.error ? `; ${result.error}` : ''}`;
    }).join('\n');
    const requestLog = buildUploadExchangeLog(exchangeEntries, 'request');
    const responseLog = buildUploadExchangeLog(exchangeEntries, 'response');
    const requestExportLog = buildUploadExchangeLog(exchangeEntries, 'request', { exportLog: true });
    const responseExportLog = buildUploadExchangeLog(exchangeEntries, 'response', { exportLog: true });
    const finalStatus = singleSuccessfulResult?.status ?? (failCount === 0
        ? 201
        : (firstHttpFailure?.status ?? 0));
    const finalStatusText = singleSuccessfulResult?.statusText
        || failureStatusText
        || firstFailure?.statusText
        || (failCount === 0 ? 'Created' : t('error'));
    const finalSummaryText = singleSuccessfulResult
        ? `${t('uploadComplete')}: ${singleSuccessfulResult.path}`
        : `${successCount} ${t('successCount')}, ${failCount} ${t('errorCount')}`;

    setExchangeInspector('upload', {
        phase: failCount === 0 ? 'complete' : 'error',
        summaryMetaMode: singleSuccessfulResult ? 'replace' : '',
        summaryMeta: singleSuccessfulResult
            ? [
                {
                    label: t('responseSummaryFieldStatus'),
                    value: `${finalStatus} ${finalStatusText}`.trim(),
                    tone: finalStatus >= 400 ? 'danger' : 'success',
                    field: 'status',
                },
                {
                    label: t('uploadResultServerPath'),
                    value: singleSuccessfulResult.path,
                    field: 'server-path',
                },
                {
                    label: t('uploadResultSize'),
                    value: formatSize(singleSuccessfulResult.size),
                    field: 'size',
                },
            ]
            : [],
        request: lastRequestExchange
            ? {
                ...lastRequestExchange,
                rawText: requestLog || lastRequestExchange.exportText,
                exportText: requestExportLog || lastRequestExchange.exportText,
                exportFilenameBase: exchangeEntries.length > 1
                    ? 'xferry-upload-requests'
                    : 'xferry-upload-request',
                sensitive: true,
            }
            : {
                phase: 'empty',
                emptyText: t('exchangeRequestEmpty'),
            },
        response: {
            phase: failCount === 0 ? 'complete' : 'error',
            summaryText: finalSummaryText,
            startLine: t('uploadComplete'),
            status: finalStatus,
            statusText: finalStatusText,
            body: createExchangeTextBody(
                `${successCount} ${t('successCount')}, ${failCount} ${t('errorCount')}\n\n${resultText}`
            ),
            rawText: responseLog || undefined,
            exportText: responseExportLog || resultText,
            exportFilenameBase: exchangeEntries.length > 1
                ? 'xferry-upload-responses'
                : 'xferry-upload-response',
        },
    });
    if (typeof setToolSummaryActions === 'function') {
        setToolSummaryActions(
            'upload',
            successCount > 0
                ? `
                    <button class="btn-info btn--sm" type="button" data-upload-response-action="show-trace" data-testid="upload-result-trace-btn">${esc(t('uploadResultTraceAction'))}</button>
                    <button class="btn-info btn--sm" type="button" data-upload-response-action="view-files" data-testid="upload-result-files-btn">${esc(t('uploadResultFilesAction'))}</button>
                `
                : ''
        );
    }
    announceLiveRegion(
        'uploadResponseAreaLive',
        `${t('uploadComplete')}: ${successCount} ${t('successCount')}, ${failCount} ${t('errorCount')}`
    );
}

async function uploadFiles(fileDataList, options = {}) {
    const {
        origin = uploadBtn,
        requestState = uploadState,
        retrying = false,
    } = options;
    const pendingFiles = Array.from(fileDataList || []).filter(Boolean);
    if (!hasSupportedUploadMethod() || pendingFiles.length === 0 || uploadState.actionPhase !== 'idle') {
        return false;
    }

    uploadState.actionPhase = 'checking';
    refreshUploadActionState();
    const previewPlans = pendingFiles.map(fileData => (
        compileBasicUploadRequest(requestState, fileData.file)
    ));
    if (!await ensureBasicUploadRoute(previewPlans)) {
        uploadState.actionPhase = 'idle';
        refreshUploadActionState();
        return false;
    }

    uploadState.actionPhase = 'sending';
    refreshUploadActionState();
    announceLiveRegion('uploadResponseAreaLive', t('uploadStarting'));
    if (typeof setToolSummaryActions === 'function') {
        setToolSummaryActions('upload', '');
    }
    setExchangeInspector('upload', {
        phase: 'sending',
        request: buildUploadRequestInspectorModel(pendingFiles.map((fileData, index) => ({
            fileData,
            request: previewPlans[index].requestExchange,
        }))),
        response: {
            phase: 'sending',
            summaryText: t('uploadStarting'),
            startLine: t('uploadStarting'),
            body: createExchangeTextBody(t('uploadStarting')),
        },
    });

    const results = [];
    let lastRequestExchange = null;
    const exchangeEntries = [];
    let routingBlocked = false;

    for (const fileData of pendingFiles) {
        fileData.status = 'uploading';
        fileData.progress = 0;
        renderFileList();
        let plan = null;

        try {
            const arrayBuffer = await fileData.file.arrayBuffer();
            const transport = await beginBasicUploadTransport(
                requestState,
                fileData.file,
                arrayBuffer,
                event => {
                    if (!event.lengthComputable) {
                        return;
                    }
                    fileData.progress = Math.round((event.loaded / event.total) * 100);
                    scheduleRenderFileList();
                }
            );
            plan = transport.plan;
            if (transport.blockedReason) {
                fileData.status = 'pending';
                fileData.progress = 0;
                routingBlocked = true;
                announceBasicUploadRoutingBlock(transport.blockedReason);
                renderFileList();
                break;
            }
            lastRequestExchange = {
                ...plan.requestExchange,
                exportText: buildExchangeRawMessageForExport(plan.requestExchange, 'request'),
            };
            setExchangeInspector('upload', {
                phase: 'sending',
                request: lastRequestExchange,
                response: {
                    phase: 'sending',
                    summaryText: `${t('statusUploading')} ${fileData.name}`,
                    startLine: `${t('statusUploading')} ${fileData.name}`,
                    body: createExchangeTextBody(`${t('statusUploading')} ${fileData.name}`),
                },
            });

            const response = await transport.responsePromise;
            const text = await response.text();
            const result = parseUploadJson(text);
            const success = Boolean(response.ok && hasCompleteBasicUpload(result));

            fileData.status = success ? 'success' : 'error';
            fileData.progress = success ? 100 : 0;
            if (success) {
                fileData.serverPath = result.file.path;
                delete fileData.error;
                delete fileData.errorDetails;
                delete fileData.retryContext;
            } else {
                fileData.error = result?.error?.message
                    || (response.ok ? t('error') : `HTTP ${response.status}`);
                fileData.errorDetails = createBasicUploadErrorDetails(plan, response, text);
                fileData.retryContext = createBasicUploadRetryContext(fileData, requestState);
            }
            results.push({
                name: fileData.name,
                success,
                path: success ? result.file.path : '',
                error: success ? '' : fileData.error,
                size: fileData.size,
                status: response.status,
                statusText: response.statusText || (success ? 'Created' : t('error')),
            });
            const responseExchange = createExchangeHttpResponseMessage(response, text, {
                method: plan.method,
                path: plan.pathname,
                phase: success ? 'complete' : 'error',
                summaryText: success
                    ? result.file.path
                    : (result?.error?.message || (response.ok ? t('error') : `HTTP ${response.status}`)),
                exportFilenameBase: 'xferry-upload-response',
            });
            exchangeEntries.push({
                fileData,
                request: lastRequestExchange,
                response: responseExchange,
            });
        } catch (error) {
            fileData.status = 'error';
            fileData.progress = 0;
            fileData.error = error?.message || String(error);
            fileData.errorDetails = createBasicUploadNetworkErrorDetails(plan, error);
            fileData.retryContext = createBasicUploadRetryContext(fileData, requestState);
            results.push({
                name: fileData.name,
                success: false,
                error: fileData.error,
                size: fileData.size,
                status: 0,
                statusText: t('error'),
            });
            if (plan && lastRequestExchange) {
                exchangeEntries.push({
                    fileData,
                    request: lastRequestExchange,
                    response: createUploadNetworkErrorExchange(plan, error),
                });
            }
        }
        renderFileList();
    }

    if (results.length > 0) {
        renderUploadCompletion(results, exchangeEntries, lastRequestExchange);
    } else if (routingBlocked) {
        refreshUploadRequestPreview();
    }
    const lastFailedFile = pendingFiles.slice().reverse().find(fileData => fileData.status === 'error');
    uploadState.files = uploadState.files.filter(fileData => fileData.status !== 'success');
    uploadState.actionPhase = 'idle';
    renderFileList();
    refreshUploadSelectionLocale();
    refreshUploadLiveSummary();
    refreshUploadActionState();
    if (lastFailedFile) {
        showBasicUploadError(lastFailedFile, origin);
    } else if (retrying) {
        httpErrors.close('uploadHttpErrorHost');
    }
    return results;
}

function uploadAllFiles() {
    return uploadFiles(getUploadPendingFiles(), { origin: uploadBtn });
}

function retryBasicUpload(fileData, origin = null, retryContext = fileData?.retryContext) {
    if (
        !fileData
        || !uploadState.files.includes(fileData)
        || fileData.status !== 'error'
        || !retryContext
    ) {
        return Promise.resolve(false);
    }
    return uploadFiles([fileData], {
        origin: origin || uploadBtn,
        requestState: retryContext.requestState,
        retrying: true,
    });
}

function bytesToHex(bytes) {
    return Array.from(new Uint8Array(bytes))
        .map(value => value.toString(16).padStart(2, '0'))
        .join('');
}

function hasCompleteBasicUpload(payload) {
    if (
        !payload
        || typeof payload !== 'object'
        || Array.isArray(payload)
        || !payload.file
        || typeof payload.file !== 'object'
        || Array.isArray(payload.file)
        || !payload.upload
        || typeof payload.upload !== 'object'
        || Array.isArray(payload.upload)
    ) {
        return false;
    }

    const fileStringKeys = ['name', 'path', 'size_human', 'content_type', 'uploaded_at', 'sha256'];
    const uploadStringKeys = ['kind', 'profile', 'carrier', 'filename_source', 'normalized_name'];
    const integerKeys = ['request_body_size', 'payload_size'];
    const mimePattern = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+\/[!#$%&'*+.^_`|~0-9A-Za-z-]+(?:\s*;\s*[!#$%&'*+.^_`|~0-9A-Za-z-]+=(?:[!#$%&'*+.^_`|~0-9A-Za-z-]+|"(?:[^"\\\r\n]|\\.)*"))*$/;

    return (
        fileStringKeys.every(key => typeof payload.file[key] === 'string' && payload.file[key])
        && uploadStringKeys.every(key => typeof payload.upload[key] === 'string' && payload.upload[key])
        && payload.upload.kind === 'basic'
        && Number.isInteger(payload.file.size_bytes) && payload.file.size_bytes >= 0
        && integerKeys.every(key => Number.isInteger(payload.upload[key]) && payload.upload[key] >= 0)
        && typeof payload.upload.collision_renamed === 'boolean'
        && mimePattern.test(payload.file.content_type)
        && /^[0-9a-f]{64}$/.test(payload.file.sha256)
    );
}

function getCompareVerdict(plan, file, localHash, response, payload) {
    if (!response) {
        return 'not-confirmed';
    }
    if (!response.ok) {
        return 'rejected-with-response';
    }
    if (!hasCompleteBasicUpload(payload)) {
        return 'not-confirmed';
    }
    if (payload.file.sha256 !== localHash || payload.upload.payload_size !== file.size) {
        return 'content-changed';
    }

    const expectedCarrier = plan.profile === 'multipart' ? 'multipart' : 'body';
    const metadataMatches = (
        payload.upload.kind === 'basic'
        && payload.upload.profile === plan.profile
        && payload.upload.carrier === expectedCarrier
        && payload.upload.filename_source === plan.filenameSource
        && payload.file.content_type === plan.mime
        && (
            plan.profile === 'multipart'
                ? payload.upload.request_body_size >= file.size
                : payload.upload.request_body_size === file.size
        )
        && (
            payload.upload.normalized_name === file.name
            || payload.upload.collision_renamed === true
        )
    );
    return metadataMatches ? 'delivered' : 'metadata-changed';
}

function getCompareVerdictLabel(verdict) {
    const labels = {
        delivered: 'uploadVerdictDelivered',
        'metadata-changed': 'uploadVerdictMetadataChanged',
        'content-changed': 'uploadVerdictContentChanged',
        'rejected-with-response': 'uploadVerdictRejected',
        'not-confirmed': 'uploadVerdictNotConfirmed',
        'not-run': 'uploadVerdictNotRun',
    };
    return t(labels[verdict] || labels['not-confirmed']);
}

function renderBasicUploadComparison() {
    const list = uploadCompareResults?.querySelector('[data-upload-compare-list]');
    if (!uploadCompareResults || !list) {
        return;
    }
    uploadCompareResults.hidden = uploadState.compareResults.length === 0;
    const fragment = document.createDocumentFragment();

    uploadState.compareResults.forEach(result => {
        const row = document.createElement('article');
        row.className = 'upload-compare-result';
        row.dataset.uploadCompareResult = result.profile;
        row.dataset.uploadVerdict = result.verdict;

        const header = document.createElement('div');
        header.className = 'upload-compare-result__header';
        const profile = document.createElement('strong');
        profile.textContent = getUploadProfileLabel(result.profile);
        header.appendChild(profile);
        const verdict = document.createElement('span');
        verdict.className = 'upload-compare-result__verdict';
        verdict.dataset.uploadCompareVerdict = '';
        verdict.textContent = getCompareVerdictLabel(result.verdict);
        header.appendChild(verdict);
        row.appendChild(header);

        if (result.collisionRenamed) {
            const note = document.createElement('p');
            note.className = 'upload-compare-result__note';
            note.textContent = t('uploadCollisionRenamed');
            row.appendChild(note);
        }

        const traces = document.createElement('div');
        traces.className = 'upload-compare-result__traces';
        [
            ['request', t('uploadCompareRequestLabel'), result.requestTrace],
            ['response', t('uploadCompareResponseLabel'), result.responseTrace],
        ].forEach(([side, label, text]) => {
            const details = document.createElement('details');
            const summary = document.createElement('summary');
            summary.textContent = label;
            details.appendChild(summary);
            const trace = document.createElement('pre');
            trace.dataset[side === 'request'
                ? 'uploadCompareRequest'
                : 'uploadCompareResponse'] = '';
            trace.textContent = text || getCompareVerdictLabel('not-run');
            details.appendChild(trace);
            traces.appendChild(details);
        });
        row.appendChild(traces);
        fragment.appendChild(row);
    });
    list.replaceChildren(fragment);
}

async function compareBasicUploadProfiles() {
    const pendingFiles = getUploadPendingFiles();
    if (
        !hasSupportedUploadMethod()
        || pendingFiles.length !== 1
        || uploadState.actionPhase !== 'idle'
    ) {
        return false;
    }

    const fileData = pendingFiles[0];
    const previewPlans = basicUploadProfiles.map(profile => compileBasicUploadRequest({
        method: uploadState.method,
        profile,
    }, fileData.file));
    uploadState.actionPhase = 'checking';
    refreshUploadActionState();
    if (!await ensureBasicUploadRoute(previewPlans)) {
        uploadState.actionPhase = 'idle';
        refreshUploadActionState();
        return false;
    }

    uploadState.actionPhase = 'confirming';
    refreshUploadActionState();
    const confirmed = await dialogs.confirm({
        title: t('uploadCompareConfirmTitle'),
        message: t('uploadCompareConfirmBody'),
        confirmLabel: t('uploadCompareConfirmAction'),
        cancelLabel: t('smuggleCancel'),
        confirmClassName: 'btn-info',
        triggerEl: uploadCompareBtn,
        restoreFocusSelector: '#uploadCompareBtn',
        initialFocus: 'cancel',
    });
    if (!confirmed) {
        uploadState.actionPhase = 'idle';
        refreshUploadActionState();
        return false;
    }

    uploadState.actionPhase = 'comparing';
    uploadState.compareResults = basicUploadProfiles.map(profile => ({
        profile,
        verdict: 'not-run',
        collisionRenamed: false,
        requestTrace: '',
        responseTrace: '',
    }));
    renderBasicUploadComparison();
    refreshUploadActionState();
    announceLiveRegion('uploadResponseAreaLive', t('uploadCompareRunning'));

    let arrayBuffer;
    let localHash;
    try {
        arrayBuffer = await fileData.file.arrayBuffer();
        localHash = bytesToHex(await crypto.subtle.digest('SHA-256', arrayBuffer));
    } catch (error) {
        uploadState.compareResults.forEach(result => {
            result.verdict = 'not-confirmed';
            result.responseTrace = `${t('error')}: ${error?.message || String(error)}`;
        });
        uploadState.actionPhase = 'idle';
        renderBasicUploadComparison();
        refreshUploadActionState();
        announceLiveRegion('uploadResponseAreaLive', getCompareVerdictLabel('not-confirmed'));
        return uploadState.compareResults.map(result => ({ ...result }));
    }

    for (let index = 0; index < basicUploadProfiles.length; index += 1) {
        const profile = basicUploadProfiles[index];
        const result = uploadState.compareResults[index];
        let plan = null;

        try {
            const transport = await beginBasicUploadTransport(
                {
                    method: uploadState.method,
                    profile,
                },
                fileData.file,
                arrayBuffer
            );
            plan = transport.plan;
            if (transport.blockedReason) {
                announceBasicUploadRoutingBlock(transport.blockedReason);
                break;
            }
            result.requestTrace = buildExchangeRawMessageForExport(
                plan.requestExchange,
                'request'
            );
            const response = await transport.responsePromise;
            const text = await response.text();
            const payload = parseUploadJson(text);
            result.responseTrace = buildExchangeRawMessageForExport(
                createExchangeHttpResponseMessage(response, text, {
                    method: plan.method,
                    path: plan.pathname,
                    phase: response.ok ? 'complete' : 'error',
                }),
                'response'
            );
            result.verdict = getCompareVerdict(
                plan,
                fileData.file,
                localHash,
                response,
                payload
            );
            result.collisionRenamed = payload?.upload?.collision_renamed === true;
        } catch (error) {
            result.verdict = 'not-confirmed';
            result.responseTrace = createUploadNetworkErrorExchange(plan, error).rawText;
        }
        renderBasicUploadComparison();
    }

    uploadState.actionPhase = 'idle';
    refreshUploadActionState();
    announceLiveRegion(
        'uploadResponseAreaLive',
        uploadState.compareResults
            .map(result => `${getUploadProfileLabel(result.profile)}: ${getCompareVerdictLabel(result.verdict)}`)
            .join('. ')
    );
    return uploadState.compareResults.map(result => ({ ...result }));
}

refreshUploadSelectionLocale();
refreshUploadMethodAvailability();
refreshUploadRequestPreview();
renderBasicUploadComparison();

app.on(app.events.LOCALE_CHANGED, () => {
    refreshUploadSelectionLocale();
    refreshUploadRequestPreview();
    renderBasicUploadComparison();
    refreshUploadActionState();
});
app.on(app.events.SERVER_METHODS_CHANGED, refreshUploadMethodAvailability);
document.addEventListener('xferry:response-options-changed', refreshUploadRequestPreview);

app.registerWorkflow('upload', {
    commands: {
        send: uploadAllFiles,
        compare: compareBasicUploadProfiles,
        'compile-request': compileBasicUploadRequest,
        'set-method': setUploadMethod,
        'set-profile': setUploadProfile,
        'handle-files': handleFiles,
        'refresh-methods': refreshUploadMethodAvailability,
    },
    getState: () => ({
        method: uploadState.method,
        profile: uploadState.profile,
        fileCount: uploadState.files.length,
        pendingCount: uploadState.files.filter(file => file.status === 'pending').length,
        previewSequence: uploadState.previewSequence,
        actionPhase: uploadState.actionPhase,
        routingPhase: uploadState.routing.phase,
        routingBlockedReason: uploadState.routing.blockedReason,
        sendRoutingBlockedReason: uploadState.routing.sendBlockedReason,
        compareRoutingBlockedReason: uploadState.routing.compareBlockedReason,
        compareResults: uploadState.compareResults.map(result => ({
            profile: result.profile,
            verdict: result.verdict,
            collisionRenamed: result.collisionRenamed,
        })),
    }),
});
})(window.XferryApp);
