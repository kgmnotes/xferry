(function initializeNotepad(app) {
    'use strict';

const {
    t,
    serverUrl: SERVER_URL,
    focusElementWithoutScroll,
    isServerMethodSupported,
} = app.service('core');
const {
    confirm: showConfirmDialog,
    notice: showNoticeDialog,
} = app.service('dialogs');
const {
    createJsonBody: createExchangeJsonBody,
    createTextBody: createExchangeTextBody,
    setInspector: setExchangeInspector,
} = app.service('inspector');

function sendCustomRequest(...args) {
    return app.service('http').request(...args);
}

// ===== Secure Notepad (ECDH + canonical NOTE HTTP/WebSocket) =====
const notepadState = {
    currentId: null,
    autoSaveTimer: null,
    session_id: null,
    derivedKey: null,
    hasEcdh: false,
    initDone: false,
    available: false,
    ws: null,
    wsReconnectAttempt: 0,
    wsReconnectTimer: null,
    wsIntentionalClose: false,
    dirty: false,
    status: 'connecting',
    statusDetail: '',
    listCache: [],
    listMode: 'notes',
    editorInstanceId: 0,
    dirtyVersion: 0,
    activeSavePromise: null,
    pendingWsSaveOperations: new Map(),
    pendingWsOperations: new Map(),
    wsGeneration: 0,
    requestCounter: 0,
    pendingCreateNoteId: null,
    loadRequestSeq: 0,
    activeLoadRequestId: null,
    selectedIds: new Set(),
    lastExchangeRequest: null,
};

const NOTEPAD_HTTP_DELAY = 500;
const NOTEPAD_WS_DELAY = 300;
const NOTEPAD_WS_ACK_TIMEOUT = 5000;

const notepadTitleInput = document.getElementById('notepadTitleInput');
const notepadTextarea = document.getElementById('notepadTextarea');
const notepadSaveIndicator = document.getElementById('notepadSaveIndicator');
const notepadCharCount = document.getElementById('notepadCharCount');
const notepadNewBtnEl = document.getElementById('notepadNewBtn');
const notepadDeleteBtnEl = document.getElementById('notepadDeleteBtn');
const notepadDeleteSelectedBtnEl = document.getElementById('notepadDeleteSelectedBtn');
const notepadClearBtnEl = document.getElementById('notepadClearBtn');
const notepadRefreshBtnEl = document.getElementById('notepadRefreshBtn');
const notepadConnStatus = document.getElementById('notepadConnStatus');
const notepadConnStatusText = document.getElementById('notepadConnStatusText');
const notepadNoteListEl = document.getElementById('notepadNoteList');
const notepadTransportInputs = Array.from(document.querySelectorAll('input[name="notepadTransport"]'));

function isNotepadMethodSupported() {
    return typeof isServerMethodSupported !== 'function'
        || isServerMethodSupported('NOTE');
}

function notepadCanDeleteCurrent() {
    return notepadState.available && isNotepadMethodSupported() && Boolean(notepadState.currentId);
}

function notepadCanDeleteSelected() {
    return notepadState.available && isNotepadMethodSupported() && notepadState.selectedIds.size > 0;
}

function notepadCanClear() {
    return notepadState.available && isNotepadMethodSupported();
}

function notepadGetDeleteSelectedButtonLabel() {
    const baseLabel = t('notepadDeleteSelectedBtn');
    if (notepadState.selectedIds.size <= 0) {
        return baseLabel;
    }
    return `${baseLabel}: ${notepadState.selectedIds.size}`;
}

function notepadSyncDestructiveControls() {
    if (notepadDeleteBtnEl) {
        notepadDeleteBtnEl.disabled = !notepadCanDeleteCurrent();
    }
    if (notepadDeleteSelectedBtnEl) {
        const deleteSelectedLabel = notepadGetDeleteSelectedButtonLabel();
        notepadDeleteSelectedBtnEl.disabled = !notepadCanDeleteSelected();
        notepadDeleteSelectedBtnEl.dataset.count = String(notepadState.selectedIds.size);
        notepadDeleteSelectedBtnEl.title = deleteSelectedLabel;
        notepadDeleteSelectedBtnEl.setAttribute('aria-label', deleteSelectedLabel);
    }
    if (notepadClearBtnEl) {
        notepadClearBtnEl.disabled = !notepadCanClear();
    }
}

function refreshNotepadMethodAvailability() {
    const enabled = isNotepadMethodSupported();
    notepadTransportInputs.forEach(input => {
        if (input.value === 'ws') {
            input.disabled = !enabled;
        } else {
            input.disabled = !enabled;
        }
    });

    const tab = document.getElementById('tab-notepad');
    if (tab) {
        tab.disabled = !enabled;
    }
    if (!enabled && !notepadState.initDone) {
        notepadMarkUnavailable('unavailableServer');
    }
    if (notepadState.available && notepadState.listMode === 'notes') {
        notepadRenderList(notepadState.listCache);
    } else {
        notepadSyncDestructiveControls();
    }
}

function notepadTraceRequest(request, response = null, phase = 'sending') {
    notepadState.lastExchangeRequest = request || notepadState.lastExchangeRequest;
    setExchangeInspector('notepad', {
        phase,
        request: notepadState.lastExchangeRequest || {
            phase: 'empty',
            emptyText: t('exchangeRequestEmpty'),
        },
        response: response || {
            phase,
            startLine: t('statusPending'),
            body: createExchangeTextBody(t('statusPending')),
        },
    });
}

function notepadBuildHttpExchangeRequest(path, body = null, headers = {}) {
    return {
        transport: 'http',
        method: 'NOTE',
        path,
        headers,
        body: body ? createExchangeTextBody(body, { contentType: headers['Content-Type'] || 'application/json' }) : null,
    };
}

function notepadTraceHttpStart(path, body = null, headers = {}) {
    const request = notepadBuildHttpExchangeRequest(path, body, headers);
    notepadTraceRequest(request, {
        phase: 'sending',
        startLine: `NOTE ${path}`,
        body: createExchangeTextBody(t('statusPending')),
    });
    return request;
}

function notepadTraceHttpComplete(request, path, response, text, phase = 'complete') {
    setExchangeInspector('notepad', {
        phase,
        request,
        response: {
            transport: 'http',
            method: 'NOTE',
            path,
            phase,
            startLine: `NOTE ${path}\n${response.status} ${response.statusText || ''}`.trim(),
            status: response.status,
            statusText: response.statusText || '',
            headers: response.headers || {},
            body: createExchangeTextBody(text, { contentType: 'application/json' }),
        },
    });
}

function notepadTraceHttpError(request, path, error) {
    setExchangeInspector('notepad', {
        phase: 'error',
        request,
        response: {
            transport: 'http',
            method: 'NOTE',
            path,
            phase: 'error',
            startLine: `NOTE ${path}\n${t('error')}`,
            body: createExchangeTextBody(error.message || String(error)),
        },
    });
}

if (notepadNewBtnEl) {
    notepadNewBtnEl.addEventListener('click', () => {
        void notepadNewNote();
    });
}

if (notepadDeleteBtnEl) {
    notepadDeleteBtnEl.addEventListener('click', notepadDeleteNote);
}

if (notepadDeleteSelectedBtnEl) {
    notepadDeleteSelectedBtnEl.addEventListener('click', notepadDeleteSelectedNotes);
}

if (notepadClearBtnEl) {
    notepadClearBtnEl.addEventListener('click', notepadClearNotes);
}

if (notepadRefreshBtnEl) {
    notepadRefreshBtnEl.addEventListener('click', notepadRefreshList);
}

if (notepadNoteListEl) {
    notepadNoteListEl.addEventListener('click', (e) => {
        const noteItem = e.target.closest('.note-item[data-note-id]');
        if (!noteItem) return;

        const encodedId = noteItem.getAttribute('data-note-id');
        if (encodedId) {
            void notepadLoadNote(decodeURIComponent(encodedId), noteItem);
        }
    });

    notepadNoteListEl.addEventListener('change', (e) => {
        const selectBox = e.target.closest('[data-note-select][data-note-id]');
        if (!selectBox) return;

        const id = decodeURIComponent(selectBox.getAttribute('data-note-id') || '');
        if (!id) return;

        if (selectBox.checked) {
            notepadState.selectedIds.add(id);
        } else {
            notepadState.selectedIds.delete(id);
        }

        const row = selectBox.closest('.note-row');
        if (row) {
            row.classList.toggle('is-selected', selectBox.checked);
        }
        notepadUpdateSelectedDeleteButton();
    });
}

function notepadSetEditingEnabled(enabled) {
    notepadTitleInput.disabled = !enabled;
    notepadTextarea.disabled = !enabled;
    notepadTransportInputs.forEach(input => {
        input.disabled = !enabled;
    });
    notepadSyncDestructiveControls();
}

function notepadUpdateSelectedDeleteButton() {
    notepadSyncDestructiveControls();
}

function notepadRenderEmpty(message) {
    if (!notepadNoteListEl) {
        return;
    }
    const empty = document.createElement('div');
    empty.className = 'notepad-no-notes';
    empty.textContent = String(message || '');
    notepadNoteListEl.replaceChildren(empty);
}

function notepadRenderUnavailable(message) {
    notepadState.listMode = 'unavailable';
    notepadState.listCache = [];
    notepadRenderEmpty(message);
}

function notepadCaptureListFocus() {
    const active = document.activeElement;
    if (!notepadNoteListEl || !active || !notepadNoteListEl.contains(active)) {
        return null;
    }

    const isNoteButton = active.matches('.note-item[data-note-id]');
    const isNoteSelect = active.matches('[data-note-select][data-note-id]');
    if (!isNoteButton && !isNoteSelect) {
        return null;
    }

    const encodedId = active.getAttribute('data-note-id') || '';
    if (!encodedId) {
        return null;
    }

    return {
        encodedId,
        selector: isNoteSelect ? '[data-note-select][data-note-id]' : '.note-item[data-note-id]',
    };
}

function notepadRestoreListFocus(focusSnapshot) {
    if (!focusSnapshot || !notepadNoteListEl) {
        return;
    }

    const replacement = Array
        .from(notepadNoteListEl.querySelectorAll(focusSnapshot.selector))
        .find(element =>
            element.getAttribute('data-note-id') === focusSnapshot.encodedId &&
            !element.disabled
        );
    if (replacement) {
        focusElementWithoutScroll(replacement);
    }
}

function notepadFormatCharCount(count) {
    return count + ' ' + t('charCountSuffix');
}

function notepadFormatListDate(updatedAt) {
    if (!updatedAt) return '';
    const date = new Date(updatedAt);
    if (Number.isNaN(date.getTime())) return '';

    const now = new Date();
    const sameDay =
        date.getFullYear() === now.getFullYear() &&
        date.getMonth() === now.getMonth() &&
        date.getDate() === now.getDate();

    const locale = (document.documentElement.lang || 'ru').startsWith('ru') ? 'ru-RU' : 'en-US';
    const formatOptions = sameDay
        ? { hour: '2-digit', minute: '2-digit' }
        : { month: 'numeric', day: 'numeric', hour: '2-digit', minute: '2-digit' };

    return new Intl.DateTimeFormat(locale, formatOptions).format(date);
}

function notepadMarkDirty() {
    notepadState.dirtyVersion++;
    notepadState.dirty = true;
    document.body.classList.add('notepad-dirty');
}

function notepadMarkClean() {
    notepadState.dirty = false;
    document.body.classList.remove('notepad-dirty');
}

function notepadReplaceEditorState() {
    notepadState.editorInstanceId++;
    notepadState.activeLoadRequestId = null;
    notepadState.pendingCreateNoteId = null;
    notepadMarkClean();
    clearTimeout(notepadState.autoSaveTimer);
    notepadState.autoSaveTimer = null;
}

function notepadIsActiveLoad(loadRequestId) {
    return loadRequestId === null || loadRequestId === notepadState.activeLoadRequestId;
}

function notepadGetStatusText(state) {
    const stateKeyMap = {
        'connecting': 'notepadConnecting',
        'connected': 'notepadConnected',
        'disconnected': 'notepadDisconnected',
        'ready': 'notepadReady',
        'unsaved': 'notepadUnsaved',
        'saving': 'notepadSaving',
        'saved': 'notepadSaved',
        'loading': 'notepadLoading',
        'loaded': 'notepadLoaded',
        'cleared': 'notepadCleared',
        'selectedDeleted': 'notepadSelectedDeleted',
        'error': 'notepadSaveError',
        'loadError': 'notepadLoadError',
        'decryptError': 'notepadDecryptError',
        'sessionFailed': 'notepadSessionFailed',
        'unavailableServer': 'notepadUnavailableServer',
        'unavailableBrowser': 'notepadUnavailableBrowser',
        'reconnecting': 'notepadReconnecting',
    };
    return t(stateKeyMap[state] || state);
}

function notepadBuildStatusText(state, detail = '') {
    const baseText = notepadGetStatusText(state);
    const detailText = String(detail || '').trim();
    return detailText ? `${baseText}: ${detailText}` : baseText;
}

function notepadErrorMessageFromResponse(response, result = null) {
    const messageText = result && result.error && typeof result.error.message === 'string'
        ? result.error.message.trim()
        : '';
    const statusText = response
        ? `${response.status || ''} ${response.statusText || ''}`.trim()
        : '';

    return messageText || statusText || t('error');
}

function notepadTryParseJson(text) {
    try {
        return JSON.parse(text);
    } catch (error) {
        return null;
    }
}

function notepadMarkUnavailable(state) {
    const message = notepadGetStatusText(state);
    notepadState.available = false;
    notepadState.hasEcdh = false;
    notepadState.initDone = true;
    notepadState.session_id = null;
    notepadState.derivedKey = null;
    notepadState.currentId = null;
    notepadState.selectedIds.clear();
    notepadTitleInput.value = '';
    notepadTextarea.value = '';
    notepadCharCount.textContent = notepadFormatCharCount(0);
    notepadReplaceEditorState();
    notepadDisconnectWs(true);
    notepadSetEditingEnabled(false);
    notepadUpdateSelectedDeleteButton();
    notepadSetStatus(state);
    notepadSetConnStatus('disconnected', message);
    notepadRenderUnavailable(message);
}

function notepadGetTransport() {
    const el = document.querySelector('input[name="notepadTransport"]:checked');
    return el ? el.value : 'http';
}

function notepadGetDelay() {
    return notepadGetTransport() === 'ws' ? NOTEPAD_WS_DELAY : NOTEPAD_HTTP_DELAY;
}

// Transport toggle handlers
document.querySelectorAll('input[name="notepadTransport"]').forEach(el => {
    el.addEventListener('change', () => {
        if (!notepadState.available) return;
        if (el.value === 'ws' && el.checked) {
            notepadConnectWs();
        } else if (el.value === 'http' && el.checked) {
            notepadDisconnectWs(false);
        }
    });
});

// Auto-save on textarea input
notepadTextarea.addEventListener('input', () => {
    notepadCharCount.textContent = notepadFormatCharCount(notepadTextarea.value.length);
    notepadMarkDirty();
    notepadScheduleAutoSave();
});

// Auto-save on title input
notepadTitleInput.addEventListener('input', () => {
    notepadMarkDirty();
    notepadScheduleAutoSave();
});

function notepadScheduleAutoSave() {
    if (!notepadState.initDone) return;
    notepadSetStatus('unsaved');
    clearTimeout(notepadState.autoSaveTimer);
    notepadState.autoSaveTimer = setTimeout(notepadSave, notepadGetDelay());
}

async function notepadConfirmDirtyTransition(options = {}) {
    if (!notepadState.dirty) return true;

    clearTimeout(notepadState.autoSaveTimer);
    notepadState.autoSaveTimer = null;

    if (notepadState.activeSavePromise) {
        const activeSaved = await notepadState.activeSavePromise;
        if (activeSaved && !notepadState.dirty) {
            return true;
        }
    }

    const saved = await notepadSave({ forceHttp: true, refreshList: false });
    if (saved && !notepadState.dirty) {
        return true;
    }

    const confirmed = await showConfirmDialog({
        title: t('notepadDiscardTitle'),
        message: t('notepadDiscardConfirm'),
        details: options.details || '',
        confirmLabel: t('notepadDiscardBtn'),
        triggerEl: options.triggerEl || null,
        initialFocus: 'cancel',
    });

    if (confirmed) {
        notepadReplaceEditorState();
        clearTimeout(notepadState.autoSaveTimer);
        notepadState.autoSaveTimer = null;
        return true;
    }

    notepadSetStatus('unsaved');
    return false;
}

function notepadSetStatus(state, detail = '') {
    notepadState.status = state;
    notepadState.statusDetail = String(detail || '').trim();
    const stateClassMap = {
        'connecting': '',
        'connected': 'saved',
        'disconnected': 'error',
        'ready': '',
        'unsaved': 'unsaved',
        'saving': 'saving',
        'saved': 'saved',
        'error': 'error',
        'loading': 'saving',
        'loaded': 'saved',
        'cleared': 'saved',
        'selectedDeleted': 'saved',
        'loadError': 'error',
        'decryptError': 'error',
        'sessionFailed': 'error',
        'unavailableServer': 'error',
        'unavailableBrowser': 'error',
    };
    const stateClass = stateClassMap[state] || '';
    notepadSaveIndicator.className = 'save-indicator ' + stateClass;
    notepadSaveIndicator.textContent = notepadBuildStatusText(state, notepadState.statusDetail);
}

function notepadSetConnStatus(cls, title) {
    notepadConnStatus.className = 'notepad-connection-status ' + cls;
    notepadConnStatus.dataset.state = cls;
    notepadConnStatus.dataset.transport = notepadGetTransport();
    notepadConnStatus.title = title;
    notepadConnStatus.setAttribute('aria-label', title);
    if (notepadConnStatusText) {
        notepadConnStatusText.textContent = title;
    }
}

function notepadFocusStableControl(preferredEl = null) {
    const candidates = [
        preferredEl,
        notepadRefreshBtnEl,
        notepadNewBtnEl,
        notepadTitleInput,
    ];
    const target = candidates.find(el =>
        el &&
        el.isConnected &&
        !el.disabled &&
        typeof el.focus === 'function'
    );
    if (target) {
        target.focus();
    }
}

function notepadGetConnStatusText(connState) {
    if (notepadState.status === 'unavailableServer' || notepadState.status === 'unavailableBrowser') {
        return notepadGetStatusText(notepadState.status);
    }
    if (notepadState.status === 'reconnecting') {
        return notepadGetStatusText('reconnecting');
    }

    const connKeyMap = {
        'connecting': 'notepadConnecting',
        'connected': 'notepadConnected',
        'disconnected': 'notepadDisconnected',
    };
    return t(connKeyMap[connState] || 'notepadDisconnected');
}

function notepadRefreshLocale() {
    notepadCharCount.textContent = notepadFormatCharCount(notepadTextarea.value.length);

    if (notepadConnStatus?.dataset?.state) {
        notepadSetConnStatus(
            notepadConnStatus.dataset.state,
            notepadGetConnStatusText(notepadConnStatus.dataset.state)
        );
    }

    if (notepadState.initDone) {
        notepadSetStatus(notepadState.status, notepadState.statusDetail);
    }

    if (!notepadState.initDone) {
        return;
    }

    if (!notepadState.available) {
        notepadRenderUnavailable(notepadGetStatusText(notepadState.status));
        return;
    }

    notepadRenderList(notepadState.listCache);
}

// ── Base64 helpers ──────────────────────────────────────

function uint8ToBase64(bytes) {
    const chunks = [];
    const chunkSize = 8192;
    for (let i = 0; i < bytes.length; i += chunkSize) {
        chunks.push(String.fromCharCode.apply(null, bytes.subarray(i, i + chunkSize)));
    }
    return btoa(chunks.join(''));
}

function base64ToUint8(b64) {
    const binary = atob(b64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes;
}

// ── ECDH Session Init ───────────────────────────────────

async function notepadInit() {
    if (!isNotepadMethodSupported()) {
        notepadMarkUnavailable('unavailableServer');
        return;
    }

    if (notepadState.initDone) {
        if (notepadState.available) {
            notepadRefreshList();
        }
        return;
    }
    notepadSetStatus('connecting');
    notepadSetConnStatus('connecting', t('notepadConnecting'));

    try {
        await notepadInitSession();
        notepadState.available = true;
        notepadState.initDone = true;
        notepadSetEditingEnabled(true);
        notepadSetStatus('connected');
        notepadSetConnStatus('connected', t('notepadConnected'));
        notepadRefreshList();
    } catch (e) {
        if (e && e.message === 'server-crypto-unavailable') {
            console.warn('[Notepad] Secure Notepad unavailable on server:', e);
            notepadMarkUnavailable('unavailableServer');
        } else if (e && e.message === 'browser-crypto-unavailable') {
            console.warn('[Notepad] Secure Notepad unavailable in browser:', e);
            notepadMarkUnavailable('unavailableBrowser');
        } else {
            console.error('[Notepad] Session init failed:', e);
            notepadMarkUnavailable('sessionFailed');
        }
    }
}

async function notepadInitSession() {
    if (!window.crypto || !window.crypto.subtle) {
        throw new Error('browser-crypto-unavailable');
    }

    // 1. Get server public key
    const keyTrace = notepadTraceHttpStart('/notes/key');
    const keyResp = await sendCustomRequest('NOTE', SERVER_URL + '/notes/key');
    const keyText = await keyResp.text();
    notepadTraceHttpComplete(keyTrace, '/notes/key', keyResp, keyText, keyResp.ok ? 'complete' : 'error');
    if (!keyResp.ok) {
        throw new Error(keyResp.status === 501 ? 'server-crypto-unavailable' : 'session-init-failed');
    }
    const keyData = JSON.parse(keyText);

    if (
        !keyData.key ||
        !keyData.key.available ||
        typeof keyData.key.public_key !== 'string' ||
        !keyData.key.public_key
    ) {
        throw new Error('server-crypto-unavailable');
    }

    // 2. Generate client ECDH key pair
    const clientKeyPair = await crypto.subtle.generateKey(
        { name: 'ECDH', namedCurve: 'P-256' },
        true,
        ['deriveBits']
    );

    // 3. Exchange keys
    const clientPubRaw = await crypto.subtle.exportKey('raw', clientKeyPair.publicKey);
    const clientPubB64 = uint8ToBase64(new Uint8Array(clientPubRaw));

    const exchangeBody = JSON.stringify({ client_public_key: clientPubB64 });
    const exchangeTrace = notepadTraceHttpStart('/notes/exchange', exchangeBody, { 'Content-Type': 'application/json' });
    const exchangeResp = await sendCustomRequest('NOTE', SERVER_URL + '/notes/exchange',
        exchangeBody,
        { 'Content-Type': 'application/json' }
    );
    const exchangeText = await exchangeResp.text();
    notepadTraceHttpComplete(exchangeTrace, '/notes/exchange', exchangeResp, exchangeText, exchangeResp.ok ? 'complete' : 'error');
    if (!exchangeResp.ok) {
        throw new Error(
            exchangeResp.status === 501 ? 'server-crypto-unavailable' : 'session-init-failed'
        );
    }
    const exchangeData = JSON.parse(exchangeText);
    if (
        !exchangeData.session ||
        typeof exchangeData.session.id !== 'string' ||
        typeof exchangeData.server_public_key !== 'string'
    ) {
        throw new Error('session-init-failed');
    }
    notepadState.session_id = exchangeData.session.id;

    // 4. Import server public key
    const serverPubRaw = base64ToUint8(exchangeData.server_public_key);
    const serverPubKey = await crypto.subtle.importKey(
        'raw', serverPubRaw,
        { name: 'ECDH', namedCurve: 'P-256' },
        false,
        []
    );

    // 5. Derive shared bits
    const sharedBits = await crypto.subtle.deriveBits(
        { name: 'ECDH', public: serverPubKey },
        clientKeyPair.privateKey,
        256
    );

    // 6. HKDF to get AES-256 key
    const sharedKeyMaterial = await crypto.subtle.importKey(
        'raw', sharedBits, 'HKDF', false, ['deriveKey']
    );

    notepadState.derivedKey = await crypto.subtle.deriveKey(
        {
            name: 'HKDF',
            hash: 'SHA-256',
            salt: new Uint8Array(32),  // 32 zero bytes
            info: new TextEncoder().encode('notepad-e2e-key'),
        },
        sharedKeyMaterial,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt']
    );

    notepadState.hasEcdh = true;
}

// ── ECDH encrypt/decrypt ────────────────────────────────

async function notepadEncrypt(text) {
    const enc = new TextEncoder();
    const plaintext = enc.encode(text);
    const nonce = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: nonce },
        notepadState.derivedKey,
        plaintext
    );
    // Wire format: nonce(12) + ciphertext + tag(16)
    const result = new Uint8Array(12 + ciphertext.byteLength);
    result.set(nonce, 0);
    result.set(new Uint8Array(ciphertext), 12);
    return result;
}

async function notepadDecrypt(encryptedBytes) {
    if (encryptedBytes.length < 12 + 16) throw new Error('Data too short');
    const nonce = encryptedBytes.slice(0, 12);
    const ciphertext = encryptedBytes.slice(12);
    const plaintext = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: nonce },
        notepadState.derivedKey,
        ciphertext
    );
    return new TextDecoder().decode(plaintext);
}

// ── WebSocket client ────────────────────────────────────

function notepadRandomHex(byteCount) {
    const bytes = crypto.getRandomValues(new Uint8Array(byteCount));
    return Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('');
}

function notepadGenerateClientNoteId() {
    return notepadRandomHex(16);
}

function notepadGenerateRequestId() {
    notepadState.requestCounter++;
    return [
        Date.now().toString(36),
        notepadState.requestCounter.toString(36),
        notepadRandomHex(8),
    ].join('-');
}

function scheduleReconnect() {
    if (notepadState.wsIntentionalClose) return;
    const delay = Math.min(1000 * Math.pow(2, notepadState.wsReconnectAttempt), 30000);
    notepadState.wsReconnectAttempt++;
    notepadSetConnStatus('disconnected', t('notepadReconnecting'));
    notepadState.wsReconnectTimer = setTimeout(() => {
        if (notepadGetTransport() === 'ws' && !notepadState.wsIntentionalClose) {
            notepadConnectWs();
        }
    }, delay);
}

function notepadConnectWs() {
    if (!notepadState.available || !isNotepadMethodSupported()) return;
    notepadDisconnectWs(true);
    notepadState.wsIntentionalClose = false;
    const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsGeneration = ++notepadState.wsGeneration;
    const ws = new WebSocket(proto + '//' + location.host + '/notes/ws');
    notepadState.ws = ws;
    notepadSetConnStatus('connecting', t('notepadConnecting'));

    ws.onopen = () => {
        if (notepadState.ws !== ws || wsGeneration !== notepadState.wsGeneration) return;
        notepadState.wsReconnectAttempt = 0;
        notepadSetConnStatus('connected', t('notepadConnected'));
        notepadRetryPendingWsSaves();
    };

    ws.onmessage = (evt) => {
        if (notepadState.ws !== ws || wsGeneration !== notepadState.wsGeneration) return;
        try {
            const msg = JSON.parse(evt.data);
            notepadHandleWsMessage(msg, evt.data);
        } catch (e) {
            console.error('[Notepad WS] Parse error:', e);
        }
    };

    ws.onclose = () => {
        if (notepadState.ws !== ws || wsGeneration !== notepadState.wsGeneration) return;
        notepadState.ws = null;
        notepadFallbackPendingWsOperations();
        if (!notepadState.wsIntentionalClose && notepadGetTransport() === 'ws') {
            scheduleReconnect();
        } else if (!notepadState.wsIntentionalClose) {
            notepadSetConnStatus('disconnected', t('notepadDisconnected'));
        }
    };

    ws.onerror = () => {
        if (notepadState.ws !== ws || wsGeneration !== notepadState.wsGeneration) return;
        // onclose will fire after this
    };
}

function notepadDisconnectWs(skipStatus) {
    notepadState.wsIntentionalClose = true;
    notepadFallbackPendingWsOperations();
    if (notepadState.wsReconnectTimer) { clearTimeout(notepadState.wsReconnectTimer); notepadState.wsReconnectTimer = null; }
    notepadState.wsGeneration++;
    const ws = notepadState.ws;
    notepadState.ws = null;
    if (ws) {
        ws.close();
    }
    if (!skipStatus) {
        notepadFallbackPendingWsSaves();
        notepadSetConnStatus('connected', t('notepadConnected'));
    }
}

function notepadSendWs(msg) {
    if (notepadState.ws && notepadState.ws.readyState === WebSocket.OPEN) {
        const messageText = JSON.stringify(msg);
        notepadTraceRequest({
            transport: 'ws',
            action: msg.action,
            request_id: msg.request_id,
            path: '/notes/ws',
            body: createExchangeTextBody(messageText, { contentType: 'application/json' }),
        }, {
            transport: 'ws',
            phase: 'sending',
            path: '/notes/ws',
            body: createExchangeTextBody(t('statusPending')),
        });
        try {
            notepadState.ws.send(messageText);
            return true;
        } catch (error) {
            console.error('[Notepad WS] Send failed:', error);
            return false;
        }
    }
    return false;
}

function notepadArmWsOperationTimeout(entry) {
    if (entry.timeoutId) {
        clearTimeout(entry.timeoutId);
    }
    entry.timeoutId = setTimeout(() => {
        void notepadFallbackWsOperation(entry.request_id);
    }, NOTEPAD_WS_ACK_TIMEOUT);
}

function notepadRegisterWsOperation(action, input, options = {}) {
    const requestId = notepadGenerateRequestId();
    let resolveOperation = () => {};
    const promise = new Promise(resolve => {
        resolveOperation = resolve;
    });
    const entry = {
        action,
        input,
        request_id: requestId,
        resolve: resolveOperation,
        fallback: options.fallback,
        onSuccess: options.onSuccess,
        onError: options.onError,
        timeoutId: null,
        completed: false,
        fallbackStarted: false,
    };
    notepadState.pendingWsOperations.set(requestId, entry);
    notepadArmWsOperationTimeout(entry);
    const sent = notepadSendWs({
        action,
        request_id: requestId,
        input,
    });
    if (!sent) {
        void notepadFallbackWsOperation(requestId);
    }
    return promise;
}

function notepadGetWsOperation(requestId) {
    return requestId && notepadState.pendingWsOperations.has(requestId)
        ? notepadState.pendingWsOperations.get(requestId)
        : null;
}

function notepadCompleteWsOperation(entry, value) {
    if (!entry || entry.completed) return;
    entry.completed = true;
    if (entry.timeoutId) {
        clearTimeout(entry.timeoutId);
        entry.timeoutId = null;
    }
    notepadState.pendingWsOperations.delete(entry.request_id);
    entry.resolve(value);
}

function notepadHandleWsOperationSuccess(entry, result) {
    if (!entry || entry.completed) return;
    try {
        const value = typeof entry.onSuccess === 'function'
            ? entry.onSuccess(result)
            : true;
        notepadCompleteWsOperation(entry, value);
    } catch (error) {
        console.error('[Notepad WS] Operation result error:', error);
        notepadCompleteWsOperation(entry, false);
        notepadSetStatus('error', error.message || t('error'));
    }
}

function notepadHandleWsOperationError(entry, message) {
    if (!entry || entry.completed) return;
    try {
        const value = typeof entry.onError === 'function'
            ? entry.onError(message)
            : { ok: false, message };
        notepadCompleteWsOperation(entry, value);
    } catch (error) {
        console.error('[Notepad WS] Operation error handler failed:', error);
        notepadCompleteWsOperation(entry, false);
    }
}

async function notepadFallbackWsOperation(requestId) {
    const entry = notepadState.pendingWsOperations.get(requestId);
    if (!entry || entry.completed || entry.fallbackStarted) return;

    entry.fallbackStarted = true;
    if (entry.timeoutId) {
        clearTimeout(entry.timeoutId);
        entry.timeoutId = null;
    }
    notepadState.pendingWsOperations.delete(requestId);

    let value = false;
    try {
        value = typeof entry.fallback === 'function'
            ? await entry.fallback()
            : false;
    } catch (error) {
        console.error('[Notepad] WebSocket HTTP fallback error:', error);
        notepadSetStatus('error', error.message || t('error'));
    }
    entry.completed = true;
    entry.resolve(value);
}

function notepadFallbackPendingWsOperations() {
    for (const requestId of Array.from(notepadState.pendingWsOperations.keys())) {
        void notepadFallbackWsOperation(requestId);
    }
}

function notepadCaptureSaveSnapshot() {
    const titleRaw = notepadTitleInput.value.trim();
    const id = notepadState.currentId || notepadState.pendingCreateNoteId || '';
    return {
        editorInstanceId: notepadState.editorInstanceId,
        dirtyVersion: notepadState.dirtyVersion,
        id,
        create_if_missing: Boolean(!notepadState.currentId && id),
        titleRaw,
        title: titleRaw || t('notepadUntitled'),
        text: notepadTextarea.value,
        session_id: notepadState.session_id || '',
    };
}

function notepadPrepareSaveSnapshot(snapshot) {
    if (snapshot.id) {
        return {
            ...snapshot,
            create_if_missing: Boolean(!notepadState.currentId && snapshot.id === notepadState.pendingCreateNoteId),
        };
    }

    const id = notepadGenerateClientNoteId();
    notepadState.pendingCreateNoteId = id;
    return {
        ...snapshot,
        id,
        create_if_missing: true,
    };
}

function notepadArmWsSaveTimeout(entry) {
    if (entry.timeoutId) {
        clearTimeout(entry.timeoutId);
    }
    entry.timeoutId = setTimeout(() => {
        void notepadFallbackWsSave(entry.request_id);
    }, NOTEPAD_WS_ACK_TIMEOUT);
}

function notepadRegisterPendingWsSave(requestId, snapshot, payload, options) {
    let resolveSave = () => {};
    const promise = new Promise(resolve => {
        resolveSave = resolve;
    });
    const entry = {
        request_id: requestId,
        snapshot,
        payload,
        options,
        resolve: resolveSave,
        timeoutId: null,
        completed: false,
        fallbackStarted: false,
    };
    notepadState.pendingWsSaveOperations.set(requestId, entry);
    notepadArmWsSaveTimeout(entry);
    return promise;
}

function notepadGetPendingWsSaveEntry(requestId) {
    return requestId && notepadState.pendingWsSaveOperations.has(requestId)
        ? notepadState.pendingWsSaveOperations.get(requestId)
        : null;
}

function notepadCompletePendingWsSave(entry, success) {
    if (!entry || entry.completed) return;
    entry.completed = true;
    if (entry.timeoutId) {
        clearTimeout(entry.timeoutId);
        entry.timeoutId = null;
    }
    notepadState.pendingWsSaveOperations.delete(entry.request_id);
    entry.resolve(Boolean(success));
}

function notepadRetryPendingWsSaves() {
    for (const entry of Array.from(notepadState.pendingWsSaveOperations.values())) {
        if (entry.completed || entry.fallbackStarted) continue;
        notepadArmWsSaveTimeout(entry);
        const sent = notepadSendWs(entry.payload);
        if (!sent) {
            void notepadFallbackWsSave(entry.request_id);
        }
    }
}

function notepadFallbackPendingWsSaves() {
    for (const requestId of Array.from(notepadState.pendingWsSaveOperations.keys())) {
        void notepadFallbackWsSave(requestId);
    }
}

async function notepadFallbackWsSave(requestId) {
    const entry = notepadState.pendingWsSaveOperations.get(requestId);
    if (!entry || entry.completed || entry.fallbackStarted) return;

    entry.fallbackStarted = true;
    if (entry.timeoutId) {
        clearTimeout(entry.timeoutId);
        entry.timeoutId = null;
    }
    notepadState.pendingWsSaveOperations.delete(requestId);

    let success = false;
    try {
        success = await notepadSaveSnapshotViaHttp(
            entry.snapshot,
            entry.payload.input.data,
            entry.options
        );
    } catch (error) {
        console.error('[Notepad] Save fallback error:', error);
        notepadSetStatus('error', error.message);
    }
    entry.completed = true;
    entry.resolve(success);
}

function notepadApplySaveSuccess(snapshot, result, options = {}) {
    const sameEditor = snapshot && snapshot.editorInstanceId === notepadState.editorInstanceId;

    if (sameEditor) {
        if (!notepadState.currentId && result.id) {
            notepadState.currentId = result.id;
        }
        if (notepadState.pendingCreateNoteId && result.id === notepadState.pendingCreateNoteId) {
            notepadState.pendingCreateNoteId = null;
        }
        notepadSyncDestructiveControls();

        if (snapshot.dirtyVersion === notepadState.dirtyVersion) {
            notepadMarkClean();
            notepadSetStatus('saved');
        } else if (notepadState.dirty) {
            notepadSetStatus('unsaved');
        }
    }

    if (options.refreshList !== false) {
        notepadRefreshList();
    }
}

function notepadHandleWsMessage(msg, rawText = '') {
    const isObject = msg && typeof msg === 'object' && !Array.isArray(msg);
    const phase = isObject && msg.error ? 'error' : 'complete';
    setExchangeInspector('notepad', {
        phase,
        request: notepadState.lastExchangeRequest || {
            transport: 'ws',
            action: null,
            request_id: null,
            path: '/notes/ws',
            body: null,
        },
        response: {
            transport: 'ws',
            action: isObject ? msg.action : null,
            request_id: isObject ? msg.request_id : null,
            path: '/notes/ws',
            phase,
            body: createExchangeJsonBody(msg, { rawText }),
        },
    });

    if (!isObject) {
        notepadSetStatus('error', t('error'));
        return;
    }

    const requestId = typeof msg.request_id === 'string' ? msg.request_id : '';
    if (msg.error) {
        if (msg.action === 'save') {
            const entry = notepadGetPendingWsSaveEntry(requestId);
            if (entry) {
                notepadCompletePendingWsSave(entry, false);
            }
        }
        const operationEntry = notepadGetWsOperation(requestId);
        if (operationEntry && operationEntry.action === msg.action) {
            notepadHandleWsOperationError(
                operationEntry,
                typeof msg.error.message === 'string' && msg.error.message
                    ? msg.error.message
                    : t('error')
            );
        }
        const message = typeof msg.error.message === 'string' && msg.error.message
            ? msg.error.message
            : t('error');
        console.error('[Notepad WS] Server error:', message);
        notepadSetStatus('error', message);
        return;
    }

    if (!msg.result || typeof msg.result !== 'object' || Array.isArray(msg.result)) {
        notepadSetStatus('error', t('error'));
        return;
    }

    if (msg.action === 'save') {
        const entry = notepadGetPendingWsSaveEntry(requestId);
        if (entry && msg.result.note) {
            notepadApplySaveSuccess(entry.snapshot, msg.result.note, entry.options);
            notepadCompletePendingWsSave(entry, true);
        }
        return;
    }

    const operationEntry = notepadGetWsOperation(requestId);
    if (!operationEntry || operationEntry.action !== msg.action) {
        return;
    }
    if (msg.action === 'load') {
        notepadHandleWsOperationSuccess(operationEntry, msg.result);
    } else if (msg.action === 'list') {
        if (Array.isArray(msg.result.notes)) {
            notepadHandleWsOperationSuccess(operationEntry, msg.result);
        } else {
            notepadHandleWsOperationError(operationEntry, t('error'));
        }
    } else if (msg.action === 'delete') {
        notepadHandleWsOperationSuccess(operationEntry, msg.result);
    } else if (msg.action === 'clear') {
        notepadHandleWsOperationSuccess(operationEntry, msg.result);
    }
}

// ── CRUD operations ─────────────────────────────────────

async function notepadSave(options = {}) {
    const savePromise = notepadRunSave(options);
    notepadState.activeSavePromise = savePromise;
    try {
        return await savePromise;
    } finally {
        if (notepadState.activeSavePromise === savePromise) {
            notepadState.activeSavePromise = null;
        }
    }
}

async function notepadSaveSnapshotViaHttp(snapshot, dataB64, options = {}) {
    const payload = { title: snapshot.title, data: dataB64 };
    if (snapshot.id) payload.id = snapshot.id;
    if (snapshot.create_if_missing) payload.create_if_missing = true;
    if (snapshot.session_id) payload.session_id = snapshot.session_id;

    const headers = { 'Content-Type': 'application/json' };
    const path = '/notes?action=save';
    const body = JSON.stringify(payload);
    const trace = notepadTraceHttpStart(path, body, headers);
    const response = await sendCustomRequest('NOTE', SERVER_URL + path, body, headers);
    const respText = await response.text();
    notepadTraceHttpComplete(trace, path, response, respText, response.ok ? 'complete' : 'error');
    const result = notepadTryParseJson(respText);

    if (response.ok && result && result.note) {
        notepadApplySaveSuccess(snapshot, result.note, options);
        return true;
    }

    notepadSetStatus('error', notepadErrorMessageFromResponse(response, result));
    return false;
}

async function notepadRunSave(options = {}) {
    if (!notepadState.available || !notepadState.derivedKey) {
        notepadSetStatus('sessionFailed');
        return false;
    }
    clearTimeout(notepadState.autoSaveTimer);
    notepadState.autoSaveTimer = null;

    const snapshot = notepadCaptureSaveSnapshot();

    if (!snapshot.text && !snapshot.titleRaw && !snapshot.id) return false;

    notepadSetStatus('saving');

    try {
        const encrypted = await notepadEncrypt(snapshot.text);
        const dataB64 = uint8ToBase64(encrypted);
        const preparedSnapshot = notepadPrepareSaveSnapshot(snapshot);

        if (!options.forceHttp && notepadGetTransport() === 'ws' && notepadState.ws && notepadState.ws.readyState === WebSocket.OPEN) {
            const requestId = notepadGenerateRequestId();
            const wsPayload = {
                action: 'save',
                request_id: requestId,
                input: {
                    id: preparedSnapshot.id,
                    create_if_missing: preparedSnapshot.create_if_missing,
                    session_id: preparedSnapshot.session_id,
                    title: preparedSnapshot.title,
                    data: dataB64,
                },
            };
            const pendingSave = notepadRegisterPendingWsSave(requestId, preparedSnapshot, wsPayload, options);
            if (!notepadSendWs(wsPayload)) {
                void notepadFallbackWsSave(requestId);
            }
            return await pendingSave;
        }

        return await notepadSaveSnapshotViaHttp(preparedSnapshot, dataB64, options);
    } catch (e) {
        console.error('[Notepad] Save error:', e);
        notepadSetStatus('error', e.message);
        return false;
    }
}

async function notepadRefreshList(options = {}) {
    if (!notepadState.available) return;
    if (!options.forceHttp && notepadGetTransport() === 'ws' && notepadState.ws && notepadState.ws.readyState === WebSocket.OPEN) {
        void notepadRegisterWsOperation('list', {}, {
            fallback: () => notepadRefreshList({ forceHttp: true }),
            onSuccess: result => {
                if (!result || !Array.isArray(result.notes)) {
                    notepadSetStatus('loadError');
                    return false;
                }
                notepadRenderList(result.notes);
                return true;
            },
            onError: message => {
                notepadSetStatus('loadError', message);
                return false;
            },
        });
        return;
    }

    try {
        const path = '/notes?action=list';
        const trace = notepadTraceHttpStart(path);
        const response = await sendCustomRequest('NOTE', SERVER_URL + path);
        const text = await response.text();
        notepadTraceHttpComplete(trace, path, response, text, response.ok ? 'complete' : 'error');
        const result = notepadTryParseJson(text);
        if (!response.ok) {
            notepadSetStatus('loadError', notepadErrorMessageFromResponse(response, result));
            return;
        }
        if (!result || !Array.isArray(result.notes)) {
            notepadSetStatus('loadError');
            return;
        }
        notepadRenderList(result.notes);
    } catch (e) {
        console.error('[Notepad] List error:', e);
        notepadSetStatus('loadError', e.message);
    }
}

function notepadRenderList(notes) {
    notepadState.listMode = 'notes';
    notepadState.listCache = Array.isArray(notes) ? notes : [];
    const focusSnapshot = notepadCaptureListFocus();
    if (!notes || notes.length === 0) {
        notepadState.selectedIds.clear();
        notepadUpdateSelectedDeleteButton();
        notepadRenderEmpty(t('notepadNoNotes'));
        return;
    }

    const visibleIds = new Set(notes.map(note => note.id).filter(Boolean));
    Array.from(notepadState.selectedIds).forEach(id => {
        if (!visibleIds.has(id)) {
            notepadState.selectedIds.delete(id);
        }
    });
    notepadUpdateSelectedDeleteButton();

    const deleteEnabled = isNotepadMethodSupported();
    const fragment = document.createDocumentFragment();
    notes.forEach(note => {
        const isActive = note.id === notepadState.currentId;
        const isSelected = deleteEnabled && notepadState.selectedIds.has(note.id);
        const date = notepadFormatListDate(note.updated_at);
        const encodedId = encodeURIComponent(note.id);
        const title = String(note.title || t('notepadUntitled'));
        const selectLabel = `${t('selectNoteLabel')}: ${title}`;

        const row = document.createElement('div');
        row.className = `note-row${isActive ? ' active' : ''}${isSelected ? ' is-selected' : ''}`;

        const select = document.createElement('label');
        select.className = 'note-select';
        select.title = selectLabel;
        select.setAttribute('aria-label', selectLabel);
        const checkbox = document.createElement('input');
        checkbox.type = 'checkbox';
        checkbox.dataset.noteSelect = '';
        checkbox.setAttribute('data-note-id', encodedId);
        checkbox.checked = isSelected;
        checkbox.disabled = !deleteEnabled;
        select.appendChild(checkbox);
        const marker = document.createElement('span');
        marker.setAttribute('aria-hidden', 'true');
        select.appendChild(marker);
        row.appendChild(select);

        const noteButton = document.createElement('button');
        noteButton.type = 'button';
        noteButton.className = `note-item${isActive ? ' active' : ''}`;
        noteButton.setAttribute('data-note-id', encodedId);
        if (isActive) {
            noteButton.setAttribute('aria-current', 'true');
        }
        const titleEl = document.createElement('div');
        titleEl.className = 'note-item-title';
        titleEl.textContent = title;
        noteButton.appendChild(titleEl);
        const dateEl = document.createElement('div');
        dateEl.className = 'note-item-date';
        dateEl.textContent = date;
        noteButton.appendChild(dateEl);
        row.appendChild(noteButton);
        fragment.appendChild(row);
    });
    notepadNoteListEl.replaceChildren(fragment);
    notepadRestoreListFocus(focusSnapshot);
}

async function notepadLoadNote(id, triggerEl = null) {
    if (!notepadState.available || !notepadState.derivedKey) {
        notepadSetStatus('sessionFailed');
        return;
    }
    if (id === notepadState.currentId) {
        return;
    }

    if (notepadState.dirty) {
        const targetNote = notepadState.listCache.find(note => note.id === id);
        const canReplaceEditor = await notepadConfirmDirtyTransition({
            triggerEl,
            details: targetNote ? (targetNote.title || t('notepadUntitled')) : id,
        });
        if (!canReplaceEditor) return;
    }

    notepadSetStatus('loading');
    const loadRequestId = ++notepadState.loadRequestSeq;
    notepadState.activeLoadRequestId = loadRequestId;

    if (notepadGetTransport() === 'ws' && notepadState.ws && notepadState.ws.readyState === WebSocket.OPEN) {
        void notepadRegisterWsOperation('load', { id }, {
            fallback: () => notepadLoadNoteViaHttp(id, loadRequestId),
            onSuccess: result => {
                void notepadHandleWsLoadResult(result, { loadRequestId });
                return true;
            },
            onError: message => {
                if (notepadIsActiveLoad(loadRequestId)) {
                    notepadSetStatus('loadError', message);
                }
                return false;
            },
        });
        return;
    }

    await notepadLoadNoteViaHttp(id, loadRequestId);
}

async function notepadLoadNoteViaHttp(id, loadRequestId) {

    try {
        const path = '/notes/' + id + '?action=load';
        const trace = notepadTraceHttpStart(path);
        const response = await sendCustomRequest('NOTE', SERVER_URL + path);
        const text = await response.text();
        notepadTraceHttpComplete(trace, path, response, text, response.ok ? 'complete' : 'error');
        const result = notepadTryParseJson(text);

        if (!notepadIsActiveLoad(loadRequestId)) {
            return;
        }

        if (!response.ok) {
            notepadSetStatus('loadError', notepadErrorMessageFromResponse(response, result));
            return;
        }

        await notepadHandleHttpLoadResult(result, { loadRequestId });
    } catch (e) {
        if (!notepadIsActiveLoad(loadRequestId)) {
            return;
        }
        console.error('[Notepad] Load error:', e);
        notepadSetStatus('loadError', e.message);
    }
}

async function notepadApplyLoadResult(note, data, options = {}) {
    try {
        if (!notepadState.available || !notepadState.derivedKey) {
            notepadSetStatus('sessionFailed');
            return;
        }
        const loadRequestId = options.loadRequestId || null;
        if (!notepadIsActiveLoad(loadRequestId)) {
            return;
        }

        const encryptedBytes = base64ToUint8(data);
        const plaintext = await notepadDecrypt(encryptedBytes);
        if (!notepadIsActiveLoad(loadRequestId) || notepadState.dirty) {
            return;
        }

        notepadReplaceEditorState();
        notepadState.currentId = note.id;
        notepadTitleInput.value = note.title || '';
        notepadTextarea.value = plaintext;
        notepadCharCount.textContent = notepadFormatCharCount(plaintext.length);
        notepadSyncDestructiveControls();
        notepadSetStatus('loaded');
        notepadRefreshList();
    } catch (e) {
        console.error('[Notepad] Decrypt/load error:', e);
        if (e.name === 'OperationError' || (e.message && e.message.includes('decrypt'))) {
            notepadSetStatus('decryptError', e.message);
        } else {
            notepadSetStatus('loadError', e.message);
        }
    }
}

async function notepadHandleHttpLoadResult(result, options = {}) {
    if (!result || !result.note) {
        notepadSetStatus('loadError');
        return;
    }
    await notepadApplyLoadResult(result.note, result.data, options);
}

async function notepadHandleWsLoadResult(result, options = {}) {
    if (!result || !result.note) {
        notepadSetStatus('loadError');
        return;
    }
    await notepadApplyLoadResult(result.note, result.data, options);
}

function notepadApplyNewNoteState() {
    notepadReplaceEditorState();
    notepadState.currentId = null;
    notepadTitleInput.value = '';
    notepadTextarea.value = '';
    notepadCharCount.textContent = notepadFormatCharCount(0);
    notepadSyncDestructiveControls();
    if (!notepadState.initDone) {
        notepadSetStatus('connecting');
    } else if (!notepadState.available) {
        notepadSetStatus('sessionFailed');
    } else {
        notepadSetStatus('ready');
        notepadTitleInput.focus();
    }
    notepadRefreshList();
}

async function notepadNewNote(options = {}) {
    if (!options.skipDirtyGuard && notepadState.dirty) {
        const canReplaceEditor = await notepadConfirmDirtyTransition({
            triggerEl: options.triggerEl || notepadNewBtnEl,
            details: notepadTitleInput.value.trim() || t('notepadUntitled'),
        });
        if (!canReplaceEditor) return false;
    }

    notepadApplyNewNoteState();
    return true;
}

async function notepadDeleteNoteViaHttp(id, noteTitle) {
    try {
        const path = '/notes/' + id + '?action=delete';
        const trace = notepadTraceHttpStart(path);
        const response = await sendCustomRequest('NOTE', SERVER_URL + path);
        const text = await response.text();
        notepadTraceHttpComplete(trace, path, response, text, response.ok ? 'complete' : 'error');
        const result = notepadTryParseJson(text);

        if (response.ok && result && result.deleted_note && result.deleted_note.id === id) {
            if (notepadState.currentId === id) {
                notepadApplyNewNoteState();
            } else {
                await notepadRefreshList({ forceHttp: true });
            }
            return true;
        }

        const message = notepadErrorMessageFromResponse(response, result);
        notepadSetStatus('error', message);
        await showNoticeDialog({
            title: t('notepadDeleteError'),
            message,
            details: noteTitle,
            triggerEl: notepadDeleteBtnEl,
        });
        return false;
    } catch (e) {
        console.error('[Notepad] Delete error:', e);
        notepadSetStatus('error', e.message);
        await showNoticeDialog({
            title: t('notepadDeleteError'),
            message: e.message,
            details: noteTitle,
            triggerEl: notepadDeleteBtnEl,
        });
        return false;
    }
}

async function notepadDeleteNote() {
    if (!notepadCanDeleteCurrent()) return;
    const noteTitle = notepadTitleInput.value.trim() || t('notepadUntitled');
    const confirmed = await showConfirmDialog({
        title: t('notepadDeleteBtn'),
        message: t('notepadDeleteConfirm'),
        details: noteTitle,
        confirmLabel: t('notepadDeleteBtn'),
        triggerEl: notepadDeleteBtnEl,
        initialFocus: 'cancel',
    });
    if (!confirmed) return;

    const id = notepadState.currentId;
    if (notepadGetTransport() === 'ws' && notepadState.ws && notepadState.ws.readyState === WebSocket.OPEN) {
        void notepadRegisterWsOperation('delete', { id }, {
            fallback: () => notepadDeleteNoteViaHttp(id, noteTitle),
            onSuccess: result => {
                if (!result || !result.deleted_note || result.deleted_note.id !== id) {
                    notepadSetStatus('error', t('error'));
                    return false;
                }
                if (notepadState.currentId === id) {
                    notepadApplyNewNoteState();
                } else {
                    void notepadRefreshList();
                }
                return true;
            },
            onError: message => {
                notepadSetStatus('error', message);
                void showNoticeDialog({
                    title: t('notepadDeleteError'),
                    message,
                    details: noteTitle,
                    triggerEl: notepadDeleteBtnEl,
                });
                return false;
            },
        });
        return;
    }

    await notepadDeleteNoteViaHttp(id, noteTitle);
}

function notepadResetEditorAfterDelete() {
    notepadReplaceEditorState();
    notepadState.currentId = null;
    notepadTitleInput.value = '';
    notepadTextarea.value = '';
    notepadCharCount.textContent = notepadFormatCharCount(0);
    notepadSyncDestructiveControls();
}

async function notepadDeleteSelectedOneViaHttp(id) {
    try {
        const path = '/notes/' + id + '?action=delete';
        const trace = notepadTraceHttpStart(path);
        const response = await sendCustomRequest('NOTE', SERVER_URL + path);
        const text = await response.text();
        notepadTraceHttpComplete(trace, path, response, text, response.ok ? 'complete' : 'error');
        const result = notepadTryParseJson(text);
        if (response.ok && result && result.deleted_note && result.deleted_note.id === id) {
            return { ok: true };
        }
        return { ok: false, message: notepadErrorMessageFromResponse(response, result) };
    } catch (e) {
        console.error('[Notepad] Selected delete error:', e);
        return { ok: false, message: e.message || t('error') };
    }
}

function notepadDeleteSelectedOneViaWs(id) {
    return notepadRegisterWsOperation('delete', { id }, {
        fallback: () => notepadDeleteSelectedOneViaHttp(id),
        onSuccess: result => {
            if (result && result.deleted_note && result.deleted_note.id === id) {
                return { ok: true };
            }
            return { ok: false, message: t('error') };
        },
        onError: message => ({ ok: false, message }),
    });
}

async function notepadDeleteSelectedNotes() {
    if (!notepadCanDeleteSelected()) return;

    const selectedIds = Array.from(notepadState.selectedIds);
    const selectedTitles = selectedIds.map(id => {
        const note = notepadState.listCache.find(item => item.id === id);
        return note ? (note.title || t('notepadUntitled')) : id;
    });

    const confirmed = await showConfirmDialog({
        title: t('notepadDeleteSelectedBtn'),
        message: t('notepadDeleteSelectedConfirm'),
        details: selectedTitles.join('\n'),
        confirmLabel: t('notepadDeleteSelectedBtn'),
        triggerEl: notepadDeleteSelectedBtnEl,
        initialFocus: 'cancel',
    });
    if (!confirmed) return;

    const deletedCurrent = selectedIds.includes(notepadState.currentId);
    const errors = [];

    for (const id of selectedIds) {
        const outcome = notepadGetTransport() === 'ws' &&
            notepadState.ws &&
            notepadState.ws.readyState === WebSocket.OPEN
            ? await notepadDeleteSelectedOneViaWs(id)
            : await notepadDeleteSelectedOneViaHttp(id);

        if (outcome && outcome.ok) {
                notepadState.selectedIds.delete(id);
        } else {
            errors.push(`${id}: ${outcome && outcome.message ? outcome.message : t('error')}`);
        }
    }

    if (deletedCurrent) {
        notepadResetEditorAfterDelete();
    }
    notepadUpdateSelectedDeleteButton();
    await notepadRefreshList();

    if (errors.length) {
        notepadSetStatus('error', errors.join('; '));
        await showNoticeDialog({
            title: t('notepadDeleteError'),
            message: errors.join('\n'),
            details: t('notepadDeleteSelectedBtn'),
            triggerEl: notepadDeleteSelectedBtnEl,
        });
        return;
    }

    notepadSetStatus('selectedDeleted');
    notepadFocusStableControl(notepadRefreshBtnEl);
}

function notepadCompleteClear(options = {}) {
    notepadState.selectedIds.clear();
    notepadUpdateSelectedDeleteButton();
    notepadResetEditorAfterDelete();
    notepadRenderList([]);
    notepadSetStatus('cleared');
    if (options.focus) {
        notepadFocusStableControl(notepadRefreshBtnEl);
    }
    return true;
}

function notepadApplyClearResult(result, options = {}) {
    if (!result || !result.cleared_notes) return false;
    return notepadCompleteClear(options);
}

async function notepadClearNotesViaHttp() {
    try {
        const path = '/notes?action=clear';
        const trace = notepadTraceHttpStart(path);
        const response = await sendCustomRequest('NOTE', SERVER_URL + path);
        const text = await response.text();
        notepadTraceHttpComplete(trace, path, response, text, response.ok ? 'complete' : 'error');
        const result = notepadTryParseJson(text);

        if (response.ok && notepadApplyClearResult(result, { focus: true })) {
            return true;
        }

        const message = notepadErrorMessageFromResponse(response, result);
        notepadSetStatus('error', message);
        await showNoticeDialog({
            title: t('notepadClearError'),
            message,
            details: '/notes',
            triggerEl: notepadClearBtnEl,
        });
        return false;
    } catch (e) {
        console.error('[Notepad] Clear error:', e);
        notepadSetStatus('error', e.message);
        await showNoticeDialog({
            title: t('notepadClearError'),
            message: e.message,
            details: '/notes',
            triggerEl: notepadClearBtnEl,
        });
        return false;
    }
}

async function notepadClearNotes() {
    if (!notepadCanClear()) return;

    const confirmed = await showConfirmDialog({
        title: t('notepadClearBtn'),
        message: t('notepadClearConfirm'),
        details: '/notes',
        confirmLabel: t('notepadClearBtn'),
        triggerEl: notepadClearBtnEl,
        initialFocus: 'cancel',
    });
    if (!confirmed) return;

    if (notepadGetTransport() === 'ws' && notepadState.ws && notepadState.ws.readyState === WebSocket.OPEN) {
        void notepadRegisterWsOperation('clear', {}, {
            fallback: () => notepadClearNotesViaHttp(),
            onSuccess: result => {
                if (notepadApplyClearResult(result, { focus: true })) {
                    return true;
                }
                notepadSetStatus('error', t('error'));
                return false;
            },
            onError: message => {
                notepadSetStatus('error', message);
                void showNoticeDialog({
                    title: t('notepadClearError'),
                    message,
                    details: '/notes',
                    triggerEl: notepadClearBtnEl,
                });
                return false;
            },
        });
        return;
    }

    await notepadClearNotesViaHttp();
}

app.on(app.events.LOCALE_CHANGED, notepadRefreshLocale);
app.on(app.events.SERVER_METHODS_CHANGED, refreshNotepadMethodAvailability);
app.on(app.events.WORKSPACE_CHANGED, ({ workspace }) => {
    if (workspace === 'notepad') {
        void notepadInit();
    }
});

app.registerWorkflow('notepad', {
    commands: {
        init: notepadInit,
        save: notepadSave,
        refresh: notepadRefreshList,
        'new-note': notepadNewNote,
        'delete-note': notepadDeleteNote,
        'delete-selected': notepadDeleteSelectedNotes,
        'clear-notes': notepadClearNotes,
        'refresh-methods': refreshNotepadMethodAvailability,
    },
    getState: () => ({
        available: notepadState.available,
        initialized: notepadState.initDone,
        dirty: notepadState.dirty,
        status: notepadState.status,
        listMode: notepadState.listMode,
        noteCount: notepadState.listCache.length,
        selectedCount: notepadState.selectedIds.size,
        hasCurrentNote: Boolean(notepadState.currentId),
        websocketConnected: Boolean(
            notepadState.ws && notepadState.ws.readyState === WebSocket.OPEN
        ),
        wsGeneration: notepadState.wsGeneration,
        loadRequestSequence: notepadState.loadRequestSeq,
    }),
});
})(window.XferryApp);
