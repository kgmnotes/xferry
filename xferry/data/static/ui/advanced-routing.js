(function initializeAdvancedSession(app) {
    'use strict';

const {
    t,
    serverUrl: SERVER_URL,
} = app.service('core');

const CREATE_URL = new URL('/_xferry/advanced-sessions', SERVER_URL || location.href).toString();
const CURRENT_URL = new URL(
    '/_xferry/advanced-sessions/current',
    SERVER_URL || location.href
).toString();
const TOKEN_PATTERN = /^[A-Za-z0-9_-]{43}$/;
const DECODERS = new Set(['auto', 'raw', 'json', 'text', 'form', 'xml', 'multipart']);
const listeners = new Set();

// Security boundary: the bearer is held only by this closure. It is copied
// only into a transient header object immediately before a control/data send.
let activeToken = null;
let metadata = null;
let phase = 'inactive';
let safeError = '';
let createOperation = null;
let lifecycleGeneration = 0;
let expiryTimer = null;

const MAX_TIMER_DELAY = 2147483647;

const panel = document.getElementById('advancedSessionPanel');
const prefixInput = document.getElementById('advancedSessionPrefixInput');
const decoderSelect = document.getElementById('advancedSessionDecoderSelect');
const diagnosticHeadersInput = document.getElementById('advancedSessionDiagnosticHeaders');
const createButton = document.getElementById('advancedSessionCreateBtn');
const revokeButton = document.getElementById('advancedSessionRevokeBtn');
const statusOutput = document.getElementById('advancedSessionStatus');
const expiresOutput = document.getElementById('advancedSessionExpiresOutput');

function responseErrorMessage(response, payload) {
    const message = String(payload?.error?.message || '').trim();
    return message
        ? `${response.status}: ${message}`
        : `${response.status}${response.statusText ? ` ${response.statusText}` : ''}`;
}

function sanitizeError(error, secret = activeToken) {
    let message = String(error?.message || error || t('advancedSessionError'));
    if (secret) {
        message = message.replaceAll(secret, '[REDACTED]');
    }
    return message.slice(0, 300);
}

function validateMetadata(value, { tokenRequired = false } = {}) {
    if (!value || typeof value !== 'object' || Array.isArray(value)) {
        throw new TypeError(t('advancedSessionInvalidResponse'));
    }
    const token = value.token;
    if (tokenRequired && (typeof token !== 'string' || !TOKEN_PATTERN.test(token))) {
        throw new TypeError(t('advancedSessionInvalidResponse'));
    }
    if (
        typeof value.prefix !== 'string'
        || !value.prefix.startsWith('/')
        || !DECODERS.has(value.decoder)
        || typeof value.diagnostic_headers !== 'boolean'
        || typeof value.created_at !== 'string'
        || typeof value.expires_at !== 'string'
        || !Number.isFinite(Date.parse(value.created_at))
        || !Number.isFinite(Date.parse(value.expires_at))
        || !Number.isInteger(value.idle_timeout_seconds)
        || value.idle_timeout_seconds <= 0
    ) {
        throw new TypeError(t('advancedSessionInvalidResponse'));
    }
    return {
        prefix: value.prefix,
        decoder: value.decoder,
        diagnostic_headers: value.diagnostic_headers,
        created_at: value.created_at,
        expires_at: value.expires_at,
        expires_at_ms: Date.parse(value.expires_at),
        idle_timeout_seconds: value.idle_timeout_seconds,
    };
}

function cancelExpiryTimer() {
    if (expiryTimer !== null) {
        clearTimeout(expiryTimer);
        expiryTimer = null;
    }
}

function clearLocalSession() {
    cancelExpiryTimer();
    activeToken = null;
    metadata = null;
    phase = 'inactive';
}

function expireLocalSession(expectedGeneration, expectedToken) {
    if (
        lifecycleGeneration !== expectedGeneration
        || activeToken !== expectedToken
        || !metadata
    ) {
        return;
    }
    if (metadata.expires_at_ms > Date.now()) {
        scheduleExpiry(expectedGeneration, expectedToken);
        return;
    }
    lifecycleGeneration += 1;
    clearLocalSession();
    safeError = '';
    publish();
}

function scheduleExpiry(expectedGeneration, expectedToken) {
    cancelExpiryTimer();
    if (
        lifecycleGeneration !== expectedGeneration
        || activeToken !== expectedToken
        || !metadata
    ) {
        return false;
    }
    const delay = metadata.expires_at_ms - Date.now();
    if (delay <= 0) {
        expireLocalSession(expectedGeneration, expectedToken);
        return false;
    }
    expiryTimer = setTimeout(
        () => expireLocalSession(expectedGeneration, expectedToken),
        Math.min(delay, MAX_TIMER_DELAY)
    );
    return true;
}

function getSnapshot() {
    return Object.freeze({
        active: Boolean(activeToken && metadata),
        phase,
        error: safeError,
        prefix: metadata?.prefix || null,
        decoder: metadata?.decoder || null,
        diagnostic_headers: metadata?.diagnostic_headers === true,
        created_at: metadata?.created_at || null,
        expires_at: metadata?.expires_at || null,
        idle_timeout_seconds: metadata?.idle_timeout_seconds || null,
    });
}

function render() {
    const snapshot = getSnapshot();
    const busy = snapshot.phase === 'creating' || snapshot.phase === 'checking';
    if (panel) {
        panel.dataset.sessionPhase = snapshot.phase;
        panel.setAttribute('aria-busy', String(busy));
    }
    if (createButton) {
        createButton.disabled = busy || snapshot.active;
    }
    if (revokeButton) {
        revokeButton.disabled = busy || !snapshot.active;
    }
    if (prefixInput) {
        prefixInput.disabled = busy || snapshot.active;
    }
    if (decoderSelect) {
        decoderSelect.disabled = busy || snapshot.active;
    }
    if (diagnosticHeadersInput) {
        diagnosticHeadersInput.disabled = busy || snapshot.active;
    }
    if (statusOutput) {
        if (snapshot.phase === 'creating') {
            statusOutput.textContent = t('advancedSessionCreating');
        } else if (snapshot.phase === 'checking') {
            statusOutput.textContent = t('advancedSessionChecking');
        } else if (snapshot.active) {
            statusOutput.textContent = t('advancedSessionActive');
        } else if (snapshot.error) {
            statusOutput.textContent = `${t('advancedSessionInactive')} ${snapshot.error}`;
        } else {
            statusOutput.textContent = t('advancedSessionInactive');
        }
    }
    if (expiresOutput) {
        expiresOutput.textContent = snapshot.expires_at || '-';
    }
}

function publish() {
    render();
    const snapshot = getSnapshot();
    Array.from(listeners).forEach(listener => {
        try {
            listener(snapshot);
        } catch (_error) {
            // A UI subscriber cannot affect bearer lifetime or control flow.
        }
    });
}

function subscribe(listener) {
    if (typeof listener !== 'function') {
        throw new TypeError('Advanced session subscriber must be a function');
    }
    listeners.add(listener);
    listener(getSnapshot());
    return () => listeners.delete(listener);
}

function attachSessionHeader(init = {}) {
    if (!activeToken) {
        throw new Error(t('advancedSessionInactive'));
    }
    const sourceHeaders = init.headers instanceof Headers
        ? Object.fromEntries(init.headers.entries())
        : { ...(init.headers || {}) };
    return {
        ...init,
        headers: {
            ...sourceHeaders,
            'X-XFerry-Advanced-Session': activeToken,
        },
    };
}

async function parseControlResponse(response) {
    const text = await response.text();
    let payload;
    try {
        payload = JSON.parse(text);
    } catch (_error) {
        throw new TypeError(t('advancedSessionInvalidResponse'));
    }
    if (!response.ok) {
        throw new Error(responseErrorMessage(response, payload));
    }
    return payload;
}

async function revokeToken(token, options = {}) {
    const response = await app.service('http').request(
        'DELETE',
        CURRENT_URL,
        null,
        { 'X-XFerry-Advanced-Session': token },
        null,
        { dataPlane: false, keepalive: options.keepalive === true }
    );
    await parseControlResponse(response);
    return true;
}

async function bestEffortRevokeToken(token, options = {}) {
    try {
        await revokeToken(token, options);
        return true;
    } catch (_error) {
        return false;
    }
}

async function create() {
    if (activeToken && metadata) {
        return getSnapshot();
    }
    const operationGeneration = lifecycleGeneration;
    if (createOperation?.generation === operationGeneration) {
        return createOperation.promise;
    }
    phase = 'creating';
    safeError = '';
    publish();
    const operation = { generation: operationGeneration, promise: null };
    operation.promise = (async () => {
        try {
            const body = {
                prefix: String(prefixInput?.value || '/advanced'),
                decoder: String(decoderSelect?.value || 'auto'),
                diagnostic_headers: diagnosticHeadersInput?.checked === true,
            };
            const response = await app.service('http').request(
                'POST',
                CREATE_URL,
                JSON.stringify(body),
                { 'Content-Type': 'application/json' },
                null,
                { dataPlane: false }
            );
            const payload = await parseControlResponse(response);
            const session = payload?.advanced_session;
            const safeMetadata = validateMetadata(session, { tokenRequired: true });
            if (lifecycleGeneration !== operationGeneration) {
                await bestEffortRevokeToken(session.token);
                return getSnapshot();
            }
            if (safeMetadata.expires_at_ms <= Date.now()) {
                lifecycleGeneration += 1;
                clearLocalSession();
                await bestEffortRevokeToken(session.token);
                return getSnapshot();
            }
            activeToken = session.token;
            metadata = safeMetadata;
            phase = 'active';
            safeError = '';
            scheduleExpiry(operationGeneration, activeToken);
        } catch (error) {
            if (lifecycleGeneration === operationGeneration) {
                clearLocalSession();
                safeError = sanitizeError(error, null);
            }
        } finally {
            if (createOperation === operation) {
                createOperation = null;
            }
            if (lifecycleGeneration === operationGeneration) {
                publish();
            }
        }
        return getSnapshot();
    })();
    createOperation = operation;
    return operation.promise;
}

async function current() {
    if (!activeToken) {
        return null;
    }
    const requestSecret = activeToken;
    const operationGeneration = lifecycleGeneration;
    phase = 'checking';
    publish();
    try {
        const init = attachSessionHeader({ headers: {} });
        const response = await app.service('http').request(
            'GET',
            CURRENT_URL,
            null,
            init.headers,
            null,
            { dataPlane: false }
        );
        const payload = await parseControlResponse(response);
        const safeMetadata = validateMetadata(payload?.advanced_session);
        if (
            lifecycleGeneration !== operationGeneration
            || activeToken !== requestSecret
        ) {
            return null;
        }
        if (safeMetadata.expires_at_ms <= Date.now()) {
            lifecycleGeneration += 1;
            clearLocalSession();
            safeError = '';
            publish();
            return null;
        }
        metadata = safeMetadata;
        phase = 'active';
        safeError = '';
        scheduleExpiry(operationGeneration, requestSecret);
        publish();
        return getSnapshot();
    } catch (error) {
        if (
            lifecycleGeneration === operationGeneration
            && activeToken === requestSecret
        ) {
            lifecycleGeneration += 1;
            clearLocalSession();
            safeError = sanitizeError(error, requestSecret);
            publish();
        }
        return null;
    }
}

async function revoke(options = {}) {
    const requestSecret = activeToken;
    lifecycleGeneration += 1;
    const revocationGeneration = lifecycleGeneration;
    // Clear first: local revocation is unconditional even if the network call fails.
    clearLocalSession();
    safeError = '';
    publish();
    if (!requestSecret) {
        return true;
    }
    try {
        return await revokeToken(requestSecret, options);
    } catch (error) {
        if (lifecycleGeneration === revocationGeneration && !activeToken) {
            safeError = sanitizeError(error, requestSecret);
            publish();
        }
        return false;
    }
}

async function ensureActive() {
    if (!activeToken) {
        await create();
    }
    if (!activeToken) {
        throw new Error(safeError || t('advancedSessionInactive'));
    }
    return activeToken;
}

createButton?.addEventListener('click', () => {
    void create();
});
revokeButton?.addEventListener('click', () => {
    void revoke();
});

app.on(app.events.WORKSPACE_CHANGED, ({ workspace }) => {
    if (workspace === 'opsec') {
        void create();
    } else {
        void revoke();
    }
});
app.on(app.events.LOCALE_CHANGED, render);
window.addEventListener('focus', () => {
    if (activeToken) {
        void current();
    }
});
window.addEventListener('pagehide', () => {
    void revoke({ keepalive: true });
});

app.registerService('advanced-session', {
    create,
    current,
    revoke,
    ensureActive,
    getSnapshot,
    subscribe,
    attachSessionHeader,
});

render();
})(window.XferryApp);
