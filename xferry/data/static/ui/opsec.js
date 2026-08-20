(function initializeAdvancedUpload(app) {
    'use strict';

const {
    t,
    formatSize,
    serverUrl: SERVER_URL,
    announceLiveRegion,
    focusElementWithoutScroll,
    bindDropZoneKeyboardTrigger,
} = app.service('core');
const {
    createBinaryBody: createExchangeBinaryBody,
    createHttpResponseMessage: createExchangeHttpResponseMessage,
    createPreviewBody: createExchangePreviewBody,
    createTextBody: createExchangeTextBody,
    setInspector: setExchangeInspector,
    withNoGzipHeader: withUiNoGzipHeader,
} = app.service('inspector');
const advancedSession = app.service('advanced-session');
const advancedCompiler = app.service('advanced-compiler');
const httpErrors = app.service('http-errors');

const PROFILE_IDS = Object.freeze([
    'body-json',
    'body-raw',
    'body-text',
    'body-form',
    'body-xml',
    'multipart-binary',
    'multipart-encoded',
    'headers',
    'query',
    'cookies',
    'path',
]);
const MODE_IDS = new Set(['managed', 'experimental']);
const BODY_FIELD_FORMATS = new Set(['json', 'form', 'xml', 'multipart-encoded']);
const METHOD_OVERRIDE_FIELD_FORMATS = new Set([
    ...BODY_FIELD_FORMATS,
    'multipart-binary',
]);
const MULTIPART_FORMATS = new Set(['multipart-binary', 'multipart-encoded']);
const SAFE_TEXT_ENCODINGS = new Set([
    'base64',
    'base64url',
    'hex',
    'percent',
    'gzip-base64',
]);
const FILENAME_PLACEMENTS = new Set([
    'hidden',
    'body',
    'header',
    'query',
    'cookie',
    'path',
    'multipart-filename',
]);
const PROFILE_PRESETS = Object.freeze({
    'body-json': {
        carrier: 'body',
        bodyFormat: 'json',
        representation: 'encoded',
        encoding: 'base64',
        mime: 'application/json',
    },
    'body-raw': {
        carrier: 'body',
        bodyFormat: 'raw',
        representation: 'binary',
        encoding: 'raw',
        mime: 'application/octet-stream',
    },
    'body-text': {
        carrier: 'body',
        bodyFormat: 'text',
        representation: 'encoded',
        encoding: 'base64',
        mime: 'text/plain',
    },
    'body-form': {
        carrier: 'body',
        bodyFormat: 'form',
        representation: 'encoded',
        encoding: 'base64',
        mime: 'application/x-www-form-urlencoded',
    },
    'body-xml': {
        carrier: 'body',
        bodyFormat: 'xml',
        representation: 'encoded',
        encoding: 'base64',
        mime: 'application/xml',
    },
    'multipart-binary': {
        carrier: 'body',
        bodyFormat: 'multipart-binary',
        representation: 'binary',
        encoding: 'raw',
        mime: 'multipart/form-data',
    },
    'multipart-encoded': {
        carrier: 'body',
        bodyFormat: 'multipart-encoded',
        representation: 'encoded',
        encoding: 'base64',
        mime: 'multipart/form-data',
    },
    headers: {
        carrier: 'headers',
        bodyFormat: 'json',
        representation: 'encoded',
        encoding: 'base64',
        mime: '',
    },
    query: {
        carrier: 'query',
        bodyFormat: 'json',
        representation: 'encoded',
        encoding: 'base64url',
        mime: '',
    },
    cookies: {
        carrier: 'cookies',
        bodyFormat: 'json',
        representation: 'encoded',
        encoding: 'base64url',
        mime: '',
    },
    path: {
        carrier: 'path',
        bodyFormat: 'json',
        representation: 'encoded',
        encoding: 'base64url',
        mime: '',
    },
});
const KNOWN_COOKIE_NAMES = Object.freeze([
    'xferry_data',
    'xferry_encryption',
    'xferry_key',
    'xferry_key_is_base64',
    'xferry_name',
    'xferry_hmac',
    'xferry_encoding',
    'xferry_method_override',
]);
const SIZE_LIMITS = Object.freeze({
    body: { server: 16 * 1024 * 1024, browser: 2 * 1024 * 1024 * 1024, suggestion: 'body-raw' },
    headers: { server: 64 * 1024, browser: 64 * 1024, suggestion: 'body-json' },
    query: { server: 16 * 1024, browser: 8 * 1024, suggestion: 'body-json' },
    cookies: { server: 64 * 1024, browser: 4096, suggestion: 'body-json' },
    path: { server: 16 * 1024, browser: 8 * 1024, suggestion: 'body-json' },
});

const opsecState = {
    file: null,
    previewSequence: 0,
    lastDispatchedPlanIdentity: null,
    previewPath: '',
    previewSuppressed: false,
    preview: null,
    sessionGateMessageKey: '',
    previewPending: false,
};

const opsecFileInput = document.getElementById('opsecFileInput');
const opsecUploadBtn = document.getElementById('opsecUploadBtn');
const opsecDropZone = document.getElementById('opsecDropZone');
const opsecEncryptionSelect = document.getElementById('opsecEncryptionSelect');
const opsecPasswordInput = document.getElementById('opsecPassword');
const opsecPasswordError = document.getElementById('opsecPasswordError');
const opsecRandomMethodBtn = document.getElementById('opsecRandomMethodBtn');
const opsecSelectionState = document.getElementById('opsecSelectionState');
const opsecMethodInput = document.getElementById('opsecMethodInput');
const opsecKeyBase64Checkbox = document.getElementById('opsecKeyBase64');
const opsecSettingsDetails = document.getElementById('opsecSettingsDetails');
const opsecEncryptionPanel = document.getElementById('opsecEncryptionPanel');
const opsecConstructorMode = document.getElementById('opsecConstructorMode');
const opsecProfileSelect = document.getElementById('opsecProfileSelect');
const opsecCarrierSelect = document.getElementById('opsecCarrierSelect');
const opsecBodyFormatPanel = document.getElementById('opsecBodyFormatPanel');
const opsecBodyFormatSelect = document.getElementById('opsecBodyFormatSelect');
const opsecEncodingSelect = document.getElementById('opsecEncodingSelect');
const opsecMimeInput = document.getElementById('opsecMimeInput');
const opsecMimePanel = document.getElementById('opsecMimePanel');
const opsecMimeHelp = document.getElementById('opsecMimeHelp');
const opsecPartMimePanel = document.getElementById('opsecPartMimePanel');
const opsecPartMimeInput = document.getElementById('opsecPartMimeInput');
const opsecFilenamePrimarySelect = document.getElementById('opsecFilenamePrimarySelect');
const opsecFilenameCopies = document.getElementById('opsecFilenameCopies');
const opsecMethodOverrideSelect = document.getElementById('opsecMethodOverrideSelect');
const opsecNormalizationPanel = document.getElementById('opsecNormalizationPanel');
const opsecNormalizationList = document.getElementById('opsecNormalizationList');
const opsecValidationError = document.getElementById('opsecValidationError');
const opsecSizeWarning = document.getElementById('opsecSizeWarning');
const opsecSizeMessage = opsecSizeWarning?.querySelector('[data-opsec-size-message]');
const opsecOutcomeSummary = document.querySelector('[data-testid="opsec-outcome-summary"]');
const opsecPreviewPending = document.getElementById('opsecPreviewPending');
const opsecOutcomeMethod = document.querySelector('[data-opsec-outcome="method"]');
const opsecOutcomeTransport = document.querySelector('[data-opsec-outcome="transport"]');
const opsecOutcomeEncoding = document.querySelector('[data-opsec-outcome="encoding"]');
const opsecOutcomeFilename = document.querySelector('[data-opsec-outcome="filename"]');
const opsecOutcomeServer = document.querySelector('[data-opsec-outcome="server"]');
const opsecEncryptionHelp = document.querySelector('[data-opsec-help="encryption"]');
const opsecMethodOverrideHelp = document.querySelector('[data-opsec-help="method-override"]');

function sendCustomRequest(...args) {
    return app.service('http').request(...args);
}

function createOpsecRandomPath() {
    return '/' + Math.random().toString(36).substring(2, 10);
}

function getOpsecPreviewPath() {
    if (!opsecState.previewPath) {
        opsecState.previewPath = createOpsecRandomPath();
    }
    return opsecState.previewPath;
}

function resetOpsecPreviewPath() {
    opsecState.previewPath = '';
}

function cloneAdvancedSessionSnapshot(snapshot) {
    if (!snapshot) {
        return null;
    }
    return {
        prefix: snapshot.prefix,
        decoder: snapshot.decoder,
        diagnostic_headers: snapshot.diagnostic_headers,
        active: snapshot.active === true,
        phase: snapshot.phase,
        expires_at: snapshot.expires_at,
    };
}

function advancedSessionSnapshotsEqual(left, right) {
    return Boolean(
        left
        && right
        && left.prefix === right.prefix
        && left.decoder === right.decoder
        && left.diagnostic_headers === right.diagnostic_headers
        && left.active === right.active
        && left.expires_at === right.expires_at
    );
}

function prefixMatchesPath(prefix, pathname) {
    if (typeof prefix !== 'string' || !prefix.startsWith('/')) {
        return false;
    }
    if (prefix === '/') {
        return pathname.startsWith('/');
    }
    return pathname === prefix || pathname.startsWith(prefix + '/');
}

function joinRoutingPath(prefix, randomPath) {
    if (!prefix) {
        return randomPath;
    }
    if (prefix === '/') {
        return randomPath;
    }
    return prefix.replace(/\/+$/, '') + randomPath;
}

function clearOpsecSessionGateMessage() {
    opsecState.sessionGateMessageKey = '';
}

function announceOpsecSessionGate(messageKey) {
    opsecState.sessionGateMessageKey = messageKey;
    announceLiveRegion('opsecResponseAreaLive', t(messageKey));
}

function clearOpsecPasswordError() {
    if (opsecPasswordInput) {
        opsecPasswordInput.setAttribute('aria-invalid', 'false');
    }
    if (opsecPasswordError) {
        opsecPasswordError.hidden = true;
    }
}

function showOpsecPasswordError() {
    if (opsecSettingsDetails) {
        opsecSettingsDetails.open = true;
    }
    if (opsecPasswordError) {
        opsecPasswordError.textContent = t('opsecPasswordRequired');
        opsecPasswordError.hidden = false;
    }
    if (opsecPasswordInput) {
        opsecPasswordInput.setAttribute('aria-invalid', 'true');
        if (typeof focusElementWithoutScroll === 'function') {
            focusElementWithoutScroll(opsecPasswordInput);
        } else {
            opsecPasswordInput.focus();
        }
    }
}

function getSelectedFilenameCopies() {
    if (!opsecFilenameCopies) {
        return [];
    }
    return Array.from(opsecFilenameCopies.querySelectorAll('input[type="checkbox"]:checked'))
        .map(input => input.value)
        .filter(value => FILENAME_PLACEMENTS.has(value));
}

function readAdvancedRequestState() {
    const mode = MODE_IDS.has(opsecConstructorMode?.value)
        ? opsecConstructorMode.value
        : 'managed';
    const profileId = PROFILE_IDS.includes(opsecProfileSelect?.value)
        ? opsecProfileSelect.value
        : 'body-json';
    return {
        mode,
        profileId,
        method: (opsecMethodInput?.value || 'CHECKDATA').trim() || 'CHECKDATA',
        carrier: opsecCarrierSelect?.value || 'body',
        bodyFormat: opsecBodyFormatSelect?.value || 'json',
        encoding: opsecEncodingSelect?.value || 'base64',
        mime: (opsecMimeInput?.value || '').trim(),
        partMime: (opsecPartMimeInput?.value || 'application/octet-stream').trim()
            || 'application/octet-stream',
        filenamePrimary: opsecFilenamePrimarySelect?.value || 'hidden',
        filenameCopies: getSelectedFilenameCopies(),
        encryption: opsecEncryptionSelect?.value || 'none',
        useEncryption: (opsecEncryptionSelect?.value || 'none') !== 'none',
        password: opsecPasswordInput?.value || '',
        encodeKeyBase64: Boolean(opsecKeyBase64Checkbox?.checked),
        methodOverride: opsecMethodOverrideSelect?.value || 'none',
        pathToken: getOpsecPreviewPath(),
    };
}

function addNormalization(normalizations, field, from, to) {
    if (from === to) {
        return;
    }
    normalizations.push({
        key: 'opsecNormalizationItem',
        args: [field, String(from || '-'), String(to || '-')],
    });
}

function decoderForMime(mime) {
    const base = String(mime || '').split(';', 1)[0].trim().toLowerCase();
    if (base === 'application/octet-stream') return 'raw';
    if (base === 'application/json' || base.endsWith('+json')) return 'json';
    if (base === 'text/plain') return 'text';
    if (base === 'application/x-www-form-urlencoded') return 'form';
    if (
        base === 'application/xml'
        || base === 'text/xml'
        || base === 'application/soap+xml'
        || base.endsWith('+xml')
    ) return 'xml';
    if (base === 'multipart/form-data') return 'multipart';
    return 'unknown';
}

function actualBodyDecoder(normalized) {
    if (normalized.carrier !== 'body') {
        return null;
    }
    return {
        raw: 'raw',
        json: 'json',
        text: 'text',
        form: 'form',
        xml: 'xml',
        'multipart-binary': 'multipart',
        'multipart-encoded': 'multipart',
    }[normalized.bodyFormat] || null;
}

function placementCompatible(placement, normalized) {
    if (placement === 'hidden' || placement === 'header' || placement === 'query') {
        return true;
    }
    if (placement === 'cookie') {
        return true;
    }
    if (placement === 'path') {
        return true;
    }
    if (placement === 'multipart-filename') {
        return normalized.carrier === 'body' && normalized.bodyFormat === 'multipart-binary';
    }
    if (placement === 'body') {
        return normalized.carrier === 'body'
            && new Set(['json', 'form', 'xml', 'multipart-encoded']).has(normalized.bodyFormat);
    }
    return false;
}

function filenamePrimaryCompatible(placement, normalized) {
    if (normalized.carrier === 'body' && normalized.bodyFormat === 'multipart-binary') {
        return placement === 'multipart-filename';
    }
    return placementCompatible(placement, normalized);
}

function filenameCopyCompatible(placement, normalized) {
    if (normalized.carrier === 'body' && normalized.bodyFormat === 'multipart-binary') {
        return new Set(['header', 'query', 'cookie', 'path']).has(placement);
    }
    return placementCompatible(placement, normalized);
}

function recommendedFilenamePlacement(normalized) {
    if (normalized.carrier === 'headers') return 'header';
    if (normalized.carrier === 'query') return 'query';
    if (normalized.carrier === 'cookies') return 'cookie';
    if (normalized.carrier === 'path') return 'path';
    if (normalized.bodyFormat === 'multipart-binary') return 'multipart-filename';
    if (BODY_FIELD_FORMATS.has(normalized.bodyFormat)) {
        return 'body';
    }
    return 'header';
}

function bodySerializesFields(normalized) {
    return normalized.carrier === 'body'
        && METHOD_OVERRIDE_FIELD_FORMATS.has(normalized.bodyFormat);
}

function normalizeAdvancedRequestState(raw, sessionSnapshot) {
    const preset = PROFILE_PRESETS[raw.profileId] || PROFILE_PRESETS['body-json'];
    const normalized = {
        ...raw,
        filenameCopies: Array.from(new Set(raw.filenameCopies || [])),
        representation: raw.bodyFormat === 'raw' || raw.bodyFormat === 'multipart-binary'
            ? 'binary'
            : 'encoded',
        normalizations: [],
        errors: [],
        sessionSnapshot: cloneAdvancedSessionSnapshot(sessionSnapshot),
        requestBasePath: joinRoutingPath(sessionSnapshot?.prefix, raw.pathToken),
    };

    if (raw.mode === 'managed') {
        for (const field of ['carrier', 'bodyFormat', 'encoding', 'mime']) {
            addNormalization(normalized.normalizations, field, normalized[field], preset[field]);
            normalized[field] = preset[field];
        }
        normalized.representation = preset.representation;

        if (!filenamePrimaryCompatible(normalized.filenamePrimary, normalized)) {
            const replacement = recommendedFilenamePlacement(normalized);
            addNormalization(
                normalized.normalizations,
                'filenamePrimary',
                normalized.filenamePrimary,
                replacement
            );
            normalized.filenamePrimary = replacement;
        }

        const compatibleCopies = [];
        for (const placement of normalized.filenameCopies) {
            if (placement === normalized.filenamePrimary) {
                normalized.normalizations.push({
                    key: 'opsecNormalizationCopyRemovedPrimary',
                    args: [placement],
                });
            } else if (!filenameCopyCompatible(placement, normalized)) {
                normalized.normalizations.push({
                    key: 'opsecNormalizationCopyRemovedIncompatible',
                    args: [placement],
                });
            } else {
                compatibleCopies.push(placement);
            }
        }
        normalized.filenameCopies = compatibleCopies;

        if (
            normalized.methodOverride === 'form'
            && !bodySerializesFields(normalized)
        ) {
            addNormalization(
                normalized.normalizations,
                'methodOverride',
                normalized.methodOverride,
                'header'
            );
            normalized.methodOverride = 'header';
        }
    } else {
        if (normalized.carrier === 'body') {
            if (
                new Set(['raw', 'multipart-binary']).has(normalized.bodyFormat)
                && normalized.encoding !== 'raw'
            ) {
                normalized.errors.push({
                    key: 'opsecBinaryRequiresRaw',
                    args: [normalized.bodyFormat, normalized.encoding],
                });
            }
            if (
                !new Set(['raw', 'multipart-binary']).has(normalized.bodyFormat)
                && !SAFE_TEXT_ENCODINGS.has(normalized.encoding)
            ) {
                normalized.errors.push({
                    key: 'opsecStructuredRequiresTextEncoding',
                    args: [normalized.bodyFormat, normalized.encoding],
                });
            }
        } else if (!SAFE_TEXT_ENCODINGS.has(normalized.encoding)) {
            normalized.errors.push({
                key: 'opsecCarrierRequiresTextEncoding',
                args: [normalized.carrier, normalized.encoding],
            });
        }
        if (
            normalized.carrier !== 'body'
            && normalized.bodyFormat === 'raw'
        ) {
            normalized.errors.push({
                key: 'opsecRawRequiresBody',
                args: [normalized.carrier],
            });
        }
        if (
            MULTIPART_FORMATS.has(normalized.bodyFormat)
            && normalized.carrier !== 'body'
        ) {
            normalized.errors.push({
                key: 'opsecMultipartRequiresBody',
                args: [normalized.bodyFormat, normalized.carrier],
            });
        }
        if (!filenamePrimaryCompatible(normalized.filenamePrimary, normalized)) {
            normalized.errors.push({
                key: 'opsecFilenamePlacementIncompatible',
                args: [normalized.filenamePrimary, normalized.carrier, normalized.bodyFormat],
            });
        }
        for (const placement of normalized.filenameCopies) {
            if (placement === normalized.filenamePrimary) {
                normalized.errors.push({
                    key: 'opsecFilenameCopyDuplicatesPrimary',
                    args: [placement],
                });
            } else if (!filenameCopyCompatible(placement, normalized)) {
                normalized.errors.push({
                    key: 'opsecFilenamePlacementIncompatible',
                    args: [placement, normalized.carrier, normalized.bodyFormat],
                });
            }
        }
        if (
            normalized.methodOverride === 'form'
            && !bodySerializesFields(normalized)
        ) {
            normalized.errors.push({
                key: 'opsecMethodOverrideIncompatible',
                args: [normalized.carrier, normalized.bodyFormat],
            });
        }
    }

    if (
        MULTIPART_FORMATS.has(normalized.bodyFormat)
        && String(normalized.mime || '').trim().toLowerCase() !== 'multipart/form-data'
    ) {
        normalized.errors.push({
            key: 'opsecMultipartMimeBrowserManaged',
            args: [normalized.mime || '-'],
        });
    }

    if (normalized.useEncryption && !normalized.password) {
        normalized.errors.push({ key: 'opsecPasswordRequired', args: [] });
    }

    const actualDecoder = actualBodyDecoder(normalized);
    const declaredDecoder = actualDecoder ? decoderForMime(normalized.mime) : null;
    if (
        actualDecoder
        && normalized.bodyFormat !== 'multipart-binary'
        && normalized.bodyFormat !== 'multipart-encoded'
        && declaredDecoder !== actualDecoder
    ) {
        const fixedDecoderIsActive = Boolean(
            sessionSnapshot
            && sessionSnapshot.decoder === actualDecoder
            && sessionSnapshot.decoder !== 'auto'
            && prefixMatchesPath(sessionSnapshot.prefix, normalized.requestBasePath)
        );
        if (!fixedDecoderIsActive) {
            normalized.errors.push({
                key: 'opsecMimeDecoderMismatch',
                args: [
                    normalized.mime || '-',
                    actualDecoder,
                    sessionSnapshot?.decoder || 'auto',
                ],
            });
        }
    }

    normalized.valid = normalized.errors.length === 0;
    return normalized;
}

function localizeIssue(issue) {
    let message = t(issue.key);
    (issue.args || []).forEach((value, index) => {
        message = message.replace(`{${index}}`, value);
    });
    return message;
}

function profileTitleKey(profileId) {
    return {
        'body-json': 'opsecProfileBodyJson',
        'body-raw': 'opsecProfileBodyRaw',
        'body-text': 'opsecProfileBodyText',
        'body-form': 'opsecProfileBodyForm',
        'body-xml': 'opsecProfileBodyXml',
        'multipart-binary': 'opsecProfileMultipartBinary',
        'multipart-encoded': 'opsecProfileMultipartEncoded',
        headers: 'opsecProfileHeaders',
        query: 'opsecProfileQuery',
        cookies: 'opsecProfileCookies',
        path: 'opsecProfilePath',
    }[profileId] || 'opsecProfileBodyJson';
}

function applyNormalizedControls(normalized) {
    if (normalized.mode !== 'managed') {
        return;
    }
    if (opsecCarrierSelect) opsecCarrierSelect.value = normalized.carrier;
    if (opsecBodyFormatSelect) opsecBodyFormatSelect.value = normalized.bodyFormat;
    if (opsecEncodingSelect) opsecEncodingSelect.value = normalized.encoding;
    if (opsecMimeInput) opsecMimeInput.value = normalized.mime;
    if (opsecFilenamePrimarySelect) {
        opsecFilenamePrimarySelect.value = normalized.filenamePrimary;
    }
    if (opsecMethodOverrideSelect) {
        opsecMethodOverrideSelect.value = normalized.methodOverride;
    }
    if (opsecFilenameCopies) {
        const selected = new Set(normalized.filenameCopies);
        opsecFilenameCopies.querySelectorAll('input[type="checkbox"]').forEach(input => {
            input.checked = selected.has(input.value);
        });
    }
}

function renderConstructorFeedback(normalized) {
    if (opsecNormalizationPanel && opsecNormalizationList) {
        opsecNormalizationList.replaceChildren();
        for (const item of normalized.normalizations) {
            const li = document.createElement('li');
            li.textContent = localizeIssue(item);
            opsecNormalizationList.appendChild(li);
        }
        opsecNormalizationPanel.hidden = normalized.normalizations.length === 0;
    }
    if (opsecValidationError) {
        opsecValidationError.hidden = normalized.errors.length === 0;
        opsecValidationError.textContent = normalized.errors.length
            ? `${t('opsecValidationTitle')}: ${normalized.errors.map(localizeIssue).join(' ')}`
            : '';
    }
}

function syncConstructorControlVisibility(normalized) {
    const isMultipart = MULTIPART_FORMATS.has(normalized.bodyFormat);
    const isMultipartBinary = normalized.bodyFormat === 'multipart-binary';
    if (opsecMimePanel) {
        opsecMimePanel.dataset.browserManaged = String(isMultipart);
    }
    if (opsecMimeInput) {
        opsecMimeInput.disabled = isMultipart;
    }
    if (opsecMimeHelp) {
        opsecMimeHelp.hidden = !isMultipart;
    }
    if (opsecPartMimePanel) {
        opsecPartMimePanel.hidden = !isMultipartBinary;
    }
    if (opsecPartMimeInput) {
        opsecPartMimeInput.disabled = !isMultipartBinary;
    }
    if (opsecBodyFormatPanel) {
        opsecBodyFormatPanel.hidden = false;
    }
    if (opsecEncryptionPanel) {
        opsecEncryptionPanel.hidden = !normalized.useEncryption;
    }
    if (opsecPasswordInput) {
        opsecPasswordInput.disabled = !normalized.useEncryption;
    }
    if (opsecKeyBase64Checkbox) {
        opsecKeyBase64Checkbox.disabled = !normalized.useEncryption;
    }
    if (opsecEncryptionHelp) {
        const helpKey = !normalized.useEncryption
            ? 'opsecEncryptionHelpOff'
            : normalized.encodeKeyBase64
                ? 'opsecEncryptionHelpKeyBase64'
                : 'opsecEncryptionHelpSendKey';
        opsecEncryptionHelp.textContent = t(helpKey);
    }
    if (opsecMethodOverrideHelp) {
        const helpKey = {
            none: 'opsecMethodOverrideHelpNone',
            header: 'opsecMethodOverrideHelpHeader',
            query: 'opsecMethodOverrideHelpQuery',
            form: 'opsecMethodOverrideHelpForm',
        }[normalized.methodOverride] || 'opsecMethodOverrideHelpNone';
        opsecMethodOverrideHelp.textContent = t(helpKey);
    }
}

function serializeCookiePairs(cookieEffects) {
    return (cookieEffects || [])
        .filter(effect => effect.action === 'set')
        .map(effect => `${effect.name}=${encodeURIComponent(effect.value)}`)
        .join('; ');
}

function utf8ByteLength(value) {
    return new TextEncoder().encode(String(value || '')).byteLength;
}

function estimateFormDataBytes(formData) {
    let estimatedBytes = 80;
    for (const [name, value] of formData.entries()) {
        estimatedBytes += 120 + utf8ByteLength(name);
        if (value instanceof Blob) {
            estimatedBytes += value.size;
            estimatedBytes += utf8ByteLength(value.type);
            estimatedBytes += utf8ByteLength(
                typeof value.name === 'string' ? value.name : ''
            );
        } else {
            estimatedBytes += utf8ByteLength(value);
        }
    }
    return estimatedBytes;
}

function estimateAdvancedRequestSize({
    method,
    path,
    headers,
    body,
    cookieEffects,
}) {
    let estimatedBytes = utf8ByteLength(`${method} ${path} HTTP/1.1\r\n`);
    for (const [name, value] of Object.entries(headers || {})) {
        if (value !== undefined && value !== null && value !== '') {
            estimatedBytes += utf8ByteLength(`${name}: ${value}\r\n`);
        }
    }
    const cookieHeader = serializeCookiePairs(cookieEffects);
    if (cookieHeader) {
        estimatedBytes += utf8ByteLength(`Cookie: ${cookieHeader}\r\n`);
    }
    estimatedBytes += 2;

    let approximate = false;
    if (body instanceof FormData) {
        approximate = true;
        estimatedBytes += estimateFormDataBytes(body);
    } else if (body instanceof Uint8Array) {
        estimatedBytes += body.byteLength;
    } else if (body instanceof ArrayBuffer) {
        estimatedBytes += body.byteLength;
    } else if (body !== null && body !== undefined) {
        estimatedBytes += utf8ByteLength(body);
    }
    return { estimatedBytes, approximate };
}

function createSizeInfo(carrier, estimate) {
    const limits = SIZE_LIMITS[carrier] || SIZE_LIMITS.body;
    return {
        estimatedBytes: estimate.estimatedBytes,
        approximate: estimate.approximate,
        serverLimit: limits.server,
        browserLimit: limits.browser,
        overLimit: estimate.estimatedBytes > Math.min(limits.server, limits.browser),
        suggestedProfile: limits.suggestion,
    };
}

async function compileAdvancedRequest(normalized, file, sessionSnapshot) {
    const method = normalized.method;
    if (!normalized.valid) {
        return {
            valid: false,
            normalized,
            method,
            errorMessage: normalized.errors.map(localizeIssue).join(' '),
            cookieEffects: [],
        };
    }

    const sourceBytes = new Uint8Array(await file.arrayBuffer());
    const compilerPrefix = normalized.carrier === 'path'
        ? (sessionSnapshot?.prefix || '/advanced')
        : normalized.requestBasePath;
    const compiled = await advancedCompiler.compile({
        method,
        prefix: compilerPrefix,
        carrier: normalized.carrier,
        bodyFormat: normalized.bodyFormat,
        encoding: normalized.encoding,
        encryption: normalized.encryption,
        key: normalized.useEncryption ? normalized.password : '',
        keyIsBase64: normalized.useEncryption && normalized.encodeKeyBase64,
        name: normalized.filenamePrimary === 'hidden' ? '' : file.name,
        methodOverride: normalized.methodOverride === 'none' ? '' : 'PUT',
        mime: normalized.mime,
        partMime: normalized.partMime,
    }, sourceBytes);
    const requestPath = compiled.requestPath;
    const requestUrl = new URL(requestPath, SERVER_URL || location.href).toString();
    const requestBody = compiled.requestBody;
    const headers = withUiNoGzipHeader(compiled.requestHeaders);
    const cookieEffects = [
        ...KNOWN_COOKIE_NAMES.map(name => ({ action: 'delete', name })),
        ...compiled.cookieEffects,
    ];
    let requestBodyDescriptor = null;
    if (requestBody instanceof Uint8Array || requestBody instanceof ArrayBuffer) {
        const bodyBytes = requestBody instanceof Uint8Array
            ? requestBody
            : new Uint8Array(requestBody);
        requestBodyDescriptor = createExchangeBinaryBody({
            filename: normalized.filenamePrimary === 'hidden' ? '' : file.name,
            contentType: normalized.partMime,
            size: bodyBytes.byteLength,
            bytes: bodyBytes,
        });
    } else if (requestBody instanceof FormData) {
        requestBodyDescriptor = createExchangePreviewBody({
            label: t(profileTitleKey(normalized.profileId)),
            size: sourceBytes.byteLength,
            text: Array.from(requestBody.keys()).join(', '),
        });
    } else if (typeof requestBody === 'string') {
        requestBodyDescriptor = createExchangeTextBody(requestBody, {
            contentType: normalized.mime,
        });
    }
    const traceHeaders = { ...headers };
    if (normalized.carrier === 'cookies') {
        const cookieHeader = serializeCookiePairs(cookieEffects);
        if (cookieHeader) {
            traceHeaders.Cookie = cookieHeader;
        }
    }
    const requestExchange = {
        transport: 'http',
        method,
        path: requestPath,
        headers: traceHeaders,
        body: requestBodyDescriptor,
        exportFilenameBase: 'xferry-opsec-request',
        sensitive: true,
    };

    const requestSizeEstimate = estimateAdvancedRequestSize({
        method,
        path: requestPath,
        headers,
        body: requestBody,
        cookieEffects,
    });
    return {
        valid: true,
        normalized,
        method,
        profileId: normalized.profileId,
        carrier: normalized.carrier,
        bodyFormat: normalized.bodyFormat,
        representation: normalized.representation,
        encoding: normalized.encoding,
        mime: normalized.mime,
        filenamePrimary: normalized.filenamePrimary,
        filenameCopies: [...normalized.filenameCopies],
        includeName: normalized.bodyFormat === 'multipart-binary'
            || normalized.filenamePrimary !== 'hidden'
            || normalized.filenameCopies.length > 0,
        useEncryption: normalized.useEncryption,
        encodeKeyBase64: normalized.encodeKeyBase64,
        requestUrl,
        requestPath,
        requestBody,
        requestHeaders: headers,
        requestBodyDescriptor,
        requestExchange,
        cookieEffects,
        sizeInfo: createSizeInfo(normalized.carrier, requestSizeEstimate),
        sessionExpiresAt: sessionSnapshot?.expires_at ?? null,
    };
}

function fingerprintHash(text) {
    let hash = 2166136261;
    for (let index = 0; index < text.length; index += 1) {
        hash ^= text.charCodeAt(index);
        hash = Math.imul(hash, 16777619);
    }
    return (hash >>> 0).toString(16).padStart(8, '0');
}

function advancedStateFingerprint(normalized, file) {
    const fingerprintInput = {
        mode: normalized.mode,
        profileId: normalized.profileId,
        method: normalized.method,
        carrier: normalized.carrier,
        bodyFormat: normalized.bodyFormat,
        representation: normalized.representation,
        encoding: normalized.encoding,
        mime: normalized.mime,
        partMime: normalized.partMime,
        filenamePrimary: normalized.filenamePrimary,
        filenameCopies: normalized.filenameCopies,
        useEncryption: normalized.useEncryption,
        password: normalized.password,
        encodeKeyBase64: normalized.encodeKeyBase64,
        methodOverride: normalized.methodOverride,
        requestBasePath: normalized.requestBasePath,
        file: file ? {
            name: file.name,
            size: file.size,
            type: file.type,
            lastModified: file.lastModified,
        } : null,
    };
    return fingerprintHash(JSON.stringify(fingerprintInput));
}

function renderOutcomeFromPlan(plan) {
    const normalized = plan?.normalized || normalizeAdvancedRequestState(
        readAdvancedRequestState(),
        advancedSession.getSnapshot()
    );
    if (opsecOutcomeMethod) opsecOutcomeMethod.textContent = normalized.method;
    if (opsecOutcomeTransport) {
        opsecOutcomeTransport.textContent =
            `${t(profileTitleKey(normalized.profileId))} · ${normalized.carrier} · ${normalized.bodyFormat}`;
    }
    if (opsecOutcomeEncoding) {
        opsecOutcomeEncoding.textContent = normalized.useEncryption
            ? `${normalized.encoding} · ${normalized.encryption.toUpperCase()}`
            : `${normalized.encoding} · none`;
    }
    if (opsecOutcomeFilename) {
        const copies = normalized.filenameCopies.length
            ? ` + ${normalized.filenameCopies.join(', ')}`
            : '';
        opsecOutcomeFilename.textContent = normalized.filenamePrimary + copies;
    }
    if (opsecOutcomeServer) {
        opsecOutcomeServer.textContent = location.host
            ? `${location.host}/uploads/`
            : t('opsecOutcomeServerBody');
    }
}

function renderSizeInfo(plan) {
    if (!opsecSizeWarning || !opsecSizeMessage || !plan?.sizeInfo) {
        if (opsecSizeWarning) opsecSizeWarning.hidden = true;
        return;
    }
    const info = plan.sizeInfo;
    const estimateLabel = t(
        info.approximate
            ? 'opsecSizeEstimateApproximate'
            : 'opsecSizeEstimateExact'
    );
    let message = t('opsecSizeWarningMessage')
        .replace('{0}', estimateLabel)
        .replace('{1}', formatSize(info.estimatedBytes))
        .replace('{2}', formatSize(info.serverLimit))
        .replace('{3}', formatSize(info.browserLimit))
        .replace('{4}', t(profileTitleKey(info.suggestedProfile)));
    if (!info.overLimit) {
        message = t('opsecSizeWithinLimitMessage')
            .replace('{0}', estimateLabel)
            .replace('{1}', formatSize(info.estimatedBytes))
            .replace('{2}', formatSize(info.serverLimit))
            .replace('{3}', formatSize(info.browserLimit))
            .replace('{4}', t(profileTitleKey(info.suggestedProfile)));
    }
    opsecSizeMessage.textContent = message;
    opsecSizeWarning.dataset.overLimit = String(info.overLimit);
    opsecSizeWarning.dataset.estimatedBytes = String(info.estimatedBytes);
    opsecSizeWarning.dataset.approximate = String(info.approximate);
    opsecSizeWarning.hidden = false;
}

function setAdvancedPreviewPending(pending) {
    opsecState.previewPending = Boolean(pending);
    if (opsecPreviewPending) {
        opsecPreviewPending.hidden = !opsecState.previewPending;
    }
    if (opsecOutcomeSummary) {
        opsecOutcomeSummary.setAttribute('aria-busy', String(opsecState.previewPending));
    }
    if (opsecUploadBtn) {
        const session = advancedSession.getSnapshot();
        opsecUploadBtn.disabled = opsecState.previewPending
            || !opsecState.file
            || session.active !== true
            || session.phase !== 'active';
    }
}

function setInspectorError(message) {
    setExchangeInspector('opsec', {
        phase: 'error',
        request: {
            phase: 'empty',
            emptyText: t('exchangeRequestEmpty'),
        },
        response: {
            phase: 'error',
            summaryText: message,
            startLine: message,
            body: createExchangeTextBody(message),
        },
    });
}

async function rebuildAdvancedPreview(options = {}) {
    if (opsecState.previewSuppressed) {
        return null;
    }
    const sequence = ++opsecState.previewSequence;
    const sessionSnapshot = cloneAdvancedSessionSnapshot(
        options.sessionSnapshot || advancedSession.getSnapshot()
    );
    const raw = readAdvancedRequestState();
    const normalized = normalizeAdvancedRequestState(raw, sessionSnapshot);

    if (!opsecState.file) {
        opsecState.preview = null;
        applyNormalizedControls(normalized);
        renderConstructorFeedback(normalized);
        syncConstructorControlVisibility(normalized);
        renderOutcomeFromPlan({ normalized });
        renderSizeInfo(null);
        setExchangeInspector('opsec', {
            phase: 'empty',
            request: { phase: 'empty', emptyText: t('exchangeRequestEmpty') },
            response: { phase: 'empty', emptyText: t('exchangeResponseEmpty') },
        });
        setAdvancedPreviewPending(false);
        return null;
    }

    setAdvancedPreviewPending(true);
    try {
        const fingerprint = advancedStateFingerprint(normalized, opsecState.file);
        const plan = await compileAdvancedRequest(
            normalized,
            opsecState.file,
            sessionSnapshot
        );
        if (sequence !== opsecState.previewSequence) {
            return null;
        }
        opsecState.preview = {
            sequence,
            fingerprint,
            sessionSnapshot,
            plan,
        };
        applyNormalizedControls(normalized);
        renderConstructorFeedback(normalized);
        syncConstructorControlVisibility(normalized);
        renderSizeInfo(plan);
        renderOutcomeFromPlan(plan);
        if (!plan.valid) {
            setInspectorError(plan.errorMessage);
            setAdvancedPreviewPending(false);
            return opsecState.preview;
        }
        setExchangeInspector('opsec', {
            phase: 'ready',
            request: {
                ...plan.requestExchange,
                summaryText: t('opsecPreviewReady'),
            },
            response: {
                phase: 'empty',
                emptyText: t('exchangeResponseEmpty'),
            },
        });
        setAdvancedPreviewPending(false);
        return opsecState.preview;
    } catch (error) {
        if (sequence !== opsecState.previewSequence) {
            return null;
        }
        opsecState.preview = null;
        applyNormalizedControls(normalized);
        renderConstructorFeedback(normalized);
        syncConstructorControlVisibility(normalized);
        renderOutcomeFromPlan({ normalized });
        renderSizeInfo(null);
        setInspectorError(error.message);
        setAdvancedPreviewPending(false);
        return null;
    }
}

async function refreshOpsecRequestPreview() {
    return rebuildAdvancedPreview();
}

function refreshOpsecSelectionLocale() {
    if (opsecSelectionState) {
        opsecSelectionState.hidden = !opsecState.file;
        opsecSelectionState.textContent = opsecState.file
            ? `${t('selectedLabel')}: ${opsecState.file.name} (${formatSize(opsecState.file.size)})`
            : t('opsecSelectionIdle');
    }
    if (opsecDropZone) {
        opsecDropZone.classList.toggle('has-selection', Boolean(opsecState.file));
    }
}

function refreshOpsecControlState() {
    const tab = document.getElementById('tab-opsec');
    if (tab) {
        tab.removeAttribute('title');
    }
    if (opsecFileInput) opsecFileInput.disabled = false;
    if (opsecMethodInput) opsecMethodInput.disabled = false;
    if (opsecRandomMethodBtn) opsecRandomMethodBtn.disabled = false;
    if (opsecEncryptionSelect) opsecEncryptionSelect.disabled = false;
    if (opsecDropZone) {
        opsecDropZone.classList.remove('is-disabled');
        opsecDropZone.setAttribute('aria-disabled', 'false');
        opsecDropZone.setAttribute('tabindex', '0');
    }
    const session = advancedSession.getSnapshot();
    const normalized = normalizeAdvancedRequestState(
        readAdvancedRequestState(),
        session
    );
    applyNormalizedControls(normalized);
    renderConstructorFeedback(normalized);
    syncConstructorControlVisibility(normalized);
    renderOutcomeFromPlan(opsecState.preview?.plan || { normalized });
    if (opsecUploadBtn) {
        opsecUploadBtn.disabled = !opsecState.file
            || session.active !== true
            || session.phase !== 'active';
    }
}

function setOpsecFile(file) {
    clearOpsecSessionGateMessage();
    resetOpsecPreviewPath();
    if (!file) {
        opsecState.preview = null;
    }
    opsecState.file = file || null;
    refreshOpsecSelectionLocale();
    refreshOpsecControlState();
    if (opsecState.file) {
        announceLiveRegion(
            'opsecResponseAreaLive',
            `${t('opsecFileSelected')}: ${opsecState.file.name}`
        );
    }
    void refreshOpsecRequestPreview();
}

function generateRandomMethod() {
    const prefixes = ['CHECK', 'SYNC', 'VERIFY', 'UPDATE', 'QUERY', 'REPORT', 'SUBMIT'];
    const suffixes = ['DATA', 'STATUS', 'INFO', 'CONTENT', 'RESOURCE', ''];
    const prefix = prefixes[Math.floor(Math.random() * prefixes.length)];
    const suffix = suffixes[Math.floor(Math.random() * suffixes.length)];
    if (opsecMethodInput) {
        opsecMethodInput.value = suffix ? `${prefix}${suffix}` : prefix;
    }
    void refreshOpsecRequestPreview();
}

function applyCookieEffects(effects) {
    for (const effect of effects) {
        if (effect.action === 'delete') {
            document.cookie = `${effect.name}=; Path=/; Max-Age=0; SameSite=Lax`;
        } else if (effect.action === 'set') {
            const cookiePair = serializeCookiePairs([effect]);
            document.cookie = `${cookiePair}; Path=/; SameSite=Lax`;
        }
    }
}

function copyAdvancedResponseHeaders(headers) {
    if (headers instanceof Headers) {
        return Object.freeze(Object.fromEntries(headers.entries()));
    }
    return Object.freeze({ ...(headers || {}) });
}

function createAdvancedRetryPlan(plan) {
    return Object.freeze({
        ...plan,
        requestHeaders: Object.freeze({ ...(plan.requestHeaders || {}) }),
        cookieEffects: Object.freeze((plan.cookieEffects || []).map(effect => Object.freeze({ ...effect }))),
    });
}

function showAdvancedUploadError(plan, response, text, message, origin) {
    const retryPlan = createAdvancedRetryPlan(plan);
    return httpErrors.show({
        host: 'opsecHttpErrorHost',
        origin: origin || opsecUploadBtn,
        method: retryPlan.method,
        path: retryPlan.requestPath,
        status: Number(response?.status || 0),
        statusText: response?.statusText || message || t('error'),
        headers: copyAdvancedResponseHeaders(response?.headers),
        body: String(text || message || ''),
        retry: () => sendAdvancedUploadPlan(retryPlan, origin || opsecUploadBtn),
    });
}

function getCanonicalAdvancedUpload(payload) {
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
        || typeof payload.file.path !== 'string'
        || !payload.file.path
        || typeof payload.file.name !== 'string'
        || !payload.file.name
        || typeof payload.upload.kind !== 'string'
        || payload.upload.kind !== 'advanced'
    ) {
        return null;
    }
    return payload;
}

async function sendAdvancedUploadPlan(plan, origin = null) {
    const sendingText = `${t('opsecUploading')} ${plan.method} [${plan.profileId}]`;
    let closeErrorCardAfterRefresh = false;
    if (opsecUploadBtn) opsecUploadBtn.disabled = true;
    announceLiveRegion('opsecResponseAreaLive', sendingText);
    setExchangeInspector('opsec', {
        phase: 'sending',
        request: plan.requestExchange,
        response: {
            phase: 'sending',
            summaryText: sendingText,
            startLine: sendingText,
            body: createExchangeTextBody(sendingText),
        },
    });

    try {
        const checkedSession = await advancedSession.current();
        if (!checkedSession?.active) {
            throw new Error(t('advancedSessionInactive'));
        }
        applyCookieEffects(plan.cookieEffects || []);
        // The bearer exists only in the session service and this transient
        // header object. It is never copied into the plan or inspector state.
        const transientInit = advancedSession.attachSessionHeader({
            headers: plan.requestHeaders,
        });
        const response = await sendCustomRequest(
            plan.method,
            plan.requestUrl,
            plan.requestBody,
            transientInit.headers
        );
        const text = await response.text();
        let result = null;
        try {
            result = JSON.parse(text);
        } catch (_error) {}

        const canonicalUpload = getCanonicalAdvancedUpload(result);
        const success = Boolean(response.ok && canonicalUpload);
        if (success) {
            const responseExchange = createExchangeHttpResponseMessage(response, text, {
                method: plan.method,
                path: plan.requestPath,
                phase: 'complete',
                summaryText: `${t('opsecSuccess')}: ${canonicalUpload.file.path}`,
                exportFilenameBase: 'xferry-opsec-response',
            });
            responseExchange.statusText = response.statusText || t('opsecUploaded');
            responseExchange.body = createExchangeTextBody(text, {
                contentType: 'application/json',
            });
            setExchangeInspector('opsec', {
                phase: 'complete',
                request: plan.requestExchange,
                response: responseExchange,
            });
            closeErrorCardAfterRefresh = true;
            announceLiveRegion(
                'opsecResponseAreaLive',
                `${t('opsecSuccess')}: ${canonicalUpload.file.path}`
            );
        } else {
            const message = result?.error?.message
                || (response.ok ? t('error') : `HTTP ${response.status}`);
            const responseExchange = createExchangeHttpResponseMessage(response, text, {
                method: plan.method,
                path: plan.requestPath,
                phase: 'error',
                summaryText: message,
                exportFilenameBase: 'xferry-opsec-response',
            });
            responseExchange.body = createExchangeTextBody(message);
            setExchangeInspector('opsec', {
                phase: 'error',
                request: plan.requestExchange,
                response: responseExchange,
            });
            showAdvancedUploadError(plan, response, text, message, origin);
            announceLiveRegion('opsecResponseAreaLive', `${plan.method} ${t('error')}: ${message}`);
        }
    } catch (error) {
        const message = error?.message || String(error);
        setInspectorError(message);
        httpErrors.show({
            host: 'opsecHttpErrorHost',
            origin: origin || opsecUploadBtn,
            method: plan.method,
            path: plan.requestPath,
            status: 0,
            statusText: message,
            headers: {},
            body: message,
            retry: () => sendAdvancedUploadPlan(createAdvancedRetryPlan(plan), origin || opsecUploadBtn),
        });
        announceLiveRegion('opsecResponseAreaLive', `${t('error')}: ${message}`);
    } finally {
        refreshOpsecControlState();
        if (closeErrorCardAfterRefresh) {
            httpErrors.close('opsecHttpErrorHost');
        }
    }
}

async function opsecUpload() {
    if (!opsecState.file) {
        return;
    }
    if (opsecState.previewPending) {
        announceOpsecSessionGate('opsecPreviewChangedBlocked');
        return;
    }
    clearOpsecSessionGateMessage();
    if (opsecUploadBtn) opsecUploadBtn.disabled = true;

    await advancedSession.current();
    try {
        await advancedSession.ensureActive();
    } catch (_error) {
        announceOpsecSessionGate('advancedSessionInactive');
        refreshOpsecControlState();
        return;
    }
    const freshSessionSnapshot = await advancedSession.current();
    if (!freshSessionSnapshot?.active) {
        announceOpsecSessionGate('advancedSessionInactive');
        refreshOpsecControlState();
        return;
    }

    const raw = readAdvancedRequestState();
    const normalized = normalizeAdvancedRequestState(raw, freshSessionSnapshot);
    const fingerprint = advancedStateFingerprint(normalized, opsecState.file);
    const preview = opsecState.preview;
    const sessionChanged = !advancedSessionSnapshotsEqual(
        preview?.sessionSnapshot,
        freshSessionSnapshot
    );
    const inputChanged = !preview || preview.fingerprint !== fingerprint;
    if (sessionChanged || inputChanged) {
        await rebuildAdvancedPreview({ sessionSnapshot: freshSessionSnapshot });
        announceOpsecSessionGate('opsecPreviewChangedBlocked');
        refreshOpsecControlState();
        return;
    }

    const plan = preview.plan;
    if (!plan?.valid) {
        if (plan?.normalized?.useEncryption && !plan.normalized.password) {
            showOpsecPasswordError();
        }
        announceLiveRegion('opsecResponseAreaLive', plan?.errorMessage || t('error'));
        refreshOpsecControlState();
        return;
    }
    clearOpsecPasswordError();

    try {
        opsecState.lastDispatchedPlanIdentity = preview.sequence;
        await sendAdvancedUploadPlan(plan, opsecUploadBtn);
    } finally {
        resetOpsecPreviewPath();
        opsecState.preview = null;
        opsecState.previewSuppressed = true;
        try {
            refreshOpsecControlState();
        } finally {
            opsecState.previewSuppressed = false;
        }
    }
}

function bindConstructorEvents() {
    const controls = [
        opsecConstructorMode,
        opsecProfileSelect,
        opsecCarrierSelect,
        opsecBodyFormatSelect,
        opsecEncodingSelect,
        opsecMimeInput,
        opsecPartMimeInput,
        opsecFilenamePrimarySelect,
        opsecMethodOverrideSelect,
    ].filter(Boolean);
    controls.forEach(control => {
        const eventName = control instanceof HTMLInputElement ? 'input' : 'change';
        control.addEventListener(eventName, () => {
            clearOpsecSessionGateMessage();
            void refreshOpsecRequestPreview();
        });
    });
    opsecFilenameCopies?.querySelectorAll('input[type="checkbox"]').forEach(input => {
        input.addEventListener('change', () => void refreshOpsecRequestPreview());
    });
    opsecMethodInput?.addEventListener('input', () => void refreshOpsecRequestPreview());
    opsecEncryptionSelect?.addEventListener('change', () => {
        if (opsecEncryptionSelect.value === 'none') {
            if (opsecKeyBase64Checkbox) opsecKeyBase64Checkbox.checked = false;
            clearOpsecPasswordError();
        } else {
            opsecSettingsDetails.open = true;
            opsecPasswordInput?.focus();
        }
        void refreshOpsecRequestPreview();
    });
    opsecKeyBase64Checkbox?.addEventListener('change', () => void refreshOpsecRequestPreview());
    opsecPasswordInput?.addEventListener('input', () => {
        clearOpsecPasswordError();
        void refreshOpsecRequestPreview();
    });
}

opsecRandomMethodBtn?.addEventListener('click', generateRandomMethod);
opsecUploadBtn?.addEventListener('click', opsecUpload);
opsecFileInput?.addEventListener('change', () => {
    if (opsecFileInput.files.length > 0) {
        setOpsecFile(opsecFileInput.files[0]);
        opsecFileInput.value = '';
    }
});

if (opsecDropZone && opsecFileInput) {
    bindDropZoneKeyboardTrigger(opsecDropZone, opsecFileInput);
    opsecDropZone.addEventListener('dragover', event => {
        event.preventDefault();
        opsecDropZone.classList.add('dragover');
    });
    opsecDropZone.addEventListener('dragleave', () => {
        opsecDropZone.classList.remove('dragover');
    });
    opsecDropZone.addEventListener('drop', event => {
        event.preventDefault();
        opsecDropZone.classList.remove('dragover');
        if (event.dataTransfer.files.length > 0) {
            setOpsecFile(event.dataTransfer.files[0]);
        }
    });
}

bindConstructorEvents();
generateRandomMethod();
refreshOpsecSelectionLocale();
refreshOpsecControlState();

let observedSessionSnapshot = cloneAdvancedSessionSnapshot(advancedSession.getSnapshot());
advancedSession.subscribe(snapshot => {
    const changed = !advancedSessionSnapshotsEqual(observedSessionSnapshot, snapshot);
    observedSessionSnapshot = cloneAdvancedSessionSnapshot(snapshot);
    refreshOpsecControlState();
    if (changed && opsecState.file) {
        void refreshOpsecRequestPreview();
    }
});

app.on(app.events.LOCALE_CHANGED, () => {
    refreshOpsecSelectionLocale();
    refreshOpsecControlState();
    if (opsecState.sessionGateMessageKey) {
        announceOpsecSessionGate(opsecState.sessionGateMessageKey);
    }
    void refreshOpsecRequestPreview();
});
app.on(app.events.SERVER_METHODS_CHANGED, refreshOpsecControlState);
document.addEventListener('xferry:response-options-changed', () => {
    void refreshOpsecRequestPreview();
});

app.registerWorkflow('advanced', {
    commands: {
        send: opsecUpload,
        'set-file': setOpsecFile,
        'refresh-controls': refreshOpsecControlState,
        'refresh-preview': refreshOpsecRequestPreview,
    },
    getState: () => ({
        fileSelected: Boolean(opsecState.file),
        previewSequence: opsecState.previewSequence,
        previewPathReady: Boolean(opsecState.previewPath),
        previewSuppressed: opsecState.previewSuppressed,
        previewPending: opsecState.previewPending,
        previewFingerprint: opsecState.preview?.fingerprint || null,
        sessionActive: advancedSession.getSnapshot().active,
        previewSessionExpiresAt: opsecState.preview?.sessionSnapshot?.expires_at ?? null,
        previewPlanReady: Boolean(opsecState.preview?.plan?.valid),
        previewPlanIdentity: opsecState.preview?.sequence ?? null,
        lastDispatchedPlanIdentity: opsecState.lastDispatchedPlanIdentity,
    }),
});
})(window.XferryApp);
