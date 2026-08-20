(function initializeInspector(app) {
    'use strict';

const {
    t,
    escapeHtml: esc,
    formatSize,
    parseJsonSafe,
    formatHttpStatusLabel,
    formatActionErrorMessage,
    writeTextToClipboard,
    announceLiveRegion,
} = app.service('core');

// ===== Shared request/response inspector =====
const exchangePreviewLimit = 4096;
const exchangeHexPreviewLimit = 64;
const exchangeBinaryTextPreviewLimit = 512;
const exchangeSecretKeys = new Set([
    'authorization',
    'cookie',
    'clientpublickey',
    'client_public_key',
    'data',
    'hmac',
    'key_is_base64',
    'publickey',
    'public_key',
    'set-cookie',
    'serverpublickey',
    'server_public_key',
    'x-session-id',
    'key',
    'x-xferry-advanced-session',
    'x-xferry-data',
    'x-xferry-hmac',
    'x-xferry-key',
    'x-xferry-key-is-base64',
    'xferry_data',
    'xferry_hmac',
    'xferry_key',
    'xferry_key_is_base64',
    'sessionid',
    'session_id',
    'password',
    'token',
]);
const exchangeSecretKeyPatterns = [
    /^x-xferry-data-(?:0|[1-9]\d{0,2})$/,
];
const exchangeInspectorStates = new Map();
const exchangeAreaRawText = new Map();
const exchangeAreaDownloadText = new Map();
const exchangeAreaDownloadMeta = new Map();
const uiNoGzipHeader = 'X-XFerry-No-Gzip';
const uiNoGzipHeaderValue = '1';
const responseNoGzipInput = document.getElementById('responseNoGzip');

function exchangeCurrentMode() {
    if (app.hasWorkflow('requests')) {
        const mode = app.getState('requests').previewMode;
        if (mode) {
            return mode;
        }
    }

    try {
        const storedMode = localStorage.getItem('requestPreviewMode');
        return storedMode === 'raw' ? 'raw' : 'summary';
    } catch (_error) {
        return 'summary';
    }
}

function isExchangeSecretKey(key) {
    const normalized = String(key || '').trim().toLowerCase();
    const compact = normalized.replace(/[-_\s]/g, '');
    return exchangeSecretKeys.has(normalized) ||
        exchangeSecretKeys.has(compact) ||
        exchangeSecretKeyPatterns.some(pattern => pattern.test(normalized));
}

function exchangeRedactedLabel() {
    return `[${t('exchangeRedacted')}]`;
}

function redactExchangeValue(value, key = '') {
    if (isExchangeSecretKey(key)) {
        return exchangeRedactedLabel();
    }

    if (Array.isArray(value)) {
        return value.map(item => redactExchangeValue(item));
    }

    if (value && typeof value === 'object') {
        return Object.fromEntries(
            Object.entries(value).map(([entryKey, entryValue]) => [
                entryKey,
                redactExchangeValue(entryValue, entryKey),
            ])
        );
    }

    return value;
}

function safeDecodeExchangeComponent(value) {
    try {
        return decodeURIComponent(String(value || '').replace(/\+/g, ' '));
    } catch (_error) {
        return String(value || '');
    }
}

function redactExchangeQueryString(query) {
    return String(query || '').split('&').map(part => {
        if (!part) {
            return part;
        }

        const equalsIndex = part.indexOf('=');
        const key = equalsIndex === -1 ? part : part.slice(0, equalsIndex);
        if (!isExchangeSecretKey(safeDecodeExchangeComponent(key))) {
            return part;
        }

        return equalsIndex === -1 ? key : `${key}=${exchangeRedactedLabel()}`;
    }).join('&');
}

function redactExchangePath(path) {
    const text = String(path || '');
    const hashIndex = text.indexOf('#');
    const pathAndQuery = hashIndex === -1 ? text : text.slice(0, hashIndex);
    const hash = hashIndex === -1 ? '' : text.slice(hashIndex);
    const queryIndex = pathAndQuery.indexOf('?');
    const basePath = queryIndex === -1
        ? pathAndQuery
        : pathAndQuery.slice(0, queryIndex);
    const redactedBasePath = basePath.replace(
        /(\/_payload\/[^/?#]+\/)([^/?#]+)/g,
        (_match, prefix) => `${prefix}${exchangeRedactedLabel()}`
    );
    if (queryIndex === -1) {
        return `${redactedBasePath}${hash}`;
    }

    const query = pathAndQuery.slice(queryIndex + 1);
    return `${redactedBasePath}?${redactExchangeQueryString(query)}${hash}`;
}

function redactExchangeJsonText(text, options = {}) {
    const parsed = parseJsonSafe(text);
    if (parsed === null || typeof parsed !== 'object') {
        return null;
    }

    return JSON.stringify(redactExchangeValue(parsed), null, options.pretty ? 2 : 0);
}

function redactExchangeHeaderLine(line) {
    const match = String(line || '').match(/^([^:\r\n]+):(\s*)(.*)$/);
    if (!match || !isExchangeSecretKey(match[1])) {
        return line;
    }

    return `${match[1]}:${match[2]}${exchangeRedactedLabel()}`;
}

function redactExchangeRequestLine(line) {
    const match = String(line || '').match(/^([A-Z]+)\s+(\S+)(\s+HTTP\/[0-9.]+.*)?$/);
    if (!match) {
        return line;
    }

    return `${match[1]} ${redactExchangePath(match[2])}${match[3] || ''}`;
}

function looksLikeExchangeQueryString(text) {
    return /^[^=\s&]+=[^\s]*(?:&[^=\s&]+=[^\s]*)*$/.test(String(text || ''));
}

function redactExchangeLines(text) {
    return String(text || '').split('\n').map(line => {
        const headerSafeLine = redactExchangeHeaderLine(line);
        const requestSafeLine = redactExchangeRequestLine(headerSafeLine);
        return looksLikeExchangeQueryString(requestSafeLine)
            ? redactExchangeQueryString(requestSafeLine)
            : requestSafeLine;
    }).join('\n');
}

function redactExchangeText(text, options = {}) {
    const normalized = String(text || '');
    if (!normalized) {
        return '';
    }

    const contentType = String(options.contentType || '').toLowerCase();
    if (contentType.includes('json') || /^[\s\r\n]*[\[{]/.test(normalized)) {
        const redactedJson = redactExchangeJsonText(normalized, options);
        if (redactedJson !== null) {
            return redactedJson;
        }
    }

    const xmlSafe = normalized.replace(
        /<(data|key|key_is_base64|hmac)(\s[^>]*)?>[\s\S]*?<\/\1>/gi,
        (_match, name, attributes = '') => (
            `<${name}${attributes}>${exchangeRedactedLabel()}</${name}>`
        )
    );

    const bodySeparatorMatch = xmlSafe.match(/\r?\n\r?\n/);
    if (options.splitHttpBody !== false && bodySeparatorMatch && bodySeparatorMatch.index !== undefined) {
        const separatorStart = bodySeparatorMatch.index;
        const separator = bodySeparatorMatch[0];
        const head = xmlSafe.slice(0, separatorStart);
        const body = xmlSafe.slice(separatorStart + separator.length);
        return [
            redactExchangeLines(head),
            separator,
            redactExchangeText(body, { ...options, splitHttpBody: false }),
        ].join('');
    }

    return redactExchangeLines(xmlSafe);
}

function normalizeExchangeHeaders(headers = {}) {
    return Object.fromEntries(
        Object.entries(headers || {}).map(([key, value]) => [
            key,
            redactExchangeValue(value, key),
        ])
    );
}

function truncateExchangeText(text, limit = exchangePreviewLimit) {
    const normalized = String(text || '');
    if (normalized.length <= limit) {
        return normalized;
    }

    return `${normalized.slice(0, limit)}\n... ${t('exchangeTruncated')} (${normalized.length - limit})`;
}

function formatExchangeHeaders(headers = {}) {
    const safeHeaders = normalizeExchangeHeaders(headers);
    const lines = Object.entries(safeHeaders)
        .filter(([, value]) => value !== undefined && value !== null && value !== '')
        .map(([key, value]) => `${key}: ${value}`);
    return lines.length ? lines.join('\n') : t('headersNA');
}

function formatExchangeBytes(bytes, limit = exchangeHexPreviewLimit) {
    if (!bytes) {
        return '';
    }

    const view = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
    return Array.from(view.slice(0, limit))
        .map(value => value.toString(16).padStart(2, '0'))
        .join(' ');
}

function getExchangeByteView(bytes) {
    if (!bytes) {
        return null;
    }

    return bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
}

function decodeExchangeBytePreview(bytes, limit = exchangeBinaryTextPreviewLimit) {
    const view = getExchangeByteView(bytes);
    if (!view) {
        return '';
    }

    const preview = view.slice(0, limit);
    if (typeof TextDecoder === 'function') {
        return new TextDecoder('utf-8', { fatal: false }).decode(preview);
    }

    return Array.from(preview)
        .map(value => (value >= 32 && value <= 126) || value === 9 || value === 10 || value === 13
            ? String.fromCharCode(value)
            : '\uFFFD')
        .join('');
}

function normalizeExchangeBodyPreviewText(text) {
    return String(text || '')
        .replace(/\0/g, '\uFFFD')
        .replace(/\r\n/g, '\n');
}

function formatExchangeBinaryBodyPreview(body = {}, options = {}) {
    const view = getExchangeByteView(body.bytes);
    if (!view) {
        return options.raw
            ? t('exchangeBinaryBodyPreviewPending')
            : `${t('exchangeBinaryBodyPreview')}: ${t('exchangeBinaryBodyPreviewPending')}`;
    }

    const previewText = normalizeExchangeBodyPreviewText(
        decodeExchangeBytePreview(view, exchangeBinaryTextPreviewLimit)
    );
    const lines = options.raw
        ? [previewText]
        : [`${t('exchangeBinaryBodyPreview')}:`, previewText];
    const previewedBytes = Math.min(view.byteLength, exchangeBinaryTextPreviewLimit);
    const omittedBytes = Math.max(0, (body.size || view.byteLength) - previewedBytes);
    if (omittedBytes > 0) {
        lines.push(`... ${t('exchangeTruncated')} (${omittedBytes})`);
    }
    return lines.filter(line => line !== '').join('\n') || t('requestPreviewNoBody');
}

function createExchangeTextBody(text, options = {}) {
    return {
        kind: options.kind || 'text',
        text: String(text || ''),
        contentType: options.contentType || '',
        size: options.size,
        label: options.label || '',
    };
}

function createExchangeJsonBody(value, options = {}) {
    return {
        kind: 'json',
        value,
        rawText: options.rawText,
        contentType: options.contentType || 'application/json',
        label: options.label || '',
    };
}

function createExchangeBinaryBody(options = {}) {
    return {
        kind: 'binary',
        filename: options.filename || '',
        contentType: options.contentType || 'application/octet-stream',
        size: Number(options.size || 0),
        bytes: options.bytes || null,
        label: options.label || '',
    };
}

function createExchangePreviewBody(options = {}) {
    return {
        kind: options.kind || 'preview',
        label: options.label || '',
        text: String(options.text || ''),
        size: options.size,
        contentType: options.contentType || '',
    };
}

function formatExchangeBody(body, options = {}) {
    if (!body) {
        return t('requestPreviewNoBody');
    }

    if (body.kind === 'json') {
        if (options.raw && body.rawText !== undefined) {
            return truncateExchangeText(redactExchangeText(body.rawText, { contentType: body.contentType })) || t('requestPreviewNoBody');
        }
        return truncateExchangeText(JSON.stringify(redactExchangeValue(body.value), null, 2));
    }

    if (body.kind === 'binary') {
        const previewText = formatExchangeBinaryBodyPreview(body, options);
        if (options.raw) {
            return previewText;
        }

        const lines = [
            `${t('exchangeBodyKind')}: ${t('exchangeBinaryBody')}`,
        ];
        if (body.filename) lines.push(`${t('fileName')}: ${body.filename}`);
        if (body.contentType) lines.push(`${t('responseSummaryFieldContentType')}: ${body.contentType}`);
        lines.push(`${t('requestPreviewFieldBodySize')}: ${formatSize(body.size || 0)}`);
        lines.push(previewText);
        const hex = formatExchangeBytes(body.bytes);
        lines.push(`${t('exchangeHexPreview')}: ${hex || t('headersNA')}`);
        if ((body.size || 0) > exchangeHexPreviewLimit) {
            lines.push(`... ${t('exchangeTruncated')} (${body.size - exchangeHexPreviewLimit})`);
        }
        return lines.join('\n');
    }

    if (body.kind === 'preview') {
        const lines = [];
        if (body.label) lines.push(`${t('exchangeBodyKind')}: ${body.label}`);
        if (body.contentType) lines.push(`${t('responseSummaryFieldContentType')}: ${body.contentType}`);
        if (body.size !== undefined) lines.push(`${t('requestPreviewFieldBodySize')}: ${formatSize(body.size)}`);
        if (body.text) lines.push(truncateExchangeText(redactExchangeText(body.text, { contentType: body.contentType })));
        return lines.length ? lines.join('\n') : t('requestPreviewNoBody');
    }

    const text = redactExchangeText(body.text || '', {
        contentType: body.contentType,
        pretty: !options.raw,
    });
    return truncateExchangeText(text) || t('requestPreviewNoBody');
}

function redactExchangeBodyModel(body) {
    if (!body || typeof body !== 'object') {
        return body;
    }

    if (body.kind === 'json') {
        return {
            ...body,
            value: redactExchangeValue(body.value),
            rawText: body.rawText === undefined
                ? body.rawText
                : redactExchangeText(body.rawText, { contentType: body.contentType }),
        };
    }

    if (body.kind === 'preview' || body.kind === 'text' || !body.kind) {
        return {
            ...body,
            text: redactExchangeText(body.text || '', { contentType: body.contentType }),
        };
    }

    return { ...body };
}

function redactExchangeMessageModel(message = {}) {
    if (!message || typeof message !== 'object') {
        return message;
    }

    return {
        ...message,
        path: message.path ? redactExchangePath(message.path) : message.path,
        startLine: message.startLine ? redactExchangeText(message.startLine) : message.startLine,
        rawText: message.rawText ? redactExchangeText(message.rawText) : message.rawText,
        headers: normalizeExchangeHeaders(message.headers || {}),
        body: redactExchangeBodyModel(message.body),
    };
}

function buildExchangeStartLine(message, side) {
    if (message.startLine) {
        return redactExchangeText(message.startLine);
    }

    if (message.transport === 'ws') {
        const direction = side === 'request' ? t('exchangeWsSend') : t('exchangeWsReceive');
        return `${direction} ${redactExchangePath(message.path || '/notes/ws')}`;
    }

    if (side === 'response') {
        const status = message.status ? `${message.status} ${message.statusText || ''}`.trim() : t('statusPending');
        return message.transport === 'ws' ? status : `HTTP/1.1 ${status}`;
    }

    const method = message.method || 'GET';
    const path = redactExchangePath(message.path || '/');
    return `${method} ${path} HTTP/1.1`;
}

function buildExchangeRawMessage(message = {}, side = 'request') {
    if (!message || message.phase === 'empty') {
        return message?.emptyText || t(side === 'request' ? 'exchangeRequestEmpty' : 'exchangeResponseEmpty');
    }

    if (message.rawText) {
        return redactExchangeText(message.rawText, {
            contentType: message.body?.contentType,
        });
    }

    const lines = [buildExchangeStartLine(message, side)];
    const headersText = formatExchangeHeaders(message.headers || {});
    if (headersText && headersText !== t('headersNA')) {
        lines.push(headersText);
    }

    if (message.body) {
        const bodyText = formatExchangeBody(message.body, { raw: true });
        lines.push('', bodyText);
    }
    return lines.join('\n');
}

function formatExchangeHeadersForExport(headers = {}) {
    const lines = Object.entries(headers || {})
        .filter(([, value]) => value !== undefined && value !== null && value !== '')
        .map(([key, value]) => `${key}: ${value}`);
    return lines.length ? lines.join('\n') : t('headersNA');
}

function formatExchangeBodyForExport(body) {
    if (!body) {
        return t('requestPreviewNoBody');
    }

    if (body.kind === 'json') {
        if (body.rawText !== undefined) {
            return String(body.rawText || '') || t('requestPreviewNoBody');
        }
        return JSON.stringify(body.value, null, 2);
    }

    if (body.kind === 'binary') {
        const lines = [
            `${t('exchangeBodyKind')}: ${t('exchangeBinaryBody')}`,
        ];
        if (body.filename) lines.push(`${t('fileName')}: ${body.filename}`);
        if (body.contentType) lines.push(`${t('responseSummaryFieldContentType')}: ${body.contentType}`);
        lines.push(`${t('requestPreviewFieldBodySize')}: ${formatSize(body.size || 0)}`);
        lines.push(formatExchangeBinaryBodyPreview(body));
        const hex = formatExchangeBytes(body.bytes);
        lines.push(`${t('exchangeHexPreview')}: ${hex || t('headersNA')}`);
        if ((body.size || 0) > exchangeHexPreviewLimit) {
            lines.push(`... ${t('exchangeTruncated')} (${body.size - exchangeHexPreviewLimit})`);
        }
        return lines.join('\n');
    }

    if (body.kind === 'preview') {
        const lines = [];
        if (body.label) lines.push(`${t('exchangeBodyKind')}: ${body.label}`);
        if (body.contentType) lines.push(`${t('responseSummaryFieldContentType')}: ${body.contentType}`);
        if (body.size !== undefined) lines.push(`${t('requestPreviewFieldBodySize')}: ${formatSize(body.size)}`);
        if (body.text) lines.push(String(body.text));
        return lines.length ? lines.join('\n') : t('requestPreviewNoBody');
    }

    return String(body.text || '') || t('requestPreviewNoBody');
}

function buildExchangeStartLineForExport(message, side) {
    if (message.startLine) {
        return String(message.startLine);
    }

    if (message.transport === 'ws') {
        const direction = side === 'request' ? t('exchangeWsSend') : t('exchangeWsReceive');
        return `${direction} ${message.path || '/notes/ws'}`;
    }

    if (side === 'response') {
        const status = message.status ? `${message.status} ${message.statusText || ''}`.trim() : t('statusPending');
        return message.transport === 'ws' ? status : `HTTP/1.1 ${status}`;
    }

    const method = message.method || 'GET';
    const path = message.path || '/';
    return `${method} ${path} HTTP/1.1`;
}

function buildExchangeRawMessageForExport(message = {}, side = 'request') {
    if (!message || message.phase === 'empty') {
        return message?.emptyText || t(side === 'request' ? 'exchangeRequestEmpty' : 'exchangeResponseEmpty');
    }

    if (message.rawText) {
        return redactExchangeText(message.rawText, {
            contentType: message.body?.contentType,
        });
    }

    const lines = [redactExchangeText(buildExchangeStartLineForExport(message, side))];
    const headersText = formatExchangeHeaders(message.headers || {});
    if (headersText && headersText !== t('headersNA')) {
        lines.push(headersText);
    }

    if (message.body) {
        lines.push('', redactExchangeText(formatExchangeBodyForExport(message.body), {
            contentType: message.body?.contentType,
        }));
    }

    return lines.join('\n');
}

function getUiNoGzipHeaderPair() {
    return [uiNoGzipHeader, uiNoGzipHeaderValue];
}

function withUiNoGzipHeader(headers = {}) {
    const requestHeaders = { ...(headers || {}) };
    if (!responseNoGzipInput?.checked) {
        return requestHeaders;
    }
    const [headerName, headerValue] = getUiNoGzipHeaderPair();
    const hasHeader = Object.keys(requestHeaders).some(key => key.toLowerCase() === headerName.toLowerCase());
    if (!hasHeader) {
        requestHeaders[headerName] = headerValue;
    }
    return requestHeaders;
}

responseNoGzipInput?.addEventListener('change', () => {
    document.dispatchEvent(new Event('xferry:response-options-changed'));
});

function getExchangeResponseContentType(response = {}) {
    const headers = response.headers || {};
    const match = Object.entries(headers).find(([key]) => String(key).toLowerCase() === 'content-type');
    return match ? String(match[1] || '') : '';
}

function buildHttpResponseRawText(response = {}, bodyText = '') {
    const status = response.status ? `${response.status} ${response.statusText || ''}`.trim() : t('statusPending');
    const headerText = String(response.rawResponseHeadersText || '').trim() || formatExchangeHeaders(response.headers || '');
    const lines = [`HTTP/1.1 ${status}`];
    if (headerText && headerText !== t('headersNA')) {
        lines.push(headerText);
    }
    lines.push('', String(bodyText || ''));
    return lines.join('\n');
}

function createExchangeHttpResponseMessage(response = {}, bodyText = '', options = {}) {
    const rawText = buildHttpResponseRawText(response, bodyText);
    return {
        transport: 'http',
        method: options.method || '',
        path: options.path || '',
        phase: options.phase || (response.ok === false ? 'error' : 'complete'),
        summaryText: options.summaryText || '',
        status: response.status,
        statusText: response.statusText || '',
        headers: response.headers || {},
        body: createExchangeTextBody(bodyText, {
            contentType: getExchangeResponseContentType(response),
        }),
        rawText,
        exportText: rawText,
        exportFilenameBase: options.exportFilenameBase || '',
        sensitive: Boolean(options.sensitive),
    };
}

function buildExchangeMetric(label, value, options = {}) {
    if (value === undefined || value === null || value === '') {
        return '';
    }

    const classes = ['request-preview-summary__metric-value'];
    if (options.badge) classes.push('request-preview-summary__metric-value--badge');
    if (options.tone) classes.push(`request-preview-summary__metric-value--${options.tone}`);

    return `
        <div class="request-preview-summary__metric">
            <span class="request-preview-summary__metric-label">${esc(label)}</span>
            <span class="${classes.join(' ')}">${esc(value)}</span>
        </div>
    `;
}

function buildSummarySection(title, content, modifier = '') {
    const className = modifier
        ? `request-preview-summary__code request-preview-summary__code--${modifier}`
        : 'request-preview-summary__code';
    return `
        <section class="request-preview-summary__section">
            <p class="request-preview-summary__section-title">${esc(title)}</p>
            <div class="${className}">${esc(content)}</div>
        </section>
    `;
}

function buildExchangeSummary(message = {}, side = 'request') {
    const metrics = [
        buildExchangeMetric(t('exchangeTransport'), message.transport === 'ws' ? 'WebSocket' : 'HTTP'),
        buildExchangeMetric(t('requestPreviewFieldMethod'), message.method || message.type || ''),
        buildExchangeMetric(t('requestPreviewFieldPath'), redactExchangePath(message.path || '')),
    ];

    if (side === 'response') {
        const statusValue = message.status
            ? formatHttpStatusLabel(message.status, message.statusText || '')
            : (message.phase === 'error' ? t('error') : t('statusPending'));
        metrics.push(buildExchangeMetric(
            t('responseSummaryFieldStatus'),
            statusValue,
            { badge: true, tone: message.phase === 'error' || message.status >= 400 ? 'danger' : (message.status ? 'success' : 'pending') }
        ));
    }

    if (message.duration) {
        metrics.push(buildExchangeMetric(t('time'), `${message.duration}ms`));
    }

    const headersText = formatExchangeHeaders(message.headers || {});
    const bodyText = formatExchangeBody(message.body, { raw: false });
    return `
        <div class="request-preview-summary exchange-summary">
            <div class="request-preview-summary__metrics">
                ${metrics.join('')}
            </div>
            ${headersText && headersText !== t('headersNA') ? buildSummarySection(t('headers'), headersText) : ''}
            ${buildSummarySection(side === 'request' ? t('requestBody') : t('responseBody'), bodyText, 'body')}
        </div>
    `;
}

function getToolPhaseKey(phase) {
    switch (String(phase || 'empty')) {
        case 'ready':
            return 'toolPhaseReady';
        case 'sending':
            return 'toolPhasePending';
        case 'complete':
            return 'toolPhaseSuccess';
        case 'error':
            return 'toolPhaseError';
        default:
            return 'toolPhaseIdle';
    }
}

function getToolPhaseLabel(phase) {
    return t(getToolPhaseKey(phase));
}

function getToolSummaryRoot(scope) {
    return document.querySelector(`[data-tool-summary-scope="${scope}"]`);
}

function getToolTraceRoot(scope) {
    return document.querySelector(`[data-tool-trace-scope="${scope}"]`);
}

function extractToolSummaryText(message = {}) {
    if (!message || message.phase === 'empty') {
        return '';
    }

    if (message.summaryText) {
        return String(message.summaryText).trim();
    }

    if (message.body) {
        const bodyText = formatExchangeBody(message.body, { raw: false });
        const firstUsefulLine = String(bodyText || '')
            .split(/\r?\n/)
            .map(line => line.trim())
            .find(line => (
                line
                && line !== t('requestPreviewNoBody')
                && line !== t('headersNA')
                && line !== '{'
                && line !== '['
            ));
        if (firstUsefulLine) {
            return firstUsefulLine;
        }
    }

    if (message.startLine) {
        const firstLine = String(redactExchangeText(message.startLine))
            .split(/\r?\n/)
            .map(line => line.trim())
            .find(Boolean);
        if (firstLine) {
            return firstLine.replace(/^HTTP\/1\.1\s+/i, '').trim();
        }
    }

    const method = message.method || message.type || '';
    const path = redactExchangePath(message.path || '');
    return `${method}${path ? ` ${path}` : ''}`.trim();
}

function buildToolSummaryMeta(state = {}) {
    const request = state.request || {};
    const response = state.response || {};
    const items = [];
    const useSummaryMetaOnly = state.summaryMetaMode === 'replace';

    if (!useSummaryMetaOnly && (request.method || request.type)) {
        items.push({
            label: t('requestPreviewFieldMethod'),
            value: request.method || request.type || '',
            field: 'method',
        });
    }

    if (!useSummaryMetaOnly && request.path) {
        items.push({
            label: t('requestPreviewFieldPath'),
            value: redactExchangePath(request.path),
            field: 'request-path',
        });
    }

    if (!useSummaryMetaOnly && response.status) {
        items.push({
            label: t('responseSummaryFieldStatus'),
            value: typeof formatHttpStatusLabel === 'function'
                ? formatHttpStatusLabel(response.status, response.statusText || '')
                : `${response.status}${response.statusText ? ` ${response.statusText}` : ''}`.trim(),
            tone: response.status >= 400 ? 'danger' : 'success',
            field: 'status',
        });
    } else if (!useSummaryMetaOnly && (response.phase || state.phase) === 'error') {
        items.push({
            label: t('responseSummaryFieldStatus'),
            value: t('toolPhaseError'),
            tone: 'danger',
            field: 'status',
        });
    }

    if (Array.isArray(state.summaryMeta)) {
        state.summaryMeta.forEach(item => {
            if (!item || item.value === undefined || item.value === null || item.value === '') {
                return;
            }

            items.push({
                label: item.label || '',
                value: item.value,
                tone: item.tone || '',
                field: item.field || '',
            });
        });
    }

    return items;
}

function renderToolSummary(scope, state = {}) {
    const root = getToolSummaryRoot(scope);
    if (!root) {
        return;
    }

    const phase = state.phase || state.response?.phase || state.request?.phase || 'empty';
    const titleEl = root.querySelector('[data-tool-summary-title]');
    const bodyEl = root.querySelector('[data-tool-summary-body]');
    const badgeEl = root.querySelector('[data-tool-summary-badge]');
    const metaEl = root.querySelector('[data-tool-summary-meta]');
    const idleTitleKey = root.dataset.toolSummaryIdleTitleKey || '';
    const idleBodyKey = root.dataset.toolSummaryIdleBodyKey || '';
    const responseText = extractToolSummaryText(state.response || {});
    const requestText = extractToolSummaryText(state.request || {});

    const title = phase === 'empty'
        ? t(idleTitleKey)
        : getToolPhaseLabel(phase);
    const body = phase === 'empty'
        ? t(idleBodyKey)
        : (responseText || requestText || '');

    root.dataset.phase = phase;
    if (titleEl) {
        titleEl.textContent = title;
    }
    if (bodyEl) {
        bodyEl.textContent = body;
    }
    if (badgeEl) {
        badgeEl.hidden = phase === 'empty';
        badgeEl.textContent = phase === 'empty' ? '' : getToolPhaseLabel(phase);
        badgeEl.dataset.phase = phase;
    }
    if (metaEl) {
        const items = buildToolSummaryMeta(state);
        metaEl.innerHTML = items.map(item => `
            <div
                class="tool-result__meta-item"
                ${item.field ? `data-tool-summary-field="${esc(item.field)}"` : ''}
                ${scope === 'upload' && item.field && ['status', 'server-path', 'size'].includes(item.field) ? `data-upload-result-field="${esc(item.field)}"` : ''}
            >
                <span class="tool-result__meta-label">${esc(item.label)}</span>
                <span class="tool-result__meta-value${item.tone ? ` tool-result__meta-value--${item.tone}` : ''}">${esc(item.value)}</span>
            </div>
        `).join('');
        metaEl.hidden = items.length === 0;
    }
}

function renderToolTrace(scope, state = {}) {
    const root = getToolTraceRoot(scope);
    if (!root) {
        return;
    }

    const phase = state.phase || state.response?.phase || state.request?.phase || 'empty';
    const phaseEl = root.querySelector('[data-tool-trace-phase]');
    root.dataset.phase = phase;
    if (phaseEl) {
        phaseEl.hidden = phase === 'empty';
        phaseEl.textContent = phase === 'empty' ? '' : getToolPhaseLabel(phase);
        phaseEl.dataset.phase = phase;
    }
}

function renderExchangePane(area, message = {}, side = 'request') {
    if (!area) {
        return;
    }

    const phase = message.phase || 'ready';
    const rawText = buildExchangeRawMessage(message, side);
    const downloadText = message.exportText !== undefined
        ? String(message.exportText || '')
        : buildExchangeRawMessageForExport(message, side);
    const hasDownload = Boolean(downloadText) && phase !== 'empty' && !(side === 'response' && phase === 'sending');
    exchangeAreaRawText.set(area.id, rawText);
    exchangeAreaDownloadText.set(area.id, hasDownload ? downloadText : '');
    exchangeAreaDownloadMeta.set(area.id, {
        filenameBase: message.exportFilenameBase || area.id,
        sensitive: Boolean(message.sensitive),
        side,
    });
    area.dataset.exchangePhase = phase;
    area.dataset.exchangeTransport = message.transport || 'http';
    area.dataset.exchangeMethod = message.method || message.type || '';
    area.dataset.exchangePath = redactExchangePath(message.path || '');
    area.dataset.requestView = exchangeCurrentMode();
    if (typeof document.querySelectorAll === 'function') {
        document.querySelectorAll('[data-exchange-download-area]').forEach(button => {
            if (button.dataset.exchangeDownloadArea === area.id) {
                button.disabled = !hasDownload;
                button.dataset.exchangeSensitive = message.sensitive ? 'true' : 'false';
            }
        });
    }

    const forceRawView = area.dataset.exchangeView === 'raw' || message.view === 'raw';
    if (phase === 'empty' || phase === 'sending' || forceRawView) {
        area.textContent = rawText;
    } else if (exchangeCurrentMode() === 'summary') {
        area.innerHTML = buildExchangeSummary(message, side);
    } else {
        area.textContent = rawText;
    }
}

function renderExchangeInspector(scope) {
    const state = exchangeInspectorStates.get(scope);
    if (!state) {
        return;
    }

    renderToolSummary(scope, state);
    renderToolTrace(scope, state);

    const root = document.querySelector(`[data-exchange-scope="${scope}"]`);
    if (!root) {
        return;
    }

    renderExchangePane(root.querySelector('[data-exchange-pane="request"]'), state.request, 'request');
    renderExchangePane(root.querySelector('[data-exchange-pane="response"]'), state.response, 'response');
    root.dataset.exchangePhase = state.phase || state.response?.phase || state.request?.phase || 'ready';
}

function renderAllExchangeInspectors() {
    Array.from(exchangeInspectorStates.keys()).forEach(renderExchangeInspector);
}

function setExchangeInspector(scope, state = {}) {
    const request = redactExchangeMessageModel(
        state.request || { phase: 'empty', emptyText: t('exchangeRequestEmpty') }
    );
    const response = redactExchangeMessageModel(
        state.response || { phase: 'empty', emptyText: t('exchangeResponseEmpty') }
    );

    exchangeInspectorStates.set(scope, {
        phase: state.phase || response?.phase || request?.phase || 'ready',
        summaryMetaMode: state.summaryMetaMode || '',
        summaryMeta: Array.isArray(state.summaryMeta) ? state.summaryMeta.slice() : [],
        request,
        response,
    });
    renderExchangeInspector(scope);
}

function getExchangeAreaRawText(areaId) {
    return exchangeAreaRawText.get(areaId) || document.getElementById(areaId)?.innerText || '';
}

function getExchangeAreaDownloadText(areaId) {
    return exchangeAreaDownloadText.get(areaId) || getExchangeAreaRawText(areaId);
}

function getExchangeInspectorState(scope) {
    const state = exchangeInspectorStates.get(scope);
    if (!state) {
        return null;
    }
    return JSON.parse(JSON.stringify(state));
}

function setToolSummaryActions(scope, markup = '') {
    const root = getToolSummaryRoot(scope);
    const actions = root?.querySelector('[data-tool-summary-actions]');
    if (!actions) {
        return;
    }

    const nextMarkup = String(markup || '').trim();
    actions.innerHTML = nextMarkup;
    actions.hidden = nextMarkup.length === 0;
}

async function copyExchangeAreaRaw(areaId, liveRegionId, messageKey) {
    const text = getExchangeAreaRawText(areaId);
    if (!text) return;

    try {
        await writeTextToClipboard(text, areaId);
        announceLiveRegion(liveRegionId, t(messageKey));
    } catch (error) {
        announceLiveRegion(liveRegionId, formatActionErrorMessage(t('clipboardCopyFailed'), error));
    }
}

function downloadBlobFile(blob, filename) {
    const blobUrlApi = window.URL || window.webkitURL;
    if (!blobUrlApi?.createObjectURL) {
        throw new Error('Blob URLs are unavailable');
    }

    const objectUrl = blobUrlApi.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = objectUrl;
    link.download = filename;
    link.hidden = true;
    document.body.appendChild(link);
    link.click();
    link.remove();

    window.setTimeout(() => {
        blobUrlApi.revokeObjectURL(objectUrl);
    }, 1000);
}

function sanitizeDownloadFilenamePart(value) {
    return String(value || '')
        .trim()
        .replace(/[^a-z0-9._-]+/gi, '-')
        .replace(/^-+|-+$/g, '')
        .slice(0, 72) || 'exchange';
}

function buildExchangeDownloadFilename(areaId, filenameBase = '') {
    const meta = exchangeAreaDownloadMeta.get(areaId) || {};
    const base = sanitizeDownloadFilenamePart(filenameBase || meta.filenameBase || areaId);
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    return `${base}-${timestamp}.http`;
}

function downloadExchangeAreaRaw(areaId, liveRegionId, messageKey, filenameBase = '') {
    const text = getExchangeAreaDownloadText(areaId);
    if (!text) return;

    const filename = buildExchangeDownloadFilename(areaId, filenameBase);
    try {
        downloadBlobFile(new Blob([text], { type: 'text/plain;charset=utf-8' }), filename);
        announceLiveRegion(liveRegionId, t(messageKey || 'exchangeLogDownloaded'));
    } catch (error) {
        announceLiveRegion(liveRegionId, formatActionErrorMessage(t('exchangeLogDownloadFailed'), error));
    }
}

document.addEventListener('click', (event) => {
    const copyButton = event.target.closest('[data-exchange-copy-area]');
    if (copyButton) {
        const areaId = copyButton.dataset.exchangeCopyArea;
        const liveRegionId = copyButton.dataset.exchangeCopyLive || '';
        const messageKey = copyButton.dataset.exchangeCopyMessage || 'exchangeCopied';
        void copyExchangeAreaRaw(areaId, liveRegionId, messageKey);
        return;
    }

    const downloadButton = event.target.closest('[data-exchange-download-area]');
    if (!downloadButton) return;

    const areaId = downloadButton.dataset.exchangeDownloadArea;
    const liveRegionId = downloadButton.dataset.exchangeDownloadLive || '';
    const messageKey = downloadButton.dataset.exchangeDownloadMessage || 'exchangeLogDownloaded';
    const filenameBase = downloadButton.dataset.exchangeDownloadBase || '';
    downloadExchangeAreaRaw(areaId, liveRegionId, messageKey, filenameBase);
});

app.on(app.events.LOCALE_CHANGED, renderAllExchangeInspectors);

app.registerService('inspector', {
    binaryTextPreviewLimit: exchangeBinaryTextPreviewLimit,
    buildRawMessage: buildExchangeRawMessage,
    buildRawMessageForExport: buildExchangeRawMessageForExport,
    createBinaryBody: createExchangeBinaryBody,
    createHttpResponseMessage: createExchangeHttpResponseMessage,
    createJsonBody: createExchangeJsonBody,
    createPreviewBody: createExchangePreviewBody,
    createTextBody: createExchangeTextBody,
    downloadBlob: downloadBlobFile,
    getAreaRawText: getExchangeAreaRawText,
    getInspectorState: getExchangeInspectorState,
    getNoGzipHeaderPair: getUiNoGzipHeaderPair,
    isSecretKey: isExchangeSecretKey,
    redactMessage: redactExchangeMessageModel,
    renderAll: renderAllExchangeInspectors,
    renderPane: renderExchangePane,
    setInspector: setExchangeInspector,
    setSummaryActions: setToolSummaryActions,
    withNoGzipHeader: withUiNoGzipHeader,
});
})(window.XferryApp);
