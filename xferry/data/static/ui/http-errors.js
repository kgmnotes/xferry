(function initializeHttpErrors(app) {
    'use strict';

const {
    t,
    writeTextToClipboard,
} = app.service('core');
const {
    isSecretKey: isInspectorSecretKey,
    redactMessage: redactInspectorMessage,
} = app.service('inspector');

const capturedBodyLimit = 16 * 1024;
const renderedBodyLimit = 4 * 1024;
const activeCards = new Map();

function normalizeUnsafeControlCharacters(value) {
    return String(value ?? '')
        .replace(/\r\n?/g, '\n')
        .replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, '\uFFFD');
}

function utf8ByteLength(value) {
    return new TextEncoder().encode(String(value ?? '')).byteLength;
}

function truncateUtf8(value, limit) {
    let bytes = 0;
    let text = '';
    for (const character of String(value ?? '')) {
        const characterBytes = utf8ByteLength(character);
        if (bytes + characterBytes > limit) {
            break;
        }
        text += character;
        bytes += characterBytes;
    }
    return { text, bytes, truncated: text.length < String(value ?? '').length };
}

function normalizeHeaders(headers = {}) {
    if (headers instanceof Headers) {
        return Object.fromEntries(headers.entries());
    }
    if (typeof headers === 'string') {
        return Object.fromEntries(
            headers.split(/\r?\n/).map(line => {
                const divider = line.indexOf(':');
                return divider > 0
                    ? [line.slice(0, divider).trim(), line.slice(divider + 1).trim()]
                    : null;
            }).filter(Boolean)
        );
    }
    return Object.fromEntries(
        Object.entries(headers || {}).map(([key, value]) => [
            normalizeUnsafeControlCharacters(key),
            normalizeUnsafeControlCharacters(value),
        ])
    );
}

function getHeader(headers, name) {
    const lowerName = String(name || '').toLowerCase();
    const entry = Object.entries(headers || {}).find(([key]) => key.toLowerCase() === lowerName);
    return entry ? String(entry[1] || '') : '';
}

function classifyBody(contentType, body) {
    if (!body) return 'empty';
    const normalizedType = String(contentType || '').toLowerCase();
    if (normalizedType.includes('json')) return 'json';
    if (normalizedType.includes('html')) return 'html';
    if (normalizedType.startsWith('text/')) return 'text';
    return 'text';
}

function formatJsonForDisplay(text) {
    try {
        return JSON.stringify(JSON.parse(text), null, 2);
    } catch (_error) {
        return text;
    }
}

function redactedValue() {
    return `[${t('exchangeRedacted')}]`;
}

function skipJsonWhitespace(value, start) {
    let index = start;
    while (index < value.length && /\s/.test(value[index])) {
        index += 1;
    }
    return index;
}

function findJsonStringEnd(value, start) {
    let escaped = false;
    for (let index = start + 1; index < value.length; index += 1) {
        const character = value[index];
        if (escaped) {
            escaped = false;
        } else if (character === '\\') {
            escaped = true;
        } else if (character === '"') {
            return index + 1;
        }
    }
    return value.length;
}

function findJsonValueEnd(value, start) {
    const valueStart = skipJsonWhitespace(value, start);
    if (valueStart >= value.length) {
        return value.length;
    }

    const firstCharacter = value[valueStart];
    if (firstCharacter === '"') {
        return findJsonStringEnd(value, valueStart);
    }
    if (firstCharacter !== '{' && firstCharacter !== '[') {
        let index = valueStart;
        while (index < value.length && !',}]'.includes(value[index])) {
            index += 1;
        }
        return index;
    }

    const expectedClosers = [firstCharacter === '{' ? '}' : ']'];
    for (let index = valueStart + 1; index < value.length; index += 1) {
        const character = value[index];
        if (character === '"') {
            const stringEnd = findJsonStringEnd(value, index);
            if (stringEnd === value.length) {
                return value.length;
            }
            index = stringEnd - 1;
        } else if (character === '{') {
            expectedClosers.push('}');
        } else if (character === '[') {
            expectedClosers.push(']');
        } else if (character === '}' || character === ']') {
            if (character !== expectedClosers[expectedClosers.length - 1]) {
                return value.length;
            }
            expectedClosers.pop();
            if (expectedClosers.length === 0) {
                return index + 1;
            }
        }
    }
    return value.length;
}

function decodeJsonPropertyName(value, start, end) {
    if (end === value.length && value[end - 1] !== '"') {
        return null;
    }
    try {
        return JSON.parse(value.slice(start, end));
    } catch (_error) {
        return null;
    }
}

function redactPartialJsonSecretValues(value) {
    const bounded = truncateUtf8(value, capturedBodyLimit).text;
    let output = '';
    let copiedThrough = 0;
    let index = 0;

    while (index < bounded.length) {
        if (bounded[index] !== '"') {
            index += 1;
            continue;
        }

        const propertyEnd = findJsonStringEnd(bounded, index);
        const propertyName = decodeJsonPropertyName(bounded, index, propertyEnd);
        const colonIndex = skipJsonWhitespace(bounded, propertyEnd);
        if (propertyName === null || bounded[colonIndex] !== ':' || !isInspectorSecretKey(propertyName)) {
            index = Math.max(index + 1, propertyEnd);
            continue;
        }

        const valueStart = skipJsonWhitespace(bounded, colonIndex + 1);
        const valueEnd = findJsonValueEnd(bounded, valueStart);
        output += `${bounded.slice(copiedThrough, valueStart)}"${redactedValue()}"`;
        copiedThrough = valueEnd;
        index = Math.max(index + 1, valueEnd);
    }

    return output + bounded.slice(copiedThrough);
}

function redactKeyValueSecretValues(value) {
    const bounded = truncateUtf8(value, capturedBodyLimit).text;
    return bounded.replace(/(^|[?&,\s])([^=\s?&,]+)=([^\s&,]*)/gi, (match, prefix, key) => {
        return isInspectorSecretKey(key) ? `${prefix}${key}=${redactedValue()}` : match;
    });
}

function redactBoundedSecretValues(value) {
    return redactKeyValueSecretValues(redactPartialJsonSecretValues(value));
}

function normalizeError(details = {}) {
    const response = details.response || {};
    const error = details.error || {};
    const rawHeaders = normalizeHeaders(details.headers || response.headers || {});
    const contentType = normalizeUnsafeControlCharacters(
        details.contentType || response.contentType || getHeader(rawHeaders, 'content-type')
    );
    const rawBody = normalizeUnsafeControlCharacters(
        details.body ?? response.body ?? ''
    );
    const totalBytes = Number.isFinite(details.totalBytes)
        ? Math.max(0, Number(details.totalBytes))
        : utf8ByteLength(rawBody);
    const bodyWasTruncated = Boolean(details.bodyTruncated) || totalBytes > utf8ByteLength(rawBody);
    const redacted = redactInspectorMessage({
        path: normalizeUnsafeControlCharacters(details.path || response.path || ''),
        headers: rawHeaders,
        body: {
            kind: 'text',
            text: bodyWasTruncated ? redactBoundedSecretValues(rawBody) : rawBody,
            contentType,
        },
    });
    const bodyKind = classifyBody(contentType, rawBody);
    const redactedBody = bodyKind === 'json' && !bodyWasTruncated
        ? formatJsonForDisplay(redacted.body?.text || '')
        : String(redacted.body?.text || '');
    const safeCapture = truncateUtf8(redactBoundedSecretValues(redactedBody), capturedBodyLimit);
    const shown = truncateUtf8(safeCapture.text, renderedBodyLimit);
    const status = Number.isFinite(details.status)
        ? Number(details.status)
        : (Number.isFinite(response.status) ? Number(response.status) : 0);
    const statusText = redactBoundedSecretValues(normalizeUnsafeControlCharacters(
        details.statusText || response.statusText || error.message || ''
    ));
    const requestId = normalizeUnsafeControlCharacters(
        details.requestId || response.requestId || getHeader(redacted.headers, 'x-request-id')
    );

    return Object.freeze({
        method: normalizeUnsafeControlCharacters(details.method || response.method || ''),
        path: normalizeUnsafeControlCharacters(redacted.path || ''),
        status,
        statusText,
        headers: Object.freeze({ ...(redacted.headers || {}) }),
        contentType,
        bodyKind,
        capturedText: safeCapture.text,
        displayText: shown.text,
        totalBytes,
        capturedBytes: safeCapture.bytes,
        shownBytes: shown.bytes,
        truncated: bodyWasTruncated || safeCapture.truncated || shown.truncated || safeCapture.bytes < totalBytes,
        requestId,
    });
}

function resolveHost(host) {
    if (host instanceof HTMLElement) return host;
    return document.getElementById(String(host || ''));
}

function canRestoreFocus(origin) {
    return Boolean(origin && origin.isConnected && !origin.disabled && typeof origin.focus === 'function');
}

function restoreFocus(origin) {
    if (canRestoreFocus(origin)) {
        origin.focus({ preventScroll: true });
    }
}

function createElement(name, className = '', text = '') {
    const element = document.createElement(name);
    if (className) element.className = className;
    if (text) element.textContent = text;
    return element;
}

function formatHeaders(headers) {
    const entries = Object.entries(headers || {});
    return entries.length
        ? entries.map(([key, value]) => `${key}: ${value}`).join('\n')
        : t('headersNA');
}

function formatCopyText(model) {
    return [
        `${model.method || 'HTTP'} ${model.path || '/'}`.trim(),
        `${model.status} ${model.statusText}`.trim(),
        `${t('httpErrorHeaders')}\n${formatHeaders(model.headers)}`,
        `${t('httpErrorBody')}\n${model.displayText || t('httpErrorNoBody')}`,
    ].join('\n\n');
}

function removeCard(host, restore = true) {
    const state = activeCards.get(host);
    if (!state) return;
    document.removeEventListener('keydown', state.keyHandler);
    state.card.remove();
    activeCards.delete(host);
    if (restore) restoreFocus(state.origin);
}

function renderCard(state, focusCard = false) {
    const { host, model } = state;
    const card = createElement('section', 'http-error-card');
    card.setAttribute('role', 'alert');
    card.setAttribute('tabindex', '-1');
    card.dataset.httpErrorCard = 'true';

    const heading = createElement('h3', 'http-error-card__title', t('httpErrorTitle'));
    const summary = createElement(
        'p',
        'http-error-card__summary',
        `${model.method || 'HTTP'} ${model.path || '/'} · ${model.status} ${model.statusText}`.trim()
    );
    card.append(heading, summary);

    if (model.requestId) {
        card.append(createElement('p', 'http-error-card__request-id', `${t('httpErrorRequestId')}: ${model.requestId}`));
    }

    const actions = createElement('div', 'http-error-card__actions');
    const detailsButton = createElement('button', 'btn-ghost btn--sm', t('httpErrorDetails'));
    detailsButton.type = 'button';
    detailsButton.dataset.httpErrorAction = 'details';
    detailsButton.setAttribute('aria-expanded', String(state.detailsOpen));
    const closeButton = createElement('button', 'btn-ghost btn--sm', t('httpErrorClose'));
    closeButton.type = 'button';
    closeButton.dataset.httpErrorAction = 'close';
    actions.append(detailsButton);
    if (typeof state.retry === 'function') {
        const retryButton = createElement('button', 'btn-info btn--sm', t('httpErrorRetry'));
        retryButton.type = 'button';
        retryButton.dataset.httpErrorAction = 'retry';
        retryButton.addEventListener('click', () => {
            void Promise.resolve(state.retry()).catch(() => {});
        });
        actions.append(retryButton);
    }
    actions.append(closeButton);
    card.append(actions);

    const details = createElement('div', 'http-error-card__details');
    details.dataset.httpErrorDetails = 'true';
    details.hidden = !state.detailsOpen;
    const headersTitle = createElement('h4', 'http-error-card__details-title', t('httpErrorHeaders'));
    const headers = createElement('pre', 'http-error-card__pre', formatHeaders(model.headers));
    const bodyTitle = createElement(
        'h4',
        'http-error-card__details-title',
        model.bodyKind === 'html' ? t('httpErrorHtmlText') : t('httpErrorBody')
    );
    const body = createElement('pre', 'http-error-card__pre', model.displayText || t('httpErrorNoBody'));
    const copyButton = createElement('button', 'btn-info btn--sm', t('httpErrorCopy'));
    copyButton.type = 'button';
    copyButton.dataset.httpErrorAction = 'copy';
    const copyStatus = createElement('p', 'sr-only');
    copyStatus.setAttribute('role', 'status');
    copyStatus.setAttribute('aria-live', 'polite');
    if (model.truncated) {
        details.append(createElement(
            'p',
            'http-error-card__truncated',
            `${t('httpErrorTruncated')} ${model.shownBytes}/${model.totalBytes}`
        ));
    }
    details.append(headersTitle, headers, bodyTitle, body, copyButton, copyStatus);
    card.append(details);

    detailsButton.addEventListener('click', () => {
        state.detailsOpen = !state.detailsOpen;
        details.hidden = !state.detailsOpen;
        detailsButton.setAttribute('aria-expanded', String(state.detailsOpen));
    });
    closeButton.addEventListener('click', () => removeCard(host));
    copyButton.addEventListener('click', () => {
        void writeTextToClipboard(formatCopyText(model), 'http-error')
            .then(() => { copyStatus.textContent = t('httpErrorCopied'); })
            .catch(() => { copyStatus.textContent = t('httpErrorCopyFailed'); });
    });

    state.card = card;
    host.replaceChildren(card);
    if (focusCard) card.focus({ preventScroll: true });
}

function showError(details = {}) {
    const host = resolveHost(details.host);
    const model = normalizeError(details);
    if (!host) {
        return Object.freeze({ card: null, model });
    }
    removeCard(host, false);
    const state = {
        host,
        model,
        origin: details.origin instanceof HTMLElement ? details.origin : document.activeElement,
        retry: details.retry,
        detailsOpen: false,
        card: null,
        keyHandler: null,
    };
    state.keyHandler = (event) => {
        if (event.key === 'Escape' && activeCards.get(host) === state) {
            event.preventDefault();
            event.stopPropagation();
            removeCard(host);
        }
    };
    activeCards.set(host, state);
    document.addEventListener('keydown', state.keyHandler);
    renderCard(state, true);
    return Object.freeze({ card: state.card, model });
}

function closeError(host, options = {}) {
    const element = resolveHost(host);
    if (element) removeCard(element, options.restore !== false);
}

app.on(app.events.LOCALE_CHANGED, () => {
    activeCards.forEach(state => renderCard(state, false));
});

app.registerService('http-errors', {
    capturedBodyLimit,
    renderedBodyLimit,
    normalize: normalizeError,
    show: showError,
    close: closeError,
});
})(window.XferryApp);
