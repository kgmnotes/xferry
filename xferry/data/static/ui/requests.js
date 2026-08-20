(function initializeRequests(app) {
    'use strict';

const {
    t,
    escapeHtml: esc,
    formatSize,
    serverUrl: SERVER_URL,
    announceLiveRegion,
    focusElementWithoutScroll,
    isServerMethodSupported,
} = app.service('core');
const {
    withNoGzipHeader: withUiNoGzipHeader,
} = app.service('inspector');
const httpErrors = app.service('http-errors');

function buildSmuggleRequestPath(...args) {
    return app.invoke('smuggle', 'build-request-path', ...args);
}

function resolveSmuggleDownloadName(...args) {
    return app.invoke('smuggle', 'resolve-download-name', ...args);
}

function adaptSmuggleResult(...args) {
    return app.invoke('smuggle', 'adapt-result', ...args);
}

function buildSmuggleResponseSummary(...args) {
    return app.invoke('smuggle', 'build-response-summary', ...args);
}

function showSmuggleDialog(...args) {
    return app.invoke('smuggle', 'show-dialog', ...args);
}

// ===== Отправка запросов =====
const responseAreaEl = document.getElementById('responseArea');
const pathInputEl = document.getElementById('pathInput');
const requestMethodButtons = Array.from(document.querySelectorAll('[data-request-method]'));
const requestPanelPrepMethods = new Set(['DELETE', 'FETCH', 'SMUGGLE']);
const requestPreviewModeStorageKey = 'requestPreviewMode';
const requestPreviewSectionEl = document.getElementById('requestPreviewSection');
const requestPreviewAreaEl = document.getElementById('requestPreviewArea');
const requestPreviewCopyBtnEl = document.getElementById('requestPreviewCopyBtn');
const heroResponsePanelEl = document.getElementById('heroResponsePanel');
const requestPreviewPaneEl = requestPreviewAreaEl
    ? requestPreviewAreaEl.closest('.exchange-pane--request')
    : null;
const requestRunAllBtnEl = document.getElementById('requestRunAllBtn');
const requestTechnicalDetailsEl = document.getElementById('requestTechnicalDetails');
const requestBatchDetailsEl = document.getElementById('requestBatchDetails');
const requestBatchRerunIssuesBtnEl = document.getElementById('requestBatchRerunIssuesBtn');
const requestBatchExportBtnEl = document.getElementById('requestBatchExportBtn');
const requestBatchClearBtnEl = document.getElementById('requestBatchClearBtn');
const requestBatchIssuesOnlyToggleEl = document.getElementById('requestBatchIssuesOnlyToggle');
const requestBatchStatusEl = document.getElementById('requestBatchStatus');
const requestBatchSummaryEl = document.getElementById('requestBatchSummary');
const requestPreviewModeButtons = Array.from(document.querySelectorAll('[data-request-preview-mode]'));
const responseCopyBtnEl = document.getElementById('responseCopyBtn');
const requestPreviewModes = new Set(['summary', 'raw']);
const requestPreviewExpectedStatuses = {
    GET: { code: 200, text: 'OK' },
    HEAD: { code: 200, text: 'OK' },
    POST: { code: 201, text: 'Created' },
    PUT: { code: 201, text: 'Created' },
    PATCH: { code: 201, text: 'Created' },
    DELETE: { code: 200, text: 'OK' },
    OPTIONS: { code: 204, text: 'No Content' },
    FETCH: { code: 200, text: 'OK' },
    INFO: { code: 200, text: 'OK' },
    PING: { code: 200, text: 'OK' },
    NONE: { code: 201, text: 'Created' },
    NOTE: { code: 200, text: 'OK' },
    SMUGGLE: { code: 200, text: 'OK' },
};
const requestPreviewStatusTextFallbacks = {
    200: 'OK',
    201: 'Created',
    204: 'No Content',
    404: 'Not Found',
};
const requestBatchInitialPaths = {
    GET: '/index.html',
    HEAD: '/index.html',
    POST: '/ignored-post',
    PUT: '/ignored-put',
    PATCH: '/ignored-patch',
    DELETE: '/ignored-delete',
    OPTIONS: '/ignored-options',
    FETCH: '/ignored-fetch',
    INFO: '/',
    PING: '/ignored-ping',
    NONE: '/ignored-none',
    NOTE: '/ignored-note',
    SMUGGLE: '/ignored-smuggle',
};
const requestState = {
    previewMode: 'summary',
    preview: {
        phase: 'empty',
        model: null,
    },
    busy: false,
    batchRunning: false,
    showBatchIssuesOnly: Boolean(requestBatchIssuesOnlyToggleEl?.checked),
    batchRun: {
        phase: 'idle',
        completed: 0,
        total: 0,
        results: [],
        selectedExchangeId: '',
    },
    responseView: {
        phase: 'idle',
        model: null,
    },
};
try {
    const storedRequestPreviewMode = localStorage.getItem(requestPreviewModeStorageKey);
    if (requestPreviewModes.has(storedRequestPreviewMode)) {
        requestState.previewMode = storedRequestPreviewMode;
    }
} catch (_error) {
    // Ignore storage access failures and keep the default summary mode.
}

requestMethodButtons.forEach(button => {
    button.addEventListener('click', async () => {
        const method = button.dataset.requestMethod;
        if (method) {
            if (method === 'SMUGGLE' && isRequestPanelSmuggleUploadPath(normalizeRequestPath(pathInputEl ? pathInputEl.value : '', ''))) {
                await launchRequestPanelSmuggleBuilder(button);
                return;
            }
            await sendRequest(method, button);
        }
    });
});

function setRequestPreviewMode(mode, btn, options = {}) {
    const { focusButton = false } = options;
    if (!requestPreviewModes.has(mode)) {
        return;
    }

    requestState.previewMode = mode;
    let activeButton = btn || null;
    requestPreviewModeButtons.forEach(button => {
        const isActive = button.dataset.requestPreviewMode === mode;
        button.classList.toggle('active', isActive);
        button.setAttribute('aria-checked', String(isActive));
        button.setAttribute('tabindex', isActive ? '0' : '-1');
        if (isActive) {
            activeButton = button;
        }
    });

    if (requestPreviewAreaEl) {
        requestPreviewAreaEl.dataset.requestView = requestState.previewMode;
    }

    try {
        localStorage.setItem(requestPreviewModeStorageKey, requestState.previewMode);
    } catch (_error) {
        // Ignore storage access failures and keep the in-memory mode.
    }

    if (focusButton) {
        focusElementWithoutScroll(activeButton);
    }

    renderRequestPreview();
    renderResponseView();
    if (typeof renderAllExchangeInspectors === 'function') {
        renderAllExchangeInspectors();
    }
}

requestPreviewModeButtons.forEach(button => {
    button.addEventListener('click', () => {
        const mode = button.dataset.requestPreviewMode;
        if (mode) {
            setRequestPreviewMode(mode, button);
        }
    });

    button.addEventListener('keydown', (event) => {
        const currentIndex = requestPreviewModeButtons.indexOf(button);
        if (currentIndex === -1) {
            return;
        }

        let nextIndex;
        if (event.key === 'ArrowRight') {
            nextIndex = (currentIndex + 1) % requestPreviewModeButtons.length;
        } else if (event.key === 'ArrowLeft') {
            nextIndex = (currentIndex - 1 + requestPreviewModeButtons.length) % requestPreviewModeButtons.length;
        } else if (event.key === 'Home') {
            nextIndex = 0;
        } else if (event.key === 'End') {
            nextIndex = requestPreviewModeButtons.length - 1;
        } else {
            return;
        }

        event.preventDefault();
        const nextButton = requestPreviewModeButtons[nextIndex];
        const mode = nextButton?.dataset.requestPreviewMode;
        if (mode) {
            setRequestPreviewMode(mode, nextButton, { focusButton: true });
        }
    });
});

if (requestRunAllBtnEl) {
    requestRunAllBtnEl.addEventListener('click', runAllRequestMethods);
}

if (requestBatchRerunIssuesBtnEl) {
    requestBatchRerunIssuesBtnEl.addEventListener('click', rerunRequestBatchIssues);
}

if (requestBatchExportBtnEl) {
    requestBatchExportBtnEl.addEventListener('click', exportRequestBatchReport);
}

if (requestBatchClearBtnEl) {
    requestBatchClearBtnEl.addEventListener('click', () => {
        clearRequestBatchRun({ announce: true, resetFilter: true });
    });
}

if (requestBatchIssuesOnlyToggleEl) {
    requestBatchIssuesOnlyToggleEl.addEventListener('change', () => {
        requestState.showBatchIssuesOnly = requestBatchIssuesOnlyToggleEl.checked;
        renderRequestBatchSummary();
    });
}

if (requestBatchSummaryEl) {
    requestBatchSummaryEl.addEventListener('click', (event) => {
        const rerunButton = event.target.closest('[data-batch-rerun-method]');
        if (!rerunButton) {
            const row = event.target.closest('[data-batch-exchange-id]');
            if (row && !event.target.closest('button, a, input, label, summary')) {
                selectRequestBatchExchange(row.dataset.batchExchangeId || '');
            }
            return;
        }

        void rerunRequestBatchRow(rerunButton);
    });

    requestBatchSummaryEl.addEventListener('keydown', (event) => {
        if (event.key !== 'Enter' && event.key !== ' ') {
            return;
        }

        const row = event.target.closest('[data-batch-exchange-id]');
        if (!row || event.target.closest('button, a, input, label, summary')) {
            return;
        }

        event.preventDefault();
        selectRequestBatchExchange(row.dataset.batchExchangeId || '');
    });
}

if (requestPreviewCopyBtnEl) {
    requestPreviewCopyBtnEl.addEventListener('click', () => {
        void copyRequestPreviewRaw();
    });
}

if (responseCopyBtnEl) {
    responseCopyBtnEl.addEventListener('click', () => {
        void copyResponseViewRaw();
    });
}

if (responseAreaEl) {
    responseAreaEl.addEventListener('click', (e) => {
        const downloadBtn = e.target.closest('[data-download-path]');
        if (!downloadBtn) return;

        const encodedPath = downloadBtn.dataset.downloadPath;
        if (encodedPath) {
            downloadFile(decodeURIComponent(encodedPath), downloadBtn);
        }
    });
}

function normalizeRequestPath(rawPath, fallback = '/') {
    const trimmed = String(rawPath || '').trim();
    if (!trimmed) {
        return fallback;
    }
    return trimmed.startsWith('/') ? trimmed : `/${trimmed}`;
}

function setRequestPathValue(path) {
    if (pathInputEl && typeof path === 'string' && path) {
        pathInputEl.value = path;
    }
}

function isVisibleRequestFocusTarget(element) {
    return Boolean(
        element &&
        typeof element.focus === 'function' &&
        !element.hidden &&
        !element.disabled &&
        typeof element.getClientRects === 'function' &&
        element.getClientRects().length > 0
    );
}

function resolveStableRequestTriggerElement(element) {
    if (isVisibleRequestFocusTarget(element)) {
        return element;
    }
    if (isVisibleRequestFocusTarget(pathInputEl)) {
        return pathInputEl;
    }
    if (isVisibleRequestFocusTarget(responseAreaEl)) {
        return responseAreaEl;
    }
    return null;
}

function syncRequestControlState() {
    const controlsDisabled = requestState.busy || requestState.batchRunning;
    requestMethodButtons.forEach(button => {
        const methodSupported = typeof isServerMethodSupported !== 'function'
            || isServerMethodSupported(button.dataset.requestMethod);
        button.disabled = controlsDisabled || !methodSupported;
    });
    if (requestRunAllBtnEl) {
        requestRunAllBtnEl.disabled = controlsDisabled;
    }
    if (pathInputEl) {
        pathInputEl.disabled = requestState.batchRunning;
    }
    updateRequestBatchExportButtonState();
    updateRequestBatchClearButtonState();
    updateRequestBatchRerunIssuesButtonState();
    updateRequestBatchRerunButtonState();
}

function setRequestButtonsBusy(isBusy) {
    requestState.busy = isBusy;
    syncRequestControlState();
}

function openRequestBatchDetails() {
    if (requestTechnicalDetailsEl) {
        requestTechnicalDetailsEl.open = true;
    }
    if (requestBatchDetailsEl) {
        requestBatchDetailsEl.open = true;
    }
}

function setRequestBatchBusy(isBusy) {
    requestState.batchRunning = isBusy;
    syncRequestControlState();
}

function setResponseAreaState(method, path, phase, status = '') {
    if (!responseAreaEl) return;
    responseAreaEl.dataset.requestMethod = method || '';
    responseAreaEl.dataset.requestPath = path || '';
    responseAreaEl.dataset.requestPhase = phase || '';
    responseAreaEl.dataset.requestStatus = status ? String(status) : '';
    responseAreaEl.dataset.requestView = requestState.previewMode;
}

function syncHeroResponsePanelState() {
    if (!heroResponsePanelEl) {
        return;
    }

    const phase = requestState.responseView.phase === 'idle' ? 'idle' : 'active';
    heroResponsePanelEl.dataset.panelState = phase;
    if (responseAreaEl) {
        responseAreaEl.dataset.panelState = phase;
        responseAreaEl.setAttribute('aria-busy', String(requestState.responseView.phase === 'progress'));
    }
}

function cloneRequestPreviewState(state) {
    return {
        phase: state.phase,
        model: state.model
            ? {
                method: state.model.method,
                path: state.model.path,
                headers: { ...(state.model.headers || {}) },
                body: state.model.body,
                result: state.model.result
                    ? { ...state.model.result }
                    : null,
            }
            : null,
    };
}

function cloneResponseViewState(state) {
    return {
        phase: state.phase,
        model: state.model
            ? {
                ...state.model,
                headers: state.model.headers ? { ...state.model.headers } : undefined,
            }
            : null,
    };
}

function createRequestExchangeSnapshot() {
    return {
        id: `exchange-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
        requestPreviewState: cloneRequestPreviewState(requestState.preview),
        responseViewState: cloneResponseViewState(requestState.responseView),
    };
}

function applyRequestExchangeSnapshot(snapshot) {
    if (!snapshot) {
        return;
    }

    requestState.preview = cloneRequestPreviewState(snapshot.requestPreviewState || { phase: 'empty', model: null });
    requestState.responseView = cloneResponseViewState(snapshot.responseViewState || { phase: 'idle', model: null });
    renderRequestPreview();
    renderResponseView();
}

function normalizePreviewBody(body) {
    if (body == null) {
        return '';
    }
    return typeof body === 'string' ? body : String(body);
}

function setRequestPreviewDataset(phase, method = '', path = '', comparison = null) {
    if (!requestPreviewAreaEl) return;
    requestPreviewAreaEl.dataset.requestPhase = phase;
    requestPreviewAreaEl.dataset.requestMethod = method;
    requestPreviewAreaEl.dataset.requestPath = path;
    requestPreviewAreaEl.dataset.requestView = requestState.previewMode;
    requestPreviewAreaEl.dataset.requestExpectedStatus = comparison?.expectedLabel || '';
    requestPreviewAreaEl.dataset.requestExpectedCode = comparison?.expectedCode || '';
    requestPreviewAreaEl.dataset.requestActualStatus = comparison?.actualLabel || '';
    requestPreviewAreaEl.dataset.requestActualCode = comparison?.actualCode || '';
    requestPreviewAreaEl.dataset.requestStatusCheck = comparison?.checkState || '';
}

function getExpectedRequestPreviewStatus(method) {
    const definition = requestPreviewExpectedStatuses[method];
    if (!definition) {
        return {
            code: '',
            label: '2xx',
        };
    }

    return {
        code: String(definition.code),
        label: `${definition.code} ${definition.text}`,
    };
}

function formatHttpStatusLabel(status, statusText = '') {
    const normalizedStatusText = String(statusText || '').trim();
    if (normalizedStatusText) {
        return `${status} ${normalizedStatusText}`;
    }

    const fallbackText = requestPreviewStatusTextFallbacks[status];
    return fallbackText ? `${status} ${fallbackText}` : String(status);
}

function getRequestPreviewComparison(model) {
    const expected = getExpectedRequestPreviewStatus(model.method);
    if (!model.result) {
        return {
            expectedCode: expected.code,
            expectedLabel: expected.label,
            actualCode: '',
            actualLabel: t('statusPending'),
            actualTone: 'pending',
            checkState: 'pending',
            checkLabel: t('requestPreviewCheckPending'),
            checkTone: 'pending',
        };
    }

    if (model.result.kind === 'response') {
        const actualCode = String(model.result.status);
        const actualLabel = formatHttpStatusLabel(model.result.status, model.result.statusText);
        const isMatch = expected.code ? actualCode === expected.code : model.result.status >= 200 && model.result.status < 300;
        return {
            expectedCode: expected.code,
            expectedLabel: expected.label,
            actualCode,
            actualLabel,
            actualTone: isMatch ? 'success' : 'danger',
            checkState: isMatch ? 'match' : 'mismatch',
            checkLabel: t(isMatch ? 'requestPreviewCheckMatch' : 'requestPreviewCheckMismatch'),
            checkTone: isMatch ? 'success' : 'danger',
        };
    }

    return {
        expectedCode: expected.code,
        expectedLabel: expected.label,
        actualCode: 'error',
        actualLabel: t('error'),
        actualTone: 'danger',
        checkState: 'failed',
        checkLabel: t('requestPreviewCheckFailed'),
        checkTone: 'danger',
    };
}

function buildRequestExecutionResult(method, path, result = null) {
    const comparison = getRequestPreviewComparison({
        method,
        result,
    });
    return {
        method,
        path,
        expectedStatus: comparison.expectedLabel,
        actualStatus: comparison.actualLabel,
        checkState: comparison.checkState,
        checkLabel: comparison.checkLabel,
        checkTone: comparison.checkTone,
    };
}

function createRequestBatchAttempt(result, timestamp = new Date().toISOString()) {
    return {
        method: result.method,
        path: result.path,
        expectedStatus: result.expectedStatus,
        actualStatus: result.actualStatus,
        checkState: result.checkState,
        checkLabel: result.checkLabel,
        timestamp,
    };
}

function getRequestBatchAttempts(result) {
    if (Array.isArray(result.attempts) && result.attempts.length > 0) {
        return result.attempts.map(attempt => ({
            method: attempt.method || result.method,
            path: attempt.path || result.path,
            expectedStatus: attempt.expectedStatus || result.expectedStatus,
            actualStatus: attempt.actualStatus || result.actualStatus,
            checkState: attempt.checkState || result.checkState,
            checkLabel: attempt.checkLabel || result.checkLabel,
            timestamp: attempt.timestamp || '',
        }));
    }

    return [createRequestBatchAttempt(result)];
}

function getRequestBatchCheckLabel(checkState, fallbackLabel = '') {
    switch (checkState) {
        case 'pending':
            return t('requestPreviewCheckPending');
        case 'match':
            return t('requestPreviewCheckMatch');
        case 'mismatch':
            return t('requestPreviewCheckMismatch');
        case 'failed':
            return t('requestPreviewCheckFailed');
        default:
            return fallbackLabel || String(checkState || '');
    }
}

function buildRequestBatchResult(result, previousResult = null) {
    const previousAttempts = previousResult ? getRequestBatchAttempts(previousResult) : [];
    return {
        ...result,
        attempts: [
            ...previousAttempts,
            createRequestBatchAttempt(result),
        ],
    };
}

function getRequestMethodButtonBaseTitle(button) {
    const titleKey = button.getAttribute('data-i18n-title');
    if (titleKey) {
        return t(titleKey);
    }

    return button.dataset.requestMethod || button.textContent.trim();
}

function getRequestMethodButtonBatchTitle(button, result) {
    const baseTitle = getRequestMethodButtonBaseTitle(button);
    if (!result) {
        return baseTitle;
    }

    const attemptCount = getRequestBatchAttempts(result).length;
    const titleParts = [
        baseTitle,
        `${t('requestPreviewFieldCheck')}: ${getRequestBatchCheckLabel(result.checkState, result.checkLabel)}`,
        `${t('requestPreviewFieldExpectedStatus')}: ${result.expectedStatus}`,
        `${t('requestPreviewFieldActualStatus')}: ${result.actualStatus}`,
    ];

    if (attemptCount > 1) {
        titleParts.push(`${t('requestBatchAttempts')}: ${attemptCount}`);
    }

    return titleParts.join('. ');
}

function updateRequestMethodBatchStates() {
    const latestByMethod = new Map();
    requestState.batchRun.results.forEach(result => {
        latestByMethod.set(result.method, result);
    });

    requestMethodButtons.forEach(button => {
        const method = button.dataset.requestMethod || '';
        const result = latestByMethod.get(method);
        if (!result) {
            delete button.dataset.batchCheck;
            delete button.dataset.batchExpectedStatus;
            delete button.dataset.batchActualStatus;
            button.title = getRequestMethodButtonBaseTitle(button);
            button.removeAttribute('aria-label');
            return;
        }

        button.dataset.batchCheck = result.checkState;
        button.dataset.batchExpectedStatus = result.expectedStatus;
        button.dataset.batchActualStatus = result.actualStatus;
        const label = getRequestMethodButtonBatchTitle(button, result);
        button.title = label;
        button.setAttribute('aria-label', label);
    });
}

function getRequestBatchPlan() {
    return requestMethodButtons
        .map(button => {
            const method = button.dataset.requestMethod;
            if (!method) {
                return null;
            }
            if (typeof isServerMethodSupported === 'function' && !isServerMethodSupported(method)) {
                return null;
            }
            return {
                method,
                initialPath: requestBatchInitialPaths[method] || '/',
            };
        })
        .filter(Boolean);
}

function countRequestBatchResults(results) {
    return results.reduce((counts, result) => {
        if (result.checkState === 'match') {
            counts.match += 1;
        } else if (result.checkState === 'mismatch') {
            counts.mismatch += 1;
        } else if (result.checkState === 'failed') {
            counts.failed += 1;
        }
        return counts;
    }, {
        match: 0,
        mismatch: 0,
        failed: 0,
    });
}

function isRequestBatchIssue(result) {
    return result.checkState === 'mismatch' || result.checkState === 'failed';
}

function getRequestBatchRerunOutcome(result) {
    const attempts = getRequestBatchAttempts(result);
    if (attempts.length <= 1) {
        return null;
    }

    const previousAttempt = attempts[attempts.length - 2];
    const latestAttempt = attempts[attempts.length - 1];
    const wasIssue = isRequestBatchIssue(previousAttempt);
    const isIssue = isRequestBatchIssue(latestAttempt);

    if (wasIssue && !isIssue) {
        return {
            state: 'fixed',
            tone: 'success',
            label: t('requestBatchRerunFixed'),
        };
    }

    if (wasIssue && isIssue) {
        return {
            state: 'still-failing',
            tone: 'danger',
            label: t('requestBatchRerunStillFailing'),
        };
    }

    if (!wasIssue && isIssue) {
        return {
            state: 'regressed',
            tone: 'danger',
            label: t('requestBatchRerunRegressed'),
        };
    }

    return {
        state: 'still-ok',
        tone: 'success',
        label: t('requestBatchRerunStillOk'),
    };
}

function buildRequestBatchCounter(label, value, tone = '') {
    const classes = ['request-batch-summary__count'];
    if (tone) {
        classes.push(`request-batch-summary__count--${tone}`);
    }
    return `
        <div class="${classes.join(' ')}">
            <span class="request-batch-summary__count-label">${esc(label)}</span>
            <span class="request-batch-summary__count-value">${esc(value)}</span>
        </div>
    `;
}

function getRequestBatchAttemptTone(attempt) {
    if (attempt.checkState === 'match') {
        return 'success';
    }
    if (attempt.checkState === 'mismatch' || attempt.checkState === 'failed') {
        return 'danger';
    }
    return 'pending';
}

function formatRequestBatchAttemptTime(timestamp) {
    if (!timestamp) {
        return '';
    }

    const date = new Date(timestamp);
    if (Number.isNaN(date.getTime())) {
        return timestamp;
    }

    const locale = document.documentElement.lang === 'ru' ? 'ru-RU' : 'en-US';
    return date.toLocaleTimeString(locale, {
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
    });
}

function buildRequestBatchAttemptHistory(result, attempts) {
    if (attempts.length <= 1) {
        return '';
    }

    const isOpen = isRequestBatchIssue(result);
    return `
        <details
            class="request-batch-summary__history"
            data-batch-attempt-history="${esc(result.method)}"
            data-batch-attempt-history-count="${esc(String(attempts.length))}"
            data-batch-attempt-history-open="${esc(String(isOpen))}"
            ${isOpen ? 'open' : ''}
        >
            <summary>${esc(t('requestBatchAttemptHistory'))} (${esc(String(attempts.length))})</summary>
            <ol class="request-batch-summary__history-list">
                ${attempts.map((attempt, index) => `
                    <li
                        class="request-batch-summary__history-item"
                        data-batch-attempt-index="${esc(String(index + 1))}"
                        data-batch-attempt-check="${esc(attempt.checkState)}"
                        data-batch-attempt-actual-status="${esc(attempt.actualStatus)}"
                    >
                        <span class="request-batch-summary__history-index">${esc(t('requestBatchAttempt'))} ${esc(String(index + 1))}</span>
                        <span class="request-batch-summary__history-status">
                            ${esc(t('requestPreviewFieldExpectedStatus'))}: ${esc(attempt.expectedStatus)}
                            &middot;
                            ${esc(t('requestPreviewFieldActualStatus'))}: ${esc(attempt.actualStatus)}
                        </span>
                        <span class="request-batch-summary__history-meta">
                            <time datetime="${esc(attempt.timestamp)}">${esc(formatRequestBatchAttemptTime(attempt.timestamp))}</time>
                            <span class="request-batch-summary__history-badge request-batch-summary__history-badge--${esc(getRequestBatchAttemptTone(attempt))}">${esc(getRequestBatchCheckLabel(attempt.checkState, attempt.checkLabel))}</span>
                        </span>
                    </li>
                `).join('')}
            </ol>
        </details>
    `;
}

function buildRequestBatchRow(result) {
    const rerunLabel = `${t('requestBatchRerunLabel')}: ${result.method} ${result.path}`;
    const rerunDisabled = requestState.busy || requestState.batchRunning ? ' disabled' : '';
    const attempts = getRequestBatchAttempts(result);
    const attemptCount = attempts.length;
    const rerunOutcome = getRequestBatchRerunOutcome(result);
    const attemptsText = attemptCount > 1
        ? `<span class="request-batch-summary__attempts">${esc(t('requestBatchAttempts'))}: ${esc(String(attemptCount))}</span>`
        : '';
    const rerunOutcomeText = rerunOutcome
        ? `<span class="request-batch-summary__rerun-outcome request-batch-summary__rerun-outcome--${esc(rerunOutcome.tone)}">${esc(t('requestBatchLastRerun'))}: ${esc(rerunOutcome.label)}</span>`
        : '';
    const attemptHistory = buildRequestBatchAttemptHistory(result, attempts);
    const exchangeId = result.exchangeSnapshot?.id || '';
    const isSelected = exchangeId && requestState.batchRun.selectedExchangeId === exchangeId;
    return `
        <div
            class="request-batch-summary__row${isSelected ? ' request-batch-summary__row--selected' : ''}"
            data-batch-method="${esc(result.method)}"
            data-batch-path="${esc(result.path)}"
            data-batch-expected-status="${esc(result.expectedStatus)}"
            data-batch-actual-status="${esc(result.actualStatus)}"
            data-batch-check="${esc(result.checkState)}"
            data-batch-attempt-count="${esc(String(attemptCount))}"
            data-batch-rerun-outcome="${esc(rerunOutcome?.state || '')}"
            data-batch-rerun-outcome-tone="${esc(rerunOutcome?.tone || '')}"
            data-batch-exchange-id="${esc(exchangeId)}"
            tabindex="${exchangeId ? '0' : '-1'}"
            role="${exchangeId ? 'button' : 'group'}"
        >
            <div class="request-batch-summary__identity">
                <span class="request-batch-summary__method">${esc(result.method)}</span>
                <span class="request-batch-summary__path">${esc(result.path)}</span>
            </div>
            <div class="request-batch-summary__details">
                <span>${esc(t('requestPreviewFieldExpectedStatus'))}: ${esc(result.expectedStatus)}</span>
                <span>${esc(t('requestPreviewFieldActualStatus'))}: ${esc(result.actualStatus)}</span>
                ${attemptsText}
                ${rerunOutcomeText}
            </div>
            <span class="request-batch-summary__badge request-batch-summary__badge--${esc(result.checkTone)}">${esc(getRequestBatchCheckLabel(result.checkState, result.checkLabel))}</span>
            <div class="request-batch-summary__actions">
                <button
                    type="button"
                    class="btn-info btn-icon request-batch-summary__rerun-btn"
                    data-batch-rerun-method="${esc(result.method)}"
                    data-batch-rerun-path="${esc(encodeURIComponent(result.path))}"
                    title="${esc(rerunLabel)}"
                    aria-label="${esc(rerunLabel)}"
                    ${rerunDisabled}
                >↻</button>
            </div>
            ${attemptHistory}
        </div>
    `;
}

function getRequestBatchStatusText(state, counts) {
    if (state.phase === 'running') {
        return `${t('requestBatchRunning')}: ${state.completed}/${state.total}`;
    }
    if (state.phase === 'complete') {
        return `${t('requestBatchCompleted')}: ${counts.match}/${state.total}`;
    }
    return '';
}

function getVisibleRequestBatchResults(results) {
    if (!requestState.showBatchIssuesOnly) {
        return results;
    }

    return results.filter(isRequestBatchIssue);
}

function getRequestBatchIssueResults() {
    return requestState.batchRun.results.filter(isRequestBatchIssue);
}

function buildRequestBatchReport() {
    const counts = countRequestBatchResults(requestState.batchRun.results);
    return {
        generatedAt: new Date().toISOString(),
        phase: requestState.batchRun.phase,
        completed: requestState.batchRun.completed,
        total: requestState.batchRun.total,
        summary: {
            label: getRequestBatchStatusText(requestState.batchRun, counts),
            matchCount: counts.match,
            mismatchCount: counts.mismatch,
            failedCount: counts.failed,
        },
        results: requestState.batchRun.results.map(result => ({
            method: result.method,
            path: result.path,
            expectedStatus: result.expectedStatus,
            actualStatus: result.actualStatus,
            checkState: result.checkState,
            checkLabel: getRequestBatchCheckLabel(result.checkState, result.checkLabel),
            attempts: getRequestBatchAttempts(result).map(attempt => ({
                method: attempt.method,
                path: attempt.path,
                expectedStatus: attempt.expectedStatus,
                actualStatus: attempt.actualStatus,
                checkState: attempt.checkState,
                checkLabel: getRequestBatchCheckLabel(attempt.checkState, attempt.checkLabel),
                timestamp: attempt.timestamp,
            })),
        })),
    };
}

function buildRequestBatchExportFilename(timestamp) {
    const normalizedTimestamp = String(timestamp || new Date().toISOString()).replace(/[:.]/g, '-');
    return `request-run-summary-${normalizedTimestamp}.json`;
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

function updateRequestBatchExportButtonState() {
    if (!requestBatchExportBtnEl) {
        return;
    }

    requestBatchExportBtnEl.disabled = requestState.busy || requestState.batchRunning || requestState.batchRun.total === 0;
}

function updateRequestBatchClearButtonState() {
    if (!requestBatchClearBtnEl) {
        return;
    }

    requestBatchClearBtnEl.disabled = requestState.busy || requestState.batchRunning || requestState.batchRun.total === 0;
}

function updateRequestBatchRerunIssuesButtonState() {
    if (!requestBatchRerunIssuesBtnEl) {
        return;
    }

    const issueCount = getRequestBatchIssueResults().length;
    requestBatchRerunIssuesBtnEl.disabled = requestState.busy || requestState.batchRunning || issueCount === 0;
    requestBatchRerunIssuesBtnEl.dataset.batchIssueCount = String(issueCount);

    const label = issueCount > 0
        ? `${t('requestBatchRerunIssuesLabel')}: ${issueCount}`
        : t('requestBatchRerunIssuesLabel');
    requestBatchRerunIssuesBtnEl.title = label;
    requestBatchRerunIssuesBtnEl.setAttribute('aria-label', label);
}

function updateRequestBatchRerunButtonState() {
    const buttons = Array.from(document.querySelectorAll('[data-batch-rerun-method]'));
    const isDisabled = requestState.busy || requestState.batchRunning;
    buttons.forEach(button => {
        button.disabled = isDisabled;
    });
}

function exportRequestBatchReport() {
    if (requestState.batchRun.total === 0) {
        updateRequestBatchExportButtonState();
        return;
    }

    const report = buildRequestBatchReport();
    const filename = buildRequestBatchExportFilename(report.generatedAt);
    const content = JSON.stringify(report, null, 2);

    try {
        downloadBlobFile(new Blob([content], { type: 'application/json;charset=utf-8' }), filename);
        announceLiveRegion('requestBatchLive', t('requestBatchExported'));
    } catch (error) {
        announceLiveRegion('requestBatchLive', formatActionErrorMessage(t('requestBatchExportFailed'), error));
    }
}

function clearRequestBatchRun(options = {}) {
    const { announce = false, resetFilter = false } = options;
    requestState.batchRun = {
        phase: 'idle',
        completed: 0,
        total: 0,
        results: [],
        selectedExchangeId: '',
    };

    if (resetFilter && requestBatchIssuesOnlyToggleEl) {
        requestBatchIssuesOnlyToggleEl.checked = false;
        requestState.showBatchIssuesOnly = false;
    }

    if (requestBatchDetailsEl) {
        requestBatchDetailsEl.open = false;
    }

    renderRequestBatchSummary();

    if (announce) {
        announceLiveRegion('requestBatchLive', t('requestBatchCleared'));
    }
}

function updateRequestBatchResult(previousMethod, previousPath, nextResult) {
    let didUpdate = false;
    let results = requestState.batchRun.results.map(result => {
        if (!didUpdate && result.method === previousMethod && result.path === previousPath) {
            didUpdate = true;
            return buildRequestBatchResult(nextResult, result);
        }
        return result;
    });

    if (!didUpdate) {
        results = requestState.batchRun.results.map(result => {
            if (!didUpdate && result.method === previousMethod) {
                didUpdate = true;
                return buildRequestBatchResult(nextResult, result);
            }
            return result;
        });
    }

    if (!didUpdate) {
        results = [...requestState.batchRun.results, buildRequestBatchResult(nextResult)];
    }

    requestState.batchRun = {
        ...requestState.batchRun,
        completed: Math.max(requestState.batchRun.completed, results.length),
        total: Math.max(requestState.batchRun.total, results.length),
        results,
        selectedExchangeId: nextResult.exchangeSnapshot?.id || requestState.batchRun.selectedExchangeId,
    };
    renderRequestBatchSummary();
}

function selectRequestBatchExchange(exchangeId) {
    if (!exchangeId) {
        return;
    }

    const result = requestState.batchRun.results.find(item => item.exchangeSnapshot?.id === exchangeId);
    if (!result?.exchangeSnapshot) {
        return;
    }

    applyRequestExchangeSnapshot(result.exchangeSnapshot);
    requestState.batchRun = {
        ...requestState.batchRun,
        selectedExchangeId: exchangeId,
    };
    renderRequestBatchSummary();
}

async function rerunRequestBatchRow(button) {
    if (requestState.busy || requestState.batchRunning) {
        return;
    }

    const method = button.dataset.batchRerunMethod || '';
    const path = decodeURIComponent(button.dataset.batchRerunPath || '');
    if (!method || !path) {
        return;
    }

    openRequestBatchDetails();
    setRequestPathValue(path);
    let result;
    try {
        result = await sendRequest(method);
    } catch (error) {
        result = buildRequestExecutionResult(method, path, {
            kind: 'error',
            message: error.message,
        });
    }

    if (result) {
        updateRequestBatchResult(method, path, result);
        announceLiveRegion('requestBatchLive', `${t('requestBatchRerunCompleted')}: ${result.method} ${result.actualStatus}`);
    }
}

async function rerunRequestBatchIssues() {
    if (requestState.busy || requestState.batchRunning) {
        return;
    }

    const issueResults = getRequestBatchIssueResults();
    if (issueResults.length === 0) {
        updateRequestBatchRerunIssuesButtonState();
        announceLiveRegion('requestBatchLive', t('requestBatchNoIssues'));
        return;
    }

    openRequestBatchDetails();
    setRequestBatchBusy(true);
    announceLiveRegion('requestBatchLive', `${t('requestBatchRerunIssuesStarted')}: ${issueResults.length}`);

    try {
        for (const issueResult of issueResults) {
            setRequestPathValue(issueResult.path);
            let result;
            try {
                result = await sendRequest(issueResult.method);
            } catch (error) {
                result = buildRequestExecutionResult(issueResult.method, issueResult.path, {
                    kind: 'error',
                    message: error.message,
                });
            }

            if (result) {
                updateRequestBatchResult(issueResult.method, issueResult.path, result);
            }
        }
    } finally {
        setRequestBatchBusy(false);
        renderRequestBatchSummary();
    }

    const remainingIssues = getRequestBatchIssueResults().length;
    announceLiveRegion('requestBatchLive', `${t('requestBatchRerunIssuesCompleted')}: ${remainingIssues}`);
}

function renderRequestBatchSummary() {
    if (!requestBatchSummaryEl) return;

    const hasContent = requestState.batchRun.total > 0;
    const counts = countRequestBatchResults(requestState.batchRun.results);
    const visibleResults = getVisibleRequestBatchResults(requestState.batchRun.results);
    const emptyStateText = requestState.batchRun.phase === 'running'
        ? t('requestBatchNoIssuesYet')
        : t('requestBatchNoIssues');
    requestBatchSummaryEl.dataset.batchPhase = requestState.batchRun.phase;
    requestBatchSummaryEl.dataset.batchCompleted = String(requestState.batchRun.completed);
    requestBatchSummaryEl.dataset.batchTotal = String(requestState.batchRun.total);
    requestBatchSummaryEl.dataset.batchMatchCount = String(counts.match);
    requestBatchSummaryEl.dataset.batchMismatchCount = String(counts.mismatch);
    requestBatchSummaryEl.dataset.batchFailedCount = String(counts.failed);
    requestBatchSummaryEl.dataset.batchFilter = requestState.showBatchIssuesOnly ? 'issues' : 'all';
    requestBatchSummaryEl.dataset.batchVisibleCount = String(visibleResults.length);

    if (requestBatchStatusEl) {
        requestBatchStatusEl.textContent = hasContent
            ? getRequestBatchStatusText(requestState.batchRun, counts)
            : '';
    }
    updateRequestMethodBatchStates();
    updateRequestBatchExportButtonState();
    updateRequestBatchClearButtonState();
    updateRequestBatchRerunIssuesButtonState();

    if (!hasContent) {
        requestBatchSummaryEl.hidden = true;
        requestBatchSummaryEl.innerHTML = '';
        return;
    }

    requestBatchSummaryEl.hidden = false;
    requestBatchSummaryEl.innerHTML = `
        <div class="request-batch-summary__counts">
            ${buildRequestBatchCounter(t('requestBatchTotal'), String(requestState.batchRun.total))}
            ${buildRequestBatchCounter(t('requestBatchMatches'), String(counts.match), 'success')}
            ${buildRequestBatchCounter(t('requestBatchMismatches'), String(counts.mismatch), counts.mismatch > 0 ? 'danger' : '')}
            ${buildRequestBatchCounter(t('requestBatchFailed'), String(counts.failed), counts.failed > 0 ? 'danger' : '')}
        </div>
        <div class="request-batch-summary__rows">
            ${visibleResults.length > 0
                ? visibleResults.map(buildRequestBatchRow).join('')
                : `<p class="request-batch-summary__empty">${esc(emptyStateText)}</p>`}
        </div>
    `;
}

function buildRequestPreviewHeaderLines(model, bodyText) {
    const headerLines = [[
        'Host',
        window.location.host || '127.0.0.1',
    ]];

    for (const [key, value] of Object.entries(withUiNoGzipHeader(model.headers || {}))) {
        if (value === undefined || value === null || value === '') {
            continue;
        }
        headerLines.push([key, String(value)]);
    }

    const hasContentLength = headerLines.some(([key]) => key.toLowerCase() === 'content-length');
    if (bodyText && !hasContentLength) {
        headerLines.push(['Content-Length', String(new TextEncoder().encode(bodyText).length)]);
    }

    return headerLines;
}

function buildRawRequestPreview(model) {
    const bodyText = normalizePreviewBody(model.body);
    const headerLines = buildRequestPreviewHeaderLines(model, bodyText);

    const head = [
        `${model.method} ${model.path} HTTP/1.1`,
        ...headerLines.map(([key, value]) => `${key}: ${value}`),
    ].join('\n');

    return bodyText ? `${head}\n\n${bodyText}` : `${head}\n`;
}

function getRawRequestPreviewText() {
    if (requestState.preview.phase !== 'ready' || !requestState.preview.model) {
        return '';
    }

    return buildRawRequestPreview(requestState.preview.model);
}

function buildSummaryMetric(label, value, options = {}) {
    const { badge = false, tone = '' } = options;
    const classes = ['request-preview-summary__metric-value'];
    if (badge) {
        classes.push('request-preview-summary__metric-value--badge');
    }
    if (tone) {
        classes.push(`request-preview-summary__metric-value--${tone}`);
    }
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

function buildSummaryRequestPreview(model) {
    const bodyText = normalizePreviewBody(model.body);
    const headerLines = buildRequestPreviewHeaderLines(model, bodyText);
    const bodyBytes = new TextEncoder().encode(bodyText).length;
    const hostValue = headerLines[0]?.[1] || (window.location.host || '127.0.0.1');
    const bodySizeValue = bodyText ? `${bodyBytes} ${t('opsecBytes')}` : t('requestPreviewNoBody');
    const comparison = getRequestPreviewComparison(model);
    const summaryMetrics = [
        { label: t('requestPreviewFieldMethod'), value: model.method },
        { label: t('requestPreviewFieldPath'), value: model.path },
        { label: t('requestPreviewFieldExpectedStatus'), value: comparison.expectedLabel },
        { label: t('requestPreviewFieldActualStatus'), value: comparison.actualLabel, tone: comparison.actualTone },
        { label: t('requestPreviewFieldCheck'), value: comparison.checkLabel, tone: comparison.checkTone, badge: true },
        { label: t('requestPreviewFieldHost'), value: hostValue },
        { label: t('requestPreviewFieldHeaderCount'), value: String(headerLines.length) },
        { label: t('requestPreviewFieldBodySize'), value: bodySizeValue },
    ];
    const headersText = headerLines.map(([key, value]) => `${key}: ${value}`).join('\n');
    const bodySummaryText = bodyText || t('requestPreviewNoBody');

    return `
        <div class="request-preview-summary">
            <div class="request-preview-summary__metrics">
                ${summaryMetrics.map(metric => buildSummaryMetric(metric.label, metric.value, { badge: metric.badge, tone: metric.tone })).join('')}
            </div>
            ${buildSummarySection(t('headers'), headersText)}
            ${buildSummarySection(t('requestBody'), bodySummaryText, 'body')}
        </div>
    `;
}

function getResponseHeaderValue(headers, name) {
    const normalizedName = String(name || '').toLowerCase();
    for (const [key, value] of Object.entries(headers || {})) {
        if (String(key).toLowerCase() === normalizedName) {
            return value;
        }
    }
    return '';
}

function buildSummaryResponseView(model) {
    const bodyText = String(model.bodyText || '');
    const bodyDisplay = formatResponseBody(bodyText);
    const bodySizeValue = bodyText ? `${new TextEncoder().encode(bodyText).length} ${t('opsecBytes')}` : t('requestPreviewNoBody');
    const contentType = getResponseHeaderValue(model.headers, 'content-type') || t('headersNA');
    const headersText = formatResponseHeaders(model.headers);
    const summaryMetrics = [
        { label: t('requestPreviewFieldMethod'), value: model.method },
        { label: t('requestPreviewFieldPath'), value: model.path },
        { label: t('responseSummaryFieldStatus'), value: formatHttpStatusLabel(model.status, model.statusText), tone: model.status < 400 ? 'success' : 'danger', badge: true },
        { label: t('time'), value: `${model.duration}ms` },
        { label: t('requestPreviewFieldHeaderCount'), value: String(Object.keys(model.headers || {}).length) },
        { label: t('responseSummaryFieldContentType'), value: contentType },
        { label: t('requestPreviewFieldBodySize'), value: bodySizeValue },
    ];

    return `
        <div class="request-preview-summary response-summary">
            <div class="request-preview-summary__metrics">
                ${summaryMetrics.map(metric => buildSummaryMetric(metric.label, metric.value, { badge: metric.badge, tone: metric.tone })).join('')}
            </div>
            ${buildSummarySection(t('headers'), headersText)}
            ${buildSummarySection(t('responseBody'), bodyDisplay, 'body')}
        </div>
    `;
}

function buildSummaryResponseErrorView(model) {
    const summaryMetrics = [
        { label: t('requestPreviewFieldMethod'), value: model.method },
        { label: t('requestPreviewFieldPath'), value: model.path },
        { label: t('responseSummaryFieldStatus'), value: t('error'), tone: 'danger', badge: true },
    ];

    return `
        <div class="request-preview-summary response-summary">
            <div class="request-preview-summary__metrics">
                ${summaryMetrics.map(metric => buildSummaryMetric(metric.label, metric.value, { badge: metric.badge, tone: metric.tone })).join('')}
            </div>
            ${buildSummarySection(t('error'), model.message || t('error'), 'body')}
        </div>
    `;
}

function buildRawResponseView(model) {
    return `<div class="response-body">${esc(buildRawResponseText(model))}</div>`;
}

function buildRawResponseText(model) {
    const headersText = formatResponseHeaders(model.headers).trimEnd();
    const bodyDisplay = formatResponseBody(model.bodyText, { raw: true });
    const statusLine = `HTTP/1.1 ${model.status} ${String(model.statusText || '').trim()}`.trim();
    return [
        statusLine,
        headersText,
        '',
        bodyDisplay,
    ].filter((part, index) => index === 2 || part !== '').join('\n');
}

function buildRawResponseErrorView(model) {
    return `
<div class="response-header">
${esc(model.method)} ${esc(model.path)}
<span class="status error">${t('error')}</span>
</div>
<div class="response-body">${esc(model.message || t('error'))}</div>`;
}

function buildRawResponseErrorText(model) {
    return [
        `${model.method} ${model.path}`,
        t('error'),
        '',
        model.message || t('error'),
    ].join('\n');
}

function buildFetchDownloadButton(path, filename) {
    return `<button class="btn-download" data-download-path="${encodeURIComponent(path)}">${t('download')} ${esc(filename)}</button>`;
}

function getRawResponseViewText() {
    if (requestState.responseView.phase === 'complete' && requestState.responseView.model) {
        return buildRawResponseText(requestState.responseView.model);
    }

    if (requestState.responseView.phase === 'error' && requestState.responseView.model) {
        return buildRawResponseErrorText(requestState.responseView.model);
    }

    return '';
}

function updateRequestCopyButtonState() {
    if (!requestPreviewCopyBtnEl) {
        return;
    }

    requestPreviewCopyBtnEl.disabled = !getRawRequestPreviewText();
}

function updateResponseCopyButtonState() {
    if (!responseCopyBtnEl) {
        return;
    }

    responseCopyBtnEl.disabled = !getRawResponseViewText();
}

async function writeTextToClipboard(text, kind) {
    const normalizedText = String(text || '');
    if (!normalizedText) {
        throw new Error(t('clipboardCopyFailed'));
    }

    if (navigator.clipboard?.writeText) {
        try {
            await navigator.clipboard.writeText(normalizedText);
            return;
        } catch (_error) {
            // Fall through to the textarea-based copy path.
        }
    }

    const textarea = document.createElement('textarea');
    textarea.value = normalizedText;
    textarea.setAttribute('readonly', '');
    textarea.style.position = 'fixed';
    textarea.style.top = '0';
    textarea.style.left = '0';
    textarea.style.opacity = '0';
    document.body.appendChild(textarea);
    textarea.select();
    textarea.setSelectionRange(0, normalizedText.length);

    let isCopied = false;
    try {
        isCopied = typeof document.execCommand === 'function' && document.execCommand('copy');
    } finally {
        textarea.remove();
    }

    if (!isCopied) {
        throw new Error(t('clipboardCopyFailed'));
    }
}

function formatActionErrorMessage(baseMessage, error) {
    const detail = String(error?.message || '').trim();
    return detail && detail !== baseMessage
        ? `${baseMessage}: ${detail}`
        : baseMessage;
}

async function copyRequestPreviewRaw() {
    const rawRequest = getRawRequestPreviewText();
    if (!rawRequest) {
        updateRequestCopyButtonState();
        return;
    }

    try {
        await writeTextToClipboard(rawRequest, 'request');
        announceLiveRegion('requestPreviewCopyLive', t('requestPreviewCopied'));
    } catch (error) {
        announceLiveRegion('requestPreviewCopyLive', formatActionErrorMessage(t('clipboardCopyFailed'), error));
    }
}

async function copyResponseViewRaw() {
    const rawResponse = getRawResponseViewText();
    if (!rawResponse) {
        updateResponseCopyButtonState();
        return;
    }

    try {
        await writeTextToClipboard(rawResponse, 'response');
        announceLiveRegion('responseAreaLive', t('responseCopied'));
    } catch (error) {
        announceLiveRegion('responseAreaLive', formatActionErrorMessage(t('clipboardCopyFailed'), error));
    }
}

function renderResponseView() {
    if (!responseAreaEl) return;

    responseAreaEl.dataset.requestView = requestState.previewMode;
    updateResponseCopyButtonState();
    if (requestState.responseView.phase === 'idle') {
        responseAreaEl.textContent = t('exchangeResponseEmpty');
        syncHeroResponsePanelState();
        return;
    }

    if (requestState.responseView.phase === 'progress' && requestState.responseView.model) {
        const { method, path, messageKey } = requestState.responseView.model;
        const hasPath = Boolean(path);
        const actionText = hasPath
            ? `${t(messageKey)} ${esc(method)} ${t('requestTo')} ${esc(path)}...`
            : `${t(messageKey)} ${esc(method)}...`;
        responseAreaEl.innerHTML = `<div class="response-header">${actionText}</div>`;
        syncHeroResponsePanelState();
        return;
    }

    if (requestState.responseView.phase === 'complete' && requestState.responseView.model) {
        const model = requestState.responseView.model;
        responseAreaEl.innerHTML = requestState.previewMode === 'summary'
            ? buildSummaryResponseView(model)
            : buildRawResponseView(model);
        if (model.method === 'FETCH' && model.status === 200) {
            const filename = resolveDownloadFilename(model.headers, model.path);
            const actionsClass = requestState.previewMode === 'summary'
                ? 'response-summary__actions'
                : '';
            const buttonHtml = buildFetchDownloadButton(model.path, filename);
            responseAreaEl.innerHTML += actionsClass ? `\n\n<div class="${actionsClass}">${buttonHtml}</div>` : `\n\n${buttonHtml}`;
        }
        syncHeroResponsePanelState();
        return;
    }

    if (requestState.responseView.phase === 'error' && requestState.responseView.model) {
        responseAreaEl.innerHTML = requestState.previewMode === 'summary'
            ? buildSummaryResponseErrorView(requestState.responseView.model)
            : buildRawResponseErrorView(requestState.responseView.model);
    }
    syncHeroResponsePanelState();
}

function renderRequestPreview() {
    if (!requestPreviewSectionEl || !requestPreviewAreaEl) return;

    requestPreviewSectionEl.hidden = false;
    if (requestPreviewPaneEl) {
        requestPreviewPaneEl.hidden = requestState.preview.phase === 'empty';
    }
    updateRequestCopyButtonState();

    if (requestState.preview.phase === 'preparing') {
        setRequestPreviewDataset('preparing');
        requestPreviewAreaEl.textContent = t('requestPreviewPreparing');
        return;
    }

    if (requestState.preview.phase === 'ready' && requestState.preview.model) {
        const comparison = getRequestPreviewComparison(requestState.preview.model);
        setRequestPreviewDataset(
            'ready',
            requestState.preview.model.method,
            requestState.preview.model.path,
            comparison,
        );
        if (requestState.previewMode === 'summary') {
            requestPreviewAreaEl.innerHTML = buildSummaryRequestPreview(requestState.preview.model);
        } else {
            requestPreviewAreaEl.textContent = buildRawRequestPreview(requestState.preview.model);
        }
        return;
    }

    setRequestPreviewDataset('empty');
    requestPreviewAreaEl.textContent = t('requestPreviewEmpty');
}

setRequestPreviewMode(requestState.previewMode);
setResponseAreaState('', '', 'idle');

function setRequestPreviewPreparing() {
    requestState.preview = {
        phase: 'preparing',
        model: null,
    };
    renderRequestPreview();
}

function setRequestPreviewModel(model) {
    requestState.preview = {
        phase: 'ready',
        model: {
            method: model.method,
            path: model.path,
            headers: { ...(model.headers || {}) },
            body: normalizePreviewBody(model.body),
            result: model.result ? { ...model.result } : null,
        },
    };
    renderRequestPreview();
}

function setRequestPreviewResult(result) {
    if (requestState.preview.phase !== 'ready' || !requestState.preview.model) {
        return;
    }

    requestState.preview = {
        phase: 'ready',
        model: {
            ...requestState.preview.model,
            result: result ? { ...result } : null,
        },
    };
    renderRequestPreview();
}

function createRequestPreviewModel(method, path, scenario) {
    return {
        method,
        path,
        headers: { ...(scenario.previewHeaders || scenario.headers || {}) },
        body: normalizePreviewBody(scenario.body),
        result: null,
    };
}

function parseJsonSafe(text) {
    try {
        return JSON.parse(text);
    } catch (_error) {
        return null;
    }
}

function summarizeErrorBody(text) {
    const parsed = parseJsonSafe(text);
    if (parsed && typeof parsed === 'object' && parsed.error && typeof parsed.error === 'object') {
        const message = typeof parsed.error.message === 'string' ? parsed.error.message : '';
        const code = typeof parsed.error.code === 'string' ? parsed.error.code : '';
        const field = typeof parsed.error.field === 'string' ? parsed.error.field : '';
        const details = parsed.error.details && typeof parsed.error.details === 'object'
            ? parsed.error.details
            : {};
        const metadata = [];
        if (code) metadata.push(code);
        if (field) metadata.push(field);
        if (typeof details.path === 'string') metadata.push(details.path);
        const suffix = metadata.length > 0 ? ` (${metadata.join(', ')})` : '';
        return `${message}${suffix}`.trim();
    }

    const normalized = String(text || '').trim();
    if (!normalized) {
        return '';
    }

    return normalized.length > 160 ? `${normalized.slice(0, 160)}...` : normalized;
}

function buildScenarioError(label, response, text) {
    const statusSummary = [response.status, response.statusText || ''].filter(Boolean).join(' ').trim();
    const detail = summarizeErrorBody(text);
    const scenarioError = new Error(detail ? `${label}: ${statusSummary} - ${detail}` : `${label}: ${statusSummary}`);
    const parsed = parseJsonSafe(text);
    const errorPayload = parsed?.error && typeof parsed.error === 'object' ? parsed.error : null;
    if (errorPayload) {
        scenarioError.code = errorPayload.code;
        scenarioError.field = errorPayload.field;
        scenarioError.details = errorPayload.details;
    }
    return scenarioError;
}

function formatResponseHeaders(headers) {
    let headersText = '';
    for (const [key, value] of Object.entries(headers)) {
        headersText += `${key}: ${value}\n`;
    }
    return headersText || t('headersNA');
}

function formatResponseBody(text, options = {}) {
    const normalized = String(text || '');
    if (options.raw) {
        return normalized.length > 500 ? `${normalized.substring(0, 500)}\n... (truncated)` : normalized;
    }

    const parsed = parseJsonSafe(text);
    if (parsed !== null) {
        return JSON.stringify(parsed, null, 2);
    }

    return normalized.length > 500 ? `${normalized.substring(0, 500)}\n... (truncated)` : normalized;
}

function renderRequestProgress(method, path, messageKey) {
    if (!responseAreaEl) return;
    const hasPath = Boolean(path);

    requestState.responseView = {
        phase: 'progress',
        model: {
            method,
            path,
            messageKey,
        },
    };
    renderResponseView();
    announceLiveRegion('responseAreaLive', hasPath ? `${t(messageKey)} ${method} ${path}` : `${t(messageKey)} ${method}`);
}

function renderRequestSuccess(method, path, response, duration, bodyText) {
    if (!responseAreaEl) return;
    requestState.responseView = {
        phase: 'complete',
        model: {
            method,
            path,
            status: response.status,
            statusText: response.statusText || '',
            headers: { ...(response.headers || {}) },
            duration,
            bodyText,
        },
    };
    renderResponseView();
}

function renderRequestError(method, path, error) {
    if (!responseAreaEl) return;
    requestState.responseView = {
        phase: 'error',
        model: {
            method,
            path,
            message: error.message,
        },
    };
    renderResponseView();
}

function buildDemoFilename(slug) {
    return `request-panel-${slug}.txt`;
}

function buildDemoUploadPath(filename) {
    return `/uploads/${filename}`;
}

function buildDemoUploadBody(method, uploadPath) {
    return `request-panel demo via ${method}\nresource: ${uploadPath}\n`;
}

function getCanonicalUploadPath(text) {
    const path = parseJsonSafe(text)?.file?.path;
    if (typeof path !== 'string' || !path) {
        throw new Error('Invalid upload response');
    }
    return path;
}

async function requestPanelUploadExists(path) {
    if (!path || !path.startsWith('/uploads/')) return false;
    const filename = path.slice('/uploads/'.length);
    if (!filename || filename.includes('/')) return false;

    try {
        const response = await sendCustomRequest('INFO', SERVER_URL + '/uploads', null);
        if (!response.ok) return false;
        const text = await response.text();
        const payload = parseJsonSafe(text);
        return Boolean(
            payload &&
            Array.isArray(payload.contents) &&
            payload.contents.some(item => item && item.name === filename)
        );
    } catch (_error) {
        return false;
    }
}

async function deleteUploadIfPresent(path) {
    if (!path) return;
    const exists = await requestPanelUploadExists(path);
    if (!exists) return;

    try {
        await sendCustomRequest('DELETE', SERVER_URL + path, null);
    } catch (_error) {
        // Ignore cleanup failures; deterministic demo names are best-effort only.
    }
}

async function createRequestPanelDemoFile(slug, label) {
    const filename = buildDemoFilename(slug);
    const uploadPath = buildDemoUploadPath(filename);
    await deleteUploadIfPresent(uploadPath);

    const response = await sendCustomRequest(
        'POST',
        SERVER_URL + '/',
        buildDemoUploadBody(label, uploadPath),
        {
            'X-File-Name': filename,
            'Content-Type': 'text/plain; charset=utf-8'
        }
    );
    const text = await response.text();
    if (!response.ok) {
        throw buildScenarioError(`${t('preparingDemoRequest')} ${label}`, response, text);
    }

    return getCanonicalUploadPath(text);
}

function isRequestPanelSmuggleUploadPath(path) {
    return Boolean(
        path &&
        path.startsWith('/uploads/') &&
        path !== '/uploads/' &&
        !path.endsWith('/')
    );
}

async function resolveRequestPanelSmuggleSourcePath(typedPath) {
    const normalizedPath = normalizeRequestPath(typedPath, '');
    if (isRequestPanelSmuggleUploadPath(normalizedPath)) {
        return normalizedPath;
    }

    return createRequestPanelDemoFile('smuggle', 'SMUGGLE');
}

async function executeRequestPanelSmuggle(filePath, builderState) {
    const requestPath = buildSmuggleRequestPath(filePath, builderState);
    const url = SERVER_URL + requestPath;
    setRequestPreviewModel(createRequestPreviewModel('SMUGGLE', requestPath, { path: requestPath }));
    setResponseAreaState('SMUGGLE', requestPath, 'sending');
    renderRequestProgress('SMUGGLE', requestPath, 'sendingRequest');

    try {
        const startTime = performance.now();
        const response = await sendCustomRequest('SMUGGLE', url);
        const endTime = performance.now();
        const duration = (endTime - startTime).toFixed(2);
        const text = await response.text();

        if (response.status === 200) {
            let result = null;
            try {
                result = JSON.parse(text);
            } catch (_error) {
                result = null;
            }
            const adaptedResult = adaptSmuggleResult(result);
            if (!adaptedResult.ok) {
                const invalidPayload = adaptedResult.error;
                const message = `${invalidPayload.message} (${invalidPayload.code})`;
                const invalidError = new Error(message);
                invalidError.code = invalidPayload.code;
                invalidError.field = invalidPayload.field;
                invalidError.details = invalidPayload.details;
                setRequestPreviewResult({
                    kind: 'error',
                    message,
                });
                renderRequestError('SMUGGLE', requestPath, invalidError);
                setResponseAreaState('SMUGGLE', requestPath, 'error');
                announceLiveRegion('responseAreaLive', `SMUGGLE ${requestPath} ${t('error')}: ${message}`);
                return null;
            }
            setRequestPreviewResult({
                kind: 'response',
                status: response.status,
                statusText: response.statusText || '',
            });
            renderRequestSuccess('SMUGGLE', requestPath, response, duration, buildSmuggleResponseSummary(result));
            setResponseAreaState('SMUGGLE', requestPath, 'complete', response.status);
            announceLiveRegion('responseAreaLive', `SMUGGLE ${requestPath} ${t('smuggleGenerated')}`);
            return result;
        }

        const requestError = buildScenarioError('SMUGGLE', response, text);
        setRequestPreviewResult({
            kind: 'error',
            message: requestError.message,
        });
        renderRequestError('SMUGGLE', requestPath, requestError);
        setResponseAreaState('SMUGGLE', requestPath, 'error');
        announceLiveRegion('responseAreaLive', `SMUGGLE ${requestPath} ${t('error')}: ${requestError.message}`);
        requestError.smuggleRequestRendered = true;
        throw requestError;
    } catch (error) {
        if (!error?.smuggleRequestRendered) {
            setRequestPreviewResult({
                kind: 'error',
                message: error.message,
            });
            renderRequestError('SMUGGLE', requestPath, error);
            setResponseAreaState('SMUGGLE', requestPath, 'error');
            announceLiveRegion('responseAreaLive', `SMUGGLE ${requestPath} ${t('error')}: ${error.message}`);
        }
        throw error;
    }
}

async function launchRequestPanelSmuggleBuilder(triggerEl = null) {
    const stableTriggerEl = resolveStableRequestTriggerElement(triggerEl);
    if (!responseAreaEl) {
        return;
    }
    if (typeof isServerMethodSupported === 'function' && !isServerMethodSupported('SMUGGLE')) {
        throw new Error('Method SMUGGLE is not advertised by the active server');
    }

    const typedPath = pathInputEl ? pathInputEl.value : '';
    const initialSourcePath = normalizeRequestPath(typedPath, '/');
    const smuggleState = typeof app.getState === 'function' ? app.getState('smuggle') : null;
    if (!isRequestPanelSmuggleStateReady(smuggleState)) {
        const message = smuggleState?.reason || t('smuggleCapabilitiesUnavailable');
        const error = new Error(message);
        setRequestPreviewResult({
            kind: 'error',
            message,
        });
        renderRequestError('SMUGGLE', initialSourcePath, error);
        setResponseAreaState('SMUGGLE', initialSourcePath, 'error');
        announceLiveRegion('responseAreaLive', `SMUGGLE ${initialSourcePath} ${t('error')}: ${message}`);
        return;
    }
    const previousRequestPreviewState = cloneRequestPreviewState(requestState.preview);
    let sourcePath = initialSourcePath;

    setRequestButtonsBusy(true);
    setResponseAreaState('SMUGGLE', '', 'preparing');
    renderRequestProgress('SMUGGLE', '', 'preparingDemoRequest');
    setRequestPreviewPreparing();

    try {
        sourcePath = await resolveRequestPanelSmuggleSourcePath(typedPath);
        setRequestPathValue(sourcePath);
        setRequestPreviewModel(createRequestPreviewModel('SMUGGLE', sourcePath, { path: sourcePath }));
        setResponseAreaState('SMUGGLE', sourcePath, 'ready');
    } catch (error) {
        requestState.preview = previousRequestPreviewState;
        renderRequestPreview();
        renderRequestError('SMUGGLE', sourcePath, error);
        setResponseAreaState('SMUGGLE', sourcePath, 'error');
        announceLiveRegion('responseAreaLive', `SMUGGLE ${sourcePath} ${t('error')}: ${error.message}`);
        return;
    } finally {
        setRequestButtonsBusy(false);
    }

    if (typeof showSmuggleDialog !== 'function') {
        const error = new Error('SMUGGLE builder UI is unavailable');
        setRequestPreviewResult({
            kind: 'error',
            message: error.message,
        });
        renderRequestError('SMUGGLE', sourcePath, error);
        setResponseAreaState('SMUGGLE', sourcePath, 'error');
        announceLiveRegion('responseAreaLive', `SMUGGLE ${sourcePath} ${t('error')}: ${error.message}`);
        return;
    }

    showSmuggleDialog(sourcePath, stableTriggerEl, {
        liveRegionId: 'responseAreaLive',
        onConfirm: builderState => executeRequestPanelSmuggle(
            sourcePath,
            builderState,
        ),
    });
}

async function buildRequestScenario(method, typedPath) {
    switch (method) {
        case 'GET':
        case 'HEAD':
        case 'INFO': {
            const path = normalizeRequestPath(typedPath, '/index.html');
            return {
                path,
                pathInputBeforeRequest: path,
            };
        }
        case 'PING':
            return {
                path: '/',
                pathInputBeforeRequest: '/',
            };
        case 'OPTIONS':
            return {
                path: '/',
                previewHeaders: { 'Access-Control-Request-Method': 'GET' },
                pathInputBeforeRequest: '/',
            };
        case 'NOTE':
            return {
                path: '/notes/key',
                pathInputBeforeRequest: '/notes/key',
            };
        case 'POST':
        case 'PUT':
        case 'PATCH':
        case 'NONE': {
            const filename = buildDemoFilename(method.toLowerCase());
            const uploadPath = buildDemoUploadPath(filename);
            await deleteUploadIfPresent(uploadPath);
            return {
                path: '/',
                body: buildDemoUploadBody(method, uploadPath),
                headers: {
                    'X-File-Name': filename,
                    'Content-Type': 'text/plain; charset=utf-8'
                },
                pathInputAfterSuccess: (bodyText) => {
                    return getCanonicalUploadPath(bodyText);
                },
            };
        }
        case 'DELETE': {
            const path = await createRequestPanelDemoFile('delete', 'DELETE');
            return {
                path,
                pathInputBeforeRequest: path,
                pathInputAfterSuccess: path,
            };
        }
        case 'FETCH': {
            const path = await createRequestPanelDemoFile('fetch', 'FETCH');
            return {
                path,
                pathInputBeforeRequest: path,
                pathInputAfterSuccess: path,
            };
        }
        case 'SMUGGLE': {
            const smuggleState = typeof app.getState === 'function' ? app.getState('smuggle') : null;
            if (!isRequestPanelSmuggleStateReady(smuggleState)) {
                throw new Error(smuggleState?.reason || t('smuggleCapabilitiesUnavailable'));
            }
            const path = await createRequestPanelDemoFile('smuggle', 'SMUGGLE');
            return {
                path,
                pathInputBeforeRequest: path,
                pathInputAfterSuccess: path,
            };
        }
        default: {
            const path = normalizeRequestPath(typedPath, '/');
            return {
                path,
                pathInputBeforeRequest: path,
            };
        }
    }
}

function isRequestPanelSmuggleStateReady(state) {
    return state?.enabled === true
        && state.status === 'valid'
        && state.capabilities !== null
        && typeof state.capabilities === 'object'
        && !Array.isArray(state.capabilities);
}

async function sendRequest(method, triggerEl = null) {
    if (!responseAreaEl) return;
    const requestOrigin = resolveStableRequestTriggerElement(triggerEl || document.activeElement);
    httpErrors.close('requestHttpErrorHost', { restore: false });
    if (typeof isServerMethodSupported === 'function' && !isServerMethodSupported(method)) {
        throw new Error(`Method ${method} is not advertised by the active server`);
    }

    const typedPath = pathInputEl ? pathInputEl.value : '';
    const fallbackPath = normalizeRequestPath(typedPath, '/');
    let currentPath = fallbackPath;
    const previousRequestPreviewState = cloneRequestPreviewState(requestState.preview);
    let previewCommitted = false;
    let transportStarted = false;
    let responseReceived = false;
    let requestResult = buildRequestExecutionResult(method, currentPath, null);
    setRequestButtonsBusy(true);
    setResponseAreaState(method, '', requestPanelPrepMethods.has(method) ? 'preparing' : 'sending');

    if (requestPanelPrepMethods.has(method)) {
        renderRequestProgress(method, '', 'preparingDemoRequest');
        setRequestPreviewPreparing();
    }

    try {
        const scenario = await buildRequestScenario(method, typedPath);
        const path = scenario.path || fallbackPath;
        currentPath = path;

        if (scenario.pathInputBeforeRequest) {
            setRequestPathValue(scenario.pathInputBeforeRequest);
        }

        setRequestPreviewModel(createRequestPreviewModel(method, path, scenario));
        previewCommitted = true;
        setResponseAreaState(method, path, 'sending');
        renderRequestProgress(method, path, 'sendingRequest');

        const startTime = performance.now();
        transportStarted = true;
        const response = await sendCustomRequest(
            method,
            SERVER_URL + path,
            scenario.body || null,
            scenario.headers || {}
        );
        responseReceived = true;
        const endTime = performance.now();
        const duration = (endTime - startTime).toFixed(2);
        const text = await response.text();

        if (!response.ok) {
            httpErrors.show({
                host: 'requestHttpErrorHost',
                origin: requestOrigin,
                retry: () => sendRequest(method, requestOrigin),
                method,
                path,
                status: response.status,
                statusText: response.statusText || '',
                headers: response.headers,
                body: text,
            });
        }

        const pathAfterSuccess = typeof scenario.pathInputAfterSuccess === 'function'
            ? scenario.pathInputAfterSuccess(text, response.headers)
            : scenario.pathInputAfterSuccess;
        if (pathAfterSuccess) {
            setRequestPathValue(pathAfterSuccess);
        }

        const previewResult = {
            kind: 'response',
            status: response.status,
            statusText: response.statusText || '',
        };
        setRequestPreviewResult(previewResult);
        requestResult = buildRequestExecutionResult(method, path, previewResult);
        renderRequestSuccess(method, path, response, duration, text);
        setResponseAreaState(method, path, 'complete', response.status);
        announceLiveRegion('responseAreaLive', `${method} ${path} ${response.status} ${response.statusText || ''}`.trim());
    } catch (error) {
        if (transportStarted && !responseReceived) {
            httpErrors.show({
                host: 'requestHttpErrorHost',
                origin: requestOrigin,
                retry: () => sendRequest(method, requestOrigin),
                method,
                path: currentPath,
                status: 0,
                statusText: t('networkError'),
                contentType: 'text/plain',
                body: error?.message || t('networkError'),
            });
        }
        if (!previewCommitted) {
            requestState.preview = previousRequestPreviewState;
            renderRequestPreview();
        } else {
            setRequestPreviewResult({
                kind: 'error',
                message: error.message,
            });
        }
        requestResult = buildRequestExecutionResult(method, currentPath, {
            kind: 'error',
            message: error.message,
        });
        renderRequestError(method, currentPath, error);
        setResponseAreaState(method, currentPath, 'error');
        announceLiveRegion('responseAreaLive', `${method} ${currentPath} ${t('error')}: ${error.message}`);
    } finally {
        setRequestButtonsBusy(false);
    }
    requestResult.exchangeSnapshot = createRequestExchangeSnapshot();
    return requestResult;
}

async function runAllRequestMethods() {
    if (requestState.batchRunning) return;

    const plan = getRequestBatchPlan();
    if (plan.length === 0) {
        return;
    }

    openRequestBatchDetails();
    requestState.batchRun = {
        phase: 'running',
        completed: 0,
        total: plan.length,
        results: [],
        selectedExchangeId: '',
    };
    setRequestBatchBusy(true);
    renderRequestBatchSummary();

    try {
        for (const step of plan) {
            setRequestPathValue(step.initialPath);
            let result;
            try {
                result = await sendRequest(step.method);
            } catch (error) {
                result = buildRequestExecutionResult(
                    step.method,
                    normalizeRequestPath(step.initialPath, '/'),
                    { kind: 'error', message: error.message }
                );
            }

            const batchResult = buildRequestBatchResult(
                result || buildRequestExecutionResult(
                    step.method,
                    normalizeRequestPath(step.initialPath, '/'),
                    { kind: 'error', message: t('error') }
                )
            );
            requestState.batchRun = {
                ...requestState.batchRun,
                completed: requestState.batchRun.completed + 1,
                results: [
                    ...requestState.batchRun.results,
                    batchResult,
                ],
                selectedExchangeId: batchResult.exchangeSnapshot?.id || requestState.batchRun.selectedExchangeId,
            };
            renderRequestBatchSummary();
        }
    } finally {
        requestState.batchRun = {
            ...requestState.batchRun,
            phase: 'complete',
        };
        renderRequestBatchSummary();
        setRequestBatchBusy(false);
    }
}

// Универсальная функция для кастомных HTTP-методов
function sendCustomRequest(method, path, body, headers = {}, onUploadProgress = null, options = {}) {
    return httpRequestAdapter(method, path, body, headers, onUploadProgress, options);
}

function performCustomRequest(method, path, body, headers = {}, onUploadProgress = null, options = {}) {
    return new Promise((resolve, reject) => {
        const xhr = new XMLHttpRequest();
        xhr.open(method, path, true);
        xhr.timeout = 30000; // 30 секунд таймаут

        if (onUploadProgress && xhr.upload) {
            xhr.upload.onprogress = onUploadProgress;
        }

        const requestHeaders = options.dataPlane === false
            ? { ...(headers || {}) }
            : withUiNoGzipHeader(headers);

        for (const [key, value] of Object.entries(requestHeaders)) {
            xhr.setRequestHeader(key, value);
        }

        xhr.onload = () => {
            const responseHeaders = {};
            const rawResponseHeadersText = xhr.getAllResponseHeaders();
            rawResponseHeadersText.split('\r\n').forEach(line => {
                const idx = line.indexOf(': ');
                if (idx > 0) {
                    const key = line.substring(0, idx);
                    const value = line.substring(idx + 2);
                    responseHeaders[key.toLowerCase()] = value;
                }
            });
            resolve({
                status: xhr.status,
                ok: xhr.status >= 200 && xhr.status < 300,
                statusText: xhr.statusText,
                headers: responseHeaders,
                rawResponseHeadersText,
                text: () => Promise.resolve(xhr.responseText),
                blob: () => Promise.resolve(new Blob([xhr.response]))
            });
        };

        xhr.onerror = () => reject(new Error(t('networkError')));
        xhr.ontimeout = () => reject(new Error(t('timeoutError')));

        if (body) {
            xhr.send(body);
        } else if (method === 'POST') {
            xhr.setRequestHeader('Content-Type', 'application/json');
            xhr.send(JSON.stringify({ demo: true, timestamp: new Date().toISOString() }));
        } else {
            xhr.send();
        }
    });
}

// Format ETA in mm:ss
function formatEta(seconds) {
    if (!isFinite(seconds) || seconds < 0) return '--:--';
    const m = Math.floor(seconds / 60);
    const s = Math.floor(seconds % 60);
    return String(m).padStart(2, '0') + ':' + String(s).padStart(2, '0');
}

function parseXhrResponseHeaders(rawHeadersText = '') {
    return Object.fromEntries(
        String(rawHeadersText || '').split(/\r?\n/).map(line => {
            const divider = line.indexOf(':');
            return divider > 0
                ? [line.slice(0, divider).trim().toLowerCase(), line.slice(divider + 1).trim()]
                : null;
        }).filter(Boolean)
    );
}

function getResponseHeaderValue(headers, name) {
    if (!headers || !name) return '';
    if (typeof headers.get === 'function') {
        return headers.get(name) || '';
    }
    const lowerName = String(name).toLowerCase();
    return headers[lowerName] || headers[name] || '';
}

function sanitizeBrowserDownloadFilename(value) {
    return String(value || '')
        .replace(/[\x00-\x1f\x7f]/g, '-')
        .replace(/[\\/]+/g, '-')
        .trim();
}

function getRfc5987Filename(contentDisposition) {
    const match = String(contentDisposition || '').match(
        /(?:^|;)\s*filename\*\s*=\s*(?:"([^"]*)"|([^;\s]*))/i
    );
    const value = (match?.[1] || match?.[2] || '').trim();
    const encoded = value.match(/^utf-8''(.+)$/i)?.[1];
    if (!encoded) return '';
    try {
        return sanitizeBrowserDownloadFilename(decodeURIComponent(encoded));
    } catch (error) {
        return '';
    }
}

function getContentDispositionFilename(contentDisposition) {
    const match = String(contentDisposition || '').match(
        /(?:^|;)\s*filename\s*=\s*(?:"([^"]*)"|([^;]*))/i
    );
    return sanitizeBrowserDownloadFilename((match?.[1] || match?.[2] || '').trim());
}

function getSafeRequestFilename(path) {
    const rawName = String(path || '').split(/[?#]/, 1)[0].split('/').filter(Boolean).pop() || '';
    try {
        return sanitizeBrowserDownloadFilename(decodeURIComponent(rawName));
    } catch (error) {
        return sanitizeBrowserDownloadFilename(rawName);
    }
}

function resolveDownloadFilename(headers, path) {
    return getRfc5987Filename(getResponseHeaderValue(headers, 'Content-Disposition'))
        || getContentDispositionFilename(getResponseHeaderValue(headers, 'Content-Disposition'))
        || getSafeRequestFilename(path)
        || 'download';
}

function encodeDownloadPath(path) {
    return String(path || '').split('/').map(segment => {
        try {
            return encodeURIComponent(decodeURIComponent(segment));
        } catch (error) {
            return encodeURIComponent(segment);
        }
    }).join('/');
}

async function decodeBoundedErrorBlob(blob) {
    if (!(blob instanceof Blob)) {
        return { body: '', totalBytes: 0 };
    }
    const totalBytes = blob.size;
    const body = await blob.slice(0, 16 * 1024).text();
    return {
        body,
        totalBytes,
        bodyTruncated: totalBytes > new TextEncoder().encode(body).byteLength,
    };
}

// Download file via FETCH with progress
async function downloadFile(path, triggerEl = null) {
    const downloadOrigin = resolveStableRequestTriggerElement(triggerEl || document.activeElement);
    httpErrors.close('filesHttpErrorHost', { restore: false });
    const xhr = new XMLHttpRequest();
    xhr.open('FETCH', SERVER_URL + encodeDownloadPath(path), true);
    xhr.responseType = 'blob';
    xhr.timeout = 30000;

    // Create/get progress container
    let progressEl = document.getElementById('downloadProgressArea');
    if (!progressEl) {
        progressEl = document.createElement('div');
        progressEl.id = 'downloadProgressArea';
        progressEl.className = 'panel download-progress-overlay';
        progressEl.hidden = true;
        document.body.appendChild(progressEl);
    }

    let progressLiveEl = document.getElementById('downloadProgressLive');
    if (!progressLiveEl) {
        progressLiveEl = document.createElement('div');
        progressLiveEl.id = 'downloadProgressLive';
        progressLiveEl.className = 'sr-only';
        progressLiveEl.setAttribute('role', 'status');
        progressLiveEl.setAttribute('aria-live', 'polite');
        progressLiveEl.setAttribute('aria-atomic', 'true');
        document.body.appendChild(progressLiveEl);
    }

    progressEl.removeAttribute('role');
    progressEl.removeAttribute('aria-live');
    progressEl.removeAttribute('aria-atomic');

    const startTime = Date.now();
    const fileName = path.split('/').pop() || 'download';
    progressEl.innerHTML = `
        <div class="download-progress-title">${t('downloadProgress')}: ${esc(fileName)}</div>
        <div class="progress-container">
            <div
                class="progress-bar-fill"
                id="dlProgressBar"
                role="progressbar"
                aria-label="${esc(t('downloadProgress'))}"
                aria-valuemin="0"
                aria-valuemax="100"
                aria-valuenow="0"
            ></div>
        </div>
        <div class="download-progress" id="dlProgressText" aria-hidden="true">0%</div>`;
    progressEl.hidden = false;

    const progressBarEl = document.getElementById('dlProgressBar');
    const progressTextEl = document.getElementById('dlProgressText');
    const progressTitleEl = progressEl.querySelector('.download-progress-title');
    let lastAnnouncedMilestone = 0;

    function setProgress(pct, text) {
        if (progressBarEl) {
            progressBarEl.style.width = pct + '%';
            progressBarEl.setAttribute('aria-valuenow', String(pct));
        }
        if (progressTextEl) {
            progressTextEl.classList.remove('download-progress--error');
            progressTextEl.textContent = text;
        }
    }

    function setLiveStatus(text) {
        announceLiveRegion('downloadProgressLive', text);
    }

    function showDownloadError(details) {
        if (progressEl) progressEl.hidden = true;
        httpErrors.show({
            host: 'filesHttpErrorHost',
            origin: downloadOrigin,
            retry: () => downloadFile(path, downloadOrigin),
            method: 'FETCH',
            path,
            status: details.status || 0,
            statusText: details.statusText || t('error'),
            headers: details.headers || {},
            contentType: details.contentType || '',
            body: details.body || '',
            totalBytes: details.totalBytes,
            bodyTruncated: details.bodyTruncated,
        });
        setLiveStatus(`${t('downloadFailed')}: ${fileName}. ${details.statusText || t('error')}`);
    }
    progressEl.classList.remove('download-progress-overlay--error');
    if (progressBarEl) {
        progressBarEl.removeAttribute('aria-invalid');
    }
    setProgress(0, '0%');
    setLiveStatus(`${t('downloadStarted')}: ${fileName}`);

    xhr.onprogress = (e) => {
        if (e.lengthComputable) {
            const pct = Math.round((e.loaded / e.total) * 100);
            const elapsed = (Date.now() - startTime) / 1000;
            const speed = elapsed > 0 ? e.loaded / elapsed : 0;
            const remaining = speed > 0 ? (e.total - e.loaded) / speed : 0;
            setProgress(
                pct,
                `${pct}%  ${formatSize(e.loaded)}/${formatSize(e.total)}  ${t('downloadSpeed')}: ${formatSize(speed)}/s  ${t('downloadEta')}: ${formatEta(remaining)}`
            );

            const milestone = Math.floor(pct / 25) * 25;
            if (milestone > lastAnnouncedMilestone && milestone < 100) {
                lastAnnouncedMilestone = milestone;
                setLiveStatus(`${t('downloadProgress')}: ${fileName} ${milestone}%`);
            }
        }
    };

    xhr.onload = async () => {
        if (xhr.status < 200 || xhr.status >= 300) {
            const headers = parseXhrResponseHeaders(xhr.getAllResponseHeaders());
            const decoded = await decodeBoundedErrorBlob(xhr.response);
            showDownloadError({
                status: xhr.status,
                statusText: xhr.statusText || t('error'),
                headers,
                contentType: headers['content-type'] || xhr.response?.type || '',
                ...decoded,
            });
            return;
        }

        setLiveStatus(`${t('downloadCompleted')}: ${fileName}`);
        if (progressEl) progressEl.hidden = true;
        const filename = resolveDownloadFilename(
            parseXhrResponseHeaders(xhr.getAllResponseHeaders()),
            path,
        );
        const blob = xhr.response;
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
        a.remove();
    };

    xhr.onerror = () => {
        showDownloadError({ statusText: t('networkError') });
    };

    xhr.ontimeout = () => {
        showDownloadError({ statusText: t('timeoutError') });
    };

    xhr.send();
}

renderRequestPreview();
renderResponseView();
renderRequestBatchSummary();

let httpRequestAdapter = performCustomRequest;

function setHttpRequestAdapter(adapter) {
    if (typeof adapter !== 'function') {
        throw new TypeError('HTTP request adapter must be a function');
    }
    const previous = httpRequestAdapter;
    httpRequestAdapter = adapter;
    return previous;
}

function resetHttpRequestAdapter() {
    httpRequestAdapter = performCustomRequest;
}

app.registerService('http', {
    request: (...args) => httpRequestAdapter(...args),
    'set-adapter': setHttpRequestAdapter,
    'reset-adapter': resetHttpRequestAdapter,
});

app.on(app.events.LOCALE_CHANGED, () => {
    renderRequestPreview();
    renderResponseView();
    renderRequestBatchSummary();
});
app.on(app.events.SERVER_METHODS_CHANGED, syncRequestControlState);
document.addEventListener('xferry:response-options-changed', renderRequestPreview);

app.registerWorkflow('requests', {
    commands: {
        send: sendRequest,
        'run-all': runAllRequestMethods,
        'download-file': downloadFile,
        'resolve-download-filename': resolveDownloadFilename,
        'record-batch-result': (method, path, response) => {
            const result = buildRequestExecutionResult(method, path, response);
            updateRequestBatchResult(method, path, result);
            return result;
        },
        'render-preview': renderRequestPreview,
        'render-response': renderResponseView,
    },
    getState: () => ({
        previewMode: requestState.previewMode,
        previewPhase: requestState.preview.phase,
        responsePhase: requestState.responseView.phase,
        busy: requestState.busy,
        batchRunning: requestState.batchRunning,
        batchPhase: requestState.batchRun.phase,
        batchResultCount: requestState.batchRun.results.length,
    }),
});
})(window.XferryApp);
