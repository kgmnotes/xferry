(function initializeFiles(app) {
    'use strict';

const {
    t,
    escapeHtml: esc,
    formatSize,
    serverUrl: SERVER_URL,
    announceLiveRegion,
    focusElementWithoutScroll,
    getState: getCoreState,
    isServerMethodSupported,
    isServerMethodInGroup,
    formatActionErrorMessage,
    writeTextToClipboard,
} = app.service('core');
const {
    open: openManagedDialog,
    confirm: showConfirmDialog,
    notice: showNoticeDialog,
} = app.service('dialogs');
const {
    createTextBody: createExchangeTextBody,
    downloadBlob: downloadBlobFile,
    setInspector: setExchangeInspector,
    withNoGzipHeader: withUiNoGzipHeader,
} = app.service('inspector');
const httpErrors = app.service('http-errors');

function sendCustomRequest(...args) {
    return app.service('http').request(...args);
}

function getCanonicalErrorMessage(payload) {
    return typeof payload?.error?.message === 'string' ? payload.error.message : '';
}

function getCanonicalResponseErrorMessage(response, payload, text) {
    return getCanonicalErrorMessage(payload)
        || (response?.ok ? t('error') : String(text || '').trim())
        || `${response?.status || 0} ${response?.statusText || t('error')}`.trim();
}

function getCanonicalInfoPayload(payload) {
    if (
        !payload
        || typeof payload !== 'object'
        || Array.isArray(payload)
        || !payload.entry
        || typeof payload.entry !== 'object'
        || Array.isArray(payload.entry)
        || typeof payload.entry.kind !== 'string'
        || typeof payload.entry.path !== 'string'
        || !payload.entry.path
        || !['file', 'directory'].includes(payload.entry.kind)
    ) {
        return null;
    }
    if (
        payload.entry.kind === 'file'
        && (
            typeof payload.entry.name !== 'string'
            || !payload.entry.name
            || !Number.isInteger(payload.entry.size_bytes)
            || payload.entry.size_bytes < 0
            || typeof payload.entry.created_at !== 'string'
            || !payload.entry.created_at
            || typeof payload.entry.modified_at !== 'string'
            || !payload.entry.modified_at
        )
    ) {
        return null;
    }
    if (payload.entry.kind === 'directory') {
        if (
            !payload.page
            || typeof payload.page !== 'object'
            || Array.isArray(payload.page)
            || !Array.isArray(payload.contents)
            || !Number.isInteger(payload.page.total_items)
            || payload.page.total_items < 0
            || payload.contents.some(item => (
                !item
                || typeof item !== 'object'
                || Array.isArray(item)
                || typeof item.name !== 'string'
                || !item.name
                || !['file', 'directory'].includes(item.kind)
            ))
        ) {
            return null;
        }
    }
    return payload;
}

function getCanonicalClearedUploads(payload) {
    const cleared = payload?.cleared_uploads;
    if (
        !cleared
        || typeof cleared !== 'object'
        || Array.isArray(cleared)
        || typeof cleared.path !== 'string'
        || !cleared.path
        || !Number.isInteger(cleared.deleted_files)
        || cleared.deleted_files < 0
        || !Number.isInteger(cleared.deleted_dirs)
        || cleared.deleted_dirs < 0
    ) {
        return null;
    }
    return cleared;
}

function getCanonicalDeletedFile(payload) {
    const deleted = payload?.deleted_file;
    if (
        !deleted
        || typeof deleted !== 'object'
        || Array.isArray(deleted)
        || typeof deleted.name !== 'string'
        || !deleted.name
        || typeof deleted.path !== 'string'
        || !deleted.path
    ) {
        return null;
    }
    return deleted;
}

function downloadFile(...args) {
    return app.invoke('requests', 'download-file', ...args);
}

// ===== Обзор файлов на сервере =====
const browseRootBtn = document.getElementById('browseRootBtn');
const browseUpBtn = document.getElementById('browseUpBtn');
const browseBtn = document.getElementById('browseBtn');
const browseRefreshBtn = document.getElementById('browseRefreshBtn');
const clearUploadsBtn = document.getElementById('clearUploadsBtn');
const deleteSelectedUploadsBtn = document.getElementById('deleteSelectedUploadsBtn');
const clearSelectedUploadsBtn = document.getElementById('clearSelectedUploadsBtn');
const browsePathInput = document.getElementById('browsePathInput');
const filesSearchInput = document.getElementById('filesSearchInput');
const filesSearchClearBtn = document.getElementById('filesSearchClearBtn');
const filesGlobalActionsEl = document.getElementById('filesGlobalActions');
const filesFilterStatusEl = document.getElementById('filesFilterStatus');
const filesListHeaderEl = document.getElementById('filesListHeader');
const filesSelectVisibleCheckbox = document.getElementById('filesSelectVisibleCheckbox');
const filesSortNameBtn = document.getElementById('filesSortNameBtn');
const filesSortNameIndicatorEl = document.getElementById('filesSortNameIndicator');
const filesToastRegionEl = document.getElementById('filesToastRegion');
const serverFilesEl = document.getElementById('serverFiles');
const filesBrowseStatusEl = document.getElementById('filesBrowseStatus');
const filesSelectionBarEl = document.getElementById('filesSelectionBar');
const filesSelectionCountEl = document.getElementById('filesSelectionCount');
let filesToastTimer = null;
let filesToastDeletedCount = null;
const filesState = {
    selectedPaths: new Set(),
    browseGeneration: 0,
    infoGeneration: 0,
    expandedFilePath: null,
    fileInfoCache: new Map(),
    fileInfoPhase: 'idle',
    fileInfoError: '',
    searchQuery: '',
    sortDirection: 'asc',
    activePath: '/',
    browsePhase: 'idle',
    lastSuccessfulPath: null,
    lastSuccessfulItems: [],
    lastSuccessfulTotalItems: 0,
    lastSuccessfulInfo: null,
    listActionsDisabled: false,
};

function isFileBrowseSupported() {
    return typeof isServerMethodSupported !== 'function'
        || isServerMethodSupported('INFO');
}

function isFileDownloadSupported() {
    return typeof isServerMethodInGroup !== 'function'
        || isServerMethodInGroup('FETCH', 'files');
}

function isFileDeleteSupported() {
    return typeof isServerMethodInGroup !== 'function'
        || isServerMethodInGroup('DELETE', 'files');
}

function isSmuggleSupported() {
    const methodSupported = typeof isServerMethodInGroup !== 'function'
        || isServerMethodInGroup('SMUGGLE', 'files');
    if (!methodSupported || !app.hasWorkflow('smuggle')) {
        return false;
    }
    return app.getState('smuggle').enabled === true;
}

function refreshFilesMethodAvailability() {
    const browseSupported = isFileBrowseSupported();
    if (browseRootBtn) browseRootBtn.disabled = !browseSupported;
    if (browseUpBtn) browseUpBtn.disabled = !browseSupported;
    if (browseBtn) browseBtn.disabled = !browseSupported;
    if (browseRefreshBtn) browseRefreshBtn.disabled = !browseSupported;
    if (browsePathInput) browsePathInput.disabled = !browseSupported;
    if (clearUploadsBtn) {
        clearUploadsBtn.disabled = !isFileDeleteSupported() || filesState.listActionsDisabled;
    }
    updateSelectedUploadsButton();
    syncFilesListControls();
}

if (browseRootBtn) {
    browseRootBtn.addEventListener('click', () => goToRoot(browseRootBtn));
}

if (browseUpBtn) {
    browseUpBtn.addEventListener('click', () => goUp(browseUpBtn));
}

if (browseBtn) {
    browseBtn.addEventListener('click', () => browseDirectory({ origin: browseBtn }));
}

if (browseRefreshBtn) {
    browseRefreshBtn.addEventListener('click', () => browseDirectory({ origin: browseRefreshBtn }));
}

if (filesSearchInput) {
    filesSearchInput.addEventListener('input', () => {
        setFilesSearchQuery(filesSearchInput.value, { announceSelectionReset: true });
    });
}

if (filesSearchClearBtn) {
    filesSearchClearBtn.addEventListener('click', () => {
        setFilesSearchQuery('', { announceSelectionReset: true });
        focusElementWithoutScroll(filesSearchInput);
    });
}

if (filesSelectVisibleCheckbox) {
    filesSelectVisibleCheckbox.addEventListener('change', toggleVisibleUploadFilesSelection);
}

if (filesSortNameBtn) {
    filesSortNameBtn.addEventListener('click', toggleFilesNameSort);
}

if (clearUploadsBtn) {
    clearUploadsBtn.addEventListener('click', () => clearUploads(clearUploadsBtn));
}

if (deleteSelectedUploadsBtn) {
    deleteSelectedUploadsBtn.addEventListener('click', () => deleteSelectedUploadFiles(deleteSelectedUploadsBtn));
}

if (clearSelectedUploadsBtn) {
    clearSelectedUploadsBtn.addEventListener('click', () => {
        clearSelectedUploadFiles();
        announceFilesSelectionCount();
    });
}

if (browsePathInput) {
    browsePathInput.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') {
            e.preventDefault();
            browseDirectory({ origin: browsePathInput });
        }
    });
}

if (serverFilesEl) {
    serverFilesEl.addEventListener('click', (e) => {
        const retryBtn = e.target.closest('[data-file-details-retry][data-path]');
        if (retryBtn) {
            if (filesState.listActionsDisabled) return;
            const encodedPath = retryBtn.dataset.path;
            if (!encodedPath) return;
            const detailsTrigger = retryBtn
                .closest('.uploaded-file--file')
                ?.querySelector('[data-file-details-trigger][data-path]') || null;
            focusElementWithoutScroll(detailsTrigger);
            void showInlineFileDetails(decodeURIComponent(encodedPath));
            return;
        }

        const detailsTrigger = e.target.closest('[data-file-details-trigger][data-path]');
        if (detailsTrigger) {
            if (filesState.listActionsDisabled) return;
            const encodedPath = detailsTrigger.dataset.path;
            if (!encodedPath) return;
            toggleInlineFileDetails(decodeURIComponent(encodedPath));
            return;
        }

        const actionBtn = e.target.closest('[data-file-action][data-path]');
        if (!actionBtn) return;

        const action = actionBtn.dataset.fileAction;
        const encodedPath = actionBtn.dataset.path;
        if (!action || !encodedPath) return;
        if (filesState.listActionsDisabled) return;

        const path = decodeURIComponent(encodedPath);
        const disclosureTrigger = actionBtn.closest('.file-row__more')?.querySelector('summary') || actionBtn;

        if (action === 'download' && isFileDownloadSupported()) {
            downloadFile(path);
        } else if (action === 'decrypt-xor' && isFileDownloadSupported()) {
            showXorDecryptDialog(path, disclosureTrigger);
        } else if (action === 'smuggle' && isSmuggleSupported()) {
            app.invoke('smuggle', 'show-dialog', path, disclosureTrigger);
        } else if (action === 'delete' && isFileDeleteSupported()) {
            deleteFile(path, disclosureTrigger);
        } else if (action === 'open-dir') {
            browsePathInput.value = path;
            browseDirectory({ origin: actionBtn });
        }
    });

    serverFilesEl.addEventListener('change', (e) => {
        const selectBox = e.target.closest('[data-file-select][data-path]');
        if (!selectBox) return;
        if (filesState.listActionsDisabled) return;

        const path = decodeURIComponent(selectBox.dataset.path || '');
        if (!path) return;

        if (selectBox.checked) {
            filesState.selectedPaths.add(path);
        } else {
            filesState.selectedPaths.delete(path);
        }

        const row = selectBox.closest('.uploaded-file');
        if (row) {
            row.classList.toggle('is-selected', selectBox.checked);
        }
        updateSelectedUploadsButton();
        announceFilesSelectionCount();
    });

    serverFilesEl.addEventListener('toggle', (e) => {
        const disclosure = e.target.closest('.file-row__more');
        if (!disclosure?.open) return;
        serverFilesEl.querySelectorAll('.file-row__more[open]').forEach(openDisclosure => {
            if (openDisclosure !== disclosure) {
                openDisclosure.open = false;
            }
        });
    }, true);
}

document.addEventListener('keydown', closeFileActionDisclosuresOnEscape);
document.addEventListener('keydown', collapseInlineFileDetailsOnEscape);
document.addEventListener('click', closeFileActionDisclosuresOnOutsideClick);

function goToRoot(origin = null) {
    document.getElementById('browsePathInput').value = '/';
    browseDirectory({ origin: origin || browseRootBtn });
}

function goUp(origin = null) {
    const pathInput = document.getElementById('browsePathInput');
    let path = pathInput.value || '/';

    // Убираем trailing slash если есть
    if (path.endsWith('/') && path.length > 1) {
        path = path.slice(0, -1);
    }

    // Находим родительскую директорию
    const lastSlash = path.lastIndexOf('/');
    if (lastSlash > 0) {
        path = path.substring(0, lastSlash);
    } else {
        path = '/';
    }

    pathInput.value = path;
    browseDirectory({ origin: origin || browseUpBtn });
}

function focusFilesBrowserAnchor() {
    if (browsePathInput && typeof browsePathInput.focus === 'function') {
        browsePathInput.focus();
    }
}

function clearFilesToastTimer() {
    if (filesToastTimer !== null) {
        window.clearTimeout(filesToastTimer);
        filesToastTimer = null;
    }
}

function getFilesDeletedToastMessage() {
    return `${t('deleteSelectedFilesSuccess')}: ${filesToastDeletedCount || 0}`;
}

function syncFilesToastCopy() {
    const toast = filesToastRegionEl?.querySelector('[data-files-toast]');
    if (!toast || filesToastDeletedCount === null) return;

    const message = toast.querySelector('[data-files-toast-message]');
    const closeButton = toast.querySelector('[data-files-toast-dismiss]');
    if (message) {
        message.textContent = getFilesDeletedToastMessage();
    }
    if (closeButton) {
        const closeLabel = t('filesToastDismiss');
        closeButton.title = closeLabel;
        closeButton.setAttribute('aria-label', closeLabel);
    }
}

function dismissFilesToast({ restoreFocus = false } = {}) {
    const toast = filesToastRegionEl?.querySelector('[data-files-toast]');
    const toastHadFocus = Boolean(toast?.contains(document.activeElement));
    clearFilesToastTimer();
    toast?.remove();
    filesToastDeletedCount = null;
    if (restoreFocus && toastHadFocus) {
        focusFilesBrowserAnchor();
    }
}

function scheduleFilesToastDismiss(toast, delay = 5000) {
    clearFilesToastTimer();
    filesToastTimer = window.setTimeout(() => {
        if (toast?.isConnected) {
            dismissFilesToast();
        }
    }, delay);
}

function showFilesDeletedToast(deletedCount) {
    const count = Number(deletedCount);
    filesToastDeletedCount = Number.isFinite(count) ? Math.max(0, count) : 0;

    if (!filesToastRegionEl) {
        announceLiveRegion('filesResponseAreaLive', getFilesDeletedToastMessage());
        filesToastDeletedCount = null;
        return;
    }

    dismissFilesToast();
    filesToastDeletedCount = Number.isFinite(count) ? Math.max(0, count) : 0;

    const toast = document.createElement('div');
    toast.className = 'file-toast file-toast--success';
    toast.dataset.filesToast = '';

    const icon = document.createElement('span');
    icon.className = 'file-toast__icon';
    icon.setAttribute('aria-hidden', 'true');
    icon.textContent = '✓';

    const message = document.createElement('p');
    message.className = 'file-toast__message';
    message.dataset.filesToastMessage = '';

    const closeButton = document.createElement('button');
    closeButton.type = 'button';
    closeButton.className = 'btn-ghost btn-icon file-toast__dismiss';
    closeButton.dataset.filesToastDismiss = '';
    closeButton.textContent = '×';
    closeButton.addEventListener('click', () => dismissFilesToast({ restoreFocus: true }));

    toast.append(icon, message, closeButton);
    filesToastRegionEl.appendChild(toast);
    syncFilesToastCopy();
    announceLiveRegion('filesToastLive', getFilesDeletedToastMessage());
    scheduleFilesToastDismiss(toast);

    toast.addEventListener('mouseenter', clearFilesToastTimer);
    toast.addEventListener('mouseleave', () => scheduleFilesToastDismiss(toast, 3000));
    toast.addEventListener('focusin', clearFilesToastTimer);
    toast.addEventListener('focusout', event => {
        if (!toast.contains(event.relatedTarget)) {
            scheduleFilesToastDismiss(toast, 3000);
        }
    });
    toast.addEventListener('keydown', event => {
        if (event.key !== 'Escape') return;
        event.preventDefault();
        event.stopPropagation();
        dismissFilesToast({ restoreFocus: true });
    });
}

refreshFilesMethodAvailability();

function closeFileActionDisclosures(except = null) {
    if (!serverFilesEl) return;
    serverFilesEl.querySelectorAll('.file-row__more[open]').forEach(disclosure => {
        if (disclosure !== except) {
            disclosure.open = false;
        }
    });
}

function closeFileActionDisclosuresOnEscape(event) {
    if (event.key !== 'Escape') return;
    const focusedDisclosure = document.activeElement?.closest?.('.file-row__more[open]') || null;
    const focusedGlobalActions = document.activeElement?.closest?.('#filesGlobalActions[open]') || null;
    closeFileActionDisclosures();
    if (focusedDisclosure) {
        focusElementWithoutScroll(focusedDisclosure.querySelector('summary'));
    }
    if (focusedGlobalActions) {
        focusedGlobalActions.open = false;
        focusElementWithoutScroll(focusedGlobalActions.querySelector('summary'));
    }
}

function closeFileActionDisclosuresOnOutsideClick(event) {
    const clickedDisclosure = event.target?.closest?.('.file-row__more') || null;
    closeFileActionDisclosures(clickedDisclosure);
    if (filesGlobalActionsEl && !event.target?.closest?.('#filesGlobalActions')) {
        filesGlobalActionsEl.open = false;
    }
}

function collapseInlineFileDetailsOnEscape(event) {
    if (event.key !== 'Escape' || !filesState.expandedFilePath) return;
    const row = event.target?.closest?.('.uploaded-file--file') || null;
    const trigger = row?.querySelector('[data-file-details-trigger][data-path]') || null;
    const panel = row?.querySelector('.file-row__details-panel') || null;
    if (!trigger || !panel) return;

    const path = decodeURIComponent(trigger.dataset.path || '');
    if (
        path !== filesState.expandedFilePath
        || (!trigger.contains(event.target) && !panel.contains(event.target))
    ) {
        return;
    }

    event.preventDefault();
    collapseInlineFileDetails();
    focusElementWithoutScroll(trigger);
}

function syncSelectedUploadFilesDom() {
    if (serverFilesEl) {
        serverFilesEl.querySelectorAll('[data-file-select]').forEach(selectBox => {
            const path = decodeURIComponent(selectBox.dataset.path || '');
            const selected = Boolean(path && filesState.selectedPaths.has(path));
            selectBox.checked = selected;
            selectBox.closest('.uploaded-file')?.classList.toggle('is-selected', selected);
        });
    }
}

function clearSelectedUploadFiles() {
    filesState.selectedPaths.clear();
    syncSelectedUploadFilesDom();
    updateSelectedUploadsButton();
}

function syncVisibleUploadFilesSelection() {
    if (!filesSelectVisibleCheckbox) return;
    const visiblePaths = getVisibleSelectableFilePaths();
    const selectedVisibleCount = visiblePaths.filter(path => filesState.selectedPaths.has(path)).length;
    const allVisibleSelected = visiblePaths.length > 0
        && selectedVisibleCount === visiblePaths.length;
    const someVisibleSelected = selectedVisibleCount > 0 && !allVisibleSelected;
    const labelKey = allVisibleSelected ? 'filesDeselectVisible' : 'filesSelectVisible';
    const label = t(labelKey);

    filesSelectVisibleCheckbox.checked = allVisibleSelected;
    filesSelectVisibleCheckbox.indeterminate = someVisibleSelected;
    filesSelectVisibleCheckbox.disabled = !isFileDeleteSupported()
        || filesState.listActionsDisabled
        || filesState.browsePhase === 'loading'
        || visiblePaths.length === 0;
    filesSelectVisibleCheckbox.setAttribute(
        'aria-checked',
        someVisibleSelected ? 'mixed' : String(allVisibleSelected),
    );
    const labelElement = filesSelectVisibleCheckbox.closest('label');
    if (labelElement) {
        labelElement.title = label;
        labelElement.setAttribute('aria-label', label);
    }
}

function toggleVisibleUploadFilesSelection() {
    const visiblePaths = getVisibleSelectableFilePaths();
    if (
        filesState.listActionsDisabled
        || !isFileDeleteSupported()
        || visiblePaths.length === 0
    ) {
        syncVisibleUploadFilesSelection();
        return;
    }

    if (filesSelectVisibleCheckbox?.checked) {
        visiblePaths.forEach(path => filesState.selectedPaths.add(path));
    } else {
        visiblePaths.forEach(path => filesState.selectedPaths.delete(path));
    }
    syncSelectedUploadFilesDom();
    updateSelectedUploadsButton();
    announceFilesSelectionCount();
}

function announceFilesSelectionCount() {
    announceLiveRegion(
        'filesResponseAreaLive',
        t('filesSelectionCount').replace('{0}', String(filesState.selectedPaths.size)),
    );
}

function updateSelectedUploadsButton() {
    const selectedCount = filesState.selectedPaths.size;
    if (deleteSelectedUploadsBtn) {
        deleteSelectedUploadsBtn.disabled = !isFileDeleteSupported()
            || filesState.listActionsDisabled
            || selectedCount === 0;
        deleteSelectedUploadsBtn.dataset.count = String(selectedCount);
        const deleteLabel = selectedCount > 0
            ? t('deleteSelectedFilesCount').replace('{0}', String(selectedCount))
            : t('deleteSelectedFilesBtn');
        deleteSelectedUploadsBtn.textContent = deleteLabel;
        deleteSelectedUploadsBtn.title = deleteLabel;
        deleteSelectedUploadsBtn.setAttribute('aria-label', deleteLabel);
    }
    if (clearSelectedUploadsBtn) {
        clearSelectedUploadsBtn.disabled = filesState.listActionsDisabled || selectedCount === 0;
    }
    if (filesSelectionCountEl) {
        filesSelectionCountEl.textContent = t('filesSelectionCount').replace('{0}', String(selectedCount));
    }
    if (filesSelectionBarEl) {
        filesSelectionBarEl.hidden = selectedCount === 0;
    }
    syncVisibleUploadFilesSelection();
}

function formatFilesBrowseSummary(path, info) {
    if (info?.entry?.kind === 'directory' && Array.isArray(info.contents)) {
        const visibleCount = info.contents.length;
        const totalItems = Number(info.page?.total_items);
        const summary = t('filesBrowseSummary')
            .replace('{0}', path)
            .replace('{1}', String(visibleCount));
        if (Number.isFinite(totalItems) && totalItems > visibleCount) {
            return `${summary} • ${t('filesBrowseVisibleCount')
                .replace('{0}', String(visibleCount))
                .replace('{1}', String(totalItems))}`;
        }
        return summary;
    }

    return `${t('methodInfo')}: ${path}`;
}

function setFilesBrowseStatus(message = '', options = {}) {
    const text = String(message || '').trim();
    const phase = options.phase || (text ? 'active' : 'idle');
    filesState.browsePhase = phase;
    if (filesBrowseStatusEl) {
        filesBrowseStatusEl.textContent = text;
        filesBrowseStatusEl.dataset.browsePhase = phase;
    }
    if (serverFilesEl) {
        serverFilesEl.setAttribute('aria-busy', String(options.busy === true));
        serverFilesEl.dataset.browsePhase = phase;
    }
    syncFilesListControls();
}

function setFilesListActionsDisabled(disabled) {
    filesState.listActionsDisabled = Boolean(disabled);
    if (serverFilesEl) {
        serverFilesEl.dataset.stale = String(filesState.listActionsDisabled);
        serverFilesEl.querySelectorAll('button, input').forEach(control => {
            control.disabled = filesState.listActionsDisabled;
        });
    }
    if (clearUploadsBtn) {
        clearUploadsBtn.disabled = !isFileDeleteSupported() || filesState.listActionsDisabled;
    }
    updateSelectedUploadsButton();
    syncFilesListControls();
}

function getFilesErrorOrigin(origin = null) {
    if (origin?.isConnected && !origin.disabled) {
        return origin;
    }
    return browseBtn || browsePathInput;
}

function showFilesBrowseError({ path, response = null, text = '', error = null, origin = null }) {
    const retryPath = String(path || '/');
    const message = error?.message || String(error || '');
    return httpErrors.show({
        host: 'filesHttpErrorHost',
        origin: getFilesErrorOrigin(origin),
        method: 'INFO',
        path: retryPath,
        status: Number(response?.status || 0),
        statusText: response?.statusText || message || t('error'),
        headers: response?.headers || {},
        body: String(text || message),
        retry: () => browseDirectory({ path: retryPath, origin: getFilesErrorOrigin(origin) }),
    });
}

function markFilesListStale() {
    filesState.selectedPaths.clear();
    if (filesState.lastSuccessfulPath) {
        renderServerFiles(
            filesState.lastSuccessfulItems,
            filesState.lastSuccessfulPath,
            { phase: 'stale', totalItems: filesState.lastSuccessfulTotalItems }
        );
    }
    setFilesListActionsDisabled(true);
    if (filesState.lastSuccessfulPath) {
        setFilesBrowseStatus(
            t('filesBrowseStale').replace('{0}', filesState.lastSuccessfulPath),
            { phase: 'stale', busy: false }
        );
    }
}

function createInspectionInfoUrl(path) {
    const url = new URL(SERVER_URL + encodeFileRequestPath(path), window.location.href);
    url.searchParams.set('inspect', 'true');
    return url.toString();
}

function createFileActionButton(className, action, encodedPath, label, text) {
    const button = document.createElement('button');
    button.type = 'button';
    button.className = className;
    button.dataset.fileAction = action;
    button.dataset.path = encodedPath;
    button.title = label;
    button.setAttribute('aria-label', label);
    button.textContent = text;
    button.disabled = filesState.listActionsDisabled;
    return button;
}

function getFileInspection(item) {
    const inspection = item?.inspection;
    if (!inspection || typeof inspection !== 'object' || Array.isArray(inspection)) {
        return null;
    }
    return inspection;
}

function getInspectionSourceLabel(source) {
    switch (String(source || '')) {
    case 'signature':
        return t('filesInspectionSourceSignature');
    case 'text':
        return t('filesInspectionSourceText');
    case 'extension':
        return t('filesInspectionSourceExtension');
    default:
        return t('filesInspectionSourceUnknown');
    }
}

function getInspectionWarningLabel(inspection) {
    switch (inspection?.warning) {
    case 'possible_encrypted_or_packed':
        return t('filesInspectionWarningPossibleEncryptedOrPacked');
    case 'extension_mismatch':
        return t('filesInspectionWarningExtensionMismatch');
    default:
        return '';
    }
}

function getInspectionAssessmentLabel(inspection) {
    switch (inspection?.content_state) {
    case 'recognized':
        return t('filesInspectionStateRecognized');
    case 'opaque':
        return t('filesInspectionStateOpaque');
    default:
        return t('filesInspectionStateUnknown');
    }
}

function formatInspectionMimeLine(inspection) {
    const mimeType = String(inspection?.mime_type || '').trim() || 'application/octet-stream';
    return t('filesInspectionMimeLine')
        .replace('{0}', mimeType)
        .replace('{1}', getInspectionSourceLabel(inspection?.mime_source));
}

function isInspectionSuspicious(inspection) {
    return inspection?.content_state === 'opaque'
        || inspection?.warning === 'possible_encrypted_or_packed';
}

function createFileDetailsDomId(kind, encodedPath) {
    const safePath = encodeURIComponent(String(encodedPath || ''));
    return `file-${kind}-${safePath}`;
}

function appendFileIdentity(container, itemName, itemIcon, inspection = null) {
    const icon = document.createElement('span');
    icon.className = 'file-icon';
    icon.setAttribute('aria-hidden', 'true');
    icon.textContent = itemIcon;
    container.appendChild(icon);

    const meta = document.createElement('div');
    meta.className = 'file-meta';
    const name = document.createElement('span');
    name.className = 'file-name';
    name.textContent = itemName;
    meta.appendChild(name);

    if (inspection) {
        const mime = document.createElement('span');
        mime.className = 'file-inspection__mime';
        mime.textContent = formatInspectionMimeLine(inspection);
        meta.appendChild(mime);

        const warning = getInspectionWarningLabel(inspection);
        if (warning) {
            const warningText = document.createElement('span');
            warningText.className = 'file-inspection__warning';
            warningText.textContent = warning;
            meta.appendChild(warningText);
        }
    }

    container.appendChild(meta);
}

function createFileInfo(
    itemName,
    itemIcon,
    selectControl = null,
    inspection = null,
    details = null,
) {
    const info = document.createElement('div');
    info.className = 'file-info';
    if (selectControl) {
        info.appendChild(selectControl);
    }

    if (!details) {
        appendFileIdentity(info, itemName, itemIcon, inspection);
        return info;
    }

    const trigger = document.createElement('button');
    trigger.type = 'button';
    trigger.className = 'file-row__details-trigger';
    trigger.id = details.triggerId;
    trigger.dataset.fileDetailsTrigger = '';
    trigger.dataset.path = details.encodedPath;
    trigger.setAttribute('aria-controls', details.panelId);
    trigger.setAttribute('aria-expanded', String(details.expanded));
    const triggerLabel = `${t(details.expanded ? 'fileDetailsCollapse' : 'fileDetailsExpand')}: ${itemName}`;
    trigger.setAttribute('aria-label', triggerLabel);
    trigger.title = triggerLabel;
    trigger.disabled = filesState.listActionsDisabled;
    appendFileIdentity(trigger, itemName, itemIcon, inspection);

    const chevron = document.createElement('span');
    chevron.className = 'file-row__details-chevron';
    chevron.setAttribute('aria-hidden', 'true');
    chevron.textContent = '⌄';
    trigger.appendChild(chevron);
    info.appendChild(trigger);
    return info;
}

function createInlineFileDetailsPanel(itemName, encodedPath, triggerId, panelId, expanded) {
    const panel = document.createElement('section');
    panel.className = 'file-row__details-panel';
    panel.id = panelId;
    panel.dataset.path = encodedPath;
    panel.setAttribute('role', 'region');
    panel.setAttribute('aria-labelledby', triggerId);
    panel.setAttribute('aria-busy', String(expanded && filesState.fileInfoPhase === 'loading'));
    panel.hidden = !expanded;
    panel.setAttribute('aria-label', `${t('fileDetailsTitle')}: ${itemName}`);
    if (expanded) {
        renderInlineFileDetailsPanel(panel, decodeURIComponent(encodedPath));
    }
    return panel;
}

function createFileSelectControl(encodedPath, label, checked = false) {
    const select = document.createElement('label');
    select.className = 'file-select';
    select.title = label;
    select.setAttribute('aria-label', label);

    const input = document.createElement('input');
    input.type = 'checkbox';
    input.name = 'file-selection';
    input.dataset.fileSelect = '';
    input.dataset.path = encodedPath;
    input.checked = checked;
    input.disabled = filesState.listActionsDisabled;
    select.appendChild(input);

    const marker = document.createElement('span');
    marker.setAttribute('aria-hidden', 'true');
    select.appendChild(marker);
    return select;
}

function createFileSelectPlaceholder() {
    const placeholder = document.createElement('span');
    placeholder.className = 'file-select file-select--placeholder';
    placeholder.setAttribute('aria-hidden', 'true');
    return placeholder;
}

function createServerFileRow(item, basePath) {
    const itemName = String(item?.name || '');
    const itemPath = basePath + '/' + itemName;
    const encodedItemPath = encodeURIComponent(itemPath);
    const itemIcon = item?.kind === 'directory' ? '📁' : '📄';
    const row = document.createElement('div');
    row.className = `uploaded-file uploaded-file--${item?.kind === 'directory' ? 'dir' : 'file'}`;
    row.setAttribute('role', 'listitem');

    if (item?.kind === 'directory') {
        row.appendChild(createFileInfo(
            itemName,
            itemIcon,
            isFileDeleteSupported() ? createFileSelectPlaceholder() : null,
        ));
        const actions = document.createElement('div');
        actions.className = 'file-row__actions';
        const primary = document.createElement('div');
        primary.className = 'file-row__actions-primary';
        primary.appendChild(createFileActionButton(
            'btn-info btn--sm file-row__action-main',
            'open-dir',
            encodedItemPath,
            `${t('open')}: ${itemName}`,
            t('open'),
        ));
        actions.appendChild(primary);
        row.appendChild(actions);
        return row;
    }

    const inspection = getFileInspection(item);
    const selected = filesState.selectedPaths.has(itemPath);
    const expanded = filesState.expandedFilePath === itemPath;
    const detailsTriggerId = createFileDetailsDomId('details-trigger', encodedItemPath);
    const detailsPanelId = createFileDetailsDomId('details-panel', encodedItemPath);
    row.classList.toggle('is-selected', selected);
    row.classList.toggle('is-expanded', expanded);
    const selectLabel = `${t('selectFileLabel')}: ${itemName}`;
    row.appendChild(createFileInfo(
        itemName,
        itemIcon,
        isFileDeleteSupported()
            ? createFileSelectControl(encodedItemPath, selectLabel, selected)
            : null,
        inspection,
        {
            encodedPath: encodedItemPath,
            triggerId: detailsTriggerId,
            panelId: detailsPanelId,
            expanded,
        },
    ));

    const actions = document.createElement('div');
    actions.className = 'file-row__actions';
    const primary = document.createElement('div');
    primary.className = 'file-row__actions-primary';
    if (isFileDownloadSupported()) {
        primary.appendChild(createFileActionButton(
            'btn-fetch btn--sm file-row__action-main',
            'download',
            encodedItemPath,
            `${t('methodFetch')}: ${itemName}`,
            t('download'),
        ));
    }
    actions.appendChild(primary);

    const more = document.createElement('details');
    more.className = 'file-row__more';
    const moreSummary = document.createElement('summary');
    moreSummary.textContent = '⋮';
    moreSummary.setAttribute('aria-label', `${t('filesMoreActions')}: ${itemName}`);
    more.appendChild(moreSummary);

    const secondary = document.createElement('div');
    secondary.className = 'file-row__actions-secondary';
    secondary.setAttribute('aria-label', t('filesMoreActions'));
    if (isFileDownloadSupported()) {
        const xorAction = createFileActionButton(
            'btn-ghost btn--sm file-row__menu-item file-row__action-muted',
            'decrypt-xor',
            encodedItemPath,
            `${t('xorDecryptButtonLabel')}: ${itemName}`,
            t('xorDecryptButtonLabel'),
        );
        const suspicious = isInspectionSuspicious(inspection);
        const hint = document.createElement('p');
        hint.className = 'file-row__xor-hint';
        if (suspicious) {
            xorAction.classList.add('file-row__action-xor--caution');
            hint.classList.add('file-row__xor-hint--caution');
        }
        hint.id = `file-xor-hint-${encodedItemPath}`;
        hint.textContent = t(suspicious ? 'filesXorHintOpaque' : 'filesXorHintNeutral');
        xorAction.setAttribute('aria-describedby', hint.id);
        secondary.appendChild(xorAction);
        secondary.appendChild(hint);
    }
    if (isSmuggleSupported()) {
        secondary.appendChild(createFileActionButton(
            'btn-ghost btn--sm file-row__menu-item file-row__action-muted',
            'smuggle',
            encodedItemPath,
            `${t('smuggleButtonLabel')}: ${itemName}`,
            t('smuggleButtonLabel'),
        ));
    }
    if (isFileDeleteSupported()) {
        if (secondary.childElementCount > 0) {
            const separator = document.createElement('hr');
            separator.className = 'file-row__menu-separator';
            secondary.appendChild(separator);
        }
        secondary.appendChild(createFileActionButton(
            'btn-ghost btn--sm file-row__menu-item file-row__action-danger',
            'delete',
            encodedItemPath,
            `${t('deleteFileAction')}: ${itemName}`,
            t('deleteFileAction'),
        ));
    }
    if (secondary.childElementCount > 0) {
        more.appendChild(secondary);
        actions.appendChild(more);
    }
    row.appendChild(actions);
    row.appendChild(createInlineFileDetailsPanel(
        itemName,
        encodedItemPath,
        detailsTriggerId,
        detailsPanelId,
        expanded,
    ));
    return row;
}

function getFilesLocale() {
    return getCoreState?.().lang || document.documentElement.lang || 'ru';
}

function normalizeFileSearchText(value) {
    const text = String(value || '');
    try {
        return text.toLocaleLowerCase(getFilesLocale());
    } catch (error) {
        return text.toLowerCase();
    }
}

function filterServerFileItems(items) {
    const query = normalizeFileSearchText(filesState.searchQuery);
    if (!query) {
        return (Array.isArray(items) ? items : []).slice();
    }
    return (Array.isArray(items) ? items : []).filter(item => (
        normalizeFileSearchText(item?.name).includes(query)
    ));
}

function sortServerFileItems(items) {
    const direction = filesState.sortDirection === 'desc' ? -1 : 1;
    return (Array.isArray(items) ? items : []).slice().sort((left, right) => {
        const leftIsDirectory = left?.kind === 'directory';
        const rightIsDirectory = right?.kind === 'directory';
        if (leftIsDirectory !== rightIsDirectory) {
            return leftIsDirectory ? -1 : 1;
        }
        const leftName = String(left?.name || '');
        const rightName = String(right?.name || '');
        return direction * leftName.localeCompare(
            rightName,
            getFilesLocale(),
            { sensitivity: 'base' },
        );
    });
}

function getVisibleServerFileItems(items = filesState.lastSuccessfulItems) {
    return sortServerFileItems(filterServerFileItems(items));
}

function getServerFileItemPath(item, path = filesState.lastSuccessfulPath) {
    const basePath = path === '/' ? '' : String(path || '');
    return `${basePath}/${String(item?.name || '')}`;
}

function getVisibleSelectableFilePaths() {
    return getVisibleServerFileItems()
        .filter(item => item?.kind !== 'directory')
        .map(item => getServerFileItemPath(item));
}

function formatFilesFilterSummary(visibleCount, loadedCount) {
    const totalItems = Number(filesState.lastSuccessfulTotalItems);
    if (Number.isFinite(totalItems) && totalItems > loadedCount) {
        return t('filesFilterSummaryPaged')
            .replace('{0}', String(visibleCount))
            .replace('{1}', String(loadedCount))
            .replace('{2}', String(totalItems));
    }
    return t('filesFilterSummary')
        .replace('{0}', String(visibleCount))
        .replace('{1}', String(loadedCount));
}

function syncFilesListControls() {
    const loadedItems = Array.isArray(filesState.lastSuccessfulItems)
        ? filesState.lastSuccessfulItems
        : [];
    const visibleItems = getVisibleServerFileItems(loadedItems);
    const hasLoadedList = Boolean(filesState.lastSuccessfulPath)
        && filesState.browsePhase !== 'loading';
    const hasItems = loadedItems.length > 0;
    const searchActive = filesState.searchQuery.length > 0;

    if (filesSearchInput) {
        if (filesSearchInput.value !== filesState.searchQuery) {
            filesSearchInput.value = filesState.searchQuery;
        }
        filesSearchInput.disabled = !hasLoadedList;
    }
    if (filesSearchClearBtn) {
        filesSearchClearBtn.hidden = !searchActive;
        filesSearchClearBtn.disabled = !hasLoadedList;
    }
    if (filesListHeaderEl) {
        filesListHeaderEl.hidden = !hasLoadedList || !hasItems;
        filesListHeaderEl.dataset.sortDirection = filesState.sortDirection;
    }
    if (filesSortNameBtn) {
        const sortLabelKey = filesState.sortDirection === 'asc'
            ? 'filesSortAscending'
            : 'filesSortDescending';
        const sortLabel = t(sortLabelKey);
        filesSortNameBtn.disabled = !hasLoadedList || !hasItems;
        filesSortNameBtn.title = sortLabel;
        filesSortNameBtn.setAttribute('aria-label', sortLabel);
        filesSortNameBtn.dataset.sortDirection = filesState.sortDirection;
    }
    if (filesSortNameIndicatorEl) {
        filesSortNameIndicatorEl.textContent = filesState.sortDirection === 'asc' ? '↑' : '↓';
    }
    if (filesFilterStatusEl) {
        filesFilterStatusEl.textContent = searchActive && hasLoadedList
            ? formatFilesFilterSummary(visibleItems.length, loadedItems.length)
            : '';
    }
    syncVisibleUploadFilesSelection();
}

function renderCurrentServerFiles() {
    if (!filesState.lastSuccessfulPath) return;
    renderServerFiles(filesState.lastSuccessfulItems, filesState.lastSuccessfulPath, {
        phase: filesState.browsePhase,
        totalItems: filesState.lastSuccessfulTotalItems,
    });
}

function setFilesSearchQuery(value, { announceSelectionReset = false } = {}) {
    const nextQuery = String(value || '');
    if (nextQuery === filesState.searchQuery) {
        syncFilesListControls();
        return;
    }

    const hadSelection = filesState.selectedPaths.size > 0;
    filesState.searchQuery = nextQuery;
    if (hadSelection) {
        clearSelectedUploadFiles();
    }

    if (filesState.expandedFilePath) {
        const visiblePaths = new Set(getVisibleServerFileItems().map(item => (
            getServerFileItemPath(item)
        )));
        if (!visiblePaths.has(filesState.expandedFilePath)) {
            collapseInlineFileDetails();
        }
    }

    renderCurrentServerFiles();
    if (announceSelectionReset && hadSelection) {
        announceLiveRegion('filesResponseAreaLive', t('filesSelectionClearedBySearch'));
    }
}

function toggleFilesNameSort() {
    filesState.sortDirection = filesState.sortDirection === 'asc' ? 'desc' : 'asc';
    closeFileActionDisclosures();
    renderCurrentServerFiles();
    announceLiveRegion(
        'filesResponseAreaLive',
        t(filesState.sortDirection === 'asc' ? 'filesSortedAscending' : 'filesSortedDescending'),
    );
}

function renderFilesListMessage(message, phase) {
    if (!serverFilesEl) return;
    const row = document.createElement('div');
    row.className = 'file-browser__list-message';
    row.dataset.browsePhase = phase;
    row.setAttribute('role', 'listitem');
    row.textContent = message;
    serverFilesEl.replaceChildren(row);
    syncFilesListControls();
}

function renderServerFiles(items, path, options = {}) {
    if (!serverFilesEl) {
        return;
    }
    const basePath = path === '/' ? '' : path;
    const fragment = document.createDocumentFragment();
    const sourceItems = Array.isArray(items) ? items : [];
    const visibleItems = getVisibleServerFileItems(sourceItems);
    if (sourceItems.length === 0) {
        renderFilesListMessage(t('filesBrowseEmpty'), options.phase || 'empty');
        return;
    }
    if (visibleItems.length === 0) {
        renderFilesListMessage(t('filesSearchNoMatches'), 'filtered-empty');
        return;
    }
    visibleItems.forEach(item => {
        fragment.appendChild(createServerFileRow(item, basePath));
    });
    serverFilesEl.replaceChildren(fragment);
    setFilesListActionsDisabled(filesState.listActionsDisabled);
    syncFilesListControls();
}

function resetFilesActionSummary() {
    setExchangeInspector('files', { phase: 'empty' });
}

async function browseDirectory(options = {}) {
    if (!isFileBrowseSupported()) {
        return false;
    }
    const suppressLiveAnnouncements = options.suppressLiveAnnouncements === true;
    const path = String(options.path || document.getElementById('browsePathInput').value || '/');
    const origin = options.origin || browseBtn;
    const serverFiles = document.getElementById('serverFiles');
    if (filesState.lastSuccessfulPath && path !== filesState.lastSuccessfulPath) {
        filesState.searchQuery = '';
    }
    const generation = ++filesState.browseGeneration;
    if (filesBrowseStatusEl) {
        filesBrowseStatusEl.setAttribute(
            'aria-live',
            suppressLiveAnnouncements ? 'off' : 'polite',
        );
    }
    filesState.infoGeneration += 1;
    clearInlineFileDetails({ clearCache: true, invalidate: false });
    const preserveActionSummary = options.preserveActionSummary === true;
    filesState.activePath = path;
    clearSelectedUploadFiles();
    closeFileActionDisclosures();
    if (filesGlobalActionsEl) filesGlobalActionsEl.open = false;
    if (!preserveActionSummary) {
        resetFilesActionSummary();
    }

    if (!suppressLiveAnnouncements) {
        announceLiveRegion('filesResponseAreaLive', `${t('loadingInfo')} ${path}`);
    }
    setFilesBrowseStatus(t('filesBrowseLoading').replace('{0}', path), { phase: 'loading', busy: true });
    renderFilesListMessage(t('filesBrowseLoading').replace('{0}', path), 'loading');

    try {
        const response = await sendCustomRequest('INFO', createInspectionInfoUrl(path));
        const text = await response.text();
        if (generation !== filesState.browseGeneration) {
            return false;
        }
        let payload = null;
        try {
            payload = JSON.parse(text);
        } catch (_error) {}
        const info = getCanonicalInfoPayload(payload);
        if (!response.ok || !info) {
            markFilesListStale();
            showFilesBrowseError({
                path,
                response,
                text: getCanonicalResponseErrorMessage(response, payload, text),
                origin,
            });
            if (!filesState.lastSuccessfulPath) {
                setFilesBrowseStatus(
                    `${response.status} ${response.statusText || t('error')}`.trim(),
                    { phase: 'error', busy: false }
                );
                renderFilesListMessage(t('filesBrowseInitialError'), 'error');
            }
            announceLiveRegion(
                'filesResponseAreaLive',
                `INFO ${path} ${response.status} ${response.statusText || t('error')}`.trim()
            );
            return false;
        }
        filesState.lastSuccessfulPath = path;
        filesState.lastSuccessfulItems = info.entry.kind === 'directory' && Array.isArray(info.contents)
            ? info.contents.slice()
            : [];
        filesState.lastSuccessfulTotalItems = Number.isFinite(Number(info.page?.total_items))
            ? Number(info.page.total_items)
            : filesState.lastSuccessfulItems.length;
        filesState.lastSuccessfulInfo = {
            ...info,
            contents: filesState.lastSuccessfulItems,
            page: {
                ...info.page,
                total_items: filesState.lastSuccessfulTotalItems,
            },
        };
        const listPhase = filesState.lastSuccessfulItems.length ? 'complete' : 'empty';
        setFilesListActionsDisabled(false);
        renderServerFiles(filesState.lastSuccessfulItems, path, {
            phase: listPhase,
            totalItems: filesState.lastSuccessfulTotalItems,
        });
        httpErrors.close('filesHttpErrorHost');

        const browseSummary = formatFilesBrowseSummary(path, info);
        setFilesBrowseStatus(browseSummary, { phase: 'complete', busy: false });
        if (!suppressLiveAnnouncements) {
            announceLiveRegion(
                'filesResponseAreaLive',
                `INFO ${path} ${response.status} ${response.statusText || 'OK'}`.trim()
            );
        }
        return true;

    } catch (error) {
        if (generation !== filesState.browseGeneration) {
            return false;
        }
        markFilesListStale();
        showFilesBrowseError({ path, error, origin });
        announceLiveRegion('filesResponseAreaLive', `INFO ${path} ${t('error')}: ${error.message}`);
        if (!filesState.lastSuccessfulPath) {
            setFilesBrowseStatus(`${t('error')}: ${error.message}`, { phase: 'error', busy: false });
            renderFilesListMessage(t('filesBrowseInitialError'), 'error');
        }
        return false;
    } finally {
        if (generation === filesState.browseGeneration && serverFiles) {
            serverFiles.setAttribute('aria-busy', 'false');
        }
        if (generation === filesState.browseGeneration && filesBrowseStatusEl) {
            filesBrowseStatusEl.setAttribute('aria-live', 'polite');
        }
    }
}

function encodeFileRequestPath(path) {
    return String(path || '').split('/').map(segment => {
        try {
            return encodeURIComponent(decodeURIComponent(segment));
        } catch (error) {
            return encodeURIComponent(segment);
        }
    }).join('/');
}

function formatInlineFileDetailValue(value) {
    const text = String(value ?? '').trim();
    return text || '-';
}

function createInlineFileDetailField(label, value, field) {
    const row = document.createElement('div');
    row.className = 'file-row__details-field';
    row.dataset.field = field;

    const term = document.createElement('dt');
    term.textContent = label;
    row.appendChild(term);

    const description = document.createElement('dd');
    description.textContent = formatInlineFileDetailValue(value);
    row.appendChild(description);
    return row;
}

function renderInlineFileDetailsPanel(panel, path) {
    if (!panel) return;
    panel.replaceChildren();
    panel.setAttribute('aria-busy', String(filesState.fileInfoPhase === 'loading'));

    if (filesState.fileInfoPhase === 'loading') {
        const loading = document.createElement('p');
        loading.className = 'file-row__details-status';
        loading.textContent = t('fileDetailsLoading').replace('{0}', path);
        panel.appendChild(loading);
        return;
    }

    if (filesState.fileInfoPhase === 'error') {
        const error = document.createElement('p');
        error.className = 'file-row__details-status file-row__details-status--error';
        error.textContent = `${t('fileInfoError')}: ${filesState.fileInfoError || t('error')}`;
        panel.appendChild(error);

        const retry = document.createElement('button');
        retry.type = 'button';
        retry.className = 'btn btn-ghost btn--sm file-row__details-retry';
        retry.dataset.fileDetailsRetry = '';
        retry.dataset.path = encodeURIComponent(path);
        retry.textContent = t('fileDetailsRetry');
        panel.appendChild(retry);
        return;
    }

    const info = filesState.fileInfoCache.get(path);
    if (!info) return;
    const inspection = getFileInspection(info);
    const numericSize = Number(info.size_bytes);
    const size = info.size_human
        || (Number.isFinite(numericSize) ? formatSize(numericSize) : '');
    const fields = [
        [t('fileName'), info.name, 'file-name'],
        [t('opsecSize'), size, 'size'],
        [
            t('responseSummaryFieldContentType'),
            inspection?.mime_type || info.content_type,
            'content-type',
        ],
        [
            t('fileInfoMimeSource'),
            inspection ? getInspectionSourceLabel(inspection.mime_source) : '',
            'mime-source',
        ],
        [
            t('fileInfoAssessment'),
            inspection ? getInspectionAssessmentLabel(inspection) : '',
            'content-assessment',
        ],
        [t('fileInfoExtension'), info.extension, 'extension'],
        [t('fileInfoCreated'), info.created_at, 'created'],
        [t('fileInfoModified'), info.modified_at, 'modified'],
    ];
    const details = document.createElement('dl');
    details.className = 'file-row__details-grid';
    fields.forEach(([label, value, field]) => {
        details.appendChild(createInlineFileDetailField(label, value, field));
    });
    panel.appendChild(details);
}

function syncInlineFileDetailsDom() {
    if (!serverFilesEl) return;
    serverFilesEl.querySelectorAll('[data-file-details-trigger][data-path]').forEach(trigger => {
        const path = decodeURIComponent(trigger.dataset.path || '');
        const expanded = path === filesState.expandedFilePath;
        const itemName = trigger.querySelector('.file-name')?.textContent || path;
        const panelId = trigger.getAttribute('aria-controls');
        const panel = panelId ? document.getElementById(panelId) : null;
        const label = `${t(expanded ? 'fileDetailsCollapse' : 'fileDetailsExpand')}: ${itemName}`;

        trigger.setAttribute('aria-expanded', String(expanded));
        trigger.setAttribute('aria-label', label);
        trigger.title = label;
        trigger.closest('.uploaded-file')?.classList.toggle('is-expanded', expanded);
        if (!panel) return;
        panel.hidden = !expanded;
        if (expanded) {
            renderInlineFileDetailsPanel(panel, path);
        } else {
            panel.setAttribute('aria-busy', 'false');
            panel.replaceChildren();
        }
    });
}

function clearInlineFileDetails({ clearCache = false, invalidate = true } = {}) {
    if (invalidate) {
        filesState.infoGeneration += 1;
    }
    filesState.expandedFilePath = null;
    filesState.fileInfoPhase = 'idle';
    filesState.fileInfoError = '';
    if (clearCache) {
        filesState.fileInfoCache.clear();
    }
    syncInlineFileDetailsDom();
}

function collapseInlineFileDetails() {
    clearInlineFileDetails({ clearCache: false, invalidate: true });
}

function toggleInlineFileDetails(path) {
    const requestPath = String(path || '/');
    closeFileActionDisclosures();
    if (filesState.expandedFilePath === requestPath) {
        collapseInlineFileDetails();
        return;
    }

    filesState.infoGeneration += 1;
    filesState.expandedFilePath = requestPath;
    filesState.fileInfoError = '';
    filesState.fileInfoPhase = filesState.fileInfoCache.has(requestPath) ? 'complete' : 'loading';
    syncInlineFileDetailsDom();
    if (!filesState.fileInfoCache.has(requestPath)) {
        void showInlineFileDetails(requestPath);
    }
}

async function showInlineFileDetails(path) {
    if (
        !isFileBrowseSupported()
        || filesState.listActionsDisabled
        || filesState.expandedFilePath !== path
    ) {
        return false;
    }

    const requestPath = String(path || '/');
    const generation = ++filesState.infoGeneration;
    filesState.fileInfoPhase = 'loading';
    filesState.fileInfoError = '';
    syncInlineFileDetailsDom();
    announceLiveRegion(
        'filesResponseAreaLive',
        t('fileDetailsLoading').replace('{0}', requestPath),
    );

    try {
        const response = await sendCustomRequest(
            'INFO',
            createInspectionInfoUrl(requestPath),
        );
        const text = await response.text();
        if (
            generation !== filesState.infoGeneration
            || filesState.expandedFilePath !== requestPath
        ) {
            return false;
        }

        let payload = null;
        try {
            payload = JSON.parse(text);
        } catch (_error) {}
        const info = getCanonicalInfoPayload(payload);
        if (!response.ok || !info || info.entry.kind !== 'file') {
            filesState.fileInfoPhase = 'error';
            filesState.fileInfoError = getCanonicalResponseErrorMessage(response, payload, text);
            syncInlineFileDetailsDom();
            announceLiveRegion(
                'filesResponseAreaLive',
                `${t('fileInfoError')}: ${filesState.fileInfoError}`,
            );
            return false;
        }

        filesState.fileInfoCache.set(requestPath, info.entry);
        filesState.fileInfoPhase = 'complete';
        filesState.fileInfoError = '';
        syncInlineFileDetailsDom();
        announceLiveRegion(
            'filesResponseAreaLive',
            `${t('fileInfoLoaded')}: ${info.entry.name || requestPath}`,
        );
        return true;
    } catch (error) {
        if (
            generation !== filesState.infoGeneration
            || filesState.expandedFilePath !== requestPath
        ) {
            return false;
        }
        filesState.fileInfoPhase = 'error';
        filesState.fileInfoError = error?.message || t('error');
        syncInlineFileDetailsDom();
        announceLiveRegion(
            'filesResponseAreaLive',
            `${t('fileInfoError')}: ${filesState.fileInfoError}`,
        );
        return false;
    }
}

function getFileNameFromPath(path) {
    const rawName = String(path || '').split(/[?#]/, 1)[0].split('/').filter(Boolean).pop() || '';
    try {
        return sanitizeXorDecryptFilename(decodeURIComponent(rawName)) || 'download';
    } catch (error) {
        return sanitizeXorDecryptFilename(rawName) || 'download';
    }
}

function sanitizeXorDecryptFilename(value) {
    return String(value || '')
        .replace(/[\x00-\x1f\x7f]/g, '-')
        .replace(/[\\/]+/g, '-')
        .trim();
}

function buildXorDecryptOutputName(filename) {
    const name = String(filename || '').trim() || 'download';
    if (/\.(enc|xor|bin)$/i.test(name)) {
        return name.replace(/\.(enc|xor|bin)$/i, '.dec');
    }
    return `${name}.dec`;
}

async function xorDecryptBytes(data, password) {
    const passwordBytes = new TextEncoder().encode(password);
    const keyBytes = new Uint8Array(await crypto.subtle.digest('SHA-256', passwordBytes));
    const result = new Uint8Array(data.length);
    for (let i = 0; i < data.length; i += 1) {
        result[i] = data[i] ^ keyBytes[i % keyBytes.length];
    }
    return result;
}

function getXorDecryptResponseHeader(headers, name) {
    if (!headers || !name) return '';
    if (typeof headers.get === 'function') {
        return headers.get(name) || '';
    }
    const lowerName = String(name).toLowerCase();
    return headers[lowerName] || headers[name] || '';
}

function getXorDecryptContentDispositionFilename(headers) {
    const contentDisposition = getXorDecryptResponseHeader(headers, 'Content-Disposition');
    const filenameStar = String(contentDisposition).match(
        /(?:^|;)\s*filename\*\s*=\s*(?:"([^"]*)"|([^;\s]*))/i
    );
    const encoded = (filenameStar?.[1] || filenameStar?.[2] || '').trim().match(/^utf-8''(.+)$/i)?.[1];
    if (encoded) {
        try {
            const filename = sanitizeXorDecryptFilename(decodeURIComponent(encoded));
            if (filename) return filename;
        } catch (error) {
            // Fall through to a plain filename parameter or the request URL.
        }
    }
    const filename = String(contentDisposition).match(
        /(?:^|;)\s*filename\s*=\s*(?:"([^"]*)"|([^;]*))/i
    );
    return sanitizeXorDecryptFilename((filename?.[1] || filename?.[2] || '').trim());
}

async function fetchFileBlobForXorDecrypt(path) {
    return new Promise((resolve, reject) => {
        const xhr = new XMLHttpRequest();
        xhr.open('FETCH', SERVER_URL + path, true);
        xhr.responseType = 'arraybuffer';
        xhr.timeout = 30000;
        Object.entries(withUiNoGzipHeader({})).forEach(([key, value]) => {
            xhr.setRequestHeader(key, value);
        });

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

            const bytes = new Uint8Array(xhr.response || new ArrayBuffer(0));
            if (xhr.status < 200 || xhr.status >= 300) {
                let message = `${xhr.status} ${xhr.statusText || t('error')}`.trim();
                try {
                    const text = new TextDecoder().decode(bytes);
                    if (text) {
                        message = text;
                    }
                } catch (error) {
                    // Keep the HTTP status message if the body is not text.
                }
                reject(new Error(message));
                return;
            }

            resolve({
                bytes,
                filename: getXorDecryptContentDispositionFilename(responseHeaders)
                    || getFileNameFromPath(path),
                headers: responseHeaders,
                status: xhr.status,
                statusText: xhr.statusText || 'OK',
            });
        };

        xhr.onerror = () => reject(new Error(t('networkError')));
        xhr.ontimeout = () => reject(new Error(t('timeoutError')));
        xhr.send();
    });
}

async function decryptXorFileFromBrowser(path, password, outputName) {
    const fetched = await fetchFileBlobForXorDecrypt(path);
    const encryptedBytes = fetched.bytes;
    const decryptedBytes = await xorDecryptBytes(encryptedBytes, password);
    const filename = String(outputName || '').trim()
        || buildXorDecryptOutputName(fetched.filename);
    downloadBlobFile(new Blob([decryptedBytes], { type: 'application/octet-stream' }), filename);
    return {
        ...fetched,
        decryptedSize: decryptedBytes.byteLength,
        outputName: filename,
    };
}

function showXorDecryptDialog(filePath, triggerEl = null) {
    const sourceName = getFileNameFromPath(filePath);
    const defaultOutputName = buildXorDecryptOutputName(sourceName);
    const restoreFocusSelector = `[data-file-action="decrypt-xor"][data-path="${encodeURIComponent(filePath)}"]`;
    const modal = openManagedDialog({
        dialogId: 'xorDecryptModal',
        triggerEl,
        restoreFocusSelector,
        restoreFocusOnConfirm: true,
        initialFocusSelector: '#xorDecryptPassword',
        markup: `
        <div class="modal-overlay">
            <div class="modal-content app-dialog" role="dialog" aria-modal="true" aria-labelledby="xorDecryptTitle" aria-describedby="xorDecryptMessage xorDecryptWarning xorDecryptStatus">
                <div class="app-dialog__header">
                    <h3 class="app-dialog__title" id="xorDecryptTitle">${esc(t('xorDecryptTitle'))}</h3>
                </div>
                <div class="app-dialog__body">
                    <p class="app-dialog__message" id="xorDecryptMessage">${esc(filePath)}</p>
                    <label class="smuggle-dialog__field" for="xorDecryptPassword">
                        <span>${esc(t('xorDecryptPasswordLabel'))}</span>
                        <input type="password" id="xorDecryptPassword" autocomplete="off" placeholder="${esc(t('xorDecryptPasswordPlaceholder'))}">
                    </label>
                    <label class="smuggle-dialog__field" for="xorDecryptOutputName">
                        <span>${esc(t('xorDecryptOutputNameLabel'))}</span>
                        <input type="text" id="xorDecryptOutputName" maxlength="180" value="${esc(defaultOutputName)}" placeholder="${esc(t('xorDecryptOutputNamePlaceholder'))}">
                    </label>
                    <p class="app-dialog__details" id="xorDecryptWarning">${esc(t('xorDecryptWarning'))}</p>
                    <p class="smuggle-dialog__hint" id="xorDecryptStatus" role="status" aria-live="polite" aria-atomic="true"></p>
                </div>
                <div class="modal-actions app-dialog__actions">
                    <button type="button" class="btn-ghost" data-dialog-action="cancel">${esc(t('smuggleCancel'))}</button>
                    <button type="button" class="btn-info" id="xorDecryptSubmitBtn" data-dialog-action="confirm">${esc(t('xorDecryptConfirm'))}</button>
                </div>
            </div>
        </div>
    `,
        onAction: async (action, dialog, actionButton) => {
            if (action !== 'confirm') {
                return false;
            }

            const passwordInput = dialog.querySelector('#xorDecryptPassword');
            const outputInput = dialog.querySelector('#xorDecryptOutputName');
            const statusEl = dialog.querySelector('#xorDecryptStatus');
            const password = String(passwordInput?.value || '');
            const outputName = String(outputInput?.value || '').trim();
            if (!password) {
                if (statusEl) statusEl.textContent = t('xorDecryptPasswordRequired');
                if (passwordInput) {
                    passwordInput.setAttribute('aria-invalid', 'true');
                    passwordInput.focus();
                }
                return undefined;
            }

            if (passwordInput) passwordInput.removeAttribute('aria-invalid');
            actionButton.disabled = true;
            if (statusEl) statusEl.textContent = t('xorDecryptRunning');
            announceLiveRegion('filesResponseAreaLive', `${t('xorDecryptRunning')}: ${sourceName}`);
            setExchangeInspector('files', {
                phase: 'sending',
                request: {
                    transport: 'http',
                    method: 'FETCH',
                    path: filePath,
                    headers: {},
                    body: null,
                },
                response: {
                    phase: 'sending',
                    summaryText: t('xorDecryptRunning'),
                    startLine: `FETCH ${filePath}`,
                    body: createExchangeTextBody(t('xorDecryptRunning')),
                },
            });

            try {
                const result = await decryptXorFileFromBrowser(filePath, password, outputName);
                const summary = `${t('xorDecryptSaved')}: ${result.outputName}`;
                announceLiveRegion('filesResponseAreaLive', summary);
                setExchangeInspector('files', {
                    phase: 'complete',
                    request: {
                        transport: 'http',
                        method: 'FETCH',
                        path: filePath,
                        headers: {},
                        body: null,
                    },
                    response: {
                        transport: 'http',
                        method: 'FETCH',
                        path: filePath,
                        phase: 'complete',
                        summaryText: summary,
                        startLine: `FETCH ${filePath}\n${result.status} ${result.statusText}`,
                        status: result.status,
                        statusText: result.statusText,
                        headers: result.headers,
                        body: createExchangeTextBody(
                            `${summary}\n${t('fileName')}: ${result.outputName}\n${t('opsecSize')}: ${formatSize(result.decryptedSize)}`
                        ),
                    },
                });
                if (statusEl) statusEl.textContent = summary;
                return true;
            } catch (error) {
                actionButton.disabled = false;
                const message = error?.message || t('error');
                if (statusEl) statusEl.textContent = `${t('xorDecryptFailed')}: ${message}`;
                announceLiveRegion('filesResponseAreaLive', `${t('xorDecryptFailed')}: ${message}`);
                setExchangeInspector('files', {
                    phase: 'error',
                    request: {
                        transport: 'http',
                        method: 'FETCH',
                        path: filePath,
                        headers: {},
                        body: null,
                    },
                    response: {
                        transport: 'http',
                        method: 'FETCH',
                        path: filePath,
                        phase: 'error',
                        summaryText: `${t('xorDecryptFailed')}: ${message}`,
                        startLine: `FETCH ${filePath}\n${t('error')}`,
                        body: createExchangeTextBody(message),
                    },
                });
                return undefined;
            }
        },
    });

    if (modal) {
        const passwordInput = modal.querySelector('#xorDecryptPassword');
        if (passwordInput) {
            passwordInput.addEventListener('input', () => passwordInput.removeAttribute('aria-invalid'));
        }
    }
}

function getClearUploadsDialogOrigin(triggerEl = null) {
    const menuSummary = filesGlobalActionsEl?.querySelector('summary') || null;
    if (triggerEl === clearUploadsBtn && filesGlobalActionsEl && !filesGlobalActionsEl.open) {
        return menuSummary || triggerEl;
    }
    return triggerEl || menuSummary || clearUploadsBtn;
}

async function clearUploads(triggerEl = null) {
    if (!isFileDeleteSupported() || filesState.listActionsDisabled) {
        return;
    }

    const dialogOrigin = getClearUploadsDialogOrigin(triggerEl);
    const confirmed = await showConfirmDialog({
        title: t('clearUploadsBtn'),
        message: t('clearUploadsConfirm'),
        details: '/uploads',
        confirmLabel: t('clearUploadsBtn'),
        triggerEl: dialogOrigin,
        initialFocus: 'cancel',
    });
    if (!confirmed) return;

    dismissFilesToast();
    announceLiveRegion('filesResponseAreaLive', t('clearUploadsRunning'));
    setExchangeInspector('files', {
        phase: 'sending',
        request: {
            transport: 'http',
            method: 'DELETE',
            path: '/uploads?clear=true',
            headers: {},
            body: null,
        },
        response: {
            phase: 'sending',
            summaryText: t('clearUploadsRunning'),
            startLine: t('clearUploadsRunning'),
            body: createExchangeTextBody(t('clearUploadsRunning')),
        },
    });

    try {
        const response = await sendCustomRequest('DELETE', `${SERVER_URL}/uploads?clear=true`);
        const text = await response.text();
        let result = null;
        try {
            result = JSON.parse(text);
        } catch (error) {
            result = null;
        }

        const clearedUploads = getCanonicalClearedUploads(result);
        if (response.ok && clearedUploads) {
            if (filesGlobalActionsEl) filesGlobalActionsEl.open = false;
            if (browsePathInput) {
                browsePathInput.value = '/';
            }
            const summary = `${t('clearUploadsSuccess')}: ${clearedUploads.deleted_files} ${t('filesDeleted')}, ${clearedUploads.deleted_dirs} ${t('dirsDeleted')}`;
            announceLiveRegion('filesResponseAreaLive', summary);
            setExchangeInspector('files', {
                phase: 'complete',
                request: {
                    transport: 'http',
                    method: 'DELETE',
                    path: '/uploads?clear=true',
                    headers: {},
                    body: null,
                },
                response: {
                    transport: 'http',
                    method: 'DELETE',
                    path: '/uploads?clear=true',
                    phase: 'complete',
                    summaryText: summary,
                    startLine: 'DELETE /uploads?clear=true\n200 OK',
                    status: 200,
                    statusText: 'OK',
                    headers: response.headers,
                    body: createExchangeTextBody(`${summary}\n\n${JSON.stringify(result, null, 2)}`, { contentType: 'application/json' }),
                },
            });
            await browseDirectory({ preserveActionSummary: true });
            focusFilesBrowserAnchor();
            return;
        }

        const message = getCanonicalResponseErrorMessage(response, result, text);
        setExchangeInspector('files', {
            phase: 'error',
            request: {
                transport: 'http',
                method: 'DELETE',
                path: '/uploads?clear=true',
                headers: {},
                body: null,
            },
            response: {
                transport: 'http',
                method: 'DELETE',
                path: '/uploads?clear=true',
                phase: 'error',
                summaryText: `${t('clearUploadsError')}: ${message}`,
                startLine: `DELETE /uploads?clear=true\n${t('error')}`,
                status: response.status,
                statusText: response.statusText || t('error'),
                headers: response.headers,
                body: createExchangeTextBody(message),
            },
        });
        const recoveryOrigin = getClearUploadsDialogOrigin(dialogOrigin);
        httpErrors.show({
            host: 'filesHttpErrorHost',
            origin: recoveryOrigin,
            retry: () => clearUploads(recoveryOrigin),
            method: 'DELETE',
            path: '/uploads?clear=true',
            status: response.status,
            statusText: response.statusText || t('error'),
            headers: response.headers,
            body: message,
        });
    } catch (e) {
        setExchangeInspector('files', {
            phase: 'error',
            request: {
                transport: 'http',
                method: 'DELETE',
                path: '/uploads?clear=true',
                headers: {},
                body: null,
            },
            response: {
                transport: 'http',
                method: 'DELETE',
                path: '/uploads?clear=true',
                phase: 'error',
                summaryText: `${t('clearUploadsError')}: ${e.message}`,
                startLine: `DELETE /uploads?clear=true\n${t('error')}`,
                body: createExchangeTextBody(e.message),
            },
        });
        const recoveryOrigin = getClearUploadsDialogOrigin(dialogOrigin);
        httpErrors.show({
            host: 'filesHttpErrorHost',
            origin: recoveryOrigin,
            retry: () => clearUploads(recoveryOrigin),
            method: 'DELETE',
            path: '/uploads?clear=true',
            status: 0,
            statusText: e.message || t('error'),
            body: e.message || '',
        });
    }
}

async function deleteSelectedUploadFiles(triggerEl = null) {
    if (!isFileDeleteSupported() || filesState.listActionsDisabled) {
        return;
    }

    const paths = Array.from(filesState.selectedPaths);
    if (paths.length === 0) return;

    const confirmed = await showConfirmDialog({
        title: t('deleteSelectedFilesBtn'),
        message: t('deleteSelectedFilesConfirm'),
        details: paths.join('\n'),
        confirmLabel: t('deleteSelectedFilesBtn'),
        triggerEl,
        initialFocus: 'cancel',
    });
    if (!confirmed) return;

    dismissFilesToast();
    const deleted = [];
    const errors = [];
    setExchangeInspector('files', {
        phase: 'sending',
        request: {
            transport: 'http',
            method: 'DELETE',
            path: t('deleteSelectedFilesBtn'),
            headers: {},
            body: createExchangeTextBody(paths.join('\n')),
        },
        response: {
            phase: 'sending',
            summaryText: t('statusPending'),
            startLine: t('statusPending'),
            body: createExchangeTextBody(t('statusPending')),
        },
    });

    for (const path of paths) {
        try {
            const response = await sendCustomRequest(
                'DELETE',
                SERVER_URL + encodeFileRequestPath(path),
            );
            const text = await response.text();
            let result = null;
            try {
                result = JSON.parse(text);
            } catch (error) {
                result = null;
            }

            if (response.ok && getCanonicalDeletedFile(result)) {
                deleted.push(path);
                filesState.selectedPaths.delete(path);
            } else {
                const message = getCanonicalResponseErrorMessage(response, result, text);
                errors.push(`${path}: ${message}`);
            }
        } catch (e) {
            errors.push(`${path}: ${e.message}`);
        }
    }

    const summary = `${t('deleteSelectedFilesSuccess')}: ${deleted.length}`;
    if (errors.length) {
        announceLiveRegion('filesResponseAreaLive', summary);
        setExchangeInspector('files', {
            phase: 'error',
            request: {
                transport: 'http',
                method: 'DELETE',
                path: t('deleteSelectedFilesBtn'),
                headers: {},
                body: createExchangeTextBody(paths.join('\n')),
            },
            response: {
                transport: 'http',
                method: 'DELETE',
                path: t('deleteSelectedFilesBtn'),
                phase: 'error',
                summaryText: errors[0] || summary,
                startLine: `DELETE ${t('deleteSelectedFilesBtn')}\n${t('error')}`,
                status: 400,
                statusText: t('error'),
                body: createExchangeTextBody(`${summary}\n\n${errors.join('\n')}`),
            },
        });
        await browseDirectory({ preserveActionSummary: true });
        await showNoticeDialog({
            title: t('deleteError'),
            message: errors.join('\n'),
            details: t('deleteSelectedFilesBtn'),
            triggerEl,
        });
    } else {
        resetFilesActionSummary();
        const refreshed = await browseDirectory({ suppressLiveAnnouncements: true });
        if (refreshed) {
            showFilesDeletedToast(deleted.length);
        } else {
            announceLiveRegion(
                'filesResponseAreaLive',
                t('deleteSelectedFilesRefreshError').replace('{0}', String(deleted.length)),
            );
        }
    }
    focusFilesBrowserAnchor();
}

// ===== DELETE file =====
async function deleteFile(path, triggerEl = null) {
    if (!isFileDeleteSupported() || filesState.listActionsDisabled) {
        return;
    }

    const restoreFocusSelector = `[data-file-action="delete"][data-path="${encodeURIComponent(path)}"]`;
    const confirmed = await showConfirmDialog({
        title: t('deleteBtn'),
        message: t('deleteConfirm'),
        details: path,
        confirmLabel: t('deleteBtn'),
        triggerEl,
        restoreFocusSelector,
        initialFocus: 'cancel',
    });
    if (!confirmed) return;

    dismissFilesToast();
    announceLiveRegion('filesResponseAreaLive', `${t('deleteBtn')}: ${path}`);
    setExchangeInspector('files', {
        phase: 'sending',
        request: {
            transport: 'http',
            method: 'DELETE',
            path,
            headers: {},
            body: null,
        },
        response: {
            phase: 'sending',
            summaryText: `${t('deleteBtn')}: ${path}`,
            startLine: `DELETE ${path}`,
            body: createExchangeTextBody(`${t('deleteBtn')}: ${path}`),
        },
    });

    try {
        const response = await sendCustomRequest(
            'DELETE',
            SERVER_URL + encodeFileRequestPath(path),
        );
        const text = await response.text();
        let result = null;
        try {
            result = JSON.parse(text);
        } catch (error) {
            result = null;
        }

        if (response.ok && getCanonicalDeletedFile(result)) {
            const summary = `${t('deleteSuccess')}: ${path}`;
            announceLiveRegion('filesResponseAreaLive', summary);
            setExchangeInspector('files', {
                phase: 'complete',
                request: {
                    transport: 'http',
                    method: 'DELETE',
                    path,
                    headers: {},
                    body: null,
                },
                response: {
                    transport: 'http',
                    method: 'DELETE',
                    path,
                    phase: 'complete',
                    summaryText: summary,
                    startLine: `DELETE ${path}\n200 OK`,
                    status: 200,
                    statusText: 'OK',
                    headers: response.headers,
                    body: createExchangeTextBody(`${summary}\n\n${JSON.stringify(result, null, 2)}`, { contentType: 'application/json' }),
                },
            });
            await browseDirectory({ preserveActionSummary: true });
            focusFilesBrowserAnchor();
            return;
        }

        const message = getCanonicalResponseErrorMessage(response, result, text);
        setExchangeInspector('files', {
            phase: 'error',
            request: {
                transport: 'http',
                method: 'DELETE',
                path,
                headers: {},
                body: null,
            },
            response: {
                transport: 'http',
                method: 'DELETE',
                path,
                phase: 'error',
                summaryText: `${t('deleteError')}: ${message}`,
                startLine: `DELETE ${path}\n${t('error')}`,
                status: response.status,
                statusText: response.statusText || t('error'),
                headers: response.headers,
                body: createExchangeTextBody(message),
            },
        });
        await showNoticeDialog({
            title: t('deleteError'),
            message,
            details: path,
            triggerEl,
        });
    } catch (e) {
        setExchangeInspector('files', {
            phase: 'error',
            request: {
                transport: 'http',
                method: 'DELETE',
                path,
                headers: {},
                body: null,
            },
            response: {
                transport: 'http',
                method: 'DELETE',
                path,
                phase: 'error',
                summaryText: `${t('deleteError')}: ${e.message}`,
                startLine: `DELETE ${path}\n${t('error')}`,
                body: createExchangeTextBody(e.message),
            },
        });
        await showNoticeDialog({
            title: t('deleteError'),
            message: e.message,
            details: path,
            triggerEl,
        });
    }
}
app.on(app.events.SERVER_METHODS_CHANGED, refreshFilesMethodAvailability);
app.on(app.events.LOCALE_CHANGED, () => {
    syncFilesToastCopy();
    updateSelectedUploadsButton();
    syncFilesListControls();
    if (filesState.browsePhase === 'loading') {
        const message = t('filesBrowseLoading').replace('{0}', filesState.activePath);
        setFilesBrowseStatus(message, { phase: 'loading', busy: true });
        renderFilesListMessage(message, 'loading');
        return;
    }
    if (filesState.browsePhase === 'error') {
        const message = t('filesBrowseInitialError');
        setFilesBrowseStatus(message, { phase: 'error', busy: false });
        renderFilesListMessage(message, 'error');
        return;
    }
    if (filesState.browsePhase === 'stale' && filesState.lastSuccessfulPath) {
        renderServerFiles(filesState.lastSuccessfulItems, filesState.lastSuccessfulPath, {
            phase: 'stale',
            totalItems: filesState.lastSuccessfulTotalItems,
        });
        setFilesBrowseStatus(
            t('filesBrowseStale').replace('{0}', filesState.lastSuccessfulPath),
            { phase: 'stale', busy: false }
        );
        return;
    }
    if (
        !filesState.lastSuccessfulPath ||
        filesState.browsePhase !== 'complete'
    ) {
        return;
    }
    renderServerFiles(filesState.lastSuccessfulItems, filesState.lastSuccessfulPath, {
        phase: filesState.lastSuccessfulItems.length ? 'complete' : 'empty',
        totalItems: filesState.lastSuccessfulTotalItems,
    });
    setFilesBrowseStatus(
        formatFilesBrowseSummary(filesState.lastSuccessfulPath, filesState.lastSuccessfulInfo),
        { phase: 'complete', busy: false }
    );
});
app.on(app.events.WORKSPACE_CHANGED, ({ workspace }) => {
    if (workspace !== 'files') {
        return;
    }
    setTimeout(() => {
        if (document.body?.dataset.activeMode === 'files') {
            void browseDirectory();
        }
    }, 100);
});

app.registerWorkflow('files', {
    commands: {
        browse: browseDirectory,
        'refresh-methods': refreshFilesMethodAvailability,
    },
    getState: () => ({
        selectedCount: filesState.selectedPaths.size,
        browseGeneration: filesState.browseGeneration,
        searchQuery: filesState.searchQuery,
        sortDirection: filesState.sortDirection,
        visibleItemCount: getVisibleServerFileItems().length,
    }),
});
})(window.XferryApp);
