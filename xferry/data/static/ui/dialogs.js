(function initializeDialogs(app) {
    'use strict';

const {
    t,
    escapeHtml: esc,
} = app.service('core');

// ===== Shared app dialogs =====
let activeDialogId = null;
let activeDialogKeyHandler = null;
let activeDialogReturnFocusEl = null;
let activeDialogReturnFocusSelector = '';
let activeDialogResolve = null;
let activeDialogRestoreFocusOnConfirm = false;
let dialogFocusRestoreSeq = 0;
let activeDialogBackgroundState = [];
let activeDialogBodyOverflow = '';
let activeDialogBackgroundIsolated = false;

function getDialogFocusable(modal) {
    return Array.from(
        modal.querySelectorAll('button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])')
    ).filter(el => !el.disabled && el.offsetParent !== null);
}

function getActiveDialogElement() {
    return activeDialogId ? document.getElementById(activeDialogId) : null;
}

function canRestoreDialogFocus(target) {
    return Boolean(
        target
        && target.isConnected
        && !target.disabled
        && typeof target.focus === 'function'
    );
}

function resolveDialogFocusTarget(target, selector = '') {
    if (canRestoreDialogFocus(target)) {
        return target;
    }
    if (!selector) {
        return null;
    }
    const resolved = document.querySelector(selector);
    return canRestoreDialogFocus(resolved) ? resolved : null;
}

function restoreDialogFocus(target, selector = '') {
    const restoreSeq = ++dialogFocusRestoreSeq;

    const applyFocus = () => {
        if (restoreSeq !== dialogFocusRestoreSeq) {
            return true;
        }

        const focusTarget = resolveDialogFocusTarget(target, selector);
        if (!focusTarget) {
            return true;
        }

        focusTarget.focus({ preventScroll: true });
        return document.activeElement === focusTarget;
    };

    if (applyFocus()) {
        return;
    }

    // Some Chromium builds asynchronously retarget focus after the dialog subtree
    // is removed, so retry after the DOM settles and after a short fallback delay.
    const scheduleRetry = typeof requestAnimationFrame === 'function'
        ? requestAnimationFrame
        : (callback) => setTimeout(callback, 16);
    scheduleRetry(() => {
        if (applyFocus()) {
            return;
        }
        setTimeout(() => {
            applyFocus();
        }, 50);
    });
}

function isolateDialogFromBackground(modal) {
    activeDialogBodyOverflow = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    activeDialogBackgroundIsolated = true;
    activeDialogBackgroundState = Array.from(document.body.children)
        .filter(element => element !== modal && element instanceof HTMLElement)
        .map(element => ({
            element,
            wasInert: element.hasAttribute('inert'),
        }));
    activeDialogBackgroundState.forEach(({ element }) => {
        element.setAttribute('inert', '');
    });
}

function restoreDialogBackground() {
    if (!activeDialogBackgroundIsolated) {
        return;
    }
    activeDialogBackgroundState.forEach(({ element, wasInert }) => {
        if (element.isConnected && !wasInert) {
            element.removeAttribute('inert');
        }
    });
    activeDialogBackgroundState = [];
    document.body.style.overflow = activeDialogBodyOverflow;
    activeDialogBodyOverflow = '';
    activeDialogBackgroundIsolated = false;
}

function finishActiveDialog(result) {
    const modal = getActiveDialogElement();
    const resolve = activeDialogResolve;
    const focusTarget = (!result || activeDialogRestoreFocusOnConfirm) ? activeDialogReturnFocusEl : null;
    const focusSelector = (!result || activeDialogRestoreFocusOnConfirm) ? activeDialogReturnFocusSelector : '';

    if (activeDialogKeyHandler) {
        document.removeEventListener('keydown', activeDialogKeyHandler);
        activeDialogKeyHandler = null;
    }

    activeDialogId = null;
    activeDialogResolve = null;
    activeDialogReturnFocusEl = null;
    activeDialogReturnFocusSelector = '';
    activeDialogRestoreFocusOnConfirm = false;

    if (modal) {
        modal.remove();
    }

    restoreDialogBackground();

    restoreDialogFocus(focusTarget, focusSelector);

    if (resolve) {
        resolve(result);
    }
}

function closeActiveDialog() {
    finishActiveDialog(false);
}

function closeAppDialog() {
    closeActiveDialog();
}

function openManagedDialog({
    dialogId,
    markup,
    triggerEl = null,
    restoreFocusSelector = '',
    initialFocusSelector = '',
    restoreFocusOnConfirm = false,
    onAction = null,
    canDismiss = null,
}) {
    closeActiveDialog();
    dialogFocusRestoreSeq += 1;

    const activeElement = document.activeElement;
    activeDialogId = dialogId;
    activeDialogReturnFocusEl = triggerEl || (activeElement instanceof HTMLElement ? activeElement : null);
    activeDialogReturnFocusSelector = restoreFocusSelector;
    activeDialogRestoreFocusOnConfirm = restoreFocusOnConfirm;

    const modal = document.createElement('div');
    modal.id = dialogId;
    modal.innerHTML = markup;
    document.body.appendChild(modal);
    isolateDialogFromBackground(modal);

    const dismissAllowed = () => (
        typeof canDismiss !== 'function' || canDismiss(modal) !== false
    );

    modal.addEventListener('click', async (event) => {
        if (event.target === modal.querySelector('.modal-overlay')) {
            if (dismissAllowed()) {
                finishActiveDialog(false);
            }
            return;
        }

        const actionButton = event.target.closest('[data-dialog-action]');
        if (!actionButton) return;

        if (onAction) {
            const result = await onAction(actionButton.dataset.dialogAction || '', modal, actionButton);
            if (typeof result === 'boolean') {
                finishActiveDialog(result);
            }
            return;
        }

        finishActiveDialog(actionButton.dataset.dialogAction === 'confirm');
    });

    activeDialogKeyHandler = (event) => {
        if (event.key === 'Escape') {
            event.preventDefault();
            event.stopPropagation();
            if (dismissAllowed()) {
                finishActiveDialog(false);
            }
            return;
        }

        if (event.key !== 'Tab') {
            return;
        }

        const focusable = getDialogFocusable(modal);
        if (focusable.length === 0) {
            return;
        }

        const first = focusable[0];
        const last = focusable[focusable.length - 1];

        if (event.shiftKey && document.activeElement === first) {
            event.preventDefault();
            last.focus();
        } else if (!event.shiftKey && document.activeElement === last) {
            event.preventDefault();
            first.focus();
        }
    };
    document.addEventListener('keydown', activeDialogKeyHandler);

    const initialFocusEl = (initialFocusSelector && modal.querySelector(initialFocusSelector)) || getDialogFocusable(modal)[0];
    if (initialFocusEl) {
        initialFocusEl.focus();
    }

    return modal;
}

function showAppDialog({
    title,
    message,
    details = '',
    role = 'alertdialog',
    confirmLabel,
    cancelLabel = t('smuggleCancel'),
    confirmClassName = 'btn-info',
    triggerEl = null,
    restoreFocusSelector = '',
    showCancel = true,
    initialFocus = 'confirm',
    restoreFocusOnConfirm = false,
}) {
    openManagedDialog({
        dialogId: 'appDialog',
        triggerEl,
        restoreFocusSelector,
        initialFocusSelector: initialFocus === 'cancel' && showCancel
            ? '[data-dialog-action="cancel"]'
            : '[data-dialog-action="confirm"]',
        restoreFocusOnConfirm,
        markup: `
        <div class="modal-overlay">
            <div class="modal-content app-dialog" role="${esc(role)}" aria-modal="true" aria-labelledby="appDialogTitle" aria-describedby="appDialogMessage${details ? ' appDialogDetails' : ''}">
                <div class="app-dialog__header">
                    <h3 class="app-dialog__title" id="appDialogTitle">${esc(title)}</h3>
                </div>
                <div class="app-dialog__body">
                    <p class="app-dialog__message" id="appDialogMessage">${esc(message)}</p>
                    ${details ? `<div class="app-dialog__details" id="appDialogDetails">${esc(details)}</div>` : ''}
                </div>
                <div class="modal-actions app-dialog__actions">
                    ${showCancel ? `<button type="button" class="btn-ghost" data-dialog-action="cancel">${esc(cancelLabel)}</button>` : ''}
                    <button type="button" class="${esc(confirmClassName)}" data-dialog-action="confirm">${esc(confirmLabel)}</button>
                </div>
            </div>
        </div>
    `,
    });

    return new Promise(resolve => {
        activeDialogResolve = resolve;
    });
}

function showConfirmDialog(options) {
    return showAppDialog({
        title: options.title,
        message: options.message,
        details: options.details,
        role: 'alertdialog',
        confirmLabel: options.confirmLabel,
        cancelLabel: options.cancelLabel || t('smuggleCancel'),
        confirmClassName: options.confirmClassName || 'btn-danger',
        triggerEl: options.triggerEl,
        restoreFocusSelector: options.restoreFocusSelector || '',
        showCancel: true,
        initialFocus: options.initialFocus || 'cancel',
        restoreFocusOnConfirm: Boolean(options.restoreFocusOnConfirm),
    });
}

function showNoticeDialog(options) {
    return showAppDialog({
        title: options.title,
        message: options.message,
        details: options.details,
        role: 'dialog',
        confirmLabel: options.confirmLabel || t('okBtn'),
        confirmClassName: options.confirmClassName || 'btn-info',
        triggerEl: options.triggerEl,
        restoreFocusSelector: options.restoreFocusSelector || '',
        showCancel: false,
        initialFocus: 'confirm',
        restoreFocusOnConfirm: true,
    });
}

app.registerService('dialogs', {
    open: openManagedDialog,
    confirm: showConfirmDialog,
    notice: showNoticeDialog,
});
})(window.XferryApp);
