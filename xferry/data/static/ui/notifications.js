(function initializeNotifications(app) {
    'use strict';

const {
    t,
    announceLiveRegion,
    focusElementWithoutScroll,
} = app.service('core');

const notificationRegion = document.getElementById('appNotificationRegion');
const notificationRecords = new Map();

function normalizeNotificationTone(value) {
    const tone = String(value || 'pending');
    return ['pending', 'success', 'error'].includes(tone) ? tone : 'pending';
}

function getNotificationIcon(tone) {
    if (tone === 'success') return '✓';
    if (tone === 'error') return '!';
    return '…';
}

function clearNotificationTimer(record) {
    if (record?.timer !== null) {
        window.clearTimeout(record.timer);
        record.timer = null;
    }
}

function scheduleNotificationDismiss(record, delay = record?.timeoutMs) {
    clearNotificationTimer(record);
    if (!record || !Number.isFinite(delay) || delay <= 0) {
        return;
    }
    record.timer = window.setTimeout(() => {
        if (record.toast.isConnected) {
            dismissNotification(record.id);
        }
    }, delay);
}

function syncNotificationDismissLabel(record) {
    const label = t('notificationDismiss');
    record.dismissButton.title = label;
    record.dismissButton.setAttribute('aria-label', label);
}

function announceNotification(record) {
    announceLiveRegion(
        record.tone === 'error' ? 'appNotificationAlert' : 'appNotificationLive',
        record.message,
    );
}

function applyNotificationOptions(record, options = {}) {
    if (options.origin !== undefined) {
        record.origin = options.origin || null;
    }
    if (options.message !== undefined) {
        record.message = String(options.message || '').trim();
    }
    if (options.tone !== undefined) {
        record.tone = normalizeNotificationTone(options.tone);
    }
    if (options.timeoutMs !== undefined) {
        record.timeoutMs = options.timeoutMs === null ? null : Number(options.timeoutMs);
    }

    record.toast.className = `app-notification app-notification--${record.tone}`;
    record.toast.dataset.tone = record.tone;
    record.icon.textContent = getNotificationIcon(record.tone);
    record.messageElement.textContent = record.message;
    syncNotificationDismissLabel(record);
    scheduleNotificationDismiss(record);
    announceNotification(record);
}

function dismissNotification(id, options = {}) {
    const record = notificationRecords.get(String(id || ''));
    if (!record) {
        return false;
    }

    const restoreFocus = options.restoreFocus === true;
    const notificationHadFocus = record.toast.contains(document.activeElement);
    clearNotificationTimer(record);
    record.toast.remove();
    notificationRecords.delete(record.id);
    if (restoreFocus && notificationHadFocus && record.origin) {
        focusElementWithoutScroll(record.origin);
    }
    return true;
}

function createNotificationRecord(id, origin = null) {
    const toast = document.createElement('div');
    toast.className = 'app-notification app-notification--pending';
    toast.dataset.appNotification = id;

    const icon = document.createElement('span');
    icon.className = 'app-notification__icon';
    icon.setAttribute('aria-hidden', 'true');

    const messageElement = document.createElement('p');
    messageElement.className = 'app-notification__message';
    messageElement.dataset.appNotificationMessage = '';

    const dismissButton = document.createElement('button');
    dismissButton.type = 'button';
    dismissButton.className = 'btn-ghost btn-icon app-notification__dismiss';
    dismissButton.dataset.appNotificationDismiss = '';
    dismissButton.textContent = '×';

    const record = {
        id,
        toast,
        icon,
        messageElement,
        dismissButton,
        origin,
        tone: 'pending',
        message: '',
        timeoutMs: null,
        timer: null,
    };

    dismissButton.addEventListener('click', () => {
        dismissNotification(id, { restoreFocus: true });
    });
    toast.addEventListener('mouseenter', () => clearNotificationTimer(record));
    toast.addEventListener('mouseleave', () => scheduleNotificationDismiss(record));
    toast.addEventListener('focusin', () => clearNotificationTimer(record));
    toast.addEventListener('focusout', event => {
        if (!toast.contains(event.relatedTarget)) {
            scheduleNotificationDismiss(record);
        }
    });
    toast.addEventListener('keydown', event => {
        if (event.key !== 'Escape') return;
        event.preventDefault();
        event.stopPropagation();
        dismissNotification(id, { restoreFocus: true });
    });

    toast.append(icon, messageElement, dismissButton);
    return record;
}

function showNotification(options = {}) {
    const id = String(options.id || '').trim();
    if (!id) {
        throw new TypeError('Notification id is required');
    }
    if (!notificationRegion) {
        announceLiveRegion(
            normalizeNotificationTone(options.tone) === 'error'
                ? 'appNotificationAlert'
                : 'appNotificationLive',
            options.message,
        );
        return id;
    }

    let record = notificationRecords.get(id);
    if (!record) {
        record = createNotificationRecord(id, options.origin || null);
        notificationRecords.set(id, record);
        notificationRegion.appendChild(record.toast);
    }
    applyNotificationOptions(record, options);
    return id;
}

function updateNotification(id, options = {}) {
    const notificationId = String(id || '').trim();
    const record = notificationRecords.get(notificationId);
    if (!record) {
        return false;
    }
    applyNotificationOptions(record, options);
    return notificationId;
}

function refreshNotificationLocale() {
    notificationRecords.forEach(syncNotificationDismissLabel);
}

app.on(app.events.LOCALE_CHANGED, refreshNotificationLocale);

app.registerService('notifications', {
    show: showNotification,
    update: updateNotification,
    dismiss: dismissNotification,
});
})(window.XferryApp);
