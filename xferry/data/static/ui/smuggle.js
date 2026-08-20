(function initializeSmuggle(app) {
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
    notice: showNoticeDialog,
} = app.service('dialogs');
const {
    createTextBody: createExchangeTextBody,
    setInspector: setExchangeInspector,
} = app.service('inspector');

function sendCustomRequest(...args) {
    return app.service('http').request(...args);
}

function getCanonicalInfoPayload(payload) {
    if (
        !payload
        || typeof payload !== 'object'
        || Array.isArray(payload)
        || !payload.entry
        || typeof payload.entry !== 'object'
        || Array.isArray(payload.entry)
        || payload.entry.kind !== 'file'
        || typeof payload.entry.name !== 'string'
        || !payload.entry.name
        || typeof payload.entry.path !== 'string'
        || !payload.entry.path
        || !Number.isInteger(payload.entry.size_bytes)
        || payload.entry.size_bytes < 0
    ) {
        return null;
    }
    return payload;
}

function getFileInspection(entry) {
    const inspection = entry?.inspection;
    return inspection && typeof inspection === 'object' && !Array.isArray(inspection)
        ? inspection
        : null;
}

// ===== HTML Smuggling =====
const SMUGGLE_FIELD_LIMIT_KEYS = [
    'download_name',
    'download_ext',
    'title',
    'message',
    'cta_label',
    'delay_ms',
    'mime_type',
    'trigger_event',
];
const SMUGGLE_DEFAULT_STRING_KEYS = [
    'mode',
    'preset',
    'locale',
    'encryption',
    'payload_encoding',
    'trigger_method',
    'trigger_event',
    'output_format',
    'download_variant',
    'page_template',
    'mime_type',
];
const SMUGGLE_DEFAULT_BOOLEAN_KEYS = ['show_notice', 'null_byte'];
const SMUGGLE_MODE_FIELD_KEYS = ['simple_only', 'constructor_only'];
const SMUGGLE_SCHEMA_V1_FIXED_ARRAYS = {
    modes: ['simple', 'constructor'],
    encryption_modes: ['none', 'xor', 'aes'],
    simple_only: ['cta_label', 'delay_ms', 'preset'],
    constructor_only: [
        'download_variant',
        'mime_type',
        'null_byte',
        'output_format',
        'page_template',
        'payload_encoding',
        'trigger_event',
        'trigger_method',
    ],
};
const SMUGGLE_VOCABULARY_KEYS = [
    'extensions',
    'mime_presets',
    'presets',
    'locales',
    'encryption_modes',
    'modes',
    'payload_encodings',
    'output_formats',
    'page_templates',
    'download_variants',
    'custom_trigger_methods',
];
const SMUGGLE_CAPABILITY_FLAG_KEYS = [
    'one_shot',
    'constructor',
    'xor_obfuscation',
    'aes_gcm',
    'source_cap_enforced',
    'custom_extension',
    'custom_mime_type',
    'custom_trigger_event',
    'searchable_options',
];
const activeSmuggleModals = new Set();
const smuggleSourceInfoCache = new Map();
let smuggleState = {
    enabled: false,
    status: 'pending',
    reason: '',
    capabilities: null,
};

function isPlainSmuggleObject(value) {
    if (!value || typeof value !== 'object' || Array.isArray(value)) {
        return false;
    }
    const prototype = Object.getPrototypeOf(value);
    return prototype === Object.prototype || prototype === null;
}

function isNonemptyString(value) {
    return typeof value === 'string' && value.length > 0;
}

function isNonnegativeInteger(value) {
    return Number.isInteger(value) && value >= 0;
}

function isNonnegativeNumber(value) {
    return typeof value === 'number' && Number.isFinite(value) && value >= 0;
}

function isStringArray(value, { nonempty = false } = {}) {
    return Array.isArray(value)
        && (!nonempty || value.length > 0)
        && value.every(isNonemptyString);
}

function isExactSmuggleSchemaV1Array(value, expected) {
    return Array.isArray(value)
        && value.length === expected.length
        && value.every((entry, index) => entry === expected[index]);
}

function validateSmuggleSchemaV1FixedInvariants(raw) {
    if (!isExactSmuggleSchemaV1Array(raw.modes, SMUGGLE_SCHEMA_V1_FIXED_ARRAYS.modes)) {
        return 'schema-v1 modes must use the documented canonical order';
    }
    if (
        !isExactSmuggleSchemaV1Array(
            raw.encryption_modes,
            SMUGGLE_SCHEMA_V1_FIXED_ARRAYS.encryption_modes,
        )
    ) {
        return 'schema-v1 encryption_modes must use the documented canonical order';
    }
    if (raw.defaults?.payload_encoding !== 'base64') {
        return 'schema-v1 defaults.payload_encoding must be base64';
    }

    const simpleOnly = raw.mode_fields?.simple_only;
    const constructorOnly = raw.mode_fields?.constructor_only;
    if (!isExactSmuggleSchemaV1Array(simpleOnly, SMUGGLE_SCHEMA_V1_FIXED_ARRAYS.simple_only)) {
        return 'schema-v1 mode_fields.simple_only must use the documented canonical order';
    }
    if (
        !isExactSmuggleSchemaV1Array(
            constructorOnly,
            SMUGGLE_SCHEMA_V1_FIXED_ARRAYS.constructor_only,
        )
    ) {
        return 'schema-v1 mode_fields.constructor_only must use the documented canonical order';
    }

    const documentedFields = [
        ...SMUGGLE_SCHEMA_V1_FIXED_ARRAYS.simple_only,
        ...SMUGGLE_SCHEMA_V1_FIXED_ARRAYS.constructor_only,
    ];
    const actualFields = [...simpleOnly, ...constructorOnly];
    if (
        new Set(simpleOnly).size !== simpleOnly.length
        || new Set(constructorOnly).size !== constructorOnly.length
        || new Set(actualFields).size !== actualFields.length
        || actualFields.length !== documentedFields.length
        || actualFields.some((field, index) => field !== documentedFields[index])
    ) {
        return 'schema-v1 mode fields must be the documented non-overlapping partition';
    }
    return '';
}

function cloneSmuggleValue(value) {
    if (Array.isArray(value)) {
        return value.map(cloneSmuggleValue);
    }
    if (isPlainSmuggleObject(value)) {
        return Object.fromEntries(
            Object.entries(value).map(([key, entry]) => [key, cloneSmuggleValue(entry)])
        );
    }
    return value;
}

function deepFreezeSmuggleValue(value) {
    if (!value || typeof value !== 'object' || Object.isFrozen(value)) {
        return value;
    }
    Object.values(value).forEach(deepFreezeSmuggleValue);
    return Object.freeze(value);
}

function validateSmuggleCapabilities(raw) {
    const fail = reason => ({ ok: false, reason });
    if (!isPlainSmuggleObject(raw)) {
        return fail('root must be an object');
    }
    if (raw.schema_version !== 1) {
        return fail('schema_version must be 1');
    }
    const schemaV1InvariantFailure = validateSmuggleSchemaV1FixedInvariants(raw);
    if (schemaV1InvariantFailure) {
        return fail(schemaV1InvariantFailure);
    }
    if (!isNonnegativeInteger(raw.source_max_bytes)) {
        return fail('source_max_bytes must be a nonnegative integer');
    }
    if (!isPlainSmuggleObject(raw.field_limits)) {
        return fail('field_limits must be an object');
    }
    for (const key of SMUGGLE_FIELD_LIMIT_KEYS) {
        if (!isNonnegativeInteger(raw.field_limits[key])) {
            return fail(`field_limits.${key} must be a nonnegative integer`);
        }
    }

    if (!isPlainSmuggleObject(raw.defaults)) {
        return fail('defaults must be an object');
    }
    for (const key of SMUGGLE_DEFAULT_STRING_KEYS) {
        if (!isNonemptyString(raw.defaults[key])) {
            return fail(`defaults.${key} must be a nonempty string`);
        }
    }
    if (!isNonnegativeInteger(raw.defaults.delay_ms)) {
        return fail('defaults.delay_ms must be a nonnegative integer');
    }
    for (const key of SMUGGLE_DEFAULT_BOOLEAN_KEYS) {
        if (typeof raw.defaults[key] !== 'boolean') {
            return fail(`defaults.${key} must be boolean`);
        }
    }

    if (!isPlainSmuggleObject(raw.mode_fields)) {
        return fail('mode_fields must be an object');
    }
    for (const key of SMUGGLE_MODE_FIELD_KEYS) {
        if (!isStringArray(raw.mode_fields[key])) {
            return fail(`mode_fields.${key} must be a string array`);
        }
    }

    for (const key of SMUGGLE_VOCABULARY_KEYS) {
        if (!isStringArray(raw[key], { nonempty: true })) {
            return fail(`${key} must be a nonempty string array`);
        }
    }

    if (!isPlainSmuggleObject(raw.mime_by_extension) || Object.keys(raw.mime_by_extension).length === 0) {
        return fail('mime_by_extension must be a nonempty object');
    }
    if (Object.entries(raw.mime_by_extension).some(([extension, mime]) => (
        !isNonemptyString(extension) || !isNonemptyString(mime)
    ))) {
        return fail('mime_by_extension must map nonempty strings to nonempty strings');
    }

    if (!isPlainSmuggleObject(raw.trigger_events) || Object.keys(raw.trigger_events).length === 0) {
        return fail('trigger_events must be a nonempty object');
    }
    for (const [method, events] of Object.entries(raw.trigger_events)) {
        if (!isNonemptyString(method) || !isStringArray(events, { nonempty: true })) {
            return fail('trigger_events must map nonempty strings to nonempty string arrays');
        }
    }

    if (!isPlainSmuggleObject(raw.temp_policy)) {
        return fail('temp_policy must be an object');
    }
    if (
        raw.temp_policy.max_age_seconds !== null
        && !isNonnegativeNumber(raw.temp_policy.max_age_seconds)
    ) {
        return fail('temp_policy.max_age_seconds must be null or a nonnegative number');
    }
    for (const key of ['max_file_count', 'max_total_bytes']) {
        if (raw.temp_policy[key] !== null && !isNonnegativeInteger(raw.temp_policy[key])) {
            return fail(`temp_policy.${key} must be null or a nonnegative integer`);
        }
    }

    if (!isPlainSmuggleObject(raw.caps)) {
        return fail('caps must be an object');
    }
    for (const key of SMUGGLE_CAPABILITY_FLAG_KEYS) {
        if (typeof raw.caps[key] !== 'boolean') {
            return fail(`caps.${key} must be boolean`);
        }
    }

    const memberships = [
        ['mode', 'modes'],
        ['preset', 'presets'],
        ['locale', 'locales'],
        ['encryption', 'encryption_modes'],
        ['payload_encoding', 'payload_encodings'],
        ['output_format', 'output_formats'],
        ['download_variant', 'download_variants'],
        ['page_template', 'page_templates'],
        ['mime_type', 'mime_presets'],
    ];
    for (const [defaultKey, vocabularyKey] of memberships) {
        if (!raw[vocabularyKey].includes(raw.defaults[defaultKey])) {
            return fail(`defaults.${defaultKey} is outside ${vocabularyKey}`);
        }
    }
    const defaultEvents = raw.trigger_events[raw.defaults.trigger_method];
    if (!defaultEvents || !defaultEvents.includes(raw.defaults.trigger_event)) {
        return fail('default trigger method/event is outside trigger_events');
    }
    if (
        raw.custom_trigger_methods.some(method => (
            !Object.prototype.hasOwnProperty.call(raw.trigger_events, method)
        ))
    ) {
        return fail('custom_trigger_methods must be a subset of trigger_events');
    }
    if (raw.defaults.delay_ms > raw.field_limits.delay_ms) {
        return fail('defaults.delay_ms exceeds field_limits.delay_ms');
    }

    const snapshot = deepFreezeSmuggleValue(cloneSmuggleValue(raw));
    return { ok: true, capabilities: snapshot };
}

function getSmuggleUnavailableReason(status) {
    if (status === 'pending') {
        return t('smuggleCapabilitiesPending');
    }
    if (status === 'unavailable') {
        return t('smuggleCapabilitiesUnavailable');
    }
    return t('smuggleCapabilitiesInvalid');
}

function invalidateOpenSmuggleDialogs(reason) {
    for (const modal of [...activeSmuggleModals]) {
        if (!modal?.isConnected) {
            activeSmuggleModals.delete(modal);
            continue;
        }
        modal.__smuggleRequestSeq = (modal.__smuggleRequestSeq || 0) + 1;
        modal.dataset.smugglePhase = 'invalid';
        modal.querySelector('.smuggle-dialog')?.setAttribute('aria-busy', 'false');
        modal.querySelectorAll('[data-smuggle-edit-control], #smuggleSubmitBtn').forEach(control => {
            control.disabled = true;
        });
        modal.querySelectorAll('[data-dialog-action="cancel"], [data-dialog-action="close"]').forEach(control => {
            control.disabled = false;
        });
        const submitButton = modal.querySelector('#smuggleSubmitBtn');
        if (submitButton) {
            submitButton.textContent = t('smuggleGenerate');
        }
        setSmuggleInlineStatus(modal, reason, 'error');
        focusElementWithoutScroll(modal.querySelector('[data-dialog-action="close"]'));
    }
}

function refreshSmuggleState() {
    const coreState = typeof getCoreState === 'function' ? getCoreState() : {};
    const discoveryStatus = coreState?.serverDiscoveryStatus;
    let nextState;
    if (discoveryStatus === 'pending') {
        nextState = {
            enabled: false,
            status: 'pending',
            reason: getSmuggleUnavailableReason('pending'),
            capabilities: null,
        };
    } else if (discoveryStatus !== 'ready') {
        nextState = {
            enabled: false,
            status: 'unavailable',
            reason: getSmuggleUnavailableReason('unavailable'),
            capabilities: null,
        };
    } else if (
        (typeof isServerMethodSupported === 'function' && !isServerMethodSupported('SMUGGLE'))
        || (typeof isServerMethodInGroup === 'function' && !isServerMethodInGroup('SMUGGLE', 'files'))
    ) {
        nextState = {
            enabled: false,
            status: 'unavailable',
            reason: t('smuggleMethodUnavailable'),
            capabilities: null,
        };
    } else {
        const validated = validateSmuggleCapabilities(coreState?.smuggleCapabilities);
        nextState = validated.ok
            ? {
                enabled: true,
                status: 'valid',
                reason: '',
                capabilities: validated.capabilities,
            }
            : {
                enabled: false,
                status: 'invalid',
                reason: `${t('smuggleCapabilitiesInvalid')} ${validated.reason}`.trim(),
                capabilities: null,
            };
    }
    const wasEnabled = smuggleState.enabled;
    smuggleState = Object.freeze(nextState);
    if (wasEnabled && !nextState.enabled) {
        invalidateOpenSmuggleDialogs(nextState.reason);
    }
    return smuggleState;
}

function requireValidSmuggleCapabilities() {
    const state = refreshSmuggleState();
    if (!state.enabled || !state.capabilities) {
        throw new Error(state.reason || t('smuggleCapabilitiesInvalid'));
    }
    return state.capabilities;
}

function getSmuggleCapabilities() {
    return requireValidSmuggleCapabilities();
}

function getSmuggleCapabilityFlag(key) {
    return getSmuggleCapabilities().caps[key];
}

function getSmuggleFieldLimit(field) {
    return getSmuggleCapabilities().field_limits[field];
}

function getSmuggleSourceMaxBytes() {
    return getSmuggleCapabilities().source_max_bytes;
}

function getSmuggleDefaultValue(key) {
    return getSmuggleCapabilities().defaults[key];
}
const SMUGGLE_COPY = {
    ru: {
        sourceFilename: 'Имя',
        sourceSize: 'Размер',
        sourceMime: 'MIME',
        sourcePath: 'uploads path',
        sourceCap: 'Лимит источника',
        sourceSizeUnknown: 'не загружен',
        sourceMimeUnknown: 'неизвестен',
        sourceWithinCap: 'ок, не выше {0}',
        sourceOverCap: 'выше лимита {0}',
        sourceCapPending: 'лимит {0}; размер уточняется',
        sourceCapUnknown: 'лимит не получен от сервера',
        dialogHint: 'Создаст одноразовую страницу для скачивания «{0}».',
        bytesWarning: 'Выбор расширения не преобразует содержимое файла.',
        artifactSettings: 'Файл для скачивания',
        extractedBaseName: 'Имя файла',
        extractedExtension: 'Расширение',
        normalizedName: 'Скачается как',
        behaviorTitle: 'Поведение страницы',
        behaviorChoiceLabel: 'После открытия',
        settingsMode: 'Режим',
        constructorModeHint: 'Конструктор включает закрытые варианты кодирования, запуска и выдачи. Выбранное шифрование применяется в обоих режимах.',
        encryptionLabel: 'Шифрование артефакта',
        constructorSection: 'Параметры конструктора',
        payloadEncoding: 'Кодирование payload',
        triggerMethod: 'Элемент запуска',
        triggerEvent: 'Событие запуска',
        outerArtifactFormat: 'Формат внешнего HTML/SVG-артефакта',
        downloadVariant: 'Способ выдачи браузеру',
        pageTemplate: 'Шаблон страницы',
        extractedMime: 'MIME извлекаемого файла',
        nullByteBeforeArtifact: 'NUL перед HTML/SVG-артефактом',
        textSection: 'Настроить страницу',
        titleLabel: 'Заголовок',
        messageLabel: 'Сообщение',
        ctaLabel: 'Текст кнопки',
        delayLabel: 'Задержка автостарта, мс',
        noticeLabel: 'Показать пометку внутренней проверки',
        advancedSettingsTitle: 'Расширенные настройки',
        sourceDetailsTitle: 'Исходный файл',
        copy: 'Копировать',
        copied: 'Скопировано.',
        copyFailed: 'Не удалось скопировать.',
        effectivePreset: 'Эффективный preset',
        requestedPreset: 'Выбранный preset',
        effectiveMode: 'Эффективный режим',
        active: 'активна',
        inactive: 'выключена',
        temporarilyInactive: 'временно не действует',
        yes: 'Да',
        no: 'Нет',
        submitting: 'Создаём страницу...',
        editSettings: 'Изменить настройки',
        openRun: 'Открыть',
        downloadHtml: 'Скачать страницу',
        copyPassword: 'Копировать пароль',
        successTitle: 'Готово',
        resultDownloadLabel: 'Браузер скачает',
        resultDetailsTitle: 'Технические детали результата',
        oneShotWarning: 'Ссылка одноразовая: её может открыть браузер или сканер до вас. Повторная генерация создаст ещё одну действующую ссылку.',
        artifactFilename: 'Имя внешнего артефакта',
        embeddedFilename: 'Имя извлекаемого файла',
        filenameHandling: 'Применение имени браузером',
        filenameApplied: 'артефакт задаёт имя',
        filenameBrowserChosen: 'имя выбирает браузер',
        generatedUrl: 'Одноразовый URL',
        resultMetadata: 'Метаданные результата',
        locale: 'Локаль',
        noticeShown: 'Пометка показана',
        passwordManual: 'пароль + ручное скачивание',
        constructor: 'constructor',
        simple: 'обычный (simple)',
        manualPasswordForm: 'ручная форма с паролем',
        error400: 'Настройки SMUGGLE отклонены. Проверьте поле и допустимые токены.',
        error404: 'Исходный файл не найден или уже недоступен в uploads.',
        error413: 'Файл больше лимита SMUGGLE.',
        error507: 'Недостаточно временного хранилища для одноразового артефакта.',
        errorNetwork: 'Сеть или сервер недоступны. Настройки сохранены в форме.',
        errorField: 'Поле',
        errorCode: 'Код',
        retryAfterEdit: 'Исправьте настройки и повторите генерацию.',
        templateArchiveWarning: 'Этот шаблон показывает нейтральные инструкции архива; он не превращает файл в RAR/ZIP.',
        locAssignFilenameWarning: 'Location assign применяет выбранный MIME к data: URL, но имя при сохранении выбирает браузер.',
        searchOptions: 'Начните вводить для поиска',
        noMatchingOptions: 'Нет подходящих вариантов',
        useCustomValue: 'Использовать своё значение: {0}',
        constrainedOptionError: 'Выберите один из предложенных вариантов.',
        extensionFormatError: 'Расширение: до {0} символов, без пути; допустим составной суффикс, например tar.gz.',
        mimeFormatError: 'Введите непустой MIME без управляющих символов (до {0} символов).',
        triggerEventFormatError: 'Введите безопасный токен события длиной до {0} символов; префикс on добавится автоматически.',
        customTriggerWarning: 'Своё событие привязано только к выбранному элементу и естественному событию браузера/пользователя. Оно может не сработать; синтетическая отправка не выполняется.',
    },
    en: {
        sourceFilename: 'Name',
        sourceSize: 'Size',
        sourceMime: 'MIME',
        sourcePath: 'uploads path',
        sourceCap: 'Source cap',
        sourceSizeUnknown: 'not loaded',
        sourceMimeUnknown: 'unknown',
        sourceWithinCap: 'ok, not above {0}',
        sourceOverCap: 'above limit {0}',
        sourceCapPending: 'limit {0}; checking size',
        sourceCapUnknown: 'server cap unavailable',
        dialogHint: 'Creates a one-shot page that downloads “{0}”.',
        bytesWarning: 'Changing the extension does not convert the file contents.',
        artifactSettings: 'Downloaded file',
        extractedBaseName: 'File name',
        extractedExtension: 'Extension',
        normalizedName: 'Downloads as',
        behaviorTitle: 'Page behavior',
        behaviorChoiceLabel: 'After opening',
        settingsMode: 'Mode',
        constructorModeHint: 'Constructor enables closed encoding, trigger, and delivery variants. The selected encryption applies in both modes.',
        encryptionLabel: 'Artifact encryption',
        constructorSection: 'Constructor settings',
        payloadEncoding: 'Payload encoding',
        triggerMethod: 'Trigger element',
        triggerEvent: 'Trigger event',
        outerArtifactFormat: 'Outer HTML/SVG artifact format',
        downloadVariant: 'Browser delivery variant',
        pageTemplate: 'Page template',
        extractedMime: 'Extracted file MIME',
        nullByteBeforeArtifact: 'NUL before HTML/SVG artifact',
        textSection: 'Customize page',
        titleLabel: 'Title',
        messageLabel: 'Message',
        ctaLabel: 'Button text',
        delayLabel: 'Auto-start delay, ms',
        noticeLabel: 'Show internal-test notice',
        advancedSettingsTitle: 'Advanced settings',
        sourceDetailsTitle: 'Source file',
        copy: 'Copy',
        copied: 'Copied.',
        copyFailed: 'Could not copy.',
        effectivePreset: 'Effective preset',
        requestedPreset: 'Selected preset',
        effectiveMode: 'Effective mode',
        active: 'active',
        inactive: 'off',
        temporarilyInactive: 'temporarily inactive',
        yes: 'Yes',
        no: 'No',
        submitting: 'Creating page...',
        editSettings: 'Edit settings',
        openRun: 'Open',
        downloadHtml: 'Download page',
        copyPassword: 'Copy password',
        successTitle: 'Ready',
        resultDownloadLabel: 'Browser download',
        resultDetailsTitle: 'Technical result details',
        oneShotWarning: 'This link is one-shot: a browser or scanner can open it before you do. Generating again creates another active link.',
        artifactFilename: 'Outer artifact filename',
        embeddedFilename: 'Extracted filename',
        filenameHandling: 'Browser filename handling',
        filenameApplied: 'artifact sets the name',
        filenameBrowserChosen: 'browser chooses the name',
        generatedUrl: 'One-shot URL',
        resultMetadata: 'Result metadata',
        locale: 'Locale',
        noticeShown: 'Notice shown',
        passwordManual: 'password + manual download',
        constructor: 'constructor',
        simple: 'simple',
        manualPasswordForm: 'manual password form',
        error400: 'SMUGGLE settings were rejected. Check the field and allowed tokens.',
        error404: 'The source file was not found or is no longer available in uploads.',
        error413: 'The file is larger than the SMUGGLE limit.',
        error507: 'There is not enough temporary storage for the one-shot artifact.',
        errorNetwork: 'Network or server is unavailable. The form values were kept.',
        errorField: 'Field',
        errorCode: 'Code',
        retryAfterEdit: 'Edit the settings and generate again.',
        templateArchiveWarning: 'This template shows neutral archive instructions; it does not convert the file to RAR/ZIP.',
        locAssignFilenameWarning: 'Location assign applies the selected MIME to the data: URL, but the browser chooses any saved filename.',
        searchOptions: 'Type to search options',
        noMatchingOptions: 'No matching options',
        useCustomValue: 'Use custom value: {0}',
        constrainedOptionError: 'Choose one of the advertised options.',
        extensionFormatError: 'Extension: up to {0} characters, no path; compound suffixes such as tar.gz are allowed.',
        mimeFormatError: 'Enter a non-empty MIME value without control characters (up to {0} characters).',
        triggerEventFormatError: 'Enter a safe event token up to {0} characters; the on prefix is added automatically.',
        customTriggerWarning: 'A custom event is bound only to the selected element and a natural browser/user event. It may not fire; no synthetic dispatch is performed.',
    },
};

const SMUGGLE_OPTION_COPY = {
    encryption: {
        none: {
            ru: ['Без шифрования', 'Артефакт скачивает исходные байты без пароля.'],
            en: ['No encryption', 'The artifact downloads the original bytes without a password.'],
        },
        xor: {
            ru: ['XOR-совместимость', 'Совместимая XOR-обфускация с паролем; это не криптографическая защита.'],
            en: ['XOR compatibility', 'Password-based XOR obfuscation for compatibility; this is not cryptographic protection.'],
        },
        aes: {
            ru: ['AES-256-GCM', 'Аутентифицированное шифрование AES-256-GCM с паролем.'],
            en: ['AES-256-GCM', 'Password-based authenticated AES-256-GCM encryption.'],
        },
    },
    payloadEncoding: {
        base64: ['Base64', 'Standard Base64 text payload.'],
        base64url: {
            ru: ['Base64 URL-safe', 'URL-safe Base64 payload без неоднозначности алфавита.'],
            en: ['Base64 URL-safe', 'URL-safe Base64 text payload without alphabet ambiguity.'],
        },
        base32: {
            ru: ['Base32', 'Base32 payload, восстанавливаемый внутри страницы.'],
            en: ['Base32', 'Base32 text payload reconstructed in the page.'],
        },
        percent: {
            ru: ['Percent encoding', 'Байты в percent-encoded виде, восстанавливаемые внутри страницы.'],
            en: ['Percent encoded', 'Percent-encoded bytes reconstructed in the page.'],
        },
        reverse: ['Reverse Base64', 'Base64 payload stored in reverse order.'],
        xor: ['XOR payload bytes', 'Payload bytes are XOR-transformed inside the generated page.'],
        hex: ['Hex', 'Payload is stored as hexadecimal text.'],
        split: ['Split chunks', 'Payload is split into several chunks before reconstruction.'],
        attrs: ['Data attributes', 'Payload is carried in element attributes.'],
        charcode: ['Character codes', 'Payload is reconstructed from numeric character codes.'],
    },
    outputFormat: {
        html: ['HTML artifact', 'Creates a .html outer artifact.'],
        htm: ['HTML short extension', 'Creates a .htm outer artifact.'],
        shtml: ['Server-parsed HTML extension', 'Creates a .shtml-looking outer artifact.'],
        shtm: ['Server-parsed short extension', 'Creates a .shtm-looking outer artifact.'],
        xhtml: ['XHTML artifact', 'Creates a .xhtml outer artifact.'],
        xht: ['XHTML short extension', 'Creates a .xht outer artifact.'],
        xhtm: ['XHTML alternate extension', 'Creates a .xhtm outer artifact.'],
        xml: ['XML-looking artifact', 'Creates a .xml outer artifact.'],
        svg: ['SVG artifact', 'Creates a .svg outer artifact.'],
    },
    pageTemplate: {
        default: ['Internal page', 'Minimal controlled-test page.'],
        minimal: {
            ru: ['Минимальная страница', 'Использует минимальное нейтральное оформление.'],
            en: ['Minimal page', 'Uses the smallest neutral page chrome.'],
        },
        corporate: ['Corporate notice', 'Business-style page chrome.'],
        drive: ['Drive-style card', 'Cloud-drive-style download card.'],
        'npf-zip-archive-help': ['Archive instructions, ZIP wording', 'Archive-help copy; bytes are unchanged.'],
    },
    downloadVariant: {
        'blob-anchor': ['Blob + anchor', 'Creates a Blob URL and clicks a download link.'],
        'data-uri': ['Data URI', 'Uses a data: URL for the download handoff.'],
        'iframe-blob': ['Hidden iframe + Blob', 'Routes a Blob URL through an iframe.'],
        filereader: ['FileReader', 'Builds the handoff through FileReader.'],
        'fetch-blob': ['Fetch to Blob URL', 'Fetches a generated Blob URL before download.'],
        'window-open': ['Window open', 'Opens the generated URL in a new browsing context.'],
        'loc-assign': ['Location assign', 'Assigns browser location to the generated object.'],
        'form-post': ['Form POST', 'Submits a form-style handoff.'],
        'timeout-blob': ['setTimeout + Blob', 'Starts the Blob handoff from a timer.'],
        'promise-blob': ['Promise + Blob', 'Starts the Blob handoff from a Promise turn.'],
        'raf-blob': ['requestAnimationFrame + Blob', 'Starts the Blob handoff from animation frame timing.'],
        'microtask-blob': ['Microtask + Blob', 'Starts the Blob handoff from a microtask.'],
        'observer-blob': ['MutationObserver + Blob', 'Starts the Blob handoff through observer timing.'],
        'response-blob': {
            ru: ['Response + Blob', 'Создаёт Blob через объект Response.'],
            en: ['Response + Blob', 'Builds the Blob through a Response object.'],
        },
        'readable-stream': {
            ru: ['ReadableStream', 'Создаёт Blob через читаемый поток байтов.'],
            en: ['ReadableStream', 'Builds the Blob through a readable byte stream.'],
        },
        'message-channel-blob': {
            ru: ['MessageChannel + Blob', 'Запускает передачу Blob из задачи MessageChannel.'],
            en: ['MessageChannel + Blob', 'Starts the Blob handoff from a MessageChannel task.'],
        },
        'idle-callback-blob': {
            ru: ['Idle callback + Blob', 'Запускает передачу Blob из requestIdleCallback.'],
            en: ['Idle callback + Blob', 'Starts the Blob handoff from requestIdleCallback.'],
        },
    },
    triggerMethod: {
        svg: ['SVG load', 'Downloads from an SVG load trigger.'],
        body: ['Body load/pageshow', 'Downloads from body load or pageshow.'],
        img: ['Image load/error', 'Uses image loading or error behavior.'],
        audio: ['Audio load/error', 'Uses audio loading events.'],
        video: ['Video load/error', 'Uses video loading events.'],
        source: ['Media source error', 'Uses a source element error path.'],
        input: ['Input focus', 'Requires focusing an input element.'],
        select: ['Select focus', 'Requires focusing a select element.'],
        button: ['Button focus', 'Requires focusing a button element.'],
        textarea: ['Textarea focus', 'Requires focusing a textarea element.'],
        details: ['Details toggle', 'Requires toggling a details element.'],
        iframe: ['Iframe srcdoc/load', 'Uses iframe srcdoc or load behavior.'],
        animate: ['SVG animate', 'Uses SVG animation events.'],
        animmotion: ['SVG animateMotion', 'Uses SVG animateMotion events.'],
        set: ['SVG set', 'Uses SVG set animation events.'],
        cssanim: ['CSS animation', 'Uses CSS animation events.'],
        csstransition: {
            ru: ['CSS transition', 'Использует естественные события CSS-перехода.'],
            en: ['CSS transition', 'Uses CSS transition events.'],
        },
        link: ['Link load/error', 'Uses link load or error behavior.'],
        script: {
            ru: ['Ошибка script', 'Использует естественное событие ошибки загрузки script.'],
            en: ['Script error', 'Uses a natural script loading error.'],
        },
        form: {
            ru: ['Отправка формы', 'Использует естественное событие отправки формы.'],
            en: ['Form submit', 'Uses a natural form submission event.'],
        },
        custom: ['Custom focus element', 'Uses a custom focus target.'],
        focusin: ['Focus-in wrapper', 'Uses a focusin event.'],
        contentvis: ['Content visibility event', 'Uses contentvisibilityautostatechange.'],
    },
    triggerEvent: {
        onload: ['Load', 'Runs on load.'],
        onpageshow: ['Page show', 'Runs on pageshow.'],
        onerror: ['Error', 'Runs on loading error.'],
        onloadstart: ['Load start', 'Runs when media load starts.'],
        onfocus: ['Focus', 'Runs when the element receives focus.'],
        onfocusin: ['Focus in', 'Runs on focusin.'],
        oninput: {
            ru: ['Ввод', 'Запускается при естественном вводе.'],
            en: ['Input', 'Runs on natural input.'],
        },
        onchange: {
            ru: ['Изменение', 'Запускается после подтверждения изменения значения.'],
            en: ['Change', 'Runs when the value change is committed.'],
        },
        onkeydown: {
            ru: ['Нажатие клавиши', 'Запускается при нажатии клавиши пользователем.'],
            en: ['Key down', 'Runs on a user key press.'],
        },
        onclick: {
            ru: ['Клик', 'Запускается при естественном клике пользователя/браузера.'],
            en: ['Click', 'Runs on a user/browser click.'],
        },
        onpointerdown: {
            ru: ['Нажатие указателя', 'Запускается при нажатии указателя пользователем.'],
            en: ['Pointer down', 'Runs on a user pointer press.'],
        },
        ontoggle: ['Toggle', 'Runs when details toggles.'],
        srcdoc: ['srcdoc', 'Runs through iframe srcdoc wiring.'],
        onbegin: ['Animation begin', 'Runs when SVG animation begins.'],
        onend: ['Animation end', 'Runs when SVG animation ends.'],
        onrepeat: ['Animation repeat', 'Runs when SVG animation repeats.'],
        onanimationstart: ['CSS animation start', 'Runs when CSS animation starts.'],
        onanimationend: ['CSS animation end', 'Runs when CSS animation ends.'],
        onanimationiteration: {
            ru: ['Итерация CSS-анимации', 'Запускается на очередной итерации CSS-анимации.'],
            en: ['CSS animation iteration', 'Runs on a CSS animation iteration.'],
        },
        ontransitionrun: {
            ru: ['Создание CSS-перехода', 'Запускается при создании CSS-перехода.'],
            en: ['CSS transition run', 'Runs when a CSS transition is created.'],
        },
        ontransitionstart: {
            ru: ['Начало CSS-перехода', 'Запускается в начале CSS-перехода.'],
            en: ['CSS transition start', 'Runs when a CSS transition starts.'],
        },
        ontransitionend: {
            ru: ['Конец CSS-перехода', 'Запускается в конце CSS-перехода.'],
            en: ['CSS transition end', 'Runs when a CSS transition ends.'],
        },
        onsubmit: {
            ru: ['Отправка формы', 'Запускается при естественной отправке формы.'],
            en: ['Form submit', 'Runs on a user/browser form submission.'],
        },
        oncontentvisibilityautostatechange: ['Content visibility auto-state change', 'Runs on content visibility auto-state changes.'],
    },
};

function getSmuggleLocale() {
    const lang = typeof getCoreState === 'function' ? getCoreState()?.lang : '';
    return lang === 'en' ? 'en' : 'ru';
}

function smuggleText(key, replacements = []) {
    const locale = getSmuggleLocale();
    let value = SMUGGLE_COPY[locale]?.[key] || SMUGGLE_COPY.ru[key] || key;
    replacements.forEach((replacement, index) => {
        value = value.replace(`{${index}}`, String(replacement));
    });
    return value;
}

function normalizeSmuggleMimeToken(value) {
    return String(value || '').trim();
}

function getSmuggleMimePresets() {
    return getSmuggleCapabilities().mime_presets;
}

function getSmuggleMimeByExtension() {
    return Object.fromEntries(
        Object.entries(getSmuggleCapabilities().mime_by_extension).map(([extension, mime]) => (
            [extension, [mime]]
        ))
    );
}

function getLocalizedSmuggleOptionPair(category, token) {
    const entry = SMUGGLE_OPTION_COPY[category]?.[token];
    if (Array.isArray(entry)) {
        return entry;
    }
    if (isPlainSmuggleObject(entry)) {
        const localized = entry[getSmuggleLocale()] || entry.en || entry.ru;
        return Array.isArray(localized) ? localized : null;
    }
    return null;
}

function getSmuggleOptionLabel(category, token) {
    const pair = getLocalizedSmuggleOptionPair(category, token);
    const raw = String(token || '');
    if (!pair) {
        return raw;
    }
    return `${pair[0]} (${raw})`;
}

function getSmuggleOptionDescription(category, token) {
    const pair = getLocalizedSmuggleOptionPair(category, token);
    if (!pair) {
        return smuggleText('searchOptions');
    }
    return pair[1];
}

function buildSmuggleComboboxMarkup(id, value, options = {}) {
    const describedBy = [options.describedBy, `${id}Error`].filter(Boolean).join(' ');
    const constructorAttributes = options.constructorField
        ? ' data-smuggle-constructor-field="true"'
        : '';
    const maxLength = Number(options.maxLength);
    const maxLengthAttribute = Number.isFinite(maxLength) && maxLength > 0
        ? ` maxlength="${esc(String(maxLength))}"`
        : '';
    const labelledByAttribute = options.labelledBy
        ? ` aria-labelledby="${esc(options.labelledBy)}"`
        : '';
    return `
        <div class="smuggle-combobox" data-smuggle-combobox="${esc(id)}">
            <input type="text" id="${esc(id)}" value="${esc(value)}" placeholder="${esc(smuggleText('searchOptions'))}" autocomplete="off" spellcheck="false"
                role="combobox" aria-autocomplete="list" aria-expanded="false"
                aria-controls="${esc(id)}Listbox"
                aria-describedby="${esc(describedBy)}" aria-errormessage="${esc(id)}Error"${labelledByAttribute}
                data-smuggle-combobox-input data-smuggle-edit-control${constructorAttributes}${maxLengthAttribute}>
            <input type="hidden" id="${esc(id)}Value" value="${esc(value)}" data-smuggle-canonical-value>
            <ul class="smuggle-combobox__listbox" id="${esc(id)}Listbox" role="listbox"${labelledByAttribute} hidden></ul>
            <span class="smuggle-combobox__error" id="${esc(id)}Error" role="alert" hidden></span>
        </div>
    `;
}

function normalizeSmuggleSearchText(value) {
    return String(value || '').trim().toLocaleLowerCase().replace(/^\./, '');
}

function normalizeSmuggleExtension(value) {
    return String(value || '').trim().replace(/^\./, '').toLowerCase();
}

function isValidSmuggleExtension(value) {
    const normalized = normalizeSmuggleExtension(value);
    const limit = getSmuggleFieldLimit('download_ext');
    return Boolean(
        normalized &&
        Array.from(normalized).length <= limit &&
        /^[a-z0-9][a-z0-9_+-]*(?:\.[a-z0-9][a-z0-9_+-]*)*$/i.test(normalized)
    );
}

function isValidSmuggleMimeType(value) {
    const normalized = normalizeSmuggleMimeToken(value);
    const limit = getSmuggleFieldLimit('mime_type');
    return Boolean(
        normalized &&
        Array.from(normalized).length <= limit &&
        Array.from(normalized).every(char => (
            char === ' ' || /[\p{Letter}\p{Mark}\p{Number}\p{Punctuation}\p{Symbol}]/u.test(char)
        ))
    );
}

function normalizeSmuggleTriggerEvent(value) {
    const normalized = String(value || '').trim().toLowerCase();
    if (!normalized || normalized.startsWith('on')) {
        return normalized;
    }
    return `on${normalized}`;
}

function isValidSmuggleTriggerEvent(value) {
    const normalized = normalizeSmuggleTriggerEvent(value);
    const limit = getSmuggleFieldLimit('trigger_event');
    return Boolean(normalized.length <= limit && /^on[a-z][a-z0-9_-]*$/.test(normalized));
}

function getSmuggleComboboxOptionScore(option, query) {
    if (!query) return 100;
    const value = normalizeSmuggleSearchText(option.value);
    const label = normalizeSmuggleSearchText(option.label);
    const keywords = normalizeSmuggleSearchText(option.keywords);
    const description = normalizeSmuggleSearchText(option.description);
    if (value === query || label === query) return 0;
    if (value.startsWith(query)) return 10;
    if (label.startsWith(query)) return 20;
    if (keywords.split(/\s+/).some(keyword => keyword.startsWith(query))) return 30;
    if (value.includes(query)) return 40 + value.indexOf(query);
    if (label.includes(query)) return 50 + label.indexOf(query);
    if (keywords.includes(query)) return 60 + keywords.indexOf(query);
    if (description.includes(query)) return 70 + description.indexOf(query);
    return Number.POSITIVE_INFINITY;
}

function createSmuggleCombobox(modal, config) {
    const root = modal.querySelector(`[data-smuggle-combobox="${config.id}"]`);
    const input = root?.querySelector('[data-smuggle-combobox-input]');
    const canonicalInput = root?.querySelector('[data-smuggle-canonical-value]');
    const listbox = root?.querySelector('[role="listbox"]');
    const error = root?.querySelector('.smuggle-combobox__error');
    if (!root || !input || !canonicalInput || !listbox || !error) {
        return null;
    }

    let visibleOptions = [];
    let activeIndex = -1;
    let filterByTypedValue = false;
    const getOptions = () => {
        const rawOptions = typeof config.options === 'function' ? config.options() : config.options;
        const seen = new Set();
        return (Array.isArray(rawOptions) ? rawOptions : []).map(rawOption => {
            const option = typeof rawOption === 'string' ? { value: rawOption } : rawOption;
            const value = String(option?.value || '').trim();
            if (!value || seen.has(value)) return null;
            seen.add(value);
            return {
                value,
                label: String(option.label || value),
                description: String(option.description || ''),
                keywords: String(option.keywords || ''),
                custom: false,
            };
        }).filter(Boolean);
    };
    const allowsCustom = () => (
        typeof config.allowCustom === 'function' ? config.allowCustom() : config.allowCustom === true
    );
    const normalizeCustom = value => (
        typeof config.normalizeCustom === 'function' ? config.normalizeCustom(value) : String(value || '').trim()
    );
    const validateCustom = value => (
        typeof config.validateCustom === 'function' ? config.validateCustom(value) : Boolean(value)
    );
    const displayValue = value => (
        typeof config.displayValue === 'function' ? config.displayValue(value) : String(value || '')
    );
    const clearError = () => {
        input.removeAttribute('aria-invalid');
        error.textContent = '';
        error.hidden = true;
    };
    const setError = message => {
        input.setAttribute('aria-invalid', 'true');
        error.textContent = String(message || smuggleText('constrainedOptionError'));
        error.hidden = false;
    };
    const close = () => {
        listbox.hidden = true;
        input.setAttribute('aria-expanded', 'false');
        input.removeAttribute('aria-activedescendant');
        activeIndex = -1;
        filterByTypedValue = false;
    };
    const setActive = index => {
        if (visibleOptions.length === 0) {
            activeIndex = -1;
            input.removeAttribute('aria-activedescendant');
            return;
        }
        activeIndex = Math.max(0, Math.min(index, visibleOptions.length - 1));
        listbox.querySelectorAll('[role="option"]').forEach((node, optionIndex) => {
            const selected = optionIndex === activeIndex;
            node.setAttribute('aria-selected', String(selected));
            if (selected) node.scrollIntoView({ block: 'nearest' });
        });
        input.setAttribute('aria-activedescendant', `${config.id}Option${activeIndex}`);
    };
    const render = () => {
        // The input also displays the committed value. Treat it as a search
        // query only after the user edits it; opening a closed combobox must
        // expose all advertised choices instead of filtering down to the
        // currently selected value.
        const query = filterByTypedValue
            ? normalizeSmuggleSearchText(input.value)
            : '';
        const options = getOptions();
        visibleOptions = options.map((option, index) => ({
            ...option,
            score: getSmuggleComboboxOptionScore(option, query),
            sourceIndex: index,
        })).filter(option => Number.isFinite(option.score))
            .sort((left, right) => left.score - right.score || left.sourceIndex - right.sourceIndex);

        const customValue = normalizeCustom(input.value);
        const exactOption = options.find(option => normalizeCustom(option.value) === customValue);
        if (query && allowsCustom() && validateCustom(customValue) && !exactOption) {
            const customOption = {
                value: customValue,
                label: smuggleText('useCustomValue', [input.value.trim()]),
                description: '',
                keywords: '',
                custom: true,
            };
            visibleOptions = [...visibleOptions, customOption];
        }

        listbox.replaceChildren();
        if (visibleOptions.length === 0) {
            const empty = document.createElement('li');
            empty.className = 'smuggle-combobox__empty';
            empty.setAttribute('role', 'option');
            empty.setAttribute('aria-disabled', 'true');
            empty.textContent = smuggleText('noMatchingOptions');
            listbox.appendChild(empty);
            activeIndex = -1;
            input.removeAttribute('aria-activedescendant');
            return;
        }
        visibleOptions.forEach((option, index) => {
            const item = document.createElement('li');
            item.id = `${config.id}Option${index}`;
            item.className = 'smuggle-combobox__option';
            item.setAttribute('role', 'option');
            item.setAttribute('aria-selected', 'false');
            item.dataset.optionIndex = String(index);
            const label = document.createElement('span');
            label.className = 'smuggle-combobox__option-label';
            label.textContent = option.label;
            item.appendChild(label);
            if (option.description) {
                const description = document.createElement('span');
                description.className = 'smuggle-combobox__option-description';
                description.textContent = option.description;
                item.appendChild(description);
            }
            listbox.appendChild(item);
        });
        if (activeIndex >= visibleOptions.length) activeIndex = -1;
        if (activeIndex >= 0) {
            setActive(activeIndex);
        } else {
            input.removeAttribute('aria-activedescendant');
        }
    };
    const open = ({ filter = false } = {}) => {
        if (input.disabled) return;
        filterByTypedValue = filter;
        render();
        listbox.hidden = false;
        input.setAttribute('aria-expanded', 'true');
    };
    const commit = (option, meta = {}) => {
        if (!option) return false;
        canonicalInput.value = option.value;
        canonicalInput.dataset.custom = option.custom ? 'true' : 'false';
        input.value = displayValue(option.value);
        clearError();
        close();
        if (typeof config.onChange === 'function') {
            config.onChange(option.value, { custom: option.custom, ...meta });
        }
        return true;
    };
    const reconcileTypedValue = (notify = true) => {
        const typed = normalizeCustom(input.value);
        const exact = getOptions().find(option => normalizeCustom(option.value) === typed);
        if (exact) {
            canonicalInput.value = exact.value;
            canonicalInput.dataset.custom = 'false';
        } else if (allowsCustom() && validateCustom(typed)) {
            canonicalInput.value = typed;
            canonicalInput.dataset.custom = 'true';
        } else {
            canonicalInput.value = '';
            canonicalInput.dataset.custom = 'false';
        }
        if (notify && typeof config.onChange === 'function') {
            config.onChange(canonicalInput.value, {
                custom: canonicalInput.dataset.custom === 'true',
                editing: true,
            });
        }
    };
    const validate = () => {
        reconcileTypedValue(false);
        const value = canonicalInput.value;
        const advertised = getOptions().some(option => option.value === value);
        if (advertised) {
            clearError();
            return true;
        }
        if (allowsCustom() && validateCustom(value)) {
            clearError();
            return true;
        }
        const customError = typeof config.customError === 'function'
            ? config.customError()
            : config.customError;
        setError(allowsCustom() && input.value.trim() ? customError : smuggleText('constrainedOptionError'));
        return false;
    };
    const setValue = (value, meta = {}) => {
        const normalized = normalizeCustom(value);
        const advertised = getOptions().find(option => normalizeCustom(option.value) === normalized);
        const isCustom = !advertised && allowsCustom() && validateCustom(normalized);
        canonicalInput.value = advertised?.value || (isCustom ? normalized : '');
        canonicalInput.dataset.custom = isCustom ? 'true' : 'false';
        input.value = displayValue(canonicalInput.value || value);
        clearError();
        close();
        if (meta.notify && typeof config.onChange === 'function') {
            config.onChange(canonicalInput.value, { custom: isCustom, programmatic: true });
        }
    };

    input.addEventListener('focus', open);
    input.addEventListener('click', open);
    input.addEventListener('input', () => {
        clearError();
        activeIndex = -1;
        input.removeAttribute('aria-activedescendant');
        reconcileTypedValue();
        open({ filter: true });
    });
    input.addEventListener('blur', () => {
        close();
        validate();
    });
    input.addEventListener('keydown', event => {
        if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
            event.preventDefault();
            if (listbox.hidden) open();
            const delta = event.key === 'ArrowDown' ? 1 : -1;
            setActive(activeIndex < 0 ? (delta > 0 ? 0 : visibleOptions.length - 1) : activeIndex + delta);
            return;
        }
        if (event.key === 'Enter') {
            event.preventDefault();
            if (activeIndex >= 0 && commit(visibleOptions[activeIndex], { keyboard: true })) return;
            reconcileTypedValue(false);
            if (validate()) {
                input.value = displayValue(canonicalInput.value);
                close();
                if (typeof config.onChange === 'function') {
                    config.onChange(canonicalInput.value, {
                        custom: canonicalInput.dataset.custom === 'true',
                        keyboard: true,
                    });
                }
            }
            return;
        }
        if (event.key === 'Escape' && !listbox.hidden) {
            event.preventDefault();
            event.stopPropagation();
            close();
            return;
        }
        if (event.key === 'Tab') {
            if (activeIndex >= 0) {
                commit(visibleOptions[activeIndex], { keyboard: true });
            } else {
                reconcileTypedValue();
                close();
            }
        }
    });
    listbox.addEventListener('pointerdown', event => {
        if (event.target.closest('[role="option"]:not([aria-disabled="true"])')) {
            event.preventDefault();
        }
    });
    listbox.addEventListener('click', event => {
        const item = event.target.closest('[data-option-index]');
        const optionIndex = Number(item?.dataset.optionIndex);
        if (Number.isInteger(optionIndex) && visibleOptions[optionIndex]) {
            event.preventDefault();
            commit(visibleOptions[optionIndex], { pointer: true });
            input.focus({ preventScroll: true });
        }
    });

    setValue(canonicalInput.value);
    return {
        id: config.id,
        root,
        input,
        canonicalInput,
        close,
        open,
        validate,
        clearError,
        setError,
        setValue,
        getValue: () => canonicalInput.value,
        isCustom: () => canonicalInput.dataset.custom === 'true',
        getOptions,
        refresh: () => {
            if (!listbox.hidden) render();
        },
    };
}

function shellQuoteSingle(value) {
    return `'${String(value || '').replace(/'/g, `'\"'\"'`)}'`;
}

function getSmuggleSourceName(filePath) {
    const parts = String(filePath || '').split('/');
    return parts[parts.length - 1] || 'artifact.bin';
}

function getSmuggleSourceStem(sourceName) {
    const name = String(sourceName || '');
    const dotIndex = name.lastIndexOf('.');
    return dotIndex > 0 ? name.slice(0, dotIndex) : name;
}

function getSmuggleSourceExt(sourceName) {
    const name = String(sourceName || '');
    const dotIndex = name.lastIndexOf('.');
    return dotIndex > 0 ? name.slice(dotIndex + 1).toLowerCase() : '';
}

function getSmuggleDefaultExtension(sourceName) {
    const extensions = getSmuggleAllowedExtensions();
    const inferredExt = getSmuggleSourceExt(sourceName);
    if (extensions.includes(inferredExt) || (isSmuggleCustomExtensionSupported() && isValidSmuggleExtension(inferredExt))) {
        return inferredExt;
    }
    return extensions[0];
}

function getSmuggleAllowedExtensions() {
    return getSmuggleCapabilities().extensions;
}

function getSmuggleAllowedPresets() {
    return getSmuggleCapabilities().presets;
}

function getSmuggleAllowedPayloadEncodings() {
    return getSmuggleCapabilities().payload_encodings;
}

function getSmuggleAllowedOutputFormats() {
    return getSmuggleCapabilities().output_formats;
}

function getSmuggleAllowedPageTemplates() {
    return getSmuggleCapabilities().page_templates;
}

function getSmuggleAllowedDownloadVariants() {
    return getSmuggleCapabilities().download_variants;
}

function getSmuggleAllowedTriggerEventsMap() {
    return getSmuggleCapabilities().trigger_events;
}

function getSmuggleAllowedTriggerMethods() {
    return Object.keys(getSmuggleAllowedTriggerEventsMap());
}

function getSmuggleInitialTriggerEvent(method) {
    return getSmuggleAllowedTriggerEventsMap()[method][0];
}

function isSmuggleCustomExtensionSupported() {
    return getSmuggleCapabilityFlag('custom_extension');
}

function isSmuggleCustomMimeTypeSupported() {
    return getSmuggleCapabilityFlag('custom_mime_type');
}

function isSmuggleCustomTriggerEventSupported() {
    return getSmuggleCapabilityFlag('custom_trigger_event');
}

function getSmuggleCustomTriggerMethods() {
    if (!isSmuggleCustomTriggerEventSupported()) return [];
    return getSmuggleCapabilities().custom_trigger_methods;
}

function isSmuggleCustomTriggerEventAllowed(modal) {
    const method = getSmuggleComboboxValue(modal, 'smuggleTriggerMethod');
    return getSmuggleCustomTriggerMethods().includes(method);
}

function getSmuggleOptionModels(category, values) {
    return values.map(value => ({
        value,
        label: getSmuggleOptionLabel(category, value),
        description: getSmuggleOptionDescription(category, value),
        keywords: `${value} ${getSmuggleOptionLabel(category, value)} ${getSmuggleOptionDescription(category, value)}`,
    }));
}

function getSmugglePresetOptionModels() {
    return getSmuggleAllowedPresets().map(value => ({
        value,
        label: `${getSmugglePresetLabel(value)} (${value})`,
        keywords: `${value} ${getSmugglePresetLabel(value)}`,
    }));
}

function getSmuggleExtensionOptionModels(sourceName) {
    const advertised = getSmuggleAllowedExtensions();
    const values = advertised.slice();
    const sourceExtension = getSmuggleSourceExt(sourceName);
    if (isSmuggleCustomExtensionSupported() && isValidSmuggleExtension(sourceExtension) && !values.includes(sourceExtension)) {
        values.unshift(sourceExtension);
    }
    return values.map(value => ({
        value,
        label: `.${value}`,
        keywords: `${value} extension suffix`,
    }));
}

function getSmuggleMimeOptionModels(filePath, modal) {
    const values = [];
    const push = value => {
        const mime = normalizeSmuggleMimeToken(value);
        if (mime && !values.includes(mime)) values.push(mime);
    };
    const sourceInfo = smuggleSourceInfoCache.get(filePath) || null;
    const inspection = sourceInfo ? getFileInspection(sourceInfo) : null;
    push(inspection?.mime_type || sourceInfo?.content_type);

    const mimeByExtension = getSmuggleMimeByExtension();
    const selectedExtension = normalizeSmuggleExtension(
        modal?.querySelector('#smuggleDownloadExtValue')?.value,
    );
    (mimeByExtension[selectedExtension] || []).forEach(push);
    (mimeByExtension[getSmuggleSourceExt(getSmuggleSourceName(filePath))] || []).forEach(push);
    getSmuggleMimePresets().forEach(push);
    Object.values(mimeByExtension).flat().forEach(push);
    return values.map(value => ({
        value,
        label: value,
        keywords: `${value} ${value.split(/[\/+.-]/).join(' ')}`,
    }));
}

function getSmuggleComboboxValue(modal, id) {
    return String(modal.querySelector(`#${id}Value`)?.value || '').trim();
}

function initializeSmuggleComboboxes(modal, filePath, defaults) {
    const registry = new Map();
    modal.__smuggleComboboxes = registry;
    const register = config => {
        const combobox = createSmuggleCombobox(modal, config);
        if (combobox) registry.set(config.id, combobox);
        return combobox;
    };
    const sync = () => syncSmuggleBuilderUi(modal, filePath);

    register({
        id: 'smuggleDownloadExt',
        options: () => getSmuggleExtensionOptionModels(defaults.sourceName),
        allowCustom: isSmuggleCustomExtensionSupported,
        normalizeCustom: normalizeSmuggleExtension,
        validateCustom: isValidSmuggleExtension,
        customError: () => smuggleText('extensionFormatError', [
            getSmuggleFieldLimit('download_ext'),
        ]),
        onChange: () => {
            registry.get('smuggleMimeType')?.refresh();
            sync();
        },
    });
    register({
        id: 'smugglePreset',
        options: getSmugglePresetOptionModels,
        onChange: sync,
    });
    register({
        id: 'smuggleEncryption',
        options: () => getSmuggleOptionModels(
            'encryption',
            getSmuggleCapabilities().encryption_modes,
        ),
        onChange: sync,
    });
    register({
        id: 'smugglePayloadEncoding',
        options: () => getSmuggleOptionModels('payloadEncoding', getSmuggleAllowedPayloadEncodings()),
        onChange: sync,
    });

    let selectedTriggerMethod = defaults.triggerMethod;
    register({
        id: 'smuggleTriggerMethod',
        options: () => getSmuggleOptionModels('triggerMethod', getSmuggleAllowedTriggerMethods()),
        onChange: value => {
            const eventCombobox = registry.get('smuggleTriggerEvent');
            if (value && value !== selectedTriggerMethod) {
                selectedTriggerMethod = value;
                const advertisedEvents = getSmuggleTriggerEvents(value);
                if (!advertisedEvents.includes(eventCombobox?.getValue())) {
                    eventCombobox?.setValue(advertisedEvents[0] || 'onload');
                }
            }
            eventCombobox?.refresh();
            sync();
        },
    });
    register({
        id: 'smuggleTriggerEvent',
        options: () => getSmuggleOptionModels(
            'triggerEvent',
            getSmuggleTriggerEvents(getSmuggleComboboxValue(modal, 'smuggleTriggerMethod') || defaults.triggerMethod),
        ),
        allowCustom: () => isSmuggleCustomTriggerEventAllowed(modal),
        normalizeCustom: normalizeSmuggleTriggerEvent,
        validateCustom: isValidSmuggleTriggerEvent,
        customError: () => smuggleText('triggerEventFormatError', [
            getSmuggleFieldLimit('trigger_event'),
        ]),
        onChange: sync,
    });
    register({
        id: 'smuggleOutputFormat',
        options: () => getSmuggleOptionModels('outputFormat', getSmuggleAllowedOutputFormats()),
        onChange: sync,
    });
    register({
        id: 'smuggleDownloadVariant',
        options: () => getSmuggleOptionModels('downloadVariant', getSmuggleAllowedDownloadVariants()),
        onChange: sync,
    });
    register({
        id: 'smugglePageTemplate',
        options: () => getSmuggleOptionModels('pageTemplate', getSmuggleAllowedPageTemplates()),
        onChange: sync,
    });
    register({
        id: 'smuggleMimeType',
        options: () => getSmuggleMimeOptionModels(filePath, modal),
        allowCustom: isSmuggleCustomMimeTypeSupported,
        normalizeCustom: normalizeSmuggleMimeToken,
        validateCustom: isValidSmuggleMimeType,
        customError: () => smuggleText('mimeFormatError', [
            getSmuggleFieldLimit('mime_type'),
        ]),
        onChange: sync,
    });

    modal.addEventListener('pointerdown', event => {
        registry.forEach(combobox => {
            if (!combobox.root.contains(event.target)) combobox.close();
        });
    });
    return registry;
}

function validateSmuggleComboboxes(modal, options = {}) {
    const invalid = [];
    modal.__smuggleComboboxes?.forEach(combobox => {
        if (!combobox.input.disabled && !combobox.validate()) invalid.push(combobox);
    });
    if (options.focusFirst && invalid[0]) {
        focusElementWithoutScroll(invalid[0].input);
    }
    return invalid.length === 0;
}

function setSmuggleFieldError(modal, field, message = '') {
    const fieldMap = {
        download_ext: 'smuggleDownloadExt',
        preset: 'smugglePreset',
        encryption: 'smuggleEncryption',
        payload_encoding: 'smugglePayloadEncoding',
        trigger_method: 'smuggleTriggerMethod',
        trigger_event: 'smuggleTriggerEvent',
        output_format: 'smuggleOutputFormat',
        download_variant: 'smuggleDownloadVariant',
        page_template: 'smugglePageTemplate',
        mime_type: 'smuggleMimeType',
    };
    const combobox = modal.__smuggleComboboxes?.get(fieldMap[field]);
    if (combobox) {
        combobox.setError(message || smuggleText('constrainedOptionError'));
        return;
    }
    const controlSelectors = {
        download_name: '#smuggleDownloadName',
        mode: '#smuggleConstructorEnabled',
        title: '#smuggleTitleInput',
        message: '#smuggleMessageInput',
        cta_label: '#smuggleCtaLabelInput',
        delay_ms: '#smuggleDelayMs',
        show_notice: '#smuggleShowNotice',
        null_byte: '#smuggleNullByte',
    };
    const controlSelector = controlSelectors[field];
    const control = controlSelector ? modal.querySelector(controlSelector) : null;
    if (!control) return;
    control.setAttribute('aria-invalid', 'true');
    control.setAttribute('aria-errormessage', 'smuggleInlineStatus');
}

function normalizeSmuggleStem(stem) {
    let normalized = '';
    Array.from(String(stem || '')).forEach(char => {
        const code = char.charCodeAt(0);
        if (/[\p{Letter}\p{Number}]/u.test(char) || char === '-' || char === '_' || char === ' ') {
            normalized += char;
            return;
        }
        if (char === '.' || char === '/' || char === '\\' || code < 32 || code === 127) {
            normalized += '-';
            return;
        }
        normalized += '-';
    });
    normalized = normalized.split(/\s+/).filter(Boolean).join('-');
    while (normalized.includes('--')) {
        normalized = normalized.replace(/--/g, '-');
    }
    normalized = normalized.replace(/^[._\-\s]+|[._\-\s]+$/g, '');
    return normalized || 'download';
}

function getDefaultSmuggleBuilderState(filePath) {
    const sourceName = getSmuggleSourceName(filePath);
    const defaultTriggerMethod = getSmuggleDefaultValue('trigger_method');
    return {
        sourceName,
        downloadName: getSmuggleSourceStem(sourceName),
        downloadExt: getSmuggleDefaultExtension(sourceName),
        mode: getSmuggleDefaultValue('mode'),
        preset: getSmuggleDefaultValue('preset'),
        locale: getSmuggleDefaultValue('locale'),
        title: t('smuggleBuilderDefaultTitle'),
        message: t('smuggleBuilderDefaultMessage'),
        ctaLabel: t('smuggleBuilderDefaultCta'),
        delayMs: clampSmuggleDelay(getSmuggleDefaultValue('delay_ms')),
        showNotice: getSmuggleDefaultValue('show_notice'),
        encryption: getSmuggleDefaultValue('encryption'),
        payloadEncoding: getSmuggleDefaultValue('payload_encoding'),
        triggerMethod: defaultTriggerMethod,
        triggerEvent: getSafeSmuggleTriggerEvent(
            defaultTriggerMethod,
            getSmuggleDefaultValue('trigger_event'),
        ),
        outputFormat: getSmuggleDefaultValue('output_format'),
        downloadVariant: getSmuggleDefaultValue('download_variant'),
        pageTemplate: getSmuggleDefaultValue('page_template'),
        mimeType: getSmuggleDefaultValue('mime_type'),
        nullByte: getSmuggleDefaultValue('null_byte'),
    };
}

function getSelectedSmuggleMode(modal) {
    return modal.querySelector('#smuggleConstructorEnabled')?.checked ? 'constructor' : 'simple';
}

function getSmugglePresetConfig(preset) {
    return {
        supportsCta: preset !== 'direct',
        supportsDelay: preset === 'card_auto',
    };
}

function getSmugglePresetLabel(preset) {
    if (preset === 'card_manual') {
        return t('smuggleBuilderPresetManual');
    }
    if (preset === 'card_auto') {
        return t('smuggleBuilderPresetAuto');
    }
    return t('smuggleBuilderPresetDirect');
}

function clampSmuggleDelay(value) {
    const parsed = Number.parseInt(String(value || ''), 10);
    if (!Number.isFinite(parsed)) {
        return getSmuggleDefaultValue('delay_ms');
    }
    return Math.max(0, Math.min(getSmuggleFieldLimit('delay_ms'), parsed));
}

function getSmuggleTriggerEvents(method) {
    const triggerEvents = getSmuggleAllowedTriggerEventsMap();
    return triggerEvents[method] || [];
}

function getSafeSmuggleTriggerEvent(method, value) {
    const events = getSmuggleTriggerEvents(method);
    const normalized = String(value || '').trim().toLowerCase();
    return events.includes(normalized) ? normalized : events[0];
}

function resolveSmuggleDownloadName(state) {
    const sourceName = String(state.sourceName || 'artifact.bin');
    const requestedName = String(state.downloadName || '').trim();
    const stem = normalizeSmuggleStem(requestedName || getSmuggleSourceStem(sourceName));
    const requestedExt = String(state.downloadExt || '').trim().replace(/^\./, '').toLowerCase();
    const extensions = getSmuggleAllowedExtensions();
    const ext = extensions.includes(requestedExt) || (
        isSmuggleCustomExtensionSupported() && isValidSmuggleExtension(requestedExt)
    ) ? requestedExt : '';
    return ext ? `${stem}.${ext}` : stem;
}

function readSmuggleBuilderState(modal, filePath) {
    const defaults = getDefaultSmuggleBuilderState(filePath);
    const downloadExt = getSmuggleComboboxValue(modal, 'smuggleDownloadExt');
    const preset = getSmuggleComboboxValue(modal, 'smugglePreset');
    const mode = getSelectedSmuggleMode(modal);
    const triggerMethod = getSmuggleComboboxValue(modal, 'smuggleTriggerMethod');
    const triggerEvent = getSmuggleComboboxValue(modal, 'smuggleTriggerEvent');
    const supports = getSmugglePresetConfig(preset);
    return {
        sourceName: defaults.sourceName,
        downloadName: String(modal.querySelector('#smuggleDownloadName')?.value || '').trim(),
        downloadExt,
        preset,
        title: String(modal.querySelector('#smuggleTitleInput')?.value || '').trim(),
        message: String(modal.querySelector('#smuggleMessageInput')?.value || '').trim(),
        ctaLabel: String(modal.querySelector('#smuggleCtaLabelInput')?.value || '').trim(),
        delayMs: supports.supportsDelay
            ? clampSmuggleDelay(modal.querySelector('#smuggleDelayMs')?.value)
            : clampSmuggleDelay(defaults.delayMs),
        showNotice: Boolean(modal.querySelector('#smuggleShowNotice')?.checked),
        mode,
        locale: defaults.locale,
        encryption: getSmuggleComboboxValue(modal, 'smuggleEncryption'),
        payloadEncoding: getSmuggleComboboxValue(modal, 'smugglePayloadEncoding'),
        triggerMethod,
        triggerEvent,
        triggerEventCustom: Boolean(
            triggerEvent &&
            !getSmuggleTriggerEvents(triggerMethod).includes(triggerEvent) &&
            modal.__smuggleComboboxes?.get('smuggleTriggerEvent')?.isCustom()
        ),
        outputFormat: getSmuggleComboboxValue(modal, 'smuggleOutputFormat'),
        downloadVariant: getSmuggleComboboxValue(modal, 'smuggleDownloadVariant'),
        pageTemplate: getSmuggleComboboxValue(modal, 'smugglePageTemplate'),
        mimeType: getSmuggleComboboxValue(modal, 'smuggleMimeType'),
        nullByte: Boolean(modal.querySelector('#smuggleNullByte')?.checked),
    };
}

function setSmuggleFieldState(modal, rowSelector, inputSelector, enabled) {
    const row = modal.querySelector(rowSelector);
    const input = modal.querySelector(inputSelector);
    if (row) {
        row.hidden = !enabled;
    }
    if (input) {
        input.disabled = !enabled;
    }
}

function syncSmuggleModePanels(modal, mode) {
    const constructorToggle = modal.querySelector('#smuggleConstructorEnabled');
    if (constructorToggle) {
        constructorToggle.checked = mode === 'constructor';
    }
    modal.querySelectorAll('[data-smuggle-mode-panel]').forEach(panel => {
        panel.hidden = !panel.matches(`[data-smuggle-mode-panel="${mode}"]`);
    });
}

function formatSmugglePresetToken(preset) {
    if (getSmuggleAllowedPresets().includes(preset)) {
        return `${getSmugglePresetLabel(preset)} (${preset})`;
    }
    return preset;
}

function formatSmuggleModeToken(mode) {
    if (mode === 'constructor') {
        return smuggleText('constructor');
    }
    if (mode === 'simple') {
        return smuggleText('simple');
    }
    return mode;
}

function createSmuggleSummaryRows(rows) {
    return rows.map(([label, value, options = {}]) => {
        const className = options.mono ? 'smuggle-summary__value smuggle-summary__value--mono' : 'smuggle-summary__value';
        return `
            <div class="smuggle-summary__row">
                <dt>${esc(label)}</dt>
                <dd class="${className}">${esc(value)}</dd>
            </div>
        `;
    }).join('');
}

function updateSmuggleDescription(modal, target, category, token) {
    const description = modal.querySelector(`[data-smuggle-description-for="${target}"]`);
    if (!description) {
        return;
    }
    description.textContent = getSmuggleOptionDescription(category, token);
}

function renderSmuggleCompatibility(modal, state) {
    const list = modal.querySelector('#smuggleCompatibilityList');
    if (!list) {
        return;
    }
    const warnings = [];
    if (state.mode === 'constructor' && state.triggerEventCustom) {
        warnings.push(smuggleText('customTriggerWarning'));
    }
    if (state.mode === 'constructor' && state.downloadVariant === 'loc-assign') {
        warnings.push(smuggleText('locAssignFilenameWarning'));
    }
    list.innerHTML = warnings.map(item => `<li>${esc(item)}</li>`).join('');
    list.closest('.smuggle-dialog__notice')?.toggleAttribute('hidden', warnings.length === 0);
}

function syncSmuggleBuilderUi(modal, filePath) {
    const state = readSmuggleBuilderState(modal, filePath);
    const supports = getSmugglePresetConfig(state.preset);
    const constructorMode = state.mode === 'constructor';
    syncSmuggleModePanels(modal, state.mode);
    modal.querySelectorAll('[data-smuggle-constructor-field="true"]').forEach(control => {
        control.disabled = !constructorMode;
    });
    const previewName = modal.querySelector('#smuggleDownloadNamePreview');
    if (previewName) {
        previewName.textContent = resolveSmuggleDownloadName(state);
    }
    setSmuggleFieldState(modal, '#smuggleCtaRow', '#smuggleCtaLabelInput', !constructorMode && supports.supportsCta);
    setSmuggleFieldState(modal, '#smuggleDelayRow', '#smuggleDelayMs', !constructorMode && supports.supportsDelay);
    updateSmuggleDescription(modal, 'smuggleEncryption', 'encryption', state.encryption);
    updateSmuggleDescription(modal, 'smugglePayloadEncoding', 'payloadEncoding', state.payloadEncoding);
    updateSmuggleDescription(modal, 'smuggleTriggerMethod', 'triggerMethod', state.triggerMethod);
    updateSmuggleDescription(modal, 'smuggleTriggerEvent', 'triggerEvent', state.triggerEvent);
    updateSmuggleDescription(modal, 'smuggleOutputFormat', 'outputFormat', state.outputFormat);
    updateSmuggleDescription(modal, 'smuggleDownloadVariant', 'downloadVariant', state.downloadVariant);
    updateSmuggleDescription(modal, 'smugglePageTemplate', 'pageTemplate', state.pageTemplate);
    renderSmuggleCompatibility(modal, state);
}

function encodeSmuggleSourcePath(filePath) {
    return String(filePath || '').split('/').map(segment => encodeURIComponent(segment)).join('/');
}

function buildSmuggleRequestPath(filePath, state) {
    const capabilities = requireValidSmuggleCapabilities();
    const input = isPlainSmuggleObject(state) ? state : {};
    const readToken = (property, defaultKey, advertised, field = defaultKey) => {
        const supplied = input[property];
        const value = supplied === undefined || supplied === null || supplied === ''
            ? capabilities.defaults[defaultKey]
            : String(supplied).trim();
        if (!advertised.includes(value)) {
            throw new Error(`SMUGGLE ${field} is not advertised by the server`);
        }
        return value;
    };
    const mode = readToken('mode', 'mode', capabilities.modes);
    const encryption = readToken(
        'encryption',
        'encryption',
        capabilities.encryption_modes,
    );
    if (mode === 'constructor' && !capabilities.caps.constructor) {
        throw new Error('SMUGGLE constructor mode is not advertised by the server');
    }
    if (encryption === 'xor' && !capabilities.caps.xor_obfuscation) {
        throw new Error('SMUGGLE XOR encryption is not advertised by the server');
    }
    if (encryption === 'aes' && !capabilities.caps.aes_gcm) {
        throw new Error('SMUGGLE AES encryption is not advertised by the server');
    }

    const activeModeFields = new Set(
        capabilities.mode_fields[mode === 'constructor' ? 'constructor_only' : 'simple_only']
    );
    const allModeFields = new Set([
        ...capabilities.mode_fields.simple_only,
        ...capabilities.mode_fields.constructor_only,
    ]);
    const fieldIsActive = field => !allModeFields.has(field) || activeModeFields.has(field);
    const params = new URLSearchParams();
    params.set('mode', mode);
    params.set('encryption', encryption);

    if (input.downloadName) {
        params.set('download_name', String(input.downloadName));
    }
    const sourceName = getSmuggleSourceName(filePath);
    const requestedExtension = String(
        input.downloadExt || getSmuggleDefaultExtension(sourceName)
    ).trim().replace(/^\./, '').toLowerCase();
    if (
        !capabilities.extensions.includes(requestedExtension)
        && !(capabilities.caps.custom_extension && isValidSmuggleExtension(requestedExtension))
    ) {
        throw new Error('SMUGGLE download_ext is not advertised by the server');
    }
    if (requestedExtension) {
        params.set('download_ext', requestedExtension);
    }

    const locale = readToken('locale', 'locale', capabilities.locales);
    params.set('locale', locale);
    params.set(
        'show_notice',
        (input.showNotice === undefined
            ? capabilities.defaults.show_notice
            : Boolean(input.showNotice)) ? '1' : '0'
    );
    if (input.title) {
        params.set('title', String(input.title));
    }
    if (input.message) {
        params.set('message', String(input.message));
    }

    if (fieldIsActive('preset')) {
        const preset = readToken('preset', 'preset', capabilities.presets);
        params.set('preset', preset);
        const presetConfig = getSmugglePresetConfig(preset);
        if (fieldIsActive('cta_label') && presetConfig.supportsCta && input.ctaLabel) {
            params.set('cta_label', String(input.ctaLabel));
        }
        if (fieldIsActive('delay_ms') && presetConfig.supportsDelay) {
            params.set(
                'delay_ms',
                String(clampSmuggleDelay(
                    input.delayMs === undefined ? capabilities.defaults.delay_ms : input.delayMs
                ))
            );
        }
    }

    if (fieldIsActive('payload_encoding')) {
        params.set(
            'payload_encoding',
            readToken(
                'payloadEncoding',
                'payload_encoding',
                capabilities.payload_encodings,
            )
        );
    }
    let triggerMethod = capabilities.defaults.trigger_method;
    if (fieldIsActive('trigger_method')) {
        triggerMethod = readToken(
            'triggerMethod',
            'trigger_method',
            Object.keys(capabilities.trigger_events),
        );
        params.set('trigger_method', triggerMethod);
    }
    if (fieldIsActive('trigger_event')) {
        const supplied = input.triggerEvent;
        const triggerEvent = supplied === undefined || supplied === null || supplied === ''
            ? capabilities.defaults.trigger_event
            : String(supplied).trim();
        const advertisedEvents = capabilities.trigger_events[triggerMethod] || [];
        const customAllowed = capabilities.caps.custom_trigger_event
            && capabilities.custom_trigger_methods.includes(triggerMethod)
            && isValidSmuggleTriggerEvent(triggerEvent);
        if (!advertisedEvents.includes(triggerEvent) && !customAllowed) {
            throw new Error('SMUGGLE trigger_event is not advertised by the server');
        }
        params.set('trigger_event', triggerEvent);
    }
    for (const [field, property, defaultKey, advertised] of [
        ['output_format', 'outputFormat', 'output_format', capabilities.output_formats],
        ['download_variant', 'downloadVariant', 'download_variant', capabilities.download_variants],
        ['page_template', 'pageTemplate', 'page_template', capabilities.page_templates],
    ]) {
        if (fieldIsActive(field)) {
            params.set(field, readToken(property, defaultKey, advertised));
        }
    }
    if (fieldIsActive('mime_type')) {
        const supplied = input.mimeType;
        const mimeType = supplied === undefined || supplied === null || supplied === ''
            ? capabilities.defaults.mime_type
            : normalizeSmuggleMimeToken(supplied);
        if (
            !capabilities.mime_presets.includes(mimeType)
            && !(capabilities.caps.custom_mime_type && isValidSmuggleMimeType(mimeType))
        ) {
            throw new Error('SMUGGLE mime_type is not advertised by the server');
        }
        params.set('mime_type', mimeType);
    }
    if (fieldIsActive('null_byte')) {
        params.set(
            'null_byte',
            (input.nullByte === undefined
                ? capabilities.defaults.null_byte
                : Boolean(input.nullByte)) ? '1' : '0'
        );
    }
    const query = params.toString();
    const encodedPath = encodeSmuggleSourcePath(filePath);
    return query ? `${encodedPath}?${query}` : encodedPath;
}

function joinUploadsPath(basePath, itemName) {
    const base = String(basePath || '/');
    const normalizedBase = base === '/' ? '' : base.replace(/\/+$/, '');
    return `${normalizedBase}/${itemName}`;
}

function createSmuggleInfoUrl(filePath) {
    const url = new URL(SERVER_URL + encodeSmuggleSourcePath(filePath), window.location.href);
    url.searchParams.set('inspect', 'true');
    return url.toString();
}

function getSmuggleSourceInfo(filePath) {
    const sourceName = getSmuggleSourceName(filePath);
    const source = smuggleSourceInfoCache.get(filePath) || {};
    const inspection = getFileInspection(source);
    const numericSize = Number(source.size_bytes);
    const sizeLabel = source.size_human || (Number.isFinite(numericSize) ? formatSize(numericSize) : smuggleText('sourceSizeUnknown'));
    const mimeLabel = inspection?.mime_type || source.content_type || smuggleText('sourceMimeUnknown');
    const capBytes = getSmuggleSourceMaxBytes();
    const capLabel = Number.isFinite(capBytes) && capBytes > 0 ? formatSize(capBytes) : '';
    let capStatus = capLabel
        ? smuggleText('sourceCapPending', [capLabel])
        : smuggleText('sourceCapUnknown');
    if (Number.isFinite(numericSize) && capLabel) {
        capStatus = numericSize > capBytes
            ? smuggleText('sourceOverCap', [capLabel])
            : smuggleText('sourceWithinCap', [capLabel]);
    }
    return {
        sourceName,
        sizeLabel,
        mimeLabel,
        capStatus,
        filePath,
    };
}

function buildSmuggleSourceMarkup(filePath) {
    const source = getSmuggleSourceInfo(filePath);
    const rows = [
        [smuggleText('sourceFilename'), source.sourceName],
        [smuggleText('sourceSize'), source.sizeLabel],
        [smuggleText('sourceMime'), source.mimeLabel],
        [smuggleText('sourcePath'), source.filePath],
        [smuggleText('sourceCap'), source.capStatus],
    ];
    return rows.map(([label, value]) => `
        <div class="smuggle-source-row__item">
            <span>${esc(label)}</span>
            <strong>${esc(value)}</strong>
        </div>
    `).join('');
}

async function hydrateSmuggleSourceInfo(filePath, modal) {
    if (!modal || !modal.isConnected || smuggleSourceInfoCache.has(filePath)) {
        return;
    }
    const requestSeq = (modal.__smuggleSourceInfoSeq || 0) + 1;
    modal.__smuggleSourceInfoSeq = requestSeq;
    try {
        const response = await sendCustomRequest('INFO', createSmuggleInfoUrl(filePath));
        const text = await response.text();
        const info = getCanonicalInfoPayload(parseSmuggleJson(text));
        if (!response.ok || !info || info.entry.kind !== 'file') {
            return;
        }
        smuggleSourceInfoCache.set(filePath, info.entry);
        if (!modal.isConnected || modal.__smuggleSourceInfoSeq !== requestSeq) {
            return;
        }
        const sourceRow = modal.querySelector('.smuggle-source-row');
        if (sourceRow) {
            sourceRow.innerHTML = buildSmuggleSourceMarkup(filePath);
        }
        modal.__smuggleComboboxes?.get('smuggleMimeType')?.refresh();
    } catch (error) {
        // Source metadata is supplementary; generation remains available if INFO fails.
    }
}

function setSmuggleInlineStatus(modal, message = '', tone = '') {
    const status = modal.querySelector('#smuggleInlineStatus');
    if (!status) {
        return;
    }
    status.textContent = message;
    status.hidden = !message;
    status.className = `smuggle-dialog__status${tone ? ` smuggle-dialog__status--${tone}` : ''}`;
}

function setSmuggleModalPhase(modal, phase) {
    modal.dataset.smugglePhase = phase;
    const busy = phase === 'submitting';
    const dialog = modal.querySelector('.smuggle-dialog');
    if (dialog) {
        dialog.setAttribute('aria-busy', String(busy));
    }
    modal.querySelector('[data-smuggle-panel="editing"]')?.toggleAttribute('hidden', phase === 'success');
    modal.querySelector('[data-smuggle-panel="success"]')?.toggleAttribute('hidden', phase !== 'success');
    modal.querySelector('[data-smuggle-actions="editing"]')?.toggleAttribute('hidden', phase === 'success');
    modal.querySelector('[data-smuggle-actions="success"]')?.toggleAttribute('hidden', phase !== 'success');
    const submitButton = modal.querySelector('#smuggleSubmitBtn');
    if (submitButton) {
        submitButton.disabled = busy;
        submitButton.textContent = busy ? smuggleText('submitting') : t('smuggleGenerate');
    }
    modal.querySelectorAll('[data-smuggle-edit-control]').forEach(control => {
        control.disabled = busy;
    });
    modal.querySelectorAll('[data-dialog-action="cancel"], [data-dialog-action="close"]').forEach(control => {
        control.disabled = busy;
    });
    if (busy) {
        const pendingStatus = modal.querySelector('#smuggleInlineStatus');
        if (pendingStatus && !pendingStatus.hidden) {
            focusElementWithoutScroll(pendingStatus);
        }
    }
}

function resetSmuggleEditingPhase(modal, filePath) {
    setSmuggleModalPhase(modal, 'editing');
    const dialogBody = modal.querySelector('#smuggleDialogBody');
    if (dialogBody) {
        dialogBody.scrollTop = 0;
    }
    syncSmuggleBuilderUi(modal, filePath);
    setSmuggleInlineStatus(modal);
}

function focusSmuggleRetryTarget(modal, field = '') {
    const fieldSelectors = {
        download_name: '#smuggleDownloadName',
        download_ext: '#smuggleDownloadExt',
        preset: '#smugglePreset',
        encryption: '#smuggleEncryption',
        mode: '#smuggleConstructorEnabled',
        title: '#smuggleTitleInput',
        message: '#smuggleMessageInput',
        cta_label: '#smuggleCtaLabelInput',
        delay_ms: '#smuggleDelayMs',
        show_notice: '#smuggleShowNotice',
        payload_encoding: '#smugglePayloadEncoding',
        trigger_method: '#smuggleTriggerMethod',
        trigger_event: '#smuggleTriggerEvent',
        output_format: '#smuggleOutputFormat',
        download_variant: '#smuggleDownloadVariant',
        page_template: '#smugglePageTemplate',
        mime_type: '#smuggleMimeType',
        null_byte: '#smuggleNullByte',
    };
    if (['title', 'message', 'cta_label', 'delay_ms', 'show_notice'].includes(field)) {
        const pageSettings = modal.querySelector('#smugglePageSettings');
        if (pageSettings) {
            pageSettings.open = true;
        }
    }
    if (['mode', 'payload_encoding', 'trigger_method', 'trigger_event', 'output_format', 'download_variant', 'page_template', 'mime_type', 'null_byte'].includes(field)) {
        const advancedSettings = modal.querySelector('#smuggleAdvancedSettings');
        if (advancedSettings) {
            advancedSettings.open = true;
        }
    }
    const fieldSelector = fieldSelectors[field];
    const fieldTarget = fieldSelector ? modal.querySelector(fieldSelector) : null;
    const retryTarget = fieldTarget && !fieldTarget.disabled && fieldTarget.getClientRects().length > 0
        ? fieldTarget
        : modal.querySelector('#smuggleSubmitBtn');
    focusElementWithoutScroll(retryTarget);
}

function parseSmuggleJson(text) {
    try {
        const parsed = JSON.parse(text);
        return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed : null;
    } catch (error) {
        return null;
    }
}

function resolveSmuggleErrorMessage(response, text, payload = null) {
    const status = Number(response?.status || 0);
    const errorPayload = payload?.error && typeof payload.error === 'object'
        ? payload.error
        : null;
    const message = errorPayload?.message || String(text || '').trim();
    let localized = message || `${status} ${response?.statusText || t('error')}`.trim();
    if (status === 400) localized = smuggleText('error400');
    if (status === 404) localized = smuggleText('error404');
    if (status === 413) localized = smuggleText('error413');
    if (status === 507) localized = smuggleText('error507');
    const details = [];
    if (errorPayload?.code) details.push(`${smuggleText('errorCode')}: ${errorPayload.code}`);
    if (errorPayload?.field) details.push(`${smuggleText('errorField')}: ${errorPayload.field}`);
    if (errorPayload?.details?.path) details.push(errorPayload.details.path);
    if (Number.isFinite(errorPayload?.details?.actual_bytes) && Number.isFinite(errorPayload?.details?.limit_bytes)) {
        details.push(`${formatSize(errorPayload.details.actual_bytes)} / ${formatSize(errorPayload.details.limit_bytes)}`);
    }
    if (message && message !== localized) details.push(message);
    details.push(smuggleText('retryAfterEdit'));
    return [localized, ...details.filter(Boolean)].join(' ');
}

function getSmuggleResultModel(result) {
    const invalidResult = () => ({
        ok: false,
        model: null,
        error: {
            code: 'invalid_smuggle_response',
            message: 'Invalid SMUGGLE response',
            field: null,
            details: {},
        },
    });
    const isRecord = value => Boolean(value) && typeof value === 'object' && !Array.isArray(value);
    const hasRequiredStrings = (value, fields) => fields.every(field => (
        typeof value[field] === 'string' && value[field].length > 0
    ));
    if (!isRecord(result)) {
        return invalidResult();
    }
    const artifact = result.artifact;
    const source = result.source;
    const download = result.download;
    const builder = result.builder;
    let capabilities;
    try {
        capabilities = requireValidSmuggleCapabilities();
    } catch (_error) {
        return invalidResult();
    }
    const hasPassword = isRecord(builder)
        && Object.prototype.hasOwnProperty.call(builder, 'password');
    const passwordRequired = isRecord(builder) && builder.encryption !== 'none';
    if (
        !isRecord(artifact)
        || !isRecord(source)
        || !isRecord(download)
        || !isRecord(builder)
        || !hasRequiredStrings(artifact, ['url', 'name', 'content_type'])
        || !Number.isFinite(artifact.size_bytes)
        || typeof artifact.one_shot !== 'boolean'
        || !(artifact.expires_at === null || typeof artifact.expires_at === 'string')
        || !hasRequiredStrings(source, ['name', 'path'])
        || !Number.isFinite(source.size_bytes)
        || !hasRequiredStrings(download, ['name', 'mime_type'])
        || typeof download.name_applied !== 'boolean'
        || builder.schema_version !== 1
        || !hasRequiredStrings(builder, [
            'mode',
            'preset',
            'locale',
            'encryption',
            'payload_encoding',
            'output_format',
            'trigger_method',
            'trigger_event',
            'download_variant',
            'page_template',
        ])
        || typeof builder.trigger_event_custom !== 'boolean'
        || typeof builder.notice_shown !== 'boolean'
        || typeof builder.null_byte !== 'boolean'
        || !capabilities.modes.includes(builder.mode)
        || !capabilities.presets.includes(builder.preset)
        || !capabilities.locales.includes(builder.locale)
        || !capabilities.encryption_modes.includes(builder.encryption)
        || !capabilities.payload_encodings.includes(builder.payload_encoding)
        || !capabilities.output_formats.includes(builder.output_format)
        || !Object.prototype.hasOwnProperty.call(
            capabilities.trigger_events,
            builder.trigger_method,
        )
        || !capabilities.download_variants.includes(builder.download_variant)
        || !capabilities.page_templates.includes(builder.page_template)
        || (passwordRequired && (!hasPassword || !isNonemptyString(builder.password)))
        || (!passwordRequired && hasPassword)
    ) {
        return invalidResult();
    }

    let artifactUrl;
    try {
        artifactUrl = new URL(artifact.url, window.location.href).toString();
    } catch (_error) {
        return invalidResult();
    }

    return {
        ok: true,
        model: {
            artifactUrl,
            artifactName: artifact.name,
            sourceName: source.name,
            embeddedName: download.name,
            encryption: builder.encryption,
            encrypted: builder.encryption !== 'none',
            password: builder.password || '',
            effectiveMode: builder.mode,
            effectivePreset: builder.preset,
            outputFormat: builder.output_format,
            payloadEncoding: builder.payload_encoding,
            triggerMethod: builder.trigger_method,
            triggerEvent: builder.trigger_event,
            triggerEventCustom: builder.trigger_event_custom,
            downloadVariant: builder.download_variant,
            pageTemplate: builder.page_template,
            mimeType: download.mime_type,
            nullByte: builder.null_byte,
            noticeShown: builder.notice_shown,
            locale: builder.locale,
            downloadNameApplied: download.name_applied,
        },
        error: null,
    };
}

function buildSmuggleSuccessMarkup(filePath, result, builderState = null) {
    const adaptedResult = getSmuggleResultModel(result);
    if (!adaptedResult.ok) {
        return '';
    }
    const model = adaptedResult.model;
    const rows = [
        [smuggleText('artifactFilename'), model.artifactName, { mono: true }],
        [smuggleText('filenameHandling'), model.downloadNameApplied ? smuggleText('filenameApplied') : smuggleText('filenameBrowserChosen')],
        [smuggleText('encryptionLabel'), `${getSmuggleOptionLabel('encryption', model.encryption)}${model.encrypted ? `: ${smuggleText('manualPasswordForm')}` : ''}`],
        [smuggleText('effectiveMode'), formatSmuggleModeToken(model.effectiveMode)],
        [smuggleText('effectivePreset'), formatSmugglePresetToken(model.effectivePreset)],
        [smuggleText('outerArtifactFormat'), `.${model.outputFormat} (${model.outputFormat})`],
        [smuggleText('payloadEncoding'), getSmuggleOptionLabel('payloadEncoding', model.payloadEncoding)],
        [smuggleText('triggerMethod'), getSmuggleOptionLabel('triggerMethod', model.triggerMethod)],
        [smuggleText('triggerEvent'), getSmuggleOptionLabel('triggerEvent', model.triggerEvent)],
        [smuggleText('downloadVariant'), getSmuggleOptionLabel('downloadVariant', model.downloadVariant)],
        [smuggleText('pageTemplate'), getSmuggleOptionLabel('pageTemplate', model.pageTemplate)],
        [smuggleText('extractedMime'), model.mimeType, { mono: true }],
        [smuggleText('nullByteBeforeArtifact'), model.nullByte ? smuggleText('yes') : smuggleText('no')],
        [smuggleText('noticeShown'), model.noticeShown ? smuggleText('yes') : smuggleText('no')],
        [smuggleText('locale'), model.locale],
    ];
    const passwordMarkup = model.password ? `
        <div class="smuggle-copy-block">
            <div class="smuggle-copy-block__header">
                <span>${esc(t('smugglePassword'))}</span>
                <button type="button" class="btn-ghost btn--sm" data-dialog-action="copy-password">${esc(smuggleText('copyPassword'))}</button>
            </div>
            <code class="smuggle-copy-block__code" id="smuggleResultPassword">${esc(model.password)}</code>
        </div>
    ` : '';
    return `
        <div class="smuggle-result__body">
            <p class="smuggle-dialog__section-title">${esc(smuggleText('successTitle'))}</p>
            <p class="smuggle-dialog__hint">${esc(smuggleText('oneShotWarning'))}</p>
            <div class="smuggle-result__primary">
                <span>${esc(smuggleText('resultDownloadLabel'))}</span>
                <strong>${esc(model.embeddedName)}</strong>
            </div>
            <div class="smuggle-copy-block">
                <div class="smuggle-copy-block__header">
                    <span>${esc(smuggleText('generatedUrl'))}</span>
                </div>
                <code class="smuggle-copy-block__code" id="smuggleResultUrl">${esc(model.artifactUrl)}</code>
            </div>
            ${passwordMarkup}
            <details class="smuggle-dialog__details smuggle-dialog__details--nested" id="smuggleResultDetails">
                <summary>${esc(smuggleText('resultDetailsTitle'))}</summary>
                <div class="smuggle-dialog__details-content">
                    <dl class="smuggle-summary__rows">
                        ${createSmuggleSummaryRows(rows)}
                    </dl>
                </div>
            </details>
            <p class="smuggle-dialog__hint smuggle-result__status" id="smuggleResultStatus" role="status" aria-live="polite" aria-atomic="true">${esc(t('smuggleReady'))}</p>
        </div>
    `;
}

function renderSmuggleSuccess(modal, filePath, result, builderState) {
    const adaptedResult = getSmuggleResultModel(result);
    if (!adaptedResult.ok) {
        return false;
    }
    const panel = modal.querySelector('#smuggleSuccessPanel');
    if (panel) {
        panel.innerHTML = buildSmuggleSuccessMarkup(filePath, result, builderState);
    }
    modal.__smuggleResult = result;
    modal.__smuggleBuilderState = builderState;
    setSmuggleInlineStatus(modal);
    setSmuggleModalPhase(modal, 'success');
    const dialogBody = modal.querySelector('#smuggleDialogBody');
    if (dialogBody) {
        dialogBody.scrollTop = 0;
    }
    setTimeout(() => {
        focusElementWithoutScroll(modal.querySelector('#smuggleCopyUrlBtn'));
    }, 0);
    return true;
}

function showSmuggleDialog(filePath, triggerEl = null, options = {}) {
    const workflowState = refreshSmuggleState();
    if (!workflowState.enabled) {
        return showNoticeDialog({
            title: t('smuggleTitle'),
            message: workflowState.reason || t('smuggleCapabilitiesInvalid'),
            triggerEl,
        });
    }

    const defaults = {
        ...getDefaultSmuggleBuilderState(filePath),
        ...(options.initialState || {}),
        ...(options.builderState || {}),
    };
    const sourceName = defaults.sourceName;

    const modal = openManagedDialog({
        dialogId: 'smuggleModal',
        triggerEl,
        initialFocusSelector: '#smuggleDownloadName',
        restoreFocusOnConfirm: false,
        canDismiss: activeModal => activeModal.dataset.smugglePhase !== 'submitting',
        markup: `
        <div class="modal-overlay smuggle-modal-overlay">
            <div class="modal-content smuggle-dialog" role="dialog" aria-modal="true" aria-labelledby="smuggleDialogTitle" aria-describedby="smuggleDialogHint smuggleInlineStatus" aria-busy="false">
                <div class="smuggle-dialog__header">
                    <div class="smuggle-dialog__heading">
                        <div>
                            <h3 id="smuggleDialogTitle">${esc(t('smuggleTitle'))}</h3>
                            <p class="smuggle-dialog__file" id="smuggleDialogHint">${esc(smuggleText('dialogHint', [sourceName]))}</p>
                        </div>
                        <button type="button" class="btn-ghost btn-icon smuggle-dialog__close" data-dialog-action="close" aria-label="${esc(t('smuggleClose'))}" title="${esc(t('smuggleClose'))}">×</button>
                    </div>
                    <p class="smuggle-dialog__status" id="smuggleInlineStatus" role="alert" tabindex="-1" hidden></p>
                </div>
                <div class="smuggle-dialog__body" id="smuggleDialogBody" tabindex="-1">
                    <div data-smuggle-panel="editing">
                        <div class="smuggle-dialog__layout">
                            <div class="smuggle-dialog__main">
                                <div class="smuggle-dialog__section">
                                    <p class="smuggle-dialog__section-title">${esc(smuggleText('artifactSettings'))}</p>
                                    <div class="smuggle-dialog__grid smuggle-dialog__grid--filename">
                                        <label class="smuggle-dialog__field" for="smuggleDownloadName">
                                            <span>${esc(smuggleText('extractedBaseName'))}</span>
                                            <input type="text" id="smuggleDownloadName" maxlength="${esc(String(getSmuggleFieldLimit('download_name')))}" value="${esc(defaults.downloadName)}" data-smuggle-edit-control>
                                        </label>
                                        <label class="smuggle-dialog__field" for="smuggleDownloadExt">
                                            <span id="smuggleDownloadExtLabel">${esc(smuggleText('extractedExtension'))}</span>
                                            ${buildSmuggleComboboxMarkup('smuggleDownloadExt', defaults.downloadExt, {
                                                labelledBy: 'smuggleDownloadExtLabel',
                                                maxLength: getSmuggleFieldLimit('download_ext') + 1,
                                            })}
                                        </label>
                                    </div>
                                    <p class="smuggle-dialog__resolved-name">${esc(smuggleText('normalizedName'))}: <strong id="smuggleDownloadNamePreview">${esc(resolveSmuggleDownloadName(defaults))}</strong></p>
                                    <p class="smuggle-dialog__hint">${esc(smuggleText('bytesWarning'))}</p>
                                    <div class="smuggle-dialog__grid">
                                        <label class="smuggle-dialog__field" for="smuggleEncryption">
                                            <span id="smuggleEncryptionLabel">${esc(smuggleText('encryptionLabel'))}</span>
                                            ${buildSmuggleComboboxMarkup('smuggleEncryption', defaults.encryption, {
                                                labelledBy: 'smuggleEncryptionLabel',
                                                describedBy: 'smuggleEncryptionDescription',
                                            })}
                                            <span class="smuggle-dialog__info" id="smuggleEncryptionDescription" data-smuggle-description-for="smuggleEncryption"></span>
                                        </label>
                                    </div>
                                </div>

                                <div class="smuggle-dialog__section" data-smuggle-mode-panel="simple">
                                    <p class="smuggle-dialog__section-title">${esc(smuggleText('behaviorTitle'))}</p>
                                    <div class="smuggle-dialog__grid">
                                        <label class="smuggle-dialog__field" for="smugglePreset">
                                            <span id="smugglePresetLabel">${esc(smuggleText('behaviorChoiceLabel'))}</span>
                                            ${buildSmuggleComboboxMarkup('smugglePreset', defaults.preset, {
                                                labelledBy: 'smugglePresetLabel',
                                            })}
                                        </label>
                                    </div>
                                    <p class="smuggle-dialog__hint">${esc(t('smuggleProtectHint'))}</p>
                                </div>

                                <details class="smuggle-dialog__section smuggle-dialog__details" id="smugglePageSettings">
                                    <summary>${esc(smuggleText('textSection'))}</summary>
                                    <div class="smuggle-dialog__details-content">
                                        <div class="smuggle-dialog__grid">
                                            <label class="smuggle-dialog__field" for="smuggleTitleInput">
                                                <span>${esc(smuggleText('titleLabel'))}</span>
                                                <input type="text" id="smuggleTitleInput" maxlength="${esc(String(getSmuggleFieldLimit('title')))}" value="${esc(defaults.title)}" data-smuggle-edit-control>
                                            </label>
                                            <label class="smuggle-dialog__field" for="smuggleCtaLabelInput" id="smuggleCtaRow">
                                                <span>${esc(smuggleText('ctaLabel'))}</span>
                                                <input type="text" id="smuggleCtaLabelInput" maxlength="${esc(String(getSmuggleFieldLimit('cta_label')))}" value="${esc(defaults.ctaLabel)}" data-smuggle-edit-control>
                                            </label>
                                            <label class="smuggle-dialog__field smuggle-dialog__field--wide" for="smuggleMessageInput">
                                                <span>${esc(smuggleText('messageLabel'))}</span>
                                                <textarea id="smuggleMessageInput" maxlength="${esc(String(getSmuggleFieldLimit('message')))}" data-smuggle-edit-control>${esc(defaults.message)}</textarea>
                                            </label>
                                            <label class="smuggle-dialog__field" for="smuggleDelayMs" id="smuggleDelayRow" hidden>
                                                <span>${esc(smuggleText('delayLabel'))}</span>
                                                <input type="number" id="smuggleDelayMs" min="0" max="${esc(String(getSmuggleFieldLimit('delay_ms')))}" step="100" value="${esc(String(defaults.delayMs))}" data-smuggle-edit-control>
                                            </label>
                                        </div>
                                        <label class="checkbox-row smuggle-dialog__toggle" for="smuggleShowNotice">
                                            <input type="checkbox" id="smuggleShowNotice"${defaults.showNotice ? ' checked' : ''} data-smuggle-edit-control>
                                            <span>${esc(smuggleText('noticeLabel'))}</span>
                                        </label>
                                    </div>
                                </details>

                                <details class="smuggle-dialog__section smuggle-dialog__details" id="smuggleAdvancedSettings"${defaults.mode === 'constructor' ? ' open' : ''}>
                                    <summary>${esc(smuggleText('advancedSettingsTitle'))}</summary>
                                    <div class="smuggle-dialog__details-content">
                                        <div class="smuggle-dialog__advanced-block">
                                            <p class="smuggle-dialog__subgroup-title">${esc(smuggleText('sourceDetailsTitle'))}</p>
                                            <div class="smuggle-source-row" aria-label="${esc(t('smuggleBuilderSourceSection'))}">
                                                ${buildSmuggleSourceMarkup(filePath)}
                                            </div>
                                        </div>
                                        <div class="smuggle-dialog__advanced-block">
                                            <p class="smuggle-dialog__subgroup-title" id="smuggleModeTitle">${esc(smuggleText('settingsMode'))}</p>
                                            <label class="checkbox-row smuggle-dialog__toggle" for="smuggleConstructorEnabled">
                                                <input type="checkbox" id="smuggleConstructorEnabled"${defaults.mode === 'constructor' ? ' checked' : ''} data-smuggle-edit-control>
                                                <span>${esc(t('smuggleBuilderConstructorToggle'))}</span>
                                            </label>
                                        </div>
                                        <div class="smuggle-dialog__advanced-block" data-smuggle-mode-panel="constructor" hidden>
                                            <p class="smuggle-dialog__section-title">${esc(smuggleText('constructorSection'))}</p>
                                            <p class="smuggle-dialog__hint">${esc(smuggleText('constructorModeHint'))}</p>
                                            <div class="smuggle-dialog__subgroup" data-smuggle-constructor-group="payload">
                                                <p class="smuggle-dialog__subgroup-title">${esc(t('smuggleBuilderConstructorGroupPayload'))}</p>
                                                <div class="smuggle-dialog__grid">
                                                    <label class="smuggle-dialog__field" for="smugglePayloadEncoding">
                                                        <span class="smuggle-dialog__field-label" id="smugglePayloadEncodingLabel">
                                                            <span>${esc(smuggleText('payloadEncoding'))}</span>
                                                        </span>
                                                        ${buildSmuggleComboboxMarkup('smugglePayloadEncoding', defaults.payloadEncoding, {
                                                            labelledBy: 'smugglePayloadEncodingLabel',
                                                            describedBy: 'smugglePayloadEncodingDescription',
                                                            constructorField: true,
                                                        })}
                                                        <span class="smuggle-dialog__info" id="smugglePayloadEncodingDescription" data-smuggle-description-for="smugglePayloadEncoding"></span>
                                                    </label>
                                                </div>
                                            </div>
                                            <div class="smuggle-dialog__subgroup" data-smuggle-constructor-group="trigger">
                                                <p class="smuggle-dialog__subgroup-title">${esc(t('smuggleBuilderConstructorGroupTrigger'))}</p>
                                                <div class="smuggle-dialog__grid">
                                                    <label class="smuggle-dialog__field" for="smuggleTriggerMethod">
                                                        <span class="smuggle-dialog__field-label" id="smuggleTriggerMethodLabel">
                                                            <span>${esc(smuggleText('triggerMethod'))}</span>
                                                        </span>
                                                        ${buildSmuggleComboboxMarkup('smuggleTriggerMethod', defaults.triggerMethod, {
                                                            labelledBy: 'smuggleTriggerMethodLabel',
                                                            describedBy: 'smuggleTriggerMethodDescription',
                                                            constructorField: true,
                                                        })}
                                                        <span class="smuggle-dialog__info" id="smuggleTriggerMethodDescription" data-smuggle-description-for="smuggleTriggerMethod"></span>
                                                    </label>
                                                    <label class="smuggle-dialog__field" for="smuggleTriggerEvent">
                                                        <span id="smuggleTriggerEventLabel">${esc(smuggleText('triggerEvent'))}</span>
                                                        ${buildSmuggleComboboxMarkup('smuggleTriggerEvent', defaults.triggerEvent, {
                                                            labelledBy: 'smuggleTriggerEventLabel',
                                                            describedBy: 'smuggleTriggerEventDescription',
                                                            constructorField: true,
                                                            maxLength: getSmuggleFieldLimit('trigger_event'),
                                                        })}
                                                        <span class="smuggle-dialog__info" id="smuggleTriggerEventDescription" data-smuggle-description-for="smuggleTriggerEvent"></span>
                                                    </label>
                                                </div>
                                            </div>
                                            <div class="smuggle-dialog__subgroup" data-smuggle-constructor-group="output">
                                                <p class="smuggle-dialog__subgroup-title">${esc(t('smuggleBuilderConstructorGroupOutput'))}</p>
                                                <div class="smuggle-dialog__grid">
                                                    <label class="smuggle-dialog__field" for="smuggleOutputFormat">
                                                        <span class="smuggle-dialog__field-label" id="smuggleOutputFormatLabel">
                                                            <span>${esc(smuggleText('outerArtifactFormat'))}</span>
                                                        </span>
                                                        ${buildSmuggleComboboxMarkup('smuggleOutputFormat', defaults.outputFormat, {
                                                            labelledBy: 'smuggleOutputFormatLabel',
                                                            describedBy: 'smuggleOutputFormatDescription',
                                                            constructorField: true,
                                                        })}
                                                        <span class="smuggle-dialog__info" id="smuggleOutputFormatDescription" data-smuggle-description-for="smuggleOutputFormat"></span>
                                                    </label>
                                                    <label class="smuggle-dialog__field" for="smuggleDownloadVariant">
                                                        <span class="smuggle-dialog__field-label" id="smuggleDownloadVariantLabel">
                                                            <span>${esc(smuggleText('downloadVariant'))}</span>
                                                        </span>
                                                        ${buildSmuggleComboboxMarkup('smuggleDownloadVariant', defaults.downloadVariant, {
                                                            labelledBy: 'smuggleDownloadVariantLabel',
                                                            describedBy: 'smuggleDownloadVariantDescription',
                                                            constructorField: true,
                                                        })}
                                                        <span class="smuggle-dialog__info" id="smuggleDownloadVariantDescription" data-smuggle-description-for="smuggleDownloadVariant"></span>
                                                    </label>
                                                    <label class="smuggle-dialog__field" for="smugglePageTemplate">
                                                        <span class="smuggle-dialog__field-label" id="smugglePageTemplateLabel">
                                                            <span>${esc(smuggleText('pageTemplate'))}</span>
                                                        </span>
                                                        ${buildSmuggleComboboxMarkup('smugglePageTemplate', defaults.pageTemplate, {
                                                            labelledBy: 'smugglePageTemplateLabel',
                                                            describedBy: 'smugglePageTemplateDescription',
                                                            constructorField: true,
                                                        })}
                                                        <span class="smuggle-dialog__info" id="smugglePageTemplateDescription" data-smuggle-description-for="smugglePageTemplate"></span>
                                                    </label>
                                                    <label class="smuggle-dialog__field smuggle-dialog__field--wide" for="smuggleMimeType">
                                                        <span id="smuggleMimeTypeLabel">${esc(smuggleText('extractedMime'))}</span>
                                                        ${buildSmuggleComboboxMarkup('smuggleMimeType', defaults.mimeType, {
                                                            labelledBy: 'smuggleMimeTypeLabel',
                                                            describedBy: 'smuggleMimeTypeDescription',
                                                            constructorField: true,
                                                            maxLength: getSmuggleFieldLimit('mime_type') * 2,
                                                        })}
                                                        <span class="smuggle-dialog__info" id="smuggleMimeTypeDescription">${esc(smuggleText('bytesWarning'))}</span>
                                                    </label>
                                                </div>
                                                <label class="checkbox-row smuggle-dialog__toggle" for="smuggleNullByte">
                                                    <input type="checkbox" id="smuggleNullByte"${defaults.nullByte ? ' checked' : ''} data-smuggle-constructor-field="true" data-smuggle-edit-control>
                                                    <span>${esc(smuggleText('nullByteBeforeArtifact'))}</span>
                                                </label>
                                            </div>
                                        </div>
                                        <div class="smuggle-dialog__notice" hidden>
                                            <ul id="smuggleCompatibilityList"></ul>
                                        </div>
                                    </div>
                                </details>
                            </div>
                        </div>
                    </div>
                    <div data-smuggle-panel="success" hidden>
                        <div class="smuggle-dialog__section" id="smuggleSuccessPanel"></div>
                    </div>
                </div>
                <div class="modal-actions smuggle-dialog__footer">
                    <div class="smuggle-dialog__actions" data-smuggle-actions="editing">
                        <button type="button" class="btn-opsec" id="smuggleSubmitBtn" data-dialog-action="confirm">${esc(t('smuggleGenerate'))}</button>
                        <button type="button" class="btn-ghost" id="smuggleCancelBtn" data-dialog-action="cancel">${esc(t('smuggleCancel'))}</button>
                    </div>
                    <div class="smuggle-dialog__actions smuggle-result__actions" data-smuggle-actions="success" hidden>
                        <button type="button" class="btn-info" id="smuggleCopyUrlBtn" data-dialog-action="copy-url">${esc(t('smuggleCopyUrl'))}</button>
                        <button type="button" class="btn-opsec" id="smuggleOpenBtn" data-dialog-action="open">${esc(smuggleText('openRun'))}</button>
                        <button type="button" class="btn-ghost" id="smuggleSaveBtn" data-dialog-action="save">${esc(smuggleText('downloadHtml'))}</button>
                        <button type="button" class="btn-ghost" id="smuggleEditBtn" data-dialog-action="edit-settings">${esc(smuggleText('editSettings'))}</button>
                        <button type="button" class="btn-ghost" id="smuggleCloseBtn" data-dialog-action="close">${esc(t('smuggleClose'))}</button>
                    </div>
                </div>
            </div>
        </div>
    `,
        onAction: async (action, activeModal) => {
            if (action === 'cancel' || action === 'close') {
                activeSmuggleModals.delete(activeModal);
                return false;
            }
            const liveRegionId = options.liveRegionId || 'filesResponseAreaLive';
            const result = activeModal.__smuggleResult || null;
            const adaptedResult = result ? getSmuggleResultModel(result) : null;
            const resultModel = adaptedResult?.ok ? adaptedResult.model : null;
            if (action === 'confirm') {
                if (activeModal.dataset.smugglePhase === 'submitting') {
                    return undefined;
                }
                if (!validateSmuggleComboboxes(activeModal, { focusFirst: true })) {
                    setSmuggleInlineStatus(activeModal, smuggleText('retryAfterEdit'), 'error');
                    return undefined;
                }
                const builderState = readSmuggleBuilderState(activeModal, filePath);
                activeModal.__smuggleRequestSeq = (activeModal.__smuggleRequestSeq || 0) + 1;
                const requestSeq = activeModal.__smuggleRequestSeq;
                setSmuggleInlineStatus(activeModal, smuggleText('submitting'));
                setSmuggleModalPhase(activeModal, 'submitting');
                if (typeof options.onConfirm === 'function') {
                    try {
                        const customResult = await options.onConfirm(builderState, activeModal);
                        if (!activeModal.isConnected || activeModal.__smuggleRequestSeq !== requestSeq) {
                            return undefined;
                        }
                        if (customResult && typeof customResult === 'object') {
                            renderSmuggleSuccess(activeModal, filePath, customResult, builderState);
                        } else {
                            resetSmuggleEditingPhase(activeModal, filePath);
                        }
                    } catch (error) {
                        if (activeModal.isConnected && activeModal.__smuggleRequestSeq === requestSeq) {
                            resetSmuggleEditingPhase(activeModal, filePath);
                            setSmuggleInlineStatus(activeModal, error?.message || String(error), 'error');
                            setSmuggleFieldError(activeModal, error?.field, error?.message);
                            focusSmuggleRetryTarget(activeModal, error?.field);
                        }
                    }
                } else {
                    await executeSmuggle(filePath, builderState, triggerEl, {
                        ...(options.executionOptions || {}),
                        modal: activeModal,
                        requestSeq,
                    });
                }
                return undefined;
            }
            if (action === 'edit-settings') {
                resetSmuggleEditingPhase(activeModal, filePath);
                focusElementWithoutScroll(activeModal.querySelector('#smuggleDownloadName'));
                return undefined;
            }
            if (!resultModel) {
                return undefined;
            }
            if (action === 'copy-url') {
                try {
                    await writeTextToClipboard(resultModel.artifactUrl, 'smuggle-url');
                    setSmuggleResultStatus(activeModal, t('smuggleCopied'), 'ok');
                    announceLiveRegion(liveRegionId, `SMUGGLE ${filePath} ${t('smuggleCopied')}`);
                } catch (error) {
                    const message = formatActionErrorMessage(t('clipboardCopyFailed'), error);
                    setSmuggleResultStatus(activeModal, message, 'error');
                    announceLiveRegion(liveRegionId, `SMUGGLE ${filePath} ${message}`);
                }
                return undefined;
            }
            if (action === 'copy-password') {
                try {
                    await writeTextToClipboard(resultModel.password, 'smuggle-password');
                    setSmuggleResultStatus(activeModal, smuggleText('copied'), 'ok');
                } catch (error) {
                    setSmuggleResultStatus(activeModal, formatActionErrorMessage(smuggleText('copyFailed'), error), 'error');
                }
                return undefined;
            }
            if (action === 'open') {
                const popup = window.open(resultModel.artifactUrl, '_blank');
                if (!popup) {
                    const message = formatActionErrorMessage(t('smuggleOpen'), new Error(t('error')));
                    setSmuggleResultStatus(activeModal, message, 'error');
                    announceLiveRegion(liveRegionId, `SMUGGLE ${filePath} ${message}`);
                    return undefined;
                }
                setSmuggleResultStatus(activeModal, t('smuggleOpened'), 'ok');
                announceLiveRegion(liveRegionId, `SMUGGLE ${filePath} ${t('smuggleOpened')}`);
                return undefined;
            }
            if (action === 'save') {
                triggerSmuggleArtifactDownload(resultModel.artifactUrl, resultModel.artifactName);
                setSmuggleResultStatus(activeModal, `${t('downloadStarted')}: ${resultModel.artifactName}`, 'ok');
                announceLiveRegion(liveRegionId, `${t('downloadStarted')}: ${resultModel.artifactName}`);
                return undefined;
            }
            return undefined;
        },
    });

    if (!modal) {
        return;
    }

    activeSmuggleModals.add(modal);
    initializeSmuggleComboboxes(modal, filePath, defaults);
    modal.querySelectorAll('input:not([data-smuggle-combobox-input]), select, textarea').forEach(control => {
        const eventName = control.tagName === 'SELECT' ? 'change' : 'input';
        control.addEventListener(eventName, () => {
            control.removeAttribute('aria-invalid');
            control.removeAttribute('aria-errormessage');
            syncSmuggleBuilderUi(modal, filePath);
        });
        if (control.type === 'checkbox' || control.type === 'radio') {
            control.addEventListener('change', () => syncSmuggleBuilderUi(modal, filePath));
        }
    });
    setSmuggleModalPhase(modal, 'editing');
    syncSmuggleBuilderUi(modal, filePath);
    modal.__smuggleRequestSeq = 0;
    void hydrateSmuggleSourceInfo(filePath, modal);
    if (options.initialResult) {
        renderSmuggleSuccess(modal, filePath, options.initialResult, defaults);
    }
}

function buildSmuggleResponseSummary(result) {
    const adaptedResult = getSmuggleResultModel(result);
    if (!adaptedResult.ok) {
        return `${adaptedResult.error.message} (${adaptedResult.error.code})`;
    }
    const model = adaptedResult.model;
    const lines = [
        model.sourceName,
        `${smuggleText('generatedUrl')}: ${model.artifactUrl}`,
        `${smuggleText('artifactFilename')}: ${model.artifactName}`,
        `${smuggleText('embeddedFilename')}: ${model.embeddedName}`,
        `${smuggleText('filenameHandling')}: ${model.downloadNameApplied ? smuggleText('filenameApplied') : smuggleText('filenameBrowserChosen')}`,
        `${smuggleText('encryptionLabel')}: ${getSmuggleOptionLabel('encryption', model.encryption)}`,
        `${smuggleText('effectiveMode')}: ${model.effectiveMode}`,
        `${smuggleText('effectivePreset')}: ${model.effectivePreset}`,
        `${smuggleText('outerArtifactFormat')}: ${model.outputFormat}`,
        `${smuggleText('payloadEncoding')}: ${model.payloadEncoding}`,
        `${smuggleText('triggerMethod')}: ${model.triggerMethod}`,
        `${smuggleText('triggerEvent')}: ${model.triggerEvent}`,
        `${smuggleText('downloadVariant')}: ${model.downloadVariant}`,
        `${smuggleText('pageTemplate')}: ${model.pageTemplate}`,
        `${smuggleText('extractedMime')}: ${model.mimeType}`,
        `${smuggleText('nullByteBeforeArtifact')}: ${model.nullByte ? smuggleText('yes') : smuggleText('no')}`,
        `${smuggleText('noticeShown')}: ${model.noticeShown ? smuggleText('yes') : smuggleText('no')}`,
        `${smuggleText('locale')}: ${model.locale}`,
    ];
    if (model.password) {
        lines.push(`${t('smugglePassword')}: ${model.password}`);
    }
    lines.push('', t('smuggleReady'), smuggleText('oneShotWarning'));
    return lines.join('\n');
}

function setSmuggleResultStatus(modal, message, tone = '') {
    const statusEl = modal.querySelector('#smuggleResultStatus');
    if (!statusEl) {
        return;
    }
    statusEl.textContent = message;
    statusEl.className = `smuggle-dialog__hint smuggle-result__status${tone ? ` smuggle-result__status--${tone}` : ''}`;
}

function triggerSmuggleArtifactDownload(artifactUrl, artifactName) {
    const link = document.createElement('a');
    link.href = artifactUrl;
    link.download = artifactName;
    document.body.appendChild(link);
    link.click();
    link.remove();
}

function showSmuggleResultDialog(filePath, result, triggerEl = null, options = {}) {
    return showSmuggleDialog(filePath, triggerEl, {
        ...options,
        initialResult: result,
        initialState: options.builderState || options.initialState || {},
    });
}

async function executeSmuggle(filePath, builderState, triggerEl = null, options = {}) {
    const liveRegionId = options.liveRegionId || 'filesResponseAreaLive';
    const activeModal = options.modal || null;
    const requestSeq = options.requestSeq || 0;
    const requestPath = buildSmuggleRequestPath(filePath, builderState);
    const url = SERVER_URL + requestPath;
    const shouldUpdateModal = () => !activeModal
        || (activeModal.isConnected && (!requestSeq || activeModal.__smuggleRequestSeq === requestSeq));
    try {
        setExchangeInspector('files', {
            phase: 'sending',
            request: {
                transport: 'http',
                method: 'SMUGGLE',
                path: requestPath,
                headers: {},
                body: null,
            },
            response: {
                phase: 'sending',
                summaryText: `SMUGGLE ${filePath}`,
                startLine: `SMUGGLE ${requestPath}`,
                body: createExchangeTextBody(t('statusPending')),
            },
        });
        const response = await sendCustomRequest('SMUGGLE', url);
        const text = await response.text();
        if (!shouldUpdateModal()) {
            return null;
        }

        if (response.status === 200) {
            const result = parseSmuggleJson(text);
            const adaptedResult = getSmuggleResultModel(result);
            if (!adaptedResult.ok) {
                const invalidError = adaptedResult.error;
                const message = `${invalidError.message} (${invalidError.code})`;
                announceLiveRegion(liveRegionId, `SMUGGLE ${filePath} ${t('error')}: ${message}`);
                setExchangeInspector('files', {
                    phase: 'error',
                    request: {
                        transport: 'http',
                        method: 'SMUGGLE',
                        path: requestPath,
                        headers: {},
                        body: null,
                    },
                    response: {
                        transport: 'http',
                        method: 'SMUGGLE',
                        path: filePath,
                        phase: 'error',
                        summaryText: message,
                        startLine: `SMUGGLE ${requestPath}\n${t('error')}`,
                        status: response.status,
                        statusText: response.statusText || t('error'),
                        headers: response.headers,
                        body: createExchangeTextBody(message, { contentType: 'text/plain' }),
                    },
                });
                if (activeModal) {
                    resetSmuggleEditingPhase(activeModal, filePath);
                    setSmuggleInlineStatus(activeModal, message, 'error');
                    setSmuggleFieldError(activeModal, invalidError.field, invalidError.message);
                    focusSmuggleRetryTarget(activeModal, invalidError.field);
                } else if (triggerEl) {
                    focusElementWithoutScroll(triggerEl);
                }
                return null;
            }
            const resultModel = adaptedResult.model;
            const responseSummary = buildSmuggleResponseSummary(result);
            setExchangeInspector('files', {
                phase: 'complete',
                request: {
                    transport: 'http',
                    method: 'SMUGGLE',
                    path: requestPath,
                    headers: {},
                    body: null,
                },
                response: {
                    transport: 'http',
                    method: 'SMUGGLE',
                    path: filePath,
                    phase: 'complete',
                    summaryText: `${t('smuggleGenerated')}: ${resultModel.embeddedName}`,
                    startLine: `SMUGGLE ${requestPath}\n${t('smuggleGenerated')}`,
                    status: 200,
                    statusText: 'OK',
                    headers: response.headers,
                    body: createExchangeTextBody(responseSummary, { contentType: 'text/plain' }),
                },
            });
            announceLiveRegion(liveRegionId, `SMUGGLE ${filePath} ${t('smuggleGenerated')}`);
            if (activeModal) {
                renderSmuggleSuccess(activeModal, filePath, result, builderState);
            } else {
                showSmuggleResultDialog(filePath, result, triggerEl, { liveRegionId, builderState });
            }
            return result;
        } else {
            const payload = parseSmuggleJson(text);
            const message = resolveSmuggleErrorMessage(response, text, payload);
            announceLiveRegion(liveRegionId, `SMUGGLE ${filePath} ${t('error')}`);
            setExchangeInspector('files', {
                phase: 'error',
                request: {
                    transport: 'http',
                    method: 'SMUGGLE',
                    path: requestPath,
                    headers: {},
                    body: null,
                },
                response: {
                    transport: 'http',
                    method: 'SMUGGLE',
                    path: filePath,
                    phase: 'error',
                    summaryText: message,
                    startLine: `SMUGGLE ${requestPath}\n${t('error')}`,
                    status: response.status,
                    statusText: response.statusText || t('error'),
                    headers: response.headers,
                    body: createExchangeTextBody(text || message),
                },
            });
            if (activeModal) {
                resetSmuggleEditingPhase(activeModal, filePath);
                setSmuggleInlineStatus(activeModal, message, 'error');
                const errorPayload = payload?.error && typeof payload.error === 'object'
                    ? payload.error
                    : null;
                setSmuggleFieldError(activeModal, errorPayload?.field, errorPayload?.message);
                focusSmuggleRetryTarget(activeModal, errorPayload?.field);
            } else if (triggerEl) {
                focusElementWithoutScroll(triggerEl);
            }
            return null;
        }
    } catch (error) {
        if (!shouldUpdateModal()) {
            return null;
        }
        const message = `${smuggleText('errorNetwork')} ${error?.message || String(error)}`.trim();
        announceLiveRegion(liveRegionId, `SMUGGLE ${filePath} ${t('error')}: ${error?.message || String(error)}`);
        setExchangeInspector('files', {
            phase: 'error',
            request: {
                transport: 'http',
                method: 'SMUGGLE',
                path: requestPath,
                headers: {},
                body: null,
            },
            response: {
                transport: 'http',
                method: 'SMUGGLE',
                path: filePath,
                phase: 'error',
                summaryText: message,
                startLine: `SMUGGLE ${requestPath}\n${t('error')}`,
                body: createExchangeTextBody(message),
            },
        });
        if (activeModal) {
            resetSmuggleEditingPhase(activeModal, filePath);
            setSmuggleInlineStatus(activeModal, message, 'error');
            focusSmuggleRetryTarget(activeModal);
        } else if (triggerEl) {
            focusElementWithoutScroll(triggerEl);
        }
        return null;
    }
}


app.on(app.events.SERVER_METHODS_CHANGED, refreshSmuggleState);

app.registerWorkflow('smuggle', {
    commands: {
        'build-request-path': buildSmuggleRequestPath,
        'resolve-download-name': resolveSmuggleDownloadName,
        'adapt-result': getSmuggleResultModel,
        'build-response-summary': buildSmuggleResponseSummary,
        'show-dialog': showSmuggleDialog,
        'show-result': showSmuggleResultDialog,
        execute: executeSmuggle,
    },
    getState: () => ({
        ...refreshSmuggleState(),
    }),
});
})(window.XferryApp);
