(function initializeCore(app) {
    'use strict';

function safeGetStorageItem(key) {
    try {
        return localStorage.getItem(key);
    } catch (error) {
        return null;
    }
}

function safeSetStorageItem(key, value) {
    try {
        localStorage.setItem(key, value);
    } catch (error) {
        // Storage is optional; the current in-memory preference still applies.
    }
}

function syncThemeAssets() {
    const isLight = document.documentElement.getAttribute('data-theme') === 'light';
    const sourceKey = isLight ? 'themeLight' : 'themeDark';
    for (const [elementId, attribute] of [
        ['brandMark', 'src'],
        ['appFavicon', 'href'],
    ]) {
        const element = document.getElementById(elementId);
        const nextSource = element?.dataset[sourceKey];
        if (element && nextSource && element.getAttribute(attribute) !== nextSource) {
            element.setAttribute(attribute, nextSource);
        }
    }
}

function syncThemeButtonState() {
    syncThemeAssets();
    const btn = document.getElementById('themeBtn');
    if (!btn) {
        return;
    }

    const isLight = document.documentElement.getAttribute('data-theme') === 'light';
    const label = t(isLight ? 'themeLightCurrentLabel' : 'themeDarkCurrentLabel');
    btn.textContent = isLight ? '☀️' : '🌙';
    btn.setAttribute('aria-pressed', String(isLight));
    btn.setAttribute('aria-label', label);
    btn.title = label;
}

function toggleTheme() {
    const html = document.documentElement;
    const current = html.getAttribute('data-theme');
    const next = current === 'light' ? 'dark' : 'light';
    if (next === 'light') {
        html.setAttribute('data-theme', 'light');
    } else {
        html.removeAttribute('data-theme');
    }
    safeSetStorageItem('theme', next);
    syncThemeButtonState();
}

// Update theme button icon on load
document.addEventListener('DOMContentLoaded', () => {
    syncThemeButtonState();
});

// ===== Система локализации =====
const translations = {
    ru: {
        brandTagline: "Инструмент для тестирования SWG",
        langRussianSelectedLabel: "Русский язык выбран",
        langRussianSelectLabel: "Переключить на русский язык",
        langEnglishSelectedLabel: "Английский язык выбран",
        langEnglishSelectLabel: "Переключить на английский язык",
        themeDarkCurrentLabel: "Тёмная тема включена. Переключить на светлую",
        themeLightCurrentLabel: "Светлая тема включена. Переключить на тёмную",
        quickRequestMethodsLabel: "Методы запроса",
        serverModesLabel: "Режимы сервера",
        browseRootLabel: "Перейти в корень",
        browseUpLabel: "На уровень выше",
        httpMethodLabel: "HTTP-метод",
        randomLabel: "Случайно",
        refreshLabel: "Обновить",
        heroWorkingPanelEyebrow: "РАБОЧАЯ ПАНЕЛЬ",
        heroWorkingPanelTitle: "Проверяйте HTTP-пути передачи данных",
        heroResponsePanelEyebrow: "ОТВЕТ",
        heroResponsePanelTitle: "Ответы и артефакты проверки",
        toolResultEyebrow: "РЕЗУЛЬТАТ",
        toolTraceSummary: "Технические детали",
        toolPhaseIdle: "Без действий",
        toolPhaseReady: "Подготовлено",
        toolPhasePending: "Выполняется",
        toolPhaseSuccess: "Готово",
        toolPhaseError: "Ошибка",
        uploadResultIdleTitle: "Файл ещё не отправлен",
        uploadResultIdleBody: "Выберите файл и нажмите «Отправить».",
        uploadResultServerPath: "Путь на сервере",
        uploadResultSize: "Размер",
        uploadResultTraceAction: "Открыть технические детали",
        uploadResultFilesAction: "Открыть Файлы",
        filesResultIdleTitle: "Пока без действий с файлами",
        filesResultIdleBody: "Откройте папку, скачайте файл, удалите выбранное или очистите uploads/.",
        opsecResultIdleTitle: "Пока без продвинутой загрузки",
        opsecResultIdleBody: "Выберите файл и настройте метод и транспорт перед отправкой.",
        opsecPreviewReady: "Запрос готов к отправке",
        advancedLabel: "Расширенные инструменты",
        methodGet: "Получение ресурсов",
        methodHead: "Проверка заголовков",
        methodPost: "Отправка данных",
        methodDelete: "Удаление ресурса",
        methodOptions: "Проверка доступных методов",
        methodFetch: "Скачивание файлов",
        methodInfo: "Метаданные файла",
        methodPing: "Проверка сервера",
        methodNone: "Загрузка файлов",
        methodPut: "Загрузка/замена",
        methodPatch: "Обновление файлов",
        methodNote: "Проверка ECDH-ключа блокнота",
        methodSmuggle: "HTML Smuggling",
        tabRequests: "Запросы",
        tabUpload: "Отправить",
        tabFiles: "Файлы",
        tabOpsec: "Расширенные",
        labelFilePath: "Путь к файлу",
        labelDirPath: "Путь к директории",
        pathPlaceholder: "/index.html или /uploads/",
        requestPreviewModeLabel: "Режим показа запроса и ответа",
        requestPreviewModeSummary: "Сводка",
        requestPreviewModeRaw: "Исходный HTTP",
        requestTechnicalDetailsSummary: "Технические запросы",
        requestTechnicalDetailsHint: "Методы, исходный HTTP и пакетный прогон",
        requestRunAllBtn: "Прогнать все",
        requestBatchDetailsSummary: "Матрица методов",
        requestBatchRerunIssuesBtn: "Повторить проблемы",
        requestBatchRerunIssuesLabel: "Повторить только проблемные методы",
        requestBatchRerunIssuesStarted: "Повтор проблемных методов начат",
        requestBatchRerunIssuesCompleted: "Повтор проблемных методов завершён, осталось проблем",
        requestBatchExportBtn: "Экспорт JSON",
        requestBatchExportLabel: "Скачать JSON-отчёт прогона",
        requestBatchExported: "JSON-отчёт прогона выгружен",
        requestBatchExportFailed: "Не удалось выгрузить JSON-отчёт прогона",
        requestBatchClearBtn: "Очистить",
        requestBatchClearLabel: "Очистить результат прогона",
        requestBatchCleared: "Результат прогона очищен",
        requestBatchIssuesOnlyLabel: "Только проблемы",
        requestBatchNoIssues: "Все методы отработали без ошибок.",
        requestBatchNoIssuesYet: "Пока все методы работают без ошибок.",
        requestBatchRerunLabel: "Повторить метод",
        requestBatchRerunCompleted: "Повторный запуск завершён",
        requestBatchAttempts: "Попыток",
        requestBatchAttempt: "Попытка",
        requestBatchAttemptHistory: "История попыток",
        requestBatchLastRerun: "Последний повтор",
        requestBatchRerunFixed: "Исправлено",
        requestBatchRerunStillFailing: "Проблема осталась",
        requestBatchRerunRegressed: "Стало проблемой",
        requestBatchRerunStillOk: "Снова OK",
        requestBatchRunning: "Выполняется",
        requestBatchCompleted: "Готово",
        requestBatchTotal: "Всего",
        requestBatchMatches: "Работает",
        requestBatchMismatches: "Не работает",
        requestBatchFailed: "Ошибок",
        copyRawRequestBtn: "Копировать запрос",
        copyRawResponseBtn: "Копировать ответ",
        copyRawRequestLabel: "Скопировать исходный запрос",
        copyRawResponseLabel: "Скопировать исходный ответ",
        downloadRawRequestBtn: "Скачать запрос",
        downloadRawResponseBtn: "Скачать ответ",
        downloadRawRequestLabel: "Скачать HTTP-запрос",
        downloadRawResponseLabel: "Скачать HTTP-ответ",
        requestPreviewCopied: "Исходный запрос скопирован",
        responseCopied: "Исходный ответ скопирован",
        clipboardCopyFailed: "Не удалось скопировать в буфер обмена",
        requestPreviewEmpty: "Выберите метод, чтобы увидеть исходящий HTTP-запрос.",
        requestPreviewPreparing: "Подготовка демонстрационного сценария перед отправкой основного запроса...",
        requestPreviewFieldMethod: "Метод",
        requestPreviewFieldPath: "Путь",
        requestPreviewFieldExpectedStatus: "Ожидаемый статус",
        requestPreviewFieldActualStatus: "Фактический статус",
        requestPreviewFieldCheck: "Проверка",
        requestPreviewFieldHost: "Host",
        requestPreviewFieldHeaderCount: "Заголовки",
        requestPreviewFieldBodySize: "Размер тела",
        responseSummaryFieldStatus: "Статус",
        responseSummaryFieldContentType: "Content-Type",
        requestBody: "Тело запроса",
        requestPreviewNoBody: "Без тела",
        exchangeRequestTitle: "Исходящий запрос",
        exchangeResponseTitle: "Входящий ответ",
        uploadRawHttpRequestTitle: "Исходный HTTP-запрос",
        uploadRawHttpResponseTitle: "Исходный HTTP-ответ",
        opsecRawHttpRequestTitle: "Исходный HTTP-запрос",
        opsecRawHttpResponseTitle: "Исходный HTTP-ответ",
        exchangeRequestEmpty: "Запрос появится здесь после действия.",
        exchangeResponseEmpty: "Ответ появится здесь после выполнения запроса.",
        exchangeCopied: "Исходные данные скопированы",
        exchangeLogDownloaded: "HTTP-лог сохранён",
        exchangeLogDownloadFailed: "Не удалось сохранить HTTP-лог",
        exchangeLogSensitiveHint: "Лог может содержать данные, ключи или cookie.",
        exchangeBrowserManagedNote: "Данные, которыми управляет браузер",
        exchangeCookieHeaderManaged: "Заголовок Cookie отправляет браузер; значения ниже будут записаны в document.cookie перед отправкой.",
        exchangeMultipartBoundaryManaged: "Границу multipart и Content-Length выставляет браузер; точные байты тела недоступны из JS в браузере.",
        exchangeTransport: "Транспорт",
        exchangeBodyKind: "Тип тела",
        exchangeBinaryBody: "Бинарные данные",
        exchangeBinaryBodyPreview: "Превью тела",
        exchangeBinaryBodyPreviewPending: "Тело файла будет передано здесь; превью появится после чтения первых байтов.",
        exchangeHexPreview: "Hex-превью",
        exchangeTruncated: "усечено, осталось символов/байт",
        exchangeRedacted: "скрыто",
        exchangeWsSend: "WS отправка",
        exchangeWsReceive: "WS получение",
        fileName: "Имя файла",
        requestPreviewCheckPending: "Ожидание ответа",
        requestPreviewCheckMatch: "Совпадает",
        requestPreviewCheckMismatch: "Не совпадает",
        requestPreviewCheckFailed: "Ошибка запроса",
        dropFilesHere: "Выберите файлы или перетащите сюда",
        uploadDropZoneLabel: "Выбрать файлы для обычной загрузки",
        uploadMethodLabel: "Метод обычной загрузки",
        uploadSelectionIdle: "Файлы не выбраны",
        uploadProfileLabel: "Профиль запроса",
        uploadProfileMultipart: "Multipart",
        uploadProfileRawUrl: "Raw URL",
        uploadProfileRawHeader: "Raw Header",
        uploadRequestSummaryTitle: "Запрос перед отправкой",
        uploadSummaryRequestLine: "Строка запроса",
        uploadSummaryBodyKind: "Тело",
        uploadSummaryMime: "MIME",
        uploadSummaryFilenameSource: "Источник имени",
        uploadBodyKindMultipart: "multipart/form-data, поле file",
        uploadBodyKindRaw: "сырые байты файла",
        uploadFilenameSourcePart: "имя части multipart",
        uploadFilenameSourceUrl: "сегмент URL",
        uploadFilenameSourceHeader: "заголовок X-File-Name",
        uploadCompareBtn: "Сравнить 3 профиля",
        uploadCompareConfirmTitle: "Создать три файла?",
        uploadCompareConfirmBody: "Сравнение последовательно отправит один файл через Multipart, Raw URL и Raw Header и создаст три файла на сервере.",
        uploadCompareConfirmAction: "Создать 3 файла",
        uploadCompareResultsTitle: "Сравнение профилей",
        uploadCompareRunning: "Сравниваем профили…",
        uploadCompareProfileLabel: "Профиль",
        uploadCompareVerdictLabel: "Результат",
        uploadCompareRequestLabel: "Запрос",
        uploadCompareResponseLabel: "Ответ",
        uploadVerdictDelivered: "доставлено",
        uploadVerdictMetadataChanged: "метаданные изменены",
        uploadVerdictContentChanged: "содержимое изменено",
        uploadVerdictRejected: "отклонено с ответом",
        uploadVerdictNotConfirmed: "не подтверждено",
        uploadVerdictNotRun: "не запускалось",
        uploadCollisionRenamed: "Сервер изменил имя из-за совпадения; это не влияет на результат.",
        uploadRoutingConflict: "Обычная загрузка доступна независимо от продвинутой сессии.",
        uploadRoutingUnknown: "Обычная загрузка доступна.",
        uploadFlowLabel: "Логика обычной загрузки",
        uploadFlowMethodTitle: "Метод",
        uploadFlowMethodBody: "HTTP-метод меняет форму запроса; тело файла отправляется на сервер.",
        uploadFlowFilesTitle: "Файлы",
        uploadFlowFilesBody: "Выбранные файлы попадают в очередь и отправляются по одному.",
        uploadFlowServerTitle: "uploads/",
        uploadFlowServerBody: "Сервер сохраняет копию и возвращает путь в результате.",
        uploadHelpTitle: "Как работает обычная загрузка",
        uploadHelpSummary: "Метод, очередь, сохранение и технические детали",
        uploadHelpMethodsTitle: "Методы",
        uploadHelpMethodsBody: "POST, NONE, PUT и PATCH используют один обработчик загрузки: тело запроса сохраняется как файл. Метод нужен для проверки конкретной HTTP-формы.",
        uploadHelpDestinationTitle: "Куда попадает файл",
        uploadHelpDestinationBody: "После успешной отправки сервер пишет файл в uploads/. Путь вида /uploads/имя видно в результате и в ответе сервера.",
        uploadHelpTraceTitle: "Что смотреть после отправки",
        uploadHelpTraceBody: "Результат показывает статус и путь. Технические детали раскрывают исходящий запрос и входящий ответ.",
        selectedLabel: "Выбрано",
        selectedFilesCount: "Файлов выбрано",
        uploadAllBtn: "Отправить",
        advancedSessionEyebrow: "СЕССИЯ ЭТОЙ ВКЛАДКИ",
        advancedSessionTitle: "Продвинутая сессия",
        advancedSessionDescription: "Продвинутые запросы получают заголовок сессии только в момент отправки. Токен сессии не показывается и не сохраняется.",
        advancedSessionPrefixLabel: "Префикс пути",
        advancedSessionPrefixPlaceholder: "/advanced",
        advancedSessionPrefixHint: "Префикс неизменяем до отзыва этой сессии.",
        advancedSessionDecoderLabel: "Декодер тела",
        advancedSessionDecoderAuto: "Авто",
        advancedSessionDecoderRaw: "Сырые байты",
        advancedSessionDecoderJson: "JSON",
        advancedSessionDecoderText: "Текст",
        advancedSessionDecoderForm: "Форма",
        advancedSessionDecoderXml: "XML",
        advancedSessionDecoderMultipart: "Мультичастная форма",
        advancedSessionDiagnosticHeadersLabel: "Диагностические заголовки ответа",
        advancedSessionExpiresLabel: "Истекает",
        advancedSessionCreate: "Создать сессию",
        advancedSessionRevoke: "Отозвать сессию",
        advancedSessionInactive: "Продвинутая сессия неактивна",
        advancedSessionCreating: "Создание продвинутой сессии…",
        advancedSessionChecking: "Проверка продвинутой сессии…",
        advancedSessionActive: "Сессия активна для этой вкладки браузера",
        advancedSessionError: "Не удалось выполнить операцию с продвинутой сессией",
        advancedSessionInvalidResponse: "Сервер вернул недопустимый ответ сессии",
        responseOptionsTitle: "Параметры ответа",
        responseOptionsDiagnosticHeadersLabel: "Дублировать диагностику в заголовках ответа",
        responseOptionsNoGzipLabel: "Не сжимать HTTP-ответ",
        dirPathPlaceholder: "Путь к директории",
        browseBtn: "Обзор",
        filesSearchLabel: "Поиск по именам файлов и папок",
        filesSearchPlaceholder: "Поиск по именам",
        filesSearchClear: "Очистить поиск",
        filesSearchNoMatches: "Нет совпадений по имени.",
        filesFilterSummary: "Показано: {0} из {1}",
        filesFilterSummaryPaged: "Показано: {0} из {1} загруженных · всего {2}",
        filesListActions: "Действия со списком",
        filesCleanupHint: "Удаляет всё содержимое uploads/. Служебные скрытые файлы будут сохранены.",
        filesSelectVisible: "Выбрать показанные файлы",
        filesDeselectVisible: "Снять выделение с показанных файлов",
        filesColumnName: "Имя",
        filesColumnActions: "Действия",
        filesSortAscending: "Сортировать по имени по убыванию. Сейчас: по возрастанию",
        filesSortDescending: "Сортировать по имени по возрастанию. Сейчас: по убыванию",
        filesSortedAscending: "Сортировка: имя по возрастанию",
        filesSortedDescending: "Сортировка: имя по убыванию",
        filesSelectionClearedBySearch: "Выделение снято из-за изменения поиска",
        filesSelectionCount: "Выбрано: {0}",
        clearSelectionBtn: "Снять выделение",
        filesBrowseLoading: "Открываем папку {0}…",
        filesBrowseEmpty: "В этой папке нет файлов.",
        filesBrowseInitialError: "Не удалось открыть папку.",
        filesBrowseVisibleCount: "Показано {0} из {1}",
        filesMoreActions: "Дополнительные действия",
        statusPending: "Ожидание",
        statusUploading: "Загрузка...",
        statusSuccess: "Загружен",
        statusError: "Ошибка",
        queueRemoveLabel: "Убрать из очереди",
        queueDetailsLabel: "Подробности ошибки",
        queueRetryLabel: "Повторить файл",
        filesBrowseStale: "Показан сохранённый список для {0}. Обновление не удалось; действия с файлами отключены.",
        networkError: "Ошибка сети: сервер недоступен",
        timeoutError: "Тайм-аут: превышено время ожидания",
        httpErrorTitle: "Ошибка HTTP",
        httpErrorDetails: "Подробности",
        httpErrorRetry: "Повторить",
        httpErrorClose: "Закрыть",
        httpErrorCopy: "Копировать",
        httpErrorCopied: "Подробности ошибки скопированы",
        httpErrorCopyFailed: "Не удалось скопировать подробности ошибки",
        httpErrorHeaders: "Заголовки",
        httpErrorBody: "Тело ответа",
        httpErrorHtmlText: "HTML показан как текст",
        httpErrorNoBody: "Тело ответа отсутствует",
        httpErrorTruncated: "Показанные подробности ограничены (байт):",
        httpErrorRequestId: "ID запроса",
        parseError: "Ошибка парсинга",
        error: "Ошибка",
        uploadStarting: "Начинаем загрузку...",
        uploadComplete: "Загрузка завершена",
        successCount: "успешно",
        errorCount: "ошибок",
        sendingRequest: "Отправка",
        preparingDemoRequest: "Подготовка демонстрационного сценария",
        requestTo: "запроса на",
        headers: "Заголовки",
        headersNA: "(не доступны)",
        responseBody: "Тело ответа",
        time: "Время",
        download: "Скачать",
        fileInfoBtn: "Метаданные файла",
        fileInfoLoaded: "Сведения о файле получены",
        fileInfoError: "Не удалось получить сведения о файле",
        fileDetailsExpand: "Показать сведения о файле",
        fileDetailsCollapse: "Скрыть сведения о файле",
        fileDetailsLoading: "Загружаем сведения о {0}…",
        fileDetailsRetry: "Повторить",
        fileDetailsTitle: "Сведения о файле",
        filesInspectionMimeLine: "MIME: {0} · {1}",
        filesInspectionSourceSignature: "по сигнатуре",
        filesInspectionSourceText: "по тексту",
        filesInspectionSourceExtension: "по расширению",
        filesInspectionSourceUnknown: "источник не определён",
        filesInspectionWarningPossibleEncryptedOrPacked: "Возможно зашифрован или упакован",
        filesInspectionWarningExtensionMismatch: "Расширение не совпадает с содержимым",
        filesInspectionStateRecognized: "Формат распознан",
        filesInspectionStateOpaque: "Формат не распознан",
        filesInspectionStateUnknown: "Недостаточно данных для определения",
        filesXorHintOpaque: "Формат не распознан: пробуйте, только если использовался XOR.",
        filesXorHintNeutral: "Только для файлов, зашифрованных XOR.",
        fileInfoMimeSource: "Источник MIME",
        fileInfoAssessment: "Оценка содержимого",
        fileInfoExtension: "Расширение",
        fileInfoCreated: "Создан",
        fileInfoModified: "Изменён",
        xorDecryptButtonLabel: "Скачать с XOR-расшифровкой",
        xorDecryptTitle: "XOR расшифровка",
        xorDecryptPasswordLabel: "Ключ",
        xorDecryptPasswordPlaceholder: "Ключ XOR",
        xorDecryptOutputNameLabel: "Имя результата",
        xorDecryptOutputNamePlaceholder: "имя-файла.dec",
        xorDecryptConfirm: "Расшифровать",
        xorDecryptPasswordRequired: "Введите ключ XOR",
        xorDecryptRunning: "Расшифровка XOR",
        xorDecryptSaved: "Расшифрованный файл сохранён",
        xorDecryptFailed: "Не удалось расшифровать файл",
        xorDecryptWarning: "XOR не проверяет правильность ключа. Неверный ключ тоже сохранит файл, но содержимое будет повреждено.",
        loadingInfo: "Загрузка информации о",
        filesBrowseSummary: "Открыта папка {0} • элементов: {1}",
        open: "Открыть",
        opsecMethodPlaceholder: "Метод (CHECKDATA)",
        opsecUploadText: "Имя скрыто",
        opsecUploadHint: "Base64, без имени",
        opsecDropZoneLabel: "Выбрать файл для продвинутой загрузки",
        opsecSelectionIdle: "Файл не выбран",
        opsecConstructorModeLabel: "Режим конструктора",
        opsecConstructorModeManaged: "Управляемый",
        opsecConstructorModeExperimental: "Экспериментальный",
        opsecProfileLabel: "Профиль запроса",
        opsecProfileBodyJson: "Тело · JSON",
        opsecProfileBodyRaw: "Тело · сырые байты",
        opsecProfileBodyText: "Тело · текст",
        opsecProfileBodyForm: "Тело · форма",
        opsecProfileBodyXml: "Тело · XML",
        opsecProfileMultipartBinary: "Multipart · бинарная часть",
        opsecProfileMultipartEncoded: "Multipart · кодированное поле",
        opsecProfileHeaders: "Заголовки",
        opsecProfileQuery: "Параметры URL",
        opsecProfileCookies: "Cookie",
        opsecProfilePath: "Путь URL",
        opsecCarrierLabel: "Носитель данных",
        opsecMimeLabel: "Объявленный MIME",
        opsecPartMimeLabel: "MIME бинарной части",
        opsecMultipartBoundaryManaged: "Граница верхнего multipart создаётся браузером; MIME бинарной части можно изменить.",
        opsecMultipartTopLevelMimeManaged: "Верхний MIME: multipart/form-data; границу создаёт браузер. Поле недоступно, потому что заголовком управляет браузер.",
        opsecFilenamePrimaryLabel: "Основное размещение",
        opsecFilenameHidden: "Скрыто",
        opsecFilenameCookie: "Cookie xferry_name",
        opsecFilenameMultipart: "Имя части multipart",
        opsecFilenameCopiesLabel: "Дополнительные точные копии имени",
        opsecNormalizationTitle: "Нормализация управляемого профиля",
        opsecNormalizationItem: "{0}: «{1}» → «{2}».",
        opsecNormalizationCopyRemovedPrimary: "Копия «{0}» удалена: это уже основное размещение.",
        opsecNormalizationCopyRemovedIncompatible: "Копия «{0}» удалена: она несовместима с выбранным профилем.",
        opsecValidationTitle: "Комбинация несовместима",
        opsecBinaryRequiresRaw: "Формат {0} требует encoding=raw; выбрано {1}. Значение не изменено.",
        opsecStructuredRequiresTextEncoding: "Формат {0} требует байт-безопасного текстового кодирования; выбрано {1}. Значение не изменено.",
        opsecCarrierRequiresTextEncoding: "Носитель {0} требует байт-безопасного текстового кодирования; выбрано {1}. Значение не изменено.",
        opsecRawRequiresBody: "Сырой формат тела требует носитель body; выбран {0}. Значение не изменено.",
        opsecMultipartRequiresBody: "Формат {0} можно отправить только через body; выбран {1}. Значение не изменено.",
        opsecFilenamePlacementIncompatible: "Размещение имени {0} несовместимо с {1}/{2}. Значение не изменено.",
        opsecFilenameCopyDuplicatesPrimary: "Копия имени {0} совпадает с основным размещением. Значение не изменено.",
        opsecMethodOverrideIncompatible: "Переопределение метода в поле формы требует носитель body и формат, который сериализует поля; выбрано {0}/{1}. Значение не изменено.",
        opsecMultipartMimeBrowserManaged: "Объявленный MIME «{0}» не может быть отправлен для multipart. Браузер управляет верхним multipart/form-data и его границей. Значение не изменено.",
        opsecMimeDecoderMismatch: "MIME «{0}» не соответствует фактическому декодеру тела «{1}». Отправка разрешена только когда активный фиксированный декодер маршрута равен «{1}»; сейчас «{2}».",
        opsecSizeWarningTitle: "Размер запроса",
        opsecSizeEstimateExact: "Оценочный размер сериализованного запроса",
        opsecSizeEstimateApproximate: "Приблизительный размер сериализованного запроса",
        opsecSizeWarningMessage: "{0}: {1}; лимит сервера: {2}; лимит браузера: {3}. Рекомендуемое действие: выбрать профиль «{4}» или уменьшить файл. Настройки не изменены.",
        opsecSizeWithinLimitMessage: "{0}: {1}; лимит сервера: {2}; лимит браузера: {3}. Рекомендуемое действие при приближении к лимиту: выбрать профиль «{4}». Настройки не изменены.",
        opsecPreviewPending: "Запрос собирается…",
        opsecPreviewChangedBlocked: "Входные данные изменились после построения предпросмотра. Предпросмотр обновлён; нажмите отправку ещё раз.",
        opsecGzipUnavailable: "Этот браузер не поддерживает CompressionStream для gzip+base64.",
        opsecAdvancedOptions: "Настроить форму запроса",
        opsecAdvancedOptionsHint: "Эти настройки не выбирают второй сценарий: они меняют форму запроса внутри выбранного канала.",
        opsecRequestShapeTitle: "Форма запроса",
        opsecPayloadOptionsTitle: "Кодирование",
        opsecMetadataOptionsTitle: "Имя файла в запросе",
        opsecIncludeName: "Имя файла",
        opsecEncryptionMode: "Шифрование",
        opsecEncryptionNone: "Нет",
        opsecEncryptionXor: "XOR (обфускация)",
        opsecEncryptionAes: "AES-256-GCM",
        opsecPasswordLabel: "Ключ шифрования",
        opsecPasswordPlaceholder: "Ключ шифрования",
        opsecKeyBase64: "Base64",
        opsecUploadBtn: "Загрузить",
        opsecFileSelected: "Файл выбран",
        opsecPasswordRequired: "Ошибка: введите пароль для шифрования",
        opsecUploading: "Загрузка через метод",
        opsecXorEncryption: "XOR шифрование",
        opsecSuccess: "Продвинутая загрузка выполнена",
        opsecUploaded: "Загружено",
        opsecId: "ID",
        opsecSize: "Размер",
        opsecBytes: "байт",
        opsecStepEndpoint: "Метод",
        opsecStepCarrier: "Куда положить данные",
        opsecStepPayload: "Данные",
        opsecStepMetadata: "Метаданные",
        opsecStepFile: "Файл",
        opsecOutcomeTitle: "Что получится",
        opsecOutcomeMethod: "Метод",
        opsecOutcomeData: "Куда пойдут данные",
        opsecOutcomeEncoding: "Кодирование",
        opsecOutcomeFilename: "Имя файла",
        opsecOutcomeServer: "Куда сохранит сервер",
        opsecOutcomeFilenameHidden: "Скрыто",
        opsecOutcomeFilenameIncluded: "{0} • {1}",
        opsecOutcomeServerBody: "Сервер сохранит файл в uploads/",
        opsecMethodOverrideHelpNone: "Не добавляет переопределение. Сервер увидит только метод из первого шага.",
        opsecMethodOverrideHelpHeader: "Заголовок: добавляет X-XFerry-Method-Override: PUT.",
        opsecMethodOverrideHelpQuery: "Параметр URL: добавляет ?method_override=PUT.",
        opsecMethodOverrideHelpForm: "Форма: добавляет поле method_override=PUT.",
        opsecBodyFormatHelpJson: "JSON: данные лежат в каноническом поле data рядом с encoding и encryption.",
        opsecBodyFormatHelpRaw: "Сырые байты: тело запроса состоит только из байтов файла. Метаданные уходят в заголовки или параметры URL.",
        opsecBodyFormatHelpText: "Текст: тело text/plain. Используйте, когда нужно проверить текстовый парсер, а не JSON.",
        opsecBodyFormatHelpForm: "Форма: тело application/x-www-form-urlencoded с каноническими полями data, encoding и encryption.",
        opsecBodyFormatHelpMultipart: "Multipart: тело multipart/form-data. Используйте для сценариев, где сервер ожидает форму с частями.",
        opsecBodyFormatHelpXml: "XML: тело application/xml с теми же полями внутри XML-узлов.",
        opsecEncodingHelpBase64: "Base64: безопасные текстовые данные для тела и заголовков. Размер вырастает примерно на треть.",
        opsecEncodingHelpBase64url: "Base64url: для URL, cookie и пути. Заменяет символы, которые ломают URL.",
        opsecEncodingHelpHex: "Hex: каждый байт становится двумя hex-символами. Просто отлаживать, но размер почти вдвое больше.",
        opsecEncodingHelpPercent: "Percent: URL-формат %XX для каждого байта. Очень заметно увеличивает размер данных.",
        opsecEncodingHelpGzipBase64: "gzip+base64: сначала сжимает, потом кодирует. Полезно для повторяющихся текстовых данных.",
        opsecEncodingHelpRaw: "Без кодирования: работает только там, где контейнер допускает сырые байты.",
        opsecEncryptionHelpOff: "encryption=none отправляется явно; ключ и HMAC отсутствуют.",
        opsecEncryptionHelpOn: "XOR: совместимая обфускация; AES: AES-256-GCM без запасного алгоритма.",
        opsecEncryptionHelpSendKey: "Ключ отправляется только для выбранного XOR или AES.",
        opsecEncryptionHelpKeyBase64: "Ключ отправляется как строгий стандартный Base64 UTF-8 текста.",
        opsecFilenameHelpHidden: "Имя скрыто: сервер создаёт случайный ID, исходное имя файла не отправляется.",
        opsecFilenameHelpBody: "Имя в теле: добавляет поле name рядом с данными.",
        opsecFilenameHelpHeaders: "Имя в заголовках: добавляет X-XFerry-Name.",
        opsecFilenameHelpQuery: "Имя в параметрах URL: добавляет ?name=filename.",
        opsecFilenameHelpPath: "Имя в пути URL: имя становится сегментом URL.",
        opsecFilenameHelpContentDisposition: "Content-Disposition: имя попадёт в часть файла multipart; работает только с телом + multipart.",
        opsecMethodRandom: "(случайный)",
        opsecPathNoName: "(не содержит имя файла)",
        opsecNameInReq: "Имя в запросе",
        opsecYes: "да",
        opsecNoHidden: "нет (скрыто)",
        opsecEncryption: "Шифрование",
        opsecNone: "нет",
        opsecXorDecrypted: "XOR (расшифровано на сервере",
        opsecKeyInBase64: ", ключ в base64",
        opsecXorEncrypted: "XOR (файл зашифрован)",
        smuggleTitle: "HTML Smuggling",
        smuggleFile: "Файл",
        smuggleButtonLabel: "HTML Smuggling",
        deleteFileAction: "Удалить файл",
        smuggleDownloadName: "Имя скачивания",
        smuggleProtect: "XOR-обфускация",
        smuggleProtectHint: "XOR сохраняет совместимость без криптографической защиты; AES-256-GCM обеспечивает аутентифицированное шифрование.",
        smuggleGenerate: "Сгенерировать",
        smuggleOpen: "Открыть",
        smuggleCopyUrl: "Копировать одноразовый URL",
        smuggleSave: "Сохранить",
        smuggleClose: "Закрыть",
        smuggleCancel: "Отмена",
        smuggleGenerated: "HTML сгенерирован",
        smuggleEncrypted: "XOR-обфускация",
        smugglePassword: "Пароль",
        smuggleYes: "Да (XOR)",
        smuggleNo: "Нет",
        smuggleReady: "Выберите действие.",
        smuggleCopied: "Одноразовый URL скопирован.",
        smuggleOpened: "Одноразовый HTML/SVG открыт в новой вкладке.",
        smuggleResultHint: "Первый GET, HEAD, conditional request или сканер может поглотить URL; повторная генерация не инвалидирует предыдущий URL.",
        smuggleCapabilitiesPending: "Возможности HTML Smuggling ещё загружаются с сервера.",
        smuggleCapabilitiesInvalid: "Сервер вернул некорректный контракт возможностей HTML Smuggling.",
        smuggleCapabilitiesUnavailable: "Не удалось получить возможности HTML Smuggling от сервера.",
        smuggleMethodUnavailable: "Активный сервер не поддерживает HTML Smuggling.",
        smuggleBuilderSourceSection: "Источник",
        smuggleBuilderSourceName: "Исходный файл",
        smuggleBuilderSourcePath: "Путь на сервере",
        smuggleBuilderDeliverySection: "Выдача",
        smuggleBuilderBaseName: "Базовое имя",
        smuggleBuilderExtension: "Расширение",
        smuggleBuilderPreviewName: "Итоговое имя",
        smuggleBuilderPresetSection: "Обычная HTML-страница",
        smuggleBuilderPresetLabel: "Поведение страницы",
        smuggleBuilderPresetDirect: "Сразу скачать",
        smuggleBuilderPresetManual: "Карточка + кнопка",
        smuggleBuilderPresetAuto: "Карточка + автостарт",
        smuggleBuilderConstructorSection: "Конструктор",
        smuggleBuilderConstructorToggle: "Использовать режим конструктора",
        smuggleBuilderPayloadEncoding: "Кодирование данных",
        smuggleBuilderOutputFormat: "Формат внешнего артефакта",
        smuggleBuilderTriggerMethod: "Элемент запуска",
        smuggleBuilderTriggerEvent: "Событие запуска",
        smuggleBuilderDownloadVariant: "Вариант скачивания",
        smuggleBuilderPageTemplate: "Визуальный шаблон",
        smuggleBuilderMimeType: "MIME извлекаемого файла",
        smuggleBuilderNullByte: "NUL перед внешним артефактом",
        smuggleBuilderConstructorGroupPayload: "Данные",
        smuggleBuilderConstructorGroupTrigger: "Запуск",
        smuggleBuilderConstructorGroupOutput: "Вывод",
        smuggleBuilderPayloadEncodingHelp: "Как байты файла будут представлены внутри страницы.",
        smuggleBuilderOutputFormatHelp: "Расширение создаваемой HTML-страницы, например html, svg или xml.",
        smuggleBuilderTriggerHelp: "Элемент и событие, которые запускают скачивание.",
        smuggleBuilderDownloadVariantHelp: "Технический способ передать файл браузеру.",
        smuggleBuilderPageTemplateHelp: "Внешний вид страницы, не расширение файла.",
        smuggleBuilderNullByteHelp: "Добавляет один нулевой байт в начало создаваемого файла.",
        smuggleBuilderConstructorHint: "Поля повторяют конструктор HTML Smuggling: кодирование данных, формат файла, событие запуска, вариант скачивания и MIME.",
        smuggleBuilderAdvancedSection: "Текст страницы",
        smuggleBuilderTitleLabel: "Заголовок",
        smuggleBuilderMessageLabel: "Сообщение",
        smuggleBuilderCtaLabel: "Текст кнопки",
        smuggleBuilderDelayLabel: "Задержка автостарта, мс",
        smuggleBuilderNoticeLabel: "Показывать пометку внутренней проверки",
        smuggleBuilderDefaultTitle: "Тестовый HTML готов",
        smuggleBuilderDefaultMessage: "Нейтральный внутренний HTML.",
        smuggleBuilderDefaultCta: "Скачать тестовый HTML",
        opsecTransportLabel: "Транспорт:",
        opsecTransportBody: "Тело",
        opsecTransportHeaders: "Заголовки",
        opsecTransportUrl: "URL параметры",
        opsecTransportCookies: "Cookie",
        opsecTransportPath: "Путь URL",
        opsecTransportUsed: "Транспорт",
        opsecBodyFormatLabel: "Формат тела",
        opsecBodyFormatJson: "JSON",
        opsecBodyFormatRaw: "Сырые байты",
        opsecBodyFormatText: "Текст",
        opsecBodyFormatForm: "Форма",
        opsecBodyFormatMultipart: "Multipart",
        opsecBodyFormatXml: "XML",
        opsecEncodingLabel: "Кодирование",
        opsecEncodingBase64: "Base64",
        opsecEncodingBase64url: "Base64url",
        opsecEncodingHex: "Hex",
        opsecEncodingPercent: "Percent",
        opsecEncodingGzipBase64: "gzip+base64",
        opsecEncodingRaw: "Без кодирования",
        opsecMetadataLabel: "Куда поместить имя",
        opsecMetadataBody: "Тело",
        opsecMetadataHeaders: "Заголовки",
        opsecMetadataQuery: "Параметры URL",
        opsecMetadataPath: "Путь URL",
        opsecMetadataContentDisposition: "Content-Disposition",
        opsecMethodOverrideLabel: "Переопределение метода",
        opsecMethodOverrideNone: "Нет",
        opsecMethodOverrideHeader: "Заголовок",
        opsecMethodOverrideQuery: "Параметр URL",
        opsecMethodOverrideForm: "Поле method_override",
        viewInFiles: "Открыть Файлы",
        tabNotepad: "Блокнот",
        notepadTitle: "Защищённый блокнот",
        notepadDesc: "Тексты заметок шифруются сквозным образом. Заголовки остаются видимыми серверу метаданными.",
        notepadRequirements: "Требуется сервер с криптографическими зависимостями по умолчанию и браузер с Web Crypto.",
        notepadTitlePlaceholder: "Заголовок (видим серверу)",
        notepadTextareaPlaceholder: "Текст... (шифруется)",
        notepadTextareaLabel: "Текст заметки",
        notepadNewBtn: "Новая",
        notepadDeleteBtn: "Удалить",
        notepadNotes: "Заметки",
        notepadNoNotes: "Нет заметок",
        notepadConnecting: "Подключение...",
        notepadConnected: "Онлайн",
        notepadDisconnected: "Офлайн",
        notepadReady: "Готово",
        notepadUnsaved: "Не сохранено",
        notepadSaving: "Сохранение...",
        notepadSaved: "Сохранено",
        notepadLoading: "Загрузка...",
        notepadLoaded: "Загружено",
        notepadSaveError: "Ошибка сохранения",
        notepadLoadError: "Ошибка загрузки",
        notepadDecryptError: "Ошибка расшифровки",
        notepadSessionFailed: "Ошибка инициализации сессии",
        notepadUnavailableServer: "Блокнот недоступен: восстановите или переустановите стандартные зависимости времени выполнения сервера.",
        notepadUnavailableBrowser: "Блокнот недоступен: нет Web Crypto.",
        notepadTransportHttp: "HTTP",
        notepadTransportWs: "WS",
        notepadEphemeralWarning: "Сохранённый текст может стать нерасшифровываемым после перезагрузки страницы, перезапуска браузера или сервера, истечения TTL сессии или LRU-вытеснения. Ключ восстановления не хранится.",
        notepadLossDetailsSummary: "Что хранит сервер",
        notepadLossDetailsBody: "Сервер хранит зашифрованный текст и метаданные, например заголовок, но не AES-ключ или материал для восстановления. Блокнот HTTP/WS не является резервной копией, синхронизацией или серверным восстановлением.",
        notepadUntitled: "Без названия",
        notepadTitleMetadataHint: "Текст заметки шифруется. Заголовок видим серверу как метаданные.",
        notepadDiscardTitle: "Есть несохранённые изменения",
        notepadDiscardConfirm: "Не удалось сохранить изменения перед переходом. Сбросить их?",
        notepadDiscardBtn: "Сбросить",
        notepadDeleteConfirm: "Удалить эту заметку?",
        notepadDeleteSelectedBtn: "Удалить выбранные заметки",
        notepadDeleteSelectedConfirm: "Удалить выбранные заметки?",
        notepadSelectedDeleted: "Выбранные заметки удалены",
        selectNoteLabel: "Выбрать заметку",
        notepadClearBtn: "Очистить заметки",
        notepadClearConfirm: "Удалить все заметки из notes/? Файлы в uploads/ не будут затронуты.",
        notepadCleared: "Заметки очищены",
        notepadClearError: "Ошибка очистки заметок",
        notepadReconnecting: "Переподключение...",
        charCountSuffix: "симв.",
        deleteBtn: "Удалить",
        deleteConfirm: "Удалить этот файл?",
        deleteSuccess: "Файл удалён",
        deleteError: "Ошибка удаления",
        selectFileLabel: "Выбрать файл",
        deleteSelectedFilesBtn: "Удалить выбранные файлы",
        deleteSelectedFilesCount: "Удалить выбранные ({0})",
        deleteSelectedFilesConfirm: "Удалить выбранные файлы из uploads/?",
        deleteSelectedFilesSuccess: "Выбранные файлы удалены",
        deleteSelectedFilesRefreshError: "Файлы удалены ({0}), но список не удалось обновить",
        filesToastDismiss: "Закрыть уведомление",
        clearUploadsBtn: "Очистить uploads/",
        clearUploadsConfirm: "Удалить всё содержимое uploads/? Служебные скрытые файлы будут сохранены.",
        clearUploadsRunning: "Очистка uploads/...",
        clearUploadsSuccess: "uploads/ очищена",
        clearUploadsError: "Ошибка очистки uploads/",
        filesDeleted: "файлов удалено",
        dirsDeleted: "папок удалено",
        notepadDeleteError: "Ошибка удаления заметки",
        okBtn: "OK",
        downloadStarted: "Скачивание начато",
        downloadCompleted: "Скачивание завершено",
        downloadFailed: "Не удалось скачать файл",
        downloadProgress: "Скачивание",
        downloadSpeed: "Скорость",
        downloadEta: "Осталось"
    },
    en: {
        brandTagline: "SWG testing tool",
        langRussianSelectedLabel: "Russian language selected",
        langRussianSelectLabel: "Switch to Russian",
        langEnglishSelectedLabel: "English language selected",
        langEnglishSelectLabel: "Switch to English",
        themeDarkCurrentLabel: "Dark theme is active. Switch to light theme",
        themeLightCurrentLabel: "Light theme is active. Switch to dark theme",
        quickRequestMethodsLabel: "Request methods",
        serverModesLabel: "Server modes",
        browseRootLabel: "Go to root",
        browseUpLabel: "Go up",
        httpMethodLabel: "HTTP method",
        randomLabel: "Random",
        refreshLabel: "Refresh",
        heroWorkingPanelEyebrow: "TEST WORKSPACE",
        heroWorkingPanelTitle: "Test HTTP data-transfer paths",
        heroResponsePanelEyebrow: "RESPONSE",
        heroResponsePanelTitle: "Responses and test artifacts",
        toolResultEyebrow: "RESULT",
        toolTraceSummary: "Technical details",
        toolPhaseIdle: "No actions yet",
        toolPhaseReady: "Ready",
        toolPhasePending: "Running",
        toolPhaseSuccess: "Done",
        toolPhaseError: "Error",
        uploadResultIdleTitle: "No file sent yet",
        uploadResultIdleBody: "Choose a file, then press Send.",
        uploadResultServerPath: "Server path",
        uploadResultSize: "Size",
        uploadResultTraceAction: "Open technical details",
        uploadResultFilesAction: "Open Files",
        filesResultIdleTitle: "No file action yet",
        filesResultIdleBody: "Open a folder, download a file, delete selected items, or clear uploads/.",
        opsecResultIdleTitle: "No advanced upload yet",
        opsecResultIdleBody: "Choose a file, then configure the method and transport before sending.",
        opsecPreviewReady: "Request ready to send",
        advancedLabel: "More actions",
        methodGet: "Get resources",
        methodHead: "Inspect headers",
        methodPost: "Send data",
        methodDelete: "Delete a resource",
        methodOptions: "Inspect allowed methods",
        methodFetch: "Download files",
        methodInfo: "File metadata",
        methodPing: "Server check",
        methodNone: "Upload files",
        methodPut: "Upload/replace",
        methodPatch: "Update files",
        methodNote: "Inspect notepad ECDH key",
        methodSmuggle: "HTML smuggling",
        tabRequests: "Requests",
        tabUpload: "Send",
        tabFiles: "Files",
        tabOpsec: "Advanced",
        labelFilePath: "File path",
        labelDirPath: "Directory path",
        pathPlaceholder: "/index.html or /uploads/",
        requestPreviewModeLabel: "Request and response view mode",
        requestPreviewModeSummary: "Summary",
        requestPreviewModeRaw: "Raw HTTP",
        requestTechnicalDetailsSummary: "Technical requests",
        requestTechnicalDetailsHint: "Methods, raw HTTP, and batch run",
        requestRunAllBtn: "Run all",
        requestBatchDetailsSummary: "Method matrix",
        requestBatchRerunIssuesBtn: "Rerun issues",
        requestBatchRerunIssuesLabel: "Rerun only problematic methods",
        requestBatchRerunIssuesStarted: "Issue rerun started",
        requestBatchRerunIssuesCompleted: "Issue rerun completed, issues left",
        requestBatchExportBtn: "Export JSON",
        requestBatchExportLabel: "Download the JSON run report",
        requestBatchExported: "JSON run report exported",
        requestBatchExportFailed: "Could not export the JSON run report",
        requestBatchClearBtn: "Clear",
        requestBatchClearLabel: "Clear the run result",
        requestBatchCleared: "Run result cleared",
        requestBatchIssuesOnlyLabel: "Only issues",
        requestBatchNoIssues: "All methods completed without issues.",
        requestBatchNoIssuesYet: "So far all methods are working.",
        requestBatchRerunLabel: "Run again",
        requestBatchRerunCompleted: "Rerun completed",
        requestBatchAttempts: "Attempts",
        requestBatchAttempt: "Attempt",
        requestBatchAttemptHistory: "Attempt history",
        requestBatchLastRerun: "Last rerun",
        requestBatchRerunFixed: "Fixed",
        requestBatchRerunStillFailing: "Still failing",
        requestBatchRerunRegressed: "Regressed",
        requestBatchRerunStillOk: "Still OK",
        requestBatchRunning: "Running",
        requestBatchCompleted: "Completed",
        requestBatchTotal: "Total",
        requestBatchMatches: "Works",
        requestBatchMismatches: "Mismatches",
        requestBatchFailed: "Failed",
        copyRawRequestBtn: "Copy request",
        copyRawResponseBtn: "Copy response",
        copyRawRequestLabel: "Copy raw request",
        copyRawResponseLabel: "Copy raw response",
        downloadRawRequestBtn: "Download request",
        downloadRawResponseBtn: "Download response",
        downloadRawRequestLabel: "Download HTTP request",
        downloadRawResponseLabel: "Download HTTP response",
        requestPreviewCopied: "Raw request copied",
        responseCopied: "Raw response copied",
        clipboardCopyFailed: "Could not copy to clipboard",
        requestPreviewEmpty: "Choose a method to inspect the outbound HTTP request.",
        requestPreviewPreparing: "Preparing the demo scenario before sending the primary request...",
        requestPreviewFieldMethod: "Method",
        requestPreviewFieldPath: "Path",
        requestPreviewFieldExpectedStatus: "Expected status",
        requestPreviewFieldActualStatus: "Actual status",
        requestPreviewFieldCheck: "Check",
        requestPreviewFieldHost: "Host",
        requestPreviewFieldHeaderCount: "Headers",
        requestPreviewFieldBodySize: "Body size",
        responseSummaryFieldStatus: "Status",
        responseSummaryFieldContentType: "Content-Type",
        requestBody: "Request body",
        requestPreviewNoBody: "No body",
        exchangeRequestTitle: "Outgoing request",
        exchangeResponseTitle: "Incoming response",
        uploadRawHttpRequestTitle: "RAW HTTP Request",
        uploadRawHttpResponseTitle: "RAW HTTP Response",
        opsecRawHttpRequestTitle: "RAW HTTP Request",
        opsecRawHttpResponseTitle: "RAW HTTP Response",
        exchangeRequestEmpty: "The request will appear here after an action.",
        exchangeResponseEmpty: "The response will appear here after the request runs.",
        exchangeCopied: "Raw copied",
        exchangeLogDownloaded: "HTTP log saved",
        exchangeLogDownloadFailed: "Could not save HTTP log",
        exchangeLogSensitiveHint: "The log may contain payloads, keys, or cookies.",
        exchangeBrowserManagedNote: "Browser-managed data limitations",
        exchangeCookieHeaderManaged: "The browser sends the Cookie header; the values below are written to document.cookie before send.",
        exchangeMultipartBoundaryManaged: "The browser sets multipart boundary and Content-Length; byte-exact body bytes are unavailable from frontend JS.",
        exchangeTransport: "Transport",
        exchangeBodyKind: "Body type",
        exchangeBinaryBody: "Binary data",
        exchangeBinaryBodyPreview: "Body preview",
        exchangeBinaryBodyPreviewPending: "The file body will be sent here; preview appears after reading the first bytes.",
        exchangeHexPreview: "Hex preview",
        exchangeTruncated: "truncated, remaining chars/bytes",
        exchangeRedacted: "redacted",
        exchangeWsSend: "WS send",
        exchangeWsReceive: "WS receive",
        fileName: "File name",
        requestPreviewCheckPending: "Waiting for response",
        requestPreviewCheckMatch: "Matches",
        requestPreviewCheckMismatch: "Mismatch",
        requestPreviewCheckFailed: "Request failed",
        dropFilesHere: "Choose files or drop them here",
        uploadDropZoneLabel: "Choose files for regular upload",
        uploadMethodLabel: "Regular upload method",
        uploadSelectionIdle: "No files selected",
        uploadProfileLabel: "Request profile",
        uploadProfileMultipart: "Multipart",
        uploadProfileRawUrl: "Raw URL",
        uploadProfileRawHeader: "Raw Header",
        uploadRequestSummaryTitle: "Request before send",
        uploadSummaryRequestLine: "Request line",
        uploadSummaryBodyKind: "Body",
        uploadSummaryMime: "MIME",
        uploadSummaryFilenameSource: "Filename source",
        uploadBodyKindMultipart: "multipart/form-data, file field",
        uploadBodyKindRaw: "raw file bytes",
        uploadFilenameSourcePart: "multipart part filename",
        uploadFilenameSourceUrl: "URL segment",
        uploadFilenameSourceHeader: "X-File-Name header",
        uploadCompareBtn: "Compare 3 profiles",
        uploadCompareConfirmTitle: "Create three files?",
        uploadCompareConfirmBody: "Comparison sends the selected file sequentially as Multipart, Raw URL, and Raw Header and creates three files on the server.",
        uploadCompareConfirmAction: "Create 3 files",
        uploadCompareResultsTitle: "Profile comparison",
        uploadCompareRunning: "Comparing profiles…",
        uploadCompareProfileLabel: "Profile",
        uploadCompareVerdictLabel: "Verdict",
        uploadCompareRequestLabel: "Request",
        uploadCompareResponseLabel: "Response",
        uploadVerdictDelivered: "delivered",
        uploadVerdictMetadataChanged: "metadata changed",
        uploadVerdictContentChanged: "content changed",
        uploadVerdictRejected: "rejected with response",
        uploadVerdictNotConfirmed: "not confirmed",
        uploadVerdictNotRun: "not run",
        uploadCollisionRenamed: "The server renamed the file after a collision; this is informational.",
        uploadRoutingConflict: "Basic upload stays available independently of the Advanced session.",
        uploadRoutingUnknown: "Basic upload stays available.",
        uploadFlowLabel: "Regular upload logic",
        uploadFlowMethodTitle: "Method",
        uploadFlowMethodBody: "The HTTP method changes request shape; the file body is sent to the server.",
        uploadFlowFilesTitle: "Files",
        uploadFlowFilesBody: "Selected files enter the queue and are sent one at a time.",
        uploadFlowServerTitle: "uploads/",
        uploadFlowServerBody: "The server saves a copy and returns its path in the result.",
        uploadHelpTitle: "How regular upload works",
        uploadHelpSummary: "Method, queue, saved copy, and technical trace",
        uploadHelpMethodsTitle: "Methods",
        uploadHelpMethodsBody: "POST, NONE, PUT, and PATCH use the same upload handler: the request body is saved as a file. Pick the method to test a specific HTTP shape.",
        uploadHelpDestinationTitle: "Where the file goes",
        uploadHelpDestinationBody: "After a successful send, the server writes the file to uploads/. The /uploads/name path appears in the result and server response.",
        uploadHelpTraceTitle: "What to check after sending",
        uploadHelpTraceBody: "The result shows status and path. Technical details expose the raw outgoing request and incoming response.",
        selectedLabel: "Selected",
        selectedFilesCount: "Files selected",
        uploadAllBtn: "Send",
        advancedSessionEyebrow: "THIS TAB'S SESSION",
        advancedSessionTitle: "Advanced session",
        advancedSessionDescription: "Advanced requests include a session header at send time. Session token is never shown or saved.",
        advancedSessionPrefixLabel: "Path prefix",
        advancedSessionPrefixPlaceholder: "/advanced",
        advancedSessionPrefixHint: "The prefix is immutable until this session is revoked.",
        advancedSessionDecoderLabel: "Body decoder",
        advancedSessionDecoderAuto: "Auto",
        advancedSessionDecoderRaw: "Raw bytes",
        advancedSessionDecoderJson: "JSON",
        advancedSessionDecoderText: "Text",
        advancedSessionDecoderForm: "Form",
        advancedSessionDecoderXml: "XML",
        advancedSessionDecoderMultipart: "Multipart",
        advancedSessionDiagnosticHeadersLabel: "Diagnostic response headers",
        advancedSessionExpiresLabel: "Expires",
        advancedSessionCreate: "Create session",
        advancedSessionRevoke: "Revoke session",
        advancedSessionInactive: "Advanced session inactive",
        advancedSessionCreating: "Creating Advanced session…",
        advancedSessionChecking: "Checking Advanced session…",
        advancedSessionActive: "Session active for this browser tab",
        advancedSessionError: "Advanced session operation failed",
        advancedSessionInvalidResponse: "The server returned an invalid session response",
        responseOptionsTitle: "Response options",
        responseOptionsDiagnosticHeadersLabel: "Mirror diagnostics in response headers",
        responseOptionsNoGzipLabel: "Do not compress HTTP response",
        dirPathPlaceholder: "Directory path",
        browseBtn: "Browse",
        filesSearchLabel: "Search file and folder names",
        filesSearchPlaceholder: "Search names",
        filesSearchClear: "Clear search",
        filesSearchNoMatches: "No matching names.",
        filesFilterSummary: "Showing: {0} of {1}",
        filesFilterSummaryPaged: "Showing: {0} of {1} loaded · {2} total",
        filesListActions: "List actions",
        filesCleanupHint: "Deletes all contents of uploads/. Hidden service files are preserved.",
        filesSelectVisible: "Select shown files",
        filesDeselectVisible: "Deselect shown files",
        filesColumnName: "Name",
        filesColumnActions: "Actions",
        filesSortAscending: "Sort by name descending. Currently ascending",
        filesSortDescending: "Sort by name ascending. Currently descending",
        filesSortedAscending: "Sorted by name ascending",
        filesSortedDescending: "Sorted by name descending",
        filesSelectionClearedBySearch: "Selection cleared because the search changed",
        filesSelectionCount: "Selected: {0}",
        clearSelectionBtn: "Clear selection",
        filesBrowseLoading: "Opening folder {0}…",
        filesBrowseEmpty: "This folder is empty.",
        filesBrowseInitialError: "Could not open this folder.",
        filesBrowseVisibleCount: "Showing {0} of {1}",
        filesMoreActions: "More actions",
        statusPending: "Pending",
        statusUploading: "Uploading...",
        statusSuccess: "Uploaded",
        statusError: "Error",
        queueRemoveLabel: "Remove from queue",
        queueDetailsLabel: "Error details",
        queueRetryLabel: "Retry file",
        filesBrowseStale: "Showing the saved list for {0}. Refresh failed; file actions are disabled.",
        networkError: "Network error: server unavailable",
        timeoutError: "Timeout: request took too long",
        httpErrorTitle: "HTTP error",
        httpErrorDetails: "Details",
        httpErrorRetry: "Retry",
        httpErrorClose: "Close",
        httpErrorCopy: "Copy",
        httpErrorCopied: "Error details copied",
        httpErrorCopyFailed: "Could not copy error details",
        httpErrorHeaders: "Headers",
        httpErrorBody: "Response body",
        httpErrorHtmlText: "HTML shown as text",
        httpErrorNoBody: "No response body",
        httpErrorTruncated: "Shown details limited (bytes):",
        httpErrorRequestId: "Request ID",
        parseError: "Parse error",
        error: "Error",
        uploadStarting: "Starting upload...",
        uploadComplete: "Upload complete",
        successCount: "successful",
        errorCount: "errors",
        sendingRequest: "Sending",
        preparingDemoRequest: "Preparing demo scenario",
        requestTo: "request to",
        headers: "Headers",
        headersNA: "(not available)",
        responseBody: "Response body",
        time: "Time",
        download: "Download",
        fileInfoBtn: "File metadata",
        fileInfoLoaded: "File details received",
        fileInfoError: "Could not get file details",
        fileDetailsExpand: "Show file details",
        fileDetailsCollapse: "Hide file details",
        fileDetailsLoading: "Loading details for {0}…",
        fileDetailsRetry: "Retry",
        fileDetailsTitle: "File details",
        filesInspectionMimeLine: "MIME: {0} · {1}",
        filesInspectionSourceSignature: "signature",
        filesInspectionSourceText: "text",
        filesInspectionSourceExtension: "extension",
        filesInspectionSourceUnknown: "unknown source",
        filesInspectionWarningPossibleEncryptedOrPacked: "Possibly encrypted or packed",
        filesInspectionWarningExtensionMismatch: "Extension does not match content",
        filesInspectionStateRecognized: "Format recognized",
        filesInspectionStateOpaque: "Format not recognized",
        filesInspectionStateUnknown: "Not enough data to assess",
        filesXorHintOpaque: "Format not recognized; try only if XOR was used",
        filesXorHintNeutral: "Only for files encrypted with XOR.",
        fileInfoMimeSource: "MIME source",
        fileInfoAssessment: "Content assessment",
        fileInfoExtension: "Extension",
        fileInfoCreated: "Created",
        fileInfoModified: "Modified",
        xorDecryptButtonLabel: "Download with XOR decryption",
        xorDecryptTitle: "XOR decrypt",
        xorDecryptPasswordLabel: "Key",
        xorDecryptPasswordPlaceholder: "XOR key",
        xorDecryptOutputNameLabel: "Output name",
        xorDecryptOutputNamePlaceholder: "file-name.dec",
        xorDecryptConfirm: "Decrypt",
        xorDecryptPasswordRequired: "Enter an XOR key",
        xorDecryptRunning: "XOR decrypting",
        xorDecryptSaved: "Decrypted file saved",
        xorDecryptFailed: "Could not decrypt file",
        xorDecryptWarning: "XOR cannot verify whether the key is correct. A wrong key will still save a file, but its contents will be corrupted.",
        loadingInfo: "Loading info for",
        filesBrowseSummary: "Opened folder {0} • items: {1}",
        open: "Open",
        opsecMethodPlaceholder: "Method (CHECKDATA)",
        opsecUploadText: "Name hidden",
        opsecUploadHint: "Base64, no name",
        opsecDropZoneLabel: "Choose a file for advanced upload",
        opsecSelectionIdle: "No file selected",
        opsecConstructorModeLabel: "Constructor mode",
        opsecConstructorModeManaged: "Managed",
        opsecConstructorModeExperimental: "Experimental",
        opsecProfileLabel: "Request profile",
        opsecProfileBodyJson: "Body · JSON",
        opsecProfileBodyRaw: "Body · raw bytes",
        opsecProfileBodyText: "Body · text",
        opsecProfileBodyForm: "Body · form",
        opsecProfileBodyXml: "Body · XML",
        opsecProfileMultipartBinary: "Multipart · binary part",
        opsecProfileMultipartEncoded: "Multipart · encoded field",
        opsecProfileHeaders: "Headers",
        opsecProfileQuery: "Query",
        opsecProfileCookies: "Cookies",
        opsecProfilePath: "Path",
        opsecCarrierLabel: "Payload carrier",
        opsecMimeLabel: "Declared MIME",
        opsecPartMimeLabel: "Binary part MIME",
        opsecMultipartBoundaryManaged: "The browser manages the top-level multipart boundary; the binary part MIME remains editable.",
        opsecMultipartTopLevelMimeManaged: "The browser sends the top level as multipart/form-data and manages its boundary. This field is unavailable because the browser owns that header.",
        opsecFilenamePrimaryLabel: "Primary placement",
        opsecFilenameHidden: "Hidden",
        opsecFilenameCookie: "Cookie xferry_name",
        opsecFilenameMultipart: "Multipart part filename",
        opsecFilenameCopiesLabel: "Optional exact filename copies",
        opsecNormalizationTitle: "Managed profile normalization",
        opsecNormalizationItem: "{0}: “{1}” → “{2}”.",
        opsecNormalizationCopyRemovedPrimary: "Removed copy “{0}”: it is already the primary placement.",
        opsecNormalizationCopyRemovedIncompatible: "Removed copy “{0}”: it is incompatible with the current constructor profile.",
        opsecValidationTitle: "Incompatible combination",
        opsecBinaryRequiresRaw: "Format {0} requires encoding=raw; {1} is selected. The value was not changed.",
        opsecStructuredRequiresTextEncoding: "Format {0} requires a byte-safe text encoding; {1} is selected. The value was not changed.",
        opsecCarrierRequiresTextEncoding: "Carrier {0} requires a byte-safe text encoding; {1} is selected. The value was not changed.",
        opsecRawRequiresBody: "Raw body format requires the body carrier; {0} is selected. The value was not changed.",
        opsecMultipartRequiresBody: "Format {0} can only be sent through body; {1} is selected. The value was not changed.",
        opsecFilenamePlacementIncompatible: "Filename placement {0} is incompatible with {1}/{2}. The value was not changed.",
        opsecFilenameCopyDuplicatesPrimary: "Filename copy {0} duplicates the primary placement. The value was not changed.",
        opsecMethodOverrideIncompatible: "Form-field method override requires the body carrier and a format that serializes fields; {0}/{1} is selected. The value was not changed.",
        opsecMultipartMimeBrowserManaged: "Declared MIME “{0}” cannot be sent for multipart. The browser-managed multipart/form-data header and boundary are authoritative. The value was not changed.",
        opsecMimeDecoderMismatch: "Declared MIME “{0}” does not match the actual body decoder “{1}”. Sending is allowed only when the active fixed routing decoder is “{1}”; it is currently “{2}”.",
        opsecSizeWarningTitle: "Request size",
        opsecSizeEstimateExact: "Estimated serialized request size",
        opsecSizeEstimateApproximate: "Approximate serialized request size",
        opsecSizeWarningMessage: "{0}: {1}; server limit: {2}; browser limit: {3}. Suggested action: choose “{4}” or reduce the file. No setting was changed.",
        opsecSizeWithinLimitMessage: "{0}: {1}; server limit: {2}; browser limit: {3}. Suggested action near the limit: choose “{4}”. No setting was changed.",
        opsecPreviewPending: "Building request…",
        opsecPreviewChangedBlocked: "Inputs changed after the preview was built. The preview was refreshed; click send again.",
        opsecGzipUnavailable: "This browser does not support CompressionStream for gzip+base64.",
        opsecAdvancedOptions: "Tune request shape",
        opsecAdvancedOptionsHint: "These controls do not choose a second scenario; they change the request shape inside the selected carrier.",
        opsecRequestShapeTitle: "Request shape",
        opsecPayloadOptionsTitle: "Encoding",
        opsecMetadataOptionsTitle: "Filename in request",
        opsecIncludeName: "Filename",
        opsecEncryptionMode: "Encryption",
        opsecEncryptionNone: "None",
        opsecEncryptionXor: "XOR (obfuscation)",
        opsecEncryptionAes: "AES-256-GCM",
        opsecPasswordLabel: "Encryption key",
        opsecPasswordPlaceholder: "Encryption key",
        opsecKeyBase64: "Base64",
        opsecUploadBtn: "Upload",
        opsecFileSelected: "File selected",
        opsecPasswordRequired: "Error: enter a password for encryption",
        opsecUploading: "Uploading via method",
        opsecXorEncryption: "XOR encryption",
        opsecSuccess: "Advanced upload completed",
        opsecUploaded: "Uploaded",
        opsecId: "ID",
        opsecSize: "Size",
        opsecBytes: "bytes",
        opsecStepEndpoint: "Endpoint",
        opsecStepCarrier: "Where data goes",
        opsecStepPayload: "Payload",
        opsecStepMetadata: "Metadata",
        opsecStepFile: "File",
        opsecOutcomeTitle: "Resulting request",
        opsecOutcomeMethod: "Method",
        opsecOutcomeData: "Where data goes",
        opsecOutcomeEncoding: "Encoding",
        opsecOutcomeFilename: "Filename",
        opsecOutcomeServer: "Server target",
        opsecOutcomeFilenameHidden: "Hidden",
        opsecOutcomeFilenameIncluded: "{0} • {1}",
        opsecOutcomeServerBody: "Server saves the file to uploads/",
        opsecMethodOverrideHelpNone: "No override. The server only sees the method from the first step.",
        opsecMethodOverrideHelpHeader: "Header: adds X-XFerry-Method-Override: PUT.",
        opsecMethodOverrideHelpQuery: "Query: adds ?method_override=PUT.",
        opsecMethodOverrideHelpForm: "Form: adds method_override=PUT.",
        opsecBodyFormatHelpJson: "JSON: payload is in canonical data beside encoding and encryption.",
        opsecBodyFormatHelpRaw: "Raw binary: the request body is only file bytes. Metadata moves to headers or query.",
        opsecBodyFormatHelpText: "Text: text/plain body. Use it when testing a text parser instead of JSON.",
        opsecBodyFormatHelpForm: "Form: application/x-www-form-urlencoded body with canonical data, encoding, and encryption fields.",
        opsecBodyFormatHelpMultipart: "Multipart: multipart/form-data body. Use it when the server expects form parts.",
        opsecBodyFormatHelpXml: "XML: application/xml body with the same fields inside XML nodes.",
        opsecEncodingHelpBase64: "Base64: safe text payload for Body and Headers. Size grows by roughly one third.",
        opsecEncodingHelpBase64url: "Base64url: for URL, cookies, and path. Replaces characters that break URLs.",
        opsecEncodingHelpHex: "Hex: each byte becomes two hex characters. Easy to debug, but almost doubles size.",
        opsecEncodingHelpPercent: "Percent: URL-style %XX for each byte. Makes the payload much larger.",
        opsecEncodingHelpGzipBase64: "gzip+base64: compresses first, then encodes. Useful for repetitive text data.",
        opsecEncodingHelpRaw: "Raw: no text encoding. Works only when the container can carry raw bytes.",
        opsecEncryptionHelpOff: "encryption=none is explicit; key and HMAC are absent.",
        opsecEncryptionHelpOn: "XOR is compatibility obfuscation; AES is AES-256-GCM with no fallback.",
        opsecEncryptionHelpSendKey: "A key is sent only for the selected XOR or AES mode.",
        opsecEncryptionHelpKeyBase64: "The key is sent as strict standard Base64 of its UTF-8 text.",
        opsecFilenameHelpHidden: "Filename hidden: the server creates a random ID and the original filename is not sent.",
        opsecFilenameHelpBody: "Filename in Body: adds name next to the payload.",
        opsecFilenameHelpHeaders: "Filename in Headers: adds X-XFerry-Name.",
        opsecFilenameHelpQuery: "Filename in Query: adds ?name=filename.",
        opsecFilenameHelpPath: "Filename in Path: the filename becomes a URL path segment.",
        opsecFilenameHelpContentDisposition: "Content-Disposition: the filename goes into the multipart file part; only works with Body + Multipart.",
        opsecMethodRandom: "(random)",
        opsecPathNoName: "(does not contain filename)",
        opsecNameInReq: "Name in request",
        opsecYes: "yes",
        opsecNoHidden: "no (hidden)",
        opsecEncryption: "Encryption",
        opsecNone: "none",
        opsecXorDecrypted: "XOR (decrypted on server",
        opsecKeyInBase64: ", key in base64",
        opsecXorEncrypted: "XOR (file encrypted)",
        smuggleTitle: "HTML smuggling",
        smuggleFile: "File",
        smuggleButtonLabel: "HTML smuggling",
        deleteFileAction: "Delete file",
        smuggleDownloadName: "Download name",
        smuggleProtect: "XOR obfuscation",
        smuggleProtectHint: "XOR preserves compatibility without cryptographic protection; AES-256-GCM provides authenticated encryption.",
        smuggleGenerate: "Generate",
        smuggleOpen: "Open",
        smuggleCopyUrl: "Copy one-shot URL",
        smuggleSave: "Save",
        smuggleClose: "Close",
        smuggleCancel: "Cancel",
        smuggleGenerated: "HTML generated",
        smuggleEncrypted: "XOR obfuscation",
        smugglePassword: "Password",
        smuggleYes: "Yes (XOR)",
        smuggleNo: "No",
        smuggleReady: "Choose an action.",
        smuggleCopied: "One-shot URL copied.",
        smuggleOpened: "One-shot HTML/SVG opened in a new tab.",
        smuggleResultHint: "The first GET, HEAD, conditional request, or scanner can consume the URL; regenerating does not invalidate the previous URL.",
        smuggleCapabilitiesPending: "HTML smuggling capabilities are still loading from the server.",
        smuggleCapabilitiesInvalid: "The server returned an invalid HTML smuggling capability contract.",
        smuggleCapabilitiesUnavailable: "HTML smuggling capabilities could not be obtained from the server.",
        smuggleMethodUnavailable: "The active server does not support HTML smuggling.",
        smuggleBuilderSourceSection: "Source",
        smuggleBuilderSourceName: "Source file",
        smuggleBuilderSourcePath: "Server path",
        smuggleBuilderDeliverySection: "Delivery",
        smuggleBuilderBaseName: "Base name",
        smuggleBuilderExtension: "Extension",
        smuggleBuilderPreviewName: "Resolved name",
        smuggleBuilderPresetSection: "Simple HTML page",
        smuggleBuilderPresetLabel: "Page behavior",
        smuggleBuilderPresetDirect: "Direct download",
        smuggleBuilderPresetManual: "Card + button",
        smuggleBuilderPresetAuto: "Card + auto-start",
        smuggleBuilderConstructorSection: "Constructor",
        smuggleBuilderConstructorToggle: "Use constructor renderer",
        smuggleBuilderPayloadEncoding: "Payload encoding",
        smuggleBuilderOutputFormat: "Outer artifact format",
        smuggleBuilderTriggerMethod: "Trigger element",
        smuggleBuilderTriggerEvent: "Trigger event",
        smuggleBuilderDownloadVariant: "Download variant",
        smuggleBuilderPageTemplate: "Visual template",
        smuggleBuilderMimeType: "Extracted file MIME",
        smuggleBuilderNullByte: "NUL before outer artifact",
        smuggleBuilderConstructorGroupPayload: "Payload",
        smuggleBuilderConstructorGroupTrigger: "Trigger",
        smuggleBuilderConstructorGroupOutput: "Output",
        smuggleBuilderPayloadEncodingHelp: "How file bytes are represented inside the page.",
        smuggleBuilderOutputFormatHelp: "Generated page file extension, such as html, svg, or xml.",
        smuggleBuilderTriggerHelp: "Element and event pair that starts the download behavior.",
        smuggleBuilderDownloadVariantHelp: "Technical method used to hand the file to the browser.",
        smuggleBuilderPageTemplateHelp: "Visual styling of the page, not the file extension.",
        smuggleBuilderNullByteHelp: "Adds one leading zero byte to the generated file.",
        smuggleBuilderConstructorHint: "These fields mirror the HTML Smuggling constructor: payload encoding, file format, trigger event, download variant, and MIME.",
        smuggleBuilderAdvancedSection: "Page text",
        smuggleBuilderTitleLabel: "Title",
        smuggleBuilderMessageLabel: "Message",
        smuggleBuilderCtaLabel: "Button label",
        smuggleBuilderDelayLabel: "Auto-start delay, ms",
        smuggleBuilderNoticeLabel: "Show internal-check marker",
        smuggleBuilderDefaultTitle: "Test HTML ready",
        smuggleBuilderDefaultMessage: "Neutral internal HTML.",
        smuggleBuilderDefaultCta: "Download test HTML",
        opsecTransportLabel: "Transport:",
        opsecTransportBody: "Body",
        opsecTransportHeaders: "Headers",
        opsecTransportUrl: "URL Params",
        opsecTransportCookies: "Cookies",
        opsecTransportPath: "Path",
        opsecTransportUsed: "Transport",
        opsecBodyFormatLabel: "Body format",
        opsecBodyFormatJson: "JSON",
        opsecBodyFormatRaw: "Raw binary",
        opsecBodyFormatText: "Text",
        opsecBodyFormatForm: "Form",
        opsecBodyFormatMultipart: "Multipart",
        opsecBodyFormatXml: "XML",
        opsecEncodingLabel: "Encoding",
        opsecEncodingBase64: "Base64",
        opsecEncodingBase64url: "Base64url",
        opsecEncodingHex: "Hex",
        opsecEncodingPercent: "Percent",
        opsecEncodingGzipBase64: "gzip+base64",
        opsecEncodingRaw: "Raw",
        opsecMetadataLabel: "Filename placement",
        opsecMetadataBody: "Body",
        opsecMetadataHeaders: "Headers",
        opsecMetadataQuery: "Query",
        opsecMetadataPath: "Path",
        opsecMetadataContentDisposition: "Content-Disposition",
        opsecMethodOverrideLabel: "Override",
        opsecMethodOverrideNone: "None",
        opsecMethodOverrideHeader: "Header",
        opsecMethodOverrideQuery: "Query",
        opsecMethodOverrideForm: "method_override field",
        viewInFiles: "Open Files",
        tabNotepad: "Notepad",
        notepadTitle: "Secure Notepad",
        notepadDesc: "Note bodies are end-to-end encrypted. Titles remain server-visible metadata.",
        notepadRequirements: "Requires the default server crypto backend and a browser with Web Crypto support.",
        notepadTitlePlaceholder: "Title (server-visible)",
        notepadTextareaPlaceholder: "Text... (encrypted)",
        notepadTextareaLabel: "Note text",
        notepadNewBtn: "New",
        notepadDeleteBtn: "Delete",
        notepadNotes: "Notes",
        notepadNoNotes: "No notes",
        notepadConnecting: "Connecting...",
        notepadConnected: "Online",
        notepadDisconnected: "Offline",
        notepadReady: "Ready",
        notepadUnsaved: "Unsaved",
        notepadSaving: "Saving...",
        notepadSaved: "Saved",
        notepadLoading: "Loading...",
        notepadLoaded: "Loaded",
        notepadSaveError: "Save error",
        notepadLoadError: "Load error",
        notepadDecryptError: "Decrypt error",
        notepadSessionFailed: "Session initialization failed",
        notepadUnavailableServer: "Notepad unavailable: repair or reinstall the server default runtime dependencies.",
        notepadUnavailableBrowser: "Notepad unavailable: no Web Crypto.",
        notepadTransportHttp: "HTTP",
        notepadTransportWs: "WS",
        notepadEphemeralWarning: "Saved note text can become undecryptable after a page reload, browser or server restart, session TTL expiry, or LRU eviction. No recovery key is stored.",
        notepadLossDetailsSummary: "What the server stores",
        notepadLossDetailsBody: "The server stores encrypted text and metadata such as the title, but not the AES key or recovery material. The HTTP/WS Notepad is not a backup, sync, or server-side recovery feature.",
        notepadUntitled: "Untitled",
        notepadTitleMetadataHint: "Note text is encrypted. The title is server-visible metadata.",
        notepadDiscardTitle: "Unsaved changes",
        notepadDiscardConfirm: "Changes could not be saved before leaving this note. Discard them?",
        notepadDiscardBtn: "Discard",
        notepadDeleteConfirm: "Delete this note?",
        notepadDeleteSelectedBtn: "Delete selected notes",
        notepadDeleteSelectedConfirm: "Delete selected notes?",
        notepadSelectedDeleted: "Selected notes deleted",
        selectNoteLabel: "Select note",
        notepadClearBtn: "Clear notes",
        notepadClearConfirm: "Delete all notes from notes/? Files in uploads/ will not be touched.",
        notepadCleared: "Notes cleared",
        notepadClearError: "Clear notes error",
        notepadReconnecting: "Reconnecting...",
        charCountSuffix: "chars",
        deleteBtn: "Delete",
        deleteConfirm: "Delete this file?",
        deleteSuccess: "File deleted",
        deleteError: "Delete error",
        selectFileLabel: "Select file",
        deleteSelectedFilesBtn: "Delete selected files",
        deleteSelectedFilesCount: "Delete selected ({0})",
        deleteSelectedFilesConfirm: "Delete selected files from uploads/?",
        deleteSelectedFilesSuccess: "Selected files deleted",
        deleteSelectedFilesRefreshError: "Files deleted ({0}), but the list could not be refreshed",
        filesToastDismiss: "Dismiss notification",
        clearUploadsBtn: "Clear uploads/",
        clearUploadsConfirm: "Delete all contents of uploads/? Hidden service files will be preserved.",
        clearUploadsRunning: "Clearing uploads/...",
        clearUploadsSuccess: "uploads/ cleared",
        clearUploadsError: "Clear uploads/ error",
        filesDeleted: "files deleted",
        dirsDeleted: "folders deleted",
        notepadDeleteError: "Note delete error",
        okBtn: "OK",
        downloadStarted: "Download started",
        downloadCompleted: "Download complete",
        downloadFailed: "Download failed",
        downloadProgress: "Downloading",
        downloadSpeed: "Speed",
        downloadEta: "ETA"
    }
};

const supportedLangs = new Set(['ru', 'en']);

function normalizeLang(lang) {
    return supportedLangs.has(lang) ? lang : 'ru';
}

const storedLang = safeGetStorageItem('lang');
let currentLang = normalizeLang(storedLang);
if (storedLang && storedLang !== currentLang) {
    safeSetStorageItem('lang', currentLang);
}

function setLang(lang) {
    currentLang = normalizeLang(lang);
    safeSetStorageItem('lang', currentLang);
    document.documentElement.lang = currentLang;
    applyTranslations();
    updateLangButtons();
    syncThemeButtonState();
}

function applyTranslations() {
    const localeTranslations = translations[currentLang] || translations.ru;

    // Обновляем все элементы с data-i18n
    document.querySelectorAll('[data-i18n]').forEach(el => {
        const key = el.getAttribute('data-i18n');
        if (localeTranslations[key]) {
            el.textContent = localeTranslations[key];
        }
    });

    // Обновляем placeholder'ы
    document.querySelectorAll('[data-i18n-placeholder]').forEach(el => {
        const key = el.getAttribute('data-i18n-placeholder');
        if (localeTranslations[key]) {
            el.placeholder = localeTranslations[key];
        }
    });

    document.querySelectorAll('[data-i18n-title]').forEach(el => {
        const key = el.getAttribute('data-i18n-title');
        if (localeTranslations[key]) {
            el.title = localeTranslations[key];
        }
    });

    document.querySelectorAll('[data-i18n-aria-label]').forEach(el => {
        const key = el.getAttribute('data-i18n-aria-label');
        if (localeTranslations[key]) {
            el.setAttribute('aria-label', localeTranslations[key]);
        }
    });

    app.emit(app.events.LOCALE_CHANGED, { lang: currentLang });
}

function updateLangButtons() {
    const controls = [
        {
            button: document.getElementById('langRu'),
            lang: 'ru',
            selectedKey: 'langRussianSelectedLabel',
            selectKey: 'langRussianSelectLabel',
        },
        {
            button: document.getElementById('langEn'),
            lang: 'en',
            selectedKey: 'langEnglishSelectedLabel',
            selectKey: 'langEnglishSelectLabel',
        },
    ];

    controls.forEach(({ button, lang, selectedKey, selectKey }) => {
        if (!button) {
            return;
        }
        const selected = currentLang === lang;
        const label = t(selected ? selectedKey : selectKey);
        button.classList.toggle('active', selected);
        button.setAttribute('aria-pressed', String(selected));
        button.setAttribute('aria-label', label);
        button.title = label;
    });
}

function t(key) {
    const localeTranslations = translations[currentLang] || translations.ru;
    return localeTranslations[key] || translations.ru[key] || key;
}

// Применяем переводы при загрузке
document.addEventListener('DOMContentLoaded', () => {
    document.documentElement.lang = currentLang;
    applyTranslations();
    updateLangButtons();
    syncThemeButtonState();
});

// HTML escape helper (XSS prevention)
function esc(str) {
    const div = document.createElement('div');
    div.textContent = String(str);
    return div.innerHTML;
}

function formatSize(bytes) {
    const value = Number(bytes) || 0;
    if (value < 1024) return value + ' B';
    if (value < 1024 * 1024) return (value / 1024).toFixed(1) + ' KB';
    if (value < 1024 * 1024 * 1024) return (value / (1024 * 1024)).toFixed(1) + ' MB';
    return (value / (1024 * 1024 * 1024)).toFixed(1) + ' GB';
}

function parseJsonSafe(text) {
    try {
        return JSON.parse(text);
    } catch (_error) {
        return null;
    }
}

function formatHttpStatusLabel(status, statusText = '') {
    const normalizedStatusText = String(statusText || '').trim();
    if (normalizedStatusText) {
        return `${status} ${normalizedStatusText}`;
    }
    const fallback = {
        200: 'OK',
        201: 'Created',
        204: 'No Content',
        404: 'Not Found',
    }[status];
    return fallback ? `${status} ${fallback}` : String(status);
}

function formatActionErrorMessage(baseMessage, error) {
    const detail = String(error?.message || '').trim();
    return detail && detail !== baseMessage
        ? `${baseMessage}: ${detail}`
        : baseMessage;
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

function bindDropZoneKeyboardTrigger(container, input) {
    if (!container || !input) {
        return;
    }
    container.addEventListener('keydown', (event) => {
        if (event.key === 'Enter' || event.key === ' ') {
            event.preventDefault();
            if (input.disabled || container.getAttribute('aria-disabled') === 'true') {
                return;
            }
            input.click();
        }
    });
}

// Базовый URL сервера (если страница открыта не с нашего сервера)
const SERVER_URL = '';
const liveRegionTimers = new Map();

// Server access scope flag
let serverSupportedMethods = null;
let serverMethodGroups = null;
let serverSmuggleCapabilities = null;
let serverDiscoveryStatus = 'pending';
let serverDiscoveryGeneration = 0;

function isServerMethodSupported(method) {
    if (!Array.isArray(serverSupportedMethods)) {
        return true;
    }
    return serverSupportedMethods.includes(String(method || '').toUpperCase());
}

function isServerMethodInGroup(method, group) {
    const normalizedMethod = String(method || '').toUpperCase();
    if (!isServerMethodSupported(normalizedMethod)) {
        return false;
    }
    if (!serverMethodGroups) {
        return true;
    }
    const groupedMethods = serverMethodGroups?.[String(group || '')];
    return Array.isArray(groupedMethods) && groupedMethods.includes(normalizedMethod);
}

function getVisibleToolTabs() {
    return Array.from(document.querySelectorAll('.tab[role="tab"][data-tab-target]'))
        .filter(button => !button.hidden);
}

function getFirstAvailableToolTabName() {
    const firstButton = getVisibleToolTabs()[0];
    return firstButton?.dataset.tabTarget || '';
}

function refreshToolEntrypoints() {
    document.querySelectorAll('.tab[role="tab"][data-tab-target]').forEach(button => {
        button.hidden = false;
        button.setAttribute('aria-hidden', 'false');
        button.disabled = false;
    });

    const activeTabButton = document.querySelector('.tab[role="tab"].active[data-tab-target]');
    if (activeTabButton && !activeTabButton.hidden) {
        return;
    }

    const fallbackTabName = getFirstAvailableToolTabName();
    if (fallbackTabName) {
        switchTab(fallbackTabName, document.getElementById(`tab-${fallbackTabName}`));
    }
}

function refreshServerMethodBoundControls() {
    document.querySelectorAll('[data-request-method]').forEach(button => {
        const supported = isServerMethodSupported(button.dataset.requestMethod);
        button.disabled = !supported;
    });
    refreshToolEntrypoints();

    app.emit(app.events.SERVER_METHODS_CHANGED, {
        serverDiscoveryStatus,
        supportedMethods: serverSupportedMethods ? [...serverSupportedMethods] : null,
        methodGroups: serverMethodGroups
            ? Object.fromEntries(
                Object.entries(serverMethodGroups).map(([group, methods]) => [group, [...methods]])
            )
            : null,
    });
}

function setServerMethodsFromPing(info) {
    serverSupportedMethods = Array.isArray(info?.supported_methods)
        ? Array.from(new Set(
            info.supported_methods
                .map(method => String(method).trim().toUpperCase())
                .filter(Boolean)
        ))
        : null;
    serverMethodGroups = info?.method_groups && typeof info.method_groups === 'object'
        ? Object.fromEntries(
            Object.entries(info.method_groups).map(([group, methods]) => [
                group,
                Array.isArray(methods)
                    ? Array.from(new Set(
                        methods
                            .map(method => String(method).trim().toUpperCase())
                            .filter(Boolean)
                    ))
                    : [],
            ])
        )
        : null;
    serverSmuggleCapabilities = Object.prototype.hasOwnProperty.call(info || {}, 'smuggle_capabilities')
        ? info.smuggle_capabilities
        : null;
    refreshServerMethodBoundControls();
}

function updateVisibleAppVersionFromPing(info) {
    const versionEl = document.getElementById('appVersion');
    if (!versionEl) {
        return;
    }

    const serverLabel = String(info?.server || '');
    const serverMatch = serverLabel.match(/^XFerry\/(.+)$/);
    const version = (serverMatch ? serverMatch[1] : String(info?.version || '')).trim();
    if (!version) {
        return;
    }

    versionEl.textContent = `v${version}`;
    versionEl.dataset.appVersion = version;
}

function announceLiveRegion(regionId, message) {
    const region = document.getElementById(regionId);
    if (!region) {
        return;
    }

    const nextMessage = String(message || '').trim();
    const pendingTimer = liveRegionTimers.get(regionId);
    if (pendingTimer) {
        clearTimeout(pendingTimer);
    }

    region.textContent = '';
    if (!nextMessage) {
        liveRegionTimers.delete(regionId);
        return;
    }

    const timer = setTimeout(() => {
        if (document.getElementById(regionId) === region) {
            region.textContent = nextMessage;
        }
        liveRegionTimers.delete(regionId);
    }, 20);

    liveRegionTimers.set(regionId, timer);
}

// Проверяем режим сервера при загрузке страницы
async function checkServerMode() {
    const discoveryGeneration = ++serverDiscoveryGeneration;
    serverDiscoveryStatus = 'pending';
    refreshServerMethodBoundControls();
    try {
        const response = await app.service('http').request(
            'PING',
            SERVER_URL + '/',
            null,
            {},
            null,
            { dataPlane: false }
        );
        if (!response.ok) {
            throw new Error(`PING failed with HTTP ${response.status || 0}`);
        }
        const text = await response.text();
        const info = JSON.parse(text);
        if (discoveryGeneration !== serverDiscoveryGeneration) {
            return;
        }

        if (info.access_scope === 'uploads') {
            const browsePathInput = app.element('files.path');
            if (browsePathInput) {
                browsePathInput.value = '/';
            }
        }
        updateVisibleAppVersionFromPing(info);
        serverDiscoveryStatus = 'ready';
        setServerMethodsFromPing(info);
    } catch (e) {
        if (discoveryGeneration !== serverDiscoveryGeneration) {
            return;
        }
        serverSupportedMethods = null;
        serverMethodGroups = null;
        serverSmuggleCapabilities = null;
        serverDiscoveryStatus = 'unavailable';
        refreshServerMethodBoundControls();
        console.log('Could not check server mode:', e);
    }
}
function focusElementWithoutScroll(element) {
    if (!element || typeof element.focus !== 'function') {
        return;
    }

    try {
        element.focus({ preventScroll: true });
    } catch (error) {
        element.focus();
    }
}

function resolveToolTabRequest(tabName, tabButton = null) {
    const requestedButton = tabButton || document.getElementById(`tab-${tabName}`);
    if (requestedButton && !requestedButton.hidden) {
        return {
            tabName,
            button: requestedButton,
        };
    }

    const fallbackTabName = getFirstAvailableToolTabName();
    const fallbackButton = fallbackTabName ? document.getElementById(`tab-${fallbackTabName}`) : null;
    return {
        tabName: fallbackTabName || tabName,
        button: fallbackButton,
    };
}

function scrollActiveTabIntoView(tabButton) {
    const tabList = tabButton?.closest('[role="tablist"]');
    if (!tabList || tabList.scrollWidth <= tabList.clientWidth + 1) {
        return;
    }

    try {
        tabButton.scrollIntoView({ block: 'nearest', inline: 'center' });
    } catch (error) {
        const tabLeft = tabButton.offsetLeft;
        const tabWidth = tabButton.offsetWidth;
        tabList.scrollLeft = tabLeft - Math.max(0, (tabList.clientWidth - tabWidth) / 2);
    }
}

function switchTab(tabName, tabButton, options = {}) {
    const { focusTabButton = false } = options;
    const resolved = resolveToolTabRequest(tabName, tabButton);
    const resolvedTabName = resolved.tabName;
    const resolvedTabButton = resolved.button;
    if (!resolvedTabButton) {
        return;
    }

    document.querySelectorAll('.tab[role="tab"]').forEach(t => {
        t.classList.remove('active');
        t.setAttribute('aria-selected', 'false');
        t.setAttribute('tabindex', '-1');
    });
    document.querySelectorAll('.tab-content[role="tabpanel"]').forEach(panel => {
        panel.classList.remove('active');
        panel.hidden = true;
    });

    resolvedTabButton.classList.add('active');
    resolvedTabButton.setAttribute('aria-selected', 'true');
    resolvedTabButton.setAttribute('tabindex', '0');
    scrollActiveTabIntoView(resolvedTabButton);

    const targetPanel = document.getElementById(resolvedTabName + '-tab');
    if (targetPanel) {
        targetPanel.classList.add('active');
        targetPanel.hidden = false;
    }

    if (document.body) {
        document.body.dataset.activeMode = resolvedTabName;
    }

    // Update URL hash
    history.replaceState(null, '', '#' + resolvedTabName);

    if (focusTabButton) {
        focusElementWithoutScroll(resolvedTabButton);
    }

    app.emit(app.events.WORKSPACE_CHANGED, {
        workspace: resolvedTabName,
        focusTabButton,
    });
}

function bindCoreControls() {
    document.querySelectorAll('[data-lang]').forEach(button => {
        button.addEventListener('click', () => {
            setLang(button.dataset.lang || 'ru');
        });
    });

    const themeBtn = document.getElementById('themeBtn');
    if (themeBtn) {
        themeBtn.addEventListener('click', toggleTheme);
    }

    document.querySelectorAll('.tab[role="tab"][data-tab-target]').forEach(button => {
        button.addEventListener('click', (event) => {
            const tabName = button.dataset.tabTarget;
            if (tabName) {
                const focusTabButton = event.detail === 0;
                switchTab(tabName, button, { focusTabButton });
            }
        });
    });
}

bindCoreControls();

function activateTabFromHash() {
    const hashAliases = {
        advanced: 'opsec',
        send: 'upload',
    };
    const rawHash = location.hash.replace('#', '');
    const hash = hashAliases[rawHash] || rawHash;
    if (hash && document.getElementById(hash + '-tab')) {
        const tabBtn = document.getElementById('tab-' + hash);
        if (tabBtn) {
            switchTab(hash, tabBtn);
            return;
        }
    }

    const fallbackTabName = getFirstAvailableToolTabName() || 'upload';
    if (fallbackTabName) {
        switchTab(fallbackTabName, document.getElementById(`tab-${fallbackTabName}`));
    }
}

// Keep the active tab in sync with direct URL hashes and manual hash edits.
window.addEventListener('DOMContentLoaded', () => {
    activateTabFromHash();
});
window.addEventListener('hashchange', () => {
    activateTabFromHash();
});
window.addEventListener('resize', () => {
    scrollActiveTabIntoView(document.querySelector('.tab[role="tab"].active[data-tab-target]'));
});

// Arrow key navigation for tabs (WAI-ARIA tab pattern)
const tabList = document.querySelector('[role="tablist"]');
if (tabList) {
    tabList.addEventListener('keydown', (e) => {
        const tabs = getVisibleToolTabs();
        const currentIndex = tabs.indexOf(document.activeElement);
        if (currentIndex === -1) return;

        let newIndex;
        if (e.key === 'ArrowRight') {
            newIndex = (currentIndex + 1) % tabs.length;
        } else if (e.key === 'ArrowLeft') {
            newIndex = (currentIndex - 1 + tabs.length) % tabs.length;
        } else if (e.key === 'Home') {
            newIndex = 0;
        } else if (e.key === 'End') {
            newIndex = tabs.length - 1;
        } else {
            return;
        }
        e.preventDefault();
        tabs[newIndex].focus();
        tabs[newIndex].click();
    });
}

app.registerService('core', {
    t,
    escapeHtml: esc,
    formatSize,
    parseJsonSafe,
    formatHttpStatusLabel,
    formatActionErrorMessage,
    writeTextToClipboard,
    serverUrl: SERVER_URL,
    announceLiveRegion,
    bindDropZoneKeyboardTrigger,
    isServerMethodSupported,
    isServerMethodInGroup,
    focusElementWithoutScroll,
    switchWorkspace: switchTab,
    checkServer: checkServerMode,
    getState: () => ({
        lang: currentLang,
        supportedMethods: serverSupportedMethods ? [...serverSupportedMethods] : null,
        methodGroups: serverMethodGroups
            ? Object.fromEntries(
                Object.entries(serverMethodGroups).map(([group, methods]) => [group, [...methods]])
            )
            : null,
        smuggleCapabilities: serverSmuggleCapabilities,
        serverDiscoveryStatus,
    }),
});
})(window.XferryApp);
