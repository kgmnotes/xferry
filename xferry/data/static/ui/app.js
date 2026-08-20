(function initializeApplication(app) {
    'use strict';

    const core = app.service('core');
    const inspector = app.service('inspector');

    void core.checkServer();

    ['upload', 'opsec', 'files', 'notepad'].forEach(scope => {
        inspector.setInspector(scope, {
            phase: 'empty',
            request: {
                phase: 'empty',
                emptyText: core.t('exchangeRequestEmpty'),
            },
            response: {
                phase: 'empty',
                emptyText: core.t('exchangeResponseEmpty'),
            },
        });
    });

    window.addEventListener('beforeunload', (event) => {
        if (app.getState('notepad').dirty) {
            event.preventDefault();
        }
    });

    document.addEventListener('keydown', (event) => {
        if ((event.ctrlKey || event.metaKey) && event.key === 's') {
            const notepadPanel = app.element('panel.notepad');
            if (notepadPanel?.classList.contains('active')) {
                event.preventDefault();
                void app.invoke('notepad', 'save');
            }
        }

        if ((event.ctrlKey || event.metaKey) && event.key === 'Enter') {
            const uploadPanel = app.element('panel.send');
            if (uploadPanel?.classList.contains('active')) {
                event.preventDefault();
                void app.invoke('upload', 'send');
            }
        }
    });

    app.emit(app.events.APP_READY, {
        publicSurface: app.describe(),
    });
})(window.XferryApp);
