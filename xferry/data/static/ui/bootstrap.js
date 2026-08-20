(function bootstrapXferryApp(global) {
    'use strict';

    if (global.XferryApp) {
        throw new Error('XferryApp is already initialized');
    }

    const initialGlobalNames = new Set(Object.getOwnPropertyNames(global));
    const events = Object.freeze({
        LOCALE_CHANGED: 'locale.changed',
        SERVER_METHODS_CHANGED: 'server.methods.changed',
        WORKSPACE_CHANGED: 'workspace.changed',
        APP_READY: 'app.ready',
    });
    const knownEvents = new Set(Object.values(events));
    const listeners = new Map();
    const services = new Map();
    const workflows = new Map();

    const dom = Object.freeze({
        'app.version': '#appVersion',
        'tabs.list': '.tabs[role="tablist"]',
        'tab.send': '#tab-upload',
        'tab.files': '#tab-files',
        'tab.requests': '#tab-request',
        'tab.advanced': '#tab-opsec',
        'tab.notepad': '#tab-notepad',
        'panel.send': '#upload-tab',
        'panel.files': '#files-tab',
        'panel.requests': '#request-tab',
        'panel.advanced': '#opsec-tab',
        'panel.notepad': '#notepad-tab',
        'files.path': '#browsePathInput',
        'files.list': '#serverFiles',
        'notepad.editor': '#notepadTextarea',
        'upload.input': '#fileInput',
    });

    function assertName(kind, name) {
        if (!/^[a-z][a-z0-9.-]*$/.test(String(name || ''))) {
            throw new TypeError(`${kind} name must be a stable lowercase identifier`);
        }
    }

    function assertApi(kind, api) {
        if (!api || typeof api !== 'object' || Array.isArray(api)) {
            throw new TypeError(`${kind} API must be an object`);
        }
    }

    function registerService(name, api) {
        assertName('Service', name);
        assertApi('Service', api);
        if (services.has(name)) {
            throw new Error(`Service already registered: ${name}`);
        }
        services.set(name, Object.freeze({ ...api }));
        return services.get(name);
    }

    function service(name) {
        if (!services.has(name)) {
            throw new Error(`Service is not registered: ${name}`);
        }
        return services.get(name);
    }

    function registerWorkflow(name, definition) {
        assertName('Workflow', name);
        assertApi('Workflow', definition);
        if (workflows.has(name)) {
            throw new Error(`Workflow already registered: ${name}`);
        }

        const commands = definition.commands || {};
        assertApi('Workflow commands', commands);
        Object.entries(commands).forEach(([commandName, command]) => {
            assertName('Command', commandName);
            if (typeof command !== 'function') {
                throw new TypeError(`Workflow command must be a function: ${name}.${commandName}`);
            }
        });
        if (definition.getState !== undefined && typeof definition.getState !== 'function') {
            throw new TypeError(`Workflow getState must be a function: ${name}`);
        }

        workflows.set(name, Object.freeze({
            commands: Object.freeze({ ...commands }),
            getState: definition.getState || (() => ({})),
        }));
        return workflows.get(name);
    }

    function hasWorkflow(name) {
        return workflows.has(name);
    }

    function invoke(name, commandName, ...args) {
        const workflow = workflows.get(name);
        if (!workflow) {
            throw new Error(`Workflow is not registered: ${name}`);
        }
        const command = workflow.commands[commandName];
        if (typeof command !== 'function') {
            throw new Error(`Workflow command is not registered: ${name}.${commandName}`);
        }
        return command(...args);
    }

    function getState(name) {
        const workflow = workflows.get(name);
        if (!workflow) {
            throw new Error(`Workflow is not registered: ${name}`);
        }
        const snapshot = workflow.getState();
        if (!snapshot || typeof snapshot !== 'object' || Array.isArray(snapshot)) {
            throw new TypeError(`Workflow state snapshot must be an object: ${name}`);
        }
        return Object.freeze({ ...snapshot });
    }

    function on(eventName, listener) {
        if (!knownEvents.has(eventName)) {
            throw new Error(`Unknown application event: ${eventName}`);
        }
        if (typeof listener !== 'function') {
            throw new TypeError(`Application event listener must be a function: ${eventName}`);
        }
        const eventListeners = listeners.get(eventName) || new Set();
        eventListeners.add(listener);
        listeners.set(eventName, eventListeners);
        return () => {
            eventListeners.delete(listener);
        };
    }

    function emit(eventName, detail = {}) {
        if (!knownEvents.has(eventName)) {
            throw new Error(`Unknown application event: ${eventName}`);
        }
        const eventListeners = Array.from(listeners.get(eventName) || []);
        eventListeners.forEach(listener => {
            try {
                listener(detail);
            } catch (error) {
                console.error(`[XferryApp] ${eventName} listener failed`, error);
            }
        });
    }

    function element(contractName) {
        const selector = dom[contractName];
        if (!selector) {
            throw new Error(`Unknown DOM contract: ${contractName}`);
        }
        return document.querySelector(selector);
    }

    function describe() {
        return Object.freeze({
            events: Object.freeze(Object.values(events)),
            dom: Object.freeze(Object.keys(dom)),
            services: Object.freeze(Object.fromEntries(
                Array.from(services.entries()).map(([name, api]) => [
                    name,
                    Object.freeze(Object.keys(api).sort()),
                ])
            )),
            workflows: Object.freeze(Object.fromEntries(
                Array.from(workflows.entries()).map(([name, workflow]) => [
                    name,
                    Object.freeze(Object.keys(workflow.commands).sort()),
                ])
            )),
        });
    }

    function unexpectedGlobals(allowedNames = []) {
        const allowed = new Set(['XferryApp', 'CryptoJS', ...allowedNames]);
        return Object.freeze(
            Object.getOwnPropertyNames(global)
                .filter(name => !initialGlobalNames.has(name) && !allowed.has(name))
                .sort()
        );
    }

    const api = Object.freeze({
        events,
        dom,
        registerService,
        service,
        registerWorkflow,
        hasWorkflow,
        invoke,
        getState,
        on,
        emit,
        element,
        describe,
        unexpectedGlobals,
    });

    Object.defineProperty(global, 'XferryApp', {
        value: api,
        enumerable: true,
        configurable: false,
        writable: false,
    });
})(window);
