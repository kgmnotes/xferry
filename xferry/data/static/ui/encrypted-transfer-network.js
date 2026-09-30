(function initializeEncryptedTransferNetwork(app) {
    'use strict';

    const transientStatuses = new Set([408, 429, 500, 502, 503, 504]);
    const maxCiphertextChunk = 8 * 1024 * 1024 + 16;

    function transferError(message, code, extras = {}) {
        return Object.assign(new Error(message), { code, ...extras });
    }

    function abortError() {
        return new DOMException('Transfer canceled', 'AbortError');
    }

    function signals(options, context) {
        return [...new Set([options?.signal, context.signal].filter(Boolean))];
    }

    function throwIfAborted(inputSignals) {
        if (inputSignals.some(signal => signal.aborted)) throw abortError();
    }

    // One watchdog covers connection setup, response headers, and body reads.
    // Racing against it also handles transports that ignore AbortSignal.
    function attemptScope(inputSignals, context) {
        throwIfAborted(inputSignals);
        const controller = new AbortController();
        const stallMs = context.stallMs ?? 30000;
        let timer;
        let disposed = false;
        let rejection;
        const canceled = new Promise((_resolve, reject) => { rejection = reject; });
        canceled.catch(() => {});
        const fail = error => {
            if (controller.signal.aborted) return;
            controller.abort(error);
            rejection(error);
        };
        const onAbort = () => fail(abortError());
        inputSignals.forEach(signal => signal.addEventListener('abort', onAbort, { once: true }));
        const reset = () => {
            if (disposed || controller.signal.aborted) return;
            clearTimeout(timer);
            timer = setTimeout(() => fail(transferError('Network transfer stalled', 'timeout')), stallMs);
            timer.unref?.();
        };
        reset();
        return {
            signal: controller.signal,
            reset,
            race: promise => Promise.race([promise, canceled]),
            dispose() {
                disposed = true;
                clearTimeout(timer);
                inputSignals.forEach(signal => signal.removeEventListener('abort', onAbort));
            },
        };
    }

    function retryAfter(value) {
        if (!value) return 0;
        const seconds = Number(value);
        if (Number.isFinite(seconds) && seconds >= 0) return seconds * 1000;
        const date = Date.parse(value);
        return Number.isFinite(date) ? Math.max(0, date - Date.now()) : 0;
    }

    function httpError(status, payload, after = '') {
        return transferError(
            typeof payload?.error?.message === 'string'
                ? payload.error.message : `Encrypted transfer failed (HTTP ${status})`,
            typeof payload?.error?.code === 'string' ? payload.error.code : 'http',
            { status, retryAfterMs: retryAfter(after), details: payload?.error?.details }
        );
    }

    function retryable(error) {
        return transientStatuses.has(error?.status)
            || (error?.status === undefined && (
                error instanceof TypeError
                || ['network', 'timeout', 'truncated'].includes(error?.code)
            ));
    }

    async function waitForNetworkOrDelay(inputSignals, delayMs, offline) {
        throwIfAborted(inputSignals);
        const target = typeof window?.addEventListener === 'function' ? window : globalThis;
        await new Promise((resolve, reject) => {
            let timer;
            const cleanup = () => {
                clearTimeout(timer);
                inputSignals.forEach(signal => signal.removeEventListener('abort', onAbort));
                if (offline) target.removeEventListener?.('online', onOnline);
            };
            const onAbort = () => { cleanup(); reject(abortError()); };
            const onOnline = () => { cleanup(); resolve(); };
            inputSignals.forEach(signal => signal.addEventListener('abort', onAbort, { once: true }));
            if (offline) {
                if (typeof target.addEventListener !== 'function') {
                    cleanup();
                    reject(transferError('Browser cannot observe network recovery', 'unsupported'));
                    return;
                }
                target.addEventListener('online', onOnline, { once: true });
                if (globalThis.navigator?.onLine !== false) onOnline();
            } else {
                timer = setTimeout(() => { cleanup(); resolve(); }, delayMs);
            }
            if (inputSignals.some(signal => signal.aborted)) onAbort();
        });
    }

    async function retry(operation, options, context) {
        const inputSignals = signals(options, context);
        let attempt = 0;
        while (true) {
            throwIfAborted(inputSignals);
            if (globalThis.navigator?.onLine === false) {
                context.onWait?.({ attempt, delayMs: 0, offline: true });
                await waitForNetworkOrDelay(inputSignals, 0, true);
            }
            const scope = attemptScope(inputSignals, context);
            let error;
            try {
                return await scope.race(operation(scope));
            } catch (caught) {
                throwIfAborted(inputSignals);
                if (caught?.name === 'AbortError' || !retryable(caught)) throw caught;
                error = caught;
            } finally {
                scope.dispose();
            }
            attempt += 1;
            const offline = globalThis.navigator?.onLine === false;
            const base = context.retryBaseMs ?? 1000;
            const max = context.maxDelayMs ?? 30000;
            const random = context.random || Math.random;
            const backoff = Math.min(max, base * 2 ** Math.min(attempt - 1, 30));
            const delayMs = offline ? 0 : Math.max(error.retryAfterMs || 0, Math.round(backoff * (0.8 + random() * 0.4)));
            context.onWait?.({ attempt, delayMs, offline });
            await waitForNetworkOrDelay(inputSignals, delayMs, offline);
        }
    }

    async function consumeJson(response, scope, jsonLimitBytes = 16 * 1024 * 1024) {
        if (!Number.isSafeInteger(jsonLimitBytes) || jsonLimitBytes < 1 ||
            jsonLimitBytes > 32 * 1024 * 1024)
            throw transferError('Encrypted JSON response limit is invalid', 'protocol');
        let text;
        if (!response.body?.getReader) {
            try { return await scope.race(response.json()); }
            catch (error) {
                if (retryable(error) || error?.name === 'AbortError') throw error;
                throw transferError('Encrypted transfer returned invalid JSON', 'protocol');
            }
        }
        const reader = response.body.getReader();
        const decoder = new TextDecoder();
        let length = 0;
        text = '';
        let complete = false;
        try {
            while (true) {
                const result = await scope.race(reader.read());
                if (result.done) break;
                if (result.value.byteLength) scope.reset();
                length += result.value.byteLength;
                if (length > jsonLimitBytes) {
                    throw transferError('Encrypted transfer response is too large', 'protocol');
                }
                text += decoder.decode(result.value, { stream: true });
            }
            text += decoder.decode();
            complete = true;
        } finally {
            if (!complete) reader.cancel().catch(() => {});
            try { reader.releaseLock(); } catch (_error) { /* A canceled read can still be settling. */ }
        }
        try { return JSON.parse(text); }
        catch (_error) { throw transferError('Encrypted transfer returned invalid JSON', 'protocol'); }
    }

    async function fetchResponse(url, options, scope) {
        const response = await scope.race(fetch(url, {
            credentials: 'same-origin', cache: 'no-store', ...options, signal: scope.signal,
        }));
        scope.reset();
        return response;
    }

    async function requestJson(url, options = {}, context = {}) {
        return retry(async scope => {
            const response = await fetchResponse(url, options, scope);
            let payload;
            try { payload = await consumeJson(response, scope, context.jsonLimitBytes); }
            catch (error) {
                if (response.ok || error?.code !== 'protocol') throw error;
                payload = null;
            }
            if (!response.ok) throw httpError(response.status, payload, response.headers?.get('Retry-After'));
            return payload;
        }, options, context);
    }

    async function uploadChunk(url, options = {}, context = {}) {
        if (typeof XMLHttpRequest === 'undefined') return requestJson(url, options, context);
        return retry(scope => new Promise((resolve, reject) => {
            const xhr = new XMLHttpRequest();
            let settled = false;
            const onAbort = () => {
                xhr.abort();
                finish(reject, scope.signal.reason || abortError());
            };
            const finish = (callback, value) => {
                if (settled) return;
                settled = true;
                scope.signal.removeEventListener('abort', onAbort);
                xhr.upload.removeEventListener('progress', onUploadProgress);
                xhr.onprogress = xhr.onload = xhr.onerror = xhr.onabort = null;
                callback(value);
            };
            const onUploadProgress = event => {
                scope.reset();
                context.onProgress?.({ loaded: event.loaded, total: event.lengthComputable ? event.total : options.body?.byteLength || options.body?.size || 0 });
            };
            xhr.open(options.method || 'PUT', url, true);
            // XHR includes cookies for same-origin requests by default.
            xhr.withCredentials = options.credentials === 'include';
            const headers = new Headers(options.headers || {});
            headers.forEach((value, key) => xhr.setRequestHeader(key, value));
            xhr.upload.addEventListener('progress', onUploadProgress);
            xhr.onprogress = () => scope.reset();
            xhr.onerror = () => finish(reject, transferError('Network transfer failed', 'network'));
            xhr.onabort = () => finish(reject, scope.signal.reason || abortError());
            xhr.onload = () => {
                let payload;
                try { payload = JSON.parse(xhr.responseText); }
                catch (_error) {
                    if (xhr.status >= 200 && xhr.status < 300) {
                        finish(reject, transferError('Encrypted transfer returned invalid JSON', 'protocol'));
                        return;
                    }
                }
                if (xhr.status >= 200 && xhr.status < 300) finish(resolve, payload);
                else finish(reject, httpError(xhr.status, payload, xhr.getResponseHeader('Retry-After')));
            };
            scope.signal.addEventListener('abort', onAbort, { once: true });
            if (scope.signal.aborted) onAbort();
            else xhr.send(options.body ?? null);
        }), options, context);
    }

    async function readChunk(url, expectedLength, context = {}) {
        if (!Number.isInteger(expectedLength) || expectedLength < 1 || expectedLength > maxCiphertextChunk) {
            throw transferError('Ciphertext chunk length is invalid', 'integrity');
        }
        return retry(async scope => {
            const response = await fetchResponse(url, {}, scope);
            if (!response.ok) {
                let payload;
                try { payload = await consumeJson(response, scope); }
                catch (error) { if (error?.code !== 'protocol') throw error; }
                throw httpError(response.status, payload, response.headers?.get('Retry-After'));
            }
            const reader = response.body?.getReader?.();
            if (!reader) throw transferError('Streaming responses are unavailable', 'unsupported');
            const output = new Uint8Array(expectedLength);
            let offset = 0;
            let complete = false;
            try {
                while (true) {
                    const result = await scope.race(reader.read());
                    if (result.done) break;
                    if (result.value.byteLength) scope.reset();
                    if (offset + result.value.byteLength > expectedLength) {
                        throw transferError('Ciphertext chunk contains trailing bytes', 'integrity');
                    }
                    output.set(result.value, offset);
                    offset += result.value.byteLength;
                    context.onProgress?.({ loaded: offset, total: expectedLength });
                }
                if (offset !== expectedLength) throw transferError('Ciphertext chunk was truncated', 'truncated');
                complete = true;
                return output;
            } finally {
                if (!complete) reader.cancel().catch(() => {});
                try { reader.releaseLock(); } catch (_error) { /* Pending aborted read. */ }
            }
        }, {}, context);
    }

    app.registerService('encrypted-transfer-network', { requestJson, uploadChunk, readChunk });
})(window.XferryApp);
