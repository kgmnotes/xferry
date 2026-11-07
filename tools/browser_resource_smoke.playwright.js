async (page) => {
    const options = __RESOURCE_OPTIONS__;
    const password = 'synthetic resource smoke password';
    const started = Date.now();
    let fileId = null;
    let uploadResumed = false;
    let downloadResumed = false;
    const requests = { uploadChunks: 0, downloadChunks: 0 };
    page.on('request', request => {
        const created = request.url().match(/\/_xferry\/encrypted-uploads\/([a-f0-9]{32})$/);
        if (created && request.method() === 'PUT' && fileId === null) fileId = created[1];
        const match = request.url().match(/\/_xferry\/encrypted-(uploads|files)\/[a-f0-9]{32}\/chunks\/[0-9]+$/);
        if (match) requests[match[1] === 'uploads' ? 'uploadChunks' : 'downloadChunks'] += 1;
    });
    await page.addInitScript(() => {
        window.__resourceOutput = { closed: false, failAfterFirstWrite: false, writes: 0 };
        window.showSaveFilePicker = async () => {
            const root = await navigator.storage.getDirectory();
            const file = await root.getFileHandle('resource-output.bin', { create: true });
            return {
                async createWritable() {
                    const writable = await file.createWritable();
                    return {
                        async write(bytes) {
                            await writable.write(bytes);
                            window.__resourceOutput.writes += 1;
                            if (window.__resourceOutput.failAfterFirstWrite) {
                                window.__resourceOutput.failAfterFirstWrite = false;
                                throw new Error('intentional resource smoke interruption');
                            }
                        },
                        async close() {
                            await writable.close();
                            window.__resourceOutput.closed = true;
                        },
                        async abort(reason) { await writable.abort(reason); },
                    };
                },
            };
        };
    });
    async function ready() {
        await page.waitForFunction(() => window.XferryApp?.getState('encrypted-transfer')?.enabled, null, { timeout: 60000 });
        await page.locator('#tab-large-files').click();
        await page.waitForFunction(() => Array.isArray(window.XferryApp.getState('encrypted-transfer').encryptedFiles), null, { timeout: 30000 });
    }
    async function unlock() {
        await page.evaluate(async ({id, password}) => {
            await window.XferryApp.invoke('encrypted-transfer', 'refresh');
            await window.XferryApp.invoke('encrypted-transfer', 'unlock', {id, password});
        }, {id: fileId, password});
    }
    async function targetIdentity() {
        return page.evaluate(async () => {
            const response = await fetch('/', {method: 'PING'});
            if (!response.ok) throw new Error('target identity PING failed');
            const body = await response.json();
            if (body.health !== 'ready' || typeof body.server !== 'string' ||
                !body.server.startsWith('XFerry/')) throw new Error('invalid target identity');
            return {
                server: body.server,
                version: body.server.slice('XFerry/'.length),
                source_commit: typeof body.source_commit === 'string' ? body.source_commit : null,
                build_id: typeof body.build_id === 'string' ? body.build_id : null,
            };
        });
    }
    async function storageEstimate() {
        return page.evaluate(async () => {
            const estimate = await navigator.storage.estimate();
            const quota = Number.isFinite(estimate.quota) ? estimate.quota : null;
            const usage = Number.isFinite(estimate.usage) ? estimate.usage : null;
            return {
                quota_bytes: quota, usage_bytes: usage,
                remaining_bytes: quota !== null && usage !== null ? quota - usage : null,
            };
        });
    }
    try {
        await page.goto(options.url, {waitUntil: 'domcontentloaded'});
        await ready();
        const targetBefore = await targetIdentity();
        const capabilities = await page.evaluate(() => ({
            webCrypto: Boolean(crypto.subtle), indexedDB: typeof indexedDB.open === 'function',
            webLocks: typeof navigator.locks.request === 'function',
            opfs: typeof navigator.storage.getDirectory === 'function',
        }));
        if (!Object.values(capabilities).every(Boolean)) throw new Error('required browser storage APIs unavailable');
        const storageBefore = await storageEstimate();
        if (storageBefore.remaining_bytes !== null && storageBefore.remaining_bytes < options.size * 2 + 64 * 1024 * 1024) {
            throw new Error('insufficient browser storage quota for ciphertext cache and plaintext output');
        }
        let pauseTask = null;
        if (options.recovery) {
            // Pause after real XHR/fetch response headers; the original nonce journal remains authoritative.
            let requested = false;
            page.on('response', response => {
                if (!requested && response.ok() && response.request().method() === 'PUT' &&
                    /\/encrypted-uploads\/[a-f0-9]{32}\/chunks\//.test(response.url())) {
                    requested = true;
                    pauseTask = page.evaluate(() => window.XferryApp.invoke('encrypted-transfer', 'pause'));
                }
            });
        }
        await page.locator('#encryptedFileInput').setInputFiles(options.input);
        await page.locator('#encryptedPasswordInput').fill(password);
        await page.locator('#encryptedPasswordConfirmInput').fill(password);
        const uploadStarted = Date.now();
        await page.locator('#encryptedUploadStartBtn').click();
        if (options.recovery) {
            await page.waitForFunction(() => window.XferryApp.getState('encrypted-transfer').phase === 'paused', null, {timeout: 120000});
            if (pauseTask) await pauseTask;
            const activeId = await page.evaluate(() => window.XferryApp.getState('encrypted-transfer').activeId);
            if (!fileId || activeId !== fileId) throw new Error('paused upload identity differs from created upload');
            await page.reload({waitUntil: 'domcontentloaded'});
            await ready();
            await page.evaluate(async () => await window.XferryApp.invoke('encrypted-transfer', 'refresh'));
            await page.locator('#encryptedResumeFileInput').setInputFiles(options.input);
            await page.evaluate(async ({id, password}) => {
                const lists = await window.XferryApp.invoke('encrypted-transfer', 'refresh');
                const record = lists.partialUploads.find(item => item.id === id);
                if (!record) throw new Error('partial upload missing after reload');
                const file = document.getElementById('encryptedResumeFileInput').files[0];
                window.__resourceResume = window.XferryApp.invoke('encrypted-transfer', 'resume', {record, file, password});
                window.__resourceResume.catch(error => { window.__resourceResumeError = error.message; });
            }, {id:fileId,password});
            uploadResumed = true;
        }
        await page.waitForFunction(() => {
            const state = window.XferryApp.getState('encrypted-transfer');
            if (state.phase === 'error' || window.__resourceResumeError) throw new Error(state.lastError || window.__resourceResumeError);
            return state.phase === 'complete' && state.activeId === null;
        }, null, {timeout: 1800000});
        const uploadSeconds = (Date.now() - uploadStarted) / 1000;
        await page.evaluate(() => window.XferryApp.invoke('encrypted-transfer', 'refresh'));
        const completed = await page.evaluate(id => window.XferryApp.getState('encrypted-transfer').encryptedFiles.find(item => item.id === id)?.plaintextSize, fileId);
        if (!fileId || completed !== options.size) throw new Error('exact completed encrypted upload missing');
        await unlock();
        const downloadStarted = Date.now();
        if (options.recovery) {
            await page.evaluate(async id => {
                window.__resourceOutput.failAfterFirstWrite = true;
                try { await window.XferryApp.invoke('encrypted-transfer', 'download-client', {id}); }
                catch (error) {
                    if (!String(error.message).includes('intentional resource smoke interruption')) throw error;
                }
                if (window.__resourceOutput.closed) throw new Error('interrupted output incorrectly closed');
            }, fileId);
            await page.reload({waitUntil: 'domcontentloaded'});
            await ready();
            await unlock();
            const cached = await page.evaluate(id => window.XferryApp.getState('encrypted-transfer').cacheFiles.some(file => file.id === id), fileId);
            if (!cached) throw new Error('download cache missing after reload');
            downloadResumed = true;
        }
        const beforeResumeRequests = requests.downloadChunks;
        await page.evaluate(id => {
            window.__resourceDownload = window.XferryApp.invoke('encrypted-transfer', 'download-client', {id});
            window.__resourceDownload.catch(error => { window.__resourceDownloadError = error.message; });
        }, fileId);
        await page.waitForFunction(() => {
            if (window.__resourceDownloadError) throw new Error(window.__resourceDownloadError);
            return window.__resourceOutput.closed;
        }, null, {timeout:1800000});
        const downloadSeconds = (Date.now() - downloadStarted) / 1000;
        if (options.recovery && requests.downloadChunks - beforeResumeRequests >= Math.ceil(options.size / (8 * 1024 * 1024))) {
            throw new Error('resumed download fetched the already authenticated cached chunk again');
        }
        const outputSize = await page.evaluate(async () => {
            const root = await navigator.storage.getDirectory();
            const handle = await root.getFileHandle('resource-output.bin');
            return (await handle.getFile()).size;
        });
        if (outputSize !== options.size) throw new Error('browser output size mismatch');
        const downloadPromise = page.waitForEvent('download', {timeout:1800000});
        await page.evaluate(async () => {
            const root = await navigator.storage.getDirectory();
            const file = await (await root.getFileHandle('resource-output.bin')).getFile();
            const url = URL.createObjectURL(file);
            const link = document.createElement('a');
            link.href = url; link.download = 'resource-output.bin'; document.body.append(link); link.click(); link.remove();
            setTimeout(() => URL.revokeObjectURL(url), 60000);
        });
        const download = await downloadPromise;
        await download.saveAs(options.output);
        await download.delete();
        const cacheCleared = await page.evaluate(id => !window.XferryApp.getState('encrypted-transfer').cacheFiles.some(file => file.id === id), fileId);
        if (!cacheCleared) throw new Error('successful download left recovery cache');
        const targetAfter = await targetIdentity();
        if (JSON.stringify(targetBefore) !== JSON.stringify(targetAfter)) {
            throw new Error('target runtime identity changed during browser measurement');
        }
        const storageAfter = await storageEstimate();
        return {kind:'browser-resource-case',status:'passed',syntheticPicker:true,transport:options.transport,
            target_identity_before:targetBefore,target_identity_after:targetAfter,
            browser_storage_before:storageBefore,browser_storage_after:storageAfter,
            capabilities,upload_seconds:uploadSeconds,download_seconds:downloadSeconds,
            elapsed_seconds:(Date.now()-started)/1000,output_bytes:outputSize,requests,
            upload_reload_resume_verified:uploadResumed,download_reload_resume_verified:downloadResumed,
            recovery_case:options.recovery,cache_cleared:true};
    } finally {
        if (fileId) {
            await page.evaluate(async id => {
                if (window.XferryApp?.getState('encrypted-transfer')?.activeId === id) {
                    await window.XferryApp.invoke('encrypted-transfer', 'pause');
                }
            }, fileId).catch(() => {});
            const deleted = await page.evaluate(async id => {
                for (const collection of ['encrypted-files', 'encrypted-uploads']) {
                    const response = await fetch(`/_xferry/${collection}/${id}`, {method:'DELETE'});
                    if (!response.ok && response.status !== 404) return false;
                }
                return true;
            }, fileId).catch(() => false);
            if (!deleted) throw new Error('task-owned encrypted resource cleanup failed');
        }
        await page.evaluate(async () => {
            const root = await navigator.storage.getDirectory();
            await root.removeEntry('resource-output.bin').catch(() => {});
        }).catch(() => {});
    }
}
