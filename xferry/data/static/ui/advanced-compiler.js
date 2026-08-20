(function initializeAdvancedCompiler(app) {
    'use strict';

const ENCRYPTIONS = new Set(['none', 'xor', 'aes']);
const ENCODINGS = new Set([
    'raw',
    'base64',
    'base64url',
    'hex',
    'percent',
    'gzip-base64',
    'gzip-base64url',
]);
const STRUCTURED_FORMATS = new Set(['json', 'form', 'xml', 'multipart-encoded']);

function toBytes(value) {
    if (value instanceof Uint8Array) {
        return new Uint8Array(value);
    }
    if (value instanceof ArrayBuffer) {
        return new Uint8Array(value.slice(0));
    }
    if (ArrayBuffer.isView(value)) {
        return new Uint8Array(value.buffer.slice(value.byteOffset, value.byteOffset + value.byteLength));
    }
    throw new TypeError('Advanced payload must be an ArrayBuffer or typed array');
}

function bytesToBase64(bytes) {
    let binary = '';
    const chunkSize = 8192;
    for (let offset = 0; offset < bytes.length; offset += chunkSize) {
        binary += String.fromCharCode(...bytes.subarray(offset, offset + chunkSize));
    }
    return btoa(binary);
}

function bytesToBase64Url(bytes) {
    return bytesToBase64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function bytesToHex(bytes) {
    return Array.from(bytes, value => value.toString(16).padStart(2, '0')).join('');
}

function bytesToPercent(bytes) {
    return Array.from(bytes, value => `%${value.toString(16).padStart(2, '0').toUpperCase()}`).join('');
}

async function gzipBytes(bytes) {
    if (typeof CompressionStream !== 'function') {
        throw new Error('CompressionStream is unavailable');
    }
    const stream = new Blob([bytes]).stream().pipeThrough(new CompressionStream('gzip'));
    return new Uint8Array(await new Response(stream).arrayBuffer());
}

async function encodeBytes(bytes, encoding) {
    if (!ENCODINGS.has(encoding)) {
        throw new TypeError(`Unsupported Advanced encoding: ${encoding}`);
    }
    if (encoding === 'raw') {
        return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    }
    if (encoding === 'base64') {
        return bytesToBase64(bytes);
    }
    if (encoding === 'base64url') {
        return bytesToBase64Url(bytes);
    }
    if (encoding === 'hex') {
        return bytesToHex(bytes);
    }
    if (encoding === 'percent') {
        return bytesToPercent(bytes);
    }
    const compressed = await gzipBytes(bytes);
    return encoding === 'gzip-base64'
        ? bytesToBase64(compressed)
        : bytesToBase64Url(compressed);
}

async function xorEncrypt(bytes, password, cryptoApi) {
    if (!cryptoApi?.subtle) {
        throw new Error('WebCrypto is unavailable');
    }
    const digest = new Uint8Array(await cryptoApi.subtle.digest(
        'SHA-256',
        new TextEncoder().encode(password)
    ));
    const result = new Uint8Array(bytes.length);
    for (let index = 0; index < bytes.length; index += 1) {
        result[index] = bytes[index] ^ digest[index % digest.length];
    }
    return result;
}

async function aesEncrypt(bytes, password, cryptoApi) {
    if (!cryptoApi?.subtle || typeof cryptoApi.getRandomValues !== 'function') {
        throw new Error('WebCrypto AES-GCM is unavailable');
    }
    const salt = cryptoApi.getRandomValues(new Uint8Array(16));
    const nonce = cryptoApi.getRandomValues(new Uint8Array(12));
    const passwordMaterial = await cryptoApi.subtle.importKey(
        'raw',
        new TextEncoder().encode(password),
        'PBKDF2',
        false,
        ['deriveKey']
    );
    const key = await cryptoApi.subtle.deriveKey(
        {
            name: 'PBKDF2',
            hash: 'SHA-256',
            salt,
            iterations: 600000,
        },
        passwordMaterial,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt']
    );
    const ciphertextWithTag = new Uint8Array(await cryptoApi.subtle.encrypt(
        { name: 'AES-GCM', iv: nonce, tagLength: 128 },
        key,
        bytes
    ));
    const wire = new Uint8Array(1 + salt.length + nonce.length + ciphertextWithTag.length);
    wire[0] = 0x01;
    wire.set(salt, 1);
    wire.set(nonce, 17);
    wire.set(ciphertextWithTag, 29);
    return wire;
}

async function computeHmac(bytes, password, cryptoApi) {
    if (!cryptoApi?.subtle) {
        throw new Error('WebCrypto HMAC is unavailable');
    }
    const key = await cryptoApi.subtle.importKey(
        'raw',
        new TextEncoder().encode(password),
        { name: 'HMAC', hash: 'SHA-256' },
        false,
        ['sign']
    );
    return bytesToHex(new Uint8Array(await cryptoApi.subtle.sign('HMAC', key, bytes)));
}

function canonicalKey(password, keyIsBase64) {
    return keyIsBase64
        ? bytesToBase64(new TextEncoder().encode(password))
        : password;
}

function validateOptions(options) {
    const encryption = String(options.encryption || '');
    if (!ENCRYPTIONS.has(encryption)) {
        throw new TypeError('Advanced encryption must be none, xor, or aes');
    }
    const key = String(options.key || '');
    if (encryption === 'none') {
        if (key || options.keyIsBase64 === true || options.hmac) {
            throw new TypeError('encryption=none forbids key, key_is_base64, and hmac');
        }
    } else if (!key) {
        throw new TypeError(`${encryption} encryption requires a key`);
    }
    if (options.carrier === 'body' && options.bodyFormat === 'text' && encryption !== 'none') {
        throw new TypeError('Encrypted payloads require a binary or encoded body');
    }
    return { encryption, key };
}

async function protectBytes(bytes, options, cryptoApi) {
    const { encryption, key } = validateOptions(options);
    let protectedBytes = bytes;
    if (encryption === 'xor') {
        protectedBytes = await xorEncrypt(bytes, key, cryptoApi);
    } else if (encryption === 'aes') {
        protectedBytes = await aesEncrypt(bytes, key, cryptoApi);
    }
    return {
        encryption,
        key,
        protectedBytes,
        hmac: options.hmac === true
            ? await computeHmac(protectedBytes, key, cryptoApi)
            : null,
    };
}

function addCryptoMetadata(fields, protectedPayload, options) {
    fields.encryption = protectedPayload.encryption;
    if (protectedPayload.encryption !== 'none') {
        fields.key = canonicalKey(protectedPayload.key, options.keyIsBase64 === true);
        if (options.keyIsBase64 === true) {
            fields.key_is_base64 = true;
        }
        if (protectedPayload.hmac) {
            fields.hmac = protectedPayload.hmac;
        }
    }
}

function addOptionalMetadata(fields, options, { includeName = true } = {}) {
    if (includeName && options.name) {
        fields.name = String(options.name);
    }
    if (options.methodOverride) {
        fields.method_override = String(options.methodOverride);
    }
}

function fieldsToHeaders(fields, { includeData = true } = {}) {
    const headers = {};
    if (includeData && fields.data !== undefined) headers['X-XFerry-Data'] = fields.data;
    if (fields.encryption !== undefined) headers['X-XFerry-Encryption'] = fields.encryption;
    if (fields.key !== undefined) headers['X-XFerry-Key'] = fields.key;
    if (fields.key_is_base64 !== undefined) {
        headers['X-XFerry-Key-Is-Base64'] = String(fields.key_is_base64);
    }
    if (fields.name !== undefined) headers['X-XFerry-Name'] = fields.name;
    if (fields.hmac !== undefined) headers['X-XFerry-HMAC'] = fields.hmac;
    if (fields.encoding !== undefined) headers['X-XFerry-Encoding'] = fields.encoding;
    if (fields.method_override !== undefined) {
        headers['X-XFerry-Method-Override'] = fields.method_override;
    }
    return headers;
}

function fieldsToParams(fields, { includeData = true } = {}) {
    const params = new URLSearchParams();
    for (const [name, value] of Object.entries(fields)) {
        if (!includeData && name === 'data') continue;
        params.set(name, String(value));
    }
    return params;
}

function fieldsToCookieEffects(fields) {
    const names = {
        data: 'xferry_data',
        encryption: 'xferry_encryption',
        key: 'xferry_key',
        key_is_base64: 'xferry_key_is_base64',
        name: 'xferry_name',
        hmac: 'xferry_hmac',
        encoding: 'xferry_encoding',
        method_override: 'xferry_method_override',
    };
    return Object.entries(fields).map(([name, value]) => ({
        action: 'set',
        name: names[name],
        value: String(value),
    }));
}

function escapeXml(value) {
    return String(value)
        .replaceAll('&', '&amp;')
        .replaceAll('<', '&lt;')
        .replaceAll('>', '&gt;')
        .replaceAll('"', '&quot;')
        .replaceAll("'", '&apos;');
}

function normalizePrefix(prefix) {
    const value = String(prefix || '/advanced');
    if (!value.startsWith('/') || (value.length > 1 && value.endsWith('/'))) {
        throw new TypeError('Advanced prefix must be an absolute normalized path');
    }
    return value;
}

async function compile(options, inputBytes) {
    const bytes = toBytes(inputBytes);
    if (!bytes.length) {
        throw new TypeError('Advanced payload is empty');
    }
    const cryptoApi = globalThis.crypto;
    const protectedPayload = await protectBytes(bytes, options, cryptoApi);
    const carrier = String(options.carrier || 'body');
    const bodyFormat = String(options.bodyFormat || 'json');
    const prefix = normalizePrefix(options.prefix);
    const name = String(options.name || 'upload.bin');
    const method = String(options.method || 'POST').toUpperCase();
    const encoding = carrier === 'path' ? 'base64url' : String(options.encoding || 'base64');
    const fields = {};
    const requestHeaders = {};
    let requestPath = prefix;
    let requestBody = null;
    let cookieEffects = [];

    if (bodyFormat !== 'raw' && bodyFormat !== 'text' && bodyFormat !== 'multipart-binary') {
        fields.data = await encodeBytes(protectedPayload.protectedBytes, encoding);
        fields.encoding = encoding;
    }
    addCryptoMetadata(fields, protectedPayload, options);
    addOptionalMetadata(fields, options, { includeName: bodyFormat !== 'multipart-binary' });

    if (carrier === 'headers') {
        const data = fields.data;
        delete fields.data;
        Object.assign(requestHeaders, fieldsToHeaders(fields, { includeData: false }));
        const chunkSize = Math.max(1, Number(options.chunkSize || 7000));
        if (data.length > chunkSize) {
            for (let offset = 0, index = 0; offset < data.length; offset += chunkSize, index += 1) {
                if (index > 255) throw new TypeError('Advanced header chunk limit exceeded');
                requestHeaders[`X-XFerry-Data-${index}`] = data.slice(offset, offset + chunkSize);
            }
        } else {
            requestHeaders['X-XFerry-Data'] = data;
        }
    } else if (carrier === 'query') {
        requestPath += `?${fieldsToParams(fields).toString()}`;
    } else if (carrier === 'cookies') {
        cookieEffects = fieldsToCookieEffects(fields);
    } else if (carrier === 'path') {
        const pathData = await encodeBytes(protectedPayload.protectedBytes, 'base64url');
        const pathMetadata = { ...fields };
        delete pathMetadata.data;
        delete pathMetadata.encoding;
        delete pathMetadata.name;
        requestPath = `${prefix === '/' ? '' : prefix}/_payload/${encodeURIComponent(name)}/${pathData}`;
        const query = fieldsToParams(pathMetadata, { includeData: false }).toString();
        if (query) requestPath += `?${query}`;
    } else if (carrier !== 'body') {
        throw new TypeError(`Unsupported Advanced carrier: ${carrier}`);
    } else if (bodyFormat === 'raw') {
        Object.assign(requestHeaders, fieldsToHeaders(fields, { includeData: false }));
        requestHeaders['Content-Type'] = String(options.mime || 'application/octet-stream');
        requestBody = protectedPayload.protectedBytes;
    } else if (bodyFormat === 'text') {
        Object.assign(requestHeaders, fieldsToHeaders(fields, { includeData: false }));
        requestHeaders['Content-Type'] = String(options.mime || 'text/plain; charset=utf-8');
        requestBody = new TextDecoder('utf-8', { fatal: true }).decode(protectedPayload.protectedBytes);
    } else if (bodyFormat === 'json') {
        requestHeaders['Content-Type'] = 'application/json';
        requestBody = JSON.stringify(fields);
    } else if (bodyFormat === 'form') {
        requestHeaders['Content-Type'] = 'application/x-www-form-urlencoded';
        requestBody = fieldsToParams(fields).toString();
    } else if (bodyFormat === 'xml') {
        requestHeaders['Content-Type'] = String(options.mime || 'application/xml');
        requestBody = `<upload>${Object.entries(fields)
            .map(([key, value]) => `<${key}>${escapeXml(value)}</${key}>`)
            .join('')}</upload>`;
    } else if (bodyFormat === 'multipart-encoded') {
        requestBody = new FormData();
        Object.entries(fields).forEach(([key, value]) => requestBody.append(key, String(value)));
    } else if (bodyFormat === 'multipart-binary') {
        requestBody = new FormData();
        requestBody.append(
            'file',
            new Blob([protectedPayload.protectedBytes], {
                type: String(options.partMime || 'application/octet-stream'),
            }),
            name
        );
        const metadataFields = {};
        addCryptoMetadata(metadataFields, protectedPayload, options);
        addOptionalMetadata(metadataFields, options, { includeName: false });
        Object.entries(metadataFields).forEach(([key, value]) => {
            requestBody.append(key, String(value));
        });
    } else if (!STRUCTURED_FORMATS.has(bodyFormat)) {
        throw new TypeError(`Unsupported Advanced body format: ${bodyFormat}`);
    }

    return Object.freeze({
        method,
        requestPath,
        requestBody,
        requestHeaders: Object.freeze({ ...requestHeaders }),
        cookieEffects: Object.freeze(cookieEffects.map(effect => Object.freeze({ ...effect }))),
        encryption: protectedPayload.encryption,
        encoding: bodyFormat === 'raw' || bodyFormat === 'text' || bodyFormat === 'multipart-binary'
            ? null
            : encoding,
    });
}

app.registerService('advanced-compiler', {
    compile,
});
})(window.XferryApp);
