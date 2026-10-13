(function initializeEncryptedTransferCrypto(app) {
    'use strict';

    const VERSION = 1;
    const CHUNK_SIZE = 8 * 1024 * 1024;
    const PBKDF2_ITERATIONS = 600000;
    const METADATA_INDEX = 0xffffffff;
    const MAX_METADATA_SIZE = 4096;
    const MAX_PASSWORD_BYTES = 1024;
    const METADATA_PREFIX = new TextEncoder().encode('XFERRY-EUF1-META\0');
    const CHUNK_PREFIX = new TextEncoder().encode('XFERRY-EUF1-CHUNK\0');
    const RESUME_PREFIX = new TextEncoder().encode('XFERRY-EUF1-RESUME\0');
    const CONTENT_INFO = new TextEncoder().encode('xferry-euf-v1/content');
    const RESUME_INFO = new TextEncoder().encode('xferry-euf-v1/resume');
    const textEncoder = new TextEncoder();
    const textDecoder = new TextDecoder('utf-8', { fatal: true });

    function asBytes(value, field = 'value') {
        if (value instanceof Uint8Array) {
            return value;
        }
        if (value instanceof ArrayBuffer) {
            return new Uint8Array(value);
        }
        if (ArrayBuffer.isView(value)) {
            return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
        }
        throw new TypeError(`${field} must be binary data`);
    }

    function concatBytes(...values) {
        const parts = values.map(value => asBytes(value));
        const result = new Uint8Array(parts.reduce((total, part) => total + part.byteLength, 0));
        let offset = 0;
        parts.forEach(part => {
            result.set(part, offset);
            offset += part.byteLength;
        });
        return result;
    }

    function uint32(value, field) {
        if (!Number.isInteger(value) || value < 0 || value > 0xffffffff) {
            throw new RangeError(`${field} must be an unsigned 32-bit integer`);
        }
        const result = new Uint8Array(4);
        new DataView(result.buffer).setUint32(0, value, false);
        return result;
    }

    function uint64(value, field) {
        if (!Number.isSafeInteger(value) || value < 0) {
            throw new RangeError(`${field} must be a non-negative safe integer`);
        }
        const result = new Uint8Array(8);
        const view = new DataView(result.buffer);
        const high = Math.floor(value / 0x100000000);
        const low = value % 0x100000000;
        view.setUint32(0, high, false);
        view.setUint32(4, low, false);
        return result;
    }

    function decodeFileId(fileId) {
        if (!/^[0-9a-f]{32}$/.test(String(fileId || ''))) {
            throw new TypeError('fileId must be exactly 32 lowercase hexadecimal characters');
        }
        const result = new Uint8Array(16);
        for (let index = 0; index < result.length; index += 1) {
            result[index] = Number.parseInt(fileId.slice(index * 2, index * 2 + 2), 16);
        }
        return result;
    }

    function encodeBase64Url(value) {
        const bytes = asBytes(value);
        let binary = '';
        for (let offset = 0; offset < bytes.byteLength; offset += 0x8000) {
            binary += String.fromCharCode(...bytes.subarray(offset, offset + 0x8000));
        }
        return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
    }

    function decodeBase64Url(value, field = 'value') {
        if (typeof value !== 'string' || !/^[A-Za-z0-9_-]*$/.test(value) || value.length % 4 === 1) {
            throw new TypeError(`${field} must be canonical unpadded base64url`);
        }
        let binary;
        try {
            binary = atob(value.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat(-value.length & 3));
        } catch (error) {
            throw new TypeError(`${field} must be canonical unpadded base64url`);
        }
        const result = Uint8Array.from(binary, character => character.charCodeAt(0));
        if (encodeBase64Url(result) !== value) {
            throw new TypeError(`${field} must be canonical unpadded base64url`);
        }
        return result;
    }

    function validateManifest(manifest) {
        if (!manifest || typeof manifest !== 'object' || Array.isArray(manifest)) {
            throw new TypeError('manifest must be an object');
        }
        if (manifest.version !== VERSION) {
            throw new RangeError('manifest version must be 1');
        }
        decodeFileId(manifest.fileId);
        if (!Number.isSafeInteger(manifest.plaintextSize) || manifest.plaintextSize < 0) {
            throw new RangeError('plaintextSize must be a non-negative safe integer');
        }
        if (manifest.chunkSize !== CHUNK_SIZE) {
            throw new RangeError(`chunkSize must be exactly ${CHUNK_SIZE}`);
        }
        if (manifest.chunkCount !== Math.ceil(manifest.plaintextSize / CHUNK_SIZE)) {
            throw new RangeError('chunkCount does not match plaintextSize');
        }
        if (asBytes(manifest.salt, 'salt').byteLength !== 16) {
            throw new RangeError('salt must contain exactly 16 bytes');
        }
        if (asBytes(manifest.noncePrefix, 'noncePrefix').byteLength !== 8) {
            throw new RangeError('noncePrefix must contain exactly 8 bytes');
        }
        return manifest;
    }

    function expectedChunkLength(manifest, index) {
        validateManifest(manifest);
        if (!Number.isInteger(index) || index < 0 || index >= manifest.chunkCount) {
            throw new RangeError('chunk index is outside the manifest');
        }
        return Math.min(CHUNK_SIZE, manifest.plaintextSize - index * CHUNK_SIZE);
    }

    function buildMetadataAad(manifest) {
        validateManifest(manifest);
        return concatBytes(
            METADATA_PREFIX,
            decodeFileId(manifest.fileId),
            uint64(manifest.plaintextSize, 'plaintextSize'),
            uint32(manifest.chunkSize, 'chunkSize'),
            uint32(manifest.chunkCount, 'chunkCount')
        );
    }

    function buildChunkAad(manifest, index, plaintextLength) {
        const expectedLength = expectedChunkLength(manifest, index);
        if (plaintextLength !== expectedLength) {
            throw new RangeError(`plaintextLength must be exactly ${expectedLength} for chunk ${index}`);
        }
        return concatBytes(
            CHUNK_PREFIX,
            decodeFileId(manifest.fileId),
            uint64(manifest.plaintextSize, 'plaintextSize'),
            uint32(manifest.chunkSize, 'chunkSize'),
            uint32(manifest.chunkCount, 'chunkCount'),
            uint32(index, 'index'),
            uint32(plaintextLength, 'plaintextLength')
        );
    }

    function buildNonce(manifest, index) {
        return concatBytes(asBytes(manifest.noncePrefix, 'noncePrefix'), uint32(index, 'index'));
    }

    function validatePassword(password) {
        if (typeof password !== 'string' || Array.from(password).length < 14) {
            throw new TypeError('password must contain at least 14 Unicode code points');
        }
        const bytes = textEncoder.encode(password);
        if (bytes.byteLength > MAX_PASSWORD_BYTES) {
            throw new RangeError(`password must not exceed ${MAX_PASSWORD_BYTES} UTF-8 bytes`);
        }
        return bytes;
    }

    async function deriveKeys(password, salt, fileId) {
        const passwordBytes = validatePassword(password);
        const saltBytes = asBytes(salt, 'salt');
        if (saltBytes.byteLength !== 16) {
            throw new RangeError('salt must contain exactly 16 bytes');
        }
        const fileIdBytes = decodeFileId(fileId);
        const passwordKey = await crypto.subtle.importKey(
            'raw',
            passwordBytes,
            'PBKDF2',
            false,
            ['deriveBits']
        );
        const masterKey = new Uint8Array(await crypto.subtle.deriveBits(
            {
                name: 'PBKDF2',
                hash: 'SHA-256',
                salt: saltBytes,
                iterations: PBKDF2_ITERATIONS,
            },
            passwordKey,
            256
        ));
        const hkdfKey = await crypto.subtle.importKey('raw', masterKey, 'HKDF', false, ['deriveBits']);

        async function expand(info) {
            return new Uint8Array(await crypto.subtle.deriveBits(
                { name: 'HKDF', hash: 'SHA-256', salt: fileIdBytes, info },
                hkdfKey,
                256
            ));
        }

        const [contentKey, resumeKey] = await Promise.all([
            expand(CONTENT_INFO),
            expand(RESUME_INFO),
        ]);
        masterKey.fill(0);
        return { contentKey, resumeKey };
    }

    async function importAesKey(key) {
        const bytes = asBytes(key, 'content key');
        if (bytes.byteLength !== 32) {
            throw new RangeError('content key must contain exactly 32 bytes');
        }
        return crypto.subtle.importKey('raw', bytes, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
    }

    async function encryptMetadata(metadata, key, manifest) {
        if (!metadata || typeof metadata !== 'object' || Array.isArray(metadata)) {
            throw new TypeError('metadata must be an object');
        }
        if (typeof metadata.name !== 'string' || !metadata.name || metadata.name.includes('\0')) {
            throw new TypeError('metadata name must be a non-empty string');
        }
        if (typeof metadata.content_type !== 'string' || /[\r\n]/.test(metadata.content_type)) {
            throw new TypeError('metadata content_type must be header-safe text');
        }
        if (!Number.isSafeInteger(metadata.last_modified_ms) || metadata.last_modified_ms < 0) {
            throw new TypeError('metadata last_modified_ms must be a non-negative safe integer');
        }
        const plaintext = textEncoder.encode(JSON.stringify({
            name: metadata.name,
            content_type: metadata.content_type,
            last_modified_ms: metadata.last_modified_ms,
        }));
        if (plaintext.byteLength > MAX_METADATA_SIZE) {
            throw new RangeError(`metadata JSON must not exceed ${MAX_METADATA_SIZE} bytes`);
        }
        const cryptoKey = await importAesKey(key);
        return new Uint8Array(await crypto.subtle.encrypt(
            {
                name: 'AES-GCM',
                iv: buildNonce(manifest, METADATA_INDEX),
                additionalData: buildMetadataAad(manifest),
                tagLength: 128,
            },
            cryptoKey,
            plaintext
        ));
    }

    async function decryptMetadata(ciphertext, key, manifest) {
        try {
            const cryptoKey = await importAesKey(key);
            const plaintext = await crypto.subtle.decrypt(
                {
                    name: 'AES-GCM',
                    iv: buildNonce(manifest, METADATA_INDEX),
                    additionalData: buildMetadataAad(manifest),
                    tagLength: 128,
                },
                cryptoKey,
                asBytes(ciphertext, 'encrypted metadata')
            );
            const metadata = JSON.parse(textDecoder.decode(plaintext));
            if (
                !metadata
                || typeof metadata !== 'object'
                || Array.isArray(metadata)
                || Object.keys(metadata).sort().join(',') !== 'content_type,last_modified_ms,name'
                || typeof metadata.name !== 'string'
                || !metadata.name
                || metadata.name.includes('\0')
                || typeof metadata.content_type !== 'string'
                || /[\r\n]/.test(metadata.content_type)
                || !Number.isSafeInteger(metadata.last_modified_ms)
                || metadata.last_modified_ms < 0
            ) {
                return null;
            }
            return metadata;
        } catch (error) {
            return null;
        }
    }

    async function encryptChunk(plaintext, key, manifest, index) {
        const bytes = asBytes(plaintext, 'plaintext chunk');
        const cryptoKey = await importAesKey(key);
        return new Uint8Array(await crypto.subtle.encrypt(
            {
                name: 'AES-GCM',
                iv: buildNonce(manifest, index),
                additionalData: buildChunkAad(manifest, index, bytes.byteLength),
                tagLength: 128,
            },
            cryptoKey,
            bytes
        ));
    }

    async function decryptChunk(ciphertext, key, manifest, index) {
        const plaintextLength = expectedChunkLength(manifest, index);
        const bytes = asBytes(ciphertext, 'encrypted chunk');
        if (bytes.byteLength !== plaintextLength + 16) {
            return null;
        }
        try {
            const cryptoKey = await importAesKey(key);
            return new Uint8Array(await crypto.subtle.decrypt(
                {
                    name: 'AES-GCM',
                    iv: buildNonce(manifest, index),
                    additionalData: buildChunkAad(manifest, index, plaintextLength),
                    tagLength: 128,
                },
                cryptoKey,
                bytes
            ));
        } catch (error) {
            return null;
        }
    }

    async function computeResumeMac(plaintext, key, manifest, index) {
        const bytes = asBytes(plaintext, 'plaintext chunk');
        buildChunkAad(manifest, index, bytes.byteLength);
        const keyBytes = asBytes(key, 'resume key');
        if (keyBytes.byteLength !== 32) {
            throw new RangeError('resume key must contain exactly 32 bytes');
        }
        const cryptoKey = await crypto.subtle.importKey(
            'raw',
            keyBytes,
            { name: 'HMAC', hash: 'SHA-256' },
            false,
            ['sign']
        );
        const message = concatBytes(
            RESUME_PREFIX,
            decodeFileId(manifest.fileId),
            uint32(index, 'index'),
            uint32(bytes.byteLength, 'plaintextLength'),
            bytes
        );
        return new Uint8Array(await crypto.subtle.sign('HMAC', cryptoKey, message));
    }

    function randomBytes(length) {
        if (!Number.isInteger(length) || length < 1 || length > 65536) {
            throw new RangeError('random byte length is outside browser limits');
        }
        return crypto.getRandomValues(new Uint8Array(length));
    }

    app.registerService('encrypted-transfer-crypto', {
        version: VERSION,
        chunkSize: CHUNK_SIZE,
        parallelChunks: 2,
        pbkdf2Iterations: PBKDF2_ITERATIONS,
        encodeBase64Url,
        decodeBase64Url,
        decodeFileId,
        randomBytes,
        deriveKeys,
        buildMetadataAad,
        buildChunkAad,
        encryptMetadata,
        decryptMetadata,
        encryptChunk,
        decryptChunk,
        computeResumeMac,
    });
})(window.XferryApp);
