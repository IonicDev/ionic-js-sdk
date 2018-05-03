/* 
 * Copyright 2018 Ionic Security Inc.
 * By using this code, I agree to the Terms & Conditions (https://dev.ionic.com/use.html)
 * and the Privacy Policy (https://www.ionic.com/privacy-notice/).
 */

/**
 * Chunk Crypto module.
 * @module chunk-crypto
 */

const ionicKey = require('../common/KeyManager.js');
const base64 = require('base-64');
const crypto = require('../../internal-modules/crypto-abstract.js');
const {STRINGS, ERRCODE, ERRMSG } = require('../constants.js');
const { customErrorResponse } = require('../common/CustomErrorResponse.js');

const availableVersions = ['v1',  'v2'];

module.exports = {
    chunkDecrypt,
    chunkEncrypt,
    handleMessage,
    encodeV1,
    encodeV2,
    decodeV1,
    decodeV2,
};

function handleMessage(msg) {
    if( msg.action === 'encryptStringChunkCipher' ||
        msg.action === 'encryptBytesChunkCipher'  ) {
        return  encryptChunkCipher(msg.info);
    } else if (msg.action == 'decryptStringChunkCipher' ||
            msg.action == 'decryptBytesChunkCipher' ) {
        return decryptChunkCipher(msg.info);
    }
}

/**
 * @param {EncryptRequestInternal} argObj Request object containing the plaintext data and any
 * additional request parameters.
 *
 * @returns {Promise<ChunkCryptoResponse>} Promise that resolves with a response object.
 * @see
 * {@link module:chunk-crypto~chunkEncrypt|chunkEncrypt}
 */
function encryptChunkCipher(argObj) {
    return chunkEncrypt(argObj)
        .then(chunkResult => {
            return {
                sdkResponseCode: 0,
                stringChunk: chunkResult
            };
        });
}

/**
 * @param {DecryptRequest} argObj Request object containing the encrypted data and any
 * additional request parameters.
 * @return {Promise<ChunkCryptoResponse>} Promise that resolves with a response object.
 * @see
 * {@link module:chunk-crypto~chunkDecrypt|chunkDecrypt}
 */
function decryptChunkCipher(argObj) {
    return chunkDecrypt(argObj)
        .then(resultObject => {
            return {
                sdkResponseCode: 0,
                stringChunk: resultObject
            };
        });
}
/**
 * Encrypt bytes with an Ionic protection key.
 * The encryption operation consists of several steps:
 * - Create a new Ionic protection key (or fetch an existing one if a key tag is specified)
 * - Encrypt data with the Ionic protection key
 * - {@link https://dev.ionic.com/fundamentals/data-format/chunkdataformat.html|Format} 
 * the encrypted data along with the associated key tag
 * 
 * @param {EncryptRequestInternal} argObj Request object containing the plaintext data and any
 * additional request parameters.
 *
 * @returns {Promise<ChunkCryptoResponse>} Promise that resolves with a response object.
 * @see
 * {@link module:chunk-crypto~encodeV1|encodeV1}
 * {@link module:chunk-crypto~encodeV2|encodeV2}
 */
function chunkEncrypt(argObj) {
    var bufferIv;
    var ionicKeyObj;
    var instanceKey = new ionicKey.IonicKey(argObj);
    return instanceKey.createKey()
        .then(key => {
            if (!key || !key.data) {
              throw "Missing key.data object";
            }
            if (!key.tag) {
              throw "Missing key.tag object";
            }
            ionicKeyObj = key;
            return Promise.all([
                crypto.getRandomValues(16),
                crypto.importKey({
                    type: 'raw',
                    key: Buffer.from(key.data, 'hex'),
                    algorithm: 'AES-CTR',
                    extractable: false,
                    usages: ['encrypt', 'decrypt'],
                }),
            ]);
        })

        .then(([iv, key]) => {
            bufferIv = iv;
            if ((argObj.cipher && availableVersions.includes(argObj.cipher.toLowerCase())) || !argObj.cipher){
                argObj.cipher = argObj.cipher || 'v2';
                return crypto.encrypt({
                    key: key,
                    data: argObj.chunkArrayBuffer,
                    algorithm: 'AES-CTR',
                    iv: iv,
                });
            } else {
                throw STRINGS.INVALID_CIPHER;
            }
        })

        .then(encryptedData => {
            if (argObj.cipher === 'v1'){
                return Promise.resolve(encodeV1(ionicKeyObj.tag, bufferIv, encryptedData));
            }
            return Promise.resolve(encodeV2(ionicKeyObj.tag, bufferIv, encryptedData));
        })
        .catch(err => {
            return customErrorResponse(err, 'chunkEncrypt error', ERRCODE.CHUNK_ERROR);
        });
}


/**
 * Decrypt an encrypted string.
 * The decrypt operation consists of several steps:
 * - {@link https://dev.ionic.com/fundamentals/data-format/chunkdataformat.html|Decode} 
 * the input and extract encrypted data along with the associated key tag
 * - Get the Ionic protection key that corresponds to the key tag
 * - Decrypt data
 * 
 * @param {DecryptRequest} argObj Request object containing the encrypted data and any
 * additional request parameters.
 * @return {Promise<ChunkCryptoResponse>} Promise that resolves with a response object.
 * @see 
 * {@link module:chunk-crypto~decodeV1|decodeV1}
 * {@link module:chunk-crypto~decodeV2|decodeV2}
 */
function chunkDecrypt(argObj) {
    let tag, IV, data;
    return Promise.resolve()
        .then(() => {
            ({tag, IV, data} = argObj.stringData.includes('~fEc!') ?
              decodeV1(argObj.stringData) :
              decodeV2(argObj.stringData));
            let inputData = { tag: tag };
            inputData.metadata = argObj.metadata || {};
            let instanceKey = new ionicKey.IonicKey(inputData);
            return instanceKey.getKey();
        })
        .then(ionicKey => {
            return crypto.importKey({
                type: 'raw',
                key: Buffer.from(ionicKey.data, 'hex'),
                algorithm: 'AES-CTR',
                extractable: false,
                usages: ['encrypt', 'decrypt'],
            });
        })
        .then(cryptoKey => {
            return crypto.decrypt({
                key: cryptoKey,
                data: Buffer.from(data, 'hex'),
                algorithm: 'AES-CTR',
                iv: Buffer.from(IV, 'hex'),
            });
        })
        .then(decryptedResult => {
            return Buffer.from(decryptedResult).toString();
        })
        .catch(err => {
            return customErrorResponse(err, ERRMSG.CHUNK_ERROR , ERRCODE.CHUNK_ERROR);
        });
}

/**
 * Encodes the provided data as {@link https://dev.ionic.com/fundamentals/data-format/chunkdataformat.html|V1 Chunk format}.
 * @param {string} tag Key tag (keyId) for the encryption key. 
 * @param {Buffer} IV The IV used with the protected data.
 * @param {Buffer} data The encrypted data.
 * @return {string} {@link https://dev.ionic.com/fundamentals/data-format/chunkdataformat.html|V1-formatted} string.
 * @see
 * {@link module:chunk-crypto~decodeV1|decodeV1}
 */
function encodeV1(tag, IV, data) {
    return `~!${tag}~fEc!${base64.encode(Buffer.from(IV).toString('binary') + Buffer.from(data).toString('binary'))}!cEf`;
}

/**
 * Encodes the provided data as {@link https://dev.ionic.com/fundamentals/data-format/chunkdataformat.html|V2 Chunk format}.
 * @param {string} tag Key tag (keyId) for the encryption key. 
 * @param {Buffer} IV The IV used with the protected data.
 * @param {Buffer} data The encrypted data.
 * @return {string} {@link https://dev.ionic.com/fundamentals/data-format/chunkdataformat.html|V2-formatted} string.
 * @see
 * {@link module:chunk-crypto~decodeV2|decodeV2}
 */
function encodeV2(tag, IV, data) {
    return `~!2!${tag}!${base64.encode(Buffer.from(IV).toString('binary') + Buffer.from(data).toString('binary'))}!`;
}


/**
 * Decodes the string encoded with {@link https://dev.ionic.com/fundamentals/data-format/chunkdataformat.html|V1 Chunk format}.
 * @param {string} v1string - Encoded string.
 * @return {ChunkComponents} Returns the {@link https://dev.ionic.com/fundamentals/data-format/chunkdataformat.html|V1 Chunk format} components (tag, IV, and data).
 * @see
 * {@link module:chunk-crypto~encodeV1|encodeV1} 
 */
function decodeV1(v1string) {
    var parts, data;
    parts = v1string.replace('~fEc', '').replace('cEf', '').split('!');
    if (
        parts.length !== 4 ||
        parts[0] !== '~' ||
        parts[3] !== ''
    ) {
        throw 'Invalid v1 format string: ' + v1string;
    }

    data =  Buffer.from(base64.decode(parts[2]), 'binary');
    return {
        tag: parts[1],
        IV: data.slice(0, 16),
        data: data.slice(16),
    };
}

/**
 * Decodes the string encoded with {@link https://dev.ionic.com/fundamentals/data-format/chunkdataformat.html|V1 Chunk format}.
 * @param {string}  v2string - Encoded string.
 * @return {ChunkComponents} Returns the {@link https://dev.ionic.com/fundamentals/data-format/chunkdataformat.html|V2 Chunk format} components (tag, IV, and data).
 * @see
 * {@link module:chunk-crypto~encodeV2|encodeV2}
 */
function decodeV2(v2string) {
    var parts, data;
    parts = v2string.split('!');
    if (
        parts.length !== 5 ||
        parts[0] !== '~' ||
        parts[1] !== '2' ||
        parts[4] !== ''
    ) {
        throw 'Invalid v2 format string: ' + v2string;
    }

    data =  Buffer.from(base64.decode(parts[3]), 'binary');
    return {
        tag: parts[2],
        IV: data.slice(0, 16),
        data: data.slice(16),
    };
}

////////////////////////////////////////////
// JSDoc custom types
// see http://usejsdoc.org/tags-typedef.html
//
// Defines objects that are passed into or
// returned by multiple functions
////////////////////////////////////////////
/**
 * Response object for an encrypt operation. Contains SDK response code (0 = success) and either the 
 * encrypted string or the error message. 
 * @typedef {Object} ChunkCryptoResponse
 * @property {Number} sdkResponseCode - 0 (success) or SDK error code.
 * @property {String} stringChunk Base64-encoded encrypted data, encoded into the specified 
 * {@link https://dev.ionic.com/fundamentals/data-format/chunkdataformat.html|Chunk format}.
 * @property {String} error - Specifies the SDK error message (if applicable).
 */

/**
 * Request object for an encrypt operation. 
 * Specifies the plaintext data to be encrypted along with the {@link https://dev.ionic.com/fundamentals/data-format/chunkdataformat.html|Chunk format} 
 * @typedef {Object} EncryptRequest
 * @property {String} stringData Plaintext string (utf8) to be encrypted.
 * @property {String} [cipher="v2"] Chunk format for encoding the encrypted content along 
 * with the associated keytag. Currently supported cipher {@link https://dev.ionic.com/fundamentals/data-format/chunkdataformat.html|formats} are 'v1' and 'v2'. 
 * See https://dev.ionic.com/fundamentals/data-format/chunkdataformat.html
 * @property {Object.<string, object>} [attributes] - Attributes (immutable) associated with the key. 
 * @property {Object.<string, object>} [mutableAttributes] Mutable attributes associated with the key. 
 * @property {Object.<string, object>} [metadata] 
 * {@link https://dev.ionic.com/fundamentals/metadata.html|Metadata}
 * associated with the key.
 * @property {Object} [tag] Key tag (aka keyId) for an existing key. If specified, a key
 * is fetched prior to encryption. Otherwise, a new key is created and used for encryption.
 */

/**
 * Request object for an encrypt operation. 
 * Specifies the plaintext data to be encrypted along with the {@link https://dev.ionic.com/fundamentals/data-format/chunkdataformat.html|Chunk format} 
 * @typedef {Object} EncryptRequestInternal
 * @property {String} stringData Plaintext string (utf8) to be encrypted.
 * @property {ArrayBuffer} chunkArrayBuffer Binary data to be encrypted.
 * @property {String} [cipher="v2"] Chunk format for encoding the encrypted content along 
 * with the associated keytag. Currently supported cipher {@link https://dev.ionic.com/fundamentals/data-format/chunkdataformat.html|formats} are 'v1' and 'v2'. 
 * See https://dev.ionic.com/fundamentals/data-format/chunkdataformat.html
 * @property {Object.<string, object>} [attributes] - Attributes (immutable) associated with the key. 
 * @property {Object.<string, object>} [mutableAttributes] Mutable attributes associated with the key. 
 * @property {Object.<string, object>} [metadata] 
 * {@link https://dev.ionic.com/fundamentals/metadata.html|Metadata}
 * associated with the key.
 * @property {Object} [tag] Key tag (aka keyId) for an existing key. If specified, a key
 * is fetched prior to encryption. Otherwise, a new key is created and used for encryption.
 */

 /**
 * Request object for a decrypt operation. 
 * Specifies the encrypted data along with {@link https://dev.ionic.com/fundamentals/metadata.html|metadata} (if applicable). 
 * @typedef {Object} DecryptRequest
 * @property {String} [stringData] Encrypted string (utf8).
 * [metadata] {@link https://dev.ionic.com/fundamentals/metadata.html|Metadata} 
 * associated with the key.
 */

/**
 * @typedef {Object} ChunkComponents Chunk format components.
 * @property {string} tag Key tag (keyId) for the encryption key. 
 * @property {Buffer} IV The IV used with the protected data.
 * @property {Buffer} data The encrypted data.
 */
