/* 
 * Copyright 2018 Ionic Security Inc.
 * By using this code, I agree to the Terms & Conditions (https://dev.ionic.com/use.html)
 * and the Privacy Policy (https://www.ionic.com/privacy-notice/).
 */

import { sendMessage } from './SendMessage.js';
const {ERRCODE, STRINGS} = require('../constants.js');

export {  
    encryptStringChunkCipher, 
    decryptStringChunkCipher 
};


/**
 * Encrypt a string with an Ionic protection key.
 * The encryption operation consists of several steps:
 * - Create a new Ionic protection key (or fetch an existing one if a key tag is specified)
 * - Encrypt data with the Ionic protection key
 * - {@link https://dev.ionic.com/fundamentals/data-format/chunkdataformat.html|Format} 
 * the encrypted data along with the associated key tag
 * 
 * @param {EncryptRequest} requestObject Request object containing the plaintext data and any
 * additional request parameters.
 *
 * @example <caption>Encrypts string (default cipher - 'v2')</caption>
 * var promise = sdk.encryptStringChunkCipher({
 *   "stringData": "Super secret string"
 * });
 * // response promise resolves to an object with the following properties:
 * // sdkResponseCode: 0
 * // stringChunk: "~!2!D7GH9lbcuEg!x9hyprKQFaUYPXkf5BdIXZYNCvcP4nyEQ81YEMR9GWTAfkk=!"
 *
 * @example <caption>Encrypts string (explicitly specified cipher - 'v1')</caption>
 * var promise = sdk.encryptStringChunkCipher({
 *   "stringData": "Some test string",
 *   "cipher": "v1"
 * });
 * @example <caption>Encrypts string and specifies metadata for the request</caption>
 * var promise = sdk.encryptStringChunkCipher({
 *   "stringData": "test string", 
 *   "metadata": {
 *      "ionic-application-name": "Javascript SDK",
 *      "ionic-application-version": "2.0"
 *   }
 * }); 
 * @return {Promise<ChunkCryptoResponse>} Promise that resolves with a response object.
 * @memberof ISAgent
 * @instance
 */
function encryptStringChunkCipher (requestObject) {
    return validateArgs(requestObject)
        .then(() => sendMessage({
            action:'encryptStringChunkCipher',
            info: Object.assign(requestObject, {
                chunkArrayBuffer: Buffer.from(requestObject.stringData)
            })
        }))
        .then(result => {
            return result;
        })
        .catch(err => {
            if (
                typeof err.sdkResponseCode === 'number' &&
                typeof err.error === 'string'
            ) {
                // this is a valid error, return
                return Promise.reject(err);
            } else {
                return Promise.reject({
                    sdkResponseCode: ERRCODE.CHUNK_ERROR,
                    error: err
                });
            }
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
 * @param {DecryptRequest} requestObject Request object containing the encrypted data and any
 * additional request parameters.
 * @example <caption>Decrypts string encoded with 'v2' format</caption>
 * // NOTE: It's easy to spot the "v2" cipher format: 
 * // look for "~!2!" prefix preceeding the keyspace.
 * var promise = sdk.decryptStringChunkCipher({
 *   "stringData": "~!2!D7GH6DwT3Bk!Z/YZlBi5KrhNfW3aMHTYblw3ozckaEm3Z7+xhiBy1cY=!"
 * });
 * // response promise resolves to an object with the following properties:
 * // sdkResponseCode: 0
 * // stringChunk: "Some test string"
 *
 * @example <caption>Decrypts string encoded with 'v1' format</caption>
 * // NOTE: The keyspace "D7GH" is prefixed with "~!" which is the prefix
 * for "v1" format.
 * var promise = sdk.decryptStringChunkCipher({
 *   "stringData": "~!D7GH9ivX3Ts~fEc!bryqabcaDIwq9cvbcBOSNTjdqeIV83Yh5BGPD3YLv6k=!cEf"
 * });
 * // response promise resolves to an object with the following properties:
 * // sdkResponseCode: 0
 * // stringChunk: "Some test string"
 * @example <caption>Decrypts string and specifies metadata for the request</caption>
 * var promise = sdk.decryptStringChunkCipher({
 *   "stringData": "~!2!D7GH98zyvsY!aWpkib3eiD6Hru1BA8HtqatGt+piocFS/SnpwOn3+hmADnQyUj0b87g5Cg==!", 
 *   "metadata": {
 *      "ionic-application-name": "Javascript SDK",
 *      "ionic-application-version": "2.0"
 *   }
 * }); 
 * @return {Promise<ChunkCryptoResponse>} Promise that resolves with a response object.
 * @memberof ISAgent
 * @instance
 */
function decryptStringChunkCipher (requestObject) {
    return validateArgs(requestObject)
        .then(() => sendMessage({
            action:'decryptStringChunkCipher',
            info: requestObject
        }))
        .then(result => {
            return result;
        })
        .catch(err => {
            if (
                typeof err.sdkResponseCode === 'number' &&
                typeof err.error === 'string'
            ) {
                // this is a valid error, return
                return Promise.reject(err);
            } else {
                return Promise.reject({
                    sdkResponseCode: ERRCODE.CHUNK_ERROR,
                    error: err
                });
            }
        });
}

function validateArgs (argObj) {
    if (!argObj || !argObj.stringData || 
        typeof argObj.stringData !== 'string'){
        return Promise.reject({
            sdkResponseCode: ERRCODE.MISSING_VALUE,
            error: STRINGS.INVALID_ARGUMENT_FOR_CHUNK_ENCRYPTION
        });
    }
    return Promise.resolve();
}
