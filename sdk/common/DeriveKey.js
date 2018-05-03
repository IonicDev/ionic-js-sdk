/* 
 * Copyright 2018 Ionic Security Inc.
 * By using this code, I agree to the Terms & Conditions (https://dev.ionic.com/use.html)
 * and the Privacy Policy (https://www.ionic.com/privacy-notice/).
 */

/**
 * Common module.
 * @module common/derive-key
 */
module.exports = { deriveAES256Key };          

/**
 * @param {ArrayBuffer} pass Binary value containing the CryptoKey representing the master key to be used
 * by the key derivation algorithm.
 * @param {ArrayBuffer} salt Specifies the salt value for PBKDF2 algorithm.
 * @param {Number} iter Specifies the number of iterations for PBKDF2 algorithm.
 * @param {Array} uses Specifies what can be done with the derivated key.
 * 
 * @returns {Promise<Object>} Promise that returns the derivated key as a CryptoKey or a CryptoKeyPair.
 * @see {@link https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/deriveKey|SubtleCrypto.deriveKey} spec 
 */
function deriveAES256Key(pass, salt, iter, uses) {

    return crypto.subtle.importKey(
        'raw',
        Buffer.from(pass),
        { 'name': 'PBKDF2' },
        false,
        ['deriveKey']
    )

        .then((baseKey) => {
            return crypto.subtle.deriveKey(
                {
                    'name': 'PBKDF2',
                    'salt': Buffer.from(salt),
                    'iterations': iter,
                    'hash': 'SHA-256'
                },
                baseKey,
                {
                    'name': 'AES-CTR',
                    'length': 256
                }, // key we want
                true,                               // Extractable
                uses
            );
        });

}
