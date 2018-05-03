/* 
 * Copyright 2018 Ionic Security Inc.
 * By using this code, I agree to the Terms & Conditions (https://dev.ionic.com/use.html)
 * and the Privacy Policy (https://www.ionic.com/privacy-notice/).
 */

/**
 * Common module.
 * @module common/decrypt-attributes
 */

var crypto = require("../../internal-modules/crypto-abstract.js");
var constants = require('../constants.js');
const { ERRCODE, ERRMSG} = constants;

module.exports = {decryptAttributes};

/**
 * @param {Buffer} decryptedKeyBuffer Decrypted key buffer containing data from the server response.
 * @param {KeyAttributes} keyObj Contains attributes and corresponding signatures used to verify server response.
 *
 * @returns {DecryptedAttributes} Decrypted attributes object.
 */
function decryptAttributes(decryptedKeyBuffer, keyObj) {
    let [csig, cattrs, msig, mattrs, keyId] = [
        keyObj['csig'], keyObj['cattrs'], keyObj['msig'], keyObj['mattrs'], keyObj['id']
    ];

    return Promise.all([
        verifySignedAttributes(decryptedKeyBuffer, csig, cattrs),
        verifySignedAttributes(decryptedKeyBuffer, msig, mattrs)
    ])
    .then(verified => {
        return { 
          cattrs: verified[0],
          mattrs: verified[1]
        };
    })
    .catch(err => {
       return Promise.reject(err);
    });
}

function verifySignedAttributes(decryptedKeyBuffer, strBase64Sig, strAttrsJSON) {
    if (!strBase64Sig) {
        //nothing to verify
        if (!strAttrsJSON) {
            return;
        } else {
            throw ERRMSG.MISSING_VALUE;
        }
    }

    return crypto.importKey({
        type: 'raw',
        key: decryptedKeyBuffer,
        algorithm: 'HMAC',
        extractable: false,
        usages: ['sign', 'verify']
    })
    .then((cryptoKey) => {
        // Compute the hmac sha-256 signature of the attributes.
        return crypto.sign({
            algorithm: 'hmac-sha-256',
            key: cryptoKey,
            data: Buffer.from(strAttrsJSON)
        });
    })

    .then((signature) => { 
        // verify the signatures match
        if(Buffer.from(strBase64Sig, 'base64').toString('hex') !== signature.toString('hex')){
            throw new Error('signatures do not match'); 
        }
        let objAttrs = {};
        try {
            strAttrsJSON = strAttrsJSON || '{}';
            objAttrs = JSON.parse(strAttrsJSON);
        } catch (e) {
            throw ERRMSG.PARSE_FAILED; 
        }
        let decryptPromises = [];

        for(var key in objAttrs){
            if(key.startsWith('ionic-protected-') || key === 'ionic-integrity-hash'){
                let bufferEncryptedAttributes = Buffer.from(objCattrs[key][0], 'base64');
                decryptPromises.push(crypto.decrypt({
                    key: decryptedKeyBuffer,
                    iv: bufferEncryptedAttributes.slice(0, 16),
                    data: bufferEncryptedAttributes.slice(16),
                    algorithm: 'AES-GCM',
                    additionalData: Buffer.from(keyId)
                }));
            }
        }

        return Promise.all(decryptPromises);
    })

    .then((arrRes) => {
        let objCattrs = JSON.parse(strAttrsJSON);
        let objCattrsDecrypted = {};
        let i = 0;
        for(var key in objCattrs){
            if(key.startsWith('ionic-protected-') || key === 'ionic-integrity-hash'){
                objCattrsDecrypted[key] = arrRes[i].toString();
                i++;
            }
            else{
                objCattrsDecrypted[key] = JSON.stringify(objCattrs[key]);
            }
        }
        return Promise.resolve(objCattrsDecrypted);
    });
}
////////////////////////////////////////////
// JSDoc custom types
// see http://usejsdoc.org/tags-typedef.html
//
// Defines objects that are passed into or
// returned by multiple functions
////////////////////////////////////////////
/**
 * Decrypted attributes object.
 * Contains the decrypted attributes: mutable (mattrs) and immutable (cattrs). 
 * @typedef {Object} DecryptedAttributes
 * @property {String} cattrs Attributes (immutable) specified as a JSON string.
 * @property {String} mattrs Attributes (mutable) specified as a JSON string.
 */

/**
 * Key Attributes object.
 * Contains the verification key properties: mutable (mattrs) and immutable (cattrs)
 * attributes and the corresponding signatures. 
 * @typedef {Object} DecryptedAttributes
 * @property {String} cattrs Attributes (immutable) specified as a JSON string.
 * @property {String} csig SHA-256 signature corresponding to the 'cattrs' field.
 * @property {String} cattrs Attributes (immutable) specified as a JSON string.
 * @property {String} msig SHA-256 signature corresponding to the 'mattrs' field.
 */