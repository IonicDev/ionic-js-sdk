/* 
 * Copyright 2018 Ionic Security Inc.
 * By using this code, I agree to the Terms & Conditions (https://dev.ionic.com/use.html)
 * and the Privacy Policy (https://www.ionic.com/privacy-notice/).
 */

/**
 * Get Keys module.
 * @module get-keys
 */
var ionicReq = require('../../internal-modules/ionic-request.js');
var crypto = require('../../internal-modules/crypto-abstract.js');
const { decryptAttributes } = require('../common/DecryptAttributes.js');
var Buffer = require('buffer/').Buffer;
var constants = require('../constants.js');
const { ERRCODE, ERRMSG, STRINGS } = constants;
const { getActiveProfile } = require('../common/ProfileManager.js');
const { customErrorResponse } = require('../common/CustomErrorResponse.js');

const supportedKeyFormats = ['hex', 'base64', 'utf-8', 'ascii'];

module.exports = {handleMessage, getKeys};

function handleMessage(msg) {
    if( msg.action === 'getKeys' ) {
        if(!msg.info){
            return customErrorResponse('', ERRMSG.BAD_REQUEST, ERRCODE.BAD_REQUEST);
        }
        return getKeys(msg.info.keyIds, msg.info.encoding, msg.info.metadata)
            .then(res => {
                return Promise.resolve({
                    sdkResponseCode: 0,
                  keys: res
                });
            }, err => {  
                return customErrorResponse(err, ERRMSG.UNKNOWN, ERRCODE.UNKNOWN); 
            });
    } else {
        return customErrorResponse(new Error('Unsupported message type: '+msg.action), 
            ERRMSG.NOT_IMPLEMENTED, ERRCODE.NOT_IMPLEMENTED);
    }
}

/**
 * Get key(s) with the specified parameters (if any)
 * @example
 *  getKeys({
 *      keyIds:["D7GH9T9ztKs", "D7GH91pKrNM", "D7GH6KA1vLU", "D7GH6AoRPt0"], 
 *      metadata: {
 *          "ionic-application-name": "Javascript SDK",
 *          "ionic-application-version": "1.0"
 *      }
 *  });
 *
 * @tutorial getkeys
 */
function getKeys(arrKeyIds, strKeyFormat, objMetadata){
    strKeyFormat = strKeyFormat ? strKeyFormat : supportedKeyFormats[0];
    const store = {};
    return Promise.resolve()

        .then(() => {
            if(supportedKeyFormats.indexOf(strKeyFormat) === -1){
                return customErrorResponse('', 'KeyFormat must be one of ' + JSON.stringify(supportedKeyFormats), ERRCODE.BAD_REQUEST);
            }

            // Ensure the first argument is not an empty array...
            if(!Array.isArray(arrKeyIds)){
                return customErrorResponse(STRINGS.INVALID_ARGUMENT_FOR_KEY_IDS, ERRMSG.BAD_REQUEST, ERRCODE.BAD_REQUEST);
            }

            // ... of valid strings
            // todo: are there any other properties we can check to validate key id validity?
            for(let i = 0; i < arrKeyIds.length; i++){
                if(typeof arrKeyIds[i] !== 'string' || arrKeyIds[i].length === 0){
                    return customErrorResponse('', 'tag ' + i + ' is not properly formatted.', ERRCODE.BAD_REQUEST);
                }
            }

            return getActiveProfile();
        })

        .then((sep) => {
            store.sep = sep;
            let strUri = sep.server + '/v2.4/keys/fetch';
            let objKeyFetchData = {
                'protection-keys': arrKeyIds
            };

            //right now we're not specifying pregenerated/current CID for Fetch requests but if 
            //this changes, we can set and specify it here

            let currentCID, nonce;
            return ionicReq.encryptedPost(strUri, objKeyFetchData, sep, currentCID, nonce, objMetadata);
        })
        .catch((err) => {
            return customErrorResponse(err, 'Error in getKeys. Request failed.', ERRCODE.REQUEST_FAILED);
        })

        .then(function(response){
            let keys = response.data['protection-keys'];
            if (!keys || !keys.length) {
                return customErrorResponse('', ERRMSG.KEY_DENIED, ERRCODE.KEY_DENIED);
            }
            let responseData = []; // simple storage for the data we're decrypting from the response
            let responseDataPromises = []; // multiple async calls before we can resolve
            for(var i = 0; i < keys.length; i++){

                const key = keys[i];

                // Key is hex encoded by default
                const bufferEncryptedKey = Buffer.from(key['key'], 'hex');

                // Generate the Additional Authenticated Data (AAD)
                // As a buffer of the utf-8 encoded string "cid:id:csig:msig"
                let authDataArray = [
                    response['request-cid'], 
                    key['id']
                ];
                if(key.csig){
                    authDataArray.push(key.csig);
                }
                if(key.msig){
                    authDataArray.push(key.msig);
                }
                const authData = Buffer.from(authDataArray.join(':'));

                // Decrypt the key and store the result
                responseDataPromises.push(decryptKey(store.sep, bufferEncryptedKey, authData, strKeyFormat, responseData, key));
            }
            return Promise.all(responseDataPromises);
        })
        .catch((err) => {
            return customErrorResponse(err, 'Error in getKeys. Unable to process server response.', ERRCODE.PARSE_FAILED);
        })

        .then(function(args){
            return Promise.resolve(args[0]);
        });

};

function decryptKey(objSep, encryptedKeyBuffer, aadBuffer, decodeFormat, keyStorage, keyObj) {
    let key;
    return crypto.importKey({
        type: 'raw',
        key: Buffer.from(objSep.ka_aes_key, 'hex'),
        algorithm: 'AES-GCM',
        extractable: false,
        usages: ['encrypt', 'decrypt']
    })

        .then(function(decryptionKey) {
            return crypto.decrypt({
                key: decryptionKey,
                iv: encryptedKeyBuffer.slice(0, 16), // IV is first 16 bytes of keyData
                data: encryptedKeyBuffer.slice(16, encryptedKeyBuffer.length), // Rest is real key data
                algorithm: 'AES-GCM',
                additionalData: aadBuffer,
                tagLength: 128
            });
        })
         
        .then(function(decryptedKeyBuffer) {
            key = decryptedKeyBuffer.toString(decodeFormat)  // Default decode format is hex
            return decryptAttributes(decryptedKeyBuffer, keyObj);
        })

        .then(function(objResp){
            keyStorage.push({
                'keyId': aadBuffer.toString().split(':')[1], // AAD = "cid:id:csig:msig"
                'key': key,
                'attributes': objResp.cattrs || {},
                'mutableAttributes': objResp.mattrs || {}
            });
            return keyStorage;
        })

        .catch((objErr) => {
            return customErrorResponse(objErr,
                ERRMSG.KEY_VALIDATION_FAILURE,
                ERRCODE.KEY_VALIDATION_FAILURE);
        });
}
