/* 
 * Copyright 2018 Ionic Security Inc.
 * By using this code, I agree to the Terms & Conditions (https://dev.ionic.com/use.html)
 * and the Privacy Policy (https://www.ionic.com/privacy-notice/).
 */

/**
 * Create Keys module.
 * @module create-keys
 */
let ionicReq = require('../../internal-modules/ionic-request.js');
let crypto = require('../../internal-modules/crypto-abstract.js');
let { addAttributes, addMutableAttributes } = require('../common/AddAttributes.js');
let Buffer = require('buffer/').Buffer;
let constants = require('../constants.js');
let generateCid = require('../common/GenerateCID.js');
let { getActiveProfile } = require('../common/ProfileManager.js');
const { ERRCODE, ERRMSG, STRINGS } = constants;
const { customErrorResponse } = require('../common/CustomErrorResponse.js');

const supportedKeyEncodings = ['hex', 'base64', 'utf-8', 'ascii'];

module.exports = {handleMessage, createKeys};

function handleMessage(msg) {
    if( msg.action === 'createKeys' ) {
        return createKeys(msg.info)
            .then(response => {
                return response;
            }, 
            err => {
                return customErrorResponse(err, ERRMSG.UNKNOWN, ERRMSG.UNKNOWN);
            });
    } else {
        return customErrorResponse(new Error('Unsupported message type: '+msg.action), 
            ERRMSG.NOT_IMPLEMENTED, ERRCODE.NOT_IMPLEMENTED);
    }
}
/**
 * Create one or more keys with the specified parameters
 *
 * @param {object} objKeyCreateInfo - specifies parameters for the key request
 * @param {number} objKeyCreateInfo.quantity - A number between 1 and 1000.
 * @param {string} [objKeyCreateInfo.ref='default'] - Descriptor used to correlate
 * key request to the key response 
 * @param {string} [objKeyCreateInfo.encoding='hex'] - 'hex', 'base64', 'utf-8' or 'ascii'
 * @param {object} [objKeyCreateInfo.attributes] - immutable attributes associated with the key 
 * @param {object} [objKeyCreateInfo.mutableAttributes] - mutable attributes associated with the key 
 * @param {object} [objKeyCreateInfo.metadata] - metadata associated with the key
 *
 * @return {Promise<object>} responsePromise - Resolves to a response object.
 * @return {object} responsePromise.sdkResponseCode - 0 (success) or SDK error code
 * @return {string} error - undefined unless.sdkResponseCode is non-zero
 * @return {object[]} responsePromise.keys - key data corresponding to the key(s) created
 * @return {string} responsePromise.keys.keyId - key id (tag) for the created key
 * @return {string} responsePromise.keys.key - key data for the created key
 *
 * @example <caption>Creates a key with mutable and immutable attributes as well as metadata</caption>
 * createKeys({
 *      quantity:1,
 *      attributes:
 *      {
 *          "attr1": "some value that will not change",
 *          "attr2": [
 *            "val1", "val2", "val3"
 *          ]
 *      }, 
 *      mutableAttributes:
 *      {
 *          "attr3": "some value that can be changed later",
 *          "attr4": [
 *            "updateable", "updateable2", "updateable3"
 *          ]
 *      },
 *      metadata: {
 *          "ionic-application-name": "Javascript SDK",
 *          "ionic-application-version": "1.0"
 *      }
 *  });
 * // response promise resolves to an object with the following properties:
 * // sdkResponseCode: 0
 * // TODO update this
 *
 * @tutorial createkeys
*/
function createKeys(argObj){
    let objSep, nonce, cid, csig, msig;

    // First, verify input args, get active SEP, generate nonce and CID values
    //NOTE: the order matters - Promise.all returns results
    //in order of calling (regardless of order of completion)
    return Promise.all([
        verifyArguments(argObj), 
        getActiveProfile(),
        crypto.getRandomValues(16)
        ])
        .then((res) => {
            if (!res || res.length !== 3) {
                throw "Initialization failed";
            }
            argObj = res[0];
            objSep = res[1];
            nonce = res[2];
            return generateCid(objSep).then(generatedCid => {
                cid = generatedCid;
            });
        })
        
        //process mutable and immutable attributes and generate signatures
        .then(() => {
            //NOTE: the order matters - Promise.all returns results
            //in order of calling (regardless of order of completion)
            return Promise.all([
                addAttributes(argObj.attributes, argObj.ref, objSep, nonce, cid),
                addMutableAttributes(argObj.mutableAttributes, argObj.ref, objSep, nonce, cid) 
            ])
            .then((signedAttributes) => {
                if (!signedAttributes || signedAttributes.length !== 2) {
                    throw "Attribute signing failed";
                }
                const cattrsResultIndex = 0;
                const mattrsResultIndex = 1;

                csig = signedAttributes[cattrsResultIndex].sig;
                msig = signedAttributes[mattrsResultIndex].sig;
                
                return { 'protection-keys': [{
                    qty: argObj.quantity,
                    ref: argObj.ref,
                    cattrs: signedAttributes[cattrsResultIndex].attrs,
                    csig: signedAttributes[cattrsResultIndex].sig,
                    mattrs: signedAttributes[mattrsResultIndex].attrs,
                    msig: signedAttributes[mattrsResultIndex].sig
                }]};
            });
        })
        .catch((err) => {
            return customErrorResponse(err, ERRMSG.BAD_REQUEST, ERRCODE.BAD_REQUEST); 
        })

        //send the key create request
        .then(protectionKeysObj => {

            return ionicReq.encryptedPost(
                objSep.server + '/v2.4/keys/create',  // Target URL
                protectionKeysObj,
                objSep,
                cid,
                nonce,
                argObj.metadata
            );
        }, err => {
          return customErrorResponse(err, ERRMSG.REQUEST_FAILED, ERRCODE.REQUEST_FAILED); 
        })

        // process the key create response
        .then(response => {
            const keys = response.data['protection-keys'];
            if (!keys || !keys.length) {
                return customErrorResponse('', ERRMSG.KEY_DENIED, ERRCODE.KEY_DENIED);
            }
            let keyDataStore = []; // simple storage for the data we're decrypting from the response
            let keyDecryptPromises = []; // multiple async calls before we can resolve
            for(var i = 0; i < keys.length; i++){
                const key = keys[i];

                // key is hex encoded by default
                const bufferEncryptedKey = Buffer.from(key['key'], 'hex');

                // Generate the Additional Authenticated Data (AAD)
                // As a buffer of the utf-8 encoded string "cid:ref:id:csig:msig"
                const  arrayAAD = [cid, key['ref'], key['id'], csig, msig];
                const AAD = Buffer.from(arrayAAD.join(':'));

                // Decrypt the key and store the result
                keyDecryptPromises.push(decryptKey(objSep, bufferEncryptedKey, AAD, argObj.encoding, keyDataStore));
            }
            return Promise.all(keyDecryptPromises);
        }, err => {
          return customErrorResponse(err, ERRMSG.BAD_RESPONSE, ERRCODE.BAD_RESPONSE); 
        })
                          
        .then((res) => {
            if (!res || res.length < 1) {
              return Promise.reject('createKeys - completed with null/empty result');
            }
            return {
              sdkResponseCode: 0, 
              keys: res[0]
            };
        }, err => {  
            return customErrorResponse(err, ERRMSG.UNKNOWN, ERRCODE.UNKNOWN); 
        });
}

function decryptKey(objSep, encryptedKeyBuffer, aadBuffer, decodeFormat, keyStorage) {
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
            keyStorage.push({
                'keyId': aadBuffer.toString().split(':')[2], // AAD = CID:ref:keyId
                'key': decryptedKeyBuffer.toString(decodeFormat)  // Default decode format is hex
            });
            return keyStorage;
        })

        .catch((objErr) => {
            return customErrorResponse(objErr,
                ERRMSG.KEY_VALIDATION_FAILURE,
                ERRCODE.KEY_VALIDATION_FAILURE);
        });
}

function verifyArguments(keyCreateArgs) {
            if (!keyCreateArgs) {
                console.log("keyCreateArgs are null, using defaults");
                return Promise.resolve ({
                    ref: STRINGS.DEFAULT_KEY_REF, 
                    encoding: supportedKeyEncodings[0], 
                    quantity:1
                });
            }
            // ref is a required field
            if(!keyCreateArgs.ref){
                keyCreateArgs.ref = STRINGS.DEFAULT_KEY_REF;
            } else if (typeof keyCreateArgs.ref !== 'string') {
                return customErrorResponse(STRINGS.INVALID_ARGUMENT_FOR_REFERENCE, ERRMSG.BAD_REQUEST, ERRCODE.BAD_REQUEST); 
            }

            if (!keyCreateArgs.encoding) {
                keyCreateArgs.encoding = supportedKeyEncodings[0];
            } else if(typeof keyCreateArgs.encoding !== 'string' || supportedKeyEncodings.indexOf(keyCreateArgs.encoding) === -1){
                return customErrorResponse(STRINGS.INVALID_ARGUMENT_FOR_KEY_ENCODING, ERRMSG.BAD_REQUEST, ERRCODE.BAD_REQUEST); 
            }

            // limit requests to max 1000 keys.
            if(!keyCreateArgs.quantity || typeof keyCreateArgs.quantity != 'number' 
                || keyCreateArgs.quantity <= 0 || keyCreateArgs.quantity > 1000){
                return customErrorResponse(STRINGS.INVALID_ARGUMENT_FOR_KEY_QUANTITY, ERRMSG.BAD_REQUEST, ERRCODE.BAD_REQUEST); 
            }
        return Promise.resolve(keyCreateArgs);
}
