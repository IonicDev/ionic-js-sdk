/* 
 * Copyright 2018 Ionic Security Inc.
 * By using this code, I agree to the Terms & Conditions (https://dev.ionic.com/use.html)
 * and the Privacy Policy (https://www.ionic.com/privacy-notice/).
 */

/**
 * Update Keys module.
 * @module update-keys
 */
let ionicReq = require('../../internal-modules/ionic-request.js');
let crypto = require('../../internal-modules/crypto-abstract.js');
let { addAttributes, addMutableAttributes } = require('../common/AddAttributes.js');
let Buffer = require('buffer/').Buffer;
let constants = require('../constants.js');
let generateCid = require('../common/GenerateCID.js');
let util  = require('../common/util.js');
let { getActiveProfile } = require('../common/ProfileManager.js');
const { ERRCODE, ERRMSG, STRINGS } = constants;
const { customErrorResponse } = require('../common/CustomErrorResponse.js');

const supportedKeyEncodings = ['hex', 'base64', 'utf-8', 'ascii'];

module.exports = {handleMessage, updateKeys};

function handleMessage(msg) {
    if( msg.action === 'updateKeys' ) {
        return updateKeys(msg.info)
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
 * Update keys with the specified parameters
 * @example
 *   updateKeys({
 *      keyRequests: [{
 *          keyId: "D7GH9T9ztKs",
 *          force: true,
 *          mutableAttributes: {
 *              "attr3": "HOORAY",
 *              "attr4": [
 *                  "somevalue", "updated", "updated1"
 *              ]
 *          }
 *      }], 
 *      metadata: {
 *          "ionic-application-name": "Javascript SDK",
 *          "ionic-application-version": "1.0"
 *      }
 *  });
 * @see updateKeys
 * @tutorial updatekeys
*/
function updateKeys(argObj){
    let objSep, nonce, cid;

    let keyRequestData = [];
    let keyResponseData;
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
            objSep = res[1];
            nonce = res[2];
            return generateCid(objSep).then(generatedCid => {
                cid = generatedCid;
            });
        })
        
        //process mutable attributes and generate signature
        .then(() => {
            let promises = [];

            for(var i = 0; i < argObj.keyRequests.length; i++){
                const keyRequest = argObj.keyRequests[i];
                const postfix = keyRequest.force ? STRINGS.FORCE_POSTFIX : '';
                const keyRef = keyRequest.keyId + postfix;
                
                keyRequestData.push ({
                    id: keyRequest.keyId,
                    prevcsig: keyRequest.prevCsig,
                    prevmsig: keyRequest.prevMsig,
                    force: keyRequest.force
                });
                    
                promises.push(addMutableAttributes(keyRequest.mutableAttributes, 
                    keyRef, objSep, nonce, cid));
            }
            return Promise.all(promises);
        })
        .then(signedAttributes => {
            for(var i = 0; i < signedAttributes.length; i++){
                keyRequestData[i].mattrs = signedAttributes[i].attrs;
                keyRequestData[i].msig = signedAttributes[i].sig;
            }
            
            return { 'protection-keys': keyRequestData } ;
        })
        .catch((err) => {
            return customErrorResponse(err, ERRMSG.BAD_REQUEST, ERRCODE.BAD_REQUEST); 
        })

        //send the key update request
        .then(protectionKeysObj => {
            return ionicReq.encryptedPost(
                objSep.server + '/v2.4/keys/modify',  // Target URL
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
            keyResponseData = {
                keys: [],
                errorMap: response.data.errorMap || {}
            };
              
            Object.keys(keyResponseData.errorMap).forEach(function(key,index) {
                util.convertErrorResponse(keyResponseData.errorMap[key],
                    ERRMSG.KEY_DENIED, ERRCODE.KEY_DENIED)
                    .catch(err => {
                        keyResponseData.errorMap[key] = err;
                    }); 
            });

            const keys = response.data['protection-keys'];
            if (!keys || !keys.length) {
                if (keyResponseData.errorMap) {
                    return;
                }
                return customErrorResponse('', ERRMSG.KEY_DENIED, ERRCODE.KEY_DENIED);
            }
            let responseDataPromises = []; // multiple async calls before we can resolve
            for(var i = 0; i < keys.length; i++){
                const key = keys[i];
                const keyRequest = keyRequestData[i];
                //expected sigs format = keyId:prevcsig,csig,prevmsig,msig
                //current spec requires that csig be blank (changes to immutable attrs
                //not currently supported but will be in the future)
                const csig = '';
                let expectedSigs = [keyRequest.prevcsig, csig, keyRequest.prevmsig, keyRequest.msig].join(",");
                expectedSigs = [key.id, expectedSigs].join(":");
                //Verify the response
                responseDataPromises.push(verifyResponse(objSep, key, expectedSigs, keyResponseData));
            }
            return Promise.all(responseDataPromises);
        })
        .then(() => {
            return {
                sdkResponseCode: 0, 
                keys: keyResponseData.keys,
                errorMap: keyResponseData.errorMap
            };
        });
}

function verifyResponse(objSep, key, expectedSigs, responseData) {

    // Import the Key Appliance AES-Key from the SEP.
    return crypto.importKey({
        type: 'raw',
        key: Buffer.from(objSep.ka_aes_key, 'hex'),
        algorithm: 'HMAC',
        extractable: false,
        usages: ['sign', 'verify']
    })

    .then((cryptoKey) => {
        // Compute the hmac sha-256 signature of the attributes.
        return crypto.sign({
            algorithm: 'hmac-sha-256',
            key: cryptoKey,
            data: Buffer.from(expectedSigs)
        });
    })

    .then((signature) => { 
        //hmac on sigs using sep key, base64 encode the hmac
        //verify that calculated and response sigs match
        if (key.sigs == signature.toString('base64')) {
            responseData.keys.push(key);
        } else {
            throw 'Signature mismatch while verifying server response.'; 
        }
    })

    .catch((objErr) => {
        const detailedError = objError && objError.message ? ' ' + objError.message : '';
        responseData.errorMap[key.id] = { 
            sdkResponseCode: ERRCODE.KEY_VALIDATION_FAILURE,
            error: ERRMSG.KEY_VALIDATION_FAILURE + detailedError
        }; 
    });
}

function verifyArguments(requestArgs) {
    // Ensure keyRequests argument is not an empty array...
    if(!requestArgs || !Array.isArray(requestArgs.keyRequests) || !requestArgs.keyRequests.length){
        throw STRINGS.INVALID_ARGUMENT_FOR_KEY_IDS;
    }

    requestArgs.keyRequests.map(
        keyRequest => {
            if(typeof keyRequest.keyId !== 'string' || keyRequest.keyId.length === 0){
                throw '', 'Tag ' + keyRequest.keyId  + ' is not properly formatted.';
            }
            
            // if 'force' boolean *is* set, but the type is invalid
            if (keyRequest.force && typeof keyRequest.force !== 'boolean') {
                throw "["+keyRequest.keyId + "] " + STRINGS.INVALID_ARGUMENT_FOR_FORCE_FLAG; 
            }
            
            // if 'force' boolean isn't set, csig+msig MUST be present
            if (!keyRequest.force && !(keyRequest.prevCsig && keyRequest.prevMsig)) {
                throw "["+keyRequest.keyId + "] " + STRINGS.MISSING_ARGUMENTS_FOR_KEY_UPDATE;
            }
        });
}
