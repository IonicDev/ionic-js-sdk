// constants
const MODULENAME = 'ionic-request.js';
const request = require('request');
const { ERRCODE, ERRMSG, STRINGS } = require('../sdk/constants.js');
const { customErrorResponse } = require('../sdk/common/CustomErrorResponse.js');

let Buffer = require('buffer/').Buffer;
let crypto = require('./crypto-abstract.js');
let logger = require('./logger.js');
let util  = require('../sdk/common/util.js');
let generateCid = require('../sdk/common/GenerateCID.js');

function IonicRequest() {}

IonicRequest.prototype.get = function(strUri) {
    return new Promise(function(resolve, reject) {
        if (typeof XMLHttpRequest !== 'undefined') {
            // make get request in browser
            let xmlHttp = new XMLHttpRequest();
            xmlHttp.onreadystatechange = function() {
                if (xmlHttp.readyState == 4 && xmlHttp.status == 200) {
                    resolve(xmlHttp.responseText);
                }
            };
            xmlHttp.open('GET', strUri, true); // true for asynchronous
            xmlHttp.send();
        } else {
            // make get request in node
            request(strUri, function(error, response, body) {
                //console.log("error:", error); // Print the error if one occurred
                //console.log("statusCode:", response && response.statusCode); // Print the response status code if a response was received
                //console.log("body:", body); // Print the response.
            });
        }
    });
};

IonicRequest.prototype.post = function(strUri, objPostData, objHeaders) {
    return new Promise(function(resolve, reject) {
        if (typeof XMLHttpRequest !== 'undefined') {
            // make post request in browser
            let xmlHttp = new XMLHttpRequest();
            xmlHttp.onreadystatechange = function() {
                if (xmlHttp.readyState === 4) {
                    if (xmlHttp.status == 200) {
                        resolve(xmlHttp.responseText);
                    } else {
                        reject(new Error(xmlHttp.statusText));
                    }
                }
            };

            xmlHttp.open('POST', strUri, true); // true for asynchronous

            // Add any headers AFTER open call
            if (objHeaders !== undefined) {
                for (let strKey in objHeaders) {
                    xmlHttp.setRequestHeader(strKey, objHeaders[strKey]);
                }
            }
            xmlHttp.send(JSON.stringify(objPostData));
        } else {
            // make post request in node
            let objOptions = {
                uri: strUri,
                method: 'POST',
                headers: objHeaders,
                body: objPostData,
                json: true
            };
            request(objOptions, function(error, response, body) {
                //console.log("error:", error); // Print the error if one occurred
                //console.log("statusCode:", response && response.statusCode); // Print the response status code if a response was received
                //console.log("body:", body); // Print the response

                if (response.statusCode === 200) {
                    resolve(body);
                } else {
                    reject(error);
                }
            });
        }
    });
};


IonicRequest.prototype.encryptedPost = function(strUri, objPostData, objSep, cid, nonce, objMetaData) {

    //TODO if we switch to always generating CID, add it to the check below
    if (!strUri || !objPostData || !objSep) {
        return customErrorResponse('', ERRMSG.BAD_REQUEST, ERRCODE.BAD_REQUEST); 
    }
    
    objMetaData = objMetaData || {};
     /*eslint-disable camelcase*/
    objMetaData.hfphash = objSep.hfp_hash;
    /*eslint-enable camelcase*/
    let requestBody = null;
    return Promise.resolve()
        .then(() => createIonicEncryptedRequestBody(objSep, objPostData, cid, nonce, objMetaData))
        .then(objRequestBody => {
            requestBody = objRequestBody;
            let returnPromise = null;
            if (typeof XMLHttpRequest !== 'undefined') {
                // make encrypted post request in browser
                returnPromise = sendHttpRequest;
            } else {
                // make encrypted post request in node
                returnPromise = makePostRequest;
            }
            return returnPromise(requestBody, strUri);
        })
        .then(objEncryptedResponse => {
            return handleIonicEncryptedResponse(objSep, objEncryptedResponse, requestBody.cid);
        })
        .then(objDecryptedResponse => {
            if (objDecryptedResponse.error) {
                return util.convertErrorResponse(objDecryptedResponse.error, ERRMSG.BAD_RESPONSE, ERRCODE.BAD_RESPONSE);
            }
            objDecryptedResponse['request-cid'] = requestBody['cid']; // set for use in calling function
            return objDecryptedResponse;
        })
        .catch(err => {
            return customErrorResponse(err, ERRMSG.REQUEST_FAILED, ERRCODE.REQUEST_FAILED);
        });
};

module.exports = new IonicRequest();

function sendHttpRequest(objRequestBody, strUri) {
    return new Promise((resolve, reject) => {
        let xmlHttp = new XMLHttpRequest();
        xmlHttp.onreadystatechange = function() {
            if (xmlHttp.readyState == XMLHttpRequest.DONE) {
                if (xmlHttp.status >= 200 && xmlHttp.status < 500) {
                  resolve(xmlHttp.responseText);
                }
            } 
        };
        xmlHttp.open('POST', strUri, true); // true for asynchronous
        xmlHttp.send(JSON.stringify(objRequestBody));
    });
}

function makePostRequest(objRequestBody, strUri) {
    return new Promise((resolve, reject) => {
        let objOptions = {
            uri: strUri,
            method: 'POST',
            body: objRequestBody,
            json: true
        };

        request(objOptions, function(error, response, body) {
            resolve(body);
        });
    });
}

module.exports = new IonicRequest();

function createIonicEncryptedRequestBody(objSep, objPostData, cid, nonce, objMetaData={}) {
    let bufferIv = null;
    let bufferSerializedEnvelopeContents = null;
    let aesKey = null;
    return new Promise(function(resolve, reject) {
        let objEnvelopeContents = {
            meta: objMetaData,
            data: objPostData
        };
        
        // Send the fingerprint only once

        if (objSep.sentHfpOnce === false) {
            objEnvelopeContents.meta.hfp = JSON.stringify(objSep.hfp); // this must be a stringified json object

            // Ensure we don't send again
            const strIonicProfiles = window.localStorage.getItem('ionic_security_device_profiles'); // should not be null here
            const objIonicProfiles = JSON.parse(strIonicProfiles);
            for (let strProfileKey in objIonicProfiles) {
                if (objIonicProfiles[strProfileKey].device_id === objSep.device_id) {
                    objIonicProfiles[strProfileKey].sentHfpOnce = true;
                }
            }
            window.localStorage.setItem('ionic_security_device_profiles', JSON.stringify(objIonicProfiles));
        }
        
        Promise.all([cid || generateCid(objSep), nonce || crypto.getRandomValues(16)])
            .then((res) => {
            
                cid = res[0];
                bufferIv = res[1];
                if (!cid || !bufferIv) {
                    throw "Failed to set CID and/or nonce";
                }
                // Serialize the envelope contents to a buffer containing the UTF-8 encoding of the contents.
                bufferSerializedEnvelopeContents = Buffer.from(JSON.stringify(objEnvelopeContents), 'utf-8');
                
                // Create an AES-GCM cipher using the SEP.CD:IDC as the key and the 16-byte initialization vector.
                // Set the authenticated data (AAD) to be the Conversation ID byte array.
                return crypto.importKey({
                    type: 'raw',
                    key: Buffer.from(objSep.idc_aes_key, 'hex'),
                    algorithm: 'AES-GCM',
                    extractable: false,
                    usages: ['encrypt', 'decrypt']
                });
            })
            .then(key => {
                //logger.log("Imported key for AES-GCM encrypt.", MODULENAME);
                aesKey = key;
                return crypto.encrypt({
                    key: aesKey,
                    iv: bufferIv,
                    data: bufferSerializedEnvelopeContents,
                    algorithm: 'AES-GCM',
                    additionalData: Buffer.from(cid)
                });
            })
            .then(bufferCipherText => {
                //logger.log("Encrypted the envelope contents.", MODULENAME);
                // Combine the initialization vector, the encrypted JSON, and the auth tag.
                // - Prepend the resulting cipher text bytes with the initialization vector.
                // The tag is already appended to the cipher text (per AES-GCM documentation) --> https://www.w3.org/TR/WebCryptoAPI/#dfn-AesGcmParams
                // The tag is already appended in sjcl crypto as well
                // In node we manually append the tag before we resolve

                let bufferIvCipherTextAad = Buffer.concat([bufferIv, bufferCipherText]);

                // Compose a JSON representation containing the resulting Base64-encoded string as the value
                //  of the envelope field and the Conversation ID string as the value of the cid field.
                // This representation should use UTF-8 encoding.
                let objRequestBody = {
                    cid: cid,
                    envelope: bufferIvCipherTextAad.toString('base64') // Encode the results of the previous step as a single array of bytes using Base64.
                };
                resolve(objRequestBody);
            })
            .catch(objErr => {
                reject(objErr);
            });
    });
}

function handleIonicEncryptedResponse(objSep, objEncryptedResponse, strRequestCid) {
    return new Promise(function(resolve, reject) {
        if (typeof objEncryptedResponse === 'string') {
            objEncryptedResponse = JSON.parse(objEncryptedResponse); // in case JSON returned as plaintext
        }
        // As a precaution, ensure that the client's CID is the same as the response's CID.
        if (objEncryptedResponse['cid'] === strRequestCid) {
            // Base 64 decode the envelope's value.
            let bufferDecodedResponseEnvelope = Buffer.from(objEncryptedResponse['envelope'], 'base64');

            // Prepare to decrypt the `envelope` contents.
            // Obtain the initialization vector which is the first 16 bytes.
            let bufferIvFromEnvelope = bufferDecodedResponseEnvelope.slice(0, 16);

            // Obtain the data to decrypt which is the bytes between the initializaiton vector and the tag.
            let bufferCipherTextFromEnvelope = bufferDecodedResponseEnvelope.slice(
                16,
                bufferDecodedResponseEnvelope.length
            );

            // Construct a cipher to decrypt the data.
            // Create an AES-GCM cipher using the SEP.CD:IDC as the key.
            // Set the cipher's `aad` as the value of the `cid`.
            crypto
                .importKey({
                    type: 'raw',
                    key: Buffer.from(objSep.idc_aes_key, 'hex'),
                    algorithm: 'AES-GCM',
                    extractable: false,
                    usages: ['encrypt', 'decrypt']
                })
                .then(key =>
                    crypto.decrypt({
                        key: key,
                        iv: bufferIvFromEnvelope,
                        data: bufferCipherTextFromEnvelope,
                        algorithm: 'AES-GCM',
                        additionalData: Buffer.from(objEncryptedResponse['cid'])
                    })
                )
                .catch(cryptoErr => {
                    return customErrorResponse(cryptoErr, ERRMSG.CRYPTO_ERROR, ERRCODE.CRYPTO_ERROR);
                })
                .then(bufferDecryptedResponseJson => {
                    let parsed = JSON.parse(bufferDecryptedResponseJson.toString());
                    resolve(parsed);
                })
                .catch(obErr => {
                    return customErrorResponse(objErr, ERRMSG.PARSE_FAILED, ERRCODE.PARSE_FAILED);
                });
        } else {
            throw 'The cid from the response is different than cid from the request.';
        }
    });
}
