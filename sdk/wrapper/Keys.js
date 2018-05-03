/* 
 * Copyright 2018 Ionic Security Inc.
 * By using this code, I agree to the Terms & Conditions (https://dev.ionic.com/use.html)
 * and the Privacy Policy (https://www.ionic.com/privacy-notice/).
 */

import { sendMessage } from './SendMessage.js';

export  { createKeys, getKeys, updateKeys };

/**
 * Creates one or more keys with the specified parameters.
 *
 * Important: it is an error to include attributes in the 'mutableAttributes' field 
 * that already exist in the 'attributes' field of the existing key. 
 * Such requests will be rejected.
 * 
 * @param {KeyRequest} objKeyCreateInfo - specifies parameters for the key request
 * @return {Promise<KeyResponse>} responsePromise - Resolves to a response object.
 *
 * @memberof ISAgent
 * @instance
 * @see
 * {@link module:create-keys~createKeys|create-keys/createKeys} for implementation details
 * @example <caption>Creates a single key</caption>
 *   var promise = sdk.createKeys({
 *      quantity:1
 *  });
 * @example <caption>Creates multiple keys with the same custom attributes</caption>
 *  var promise = sdk.createKeys({
 *      quantity:2,
 *      attributes:
 *      {
 *          "attr1": "some value",
 *          "attr2": [
 *            "val1", "val2", "val3"
 *          ]
 *      }
 *  });
 * @example <caption>Creates a key with request metadata as well some mutable and immutable attributes</caption>
 *  var promise = sdk.createKeys({
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
 *
*/
function createKeys(objKeyCreateInfo) {
    return sendMessage({
        action: 'createKeys',
        info: objKeyCreateInfo
    });
}

/**
 * Returns key data for keys matching the specified key id's.
 *
 * @param {GetKeyRequest} objGetKeyInfo Specifies the keys to be fetched.
 * @return {Promise<KeyResponse>} responsePromise - Resolves to a response object.
 * @memberof ISAgent
 * @instance
 * @see
 * {@link module:get-keys~getKeys|get-keys/getKeys} for implementation details
 * @example <caption> Fetches a single key for the specific key tag (keyId). </caption>
 *  var promise = sdk.getKeys({keyIds: ["D7GH91pKrNM"]});
 * @example <caption> Fetches multiple keys for the specified key tags (keyIds). </caption>
 *  var promise = sdk.getKeys({
 *      keyIds: ["D7GH91pKrNM", "D7GH6KA1vLU", "D7GH99uYwtI"]
 *  });
 * @example <caption> Fetches multiple keys, specifying an output encoding for the key data. </caption>
 *  var promise = sdk.getKeys({
 *      keyIds: ["D7GH91pKrNM", "D7GH6KA1vLU", "D7GH99uYwtI"],
 *      encoding: 'base64'
 *  });
 * @example <caption> Fetches multiple keys, specifying metadata for the request. </caption>
 *  var promise = sdk.getKeys({
 *      keyIds:['D7GH9T9ztKs'], 
 *      metadata: {
 *          "ionic-application-name": "Javascript SDK",
 *          "ionic-application-version": "1.0"
 *      }
 *  });
 * @example <caption> Fetches multiple keys (some with and some without mutable attributes).</caption>
 *  var promise = sdk.getKeys({
 *      keyIds:["D7GH9T9ztKs", "D7GH91pKrNM", "D7GH6KA1vLU", "D7GH6AoRPt0"], 
 *      metadata: {
 *          "ionic-application-name": "Javascript SDK",
 *          "ionic-application-version": "1.0"
 *      }
 *  });
 */
function getKeys(objGetKeyInfo) {
    return sendMessage({
        action: 'getKeys',
        info: objGetKeyInfo
    });
}


/**
 * Updates keys with the specified parameters.
 *
 * Important: it is an error to include attributes in the 'mutableAttributes' field 
 * that already exist in the 'attributes' field of the existing key. 
 * Such requests will be rejected.
 *
 * @param {KeyUpdateRequest} objKeyUpdateInfo - specifies parameters for the key request.
 * @return {Promise<KeyResponse>} responsePromise - Resolves to a response object. 
 * @memberof ISAgent
 * @instance
 * @see
 * {@link module:update-keys~updateKeys|update-keys/updateKeys} for implementation details
 * @example <caption>Updates key mutable attributes regardless of previous state (Force=true)</caption>
 *  var promise = sdk.updateKeys({
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
 * @example <caption>Updates multiple keys (Force = true for both)</caption>
 *  var promise = sdk.updateKeys({
 *      keyRequests: [{
 *          keyId: "D7GH9T9ztKs",
 *          force: true, 
 *          mutableAttributes: {
 *              "attr3": "changed value!",
 *              "attr5": [
 *                  "1likenew", "updated", "updateable3"
 *              ]
 *          }
 *      }, {
 *          keyId: "D7GH9RGaTlA",
 *          force: true,
 *          mutableAttributes: {
 *              "attr3": "updated new value!",
 *              "attr4": [
 *                  "2somevalue", "updated", "updated3"
 *              ]
 *          }
 *      }], 
 *      metadata: {
 *          "ionic-application-name": "Javascript SDK",
 *          "ionic-application-version": "1.0"
 *      }
 *  });
*/
function updateKeys(objKeyUpdateInfo) {
    return sendMessage({
        action: 'updateKeys',
        info: objKeyUpdateInfo
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
 * Key request object.
 * Contains the key request properties. 
 * @typedef {Object} KeyRequest
 * @property {Number} quantity A number between 1 and 1000.
 * @property {String} [ref='default'] Descriptor used to correlate
 * key request to the key response. 
 * @property {String} [encoding='hex'] - 'hex', 'base64', 'utf-8' or 'ascii'.
 * @property {Object} [attributes={}] - Specifies immutable attributes associated with the key. 
 * @property {Object} [mutableAttributes={}] - Specifies mutable attributes associated with the key. 
 * @property {Object} [metadata={}] - Specifies metadata associated with the request.
*/

/**
 * Key fetch request object.
 * Contains the key fetch request properties.
 * @typedef {Object} GetKeyRequest
 * @property {String[]} keyIds Array of key tags (id's), each specified as a string.
 * @property {String} [encoding='hex'] Supported formats: 'hex', 'base64', 'utf-8' or 'ascii'.
 * @property {Object} [metadata={}] - Specifies metadata associated with the request.
*/

/**
 * Key update request object.
 * Contains the key update request properties. 
 * @typedef {Object} KeyUpdateRequest
 * @property {KeyUpdateRequestObject[]} keyRequests
 * @property {Object} [metadata={}] - Specifies metadata associated with the request.
*/

/**
 * Key response object.
 * Contains the key response properties. 
 * @typedef {Object} KeyResponse
 * @property {Number} sdkResponseCode - The value is 0 (success) or SDK error code.
 * @property {?String} error - The value is undefined unless 'sdkResponseCode' is non-zero.
 * @property {KeyData[]} keys - Key data corresponding to the key(s) created.
 */

/**
 * Key data object.
 * Contains the key data and the corresponding key tag (keyId).
 * @typedef {Object} KeyData 
 * @property {String} keyId Key id (tag) for the key.
 * @property {Object} mutableAttributes Mutable attributes associated with the key.
 * @property {Boolean} [force=false] Indicates that the server should disregard any 
 * signature failures or update conflicts.
*/

/**
 * Key data object.
 * Contains the key data and the corresponding key tag (keyId).
 * @typedef {Object} KeyData 
 * @property {String} keyId Key id (tag) for the key.
 * @property {String} key Key data.
 * @property {Object} [attributes={}] Immutable attributes associated with the key.
 * @property {Object} [mutableAttributes={}] Mutable attributes associated with the key.
*/
