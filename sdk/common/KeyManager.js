/* 
 * Copyright 2018 Ionic Security Inc.
 * By using this code, I agree to the Terms & Conditions (https://dev.ionic.com/use.html)
 * and the Privacy Policy (https://www.ionic.com/privacy-notice/).
 */

const getKeys = require('../get-keys/index.js');
const createKeys = require('../create-keys/index.js');
const {ERRCODE, ERRMSG } = require('../constants.js');
const { customErrorResponse } = require('./CustomErrorResponse.js');

class IonicKey {
    /**
     * @typedef {Object} key
     * @property {string}       tag key tag used in the ChunkString.
     * @property {Buffer}       data The key data.
     * @property {attributes=}  attributes The immutable attributes stored with the key.
     * @property {mutableAttributes=} mutableAttributes The mutable attributes associated with the key 
     * @property {metadata=}    metadata The metadata stored with the key.
     */
    constructor({
        tag = '',
        data = '',
        attributes = {},
        mutableAttributes = {},
        metadata = {}
    } = {}) {
        Object.assign(this, {tag, data, attributes, mutableAttributes, metadata});
    }

    getKey() {
        let meta = this.metadata || {};
        return getKeys.getKeys([this.tag], 'hex', meta)
            .then(keys => {
                var keyData = '';
                if (keys && keys.length && keys.length > 0) {
                    keyData = keys[0].key;
                } 
                return {
                    data: keyData,
                    tag: this.tag
                };
            })
            .catch(err => {
                return customErrorResponse(err, ERRMSG.REQUEST_FAILED, ERRCODE.REQUEST_FAILED);
            });
    }

    createKey() {
        return Promise.resolve()
            .then(() => {
                if (this.tag) {
                    return this.getKey()
                    .then(res => {
                        return res;
                    })
                    .catch(err => {
                        return customErrorResponse(err, ERRMSG.INVALID_KEY, ERRCODE.INVALID_KEY);
                    });
                } else {
                    let attributes = this.attributes || {}; 
                    let mutableAttributes = this.mutableAttributes || {}; 
                    let meta = this.metadata || {};
                    return createKeys.createKeys({
                      quantity:1,
                      attributes: attributes,
                      mutableAttributes: mutableAttributes,
                      metadata: meta
                    })
                    .then(result => {
                        return {
                            tag: result.keys[0].keyId,
                            data: result.keys[0].key
                        };
                    });
                }
            })
            .catch(err => {
                return customErrorResponse(err, ERRMSG.REQUEST_FAILED, ERRCODE.REQUEST_FAILED);
            });
    }
}

export {IonicKey};
