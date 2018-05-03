/* 
 * Copyright 2018 Ionic Security Inc.
 * By using this code, I agree to the Terms & Conditions (https://dev.ionic.com/use.html)
 * and the Privacy Policy (https://www.ionic.com/privacy-notice/).
 */
const ionicKey = require('../common/KeyManager.js');
const {STRINGS, ERRCODE} = require('../constants.js');
const decryptFileBuffer = require('./index.js');

function handleMessage(msg) {
    if( msg.action === 'decryptFile') {
        return decryptFileBuffer(msg.info.data)
            .then((plaintext) => {
                return {
                    sdkResponseCode: 0,
                    data: plaintext
                };
            });
    }
}

module.exports = {
    handleMessage
};
