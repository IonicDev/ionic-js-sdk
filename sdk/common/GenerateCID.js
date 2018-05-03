/* 
 * Copyright 2018 Ionic Security Inc.
 * By using this code, I agree to the Terms & Conditions (https://dev.ionic.com/use.html)
 * and the Privacy Policy (https://www.ionic.com/privacy-notice/).
 */

var crypto = require("../../internal-modules/crypto-abstract.js");

module.exports = function (objSEP) {
    
    // Get the current time in milliseconds since epoch and convert it to a string.
    var strCurrentTimeMs = Date.now().toString();

    return Promise.resolve()

    .then(() => {
        // Here we will use the javascript window crypto object's ability to generate (cryptographically) random bits.
        return crypto.getRandomValues(4);
    })

    .then(bufferNonce => {
        // Base64 encode the random 32-bit nonce.
        let strBase64EncodedNonce = bufferNonce.toString("base64");

        // Form the CID as the '|' separated concatenation of the 'CID' string, the device's ID, the stringified milliseconds
        // since epoch, and the nonce.
        return Promise.resolve(["CID", objSEP.device_id, strCurrentTimeMs, strBase64EncodedNonce, "2.4.0"].join("|"));
    })

    .catch(err => {
        return Promise.reject(err);
    })
}
