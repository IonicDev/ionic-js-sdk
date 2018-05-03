/* 
 * Copyright 2018 Ionic Security Inc.
 * By using this code, I agree to the Terms & Conditions (https://dev.ionic.com/use.html)
 * and the Privacy Policy (https://www.ionic.com/privacy-notice/).
 */
var crypto = require('../../internal-modules/crypto-abstract.js');

module.exports = {
    set: function(strMode){
        return crypto.setMode(strMode);
    },
    get: function(){
        return crypto.getMode();
    },
    getAvailable: function(){
        return crypto.getAvailableModes();
    }
}
