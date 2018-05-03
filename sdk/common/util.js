/* 
 * Copyright 2018 Ionic Security Inc.
 * By using this code, I agree to the Terms & Conditions (https://dev.ionic.com/use.html)
 * and the Privacy Policy (https://www.ionic.com/privacy-notice/).
 */

const { ERRCODE, ERRMSG, ERRMAP } = require('../constants.js');
const { customErrorResponse } = require('./CustomErrorResponse.js');

module.exports = {convertErrorResponse};

// converts IDC error response by mapping any known error codes
// to corresponding SDK errors
function convertErrorResponse(errObj, alternateMsg, alternateCode) {
    const errCode = alternateCode ? alternateCode : ERRCODE.UNKNOWN;
    const errMsg = alternateMsg ? alternateMsg : ERRMSG.UNKNOWN;
    if (!errObj) {
        return customErrorResponse('Server returned an empty \'error\' object', 
            alternateMsg, alternateCode);
    }
    const serverError = JSON.stringify(errObj);

    //attempt to map to a known SDK error message
    if (errObj.code) {
        let sdkErr = ERRMAP[errObj.code];
        if (sdkErr) {
            return customErrorResponse(serverError, sdkErr.error, sdkErr.sdkResponseCode);
        }
    }
    return customErrorResponse(serverError, alternateMsg, alternateCode);

}
