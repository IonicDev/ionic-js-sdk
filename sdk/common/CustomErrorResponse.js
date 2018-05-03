/* 
 * Copyright 2018 Ionic Security Inc.
 * By using this code, I agree to the Terms & Conditions (https://dev.ionic.com/use.html)
 * and the Privacy Policy (https://www.ionic.com/privacy-notice/).
 */

module.exports = { customErrorResponse };

function customErrorResponse(currentErr, message, code) {
    // Just pass along properly formatted rejections
    if(
        typeof currentErr === 'object' &&
        currentErr !== null &&
        currentErr.sdkResponseCode !== 0 &&
        typeof currentErr.error === 'string'
    ){
        return Promise.reject(currentErr);
    }
    message = currentErr ? message + ' ' + currentErr : message;
    // Otherwise create the custom rejection
    return Promise.reject({
        sdkResponseCode: code,
        error: message
    });
}
