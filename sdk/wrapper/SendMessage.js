/* 
 * Copyright 2018 Ionic Security Inc.
 * By using this code, I agree to the Terms & Conditions (https://dev.ionic.com/use.html)
 * and the Privacy Policy (https://www.ionic.com/privacy-notice/).
 */

let { generateId } = require('../common/GenerateId.js');
let { STRINGS, ERRCODE, ERRMSG, NUMBERS } = require('../constants.js');

module.exports = { 
    sendMessage, 
    setInstanceId, 
    setSdkFrame, 
    setAppId, 
    setUserId, 
    setPreSendRequirement,
    urlOrigin
};

let instanceId;
let appId = 'default';
let userId = 'default';
let sdkWindow;
let sdkOrigin;
let sdkSource;
let waitUntil = [];

function setInstanceId(newId) {
    instanceId = newId;
}

function setAppId(newId) {
    appId = newId;
}

function setUserId(newId) {
    userId = newId;
}

function setSdkFrame(window, origin, source) {
    sdkWindow = window;
    sdkOrigin = origin;
    sdkSource = source;
}

function urlOrigin(url) {
    if (!url || !url.protocol || !url.host) {
        throw "Failed to extract HTTP origin from URL: "+JSON.stringify(url);
    }
    return url.protocol + "//" + url.host;
}

function setPreSendRequirement(prom) {
    waitUntil.push(prom);
}

function sendMessage(message, timeout = NUMBERS.DEFAULT_MESSAGE_TIMEOUT) {

    return Promise.all(waitUntil)

        .then(() => {
            return new Promise(function(resolve, reject){
                // The one requirement here is that a sendMessage is given a message object to send.
                // It makes ZERO assumptions about what fields should be on the provided objects.
                if(typeof message !== 'object') {
                    reject({
                        sdkResponseCode: ERRCODE.INVALID_VALUE,
                        error: ERRMSG.INVALID_VALUE + ': sendMessage expected an object but received ' + (typeof message)
                    });
                    return;
                }

                if (!window) {
                    reject({
                        sdkResponseCode: ERRCODE.INVALID_VALUE,
                        error: ERRMSG.INVALID_VALUE + ': sendMessage unable to access the window object'
                    });
                    return;
                }
                // Create our message structure.
                var msg = {
                    origin: urlOrigin(window.location),
                    id: generateId(),
                    message: message,
                    version: STRINGS.SDK_VERSION,
                    instance: instanceId,
                    appId: appId,
                    userId: userId
                };

                // Generate our handler for the response.
                // Chrome is nice in that PostMessage has no data limits outside of actually running out of memory
                // (as far as I can tell...). This means we shouldn't have to support multimessage schemes.
                window.addEventListener('message', function generatedListener(pResp){
                    // Strict checking for our allowed domains.  This is not optional. DO NOT REMOVE!
                    // Removing this check results in serious security holes.
                    if(pResp.origin !== sdkOrigin) {

                        console.error("SDK origin: "+sdkOrigin);
                        console.error("Ignoring messages from untrusted source: ", pResp.origin);
                        console.error(pResp);
                        return;
                    }

                    if(pResp.data.id === msg.id) {
                        window.removeEventListener('message', generatedListener);  // remove the listener when we have a response.
                        //Determine correct resolution based on fields
                        if(typeof pResp.data.message === 'object') {
                            // Reject on error
                            if(typeof pResp.data.message.error === 'string' || pResp.data.message.sdkResponseCode !== 0) {
                                console.error("Message rejected. sdkResponseCode="+ pResp.data.message.sdkResponseCode);
                                console.error(pResp.data.message.error);
                                reject(pResp.data.message);
                            }
                            else {
                                resolve(pResp.data.message);
                            }
                        }
                        else {
                            // Serious error, invalid message
                            reject({
                                sdkResponseCode: ERRCODE.UNKNOWN,
                                error: 'Internal sdk error. Invalid message format: ' + pResp.data.message
                            });
                        }

                    }
                });
                // Post the message to our known list of supported hosts.
                // DO NOT POST TO '*'
                sdkWindow.postMessage(msg, sdkSource);

                // Prevent invalid timeout values by reverting to default if needed.
                if(typeof timeout !== 'number') {
                    timeout = NUMBERS.DEFAULT_MESSAGE_TIMEOUT;
                }

                // Schedule a rejection for the specified timeout.
                window.setTimeout(function(){
                    reject({
                        sdkResponseCode: ERRCODE.UNKNOWN,
                        error: 'An unexpected error has occurred: sendMessage did not receive a response before timeout (' + timeout + 'ms).'
                    });
                }, timeout);
            });
        });
}
