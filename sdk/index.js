/* 
 * Copyright 2018 Ionic Security Inc.
 * By using this code, I agree to the Terms & Conditions (https://dev.ionic.com/use.html)
 * and the Privacy Policy (https://www.ionic.com/privacy-notice/).
 */

const { STRINGS, ERRCODE } = require('./constants.js');
const semver = require('semver');

function IonicSDKInternal() {

    // Need to perform an environment check here
    // This should determine where we're running and set capabilties appropriately
    // EX: Fall back to forge crypto mode for IE/Safari/AndroidMobile
    // --------------------------------------------------------------
    // CheckEnvironment();


    // Listen for postMessage calls into SDK
    window.addEventListener('message', function(evt) {

        Promise.resolve()
            .then(() => {
                return verifyMessageFormat(evt.data, evt.origin);
            }, err => {
                console.error("Failed to verify message: "+JSON.stringify(err));
                throw err;
            })

            .then(function(){
                // We should determine the correct SEP to use (assuming one exists)
                // based on userId and appId in this step.  For now, skip.
                return;
            })
        
            .then(function(){
                // Route message to correct handlers.  I'd like to abstract this a bit
                // but for now big if-else...
                if(evt.data.message.action.includes('ChunkCipher')) {
                    var chunk = require('./chunk-crypto/index.js');
                    return chunk.handleMessage(evt.data.message);
                }
                else if(evt.data.message.action === 'decryptFile') {
                    var decryptFile = require('./decrypt-file/message-handler.js');
                    return decryptFile.handleMessage(evt.data.message);
                }
                else if(evt.data.message.action === 'createDevice') {
                    var createDevice = require('./create-device/index.js');
                    return createDevice.handleMessage(evt.data.message);
                }
                else if(evt.data.message.action === 'enrollUser' || evt.data.message.action === 'notifyRegistration') {
                    // We don't trust the client for the origin on this event.  We need to pull it directly from the evt object
                    // and not from our internal message.
                    var enrollUser = require('./user/enroll.js');
                    return enrollUser.handleMessage(evt.data.message, evt.origin);
                }
                else if(evt.data.message.action === 'loadUser') {
                    // We don't trust the client for the origin on this event.
                    var loadUser = require('./user/load.js');
                    return loadUser.handleMessage(evt.data.message, evt.origin);
                }
                else if(evt.data.message.action === 'queryProfiles' || 
                    evt.data.message.action === 'setActiveProfile') {
                    var profileActions = require('./user/profile.js');
                    return profileActions.handleMessage(evt.data.message, evt.origin);
                }
                else if(evt.data.message.action === 'createKeys') {
                    var createKeys = require('./create-keys/index.js');
                    return createKeys.handleMessage(evt.data.message);
                }
                else if(evt.data.message.action === 'getKeys') {
                    var getKeys = require('./get-keys/index.js');
                    return getKeys.handleMessage(evt.data.message);
                }
                else if(evt.data.message.action === 'updateKeys') {
                    var updateKeys = require('./update-keys/index.js');
                    return updateKeys.handleMessage(evt.data.message);
                }
                else {
                    return Promise.reject({
                        sdkResponseCode: ERRCODE.NOT_IMPLEMENTED,
                        error: 'Unsupported action: ' + evt.data.message.action
                    });
                }
            })

            .catch(function(err){
                if(typeof err === 'object' && typeof err.error === 'string' && typeof err.sdkResponseCode === 'number') {
                    // This is a properly formatted rejection. We can send this as a response
                    return err;
                }
                else {
                    // This is a truly unexpected error (FIND OUT WHERE IT CAME FROM!)
                    console.error(err);
                    return {
                        sdkResponseCode: ERRCODE.UNKNOWN,
                        error: 'An unexpected error occurred: ' + err
                    };
                }
            })

            .then(function(resp){
                var responseMessage = {
                    id: evt.data.id,
                    version: STRINGS.SDK_VERSION,
                    instance: evt.data.instance,
                    message: resp
                };
                evt.source.postMessage(responseMessage, evt.origin);
            });

    });
}

function verifyMessageFormat(msgObject, origin){
    if (!msgObject) {
        return Promise.reject({
            sdkResponseCode:  ERRCODE.INVALID_VALUE,
            error: STRINGS.INVALID_MSG_DATA
        });
    }
    
    //check version
    if(typeof msgObject.version !== 'string') {
        return Promise.reject({
            sdkResponseCode:  ERRCODE.INVALID_VALUE,
            error: STRINGS.INVALID_MSG_VERSION
        });
    }

    if (!semver.satisfies(semver.coerce(msgObject.version), STRINGS.SUPPORTED_VERSIONS)) {
        return Promise.reject({
            sdkResponseCode:  ERRCODE.INVALID_VALUE,
            error: STRINGS.INVALID_MSG_VERSION_STRING + STRINGS.SUPPORTED_VERSIONS
        });
    }

    if(typeof msgObject.id !== 'number') {
        return Promise.reject({
            sdkResponseCode:  ERRCODE.INVALID_VALUE,
            error: STRINGS.INVALID_MSG_ID
        });
    }

    if(typeof origin !== 'string') {
        return Promise.reject({
            sdkResponseCode:  ERRCODE.INVALID_VALUE,
            error: STRINGS.INVALID_EVENT_ORIGIN
        });
    }

    if (msgObject.origin && 
        (typeof msgObject.origin !== 'string' || 
        msgObject.origin !== origin)) {

        return Promise.reject({
            sdkResponseCode:  ERRCODE.INVALID_VALUE,
            error: STRINGS.INVALID_MSG_ORIGIN
        });
    }
        
    if (!msgObject.message) {
        return Promise.reject({
            sdkResponseCode:  ERRCODE.INVALID_VALUE,
            error: INVALID_MSG_MESSAGE
        });
    }
    
    if(typeof msgObject.message.action !== 'string') {
        return Promise.reject({
            sdkResponseCode:  ERRCODE.INVALID_VALUE,
            error: STRINGS.INVALID_MSG_ACTION
        });
    }


}

// Go ahead and create an internal instance when the frame loads.
new IonicSDKInternal();
