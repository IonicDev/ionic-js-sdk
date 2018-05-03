/* 
 * Copyright 2018 Ionic Security Inc.
 * By using this code, I agree to the Terms & Conditions (https://dev.ionic.com/use.html)
 * and the Privacy Policy (https://www.ionic.com/privacy-notice/).
 */

/**
 * User module.
 * @module user/enroll
 */
const { ERRCODE, ERRMSG, STRINGS } = require('../constants.js');
const { customErrorResponse } = require('../common/CustomErrorResponse.js');
const profileManager = require('../common/ProfileManager.js');
const { deriveAES256Key } = require('../common/DeriveKey.js');
const crypto = require('../../internal-modules/crypto-abstract.js');
const { loadUser } = require('./load.js');

module.exports = {
    handleMessage, 
    enrollUser, 
    notifyRegistration
};

function handleMessage(msg, origin) {
    if(msg.action === 'enrollUser') {
        return enrollUser(msg.info, origin);
    }
    if(msg.action === 'notifyRegistration') {
        return notifyRegistration(msg.info, origin);
    }
}

/**
 * Initiates the enrollment process. 
 * Stores the enrollment attempt details with the specified parameters.
 * @param {ProfileInfo} info Identifying information for the specific client application and user/device.
 * @param {String} origin HTTP origin of the client application.
 * @returns {Promise<object>} - A promise containing the decrypted stored profiles for this app/user/auth combination.
 */
function enrollUser(info, origin) {
    if (!info || !info.appId || !info.userId || !info.userAuth) {
        return customErrorResponse(new Error("appId, userId, and userAuth are required parameters."), 
              ERRMSG.BAD_REQUEST, ERRCODE.BAD_REQUEST);
    }

    return Promise.resolve()

        .then(() => {
            if(typeof info.fromAlternate === 'object') {
                return customErrorResponse(null, 'Error in enrollUser. Alternate registration formats are not yet supported.', ERRCODE.NOT_IMPLEMENTED);
            }
            // Derive pass from user auth and origin
            return deriveAES256Key(
                info.userAuth + origin,
                info.appId,
                1000,
                ['encrypt', 'decrypt']
            );
        })
        .catch((err) => {
            return customErrorResponse(err, 'Error in enrollUser. Unable to derive SEP passphrase.', ERRCODE.CRYPTO_ERROR);
        })

        .then((derivedKey)=> {

            return crypto.exportKey({
                format: 'raw',
                key: derivedKey
            });
        })

        .then((keyData) => {

            if(typeof info.enrollmentUrl !== 'string' || info.enrollmentUrl === '') {
                return customErrorResponse(null, "Error in enrollUser. Missing required 'enrollmentUrl' field.", ERRCODE.MISSING_VALUE);
            }

            const storageInfo = {
                appId: info.appId,
                userId: info.userId,
                userAuth: Buffer.from(keyData).toString('base64')
            };

            window.localStorage.setItem(STRINGS.ENROLLMENT_ATTEMPT, JSON.stringify({
                origin: origin,
                info: storageInfo,
                validUntil: new Date(Date.now() + (10 * 60000)).getTime()
            }));

            return Promise.resolve({
                sdkResponseCode: 0,
                redirect: info.enrollmentUrl
            });

        })

        .catch((err) => {
            return customErrorResponse(err, 'Error in enrollUser.', ERRCODE.UNKNOWN);
        });
}


// This call interacts indirectly with CreateUser, using sessionStorage as an intermediary.
// They are faily tightly coupled, and refactoring here usually means you need to look at
// CreateUser as well.
function notifyRegistration(info, origin) {

    return profileManager.queryProfiles(info.appId, info.userId, info.userAuth, origin)

        .then(({profiles}) => {
            return new Promise(function(resolve, reject){
                
                let storageEventHandler = function(e) {  
                    if(e.key !== 'ionic_security_device_profiles') { 
                        return;
                    }

                    // On change, query the profiles again to see if this user/app has a new profile
                    profileManager.queryProfiles(info.appId, info.userId, info.userAuth, origin)
                        .then(({profiles: newProfiles}) => {
                            if(newProfiles.length > profiles.length) {
                                // If yes, load this user and return 
                                // (Note, use the external load user to only provide app safe data rather than calling
                                // loadUser directly on the profileManager)
                                return loadUser(info, origin);
                            }
                        })
                        .then(resolve)
                        .catch(reject);
                };
                window.addEventListener('storage', storageEventHandler);
            });
        })
        .catch((err) => {
            return customErrorResponse(err, 'Error waiting for registration notification.', ERRCODE.UNKNOWN);
        });


}
