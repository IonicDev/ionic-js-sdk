/* 
 * Copyright 2018 Ionic Security Inc.
 * By using this code, I agree to the Terms & Conditions (https://dev.ionic.com/use.html)
 * and the Privacy Policy (https://www.ionic.com/privacy-notice/).
 */

/**
 * User module.
 * @module user/profile
 */
const profileManager = require('../common/ProfileManager.js');
const { deriveAES256Key } = require('../common/DeriveKey.js');
const { customErrorResponse } = require('../common/CustomErrorResponse.js');
const { ERRCODE, ERRMSG } = require('../constants.js');

module.exports = {handleMessage, setActiveProfile, queryProfiles};

function handleMessage(msg, origin) {
    if(msg.action === 'setActiveProfile') {
        return setActiveProfile(msg.info, origin);
    } else if(msg.action === 'queryProfiles') {
        return queryProfiles(msg.info, origin);
    }
}

/**
 * Initiates the enrollment attempt. 
 * Sets the profile that matches the specified deviceId as active (active=true).
 * @param {ProfileInfo} info Identifying information for the specific client application and user/device.
 * @param {String} origin HTTP origin of the client application.
 * @returns {Promise<object>} - A promise containing the updated list of profiles for this app/user/auth combination.
 */
function setActiveProfile(info, origin) {
    if (!info || !info.appId || !info.userId || !info.userAuth || !info.deviceId) {
        return customErrorResponse(new Error("appId, userId, userAuth, and deviceId are required parameters."), 
              ERRMSG.BAD_REQUEST, ERRCODE.BAD_REQUEST);
    }
    return deriveAES256Key(
        info.userAuth + origin,   // This is the passphrase.  The site can't lie about origin unless MITM'd
        info.appId,  // Use the appId as a known salt (we'll later use this to store the key as well)
        1000,   // number of iterations (balance for performance, 100 is low, 100000 is high)
        ['encrypt', 'decrypt'] // Allowed uses.
    )

        .then((sepKey) => {
            return profileManager.setActiveProfile(info.deviceId, sepKey, info.appId, info.userId, origin);
        })

        .then(() => {
            return profileManager.setActiveSession(info.appId, info.userId, info.userAuth, origin);
        })

        .then(() => {
            // Use the external interface for pretty-printing. Avoid the internal profileManager version.
            return queryProfiles(info, origin);
        });
    
}

/**
 * Performs an enrollment profile look-up for the specified application and user. 
 * Uses the profile information to load and decrypt matching profiles from localStorage.
 * @param {ProfileInfo} info Identifying information for the specific client application and user/device.
 * @param {String} origin HTTP origin of the client application.
 * @returns {Promise<object>} - A promise containing the list of profiles for this app/user/auth combination.
 */
function queryProfiles(info, origin) {
    if (!info || !info.appId || !info.userId || !info.userAuth) {
        return customErrorResponse(new Error("appId, userId, and userAuth are required parameters."), 
              ERRMSG.BAD_REQUEST, ERRCODE.BAD_REQUEST);
    }
    return profileManager.queryProfiles(info.appId, info.userId, info.userAuth, origin)
        .then((res) => {
            return {
                sdkResponseCode: res.sdkResponseCode,
                profiles: res.profiles.map((prof) => {
                    return {
                        active: prof.is_active_profile,
                        created: new Date(prof.created_on).toString(),
                        deviceId: prof.device_id,
                        server: prof.server,
                        keyspace: prof.keyspace
                    };
                })
            };
        });
}
