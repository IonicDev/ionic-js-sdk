/* 
 * Copyright 2018 Ionic Security Inc.
 * By using this code, I agree to the Terms & Conditions (https://dev.ionic.com/use.html)
 * and the Privacy Policy (https://www.ionic.com/privacy-notice/).
 */

/**
 * User module.
 * @module user/load
 */
const { ERRCODE, ERRMSG } = require('../constants.js');
const { customErrorResponse } = require('../common/CustomErrorResponse.js');
const profileManager = require('../common/ProfileManager.js');

module.exports = {handleMessage, loadUser};

function handleMessage(msg, origin) {
    if(msg.action === 'loadUser') {
        return loadUser(msg.info, origin);
    }
}

/**
 * Loads an existing enrollment profile from localStorage. 
 * Calls setActiveSession with the specified application and user parameters.
 * @param {ProfileInfo} info Identifying information for the specific client application and user/device.
 * @param {String} origin HTTP origin of the client application.
 * @returns {Promise<object>} - A promise containing the updated list of profiles for this app/user/auth combination.
 */
function loadUser(info, origin) {
    if (!info || !info.appId || !info.userId || !info.userAuth) {
        return customErrorResponse(new Error("appId, userId, and userAuth are required parameters."), 
              ERRMSG.BAD_REQUEST, ERRCODE.BAD_REQUEST);
    }
    return profileManager.setActiveSession(
        info.appId,
        info.userId,
        info.userAuth,
        origin
    )

        .then((res) => {
            return {
                sdkResponseCode: res.sdkResponseCode,
                profiles: res.profiles.map((prof) => {
                    return {
                        active: prof.is_active_profile,
                        created: prof.created_on,
                        deviceId: prof.device_id,
                        server: prof.server,
                        keyspace: prof.keyspace
                    };
                })
            };
        })

        .catch((err) => {
            console.log("loadUser() failed");
            console.log(JSON.stringify(err));
            return customErrorResponse(err, 'Unexpected error in loadUser.', ERRCODE.UNKNOWN);
        });
}
