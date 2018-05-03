/* 
 * Copyright 2018 Ionic Security Inc.
 * By using this code, I agree to the Terms & Conditions (https://dev.ionic.com/use.html)
 * and the Privacy Policy (https://www.ionic.com/privacy-notice/).
 */

import { sendMessage } from './SendMessage.js';

export  { loadUser, enrollUser, queryProfiles, setActiveProfile };

/**
 * Load a stored user profile from a previous session (if any).
 * @param {ProfileInfo} argObj Identifying information for the specific client application and user/device.
 * @returns {Promise<object>} - A promise that the profile for that user is loaded.
 * @example
 * var promise = sdk.loadUser({
 *      appId: 'helloworld',
 *      userId: 'myuser',
 *      userAuth: 'password123'
 * });
 * @tutorial helloworld
 * @memberof ISAgent
 * @instance
 */
function loadUser(argObj) {
    return sendMessage({
        action: 'loadUser',
        info: argObj
    });
}


/**
 * Initiate user (device) {@link https://dev.ionic.com/registration.html|enrollment}.
 * Stores 'IonicEnrollmentAttempt' in localStorage and schedules a 'notifier' message
 * that resolves upon successful enrollment. The message timeout is set to 10 minutes.
 *
 * NOTE: The enrollment process is completed by the JSSDK-enabled Enrollment Server.
 * 
 * @param {ProfileInfo} argObj 
 * @returns {Promise<object>} A promise that the payload is stored. The result contains a "Notifier" property 
 *                            with a second promise that will resolve once the user has completed registration 
 *                            with Ionic.com.
 *
 * @example
 * var promise = sdk.enrollUser({
 *      appId: 'helloworld',
 *      userId: 'myuser',
 *      userAuth: 'password123',
 *      enrollmentUrl: 'https://someurl.ionic.com/keyspace/register'
 * });
 * //returns a Promise with a 'notifier' property that resolves when enrollment completes 
 * @tutorial device_enrollment
 * @memberof ISAgent
 * @instance
 * @see
  * {@link module:user~enrollUser|user/enrollUser} for implementation details
 */
function enrollUser(argObj) {
    return sendMessage({
        action: 'enrollUser',
        info: argObj
    })

        .then((response) => {
            // First queue up a call that allows the site to be alerted when registration is completed.
            response.notifier = sendMessage({
                action: 'notifyRegistration',
                info: argObj
            }, 600000); // 10 minutes timeout.

            return response;
        });
}

/**
 * Returns all available profiles for the given application and user. 
 *
 * Each profile specifies the following:
 * * deviceId - A UUID for the device, constructed of the four-character keyspace followed by a Base64-encoded random number.
 * * server - The IDC server that the device was registered with.
 * * created - The time at which registration completed.
 * * active - Only one profile is marked active at a time. This is the profile used for any subsequent key requests or encrypt/decrypt operations.
 * * keyspace - Four-character string.
 * 
 * Important: 
 * Failure to find **any** profiles may indicate that the device isn't enrolled. 
 * However, it can also be due to erroneous parameters. 
 * The values must match the appId, userId, and userAuth specified during device enrollment. 
 * These same three parameters are used for look up, encryption, and decryption of 
 * device profile information.
 * @param {ProfileInfo} argObj Identifying information for the specific client application and user/device.
 * @returns {Promise<object>} - A promise for the stored profiles for this app/user/auth combination.
 * @example
 * var promise = sdk.queryProfiles({ 
 *      appId: 'helloworld',
 *      userId: 'myuser',
 *      userAuth: 'password123'
 * });
 * // eg output: in this example, only one profile exists for the
 * // specific client application and user.
 * // { 
 * //     .sdkResponseCode" : 0,
 * //     "profiles" : [{
 * //         "active": true, 
 * //         "created": "Tue Jan 16 2018 12:46:39 GMT-0500 (EST)",
 * //         "deviceId": "D7GH.6.4cd46ce3-95e2-4aa5-b4f1-9c2be7f27dbf",
 * //         "server": "https://mastereng-api.in.ionicsecurity.com",
 * //         "keyspace":"D7GH"
 * //     }]
 * // }
 * @tutorial profile
 * @memberof ISAgent
 * @instance
 */
function queryProfiles(argObj) {
    return sendMessage({
        action: 'queryProfiles',
        info: argObj
    });
}

/**
 * Set the profile for the specified *deviceId* as the active profile.
 * For the specific *appId* and *userId* combination, only one profile (*deviceId*)
 * can be set as 'active' at any given time. All other profiles are made
 * inactive ('active'=false in the device profile object). Once set, this 
 * profile determines the deviceId (and consequently the keyspace) for 
 * all SDK operations.
 *
 * NOTE: The 'active' profile setting in JSSDK and 'Enabled'/'Disabled' 
 * device settings on the Ionic.com (IDC) Dashboard have distinct functions.
 * An enabled status indicates a policy state while 'active=true' profile
 * property indicates this deviceId as the "chosen one" for the specific 
 * SDK functions.
 * 
 * For example, user John Smith may have five Ionic-enabled devices with 
 * corresponding entries in IDC. Any number of them may be enabled or disabled
 * but only one device can be set as 'active' in the context of JSSDK.
 *
 * @param {ProfileInfo} argObj Specifies the deviceId for the enrollment
 * profile that should be set as active. If the deviceId doesn't exist or the 
 * identifiers and/or user secret aren't correct, this function returns
 * an error response. 
 * @returns {Promise<object>}
 * @example
 * //An entry for the specified deviceId must exist in localStorage 
 * // and the 'appdId', 'userId', 'userAuth' _must match exactly_ those used
 * //during device enrollment. 
 * var promise = sdk.setActiveProfile({ 
 *      appId: 'helloworld',
 *      userId: 'myuser',
 *      userAuth: 'password123',
 *      deviceId: 'D7GH.6.4cd46ce3-95e2-4aa5-b4f1-9c2be7f27dbf'
 * });
 * @tutorial profile
 * @memberof ISAgent
 * @instance
 */
function setActiveProfile(argObj) {
    return sendMessage({
        action: 'setActiveProfile',
        info: argObj
    });
}


////////////////////////////////////////////
// JSDoc custom types
// see http://usejsdoc.org/tags-typedef.html
//
// Defines objects that are passed into or
// returned by multiple functions
////////////////////////////////////////////
/**
 * Device (user) enrollment profile. 
 * Contains identifying information for the specific client application and user/device.  
 * @typedef {Object.<string, string>} ProfileInfo
 * @property {String} appId Unique application identifier used for device profile lookup.
 * @property {String} userId Identifier for the enrolling user/device.
 * @property {String} userAuth Password/pin/key for the enrolling user/device.
 * @property {String} [enrollmentUrl] Password/pin/key of the user.
 * @property {String} [deviceId] Unique device identifier - each successful 
 * enrollment generates a new (and guaranteed unique for that keyspace) deviceId.
 * A UUID for the device, constructed of the four-character keyspace followed by 
 * a Base64-encoded random number.
 */
