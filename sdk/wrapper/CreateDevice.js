/* 
 * Copyright 2018 Ionic Security Inc.
 * By using this code, I agree to the Terms & Conditions (https://dev.ionic.com/use.html)
 * and the Privacy Policy (https://www.ionic.com/privacy-notice/).
 */

import { sendMessage } from './SendMessage.js';

export  { createDevice };

/**
 * Creates a new Ionic device profile for a user.
 * This function is called by the Enrollment Server as the last step in the 
 * enrollment process.
 * @param {Object} objRegistration Values obtained from or specified by the Enrollment Server.
 * @param {String} objRegistration.X-Ionic-Reg-Stoken - A unique string that is returned directly by the Enrollment Portal to provide an extra factor of authentication.
 * @param {String} objRegistration.X-Ionic-Reg-Uidauth - A signed and optionally encrypted token value that contains information about the identity of the user.
 * @param {String} objRegistration.X-Ionic-Reg-Enrollment-Tag - The unique identifier of the set of keyservers into which the device is enrolling.
 * @param {String} objRegistration.X-Ionic-Reg-Pubkey - Typically an RSA 3072-bit key used for encrypting the enrollment package for the key server via an ephemeral intermediate key.
 * @param {String} objRegistration.X-Ionic-Reg-Ionic-Url - The scheme, host, and optionally port of the Ionic.com API server that should be used by the device when enrolling.
 * @param {String} objRegistration.X-Ionic-Reg-Pending-Url - The page displayed while enrollment attempts to complete the createDevice call.
 * @param {String} objRegistration.X-Ionic-Reg-Success-Url - The page displayed if enrollment successfully completes the createDevice call.
 * @param {String} objRegistration.X-Ionic-Reg-Failure-Url - The page displayed if enrollment fails to complete the createDevice call.
 * @return {Promise<Object>} - Resolves to a response object.
 * @tutorial device_enrollment
 * @memberof ISAgent
 * @instance
 * @see
 * {@link module:create-device~createDevice|create-device/createDevice} for implementation details
 */
function createDevice(argObj) {
    return sendMessage({
        action: 'createDevice',
        info: argObj
    });
}
