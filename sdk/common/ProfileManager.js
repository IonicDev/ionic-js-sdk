/* 
 * Copyright 2018 Ionic Security Inc.
 * By using this code, I agree to the Terms & Conditions (https://dev.ionic.com/use.html)
 * and the Privacy Policy (https://www.ionic.com/privacy-notice/).
 */

const { ERRCODE, ERRMSG } = require('../constants.js');
const crypto = require('../../internal-modules/crypto-abstract.js');
const Buffer = require('buffer/').Buffer;
const { customErrorResponse } = require('./CustomErrorResponse.js');
const { deriveAES256Key } = require('./DeriveKey.js');

module.exports = {storeProfile, queryProfiles, setActiveSession, getActiveProfile, setActiveProfile};

let session = [];
let sessionDetails = {};

function getActiveProfile() {

    return Promise.resolve()
        .then(() => {

            if(!(session.length > 0)) {
                return customErrorResponse('No loaded sessions.', 'Error getting active profile.', ERRCODE.NO_DEVICE_PROFILE);
            }

            for(let i = 0; i < session.length; i++) {
                if(session[i].is_active_profile) {
                    return session[i];
                }
            }

        });
}

function queryProfiles(appId, userId, userAuth, origin) {
    return Promise.resolve()

        .then(() => {
            return deriveAES256Key(
                userAuth + origin,   // This is the passphrase.  The site can't lie about origin unless MITM'd
                appId,  // Use the appId as a known salt (we'll later use this to store the key as well)
                1000,   // number of iterations (balance for performance, 100 is low, 100000 is high)
                ['encrypt', 'decrypt'] // Allowed uses.
            );
        })
        .catch((err) => {
            return customErrorResponse(err, 'Error in queryProfiles. Unable to derive SEP passphrase.', ERRCODE.CRYPTO_ERROR);
        })

        .then((sepKey) => {
            let profileString = window.localStorage.getItem('ionic_security_device_profiles');
            if(profileString === null) { 
              profileString = '{}';
              throw "No profiles found in localstorage.";
            }
            const profiles = JSON.parse(profileString);
            if (!profiles[origin]) {
              profiles[origin] = {};
              if (profiles.length > 0) {
                throw "profiles exist in localstorage but none for this origin: "+origin;
              }
            }
            if (!profiles[origin][appId]) {
                profiles[origin][appId] = {};
                if (profiles.length > 0) {
                  throw "profiles exist in localstorage but none for this appId: "+appId;
                }
              }
            if (!profiles[origin][appId][userId]) {
              profiles[origin][appId][userId] = [];
            }
            const relevantProfiles = profiles[origin][appId][userId];
            if (profiles[origin][appId].length > 0 && relevantProfiles.length === 0) {
              throw "profiles found for appId="+ appId + " but none exist for this userId: " + userId;
            }
            let profileDecryptPromises = [];
            for(let i = 0; i < relevantProfiles.length; i++) {
                let sep = Buffer.from(relevantProfiles[i], 'base64');
                profileDecryptPromises.push(
                    crypto.decrypt({
                        key: sepKey,
                        iv: sep.slice(0, 16),
                        data: sep.slice(16),
                        algorithm: 'AES-CTR',
                        blockSize: 128
                    })
                );
            }
            return Promise.all(profileDecryptPromises);
        })

        .then((profiles) => {
            return {
                profiles: profiles.map(function(prof){
                    return JSON.parse(Buffer.from(prof).toString());
                }),
                sdkResponseCode: 0
            }; 
        })

        .catch((msg) => {
            return Promise.resolve({
                profiles: [],
                sdkResponseCode: 0
            }); 
        });

}


function setActiveSession(appId, userId, userAuth, origin) {
    return queryProfiles(appId, userId, userAuth, origin)
        .then(({profiles}) => {

            if(profiles.length > 0) {
                session = profiles;
                sessionDetails = {
                    appId: appId,
                    userId: userId
                };
                return {
                    sdkResponseCode: 0,
                    profiles: profiles
                };
            }
            else {
                return customErrorResponse('No profiles found.', 'Error setting active session.', ERRCODE.NO_DEVICE_PROFILE);
            }

        })
        .catch((err) => {
            return customErrorResponse(err, 'Error in setActiveSession.', ERRCODE.UNKNOWN);
        });
}


// Note about this process: The expectation is that a malicious *site* shouldn't be able to access the data protected
// with this key.  We're not protecting very well against malicious users (although it does add difficulty to extract).
// The better the userAuth field, the better the protection available.  We should encourage something other than Email/Name/Etc.
function storeProfile(sep, key, appId, userId, origin) {
    const store = {};
    return crypto.getRandomValues(16)

        .then((IV) => {
            store.IV = IV;
            // Encrypt SEP with the generated AESKey and IV
            return crypto.encrypt({
                key: key,
                data: Buffer.from(JSON.stringify(sep)),
                algorithm: 'AES-CTR',
                iv: IV,
                blockSize: 128
            });
        })
        .catch((err) => {
            return customErrorResponse(err, 'Error storing profile.', ERRCODE.CRYPTO_ERROR);
        })

        .then((protectedSEP) => {
            let profileString = window.localStorage.getItem('ionic_security_device_profiles');
            if(profileString === null) { profileString = '{}'; }
            const profiles = JSON.parse(profileString);
            
            if(!profiles[origin]) { 
                profiles[origin] = {}; 
            }
            if(!profiles[origin][appId]) { 
                profiles[origin][appId] = {}; 
            }
            if(!profiles[origin][appId][userId]) { 
                profiles[origin][appId][userId] = []; 
            }
            
            profiles[origin][appId][userId].push(Buffer.concat([store.IV, protectedSEP]).toString('base64'));

            window.localStorage.setItem('ionic_security_device_profiles', JSON.stringify(profiles));
            return {
                sdkResponseCode: 0,
            };
        })
        .catch((err) => {
          console.log("Error storing profile");
            return customErrorResponse(err, 'Error storing profile.', ERRCODE.UNKNOWN);
        });
}

// create a call that can be used in the future to set specific SEPS as active
function setActiveProfile(deviceId, sepKey, appId, userId, origin){
    let profileString = window.localStorage.getItem('ionic_security_device_profiles');
    if(profileString === null) { profileString = '{}'; }
    const encryptedStoredProfiles = JSON.parse(profileString);

    return Promise.resolve()

        .then(() => {

            if(!encryptedStoredProfiles[origin]) {
                encryptedStoredProfiles[origin] = {};
            }
            if(!encryptedStoredProfiles[origin][appId]) {
                encryptedStoredProfiles[origin][appId] = {};
            }
            if(!encryptedStoredProfiles[origin][appId][userId]) {
                encryptedStoredProfiles[origin][appId][userId] = [];
            }
            const relevantProfiles = encryptedStoredProfiles[origin][appId][userId]
            
            let profileDecryptPromises = [];
            for(let i = 0; i < relevantProfiles.length; i++) {
                let sep = Buffer.from(relevantProfiles[i], 'base64');
                profileDecryptPromises.push(
                    crypto.decrypt({
                        key: sepKey,
                        iv: sep.slice(0, 16),
                        data: sep.slice(16),
                        algorithm: 'AES-CTR',
                        blockSize: 128
                    })
                );
            }
            return Promise.all(profileDecryptPromises);
        })

        .then((decryptedProfiles) => {
            let profiles = decryptedProfiles.map(function(prof){
                return JSON.parse(Buffer.from(prof).toString());
            });


            const profileMatches = profiles.filter(profile => profile.device_id === deviceId);
            if(!profileMatches.length) {
                return customErrorResponse("Missing a profile for the specified deviceId: "+deviceId,
                    ERRMSG.NO_DEVICE_PROFILE, ERRCODE.NO_DEVICE_PROFILE);
            }
            if (profileMatches.length != 1) {
                return customErrorResponse("Profile set is corrupted. Multiple profiles found for deviceId: "+deviceId,
                    ERRMSG.NO_DEVICE_PROFILE, ERRCODE.NO_DEVICE_PROFILE);
            }
            
            encryptedStoredProfiles[origin][appId][userId] = [];
            window.localStorage.setItem('ionic_security_device_profiles', JSON.stringify(encryptedStoredProfiles));
            let storeProfilePromises = [];
            for(let i = 0; i < profiles.length; i++){
                /*eslint-disable camelcase*/
                if(profiles[i].device_id === deviceId){
                    profiles[i].is_active_profile = true;
                }
                else{
                    profiles[i].is_active_profile = false;
                }
                /*eslint-enable camelcase*/
                storeProfilePromises.push(storeProfile(profiles[i], sepKey, appId, userId, origin))
            }
            return Promise.all(storeProfilePromises);
        });
}
