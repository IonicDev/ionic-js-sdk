/* 
 * Copyright 2018 Ionic Security Inc.
 * By using this code, I agree to the Terms & Conditions (https://dev.ionic.com/use.html)
 * and the Privacy Policy (https://www.ionic.com/privacy-notice/).
 */

/**
 * Create device module.
 * @module create-device
 */
const { ERRCODE, STRINGS } = require('../constants.js');
const ionicReq = require('../../internal-modules/ionic-request.js');
const crypto = require('../../internal-modules/crypto-abstract.js');
const Buffer = require('buffer/').Buffer;
const uuid4 = require('uuid4');
const { customErrorResponse } = require('../common/CustomErrorResponse.js');
const profileManager = require('../common/ProfileManager.js');


module.exports = {handleMessage, createDevice};

function handleMessage(msg) {

    const store = {};
    return Promise.resolve()

        .then(() => {
            // Ensure a client actually requested this registration.
            var regInfo = window.localStorage.getItem(STRINGS.ENROLLMENT_ATTEMPT);
            if(regInfo === null) { throw 'No pending profiles.'; }
  
            const reg = JSON.parse(regInfo);
            if(reg.validUntil < Date.now()) {
                localStorage.removeItem(STRINGS.ENROLLMENT_ATTEMPT);
                throw 'Pending profile is expired.';
            }
            store.pendingRegistration = reg;

            return crypto.importKey({
                type: 'raw',
                key: Buffer.from(reg.info.userAuth, 'base64'),
                algorithm: 'AES-CTR',
                extractable: false,
                usages: ['encrypt', 'decrypt']
            });
        })
        .catch((err) => {
            return customErrorResponse(err, 'Error in createDevice.', ERRCODE.BAD_REQUEST);
        })

        .then((userKey) => {
            store.pendingRegistration.info.userKey = userKey;
            return createDevice(
                msg.info['X-Ionic-Reg-Pubkey'],
                msg.info['X-Ionic-Reg-Enrollment-Tag'],
                msg.info['X-Ionic-Reg-Ionic-API-Urls'],
                msg.info['X-Ionic-Reg-Stoken'],
                msg.info['X-Ionic-Reg-Uidauth']
            );
        })

        .then((sep) => {
            store.sep = sep;
            const info = store.pendingRegistration.info;
            return profileManager.storeProfile(
                sep,
                info.userKey,
                info.appId,    
                info.userId,
                store.pendingRegistration.origin
            );
        })

        .then(() => {
            const info = store.pendingRegistration.info;
            return profileManager.setActiveProfile(
                store.sep.device_id,
                info.userKey,
                info.appId,    
                info.userId,
                store.pendingRegistration.origin
            );           
        })

        .then(() => {

            localStorage.removeItem(STRINGS.ENROLLMENT_ATTEMPT);
            return {
                sdkResponseCode: 0,
                redirect: msg.info['X-Ionic-Reg-Success-Url']
            };
        })

        .catch((err) => {
            return customErrorResponse(err, 'Error in createDevice.', ERRCODE.UNKNOWN)
                .catch((err) => {
                    // Only trigger redirect if not a bad_request (Ignore those)
                    if(err.sdkResponseCode !== ERRCODE.BAD_REQUEST) {
                        err.redirect = msg.info['X-Ionic-Reg-Failure-Url'];
                    }
                    return Promise.reject(err);
                });
        });
}

/**
 * Creates a new Ionic device profile for a user.
 * This function is called by the Enrollment Server as the last step in the 
 * enrollment process.
 * @param {String} strBase64EncodedPubKey - Typically an RSA 3072-bit key used for encrypting the enrollment package for the key server via an ephemeral intermediate key.
 * @param {String} strKeyspace - The unique identifier of the set of keyservers into which the device is enrolling.
 * @param {String} strApiUrl - The scheme, host, and optionally port of the Ionic.com API server that should be used by the device when enrolling.
 * @param {String} strSToken - A unique string that is returned directly by the Enrollment Portal to provide an extra factor of authentication.
 * @param {String} strUidAuth - A signed and optionally encrypted token value that contains information about the identity of the user.
 * @return {SEP} Secure enrollment profile.
 * @tutorial device_enrollment
 */
function createDevice(strBase64EncodedPubKey, strKeyspace, strApiUrl, strSToken, strUidAuth) {

    // We need to hang onto some values through several steps
    let store = {};

    // We can go ahead and populate the SEP value we'll complete during this call
    store.sep = {
        server: strApiUrl,
        /*eslint-disable camelcase*/
        hfp: { // Not required to be accurate (we don't really use) however it should be if possible. TODO
            fp_type: 'com.ionicsecurity.fp.macosx.1.0.0',
            os_family: 'OS X',
            os_release: '10.11.6' 
        },
        sentHfpOnce: false,
        hfp_hash: '',       // Set during call
        idc_aes_key: '',    // Set during call
        ka_aes_key: ''      // Set during call
        /*eslint-enable camelcase*/
    };

    return Promise.resolve()
        .then(() => {
            return verifyArgs({
                token: strSToken,
                uIdAuth: strUidAuth,
                keyspace: strKeyspace
            });
        })

        .then(() => {
            // We need these three things
            return Promise.all([
                // 3072-bit RSA public and private key pair.
                crypto.generateKey({
                    algorithm: 'RSA-PSS',
                    extractable: true,
                    usages: ['sign', 'verify']
                }),
                // Random 256-bit AES key.
                crypto.generateKey({
                    algorithm: 'AES-CTR',
                    extractable: true,
                    usages: ['encrypt', 'decrypt'],
                    keySize: 256
                }),
                // Random IV
                crypto.getRandomValues(16)
            ]);
        })
        .catch((err)=> {
            return customErrorResponse(err, 
                'Error in createDevice. Unable to generate required keys.', ERRCODE.CRYPTO_ERROR);
        })

        .then(([rsaKeyPair, aesKey, IV]) => {
            // Store these for later.
            store.rsaKeyPair = rsaKeyPair;
            store.aesKey = aesKey;
            store.IV = IV;
            // Encode the public key as DER using the public format Subject Public Key info (spki)
            return crypto.exportKey({
                format: 'spki',
                key: rsaKeyPair.publicKey
            });
        })
        .catch((err)=> {
            return customErrorResponse(err, 
                'Error in createDevice. Unable SPKI encode RSAPubKey.', ERRCODE.CRYPTO_ERROR);
        })

        .then((rsaPubKeyDER) => {          
            // form the required auth object
            var authObj = {
                tkRespPubKDERB64: rsaPubKeyDER.toString('base64'),
                AUTH: Buffer.from(strSToken + ',' + strUidAuth).toString('base64')
            };

            // Encrypt it with the generated aesKey and IV
            return crypto.encrypt({
                key: store.aesKey,
                data: Buffer.from(JSON.stringify(authObj)),
                algorithm: 'AES-CTR',
                iv: store.IV,
                blockSize: 128
            });
        })
        .catch((err)=> {
            return customErrorResponse(err, 
                'Error in createDevice. Unable to encrypt auth data.', ERRCODE.CRYPTO_ERROR);
        })

        .then((encryptedAuthObj) => {
            // Concat the IV and encrypted Auth object and encode as base64.
            // This is the value 'p'. Store this for later.
            store.p = Buffer.concat([store.IV, encryptedAuthObj]).toString('base64');

            // Use the public key passed to the function to encrypt the AES key we just used
            // to protect the authObj.  This will allow the EP to decrypt it with their private key.
            // To do this, we first have to decode & import the provided pubkey and get the AES Key bytes

            // Decode pub key (Not sure why we need to import this differently?)
            var serverPubKey;
            if (typeof window !== 'undefined') {
                serverPubKey = Buffer.from(window.atob(strBase64EncodedPubKey), 'ascii');
            } else {
                serverPubKey = Buffer.from(strBase64EncodedPubKey, 'base64');
            }

            // Import and get AES bytes
            return Promise.all([
                crypto.importKey({
                    type: 'spki',
                    key: serverPubKey,
                    algorithm: 'RSA-OAEP',
                    extractable: false,
                    usages: ['encrypt']
                }),
                crypto.exportKey({
                    format: 'raw',
                    key: store.aesKey
                })
            ]);
        })
        .catch((err)=> {
            return customErrorResponse(err, 
                'Error in createDevice. Unable to import provided PubKey.', ERRCODE.CRYPTO_ERROR);
        })

        .then(([serverPubKey, rawAESKey]) => {
            // Encrypt the AES key using the public key of the key server using the OAEP padding scheme with SHA-1 as defined in PKCS #1.
            return crypto.encrypt({
                key: serverPubKey,
                data: rawAESKey,
                algorithm: 'RSA-OAEP'
            });
        })
        .catch((err)=> {
            return customErrorResponse(err, 
                'Error in createDevice. Unable to encrypt AES shared key.', ERRCODE.CRYPTO_ERROR);
        })

        .then((encryptedAESKey) => {
            // The base64 encoded encrypted AES key is the value 's'
            // We need to store this
            store.s = encryptedAESKey.toString('base64');

            // Now we need to sign the auth payload (p)
            return crypto.sign({
                algorithm: 'RSA-PSS',
                key: store.rsaKeyPair.privateKey,
                data: Buffer.from(store.p)
            });
        })
        .catch((err)=> {
            return customErrorResponse(err, 
                'Error in createDevice. Unable to sign auth payload.', ERRCODE.CRYPTO_ERROR);
        })

        .then((payloadSignature) => {
            // NOTE: This is the value 'g'
            store.g = payloadSignature.toString('base64');

            return ionicReq.post(
                strApiUrl + '/v2.3/register/' + strKeyspace,
                {
                    k: strKeyspace, // Function argument
                    p: store.p,
                    s: store.s,
                    g: store.g
                }, 
                {
                    'Content-Type': 'application/json',
                    'X-Conversation-ID': uuid4()
                });
        })
        .catch((err)=> {
            return customErrorResponse(err, 
                'Error in createDevice. Unexpected network error.', ERRCODE.REQUEST_FAILED);
        })

        .then((response) => {
            /////////////////////////////////////////////////////
            ///  Registration has been completed              ///
            ///  response contains the API's response         ///
            /////////////////////////////////////////////////////
            var objResponseData;
            if (typeof response === 'string') {
                objResponseData = JSON.parse(response);
            } else {
                objResponseData = response; // response returned as an object (When can this happen?)
            }

            store.encryptedIdcKey = Buffer.from(objResponseData['SEPAESK-IDC'], 'base64');
            store.encryptedKaKey = Buffer.from(objResponseData['SEPAESK'], 'base64');
            
            /*eslint-disable camelcase*/
            store.sep.device_id = objResponseData['deviceID'];
            /*eslint-enable camelcase*/

            // The server response contains peices protected with our generated pubkey.
            // We need to use it to decrypt them. Unfortunatly we need to tell subtle.crypto
            // that we want to allow using this key for decryption, so we have to export and
            // re-import it with that use case.
            return crypto.exportKey({
                format: 'pkcs8',
                key: store.rsaKeyPair.privateKey
            }).then((rsaPrivateKeyPKCS8) => {
                return crypto.importKey({
                    type: 'pkcs8',
                    key: rsaPrivateKeyPKCS8,
                    algorithm: 'RSA-OAEP',
                    extractable: false,
                    usages: ['decrypt']
                });
            });
        })
        .catch((err)=> {
            return customErrorResponse(err, 
                'Error in createDevice. Unable to parse server response.', ERRCODE.PARSE_FAILED);
        })

        .then((rsaPrivateKey) => {
            // Decrypt the idc key and the ka key
            return Promise.all([
                crypto.decrypt({
                    key: rsaPrivateKey,
                    data: store.encryptedIdcKey,
                    algorithm: 'RSA-OAEP'
                }),
                crypto.decrypt({
                    key: store.aesKey,
                    iv: store.encryptedKaKey.slice(0, 16),
                    data: store.encryptedKaKey.slice(16),
                    algorithm: 'AES-CTR',
                    blockSize: 128
                })
            ]);
        })
        .catch((err)=> {
            return customErrorResponse(err, 
                'Error in createDevice. Unable decrypt server keys.', ERRCODE.CRYPTO_ERROR);
        })

        .then(([idcKey, kaKey]) => {
             /*eslint-disable camelcase*/
            store.sep.idc_aes_key = Buffer.from(idcKey).toString('hex');
            store.sep.ka_aes_key = Buffer.from(kaKey).toString('hex');
             /*eslint-enable camelcase*/

            return crypto.digest({
                algorithm: 'SHA-256',
                data: JSON.stringify(store.sep.hfp)
            });
        })
        .then((hfpHashHex) => {
            store.sep['hfp_hash'] = hfpHashHex;
            store.sep['is_active_profile'] = true; // always set newest registration to active device
            store.sep['created_on'] = Date.now();
            store.sep['keyspace'] = strKeyspace;
            return store.sep;
        });          
}

function verifyArgs({token, uIdAuth, keyspace}) {
    if (typeof token !== 'string' || token === '') {
        return Promise.reject({
            sdkResponseCode:  ERRCODE.INVALID_VALUE,
            error: 'Error in createDevice. token is invalid. A valid string is required.'
        });
    }

    if (typeof uIdAuth !== 'string' || uIdAuth === '') {
        return Promise.reject({
            sdkResponseCode:  ERRCODE.INVALID_VALUE,
            error: 'Error in createDevice. UidAuth is invalid. A valid string is required.'
        });
    }

    if (typeof keyspace !== 'string' || keyspace === '') {
        return Promise.reject({
            sdkResponseCode:  ERRCODE.INVALID_VALUE,
            error: 'Error in createDevice. keyspace is invalid. A valid string is required.'
        });
    }
}
////////////////////////////////////////////
// JSDoc custom types
// see http://usejsdoc.org/tags-typedef.html
//
// Defines objects that are passed into or
// returned by multiple functions
////////////////////////////////////////////
/**
 * SEP object.
 * Contains the enrollment profile properties. 
 * @typedef {Object} SEP
 * @property {String} server The scheme, host, and optionally port of the Ionic.com API server that should be used by the device when enrolling. 
 * @property {String} device_id A UUID for the device, constructed of the four-character keyspace followed by a Base64-encoded random number.
 * @property {Object} hfp Hardware fingerprint value (currently always defaulted).
 * @property {String} hfp_hash Hash (SHA-256) of the hfp value.
 * @property {Boolean} is_active_profile Specifies whether this profile is currently set active.
 * Always set to 'true' for the most recent enrollment profile.
 * @property {Object} created_on Profile creation date, specified in milliseconds.
 * @property {String} keyspace The unique identifier of the set of keyservers into which the device is enrolled.
 * @property {String} ka_aes_key Keyserver AES key decrypted from 'SEPAESK' server response property.
 * @property {String} idc_aes_key IDC AES key decrypted from 'SEPAESK-IDC' server response property.
*/