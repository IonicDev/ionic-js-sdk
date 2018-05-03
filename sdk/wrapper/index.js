/* 
 * Copyright 2018 Ionic Security Inc.
 * By using this code, I agree to the Terms & Conditions (https://dev.ionic.com/use.html)
 * and the Privacy Policy (https://www.ionic.com/privacy-notice/).
 */

let {   setPreSendRequirement, 
        setInstanceId, 
        setSdkFrame,
        urlOrigin
    } = require('./SendMessage.js');

let { generateId } = require('../common/GenerateId.js');
let { createDevice } = require('./CreateDevice.js'); 
const {ERRCODE, ERRMSG, STRINGS} = require('../constants.js');

let {   loadUser,
        enrollUser,
        queryProfiles,
        setActiveProfile 
    } = require('./Profile.js');

let {   encryptStringChunkCipher,
        decryptStringChunkCipher 
    } = require('./ChunkCipher.js');

let { decryptFile } = require('./FileCipher.js');

let { createKeys, getKeys, updateKeys } = require('./Keys.js');

const proto = {
    createKeys,
    getKeys,
    updateKeys,
    createDevice,
    enrollUser,
    loadUser,
    queryProfiles,
    setActiveProfile,
    decryptStringChunkCipher,
    encryptStringChunkCipher,
    decryptFile
};

/**
 * Creates a new ISAgent instance.
 * @class
 * @param {String} [sdkSource] URL location for the internal (iframe source) SDK page.
 * If not specified, the location is assumed to be one level up from libs/sdk.bundle.js 
 * that is currently loaded.
 * @example <caption>Uses an explicitly defined location for sdkSource</caption>
 * > new IonicSdk.ISAgent("https://preview-api.ionic.com/jssdk/latest/").sdkOrigin
 * "https://preview-api.ionic.com"
 * @example <caption>Uses a default location for sdkSource</caption>
 * //the current page contains the following script tag:
 * //<script src="https://api.ionic.com/jssdk/latest/libs/sdk.bundle.js" />
 * > new IonicSdk.ISAgent().sdkOrigin
 * "https://api.ionic.com"
 */
function ISAgent(sdkSource) {
    const sdk = Object.create(proto);

    try {
        if (!sdkSource) {
            let matchingScripts = Array.from(document.getElementsByTagName('script'))
                .filter(a => a.src.indexOf(STRINGS.SDK_BUNDLE_NAME) != -1);
            if (matchingScripts && matchingScripts[0].src) {
                const scriptSource = matchingScripts[0].src;
                const index = scriptSource.toLowerCase().indexOf("/libs");
                sdkSource = scriptSource.substring(0, index);
            } else {
                throw "Unable to dynamically determine the hosted SDK location.";
            }           
        }
        sdk.sdkOrigin = urlOrigin(new URL(sdkSource));

    } catch(e) {
        console.error(e);
        return {
            sdkResponseCode:  ERRCODE.INVALID_VALUE, 
            error: "Invalid SDK source URL specified!"
        };
    }

    // Define the ID of this particular instance (may not be needed)
    sdk.instanceId = generateId();
    setInstanceId(sdk.instanceId);
    sdk.version = STRINGS.SDK_VERSION;

    // Load SDK frame.
    sdk.sdkFrame = document.createElement('iframe');

    sdk.waitForLoad = new Promise((resolve) => {
        sdk.sdkFrame.onload = () => {
            setSdkFrame(sdk.sdkFrame.contentWindow, sdk.sdkOrigin, sdkSource);
            resolve();
        };

        sdk.sdkFrame.src = sdkSource;   
        sdk.sdkFrame.style.display = 'none';
        document.body.appendChild(sdk.sdkFrame);
    })
    .catch((err) => {
        return {
            sdkResponseCode:  ERRCODE.INVALID_VALUE, 
            error: "Invalid SDK source URL specified!"
        };
    });
    setPreSendRequirement(sdk.waitForLoad);

    //TODO wait for an initialization ACK of some sort from internal
    //before allowing calls to the SDK
    return sdk;
}

export { ISAgent };
