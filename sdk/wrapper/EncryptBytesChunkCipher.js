/* 
 * Copyright 2018 Ionic Security Inc.
 * By using this code, I agree to the Terms & Conditions (https://dev.ionic.com/use.html)
 * and the Privacy Policy (https://www.ionic.com/privacy-notice/).
 */

import { sendMessage } from './SendMessage.js';

export  { encryptBytesChunkCipher };

function encryptBytesChunkCipher(argObj) {
    return sendMessage({
        action: 'encryptBytesChunkCipher',
        info: argObj
    });
}
