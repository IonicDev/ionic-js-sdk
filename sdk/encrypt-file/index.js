/* 
 * Copyright 2018 Ionic Security Inc.
 * By using this code, I agree to the Terms & Conditions (https://dev.ionic.com/use.html)
 * and the Privacy Policy (https://www.ionic.com/privacy-notice/).
 */

const MODULENAME = 'encrypt-file/index.js';

var crypto = require('../../internal-modules/crypto-abstract.js');
var logger = require('../../internal-modules/logger.js');
var createKeys = require('../create-keys/index.js'); // call create keys directly to generate the key to encrypt the file
var getActiveProfile = require('../get-active-profile/index.js');
var Buffer = require('buffer/').Buffer;
var constants = require('../constants.js');

// Currently we will support version 1.2 for generic file crypto
module.exports = function(arrayBufferPlainTextFile, strEncryptionType){

    var arrSupportedTypes = ['generic'];
    var bufferPlainTextFile = Buffer.from(arrayBufferPlainTextFile); // make a nodeJS Buffer

    // set default
    if(arrSupportedTypes.indexOf(strEncryptionType) === -1){
        strEncryptionType = 'generic';
    }

    logger.log('Encrypting a file.', MODULENAME);

    var objFileHeader = {
        'family': strEncryptionType,
        'version': '1.2'
    };

    var strHexKey = '';
    var aesKey = null;
    var hmacKey = null;
    var strKeyTag = '';
    var bufferOutFile = new Buffer('');
    var bufferHmacIv = null;
    var strFullSegmentHash = '';
    var arrPlainTextSegments = [];
    var arrCipherTextSegments = []; // includes the 16 byte IV and the 10 million byte ciphertext segments.
    var arrEncryptionIvs = [];

    return Promise.resolve()

    // create an aes crypto key
    // this will be used to encrypt the file and calculate the hmac signature
    .then(() => {
        return createKeys.createKeys({quantity:1, encoding:'hex'});
    })

    .then((objKeyResponse) => {

        logger.log('Aes key for encryption has been created.', MODULENAME);

        for(let key in objKeyResponse){
            strKeyTag = key;
            strHexKey = objKeyResponse[strKeyTag]['key'];
            objFileHeader['tag'] = strKeyTag;
            break;
        }
        return getActiveProfile(); // NOTE: MUST BE THE SAME AS THE PROFILE THAT CREATED THE KEY
    })

    .then((objSep) => {
        if(objSep === null){
            return Promise.reject(new Error(constants.ERROR_NO_PROFILES_AVAILABLE));
        }
        else{
            objFileHeader['server'] = objSep['server'];
        }

        let strHeader = JSON.stringify(objFileHeader) + '\r\n\r\n';
        bufferOutFile = Buffer.concat([bufferOutFile, Buffer.from(strHeader)]); // add json header and line breaks to outfile

        return crypto.getRandomValues(16); // generate hmacIv
    })

    .then((bufferRandomValues) => {

        logger.log('HMAC hash IV has been created.', MODULENAME);

        bufferHmacIv = bufferRandomValues;
        bufferOutFile = Buffer.concat([bufferOutFile, bufferHmacIv]); // add the hmaciv to outfile

        // import the keys
        let promiseImportAesKey = crypto.importKey({
			type: 'raw',
			key: Buffer.from(strHexKey, 'hex'),
			algorithm: 'AES-CTR',
			extractable: false,
			usages: ['encrypt']
        });
        let promiseImportHmacKey = crypto.importKey({
			type: 'raw',
			key: Buffer.from(strHexKey, 'hex'),
			algorithm: 'HMAC',
			extractable: false,
			usages: ['sign', 'verify']
        });
        return Promise.all([promiseImportAesKey, promiseImportHmacKey]);
    })

    .then((arrPromiseValues) => {

        logger.log('Imported keys for file encryption.', MODULENAME);

        aesKey = arrPromiseValues[0];
        hmacKey = arrPromiseValues[1];

        // Get the plaintext segments and generate IVs for each segment
        let intBytesRemaining = bufferPlainTextFile.length;
        let intSegmentSize = 10000000; // 10 million byte segments
        let intLastIndex = 0;
        let arrIvPromises = [];
        while(intBytesRemaining > 0){
            var intBytesToSlice = intSegmentSize;
            if(intSegmentSize > intBytesRemaining){
                intBytesToSlice = intBytesRemaining;
            }

            arrPlainTextSegments.push(bufferPlainTextFile.slice(intLastIndex, intBytesToSlice));
            // generate a new Iv for each plaintext segment
            arrIvPromises.push(crypto.getRandomValues(16));
            intLastIndex += intSegmentSize;
            intBytesRemaining -= intSegmentSize;
        }

        return Promise.all(arrIvPromises);
    })

    .then((arrIv) => {

        logger.log('Ivs have been generated for each plaintext segment to be encrypted.', MODULENAME);

        arrEncryptionIvs = arrIv;

        // encrypt plain text segments

        let arrEncryptionPromises = [];
        for(let i = 0; i < arrPlainTextSegments.length; i++){
            arrEncryptionPromises.push(crypto.encrypt({
                key: aesKey,
                algorithm: 'AES-CTR',
                iv: arrEncryptionIvs[i],
                data: arrPlainTextSegments[i],
                blockSize: 64
		    })); // encrypt each plaintext segment
        }

        return Promise.all(arrEncryptionPromises);
    })

    .then((arrEncryptedSegments) => {

        logger.log('Plain text segments have been encrypted.', MODULENAME);

        for(let i = 0; i < arrEncryptedSegments.length; i++){
            arrCipherTextSegments.push(Buffer.concat([arrEncryptionIvs[i], arrEncryptedSegments[i]]));
        }

        // sign plain text segments

        let arrDigestPromises = [];
        for(let i = 0; i < arrPlainTextSegments.length; i++){
            arrDigestPromises.push(crypto.sign({
                key: hmacKey,
                algorithm: 'HMAC-SHA-256',
                data: arrPlainTextSegments[i]
            })); // generate hash of each plaintext segment
        }

        return Promise.all(arrDigestPromises);
    })

    .then((arrSignatureOfSegments) => {
        logger.log('Plaintext hmac segments has been generated.', MODULENAME);

        for(let i = 0; i < arrSignatureOfSegments.length; i++){
            strFullSegmentHash += arrSignatureOfSegments[i].toString('hex');
        }

        // Now generate hash of all segments hashes concantenated.
        return crypto.sign({
            key: hmacKey,
            algorithm: 'HMAC-SHA-256',
            data: Buffer.from(strFullSegmentHash, 'hex')
        });
    })

    .then((bufferHashOfFullSegmentHash) => {

        logger.log('HMAC of plain text hmac segments has been generated.', MODULENAME);
        logger.log('Input data length is: ' + bufferHashOfFullSegmentHash.length, MODULENAME);

        // encrypt the hash of segment hashes using aes 256
        return crypto.encrypt({
            key: aesKey,
            data: bufferHashOfFullSegmentHash,
            algorithm: 'AES-CTR',
            iv: bufferHmacIv,
            blockSize: 32
        });
    })

    .then((bufferHmac) => {

        logger.log('Output ciphertext length is: ' + bufferHmac.length, MODULENAME);
        logger.log('HMAC has been generated.', MODULENAME);

        bufferOutFile = Buffer.concat([bufferOutFile, bufferHmac]); // add hmac cipher text to out file

        // add iv and 10 million byte segment blocks
        for(let i = 0; i < arrCipherTextSegments.length; i++){
            bufferOutFile = Buffer.concat([bufferOutFile, arrCipherTextSegments[i]]);
        }


        logger.log('File encryption complete.', MODULENAME);

        return Promise.resolve(bufferOutFile);
    })

    .catch((objErr) => {
        logger.log(objErr.message, MODULENAME);
        return Promise.reject(objErr);
    });
}
