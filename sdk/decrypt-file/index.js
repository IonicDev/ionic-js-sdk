/* 
 * Copyright 2018 Ionic Security Inc.
 * By using this code, I agree to the Terms & Conditions (https://dev.ionic.com/use.html)
 * and the Privacy Policy (https://www.ionic.com/privacy-notice/).
 */

const MODULENAME = 'decrypt-file/index.js';

var crypto = require('../../internal-modules/crypto-abstract.js');
var logger = require('../../internal-modules/logger.js');
var getKeys = require('../get-keys/index.js'); // call get keys directly to get the key to decrypt the file
var Buffer = require('buffer/').Buffer;
var JSZip = require('jszip');

// Currently we will support version 1.2 for generic file crypto
module.exports = function(arrayBufferEncryptedFile){

	let strKeyTag = '';
	let bufferEncryptedFile = Buffer.from(arrayBufferEncryptedFile);
	let bufferGlobalHashIv = null;
	let bufferGlobalHash = null;
	let cryptoKey = null;
	let hmacKey = null;
	let arrPlainTextSegments = [];
	let bufferDecryptedFile = new Buffer('');

	return Promise.resolve()

	.then(() => {
		return new Promise((resolve, reject) => {
			// try openxml first
			var zip = new JSZip();
			zip.loadAsync(arrayBufferEncryptedFile).then((objZipContents) => {
				let objFiles = objZipContents.files;
				for(let strKeyFileName in objFiles){
					if(strKeyFileName === 'ionic/embed.ion'){
						objFiles[strKeyFileName].async('nodeBuffer').then(function(bufferContent){
							// update buffer to contain generic crypto only
							bufferEncryptedFile = bufferContent;
							resolve();
						});
					}
				}
			}).catch((objErr) => {
				// continue as normal to handle pdf, csv, and generic files
				resolve();
			});
		})
	})

	.then(() => {

		let strEncryptedFile = bufferEncryptedFile.toString('utf-8');

		// Handle Ionic CSV types
		if(strEncryptedFile.indexOf('[IONIC-FILE-CSV-1.0]') !== -1){
			// CSV files are base64 encoded and wrapped in starting/ ending tags
			let strStartTag = '[IONIC-DATA-BEGIN]';
			let strEndTag  = '[IONIC-DATA-END]';
			let strBase64EncodedFileData = strEncryptedFile.split(strStartTag)[1].split(strEndTag)[0].trim();
			bufferEncryptedFile = Buffer.from(strBase64EncodedFileData, 'base64');
		}

		// Extract the header from the file Ex: --> {"family":"generic","server":"https://api.ionic.com","tag":"O_6tfUbwDh8","version":"1.2"}
		let strHeader = '';
		let strDelimJsonHeaderV1Dot2 = '\r\n\r\n';
		let intStartingSliceByte = 0;
		for(let i = 0; i < bufferEncryptedFile.length; i++){
			let strCurrentChars = bufferEncryptedFile.toString('utf-8', i, i + strDelimJsonHeaderV1Dot2.length);
			if(strCurrentChars === strDelimJsonHeaderV1Dot2){
				strHeader = bufferEncryptedFile.slice(0, i).toString('utf-8'); // get copy of the header
				bufferEncryptedFile = bufferEncryptedFile.slice(i + strDelimJsonHeaderV1Dot2.length); // get the rest of the data omitting everything before the delimeter
				break;
			}
		}

		// Handle Ionic PDF types
		if(strHeader.indexOf('stream') !== -1){

			// get the pdf header (pdf header string will contain extra data prepended)
			let arrPdfPieces = strHeader.split('stream');
			strHeader = arrPdfPieces[arrPdfPieces.length - 1];

			// read from buffer until we find the 'endstream' portion
			let strSearch = 'endstream';
			for(let i = 0; i < bufferEncryptedFile.length; i++){
				let strCurrentChars = bufferEncryptedFile.toString('utf-8', i, i + strSearch.length);
				if(strCurrentChars === strSearch){
					// slice from first byte to byte i
					bufferEncryptedFile = bufferEncryptedFile.slice(0, i);
					break;
				}
			}
		}

		// Proceed... at this point we simply use generic deccryption.
		if(strHeader === ''){
			throw new Error('File decrypt failed. Unable to find the header in the file.');
		}
		else{

			logger.log('File header: ' + strHeader, MODULENAME);

			let objHeader = JSON.parse(strHeader);
			strKeyTag = objHeader['tag'];
			let strVersion = objHeader['version'];

			// We only support 1.2 decryption for now.
			if(strVersion !== '1.2'){
				throw new Error('Unsupported version for decryption: ' + strVersion + '. File decryption only supports version 1.2');
			}

			return getKeys.getKeys([strKeyTag], 'hex');
		}
	})
	.then((objKeys) => {
		logger.log('Got response from get keys.', MODULENAME);
		
		let strHexKey = objKeys[0].key;

		// Update the buffer to no longer have the global data hash.

		// Get the hash ivBuffer (first 16 bytes)
		let intHashIvSize = 16;
		bufferGlobalHashIv = bufferEncryptedFile.slice(0, intHashIvSize);

		// Get the hash buffer (the next 32 bytes after the hashIv)
		let intHashSize = 32;
		bufferGlobalHash = bufferEncryptedFile.slice(intHashIvSize, intHashIvSize + intHashSize);

		// Slice off hash iv and the hash buffers. Enc File Buffer should only contain ciphertext and iv for cipher text chunks now.
		bufferEncryptedFile = bufferEncryptedFile.slice(intHashIvSize + intHashSize);

		let promiseImportHmacKey = crypto.importKey({
			type: 'raw',
			key: Buffer.from(strHexKey, 'hex'),
			algorithm: 'HMAC',
			extractable: false,
			usages: ['sign', 'verify']
        });
		let promiseImportAesKey = crypto.importKey({
			type: 'raw',
			key: Buffer.from(strHexKey, 'hex'),
			algorithm: 'AES-CTR',
			extractable: false,
			usages: ['decrypt']
		});
		return Promise.all([promiseImportAesKey, promiseImportHmacKey]);
	})
	.then((arrPromiseValues) => {

		cryptoKey = arrPromiseValues[0];
		hmacKey = arrPromiseValues[1];

		logger.log('Imported aes key for decryption.', MODULENAME);

		// Get the 10 million byte cipher text segments
        let intBytesRemaining = bufferEncryptedFile.length;
        let intSegmentSize = 10000016; // 10 million byte segments (include the initialization vector)
		let intLastIndex = 0;
		let arrDecryptionPromises = [];
        while(intBytesRemaining > 0){
            var intBytesToSlice = intSegmentSize;
            if(intSegmentSize > intBytesRemaining){
                intBytesToSlice = intBytesRemaining;
			}
			let cipherText = bufferEncryptedFile.slice(intLastIndex, intBytesToSlice);
			arrDecryptionPromises.push(crypto.decrypt({
				key: cryptoKey,
				algorithm: 'AES-CTR',
				iv: cipherText.slice(0, 16), // first 16 bytes of the segment is the IV
				data: cipherText.slice(16),
				blockSize: 64
			}));
            intLastIndex += intSegmentSize;
            intBytesRemaining -= intSegmentSize;
        }

		return Promise.all(arrDecryptionPromises);
	})
	.then((arrDecryptedSegments) => {
		for(let i = 0; i < arrDecryptedSegments.length; i++){
			arrPlainTextSegments.push(arrDecryptedSegments[i]); // used in verification step
			bufferDecryptedFile = Buffer.concat([bufferDecryptedFile, arrDecryptedSegments[i]]);
		}

		logger.log('File decryption complete.', MODULENAME);
		return Promise.resolve(bufferDecryptedFile);
	})
	.catch((objErr) => {
		return Promise.reject(objErr);
	});
}
