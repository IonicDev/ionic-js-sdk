// constants
const MODULENAME = "crypto-abstract.js";
const UNSUPPORTEDCRYPTO = "Current crypto mode not supported for this action.";

var logger = require("./logger.js");
var Buffer = require("buffer/").Buffer;
const detectIE = require("./detectIE.js");

/**
 * CryptoAbstract layer wraps different crypto implementations.
 * @constructor
 */
function CryptoAbstract() {
    this.availableModes = ["nodejs", "browser", "sjcl", "forge"];
    this.crypto = null;
    this.mode = "";

    if (typeof window !== "undefined") {
        this.crypto = window.crypto || window.msCrypto;
        if (!this.crypto.subtle) {
            this.crypto.subtle = this.crypto.webkitSubtle;
        }
        this.mode = "browser";
    } else {
        try {
            this.crypto = require("crypto");
            this.mode = "nodejs";
        } catch (e) {}
    }
    /****    THIS CAN GO BACK IN IF WE WANT... ***/
    // if (detectIE()){
    //     console.log('IE detected, setting to forge.')
    //     this.mode = 'forge';
    //     this.crypto = require("node-forge");
    // }
    // logger.log("Default SDK crypto source: " + this.mode, MODULENAME);
}

/**
 * Gets all of the available crypto libraries.
 * @return {Array} Returns an array of crypto library names.
 */
CryptoAbstract.prototype.getAvailableModes = function() {
    return this.availableModes;
};

/**
 * Gets the current crypto mode that was automatically set when class was instantiated.
 * @return {string} Returns a string representing the current crypto mode.
 */
CryptoAbstract.prototype.getMode = function() {
    return this.mode;
};

/**
 * Gets the current crypto mode that is currently set.
 * @param {string} strMode - The crypto library to use. Possible values are 'forge', 'sjcl', 'nodejs', or 'browser'.
 * @return {string} Returns a string representing the current crypto mode.
 */
CryptoAbstract.prototype.setMode = function(strMode) {
    if (this.availableModes.indexOf(strMode) !== -1) {
        if (strMode === "sjcl") {
            this.crypto = require("sjcl");
        } else if (strMode === "nodejs") {
            this.crypto = require("crypto");
        } else if (strMode === "forge") {
            this.crypto = require("node-forge");
        } else if (strMode === "browser") {
            if (typeof window === "undefined") {
                logger.log(
                    "Cannot set crypto mode to browser in this context.",
                    MODULENAME
                );
                return false;
            } else {
                this.crypto = window.crypto || window.msCrypto;
                this.crypto.subtle =
                    this.crypto.subtle || this.crypto.webkitSubtle;
            }
        } else {
            return false;
        }
        this.mode = strMode;
        logger.log("Crypto mode has been set to: " + this.mode, MODULENAME);
    } else {
        logger.log("Unsupported crypto mode: " + strMode, MODULENAME);
        return false;
    }
};

/**
 * Allocates a buffer of size 'intBytes' and populates the buffer with cryptographically random bytes.
 * @param {Number} intBytes - The number of random bytes to generate.
 * @return {Buffer} Returns a nodeJS Buffer of length 'intBytes' on success. Returns null on error.
 */
CryptoAbstract.prototype.getRandomValues = function(intBytes) {
    try{
        let buff = Buffer.alloc(intBytes);
        if(this.mode === 'nodejs'){
            return new Promise((resolve, reject) => {
                this.crypto.randomBytes(intBytes, (err, buff) => {
                    if(err){
                        reject(err);
                    }
                    else{
                        resolve(Buffer.from(buff));
                    }
                });
            });
        }
        else if(this.mode === 'forge'){
            return Promise.resolve(Buffer.from(this.crypto.random.getBytesSync(intBytes), 'binary'));
        }
        else if(this.mode === 'sjcl'){
            return Promise.resolve(Buffer.from(this.crypto.random.randomWords(intBytes, 0)));
        }
        else if(this.mode === 'browser'){
            return Promise.resolve(this.crypto.getRandomValues(buff));
        }
        else{
            logger.log(UNSUPPORTEDCRYPTO, MODULENAME);
            throw new Error(UNSUPPORTEDCRYPTO);
        }
    }
    catch(objErr){
        logger.log(objErr.message, MODULENAME);
        return Promise.reject(objErr);
    }
};

/**
 * Hash data using the supplied algorithm.
 * @param {object} objParams Object containing the params.
 * @param {string} algorithm The hash algorithm to use. Supported algorithms are 'SHA-256'.
 * @param {object} data The data to hash.
 * @return {Promise} Returns a Promise. Resolves to a hex string representing the hash. Rejects with an error message.
 */
CryptoAbstract.prototype.digest = function(
    { algorithm = required("algorithm"), data = required("data") } = required(
        "Digest param object"
    )
) {
    return new Promise((resolve, reject) => {
        if (this.mode === "nodejs") {
            if (algorithm.toLowerCase() === "sha-256") {
                let hash = this.crypto.createHash('sha256');
                hash.update(data);
                resolve(hash.digest('hex'));
            }
        } else if (this.mode === "forge") {
            if (algorithm.toLowerCase() === "sha-256") {
                let md = this.crypto.md.sha256.create();
                md.update(data);
                resolve(md.digest().toHex());
            }
        } else if (this.mode === "browser") {
            this.crypto.subtle
                .digest(algorithm.toUpperCase(), Buffer.from(data))
                .then(arrayBufferHashed => {
                    resolve(Buffer.from(arrayBufferHashed).toString("hex"));
                })
                .catch(err => {
                    reject(err);
                });
        } else {
            logger.log(UNSUPPORTEDCRYPTO, MODULENAME);
            reject(UNSUPPORTEDCRYPTO);
        }
    });
};

/**
 * Sign data using the supplied algorithm.
 * @param {object} objParams Object containing the params.
 * @param {string} algorithm The hash algorithm to use. Supported algorithms are 'RSA-PSS'.
 * @param {Buffer} data A nodeJS Buffer containing data to be signed.
 * @param {Buffer} key The private key. The format can vary based on crypto implementation that is being used.
 * @return {Promise} Returns a Promise. Resolves to a nodeJS Buffer representing the signature. Rejects with an error message.
 */
CryptoAbstract.prototype.sign = function(
    {
        algorithm = required("algorithm"),
        data = required("data"),
        key = required("key")
    } = required("Sign param object")
) {
    return new Promise((resolve, reject) => {
        if (this.mode === "forge") {
            if (algorithm.toLowerCase() === "rsa-pss") {
                let md = this.crypto.md.sha256.create();
                md.update(data.toString("utf-8"), "utf8");
                let pss = this.crypto.pss.create({
                    md: this.crypto.md.sha256.create(),
                    mgf: this.crypto.mgf.mgf1.create(
                        this.crypto.md.sha256.create()
                    ),
                    saltLength: 32
                });
                resolve(new Buffer(key.sign(md, pss), "binary"));
            }
            else if (algorithm.toLowerCase() === "hmac-sha-256") {
                let hmac = this.crypto.hmac.create();
                hmac.start('sha256', key.toString());
                hmac.update(data);
                resolve(Buffer.from(hmac.digest().toHex(), 'hex'));
            }            
        } else if (this.mode === "browser") {
            let objAlgorithm = null;

            if (algorithm.toLowerCase() === "rsa-pss") {
                objAlgorithm = {
                    name: "RSA-PSS",
                    saltLength: 32
                };
            }
            else if (algorithm.toLowerCase() === "hmac-sha-256") {
                objAlgorithm = {
                    name: "HMAC"
                };
            }
            this.crypto.subtle
                .sign(objAlgorithm, key, data)
                .then(arrayBufferSignature => {
                    resolve(Buffer.from(arrayBufferSignature));
                })
                .catch(objErr => {
                    reject(objErr);
                });
        } else if (this.mode === 'nodejs') {
            if (algorithm.toLowerCase() === "hmac-sha-256") {
                let hmac = this.crypto.createHmac('sha256', key);
                hmac.update(data);
                resolve(Buffer.from(hmac.digest('hex'), 'hex'));
            }
        } else {
            logger.log(UNSUPPORTEDCRYPTO, MODULENAME);
            reject(UNSUPPORTEDCRYPTO);
        }
    });
};

/**
 * Generate a crypto key.
 * @param {object} objParams Object containing the params.
 * @param {Number} keySize The number of bits in the key. The default is 256. Not required for RSA key generation.
 * @param {string} algorithm The hash algorithm to use. Supported algorithms are 'AES-CTR' and 'RSA-PSS'.
 * @param {boolean} extractable Indicates whether the key can be extracted at a later stage. This param is required only when the crypto mode is 'browser'.
 * @param {Array} usages Indicates what can be done with the key. This param is required only when the crypto mode is 'browser'.
 * @return {Promise} Returns a Promise. Resolves to a nodeJS Buffer representing the generated crypto key. Rejects with an error message.
 */
CryptoAbstract.prototype.generateKey = function(
    {
        keySize = 256,
        algorithm = required("algorithm"),
        extractable = required("extractable"),
        usages = required("usages")
    } = required("generateKey parameter object")
) {
    return new Promise((resolve, reject) => {
        if (this.mode === "forge") {
            if (algorithm.toLowerCase() === "aes-ctr") {
                resolve(
                    new Buffer(
                        this.crypto.random.getBytesSync(keySize / 8),
                        "binary"
                    )
                );
            } else if (algorithm.toLowerCase() === "rsa-pss") {
                resolve(
                    this.crypto.pki.rsa.generateKeyPair({
                        bits: 3072,
                        workers: -1,
                        e: 0x10001
                    })
                );
            } else {
                return Promise.reject(
                    "unsupported generate key algorithm for forge crypto"
                );
            }
        } else if (this.mode === "browser") {
            let objAlgorithm = null;
            if (algorithm.toLowerCase() === "aes-ctr") {
                objAlgorithm = {
                    name: "AES-CTR",
                    length: keySize
                };
            } else if (algorithm.toLowerCase() === "rsa-pss") {
                objAlgorithm = {
                    name: "RSA-PSS",
                    modulusLength: 3072,
                    publicExponent: new Uint8Array([0x01, 0x00, 0x01]), // 24 bit representation of 65537
                    hash: {
                        name: "SHA-256"
                    }
                };
            }
            this.crypto.subtle
                .generateKey(
                    objAlgorithm,
                    extractable,
                    usages
                )
                .then(key => {
                    resolve(key);
                })
                .catch(objErr => {
                    logger.log("Failed to generate a " + algorithm + " key", MODULENAME);
                    reject(objErr);
                });
        } else {
            logger.log(UNSUPPORTEDCRYPTO, MODULENAME);
            reject(UNSUPPORTEDCRYPTO);
        }
    });
};

/**
 * Imports a generated crypto key into a format that the current crypto implementation can interpret.
 * @param {object} objParams Object containing the params.
 * @param {string} type The format the key is in. Possible values are 'spki' and 'raw'.
 * @param {Buffer} key The key to import as a nodeJS Buffer.
 * @param {string} algorithm The algorithm that the key will be used with. This param is required only when the crypto mode is 'browser'.
 * @param {boolean} extractable Indicates whether the key can be extracted at a later stage. This param is required only when the crypto mode is 'browser'.
 * @param {Array} usages Indicates what can be done with the key. This param is required only when the crypto mode is 'browser'.
 * @return {Promise} Returns a Promise. Resolves to a nodeJS Buffer representing the imported crypto key. Rejects with an error message.
 */
CryptoAbstract.prototype.importKey = function(
    {
        key = required("key"),
        algorithm = required("algorithm"),
        type = required("type"),
        extractable = required("extractable"),
        usages = required("usages")
    } = required("importKey parameter object")
) {
    return new Promise((resolve, reject) => {
        if (this.mode === "nodejs" || this.mode === "sjcl") {
            resolve(key);
        } else if (this.mode === "forge") {
            if (type.toLowerCase() === "spki") {
                resolve(
                    this.crypto.pki.publicKeyFromAsn1(
                        this.crypto.asn1.fromDer(
                            key.toString("binary")
                        )
                    )
                );
            } else {
                resolve(key);
            }
        } else if (this.mode === "browser") {
            if (algorithm.toLowerCase() === "rsa-oaep") {
                // use an object instead of a string
                algorithm = {
                    name: "RSA-OAEP",
                    hash: {
                        name: "SHA-1"
                    }
                };
            }
            else if (algorithm.toLowerCase() === 'hmac') {
                // use an object instead of a string
                algorithm = {
                    name: "HMAC",
                    hash: {
                        name: "SHA-256"
                    }
                };              
            }
            if (!detectIE()) {
                this.crypto.subtle
                    .importKey(
                        type,
                        key,
                        algorithm,
                        extractable,
                        usages
                    )
                    .then(bufferKeyOut => {
                        resolve(bufferKeyOut);
                    })
                    .catch(err => {
                        reject(err);
                    });
            } else {
                const keyObject = this.crypto.subtle.importKey(
                    type,
                    key,
                    algorithm,
                    extractable,
                    usages
                );
                keyObject.oncomplete = function(e) {
                    resolve(e);
                };
                keyObject.onerror = function(e) {
                    reject(e);
                };
            }
        } else {
            logger.log(UNSUPPORTEDCRYPTO, MODULENAME);
            reject(UNSUPPORTEDCRYPTO);
        }
    });
};

/**
 * Exports a generated crypto key into a format that the current crypto implementation can interpret.
 * @param {object} objParams Object containing the params.
 * @param {string} format The format to return the key in. Possible values are 'spki', 'pkcs8', and 'raw'.
 * @param {Buffer} key The key to import as a nodeJS Buffer.
 * @return {Promise} Returns a Promise. Resolves to a nodeJS Buffer representing the imported crypto key. Rejects with an error message.
 */
CryptoAbstract.prototype.exportKey = function(
    { format = required("format"), key = required("key") } = required(
        "exportKey parameter object"
    )
) {
    return new Promise((resolve, reject) => {
        if (this.mode === "forge") {
            if (format.toLowerCase() === "spki") {
                // convert a Forge public key to an ASN.1 SubjectPublicKeyInfo
                let subjectPublicKeyInfo = this.crypto.pki.publicKeyToAsn1(
                    key
                ); // 'bufferKeyIn' is actually a forge public key (not a nodeJS Buffer)
                let derBuffer = this.crypto.asn1.toDer(subjectPublicKeyInfo);
                resolve(new Buffer(derBuffer.getBytes(), "binary"));
            } else if (format.toLowerCase() === "pkcs8") {
                resolve(key); // already in a format that forge can interpret
            } else if (format.toLowerCase() === "raw") {
                resolve(key); // already in a format that forge can interpret
            }
        } else if (this.mode === "browser") {
            this.crypto.subtle
                .exportKey(format, key)
                .then(bufferKeyOut => {
                    resolve(Buffer.from(bufferKeyOut));
                })
                .catch(err => {
                    reject(err);
                });
        } else {
            logger.log(UNSUPPORTEDCRYPTO, MODULENAME);
            reject(UNSUPPORTEDCRYPTO);
        }
    });
};

/**
 * Encrypt data.
 * @param {object} objParams Object containing the params.
 * @param {Buffer} key The crypto key to use.
 * @param {Buffer} data The data to encrypt.
 * @param {Buffer} algorithm The encrypt algorithm to use.
 * @param {Buffer} iv The initialization vector.
 * @param {Buffer} additionalData The additional data. Do not pass this parameter for AES-CTR.
 * @param {Number} tagLength The tag length for AES-GCM. Size is in bits. Default is 128.
 * @param {Number} blockSize The block for AES-CTR only. Size is in bits. Default is 128.
 * @return {Promise} Returns a Promise. Resolves to a nodeJS Buffer representing the encrypted data. Rejects with an error message.
 */
CryptoAbstract.prototype.encrypt = function(
    {
        key = required("key"),
        data = required("data"),
        algorithm = required("algorithm"),
        iv = null,
        tagLength = 128,
        blockSize = 128,
        additionalData = null
    } = required("Encrypt parameter object")
) {
    return new Promise((resolve, reject) => {
        try {
            if (this.mode === "nodejs") {
                if (algorithm.toLowerCase() === "aes-ctr") {
                    let cipher = this.crypto.createCipheriv(
                        "aes-256-ctr",
                        key,
                        iv
                    );
                    let bufferEncrypted = cipher.update(Buffer.from(data));
                    let bufferEncryptedFinal = cipher.final();
                    if (bufferEncryptedFinal.length === 0) {
                        resolve(Buffer.from(bufferEncrypted));
                    } else {
                        resolve(
                            Buffer.concat([
                                Buffer.from(bufferEncrypted),
                                Buffer.from(bufferEncryptedFinal)
                            ])
                        );
                    }
                } else if (algorithm.toLowerCase() === "aes-gcm") {
                    let cipher = this.crypto.createCipheriv(
                        "aes-256-gcm",
                        key,
                        iv
                    );
                    let bufferEncrypted = cipher
                        .setAAD(additionalData)
                        .update(data);
                    let bufferEncryptedFinal = cipher.final();
                    let bufferAuthTag = cipher.getAuthTag();
                    if (bufferEncryptedFinal.length === 0) {
                        resolve(
                            Buffer.concat([
                                Buffer.from(bufferEncrypted),
                                Buffer.from(bufferAuthTag)
                            ])
                        );
                    } else {
                        resolve(
                            Buffer.concat([
                                Buffer.from(bufferEncrypted),
                                Buffer.from(bufferEncryptedFinal),
                                Buffer.from(bufferAuthTag)
                            ])
                        );
                    }
                } else {
                    reject(new Error("unsupported encrypt algorithm"));
                }
            } else if (this.mode === "forge") {
                if (algorithm.toLowerCase() === "aes-ctr") {
                    let cipher = this.crypto.cipher.createCipher(
                        "AES-CTR",
                        key.toString("binary")
                    );
                    cipher.start({ iv: iv.toString("binary") });
                    cipher.update(
                        this.crypto.util.createBuffer(data.toString("binary"))
                    );
                    cipher.finish();
                    resolve(new Buffer(cipher.output.getBytes(), "binary"));
                } else if (algorithm.toLowerCase() === "aes-gcm") {
                    let cipher = this.crypto.cipher.createCipher(
                        "AES-GCM",
                        key.toString("binary")
                    );
                    cipher.start({
                        iv: iv.toString("binary"),
                        additionalData: additionalData.toString("binary"),
                        tagLength: tagLength
                    });
                    cipher.update(
                        this.crypto.util.createBuffer(data.toString("binary"))
                    );
                    cipher.finish();
                    let encrypted = cipher.output.getBytes();
                    let tag = cipher.mode.tag.getBytes();

                    resolve(
                        Buffer.concat([
                            new Buffer(encrypted, "binary"),
                            new Buffer(tag, "binary")
                        ])
                    );
                } else if (algorithm.toLowerCase() === "rsa-oaep") {
                    // 'key' is actually a forge public key (not a nodeJS Buffer)
                    let encrypted = key.encrypt(
                        data.toString("binary"),
                        "RSA-OAEP",
                        {
                            md: this.crypto.md.sha1.create(),
                            mgf1: {
                                md: this.crypto.md.sha1.create()
                            }
                        }
                    );
                    resolve(new Buffer(encrypted, "binary"));
                } else {
                    reject(
                        new Error("unsupported algorithm for forge encrypt")
                    );
                }
            } else if (this.mode === "sjcl") {
                if (algorithm.toLowerCase() === "aes-gcm") {
                    let bitArrayKey = this.crypto.codec.hex.toBits(
                        key.toString("hex")
                    );
                     /*eslint-disable new-cap*/
                    let aesCipher = new this.crypto.cipher.aes(bitArrayKey);
                     /*eslint-enable new-cap*/
                    let bitArrayPlainTextData = this.crypto.codec.hex.toBits(
                        data.toString("hex")
                    );
                    let bitArrayIv = this.crypto.codec.hex.toBits(
                        iv.toString("hex")
                    );
                    let bitArrayAdditionalData = this.crypto.codec.hex.toBits(
                        additionalData.toString("hex")
                    );
                    let encrypted = this.crypto.mode["gcm"].encrypt(
                        aesCipher,
                        bitArrayPlainTextData,
                        bitArrayIv,
                        bitArrayAdditionalData
                    );
                    resolve(
                        Buffer.from(
                            this.crypto.codec.hex.fromBits(encrypted, true),
                            "hex"
                        )
                    ); // adding true to fromBits disables sjcl padding, this is important!!
                }
            } else if (this.mode === "browser") {
                let objAlgorithm = null;
                if (algorithm.toLowerCase() === "aes-ctr") {
                    objAlgorithm = {
                        name: "AES-CTR",
                        counter: iv,
                        length: blockSize
                    };
                } else if (algorithm.toLowerCase() === "aes-gcm") {
                    objAlgorithm = {
                        name: "AES-GCM",
                        iv: iv,
                        additionalData: additionalData,
                        tagLength: tagLength
                    };
                } else if (algorithm.toLowerCase() === "rsa-oaep") {
                    objAlgorithm = {
                        name: "RSA-OAEP"
                    };
                } else {
                    reject(new Error("unsupported decrypt algorithm"));
                    return;
                }
                if (!detectIE()) {
                    this.crypto.subtle
                        .encrypt(objAlgorithm, key, data)
                        .then(arrayBufferEncryptedData => {
                            resolve(Buffer.from(arrayBufferEncryptedData));
                        })
                        .catch(err => {
                            reject(err);
                        });
                } else {
                    var encData = this.crypto.subtle.encrypt(
                        objAlgorithm,
                        key,
                        data
                    );
                    encData.oncomplete(function(e) {
                        resolve(e);
                    });
                    encData.onerror(function(e) {
                        reject(e);
                    });
                }
            }
        } catch (objErr) {
            logger.log(objErr.message, MODULENAME);
            reject(objErr.message);
        }
    });
};

/**
 * Decrypt data.
 * @param {object} objParams Object containing the params.
 * @param {Buffer} key The crypto key to use.
 * @param {Buffer} data The data to decrypt.
 * @param {Buffer} algorithm The encrypt algorithm to use. Supported values are 'AES-CTR', 'AES-GCM', and 'RSA-OAEP'.
 * @param {Buffer} iv The initialization vector.
 * @param {Buffer} additionalData The additional data. Do not pass this parameter for AES-CTR.
 * @param {Number} tagLength The tag length for AES-GCM. Default is 128.
 * @param {Number} blockSize The block size for AES-CTR only. Default is 128.
 * @return {Promise} Returns a Promise. Resolves to a nodeJS Buffer representing the decrypted data. Rejects with an error message.
 */

CryptoAbstract.prototype.decrypt = function(
    {
        key = required("key"),
        data = required("data"),
        algorithm = required("algorithm"),
        iv = null,
        tagLength = 128,
        blockSize = 128,
        additionalData = null
    } = required("Decrypt parameter object")
) {
    return new Promise((resolve, reject) => {
        try {
            if (this.mode === "nodejs") {
                let decipher = null;
                let bufferDecrypted = null;
                let bufferDecryptedFinal = null;

                if (algorithm.toLowerCase() === "aes-ctr") {
                    decipher = this.crypto.createDecipheriv(
                        "aes-256-ctr",
                        key,
                        iv
                    );
                    bufferDecrypted = decipher.update(Buffer.from(data));
                    bufferDecryptedFinal = decipher.final();
                } else if (algorithm.toLowerCase() === "aes-gcm") {
                    decipher = this.crypto.createDecipheriv(
                        "aes-256-gcm",
                        key,
                        iv
                    );
                    // slice off last 16 bytes of the cipher text to get the auth tag
                    var bufferAuthTag = data.slice(data.length - 16);
                    data = data.slice(0, data.length - 16);

                    bufferDecrypted = decipher
                        .setAuthTag(bufferAuthTag)
                        .setAAD(Buffer.from(additionalData))
                        .update(Buffer.from(data));
                    bufferDecryptedFinal = decipher.final();
                } else {
                    reject(new Error("unsupported decrypt algorithm"));
                    return;
                }

                if (bufferDecryptedFinal.length === 0) {
                    resolve(Buffer.from(bufferDecrypted));
                } else {
                    resolve(
                        Buffer.concat([
                            Buffer.from(bufferDecrypted),
                            Buffer.from(bufferDecryptedFinal)
                        ])
                    );
                }
            } else if (this.mode === "forge") {
                if (algorithm.toLowerCase() === "aes-gcm") {
                    let forgeBufferEncryptedData = this.crypto.util.createBuffer(
                        data.slice(0, data.length - 16).toString("binary")
                    );
                    let forgeBufferAuthTag = this.crypto.util.createBuffer(
                        data.slice(data.length - 16).toString("binary")
                    );
                    let decipher = this.crypto.cipher.createDecipher(
                        "AES-GCM",
                        key.toString("binary")
                    );
                    decipher.start({
                        iv: iv.toString("binary"),
                        additionalData: additionalData.toString("binary"),
                        tagLength: tagLength,
                        tag: forgeBufferAuthTag
                    });
                    decipher.update(forgeBufferEncryptedData);
                    let success = decipher.finish();
                    if (success) {
                        resolve(
                            new Buffer(decipher.output.getBytes(), "binary")
                        );
                    } else {
                        reject(
                            new Error("Failed to decrypt using forge AES-GCM")
                        );
                    }
                } else if (algorithm.toLowerCase() === "rsa-oaep") {
                    // 'key' is actually a forge private key (not a nodeJS Buffer)
                    let decrypted = key.decrypt(
                        data.toString("binary"),
                        "RSA-OAEP",
                        {
                            md: this.crypto.md.sha1.create(),
                            mgf1: {
                                md: this.crypto.md.sha1.create()
                            }
                        }
                    );
                    resolve(new Buffer(decrypted, "binary"));
                } else if (algorithm.toLowerCase() === "aes-ctr") {
                    let decipher = this.crypto.cipher.createDecipher(
                        "AES-CTR",
                        key.toString("binary")
                    );
                    decipher.start({ iv: iv.toString("binary") });
                    decipher.update(
                        this.crypto.util.createBuffer(data.toString("binary"))
                    );
                    let success = decipher.finish();
                    if (success) {
                        resolve(
                            new Buffer(decipher.output.getBytes(), "binary")
                        );
                    } else {
                        reject(
                            new Error("Failed to decrypt using forge AES-CTR")
                        );
                    }
                }
            } else if (this.mode === "sjcl") {
                let objAlgorithm = null;
                if (algorithm.toLowerCase() === "aes-gcm") {
                    let bitArrayKey = this.crypto.codec.hex.toBits(
                        key.toString("hex")
                    );
                    /*eslint-disable new-cap*/
                    let aesCipher = new this.crypto.cipher.aes(bitArrayKey);
                    /*eslint-enable new-cap*/
                    let bitArrayEncryptedData = this.crypto.codec.hex.toBits(
                        data.toString("hex")
                    );
                    let bitArrayIv = this.crypto.codec.hex.toBits(
                        iv.toString("hex")
                    );
                    let bitArrayAdditionalData = this.crypto.codec.hex.toBits(
                        additionalData.toString("hex")
                    );
                    let decrypted = this.crypto.mode["gcm"].decrypt(
                        aesCipher,
                        bitArrayEncryptedData,
                        bitArrayIv,
                        bitArrayAdditionalData
                    );
                    resolve(
                        Buffer.from(
                            this.crypto.codec.hex.fromBits(decrypted, true),
                            "hex"
                        )
                    ); // adding true to fromBits disables sjcl padding, this is important!!
                }
            } else if (this.mode === "browser") {
                let objAlgorithm = null;
                if (algorithm.toLowerCase() === "aes-ctr") {
                    objAlgorithm = {
                        name: "AES-CTR",
                        counter: iv,
                        length: blockSize
                    };
                } else if (algorithm.toLowerCase() === "aes-gcm") {
                    objAlgorithm = {
                        name: "AES-GCM",
                        iv: iv,
                        additionalData: additionalData,
                        tagLength: tagLength
                    };
                } else if (algorithm.toLowerCase() === "rsa-oaep") {
                    objAlgorithm = {
                        name: "RSA-OAEP"
                    };
                } else {
                    reject(new Error("unsupported decrypt algorithm"));
                    return;
                }

                if (!detectIE()) {
                    this.crypto.subtle
                        .decrypt(objAlgorithm, key, data)
                        .then(arrayBufferDecryptedData => {
                            resolve(Buffer.from(arrayBufferDecryptedData));
                        })
                        .catch(e => {
                            reject(e);
                        });
                } else {
                    var encData = this.crypto.subtle.decrypt(
                        objAlgorithm,
                        key,
                        data
                    );
                    encData.oncomplete(function(e) {
                        resolve(e);
                    });
                    encData.onerror(function(e) {
                        reject(e);
                    });
                }
            }
        } catch (err) {
            reject(err);
        }
    });
};

module.exports = new CryptoAbstract();

function required(param) {
    throw new Error(
        "Missing required parameter: " + param
    );
}
