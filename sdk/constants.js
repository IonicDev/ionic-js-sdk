/* 
 * Copyright 2018 Ionic Security Inc.
 * By using this code, I agree to the Terms & Conditions (https://dev.ionic.com/use.html)
 * and the Privacy Policy (https://www.ionic.com/privacy-notice/).
 */

const strings = {
    IONIC_PROFILES_LOCAL_STORAGE_NAME: 'ionic_security_device_profiles',
    ERROR_NO_PROFILES_AVAILABLE: 'No Ionic device profiles available.',
    ERROR_NOT_REGISTERED_FOR_KEYSPACE : 'No profile available to handle key request.',
    INVALID_ARGUMENT_FOR_KEY_IDS: 'A "keyIds" argument of type Array must be passed with argument object.',
    INVALID_ARGUMENT_FOR_KEY_FORMAT: 'Supported key formats are "hex", "base64", "utf-8", or "ascii".',
    INVALID_ARGUMENT_FOR_KEY_QUANTITY: 'Key create quantity must be between 1 and 1000 keys.',
    INVALID_ARGUMENT_FOR_KEY_ENCODING: 'Invalid key encoding format.',
    INVALID_ARGUMENT_FOR_REFERENCE: 'Invalid key reference identifier.',
    INVALID_ARGUMENT_FOR_CHUNK_ENCRYPTION: 'A "stringData" argument must be passed with argument object.',
    
    //error messages for postMessage verification checks
    INVALID_EVENT_ORIGIN: 'Missing required parameter "origin" of type "string".',
    INVALID_MSG_ORIGIN: 'Message "data.origin" doesn\'t match the postMessage event origin.',
    INVALID_MSG_DATA: 'Missing required parameter "data" of type "object".',
    INVALID_MSG_MESSAGE: 'Missing required parameter "message" of type "object".',
    INVALID_MSG_ACTION: 'Missing required parameter "message.action" of type "string".',
    INVALID_MSG_VERSION: 'Missing required parameter "version" of type "string".',
    INVALID_MSG_VERSION_STRING: 'The loaded SDK does not support this message version. Supported versions are: ',
    INVALID_MSG_ID: 'Missing required parameter "id" of "number" type.',
    
    INVALID_CIPHER: 'The cipher selected is not supported.',
    INVALID_ARGUMENT_FOR_FORCE_FLAG: 'Invalid parameter type - "Force" must be a boolean.',
    MISSING_ARGUMENTS_FOR_KEY_UPDATE: 'Either "Force" OR "PrevMsig" and "PrevCsig" parameters must be specified.',
    
    // key request string constants
    FORCE_POSTFIX: ':force',
    MUTABLE_PREFIX: 'm:',
    DEFAULT_KEY_REF: 'default',

    //semantic versioning range
    //https://docs.npmjs.com/misc/semver
    SUPPORTED_VERSIONS: '>=0.2.0',

    // **** UPDATE THIS**** anytime the release 
    //version or URL changes!!
    // major.minor.patch
    SDK_VERSION: '2.0.0',
    SDK_BUNDLE_NAME: 'sdk.bundle.js',

    ENROLLMENT_ATTEMPT: 'IonicEnrollmentAttempt'
};

const numbers = {
    DEFAULT_MESSAGE_TIMEOUT : 60000

};

const errorcodes = {
    CHUNK_ERROR: 20001,

    UNKNOWN: 40002,
    MISSING_VALUE: 40004,
    INVALID_VALUE: 40005,
    REQUEST_FAILED: 40009,
    PARSE_FAILED: 40010,
    BAD_REQUEST: 40014,
    BAD_RESPONSE: 40015,
    NOT_IMPLEMENTED: 40018,
    TIMEOUT: 40020,
    NO_DEVICE_PROFILE: 40022,
    KEY_DENIED: 40024,
    STALE_KEY_ATTRIBUTES: 40031,

    KEY_VALIDATION_FAILURE: 50007,
    CRYPTO_ERROR: 50001,
    INVALID_KEY: 40030
};

const errormessages = {
  CHUNK_ERROR: "A general error occurred, but its specific problem is not represented with its own code.",
  MISSING_VALUE: "An expected and required value was not found.",
  INVALID_VALUE: "A value was found that is invalid.",
  REQUEST_FAILED: "A network request failed.",
  PARSE_FAILED: "Failed to parse serialized data.",
  BAD_REQUEST: "The request object is invalid.",
  BAD_RESPONSE: "Invalid response object received from server.",
  NOT_IMPLEMENTED:"Function (or dependent function) is not implemented.",
  TIMEOUT:"Operation timed out.",
  NO_DEVICE_PROFILE:"No active device profile is set.",
  KEY_DENIED:"Key fetch or creation was denied by the server.",
  KEY_VALIDATION_FAILURE:"",
  CRYPTO_ERROR:"",
  INVALID_KEY:"A key is invalid in some way (key ID, key length, etc).",
  STALE_KEY_ATTRIBUTES: "",
  UNKNOWN: "Unknown error"
};

const errorMap = {
    4020: { sdkResponseCode: errorcodes.KEY_DENIED, error: errormessages.KEY_DENIED },
    4202: { sdkResponseCode: errorcodes.STALE_KEY_ATTRIBUTES, Error: errormessages.STALE_KEY_ATTRIBUTES },
    409: { sdkResponseCode: errorcodes.STALE_KEY_ATTRIBUTES, Error: errormessages.STALE_KEY_ATTRIBUTES }

};

module.exports = {
    STRINGS: strings,
    NUMBERS: numbers,
    ERRCODE: errorcodes,
    ERRMSG: errormessages,
    ERRMAP: errorMap
};
