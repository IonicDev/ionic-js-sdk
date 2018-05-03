let ionicSep = require('../../spec/ionic_sep.js');
let {ERRMSG, ERRCODE, STRINGS} = require('../constants.js');
let path = require('path');

// selenium webdriver setup
let webdriver = require('selenium-webdriver');
let By = webdriver.By;
let until = webdriver.until;

const expectedProfiles = {
    "sdkResponseCode":0,
    "profiles":[{
        "active":false,
        "created":"Thu Jan 18 2018 01:22:32 GMT-0500 (EST)",
        "deviceId":"D7GH.6.5cb1d370-8534-4188-aa93-0fb6c87b76a6",
        "server":"https://mastereng-api.in.ionicsecurity.com",
        "keyspace":"D7GH"
        },{
        "active":true,
        "created":"Wed Feb 21 2018 11:23:16 GMT-0500 (EST)",
        "deviceId":"D7GH.6.ce375612-d09f-495f-a71b-4cbd8f96dc91",
        "server":"https://mastereng-api.in.ionicsecurity.com",
        "keyspace":"D7GH"
        }
    ]
};

describe("Ionic JS SDK Test - createKeys", function() {

    it("Should validate input parameters.", function(done) {
        var driver = new webdriver.Builder()
        .forBrowser('chrome')
        .build();

        let sdk;
        driver.manage().timeouts().setScriptTimeout(10000); // wait no longer than 10 secs for callback to get executed
        // ensure profile exists
        driver.get('https://sdk.in.ionicsecurity.com/0.0.10')
        .then(() => {
            return driver.executeAsyncScript(function(sep, callback){
                window.localStorage.setItem('ionic_security_device_profiles', sep);
                currSep = window.localStorage.getItem('ionic_security_device_profiles');
                callback(currSep);
            }, JSON.stringify(ionicSep));
        })
        .then((currSep) => {
            expect(currSep).toBeTruthy();
            expect(currSep).toEqual(JSON.stringify(ionicSep));
            return driver.get("https://sdk.in.ionicsecurity.com:8043");
        })
        .then(() => {
            return driver.executeAsyncScript(function(callback){
                sdk = new IonicSdk.ISAgent("https://sdk.in.ionicsecurity.com/0.0.10");
                sdk.setActiveProfile({ 
                  "appId":"testapp", 
                  "userId":"testuser", 
                  "userAuth":"testuserauth", 
                  "deviceId":"D7GH.6.5cb1d370-8534-4188-aa93-0fb6c87b76a6"
                }).then(() => {
                    sdk.createKeys({
                        quantity:1, 
                        ref: "reference"
                    }).then(function(objResponse){
                        callback(objResponse);
                    });
                })
            })
            .then((objResponse) => {
                expect(objResponse['sdkResponseCode']).toBe(0); // 0 is success
                expect(objResponse.keys[0].key).toBeTruthy();
            });
        })
        .then(() => {
            //"Should fail if quantity is invalid
            return driver.executeAsyncScript(function(callback){
                sdk.createKeys({
                    quantity:1001,
                    encoding: "hex"
                }).catch((objRes) => {
                    callback(objRes);
                });
            })
            .then((objResponse) => {
                expect(objResponse['sdkResponseCode']).toBe(ERRCODE.BAD_REQUEST); // should be an Ionic defined error code
                expect(objResponse['error']).toBe(ERRMSG.BAD_REQUEST+" "+STRINGS.INVALID_ARGUMENT_FOR_KEY_QUANTITY);
            });
        })
        .then(() => {
            //"Should fail if quantity is invalid
            return driver.executeAsyncScript(function(callback){
                sdk.createKeys({}).catch((objRes) => {
                    callback(objRes);
                });
            })
            .then((objResponse) => {
                expect(objResponse['sdkResponseCode']).toBe(ERRCODE.BAD_REQUEST); // should be an Ionic defined error code
                expect(objResponse['error']).toBe(ERRMSG.BAD_REQUEST+" "+STRINGS.INVALID_ARGUMENT_FOR_KEY_QUANTITY);
            });
        })
        .then(() => {
            //"Should fail if quantity is invalid
            return driver.executeAsyncScript(function(callback){
                sdk.createKeys({
                    quantity:"something",
                    encoding:"hex"
                }).catch((objRes) => {
                    callback(objRes);
                });
            })
            .then((objResponse) => {
                expect(objResponse['sdkResponseCode']).toBe(ERRCODE.BAD_REQUEST); // should be an Ionic defined error code
                expect(objResponse['error']).toBe(ERRMSG.BAD_REQUEST+" "+ STRINGS.INVALID_ARGUMENT_FOR_KEY_QUANTITY);
            });
        })
        .then(() => {
            //"Should fail if encoding is invalid
            return driver.executeAsyncScript(function(callback){
                sdk.createKeys({
                    quantity:1,
                    encoding:"invalidenc"
                }).catch((objRes) => {
                    callback(objRes);
                });
            })
            .then((objResponse) => {
                expect(objResponse['sdkResponseCode']).toBe(ERRCODE.BAD_REQUEST); // should be an Ionic defined error code
                expect(objResponse['error']).toBe(ERRMSG.BAD_REQUEST+" "+ STRINGS.INVALID_ARGUMENT_FOR_KEY_ENCODING);
            });
        })
        .then(() => {
            //"Should fail if encoding is invalid
            return driver.executeAsyncScript(function(callback){
                sdk.createKeys({
                    quantity:1,
                    encoding:5
                }).catch((objRes) => {
                    callback(objRes);
                });
            })
            .then((objResponse) => {
                expect(objResponse['sdkResponseCode']).toBe(ERRCODE.BAD_REQUEST); // should be an Ionic defined error code
                expect(objResponse['error']).toBe(ERRMSG.BAD_REQUEST+" "+ STRINGS.INVALID_ARGUMENT_FOR_KEY_ENCODING);
            });
        })
        .then(() => {
            //"Should fail if reference is invalid
            return driver.executeAsyncScript(function(callback){
                sdk.createKeys({
                    quantity:1,
                    ref:{}
                }).catch((objRes) => {
                    callback(objRes);
                });
            })
            .then((objResponse) => {
                expect(objResponse['sdkResponseCode']).toBe(ERRCODE.BAD_REQUEST); // should be an Ionic defined error code
                expect(objResponse['error']).toBe(ERRMSG.BAD_REQUEST+" "+ STRINGS.INVALID_ARGUMENT_FOR_REFERENCE);
            });
        })
        .then(() => {
            driver.quit();
            done();
        })
        .catch((err) => {
            driver.quit();
            fail(err);
        });
    }); 

    it("Should fail when the device is disabled.", function(done) {
        var driver = new webdriver.Builder()
        .forBrowser('chrome')
        .build();

        let sdk;
        driver.manage().timeouts().setScriptTimeout(10000); // wait no longer than 10 secs for callback to get executed
        // ensure profile exists
        driver.get('https://sdk.in.ionicsecurity.com/0.0.10')
        .then(() => {
            return driver.executeAsyncScript(function(sep, callback){
                window.localStorage.setItem('ionic_security_device_profiles', sep);
                currSep = window.localStorage.getItem('ionic_security_device_profiles');
                callback(currSep);
            }, JSON.stringify(ionicSep));
        })
        .then((currSep) => {
            expect(currSep).toBeTruthy();
            expect(currSep).toEqual(JSON.stringify(ionicSep));
            return driver.get("https://sdk.in.ionicsecurity.com:8043");
        })
        .then(() => {
            return driver.executeAsyncScript(function(callback){
                sdk = new IonicSdk.ISAgent("https://sdk.in.ionicsecurity.com/0.0.10");
                sdk.setActiveProfile({ 
                  "appId":"testapp", 
                  "userId":"testuser", 
                  "userAuth":"testuserauth", 
                  "deviceId":"D7GH.6.ce375612-d09f-495f-a71b-4cbd8f96dc91"
                }).then((res) => {
                    callback(res);
                });
            });
        })
        .then((res) => {
            expect(res).toBeTruthy();
            expect(res.profiles).toBeTruthy();
            expect(res).toEqual(expectedProfiles);
            return driver.executeAsyncScript(function(callback){
                sdk.createKeys().catch((objRes) => {
                    callback(objRes);
                });
            })
            .then((objResponse) => {
                expect(objResponse['sdkResponseCode']).toBe(ERRCODE.KEY_DENIED);
                expect(objResponse['error']).toBe(ERRMSG.KEY_DENIED + ' {"code":4020,"message":"Account is disabled"}');
            });
        })
        .then(() => {
            driver.quit();
            done();
        })
        .catch((err) => {
            driver.quit();
            fail(err);
        });
    }); 
    
});
