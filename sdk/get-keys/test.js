var ionicSep = require('../../spec/ionic_sep.js');
var {ERRMSG, ERRCODE, STRINGS} = require('../constants.js');
var path = require('path');

// selenium webdriver setup
var webdriver = require('selenium-webdriver');
var By = webdriver.By;
var until = webdriver.until;

jasmine.DEFAULT_TIMEOUT_INTERVAL = 30000;
describe("Ionic JS SDK Test - getKeys", function() {

    it("Should succeed when profile exists and correct arguments passed.", function(done) {
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
                callback('');
            }, JSON.stringify(ionicSep));
        })
        .then(() => {
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
                    sdk.getKeys({keyIds:['D7GH91pKrNM']}).then(function(objResponse){
                        callback(objResponse);
                    });
                });
            })
            .then((objResponse) => {
                expect(objResponse['sdkResponseCode']).toBe(0); // 0 is success
                expect(objResponse.keys[0].key).toBe('239e4505f13f431b8380fd6f3781ea0a4b5c8a8f327b343b60a7e259bd205d8a');
            });
        })
        .then(() => {
            //"Should fail if no arguments are supplied."
            return driver.executeAsyncScript(function(callback){
                        sdk.getKeys().catch((objRes) => {
                            callback(objRes);
                        });
            })
            .then((objResponse) => {
                expect(objResponse['sdkResponseCode']).toBe(ERRCODE.BAD_REQUEST); // should be an Ionic defined error code
                expect(objResponse['error']).toBe(ERRMSG.BAD_REQUEST);
            });
        })
        .then(() => {
            //"Should fail if first argument is not an array."
            return driver.executeAsyncScript(function(callback){
                sdk.getKeys({keyIds:'D7GH91pKrNM'}).catch((objRes) => {
                    callback(objRes);
                });
            })
            .then((objResponse) => {
                expect(objResponse['sdkResponseCode']).toBe(ERRCODE.BAD_REQUEST); // should be an Ionic defined error code
                expect(objResponse['error']).toBe(ERRMSG.BAD_REQUEST + " " + STRINGS.INVALID_ARGUMENT_FOR_KEY_IDS);
            });
        })
        .then(() => {
            // no matching keys returned results in key denied error
            return driver.executeAsyncScript(function(callback){
                sdk.getKeys({keyIds:['D7dskjgkjgGH91pKrNM']}).catch((objRes) => {
                    callback(objRes);
                });
            })
            .then((objResponse) => {
                expect(objResponse['sdkResponseCode']).toBe(ERRCODE.KEY_DENIED); // should be an Ionic defined error code
                expect(objResponse['error']).toBe(ERRMSG.KEY_DENIED);
            });
        })
        .then(() => {
            //Should succeed when metadata is specified
            return driver.executeAsyncScript(function(callback){
                sdk.getKeys({
                    keyIds:['D7GH9T9ztKs'], 
                    encoding:'hex', 
                    "metadata": {
                        "ionic-application-name": "Javascript SDK",
                        "ionic-application-version": "1.0"
                    }
                }).then((objRes) => {
                    callback(objRes);
                });
            })
            .then((objResponse) => {
                expect(objResponse['sdkResponseCode']).toBe(0); // 0 is success
                expect(objResponse.keys[0].key).toBe("219613f1e8d87976e57014a1441a5ddaaba2d9abb30ef8504a99f12e599a89c4");
            });
        })
        .then(() => {
          //Should fail (relies on 'deny' policy defined for this application name)
            return driver.executeAsyncScript(function(callback){
                sdk.getKeys({
                    keyIds:['D7GH9T9ztKs'], 
                    metadata: {
                        "ionic-application-name": "Javascript SDK",
                        "ionic-application-version": "1.1"
                    }
                }).catch((objRes) => {
                    callback(objRes);
                });
            })
            .then((objResponse) => {
                expect(objResponse['sdkResponseCode']).toBe(ERRCODE.KEY_DENIED);
                expect(objResponse['error']).toBe(ERRMSG.KEY_DENIED);
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
