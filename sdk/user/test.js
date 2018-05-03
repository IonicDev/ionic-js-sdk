let webdriver = require('selenium-webdriver');
let {ERRMSG, ERRCODE, STRINGS} = require('../constants.js');
jasmine.DEFAULT_TIMEOUT_INTERVAL = 30000;

describe("Ionic JS SDK Test - queryProfiles tests", function() {

    //TODO differentiate between the more specific conditions
    // matching profile exists for appId and userId but userAuth isn't correct leading to decrypt failure
    // matching profile exists for app but not for userId
    // matching profile doesn't exist
    it("Should succeed even when no matching profiles exist", function(done) {
        let driver = new webdriver.Builder()
                .forBrowser('chrome')
                .build();
        
        driver.get('https://sdk.in.ionicsecurity.com:8043')
        .then(() => {
            return driver.executeAsyncScript(function(callback){
                const sdk = new IonicSdk.ISAgent("https://sdk.in.ionicsecurity.com/0.0.10");
                if (!sdk){
                    throw "SDK must be initialized at this point";
                }
                sdk.queryProfiles({ 
                  "appId":"testapp", 
                  "userId":"testuser", 
                  "userAuth":"akdjgaskjdgkjgdkgj" //invalid auth value - testing for profiles=[]
                }).then(res =>  {
                    callback(res);
                }).catch(err => {
                    callback(err);
                });
            });
        })
        .then((objResponse) => {
            expect(objResponse.sdkResponseCode).toBe(0); // 0 is success
            done();
        })
        .catch(err => {
            fail(err);
        });
        driver.quit();
    });

    it("Should fail given invalid/missing parameters", function(done) {
        let driver = new webdriver.Builder()
                .forBrowser('chrome')
                .build();
        
        driver.get('https://sdk.in.ionicsecurity.com:8043')
        .then(() => {
            return driver.executeAsyncScript(function(callback){
                const sdk = new IonicSdk.ISAgent("https://sdk.in.ionicsecurity.com/0.0.10");
                if (!sdk){
                    throw "SDK must be initialized at this point";
                }
                sdk.queryProfiles({ 
                  "appId":"testapp", 
                  "userId":"testuser"
                  //missing required param userAuth
                }).then(res =>  {
                    callback(res);
                }).catch(err => {
                    callback(err);
                });
            });
        })
        .then((objResponse) => {
            expect(objResponse.sdkResponseCode).toBe(ERRCODE.BAD_REQUEST);
            expect(objResponse.error).toBe(ERRMSG.BAD_REQUEST+" "+
                "Error: appId, userId, and userAuth are required parameters.");
            done();
        })
        .catch(err => {
            fail(err);
        });
        driver.quit();
    });
});

describe("Ionic JS SDK Test - loadUser tests", function() {

    //TODO differentiate between the more specific conditions
    // matching profile exists for appId and userId but userAuth isn't correct leading to decrypt failure
    // matching profile exists for app but not for userId
    // matching profile doesn't exist
    it("Should fail when the lookup fails", function(done) {
        let driver = new webdriver.Builder()
                .forBrowser('chrome')
                .build();
        
        driver.get('https://sdk.in.ionicsecurity.com:8043')
        .then(() => {
            return driver.executeAsyncScript(function(callback){
                const sdk = new IonicSdk.ISAgent("https://sdk.in.ionicsecurity.com/0.0.10");
                if (!sdk){
                    throw "SDK must be initialized at this point";
                }
                sdk.loadUser({ 
                  "appId":"testapp", 
                  "userId":"testuser", 
                  "userAuth":"akdjgaskjdgkjgdkgj" //invalid auth value - testing for profiles=[]
                }).then(res =>  {
                    callback(res);
                }).catch(err => {
                    callback(err);
                });
            });
        })
        .then((objResponse) => {
            expect(objResponse.sdkResponseCode).toBe(ERRCODE.NO_DEVICE_PROFILE);
            done();
        })
        .catch(err => {
            fail(err);
        });
        driver.quit();
    });

    it("Should fail given missing parameters", function(done) {
        let driver = new webdriver.Builder()
                .forBrowser('chrome')
                .build();
        
        driver.get('https://sdk.in.ionicsecurity.com:8043')
        .then(() => {
            return driver.executeAsyncScript(function(callback){
                const sdk = new IonicSdk.ISAgent("https://sdk.in.ionicsecurity.com/0.0.10");
                if (!sdk){
                    throw "SDK must be initialized at this point";
                }
                sdk.loadUser({ 
                  "appId":"testapp", 
                  "userAuth":"testuserauth"
                  //missing required param userId
                }).then(res =>  {
                    callback(res);
                }).catch(err => {
                    callback(err);
                });
            });
        })
        .then((objResponse) => {
            expect(objResponse.sdkResponseCode).toBe(ERRCODE.BAD_REQUEST);
            expect(objResponse.error).toBe(ERRMSG.BAD_REQUEST+" "+
                "Error: appId, userId, and userAuth are required parameters.");
            done();
        })
        .catch(err => {
            fail(err);
        });
        driver.quit();
    });
});

describe("Ionic JS SDK Test - setActiveProfile tests", function() {

    //TODO differentiate between the more specific conditions
    // matching profile exists for appId and userId but userAuth isn't correct leading to decrypt failure
    // matching profile exists for app but not for userId
    // matching profile doesn't exist
    it("Should fail when there is no matching profile", function(done) {
        let driver = new webdriver.Builder()
                .forBrowser('chrome')
                .build();
        
        driver.get('https://sdk.in.ionicsecurity.com:8043')
        .then(() => {
            return driver.executeAsyncScript(function(callback){
                const sdk = new IonicSdk.ISAgent("https://sdk.in.ionicsecurity.com/0.0.10");
                if (!sdk){
                    throw "SDK must be initialized at this point";
                }
                sdk.setActiveProfile({ 
                    "appId":    "testapp", 
                    "userId":   "testuser", 
                    "userAuth": "akdjgaskjdgkjgdkgj",//invalid auth value
                    "deviceId": "D7GH.6.64225248-f6c7-4825-983a-c62e1b0b5330"
                }).then(res =>  {
                    callback(res);
                }).catch(err => {
                    callback(err);
                });
            });
        })
        .then((objResponse) => {
            expect(objResponse.sdkResponseCode).toBe(ERRCODE.NO_DEVICE_PROFILE);
            expect(objResponse.error).toBe(ERRMSG.NO_DEVICE_PROFILE+ 
               " Missing a profile for the specified deviceId: "+
               "D7GH.6.64225248-f6c7-4825-983a-c62e1b0b5330");
            done();
        })
        .catch(err => {
            fail(err);
        });
        driver.quit();
    });

    it("Should fail given invalid/missing parameters", function(done) {
        let driver = new webdriver.Builder()
                .forBrowser('chrome')
                .build();
        
        driver.get('https://sdk.in.ionicsecurity.com:8043')
        .then(() => {
            return driver.executeAsyncScript(function(callback){
                const sdk = new IonicSdk.ISAgent("https://sdk.in.ionicsecurity.com/0.0.10");
                if (!sdk){
                    throw "SDK must be initialized at this point";
                }
                sdk.setActiveProfile({ 
                    "appId":"testapp", 
                    "userId":"testuser",
                    "userAuth": "akdjgaskjdgkjgdkgj"
                    //missing required param deviceId
                }).then(res =>  {
                    callback(res);
                }).catch(err => {
                    callback(err);
                });
            });
        })
        .then((objResponse) => {
            expect(objResponse.sdkResponseCode).toBe(ERRCODE.BAD_REQUEST);
            expect(objResponse.error).toBe(ERRMSG.BAD_REQUEST+" "+
                "Error: appId, userId, userAuth, and deviceId are required parameters.");
            done();
        })
        .catch(err => {
            fail(err);
        });
        driver.quit();
    });
});

describe("Ionic JS SDK Test - enrollUser tests", function() {
    //TODO 
    // test for CRYPTO_ERROR
    // test for MISSING_VALUE - invalid/missing enrollmentUrl
    it("Should fail given invalid/missing parameters", function(done) {
        let driver = new webdriver.Builder()
                .forBrowser('chrome')
                .build();
        
        driver.get('https://sdk.in.ionicsecurity.com:8043')
        .then(() => {
            return driver.executeAsyncScript(function(callback){
                const sdk = new IonicSdk.ISAgent("https://sdk.in.ionicsecurity.com/0.0.10");
                if (!sdk){
                    throw "SDK must be initialized at this point";
                }
                sdk.enrollUser({ 
                    "appId":"testapp", 
                    "userId":"testuser"
                    //missing required userAuth parameter
                }).then(res =>  {
                    callback(res);
                }).catch(err => {
                    callback(err);
                });
            });
        })
        .then((objResponse) => {
            expect(objResponse.sdkResponseCode).toBe(ERRCODE.BAD_REQUEST);
            expect(objResponse.error).toBe(ERRMSG.BAD_REQUEST+" "+
                "Error: appId, userId, and userAuth are required parameters.");
            done();
        })
        .catch(err => {
            fail(err);
        });
        driver.quit();
    }); 

});
