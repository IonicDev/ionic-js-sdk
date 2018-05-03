let webdriver = require('selenium-webdriver');
let {ERRCODE, STRINGS} = require('../constants.js');
let messageHandler  = require('./SendMessage.js');
jasmine.DEFAULT_TIMEOUT_INTERVAL = 30000;
const SDK_URL= 'https://sdk.in.ionicsecurity.com/0.0.10';
const SDK_ORIGIN= 'https://sdk.in.ionicsecurity.com';
const APP_URL = 'https://sdk.in.ionicsecurity.com:8043';

describe("Ionic JS SDK Test - message tests", function() {


    it("Should return SDK error for invalid 'action' parameter", function(done) {
        let driver = new webdriver.Builder()
            .forBrowser('chrome')
            .build();

        driver.get(APP_URL)
        .then(() => {

            return driver.executeAsyncScript(function(sdkUrl, expectedSdkOrigin, callback){
                //this call results in the SDK iFrame being added to the page
                const sdk = new IonicSdk.ISAgent(sdkUrl);
                if (!sdk){
                    callback(new Error("SDK must be initialized at this point"));
                }

                window.addEventListener("message", function (e) {
                        callback({
                            "data": e.data,
                            "origin": e.origin
                        });
                    }, true);

                sdk.sdkFrame.onload = () => {
                    if (sdk.sdkOrigin !== expectedSdkOrigin) {
                        callback(new Error("Invalid SDK instance object: sdkOrigin="+sdk.sdkOrigin));
                    }

                    sdk.sdkFrame.contentWindow.postMessage({
                            id: 12345, 
                            version: '1.0.0', 
                            instance: 'blah', 
                            message: 'OKOK'
                        }, 
                        sdkUrl
                    );
                };
                
            }, SDK_URL, SDK_ORIGIN);
        })
        .then((res) => {
            expect(res).toBeTruthy();
            expect(res.origin).toBe(SDK_ORIGIN);
            expect(res.data).toBeTruthy();
            expect(res.data.version).toBe(STRINGS.SDK_VERSION);

            //verify SDK message contents
            expect(res.data.message).toBeTruthy();
            expect(res.data.message.sdkResponseCode).toBe(ERRCODE.INVALID_VALUE);
            expect(res.data.message.error).toBe(STRINGS.INVALID_MSG_ACTION);
            done();
        })
        .catch(err => {
            fail(err);
        });
        driver.quit();
    });

    it("Should return SDK error for invalid 'version' parameter", function(done) {
        let driver = new webdriver.Builder()
            .forBrowser('chrome')
            .build();

        driver.get(APP_URL)
        .then(() => {

            return driver.executeAsyncScript(function(sdkUrl, expectedSdkOrigin, callback){
                //this call results in the SDK iFrame being added to the page
                const sdk = new IonicSdk.ISAgent(sdkUrl);
                if (!sdk){
                    callback(new Error("SDK must be initialized at this point"));
                }

                window.addEventListener("message", function (e) {
                        callback({
                            "data": e.data,
                            "origin": e.origin
                        });
                    }, true);

                sdk.sdkFrame.onload = () => {
                    if (sdk.sdkOrigin !== expectedSdkOrigin) {
                        callback(new Error("Invalid SDK instance object: sdkOrigin="+sdk.sdkOrigin));
                    }

                    sdk.sdkFrame.contentWindow.postMessage({
                            action: "someaction",
                            id: 12345, 
                            version: 12345, 
                            instance: 'blah', 
                            message: 'OKOK'
                        }, 
                        sdkUrl
                    );
                };
                
            }, SDK_URL, SDK_ORIGIN);
        })
        .then((res) => {
            expect(res).toBeTruthy();
            expect(res.origin).toBe(SDK_ORIGIN);
            expect(res.data).toBeTruthy();
            expect(res.data.version).toBe(STRINGS.SDK_VERSION);

            //verify SDK message contents
            expect(res.data.message).toBeTruthy();
            expect(res.data.message.sdkResponseCode).toBe(ERRCODE.INVALID_VALUE);
            expect(res.data.message.error).toBe(STRINGS.INVALID_MSG_VERSION);
            done();
        })
        .catch(err => {
            fail(err);
        });
        driver.quit();
    });

    it("Should return SDK error for unsupported 'version' parameter", function(done) {
        let driver = new webdriver.Builder()
            .forBrowser('chrome')
            .build();

        driver.get(APP_URL)
        .then(() => {

            return driver.executeAsyncScript(function(sdkUrl, expectedSdkOrigin, callback){
                //this call results in the SDK iFrame being added to the page
                const sdk = new IonicSdk.ISAgent(sdkUrl);
                if (!sdk){
                    callback(new Error("SDK must be initialized at this point"));
                }

                window.addEventListener("message", function (e) {
                        callback({
                            "data": e.data,
                            "origin": e.origin
                        });
                    }, true);

                sdk.sdkFrame.onload = () => {
                    if (sdk.sdkOrigin !== expectedSdkOrigin) {
                        callback(new Error("Invalid SDK instance object: sdkOrigin="+sdk.sdkOrigin));
                    }

                    sdk.sdkFrame.contentWindow.postMessage({
                            action: "someaction",
                            id: 12345, 
                            version: '0.1.0', 
                            instance: 'blah', 
                            message: 'OKOK'
                        }, 
                        sdkUrl
                    );
                };
                
            }, SDK_URL, SDK_ORIGIN);
        })
        .then((res) => {
            expect(res).toBeTruthy();
            expect(res.origin).toBe(SDK_ORIGIN);
            expect(res.data).toBeTruthy();
            expect(res.data.version).toBe(STRINGS.SDK_VERSION);

            //verify SDK message contents
            expect(res.data.message).toBeTruthy();
            expect(res.data.message.sdkResponseCode).toBe(ERRCODE.INVALID_VALUE);
            expect(res.data.message.error).toBe(STRINGS.INVALID_MSG_VERSION_STRING
                +STRINGS.SUPPORTED_VERSIONS);
            done();
        })
        .catch(err => {
            fail(err);
        });
        driver.quit();
    });

    it("Should return SDK error for invalid 'id' parameter", function(done) {
        let driver = new webdriver.Builder()
            .forBrowser('chrome')
            .build();

        driver.get(APP_URL)
        .then(() => {

            return driver.executeAsyncScript(function(sdkUrl, expectedSdkOrigin, callback){
                //this call results in the SDK iFrame being added to the page
                const sdk = new IonicSdk.ISAgent(sdkUrl);
                if (!sdk){
                    callback(new Error("SDK must be initialized at this point"));
                }

                window.addEventListener("message", function (e) {
                        callback({
                            "data": e.data,
                            "origin": e.origin
                        });
                    }, true);

                sdk.sdkFrame.onload = () => {
                    if (sdk.sdkOrigin !== expectedSdkOrigin) {
                        callback(new Error("Invalid SDK instance object: sdkOrigin="+sdk.sdkOrigin));
                    }

                    sdk.sdkFrame.contentWindow.postMessage({
                            action: "someaction",
                            id: "ajdkgjadlksgj", 
                            version: '0.2.0', 
                            instance: 'blah', 
                            message: 'OKOK'
                        }, 
                        sdkUrl
                    );
                };
                
            }, SDK_URL, SDK_ORIGIN);
        })
        .then((res) => {
            expect(res).toBeTruthy();
            expect(res.origin).toBe(SDK_ORIGIN);
            expect(res.data).toBeTruthy();
            expect(res.data.version).toBe(STRINGS.SDK_VERSION);

            //verify SDK message contents
            expect(res.data.message).toBeTruthy();
            expect(res.data.message.sdkResponseCode).toBe(ERRCODE.INVALID_VALUE);
            expect(res.data.message.error).toBe(STRINGS.INVALID_MSG_ID);
            done();
        })
        .catch(err => {
            fail(err);
        });
        driver.quit();
    });

    it("Should return SDK error for invalid 'origin' parameter", function(done) {
        let driver = new webdriver.Builder()
            .forBrowser('chrome')
            .build();

        driver.get(APP_URL)
        .then(() => {

            return driver.executeAsyncScript(function(sdkUrl, expectedSdkOrigin, callback){
                //this call results in the SDK iFrame being added to the page
                const sdk = new IonicSdk.ISAgent(sdkUrl);
                if (!sdk){
                    callback(new Error("SDK must be initialized at this point"));
                }

                window.addEventListener("message", function (e) {
                        callback({
                            "data": e.data,
                            "origin": e.origin
                        });
                    }, true);

                sdk.sdkFrame.onload = () => {
                    if (sdk.sdkOrigin !== expectedSdkOrigin) {
                        callback(new Error("Invalid SDK instance object: sdkOrigin="+sdk.sdkOrigin));
                    }

                    sdk.sdkFrame.contentWindow.postMessage({
                            action: "someaction",
                            id: 123, 
                            version: '0.2.0', 
                            instance: 'blah', 
                            message: 'OKOK',
                            origin: 'https://some.other.origin.com'
                        }, 
                        sdkUrl
                    );
                };
                
            }, SDK_URL, SDK_ORIGIN);
        })
        .then((res) => {
            expect(res).toBeTruthy();
            expect(res.origin).toBe(SDK_ORIGIN);
            expect(res.data).toBeTruthy();
            expect(res.data.version).toBe(STRINGS.SDK_VERSION);

            //verify SDK message contents
            expect(res.data.message).toBeTruthy();
            expect(res.data.message.sdkResponseCode).toBe(ERRCODE.INVALID_VALUE);
            expect(res.data.message.error).toBe(STRINGS.INVALID_MSG_ORIGIN);
            done();
        })
        .catch(err => {
            fail(err);
        });
        driver.quit();
    });
});

describe("Ionic JS SDK Test - ISAgent initialization test", function() {
    it("Should dynamically determine the location for hosted internal SDK", function(done) {
        let driver = new webdriver.Builder()
            .forBrowser('chrome')
            .build();

        driver.get(APP_URL)
        .then(() => {

            return driver.executeAsyncScript(function(callback){
                // the default/empty constructor looks for loaded script "sdk.bundle.js"
                // and uses its location to determine the iframe source
                const sdk = new IonicSdk.ISAgent();
                if (!sdk){
                    callback(new Error("SDK must be initialized at this point"));
                }

                sdk.sdkFrame.onload = () => {
                    callback({
                        sdkOrigin: sdk.sdkOrigin,
                        sdkSource: sdk.sdkFrame.src
                    })
                };
            });
        })
        .then((res) => {
            expect(res).toBeTruthy();

            //verify that origin and iframe src URL were correctly identified
            expect(res.sdkOrigin).toBe(SDK_ORIGIN);
            expect(res.sdkSource).toBe(SDK_URL);

            done();
        })
        .catch(err => {
            fail(err);
        });
        driver.quit();
    });
});
