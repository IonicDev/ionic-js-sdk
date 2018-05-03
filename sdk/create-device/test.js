// selenium webdriver setup
let ionicRegAttempt = require('../../spec/ionic_reg_attempt.js');
let webdriver = require('selenium-webdriver');
let {ERRMSG, ERRCODE, STRINGS} = require('../constants.js');
let By = webdriver.By;
let until = webdriver.until;

jasmine.DEFAULT_TIMEOUT_INTERVAL = 30000;

describe("Ionic JS SDK Test - createDevice", function() {
    it("Should redirect to success url when registration succeeds.", function(done) {

        let driver = new webdriver.Builder()
            .forBrowser('chrome')
            .build();

        driver.manage().timeouts().pageLoadTimeout(10000) // wait no longer than 10 secs for page to load (connection over VPN and slow wifi)
        .then(() => {
            return driver.manage().timeouts().setScriptTimeout(10000); // wait no longer than 10 secs for callback to get executed
        })
        .then(() => {
            driver.get('https://sdk.in.ionicsecurity.com/0.0.10')
        })
        .then(() => {
            return driver.executeAsyncScript(function(localStorageKey, regAttempt, callback){
                window.localStorage.setItem(localStorageKey, regAttempt);
                callback('');
            }, STRINGS.ENROLLMENT_ATTEMPT, JSON.stringify(ionicRegAttempt));
        }, () => { console.error("Failed to set SEP"); })
        .then(() => {
            // go to registration page
            return driver.get('https://sdk.in.ionicsecurity.com:8081/keyspace/D7GH/register');
        })
        .then(() => {
            var userInput = driver.findElement(By.id('user'));
            var passwordInput = driver.findElement(By.id('password'));

            userInput.sendKeys('testuser@ionic.com');
            passwordInput.sendKeys('Testpassw0rd');

            return driver.findElement(By.id('sendtoken')).click();
        })
        .then(() => {
            return driver.wait(until.urlIs('https://sdk.in.ionicsecurity.com:8081/keyspace/D7GH/static/success.html'));
        })
        .then(() => {
            done();
        })        
        .catch((err) => {
            fail(err);
        });

        driver.quit(); 
    });
});
