### A Basic Ionic Application

This code sample demonstrates the core functionality of the Ionic JavaScript SDK.  Creating a user profile, encrypting, and decrypting a string -- all client-side.

`index.html`
~~~html
<html>
    <head>
        <title>Ionic Hello World</title>
    </head>
    <body>
        <script src='https://api.ionic.com/jssdk/latest/Libs/sdk.bundle.js'></script>
        <script src='index.js'></script>

        <p>Plaintext Input: <input id='fieldToEncrypt' type='text' value='Test'></p>
        <input type='button' class='button' onClick='encryptText()' value='Encrypt'>
        <p>Encrypted Text: <div id='encryptedText'></div></p>
        <input type='button' class='button' onClick='decryptText()' value='Decrypt'>
        <p>Decrypted Text: <div id='decryptedText'></div></p>
    </body>
</html>
~~~

`index.js`
~~~javascript
var init = funciton() {
    sdk = new window.IonicSdk.ISAgent();

    var appData =
    {
        appId: 'helloworld',
        userId: 'myuser',
        userAuth: 'password123',
        enrollmentUrl: 'https://someurl.ionic.com/keyspace/your-tenant-id/register'
    }
}

var register = function() {
    return sdk.enrollUser(appData)
    .then(resp => {
        if(resp)
            if (resp.Redirect) {
                window.open(resp.Redirect);
                return resp.Notifier;
            }
        else {
            return Promise.reject("Error enrolling");
        }
    });
}

var loadProfile = function() {
    return sdk.loadUser(appData)
    .then(res => {
        return Promise.resolve();
    })
    .catch(err => {
        if (
            err &&
            err.sdkResponseCode &&
            (err.sdkResponseCode === 40022 || err.sdkResponseCode === 40002)
        ) {
            return register();
        }
    });
}

var encryptText = function(){
    var data = document.getElementById('fieldToEncrypt').value;
    sdk.encryptStringChunkCipher({stringData: data, cipher: 'v2'})
    .then(res => {
        document.getElementById('encryptedText').innerText = res.stringChunk;
    })
    .catch(err => {
        console.log('err: ', err);
    });
}

var decryptText = function(){
    var data = document.getElementById('encryptedText').innerText;

    sdk.decryptStringChunkCipher({stringData: data})
    .then(res => {
        document.getElementById('decryptedText').innerText = res.stringChunk;
    });
}

init();
loadProfile();
~~~

The easist way to run the sample is with [http-server](https://www.npmjs.com/package/http-server). 
This tool will turn your current directory into a static server.

~~~bash
npm install -g http-server
http-server .
~~~

Then open your Chrome browser and navigate to http://127.0.0.1:8080