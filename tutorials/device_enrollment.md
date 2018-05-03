### Ionic Enrollment
In order for your application to communicate with Ionic, authenticate, and receive securely transferred keys, you must have an Ionic Profile.

Because browsers are sandboxed applications, the Profile needs to be created and saved inside the browser -- we will not be able to use profiles created with other tools or SDKs.
Ionic's Enrollment Service has tools built-in to use configured IdPs to handle the complexities of authentication and enrollment.

Profiles created for the JavaScript SDK are saved in the browser's [localStorage](https://developer.mozilla.org/en-US/docs/Web/API/Window/localStorage).

In the following example, device enrollment is initiated by calling [enrollUser()](./ISAgent.html#enrollUser).

If the user successfully authenticates with the Enrollment Service within the 10-minute timeout window, an enrollment profile is encrypted and stored in localStorage under the appId, userId, and the origin of the calling application. See [enrollUser](./ISAgent.html#enrollUser) API documentation for more information.

~~~javascript
var register = function() {
    return sdk.enrollUser({
        appId: 'helloworld',
        userId: 'myuser',
        userAuth: 'password123',
        enrollmentUrl: 'https://someurl.ionic.com/keyspace/your-tenant-id/register'
    }

    .then(resp => {
        if(resp)
            if (resp.redirect) {
                window.open(resp.redirect);
                return resp.Notifier;
            }
        else {
            return Promise.reject("Error enrolling");
        }
    });
}
~~~

Once a profile is stored, it persists in the browser's localStorage until it is cleared.  This way, the user only has to enroll once for each Ionic-enabled application.

The following example loads an existing profile for the specific combination of 'userId' and 'appId' (and, implicitly, the application HTTP origin), if one exists. 
Otherwise, it launches the enrollment workflow. See [loadUser()](./ISAgent.html#loadUser) spec for details.
> **Important**: 'userAuth' is a secret or pin specified (and determined) by the application for the enrolling user/device. The application must store and handle it securely - the value is used to derive an encryption key for the stored enrollment profile. 

~~~javascript
var loadUser = function() {
    return sdk.loadUser({
        appId: 'helloworld',
        userId: 'myuser',
        userAuth: 'password123',
    }
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
~~~
