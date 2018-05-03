An enrollment profile is created upon each successful enrollment (aka registration) of a device in a particular keyspace. It establishes the device as "trusted" (by the keyspace owner *and* by Ionic).

The ability of the device to encrypt or decrypt data isn't guaranteed by the presence of the enrollment profile. The "trusted" status merely allows access to the keyspace, at which point tenant and keyspace-specific access policies apply (as configured by the tenant admin using the Ionic Dashboard application). 

NOTE: A single device may have multiple enrollment profiles stored locally as a result of multiple enrollments. "active" and "created" can be helfpul in determining which profile to use, if multiple are available. 

## Fields
Each profile specifies the following:  
* deviceId - A UUID for the device, constructed of the four-character keyspace followed by a Base64-encoded random number.  
* server - The IDC server that the device was registered with.  
* created - The time at which registration completed.  
* active - Only one profile is marked active at a time. This is the profile used for any subsequent key requests or encrypt/decrypt operations.  
* keyspace - Four-character string.

## SDK response

Upon successful completion of a profile access function (see API functions documented below), an array of profiles is returned. In this example, only one profile exists for the given client application and user.

    { 
        "sdkResponseCode" : 0,
        "profiles" : [{
            "active": true, 
            "created": "Tue Jan 16 2018 12:46:39 GMT-0500 (EST)",
            "deviceId": "D7GH.6.4cd46ce3-95e2-4aa5-b4f1-9c2be7f27dbf",
            "server": "https://mastereng-api.in.ionicsecurity.com",
            "keyspace":"D7GH"
        }]
    }

## Example of an encrypted device profile stored in localStorage:

    sdk.ionicsecurity.com
      ionic_security_device_profiles
        {"clientapp":{"username":["jNBi9dNkfxu4P6JCWhbp0s2mBqBtkPoKOTY51tDkj0Jpkny5A5AgfyOnI+8AmXj737Uew4Rv9HuH6iemYP8CloyfZ7zccl3MUxYSows1I13QirnlLpaeJQIuP8owtyjXtDLxyuAm781Qwup3o0/F/2PNYCi5If2SiguCkqWBqlBIoCfc+gVUrNpcnnr3wjAD71evzAiyg1c+eEUi+C0kRP57E2H+dlcBLLlRSMMSjnvmfkJcsy3l1RpkZHgzW1M4k7dpc1txzkgojaJ+sWNPRdcZiJlAUPmh9x2tHxsmN/KkY5HObur25lWf1yok09RCL3qjo6E2Hj58p2Ge1GrQ32+4H5tZdUqcnZRO9gTBg65ksw6QunFX05odnF4gkaVVo0HG9Mhm25T6yA9LIHa7zkfGE7yoqjEKpF0jkq0hNPj5KCCuodP70nLRnJTsyPISTTDPLwpTO4RzKPNOCzx+JPq+SKbYh3bnyJ/7g3vh/m//J2/xtJUNitcMfDftyT5SIXd1YmmCgaKODxuW2rm5z2T7bV/n97N9LoQa6aztLdHAicBVjp4HyJDDOU9rXHFD4mfBNCygTVdNWFJaG3Ux1M1vC7a1Ul7bBwWtPyPJc5rmk51TI/AaWp+Yq4g9ZX6HGQgnbdU+U8u6ZoHIGvVV2ESYmaduJ6UPyvrhXWhyvwkcITkiHXzppot4WDROX0cSqdDz1wC5+YwQJaUyfw4c5/ND9dRMa915IA=="]}}
