# ionic-js-sdk

[Ionic](https://ionic.com) JavaScript (JS) software development kit (SDK).

## Release Notes

This is the first general availability (GA) release of the JS SDK.

The following [Ionic platform functions](https://dev.ionic.com/fundamentals.html) are supported:
* **Enrollment**: create and store secure enrollment profiles (SEPs) for trusted devices.
See ["Enrolling a Device"](https://dev.ionic.com/fundamentals/glossary.html) for details. 
* **Key requests**: create, fetch (aka 'get'), and update Ionic protection keys. See ["Data Key Related"](https://dev.ionic.com/fundamentals/glossary.html) for details.
* **Encryption**: encrypt and decrypt data with Ionic protection keys using [cryptographic primitives](https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto) available in a browser window context.
* **Chunk Data Format**: [encode](https://dev.ionic.com/fundamentals/data-format/chunkdataformat.html) encrypted data along with the associated key tag (aka keyId).
* **Key Attributes**: add mutable (updateable) and immutable (cannot be changed once set on the key) [attributes](https://dev.ionic.com/fundamentals/metadata.html).
* **Request Metadata**: specify [metadata](https://dev.ionic.com/fundamentals/metadata.html) such as device or application information.

Future capabilties such as the following are forthcoming:
* Interoperability with other browsers and the node.js envrionment.
* Support for file format encryption/decryption.

## Developer documentation

Additional [Ionic developer](https://dev.ionic.com) resources are available, as are a general introduction to the Ionic platform [fundamentals](https://dev.ionic.com/fundamentals.html).

Visit [Getting Started with the JavaScript SDK](https://dev.ionic.com/getting-started/web-javascript.html) for a guide.

### JS SDK Requirements

* Google Chrome
 * The WebCrypto API was enabled by default starting in Chrome 37 (August 26, 2014)
* [SubtleCrypto](https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto) interface
 * Access to the WebCrypto API is restricted to **secure origins (which is to say https:// pages)**

### Getting The SDK

The [JSSDK version listing](https://api.ionic.com/jssdk/) hosts links to all of the publicly released and hosted JSSDK versions.

> NOTE: If your tenant is in the Preview environment, use the Preview [listings page](https://preview-api.ionic.com/jssdk/).

