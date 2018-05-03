This document describes Enrollment Server configuration parameters related to the JS SDK support. For an extensive list of available configuration parameters, see enrollment.conf.example (samples are always included within any given RPM or docker image under /etc/opt/ionic/enrollment/)

## What do we mean by JS SDK support?

JS SDK allows users to become Ionic-enabled without requiring that they first install an Ionic registration (enrollment) tool such as IonicManager, a browser plugin, or reggie. 

This convenience comes with added configuration cost - it's up to the keyspace/tenant administrator to enable JS SDK enrollment capability by configuring the parameters below. 

## Enabling JS SDK enrollment 

### (Required) source
External registration script source (relative path or URL)

    source =“path/to/sdk.bundle.js”

### (Optional) knownhost

    knownhost = “path/to/hosted/jssdk” 

### (Optional) digest
If specified, the browser will verify the integrity of the script loaded by the Enrollment Server using this known digest (hash value).
See [spec](https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity) for details.
	digest = “sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC”
	


### Excerpt from enrollment.conf.example
    # CONFIGURING External/Custom Registration (JavaScript SDK, aka JS-SDK)
    # --------------------------------------------------------------------
    # NOTE: This configuration can be specified globally for the server (here)
    # or per enrollment endpoint (see specific saml/oauth/etc example)
    # 
    # [extregscript]
    # OPTIONAL: source                 = "/path/to/script.js"
    #           -> External/custom registration script source
    #              Allows embedding of an external registration script (eg. JavaScript SDK)
    #              NOTE: this can be a path local to the server or an external URL. In the
    #              case of the latter, you may want to specify a digest for script integrity
    #              verification.
    # OPTIONAL: digest
    #           -> crypto digest (aka "hash") formed by applying a hash function to the input.
    #              From the spec: "An integrity value may contain multiple hashes separated 
    #              by whitespace. A resource will be loaded if it matches one of those hashes.
    #              https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity
    # CONDITIONAL: knownhost
    #           -> Specifies a hostname (if different from https://sdk.ionicsecurity.com)
    #              eg. https://company.domain.com  
