# cyrus-sasl-xoauth2-idp

This is a plugin of [XOAUTH2](https://developers.google.com/gmail/xoauth2_protocol) mechanism for Cyrus SASL, extending [cyrus-sasl-xoauth2](https://github.com/moriyoshi/cyrus-sasl-xoauth2) to have the following features;

* Server side

  JWT is verified by the issuer's public key using [SciTokens](https://github.com/scitokens/scitokens-cpp)

* Client side

  The username is taken from the JWT's user claim instead of the input.
  
## Required packages
* [Cyrus SASL](https://github.com/cyrusimap/cyrus-sasl)
* [SciTokens](https://github.com/scitokens/scitokens-cpp)

### RPM
- cyrus-sasl-devel
- scitokens-cpp-devel

### Debian
- libsasl2-dev, sasl2-bin
- libscitokens-dev

## Build and install

```
./autogen.sh
./configure --libdir=$(pkg-config --variable=libdir libsasl2)
make
sudo make install
```

## Server-side configuration

sasl_plugin_dir=$(pkg-config --variable=libdir libsasl2)/sasl2

* `${sasl_plugin_dir}/{service_name}.conf`:

    ```
    mech_list: xoauth2
    xoauth2_scope: xxxx
    xoauth2_aud: xxxx
    xoauth2_user_claim: xxxx
    xoauth2_issuers: xxxx
    xoauth2_group_user: xxxx
    ```

For more details, see [here](doc/configuration.md).

## Client-side configuration

* `${sasl_plugin_dir}/{service_name}-client.conf`:

    ```
    xoauth2_user_claim: xxxx
    ```
