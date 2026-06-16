# How to configure for cyrus-sasl-xoauth2-idp

Configure in the `${sasl_plugin_dir}/{service_name}.conf` file.
The `sasl_plugin_dir` is below.

sasl_plugin_dir=$(pkg-config --variable=libdir libsasl2)/sasl2

This plugin performs username verification based on the username
sent from the client.
The valid username is determined by the JWT and the configuration file.

## mech_list

Whitespace separated list of mechanisms to allow (e.g. `plain` and `otp`).
Used to restrict the mechanisms to a subset of the installed plugins.
This plugin is for XOAUTH, so when using this plugin, specify xoauth2.

example:

```properties
mech_list: xoauth2 plain
```

## xoauth2_scope

Whitespace separated list of the JWT scope claim to allow.
If one of the listed items is defined in the JWT scope claim,
it is permitted. Wildcards can be used in items.

example:

```properties
xoauth2_scope: foo bar h*i
```

## xoauth2_aud

Whitespace separated list of the JWT aud claim to allow.
If one of the listed items matches the JWT aud claim,
it is permitted. Wildcards cannot be used in items.

example:

```properties
xoauth2_aud: aud1 aud2
```

## xoauth2_issuers

Whitespace separated list of the JWT iss claim to allow.
If one of the listed items matches the JWT iss claim,
it is permitted. Wildcards cannot be used in items.

example:

```properties
xoauth2_issuers: https://keycloak.example.com/auth/realms/hpci https://keycloak.example.org/auth/realms/hpci
```

## xoauth2_user_claim

### Server-side SASL plugin:

Specify the claim name of the JWT that contains the username granting access.

You can also specify different claim names for each issuer. In that case, separate them with a '|' as shown below.

`claim_name|issuer`

If only the claim name is specified, the default claim name is
enabled for all issuers.
Multiple definitions can be specified separated by whitespaces.

example:

```properties
xoauth2_user_claim: hoge.id sub|https://keycloak.example.org:8443/auth/realms/yyyy
```

### Client-side SASL plugin:

Specify the claim name.  
If an application does not supply a username to this client-side plugin,
this plugin will retrieve the value of the claim specified in the `xoauth2_user_claim` option from the JWT and use it as the username.

At this time, this is the only option available for client-side plugin.

example:

```properties
xoauth2_user_claim: hoge.id
```

## xoauth2_group_user (optional)

Specify a combination of group username, scope, and issuer to grant access.
Access using this group username is granted to all users whose JWT scope and issuer match.

If `xoauth2_group_user` is configured, the access permissions granted by this setting are added to those granted by the `xoauth2_user_claim` setting.

Specify the group username, the scope and the issuer separated by '|'
as shown below.

`group_user_name|scope|issuer`

Wildcards can be used in the scope and the issuer definition.
These cannot be omitted.
Multiple definitions can be specified separated by whitespaces.

example:

```properties
xoauth2_group_user: web|web_access|https://keycloak.example.org:8443/auth/realms/yyyy storage_read|storage.read:*|https://keycloak.example.org:8443/auth/realms/yyyy anyone|*|*
```

## proxy (optional)

Specify the HTTP proxy server used when retrieving the issuer's
public key or other metadata.

example:

```properties
proxy: http://proxy.example.com:8080/
```

## no_proxy (optional)

Comma-separated list of hosts that should bypass the proxy.

example:

```properties
no_proxy: localhost,127.0.0.1
```
