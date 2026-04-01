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

Specify the claim name and issuer name separated by '|'
and define the claim name representing the username for each issuer below.

`claim_name|issuer`

If only the claim name is specified, the default claim name is
enabled for all issues.
Multiple definitions can be specified separated by whitespaces.

example:

```properties
xoauth2_user_claim: hoge.id sub|https://xxx.domain.jp:8443/auth/realms/yyyy
```

## xoauth2_group_user

Define group usernames for each scope and issue pair.
Group username verification is performed after username verification.
Specify the group username, the scope and the issuer separated by '|'.

`group_user_name|scope|issuer`

Wildcards can be used in the scope and the issuer definition.
These cannot be omitted.
Multiple definitions can be specified separated by whitespaces.

example:

```properties
xoauth2_group_user: web|web_access|https://xxx.domain.jp:8443/auth/realms/yyyy strage_read|storage.read:*|https://xxx.domain.jp:8443/auth/realms/yyyy anyone|*|*
```
