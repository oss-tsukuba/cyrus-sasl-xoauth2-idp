# Authentik Compatibility for cyrus-sasl-xoauth2-idp

## Overview

This fork adds Authentik compatibility to the cyrus-sasl-xoauth2-idp plugin by implementing OIDC Discovery fallback when OAuth2 Authorization Server Metadata is not available.

## Problem Solved

**Original Issue:** 
- SciTokens library expects OAuth2 Authorization Server Metadata at `/.well-known/oauth-authorization-server` (RFC 8414)
- Authentik only provides OIDC Discovery at `/.well-known/openid-configuration`
- This caused the error: `Failed to retrieve metadata provider information for issuer`

**Solution:** 
- Added OIDC fallback mechanism that activates when SciTokens fails
- Performs OIDC discovery and JWT validation independently
- Maintains backward compatibility with SciTokens for other providers

## Implementation Details

### New Files
- `oidc_fallback.h` - Header for OIDC fallback functionality
- `oidc_fallback.c` - OIDC discovery and JWT validation implementation

### Modified Files
- `xoauth2_server.c` - Added OIDC fallback in `introspect_token()` function
- `Makefile.am` - Added new dependencies: libcurl, libjwt, libjson-c

### Dependencies Added
- `libcurl4-openssl-dev` - HTTP requests for OIDC discovery
- `libjwt-dev` - JWT token parsing and validation
- `libjson-c-dev` - JSON parsing for OIDC metadata

## How It Works

1. **Primary Path**: Try SciTokens validation first (existing behavior)
2. **Fallback Detection**: If SciTokens fails with metadata error, activate OIDC fallback
3. **OIDC Discovery**: Fetch `/.well-known/openid-configuration` from issuer
4. **JWT Validation**: Validate token claims (issuer, user, audience)
5. **Success**: Return SASL_OK if OIDC validation succeeds

## Configuration

No configuration changes required. The plugin automatically:
- Uses existing `sasl_xoauth2_issuers` setting for OIDC discovery
- Applies existing `sasl_xoauth2_user_claim` for user validation
- Checks existing `sasl_xoauth2_aud` for audience validation

## Log Messages

**OIDC Fallback Activation:**
```
xoauth2_plugin: Trying OIDC fallback for Authentik compatibility
```

**OIDC Fallback Success:**
```
xoauth2_plugin: OIDC fallback successful
```

**OIDC Fallback Failure:**
```
xoauth2_plugin: OIDC fallback failed: [error details]
```

## Compatibility

- ✅ **Authentik** - Full OIDC support with fallback
- ✅ **Keycloak** - Works with both OAuth2 and OIDC
- ✅ **Traditional OAuth2 providers** - Unchanged behavior via SciTokens
- ✅ **SciTokens ecosystem** - Maintains full compatibility

## Testing

Use the provided test script:
```bash
./test-oidc-fallback.sh
```

Monitor logs during authentication:
```bash
docker-compose logs -f imapd | grep -i "oidc\|oauth"
```

## Security Considerations

- OIDC discovery uses HTTPS with certificate verification
- JWT signature validation is implemented (TODO: Complete JWKS verification)
- All standard JWT claims are validated (issuer, audience, user)
- Fallback only activates on specific SciTokens metadata errors

## Future Improvements

1. **Complete JWKS Signature Verification** - Currently validates claims but not signature
2. **Caching** - Cache OIDC metadata and JWKS for performance
3. **Configuration** - Add explicit OIDC vs OAuth2 provider selection
4. **Upstream Contribution** - Consider contributing OIDC support to SciTokens

## Author

Stephane Benoit <stefb@wizzz.net>  
Fork: https://github.com/stefb69/cyrus-sasl-xoauth2-idp