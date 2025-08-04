/*
 * OIDC Fallback Header for Authentik Compatibility
 * Copyright (c) 2025 Stephane Benoit <stefb@wizzz.net>
 */

#ifndef OIDC_FALLBACK_H
#define OIDC_FALLBACK_H

typedef struct {
    char *issuer;
    char *jwks_uri;
} oidc_metadata_t;

/**
 * Verify a JWT token using OIDC discovery and validation
 * 
 * @param token_str The JWT token string
 * @param issuer The issuer URL for OIDC discovery
 * @param allowed_issuers Array of allowed issuers (NULL-terminated)
 * @param expected_user The expected username 
 * @param user_claim The claim name containing the username
 * @param audience The expected audience (can be NULL)
 * @param err_msg Output parameter for error messages
 * @return 0 on success, -1 on failure
 */
int oidc_verify_token(const char *token_str, const char *issuer, 
                      const char **allowed_issuers, const char *expected_user,
                      const char *user_claim, const char *audience,
                      char **err_msg);

#endif /* OIDC_FALLBACK_H */