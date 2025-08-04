/*
 * JWT Utilities Header
 */

#ifndef JWT_UTILS_H
#define JWT_UTILS_H

/**
 * Extract a claim from a JWT token without signature verification
 * 
 * @param jwt_token The complete JWT token string
 * @param claim_name The name of the claim to extract (e.g., "iss", "sub", "aud")
 * @return The claim value as a string (must be freed), or NULL if not found
 */
char *extract_jwt_claim(const char *jwt_token, const char *claim_name);

#endif /* JWT_UTILS_H */