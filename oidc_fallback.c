/*
 * OIDC Fallback Implementation for Authentik Compatibility
 * Copyright (c) 2025 Stephane Benoit <stefb@wizzz.net>
 * 
 * This module provides OIDC discovery fallback when OAuth2 Authorization Server
 * Metadata is not available, making the plugin compatible with Authentik and
 * other OIDC-only providers.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <curl/curl.h>
#include <jwt.h>
#include <json-c/json.h>

#include "xoauth2_plugin.h"
#include "oidc_fallback.h"

#define MAX_URL_LEN 512
#define MAX_RESPONSE_SIZE 65536

typedef struct {
    char *memory;
    size_t size;
} http_response_t;

static size_t http_write_callback(void *contents, size_t size, size_t nmemb, http_response_t *userp) {
    size_t realsize = size * nmemb;
    char *ptr = realloc(userp->memory, userp->size + realsize + 1);
    
    if (!ptr) {
        printf("Not enough memory (realloc returned NULL)\n");
        return 0;
    }
    
    userp->memory = ptr;
    memcpy(&(userp->memory[userp->size]), contents, realsize);
    userp->size += realsize;
    userp->memory[userp->size] = 0;
    
    return realsize;
}

static int fetch_oidc_metadata(const char *issuer, oidc_metadata_t *metadata, char **err_msg) {
    CURL *curl;
    CURLcode res;
    http_response_t chunk = {0};
    char url[MAX_URL_LEN];
    int ret = -1;
    
    // Construire l'URL de découverte OIDC (éviter double slash)
    char clean_issuer[MAX_URL_LEN];
    strncpy(clean_issuer, issuer, sizeof(clean_issuer) - 1);
    clean_issuer[sizeof(clean_issuer) - 1] = '\0';
    
    // Supprimer le slash de fin si présent
    size_t len = strlen(clean_issuer);
    if (len > 0 && clean_issuer[len - 1] == '/') {
        clean_issuer[len - 1] = '\0';
    }
    
    if (snprintf(url, sizeof(url), "%s/.well-known/openid-configuration", clean_issuer) >= sizeof(url)) {
        *err_msg = strdup("Issuer URL too long");
        return -1;
    }
    
    curl = curl_easy_init();
    if (!curl) {
        *err_msg = strdup("Failed to initialize CURL");
        return -1;
    }
    
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, http_write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "cyrus-sasl-xoauth2-oidc/1.0");
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
    
    res = curl_easy_perform(curl);
    
    if (res != CURLE_OK) {
        *err_msg = strdup(curl_easy_strerror(res));
        goto cleanup;
    }
    
    long response_code;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
    
    if (response_code != 200) {
        char error_buf[256];
        snprintf(error_buf, sizeof(error_buf), "HTTP %ld from %s", response_code, url);
        *err_msg = strdup(error_buf);
        goto cleanup;
    }
    
    // Parser le JSON
    json_object *root = json_tokener_parse(chunk.memory);
    if (!root) {
        *err_msg = strdup("Failed to parse JSON response");
        goto cleanup;
    }
    
    // Extraire les champs nécessaires
    json_object *jwks_uri_obj;
    if (json_object_object_get_ex(root, "jwks_uri", &jwks_uri_obj)) {
        const char *jwks_uri = json_object_get_string(jwks_uri_obj);
        metadata->jwks_uri = strdup(jwks_uri);
    } else {
        *err_msg = strdup("No jwks_uri in OIDC metadata");
        json_object_put(root);
        goto cleanup;
    }
    
    json_object *issuer_obj;
    if (json_object_object_get_ex(root, "issuer", &issuer_obj)) {
        const char *iss = json_object_get_string(issuer_obj);
        metadata->issuer = strdup(iss);
    } else {
        metadata->issuer = strdup(issuer);
    }
    
    json_object_put(root);
    ret = 0;
    
cleanup:
    if (chunk.memory) {
        free(chunk.memory);
    }
    curl_easy_cleanup(curl);
    return ret;
}

static int fetch_jwks(const char *jwks_uri, char **jwks_json, char **err_msg) {
    CURL *curl;
    CURLcode res;
    http_response_t chunk = {0};
    int ret = -1;
    
    curl = curl_easy_init();
    if (!curl) {
        *err_msg = strdup("Failed to initialize CURL");
        return -1;
    }
    
    curl_easy_setopt(curl, CURLOPT_URL, jwks_uri);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, http_write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "cyrus-sasl-xoauth2-oidc/1.0");
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
    
    res = curl_easy_perform(curl);
    
    if (res != CURLE_OK) {
        *err_msg = strdup(curl_easy_strerror(res));
        goto cleanup;
    }
    
    long response_code;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
    
    if (response_code != 200) {
        char error_buf[256];
        snprintf(error_buf, sizeof(error_buf), "HTTP %ld from %s", response_code, jwks_uri);
        *err_msg = strdup(error_buf);
        goto cleanup;
    }
    
    *jwks_json = chunk.memory;
    chunk.memory = NULL; // Transfer ownership
    ret = 0;
    
cleanup:
    if (chunk.memory) {
        free(chunk.memory);
    }
    curl_easy_cleanup(curl);
    return ret;
}

int oidc_verify_token(const char *token_str, const char *issuer, 
                      const char **allowed_issuers, const char *expected_user,
                      const char *user_claim, const char *audience,
                      char **err_msg) {
    
    oidc_metadata_t metadata = {0};
    char *jwks_json = NULL;
    jwt_t *jwt = NULL;
    int ret = -1;
    
    // Étape 1: Récupérer les métadonnées OIDC
    if (fetch_oidc_metadata(issuer, &metadata, err_msg) != 0) {
        goto cleanup;
    }
    
    // Étape 2: Récupérer les clés JWKS
    if (fetch_jwks(metadata.jwks_uri, &jwks_json, err_msg) != 0) {
        goto cleanup;
    }
    
    // Étape 3: Décoder le JWT
    if (jwt_decode(&jwt, token_str, NULL, 0) != 0) {
        *err_msg = strdup("Failed to decode JWT token");
        goto cleanup;
    }
    
    // Étape 4: Vérifier l'issuer
    const char *token_issuer = jwt_get_grant(jwt, "iss");
    if (!token_issuer) {
        *err_msg = strdup("No issuer claim in token");
        goto cleanup;
    }
    
    int issuer_allowed = 0;
    for (int i = 0; allowed_issuers && allowed_issuers[i]; i++) {
        if (strcmp(token_issuer, allowed_issuers[i]) == 0) {
            issuer_allowed = 1;
            break;
        }
    }
    
    if (!issuer_allowed) {
        *err_msg = strdup("Token issuer is not in list of allowed issuers");
        goto cleanup;
    }
    
    // Étape 5: Vérifier l'utilisateur
    const char *token_user = jwt_get_grant(jwt, user_claim);
    if (!token_user) {
        char error_buf[256];
        snprintf(error_buf, sizeof(error_buf), "No %s claim in token", user_claim);
        *err_msg = strdup(error_buf);
        goto cleanup;
    }
    
    if (strcmp(token_user, expected_user) != 0) {
        *err_msg = strdup("Token user does not match expected user");
        goto cleanup;
    }
    
    // Étape 6: Vérifier l'audience (optionnel)
    if (audience && strlen(audience) > 0) {
        const char *token_aud = jwt_get_grant(jwt, "aud");
        if (!token_aud || strcmp(token_aud, audience) != 0) {
            *err_msg = strdup("Token audience does not match");
            goto cleanup;
        }
    }
    
    // TODO: Étape 7: Vérifier la signature JWT avec JWKS
    // Cette étape nécessite l'implémentation de la validation de signature
    // Pour l'instant, on fait confiance au token si les autres vérifications passent
    
    ret = 0; // Succès
    
cleanup:
    if (metadata.issuer) free(metadata.issuer);
    if (metadata.jwks_uri) free(metadata.jwks_uri);
    if (jwks_json) free(jwks_json);
    if (jwt) jwt_free(jwt);
    
    return ret;
}