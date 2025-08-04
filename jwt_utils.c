/*
 * JWT Utilities for OIDC Fallback
 * Simple JWT parsing without signature verification for extracting claims
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <json-c/json.h>
#include "base64.h"
#include "jwt_utils.h"

// Wrapper for base64 decoding that matches our needs
static char *simple_base64_decode(const char *input, size_t *output_len) {
    size_t input_len = strlen(input);
    size_t max_output_len = b64d_size(input_len);
    
    unsigned char *output = malloc(max_output_len + 1);
    if (!output) return NULL;
    
    unsigned int actual_len = b64_decode((const unsigned char*)input, input_len, output);
    output[actual_len] = '\0';
    
    if (output_len) *output_len = actual_len;
    return (char*)output;
}

static char *base64_url_decode(const char *input, size_t *output_len) {
    char *padded_input;
    size_t input_len = strlen(input);
    size_t padding = (4 - (input_len % 4)) % 4;
    
    // Add padding if needed
    padded_input = malloc(input_len + padding + 1);
    if (!padded_input) return NULL;
    
    strcpy(padded_input, input);
    for (size_t i = 0; i < padding; i++) {
        strcat(padded_input, "=");
    }
    
    // Convert URL-safe base64 to standard base64
    for (size_t i = 0; i < strlen(padded_input); i++) {
        if (padded_input[i] == '-') padded_input[i] = '+';
        if (padded_input[i] == '_') padded_input[i] = '/';
    }
    
    char *decoded = simple_base64_decode(padded_input, output_len);
    free(padded_input);
    return decoded;
}

char *extract_jwt_claim(const char *jwt_token, const char *claim_name) {
    if (!jwt_token || !claim_name) return NULL;
    
    // Find the second dot (separator between header.payload.signature)
    const char *first_dot = strchr(jwt_token, '.');
    if (!first_dot) return NULL;
    
    const char *second_dot = strchr(first_dot + 1, '.');
    if (!second_dot) return NULL;
    
    // Extract payload part
    size_t payload_len = second_dot - first_dot - 1;
    char *payload_b64 = strndup(first_dot + 1, payload_len);
    if (!payload_b64) return NULL;
    
    // Decode base64 payload
    size_t decoded_len;
    char *payload_json = base64_url_decode(payload_b64, &decoded_len);
    free(payload_b64);
    
    if (!payload_json) return NULL;
    
    // Parse JSON
    json_object *root = json_tokener_parse(payload_json);
    free(payload_json);
    
    if (!root) return NULL;
    
    // Extract claim
    json_object *claim_obj;
    char *result = NULL;
    
    if (json_object_object_get_ex(root, claim_name, &claim_obj)) {
        const char *claim_value = json_object_get_string(claim_obj);
        if (claim_value) {
            result = strdup(claim_value);
        }
    }
    
    json_object_put(root);
    return result;
}