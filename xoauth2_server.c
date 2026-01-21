/*
 * Copyright (c) 2016 Moriyoshi Koizumi
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <scitokens/scitokens.h>

#include "xoauth2_plugin.h"

#define DELIMITER " \t"
#define SEPARATOR '|'

static int
wildcard_match(const char *str, size_t len_s,
                   const char *pat, size_t len_p)
{
    /* str pointer and pat pointer */
    size_t i = 0, j = 0;

    /* Backup positions for '*' handling */
    size_t star_pat = (size_t)-1;
    size_t star_str = (size_t)-1;

    while (i < len_s) {
        if (j < len_p && pat[j] == '*') {
            /* Record position of '*' */
            star_pat = j++;
            star_str = i;
        }
        else if (j < len_p && (pat[j] == '?' || pat[j] == str[i])) {
            /* direct match or '?' match */
            i++;
            j++;
        }
        else if (star_pat != (size_t)-1) {
            /* Backtrack: try to extend '*' */
            j = star_pat + 1;
            i = ++star_str;
        }
        else {
            return 0;
        }
    }

    /* Skip trailing '*' */
    while (j < len_p && pat[j] == '*')
        j++;

    return (j == len_p);
}

static int
has_str(const char *words1, const char *words2)
{
    if (!words1 || !words2 || !*words2)
        return 0;

    const char *p = words1;

    while (*p) {
        /* extract token from words1 */
        p += strspn(p, DELIMITER);
        if (!*p)
            break;

        const char *word1 = p;
        size_t len1 = strcspn(p, DELIMITER);
        p += len1;

        /* compare with each pattern from words2 */
        const char *n = words2;
        while (*n) {
            n += strspn(n, DELIMITER);
            if (!*n)
                break;

            const char *word2 = n;
            size_t len2 = strcspn(n, DELIMITER);
            n += len2;

            if (wildcard_match(word1, len1, word2, len2)) {
				return 1;
			}
        }
    }

    return 0;
}

static int
get_user_claim(char **argp, char **user_claim, char **iss)
{
    char *arg = *argp;
    char *start, *end, *sep;

    arg += strspn(arg, DELIMITER);

    if (*arg == '\0') {
        *argp = arg;
        return 0;
    }

    start = arg;

    end = start + strcspn(start, DELIMITER);

    if (*end != '\0') {
        *end = '\0';
        end++;
    }

    sep = strchr(start, SEPARATOR);
    if (sep != NULL) {
        *sep = '\0';
        *user_claim = start;
        *iss = sep + 1;
    } else {
        *user_claim = start;
        *iss = NULL;
    }

    end += strspn(end, DELIMITER);

    *argp = end;
    return 1;
}

static int
get_group_user_name(char **argp,
                    char **group, char **authority, char **issuer)
{
    char *arg = *argp;
    char *start, *end;
    char *p1, *p2;

    /* skip leading spaces/tabs */
    arg += strspn(arg, DELIMITER);

    if (*arg == '\0') {
        *argp = arg;
        return 0;
    }

    start = arg;

    /* find end of token */
    end = start + strcspn(start, DELIMITER);

    if (*end != '\0') {
        *end = '\0';  /* terminate token */
        end++;
    }

    /* split by SEPARATOR */
    p1 = strchr(start, SEPARATOR);
    if (p1 == NULL) {
        *group = start;
        *authority = NULL;
        *issuer = NULL;
    } else {
        *p1 = '\0';
        p1++;

        p2 = strchr(p1, SEPARATOR);
        if (p2 == NULL) {
            *group = start;
            *authority = p1;
            *issuer = NULL;
        } else {
            *p2 = '\0';
            *group = start;
            *authority = p1;
            *issuer = p2 + 1;
        }
    }

    /* skip spaces/tabs after token */
    end += strspn(end, DELIMITER);

    *argp = end;
    return 1;
}

static int introspect_token(
        xoauth2_plugin_server_settings_t *settings,
        sasl_server_params_t *params,
        const char *user,
        char *token,
        sasl_out_params_t *oparams)
{
    const sasl_utils_t *utils = params->utils;

    if (settings->proxy != NULL) {
      if (setenv("http_proxy", settings->proxy, 0) != 0 ||
		  setenv("https_proxy", settings->proxy, 0) != 0 ) {
		  SASL_log((utils->conn, SASL_LOG_ERR, "xoauth2_plugin: CURLOPT_PROXY=%s", settings->proxy));
      }
    }

    SciToken scitoken;
    char *err_msg;
	char *scope_claim;
    char *value;
	char *cur;
	char *iss;
    int err = SASL_FAIL;

    if(scitoken_deserialize(token, &scitoken, (const char * const*)settings->issuers, &err_msg)) {
      SASL_log((utils->conn, SASL_LOG_ERR, "xoauth2_plugin: introspect_token: %s", err_msg));
      free(err_msg);
      return err;
    }

    char *issuer_ptr = NULL;
    if(scitoken_get_claim_string(scitoken, "iss", &issuer_ptr, &err_msg)) {
      SASL_log((utils->conn, SASL_LOG_ERR, "xoauth2_plugin: introspect_token, Failed to get issuer claim: %s", err_msg));
      free(err_msg);
      scitoken_destroy(scitoken);
      return 0;
    }

    //Preparing for enforcer test
    char aud[settings->aud_len + 1];
    strncpy(aud, settings->aud, settings->aud_len);
    aud[settings->aud_len] = 0;

    int aud_num = 0;
    int i = 0;
    int not_count = 1;
    int aud_len = strlen(aud);

    for (i = 0; i < aud_len; i++) {
      if (aud[i] != ' ') {
	if (not_count) {
	  aud_num++;
	  not_count = 0;
	}
      } else {
	aud[i] = 0;
	not_count = 1;
      }
    }

    Enforcer enf;
    char** aud_list = (char**)malloc(sizeof(char*) * (aud_num + 1));
    int pos = 0;
    int not_set = 1;

    memset(aud_list, 0, aud_num + 1);

    for (i = 0; i < aud_len; i++) {
      if (aud[i] != 0) {
	if (not_set) {
	  aud_list[pos++] = &aud[i];
	  not_set = 0;
	}
      } else {
	not_set = 1;
      }
    }
    aud_list[aud_num] = NULL;

    if (!(enf = enforcer_create(issuer_ptr, (const char**)aud_list, &err_msg))) {
      SASL_log((utils->conn, SASL_LOG_ERR, "xoauth2_plugin: introspect_token, Failed to create enforcer: %s", aud));
      SASL_log((utils->conn, SASL_LOG_ERR, "%s", err_msg));
      free(err_msg);
      scitoken_destroy(scitoken);
      free(issuer_ptr);
      free(aud_list);
      return 0;
    }
    free(aud_list);
    enforcer_destroy(enf);

    if(scitoken_get_claim_string(scitoken, "scope", &scope_claim, &err_msg)) {
		SASL_log((utils->conn, SASL_LOG_ERR, "xoauth2_plugin: introspect_token, Failed to get scope"));
		free(err_msg);
		free(scope_claim);
		free(issuer_ptr);
		scitoken_destroy(scitoken);
		return err;
    }

    char scope[settings->scope_len + 1];
    strncpy(scope, settings->scope, settings->scope_len);
    scope[settings->scope_len] = 0;

	if (!has_str(scope_claim, scope)) {
		SASL_log((utils->conn, SASL_LOG_ERR, "xoauth2_plugin: invalid scope"));
		free(scope_claim);
		free(issuer_ptr);
		scitoken_destroy(scitoken);
		return err;
	}

    int user_ok = 0;

    char user_claim_setting[settings->user_claim_len + 1];
    strncpy(user_claim_setting, settings->user_claim, settings->user_claim_len);
    user_claim_setting[settings->user_claim_len] = 0;

    char *user_claim;
    cur = user_claim_setting;

    while (get_user_claim(&cur, &user_claim, &iss)) {
		if (iss != NULL && strcmp(issuer_ptr, iss) != 0)
			continue;

		if(scitoken_get_claim_string(scitoken, user_claim, &value, &err_msg)) {
			SASL_log((utils->conn, SASL_LOG_ERR, "xoauth2_plugin: introspect_token, Failed to get user claim[%s] %s",
					  user_claim, err_msg));
			free(err_msg);
			continue;
		}

		if (strcmp(value, user) != 0) {
			SASL_log((utils->conn, SASL_LOG_ERR, "xoauth2_plugin: introspect_token, different user's token"));
			free(value);
			continue;
		}

		free(value);

		user_ok = 1;
		break;
	}

    if (!user_ok) {
		// check group user
		char group_user_setting[settings->group_user_len + 1];
		strncpy(group_user_setting, settings->group_user, settings->group_user_len);
		group_user_setting[settings->group_user_len] = 0;

		char *group_user;
		char *auth;
		cur = group_user_setting;

		while (get_group_user_name(&cur, &group_user, &auth, &iss)) {
			if (*iss == 0 || *auth == 0)
				continue;

			if (!wildcard_match(issuer_ptr, strlen(issuer_ptr), iss, strlen(iss)) || !has_str(scope_claim, auth))
				continue;

			if (strcmp(group_user, user) != 0) {
				SASL_log((utils->conn, SASL_LOG_ERR, "xoauth2_plugin: introspect_token, different group user's token"));
				continue;
			}

			user_ok = 1;
			break;
		}
    }

    free(issuer_ptr);
    free(scope_claim);

    if (user_ok)
        err = SASL_OK;

    scitoken_destroy(scitoken);
    return err;
}

static int xoauth2_plugin_server_mech_new(
        void *glob_context, 
        sasl_server_params_t *params,
        UNUSED(const char *challenge),
        UNUSED(unsigned challenge_len),
        void **pcontext)
{
    int err;
    const sasl_utils_t *utils = params->utils;
    xoauth2_plugin_server_context_t *context;

    context = SASL_malloc(sizeof(*context));
    if (!context) {
        SASL_seterror((utils->conn, 0, "Failed to allocate memory"));
        return SASL_NOMEM;
    }

    context->settings = (xoauth2_plugin_server_settings_t *)glob_context;
    context->state = 0;
    context->resp.buf = NULL;
    err = xoauth2_plugin_str_init(utils, &context->outbuf);
    if (err != SASL_OK) {
        SASL_free(context);
        SASL_log((utils->conn, SASL_LOG_ERR, "xoauth2_plugin: failed to allocate buffer"));
        return err;
    }
    *pcontext = context;
    return SASL_OK;
}

static int append_string(const sasl_utils_t *utils, xoauth2_plugin_str_t *outbuf, const char *v, unsigned vlen)
{
    int err;
    const char *p;
    const char *e = v + vlen;
    err = xoauth2_plugin_str_alloc(utils, outbuf, outbuf->len + 2 + vlen * 2);
    if (err != SASL_OK) {
        return err;
    }
    outbuf->buf[outbuf->len++] = '"';
    for (p = v; p < e; ++p) {
        switch (*p) {
        case 8:
            outbuf->buf[outbuf->len++] = '\\';
            outbuf->buf[outbuf->len++] = 'b';
            break;
        case 9:
            outbuf->buf[outbuf->len++] = '\\';
            outbuf->buf[outbuf->len++] = 't';
            break;
        case 10:
            outbuf->buf[outbuf->len++] = '\\';
            outbuf->buf[outbuf->len++] = 'n';
            break;
        case 12:
            outbuf->buf[outbuf->len++] = '\\';
            outbuf->buf[outbuf->len++] = 'f';
            break;
        case 13:
            outbuf->buf[outbuf->len++] = '\\';
            outbuf->buf[outbuf->len++] = 'r';
            break;
        case '"': case '\\':
            outbuf->buf[outbuf->len++] = '\\';
            /* fall-through */ 
        default:
            outbuf->buf[outbuf->len++] = *p;
            break;
        }
    }
    outbuf->buf[outbuf->len++] = '"';
    return SASL_OK; 
}

#if 0 /* not used in cyrus-sasl-xoauth2-idp */
static int append_int(const sasl_utils_t *utils, xoauth2_plugin_str_t *outbuf, int n)
{
    char buf[1024];
    int len = snprintf(buf, sizeof(buf) - 1, "%d", n);
    if (len < 0) {
        return SASL_NOMEM; 
    }
    return xoauth2_plugin_str_append(utils, outbuf, buf, (unsigned)len);
}
#endif

static int build_json_response(const sasl_utils_t *utils, xoauth2_plugin_str_t *outbuf, const char *status, xoauth2_plugin_server_settings_t *settings, xoauth2_plugin_auth_response_t *resp)
{
    int err;
    err = xoauth2_plugin_str_append(utils, outbuf, "{", 1);
    if (err != SASL_OK) {
        return err;
    }
    err = append_string(utils, outbuf, "status", 6);
    if (err != SASL_OK) {
        return err;
    }
    err = xoauth2_plugin_str_append(utils, outbuf, ":", 1);
    if (err != SASL_OK) {
        return err;
    }
    err = append_string(utils, outbuf, status, strlen(status));
    if (err != SASL_OK) {
        return err;
    }
    err = xoauth2_plugin_str_append(utils, outbuf, ",", 1);
    if (err != SASL_OK) {
        return err;
    }
    err = append_string(utils, outbuf, "schemes", 6);
    if (err != SASL_OK) {
        return err;
    }
    err = xoauth2_plugin_str_append(utils, outbuf, ":", 1);
    if (err != SASL_OK) {
        return err;
    }
    err = append_string(utils, outbuf, resp->token_type, resp->token_type_len);
    if (err != SASL_OK) {
        return err;
    }
    err = xoauth2_plugin_str_append(utils, outbuf, ",", 1);
    if (err != SASL_OK) {
        return err;
    }
    err = append_string(utils, outbuf, "scope", 5);
    if (err != SASL_OK) {
        return err;
    }
    err = xoauth2_plugin_str_append(utils, outbuf, ":", 1);
    if (err != SASL_OK) {
        return err;
    }
    err = append_string(utils, outbuf, settings->scope, settings->scope_len);
    if (err != SASL_OK) {
        return err;
    }
    err = xoauth2_plugin_str_append(utils, outbuf, "}", 1);
    if (err != SASL_OK) {
        return err;
    }
    return SASL_OK;
}

static int xoauth2_plugin_server_mech_step1(
        void *_context,
        sasl_server_params_t *params,
        const char *clientin,
        unsigned clientin_len,
        const char **serverout,
        unsigned *serverout_len,
        sasl_out_params_t *oparams)
{
    const sasl_utils_t *utils = params->utils;
    xoauth2_plugin_server_context_t *context = _context;
    int err = SASL_OK;
    xoauth2_plugin_auth_response_t resp;
    int token_is_valid = 0;

    *serverout = NULL;
    *serverout_len = 0;

    SASL_log((utils->conn, SASL_LOG_DEBUG, "xoauth2_plugin: xoauth2: step1"));
    
    if (!context) {
        err = SASL_BADPROT;
        goto out;
    }

    if (!clientin) {
        err = SASL_BADPROT;
        goto out;
    }

    {
        char *p, *e, *token_e;
        resp.buf = SASL_malloc(clientin_len + 1);
        if (!resp.buf) {
            SASL_seterror((utils->conn, 0, "Failed to allocate memory"));
            err = SASL_NOMEM;
            goto out;
        }
        memcpy(resp.buf, clientin, clientin_len);
        resp.buf[clientin_len] = '\0';
        resp.buf_size = clientin_len;

        p = resp.buf, e = resp.buf + resp.buf_size;

        if (e - p < 5 || strncasecmp(p, "user=", 5) != 0) {
            SASL_seterror((utils->conn, 0, "Failed to parse authentication information user: <%s>", resp.buf));
            err = SASL_BADPROT;
            goto out;
        }
        p += 5;

        resp.authid = p;
        for (;;) {
            if (p >= e) {
                SASL_seterror((utils->conn, 0, "Failed to parse authentication information authid: <%s>", resp.buf));
                err = SASL_BADPROT;
                goto out;
            }
            if (*p == '\001') {
                break;
            }
            ++p;
        }
        *p = '\0';
        resp.authid_len = p - resp.authid;
        ++p;

        if (e - p < 5 || strncasecmp(p, "auth=", 5) != 0) {
            SASL_seterror((utils->conn, 0, "Failed to parse authentication information auth: <%s>", resp.buf));
            err = SASL_BADPROT;
            goto out;
        }

        p += 5;

        resp.token_type = p;
        for (;;) {
            if (p >= e) {
                SASL_seterror((utils->conn, 0, "Failed to parse authentication information token_type/1: <%s>", resp.buf));
                err = SASL_BADPROT;
                goto out;
            }
            if (*p == '\001') {
                break;
            }
            ++p;
        }
        *p = '\0';
        token_e = p;

        if (*++p != '\001') {
            SASL_seterror((utils->conn, 0, "Failed to parse authentication information token_type/2: <%s>", resp.buf));
            err = SASL_BADPROT;
            goto out;
        }
        if (p + 1 != e) {
            SASL_seterror((utils->conn, 0, "Failed to parse authentication information token_type/3: <%s>", resp.buf));
            err = SASL_BADPROT;
            goto out;
        }

        p = resp.token_type;
        for (;;) {
            if (p >= token_e) {
                SASL_seterror((utils->conn, 0, "Failed to parse authentication information token_type/4: <%s>", resp.buf));
                err = SASL_BADPROT;
                goto out;
            }
            if (*p == ' ') {
                break;
            }
            ++p;
        }
        *p = '\0';
        resp.token_type_len = p - resp.token_type;
        ++p;

        for (;;) {
            if (p >= token_e) {
                SASL_seterror((utils->conn, 0, "Failed to parse authentication information token_type/5: <%s>", resp.buf));
                err = SASL_BADPROT;
                goto out;
            }
            if (*p != ' ') {
                break;
            }
            ++p;
        }
        resp.token = p;
        resp.token_len = token_e - resp.token;
    }

    if (resp.token_type_len != 6 || strncasecmp(resp.token_type, "bearer", 6) != 0) {
        /* not sure if we can return a plain error instead of a challange-impersonated error */
        err = SASL_BADPROT;
        SASL_seterror((utils->conn, 0, "unsupported token type: %s", resp.token_type));
        goto out;
    }

    err = params->canon_user(utils->conn, resp.authid, 0, SASL_CU_AUTHID | SASL_CU_AUTHZID, oparams);

    if (err == SASL_OK) {
	err = introspect_token(context->settings, params, resp.authid, resp.token, oparams);
	if (err == SASL_OK) {
	    token_is_valid = 1;
	}
    } else {
	SASL_log((utils->conn, SASL_LOG_ERR, "xoauth2_plugin: failed to canonify user and get auxprops for user %s", resp.authid));
    }

    if (!token_is_valid) {
        err = build_json_response(utils, &context->outbuf, "401", context->settings, &resp);
        if (err != SASL_OK) {
            SASL_log((utils->conn, SASL_LOG_ERR, "xoauth2_plugin: failed to allocate buffer"));
            goto out;
        }
        context->state = 1;
        context->resp = resp, resp.buf = NULL;
        *serverout = context->outbuf.buf;
        *serverout_len = context->outbuf.len;
        err = SASL_CONTINUE;
        goto out;
    }

out:
    if (resp.buf != NULL) {
        memset(resp.buf, 0, resp.buf_size);
        SASL_free(resp.buf);
    }
    return err;
}

static int xoauth2_plugin_server_mech_step2(
        void *_context,
        sasl_server_params_t *params,
        const char *clientin,
        unsigned clientin_len,
        const char **serverout,
        unsigned *serverout_len,
        sasl_out_params_t *oparams)
{
    const sasl_utils_t *utils = params->utils;
    xoauth2_plugin_server_context_t *context = _context;

    *serverout = NULL;
    *serverout_len = 0;

    SASL_log((utils->conn, SASL_LOG_DEBUG, "xoauth2_plugin: xoauth2: step2"));
    
    if (!context) {
        return SASL_BADPROT;
    }

    //    SASL_seterror((utils->conn, 0, "bearer token is not valid: %s", context->resp.token));
    //    return params->transition ? SASL_TRANS: SASL_NOUSER;
    return SASL_FAIL;
}

static int xoauth2_plugin_server_mech_step(
        void *_context,
        sasl_server_params_t *params,
        const char *clientin,
        unsigned clientin_len,
        const char **serverout,
        unsigned *serverout_len,
        sasl_out_params_t *oparams)
{
    xoauth2_plugin_server_context_t *context = _context;
    switch (context->state) {
    case 0:
        return xoauth2_plugin_server_mech_step1(
            context, params,
            clientin, clientin_len,
            serverout, serverout_len,
            oparams);
    case 1:
        return xoauth2_plugin_server_mech_step2(
            context, params,
            clientin, clientin_len,
            serverout, serverout_len,
            oparams);
    default:
        return SASL_BADPROT;
    }
}

static void xoauth2_plugin_server_mech_dispose(void *_context, const sasl_utils_t *utils)
{
    xoauth2_plugin_server_context_t *context = _context;

    if (!context) {
        return;
    }

    if (context->resp.buf) {
        memset(context->resp.buf, 0, context->resp.buf_size);
        SASL_free(context->resp.buf);
        context->resp.buf = NULL;
    }

    xoauth2_plugin_str_free(utils, &context->outbuf);
    SASL_free(context);
}

static int xoauth2_server_plug_get_options(const sasl_utils_t *utils, xoauth2_plugin_server_settings_t *settings)
{
    int err;
    const char *issuers;
    unsigned issuers_len;

    err = utils->getopt(
            utils->getopt_context,
            "XOAUTH2",
            "xoauth2_scope",
            &settings->scope, &settings->scope_len);
    if (err != SASL_OK || !settings->scope) {
        SASL_log((utils->conn, SASL_LOG_NOTE, "xoauth2_plugin: xoauth2_scope is not set"));
        settings->scope = "";
        settings->scope_len = 0;
    }

    err = utils->getopt(
            utils->getopt_context,
            "XOAUTH2",
            "xoauth2_aud",
            &settings->aud, &settings->aud_len);
    if (err != SASL_OK || !settings->aud) {
        SASL_log((utils->conn, SASL_LOG_NOTE, "xoauth2_plugin: xoauth2_aud is not set"));
        settings->aud = "";
        settings->aud_len = 0;
    }

    err = utils->getopt(
            utils->getopt_context,
            "XOAUTH2",
            "xoauth2_user_claim",
            &settings->user_claim, &settings->user_claim_len);
    if (err != SASL_OK || !settings->user_claim) {
        SASL_log((utils->conn, SASL_LOG_NOTE, "xoauth2_plugin: xoauth2_user_claim is not set"));
        settings->user_claim = "";
        settings->user_claim_len = 0;
    }

    err = utils->getopt(
            utils->getopt_context,
            "XOAUTH2",
            "xoauth2_group_user",
            &settings->group_user, &settings->group_user_len);
    if (err != SASL_OK || !settings->group_user) {
        SASL_log((utils->conn, SASL_LOG_NOTE, "xoauth2_plugin: xoauth2_group_user is not set"));
        settings->group_user = "";
        settings->group_user_len = 0;
    }

    memset(settings->issuers, 0, sizeof(settings->issuers));
    issuers = NULL;
    issuers_len = 0;
    err = utils->getopt(
            utils->getopt_context,
            "XOAUTH2",
            "xoauth2_issuers",
            &issuers, &issuers_len);
    if (err != SASL_OK || issuers == NULL) {
        SASL_log((utils->conn, SASL_LOG_NOTE, "xoauth2_plugin: xoauth2_issuers is not set"));
    } else {
      char *iss;
      int num = 0;

      iss = strtok((char *)issuers, DELIMITER);
      while (iss != NULL) {
	if (num >= MAX_ISSUERS - 1) {
	    /* MAX_ISSUERS - 1: settings->issuers[num] should be NULL */
	    SASL_log((utils->conn, SASL_LOG_WARN, "xoauth2_plugin: number of issuers exceeds %d", MAX_ISSUERS - 1));
	} else {
	    settings->issuers[num++] = strdup(iss);
	}
	iss = strtok(NULL, DELIMITER);
      }
    }

    err = utils->getopt(
            utils->getopt_context,
            "XOAUTH2",
            "proxy",
            &settings->proxy, &settings->proxy_len);
    /* it's ok that "proxy" is not defined */

    return SASL_OK;
}
    
static xoauth2_plugin_server_settings_t xoauth2_server_settings;

static sasl_server_plug_t xoauth2_server_plugins[] = 
{
    {
        "XOAUTH2",                              /* mech_name */
        0,                                      /* max_ssf */
        SASL_SEC_NOANONYMOUS
        | SASL_SEC_PASS_CREDENTIALS,            /* security_flags */
        SASL_FEAT_WANT_CLIENT_FIRST
        | SASL_FEAT_ALLOWS_PROXY,               /* features */
        NULL,                                   /* glob_context */
        &xoauth2_plugin_server_mech_new,        /* mech_new */
        &xoauth2_plugin_server_mech_step,       /* mech_step */
        &xoauth2_plugin_server_mech_dispose,    /* mech_dispose */
        NULL,                                   /* mech_free */
        NULL,                                   /* setpass */
        NULL,                                   /* user_query */
        NULL,                                   /* idle */
        NULL,                                   /* mech_avail */
        NULL                                    /* spare */
    }
};

int xoauth2_server_plug_init(
        const sasl_utils_t *utils,
        int maxversion,
        int *out_version,
        sasl_server_plug_t **pluglist,
        int *plugcount)
{
    int err;

    if (maxversion < SASL_SERVER_PLUG_VERSION) {
        SASL_seterror((utils->conn, 0, "xoauth2: version mismatch"));
        return SASL_BADVERS;
    }

    err = xoauth2_server_plug_get_options(utils, &xoauth2_server_settings);
    if (err != SASL_OK) {
        return err;
    }

    xoauth2_server_plugins[0].glob_context = &xoauth2_server_settings;

    *out_version = SASL_SERVER_PLUG_VERSION;
    *pluglist = xoauth2_server_plugins;
    *plugcount = sizeof(xoauth2_server_plugins) / sizeof(*xoauth2_server_plugins);
    
    return SASL_OK;
}
