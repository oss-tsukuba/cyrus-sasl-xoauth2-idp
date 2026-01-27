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
/*
 * Copyright (c) 1998-2016 Carnegie Mellon University.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. The name "Carnegie Mellon University" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For permission or any other legal
 *    details, please contact
 *      Carnegie Mellon University
 *      Center for Technology Transfer and Enterprise Creation
 *      4615 Forbes Avenue
 *      Suite 302
 *      Pittsburgh, PA  15213
 *      (412) 268-7393, fax: (412) 268-7395
 *      innovation@andrew.cmu.edu
 *
 * 4. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by Computing Services
 *     at Carnegie Mellon University (http://www.cmu.edu/computing/)."
 *
 * CARNEGIE MELLON UNIVERSITY DISCLAIMS ALL WARRANTIES WITH REGARD TO
 * THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS, IN NO EVENT SHALL CARNEGIE MELLON UNIVERSITY BE LIABLE
 * FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
 * AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <sasl/saslutil.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "xoauth2_plugin.h"

#include "base64.h"
#include "cJSON.h"

#define PATHS_DELIMITER ':'
#define HIER_DELIMITER '/'

static struct xoauth2_plugin_client_settings xoauth2_client_settings;

static pthread_once_t load_config_initialized = PTHREAD_ONCE_INIT;

static int
jwt_get_claim_string(const char *token, const char *claim, char **dst)
{
	char *payload;
	int len, dlen;
	int first, second, i;
	int ret = 0;
	cJSON *root, *item;

	if (token == NULL || claim == NULL) {
		return (0);
	}

	for (first = 0, second = 0, i = 0; i < strlen(token); i++) {
		if (token[i] == '.') {
			if (first == 0) {
				first = i + 1;
			} else {
				second = i;
			}
		}
	}

	if (second - first <= 0) {
		return (-1);
	}

	len = second - first;
	len += len % 4;
	dlen = b64d_size(len);
	payload = malloc((dlen + 1) * sizeof(char));
	memset(payload, 0, dlen + 1);

	len = b64_decode((const unsigned char *)token + first,
			 len,
			 (unsigned char *)payload);
	if (len <= 0) {
		free(payload);
		return (-1);
	}

	root = cJSON_Parse(payload);
	item = cJSON_GetObjectItem(root, claim);

	if (item != NULL) {
		*dst = strdup(cJSON_GetStringValue(item));
		ret = strlen(*dst);
	}

	free(payload);
	cJSON_Delete(root);

	return (ret);
}

static int
xoauth2_client_plug_get_options(const sasl_utils_t *utils,
				struct xoauth2_plugin_client_settings *settings)
{
	int err;

	err = utils->getopt(utils->getopt_context,
			    "XOAUTH2",
			    "xoauth2_user_claim",
			    &settings->user_claim,
			    &settings->user_claim_len);
	if (err != SASL_OK || !settings->user_claim) {
		SASL_log((utils->conn,
			  SASL_LOG_ERR,
			  "xoauth2_plugin: xoauth2_user_claim is not set"));
		settings->user_claim = "";
		settings->user_claim_len = 0;
	}

	return (SASL_OK);
}

static int xoauth2_plugin_client_mech_new(UNUSED(void *glob_context),
					  sasl_client_params_t *params,
					  void **pcontext)
{
	int err;
	const sasl_utils_t *utils = params->utils;
	struct xoauth2_plugin_client_context *context;

	context = SASL_malloc(sizeof(*context));
	if (!context) {
		SASL_seterror((utils->conn,
			       0,
			       "xoauth2_plugin: Failed to allocate memory"));
		return (SASL_NOMEM);
	}

	context->state = 0;
	context->resp.buf = NULL;
	err = xoauth2_plugin_str_init(utils, &context->outbuf);
	if (err != SASL_OK) {
		SASL_free(context);
		return (err);
	}
	*pcontext = context;
	return (SASL_OK);
}

static int build_client_response(const sasl_utils_t *utils,
				 struct xoauth2_plugin_str *outbuf,
				 struct xoauth2_plugin_auth_response *resp)
{
	int err;
	err = xoauth2_plugin_str_append(utils, outbuf, "user=", 5);
	if (err != SASL_OK) {
		return (err);
	}
	err = xoauth2_plugin_str_append(
		utils, outbuf, resp->authid, resp->authid_len);
	if (err != SASL_OK) {
		return (err);
	}
	err = xoauth2_plugin_str_append(utils, outbuf, "\1", 1);
	if (err != SASL_OK) {
		return (err);
	}
	err = xoauth2_plugin_str_append(utils, outbuf, "auth=", 5);
	if (err != SASL_OK) {
		return (err);
	}
	err = xoauth2_plugin_str_append(
		utils, outbuf, resp->token_type, resp->token_type_len);
	if (err != SASL_OK) {
		return (err);
	}
	err = xoauth2_plugin_str_append(utils, outbuf, " ", 1);
	if (err != SASL_OK) {
		return (err);
	}
	err = xoauth2_plugin_str_append(
		utils, outbuf, resp->token, resp->token_len);
	if (err != SASL_OK) {
		return (err);
	}
	err = xoauth2_plugin_str_append(utils, outbuf, "\1\1", 2);
	if (err != SASL_OK) {
		return (err);
	}
	return (SASL_OK);
}

static sasl_interact_t *find_prompt(sasl_interact_t *prompts, unsigned id)
{
	sasl_interact_t *p;
	for (p = prompts; p->id != SASL_CB_LIST_END; ++p) {
		if (p->id == id) {
			return (p);
		}
	}
	return (NULL);
}

static int get_prompt_value(sasl_interact_t *prompts,
			    unsigned id,
			    const char **result,
			    unsigned *result_len)
{
	sasl_interact_t *prompt;
	prompt = find_prompt(prompts, id);
	if (!prompt) {
		return (SASL_FAIL);
	}

	*result = prompt->result;
	*result_len = prompt->len;

	return (SASL_OK);
}

static int get_cb_value(const sasl_utils_t *utils,
			unsigned id,
			const char **result,
			unsigned *result_len)
{
	int err;
	switch (id) {
	case SASL_CB_PASS: {
		sasl_getsecret_t *cb;
		void *cb_ctx;
		sasl_secret_t *secret;
		err = utils->getcallback(
			utils->conn, id, (sasl_callback_ft *)&cb, &cb_ctx);
		if (err != SASL_OK) {
			return (err);
		}
		err = cb(utils->conn, cb_ctx, id, &secret);
		if (err != SASL_OK) {
			return (err);
		}
		if (secret->len >= UINT_MAX) {
			return (SASL_BADPROT);
		}
		*result = (char *)secret->data;
		*result_len = secret->len;
	} break;
	case SASL_CB_GETCONFPATH: {
		sasl_getpath_t *cb;
		void *cb_ctx;
		err = utils->getcallback(
			utils->conn, id, (sasl_callback_ft *)&cb, &cb_ctx);
		if (err != SASL_OK) {
			return (err);
		}
		err = cb(NULL, result);
	} break;
	case SASL_CB_USER:
	case SASL_CB_AUTHNAME:
	case SASL_CB_LANGUAGE:
	case SASL_CB_CNONCE: {
		sasl_getsimple_t *cb;
		void *cb_ctx;
		err = utils->getcallback(
			utils->conn, id, (sasl_callback_ft *)&cb, &cb_ctx);
		if (err != SASL_OK) {
			return (err);
		}
		err = cb(cb_ctx, id, result, result_len);
	} break;
	default:
		err = SASL_FAIL;
	}
	return (err);
}

/**
 * @fn load_config(const sasl_utils_t *utils)
 * @brief load client-side configuration file
 * @return SASL_OK: success
 * @return SASL_FAIL: failure
 * @return SASL_CONTINUE: there is no configuration file
 */
static int load_config(const sasl_utils_t *utils)
{
	int result;
	const char *path_to_config = NULL;
	unsigned path_len;
	char *config_filename = NULL;
	char *service_name = NULL;
	size_t len;
	const char *next;

	result = sasl_getprop(
		utils->conn, SASL_SERVICE, (const void **)&service_name);
	if (result != SASL_OK)
		goto done;

	result = get_cb_value(utils,
			      SASL_CB_GETCONFPATH,
			      (const char **)&path_to_config,
			      &path_len);
	if (result != SASL_OK)
		goto done;
	if (path_to_config == NULL)
		path_to_config = "";

	next = path_to_config;

	while (next != NULL) {
		next = strchr(path_to_config, PATHS_DELIMITER);

		if (next != NULL) {
			path_len = next - path_to_config;
			next++; /* Skip to the next path */
		} else {
			path_len = strlen(path_to_config);
		}

		len = path_len + 2 + strlen(service_name) + 5 + 1;
		/* XXX - shut out the warning of gcc-13.2: output may be
		 * truncated */
		len += 2;

		if (len > PATH_MAX) {
			result = SASL_FAIL;
			goto done;
		}

		/* construct the filename for the config file */
		config_filename = malloc((unsigned)len);
		if (!config_filename) {
			result = SASL_NOMEM;
			goto done;
		}

		snprintf(config_filename,
			 len,
			 "%.*s%c%s.conf",
			 (int)path_len,
			 path_to_config,
			 HIER_DELIMITER,
			 service_name);

		/* returns SASL_CONTINUE if the config file doesn't exist */
		result = sasl_config_init(config_filename);

		if (result != SASL_CONTINUE) {
			/* We are done */
			break;
		}

		if (config_filename) {
			if (access(config_filename, R_OK) != 0 &&
			    errno != ENOENT) {
				SASL_log((utils->conn,
					  SASL_LOG_WARN,
					  "xoauth2_plugin: cannot read config "
					  "file %s: %s",
					  config_filename,
					  strerror(errno)));
			}

			free(config_filename);
			config_filename = NULL;
		}

		path_to_config = next;
	}

done:
	if (config_filename)
		free(config_filename);

	return (result);
}

static const sasl_utils_t *load_config_utils;
static int load_config_result = 0;

static void load_config_once()
{
	load_config_result = load_config(load_config_utils);
}

static int xoauth2_plugin_client_mech_step1(void *_context,
					    sasl_client_params_t *params,
					    const char *serverin,
					    unsigned serverin_len,
					    sasl_interact_t **prompt_need,
					    const char **clientout,
					    unsigned *clientout_len,
					    sasl_out_params_t *oparams)
{
	const sasl_utils_t *utils = params->utils;
	struct xoauth2_plugin_client_context *context = _context;
	int err = SASL_OK;
	struct xoauth2_plugin_auth_response resp;
	int authid_wanted = 1;
	int password_wanted = 1;
	int get_from_jwt = 0;
	sasl_interact_t *prompt_returned = NULL;
	char *username = NULL;

	*clientout = NULL;
	*clientout_len = 0;

	resp.authid = NULL;
	resp.authid_len = 0;

	SASL_log((
		utils->conn, SASL_LOG_DEBUG, "xoauth2_plugin: xoauth2: step1"));

	if (!context) {
		return (SASL_BADPROT);
	}

	if (prompt_need && *prompt_need) {
		if (SASL_OK == get_prompt_value(*prompt_need,
						SASL_CB_AUTHNAME,
						&resp.authid,
						&resp.authid_len)) {
			authid_wanted = 0;
		}
	}

	if (authid_wanted) {
		err = get_cb_value(utils,
				   SASL_CB_AUTHNAME,
				   (const char **)&resp.authid,
				   &resp.authid_len);

		if (err == SASL_FAIL) {
			authid_wanted = 0;
			get_from_jwt = 1;
		} else {
			switch (err) {
			case SASL_OK:
				authid_wanted = 0;
				break;
			case SASL_INTERACT:
				break;
			default:
				goto out;
			}
		}
	}

	if (prompt_need && *prompt_need) {
		if (SASL_OK == get_prompt_value(*prompt_need,
						SASL_CB_PASS,
						(const char **)&resp.token,
						&resp.token_len)) {
			password_wanted = 0;
		}
	}

	if (password_wanted) {
		err = get_cb_value(utils,
				   SASL_CB_PASS,
				   (const char **)&resp.token,
				   &resp.token_len);
		switch (err) {
		case SASL_OK:
			password_wanted = 0;
			break;
		case SASL_INTERACT:
			break;
		default:
			goto out;
		}
	}

	if (!authid_wanted && !password_wanted) {

		if (get_from_jwt) {
			struct xoauth2_plugin_client_settings *settings =
				&xoauth2_client_settings;
			load_config_utils = utils;
			pthread_once(&load_config_initialized,
				     load_config_once);
			err = load_config_result;
			if (err == SASL_OK &&
			    (err = xoauth2_client_plug_get_options(
				     utils, settings)) == SASL_OK) {
				char user_claim[settings->user_claim_len + 1];

				strncpy(user_claim,
					settings->user_claim,
					settings->user_claim_len);
				user_claim[settings->user_claim_len] = 0;

				if (jwt_get_claim_string(resp.token,
							 user_claim,
							 &username) > 0) {
					resp.authid = username;
					resp.authid_len = strlen(username);
				} else {
					SASL_log((utils->conn,
						  SASL_LOG_ERR,
						  "xoauth2_plugin: failed to "
						  "get username claim \"%s\" "
						  "from JWT",
						  user_claim));
				}
			}
		}

		if (resp.authid == NULL) {
			SASL_log((utils->conn,
				  SASL_LOG_ERR,
				  "xoauth2_plugin: authid is not set"));
			err = SASL_FAIL;
			goto out;
		}

		err = params->canon_user(utils->conn,
					 resp.authid,
					 resp.authid_len,
					 SASL_CU_AUTHID | SASL_CU_AUTHZID,
					 oparams);
		if (err != SASL_OK) {
			goto out;
		}
		resp.token_type = "Bearer";
		resp.token_type_len = 6;
		err = build_client_response(utils, &context->outbuf, &resp);
		if (err != SASL_OK) {
			goto out;
		}
		*clientout = context->outbuf.buf;
		*clientout_len = context->outbuf.len;
		context->state = 1;
		err = SASL_CONTINUE;
	} else {
		const size_t prompts = authid_wanted + password_wanted + 1;
		sasl_interact_t *p;
		prompt_returned =
			SASL_malloc(sizeof(sasl_interact_t) * prompts);
		if (!prompt_returned) {
			SASL_log((utils->conn,
				  SASL_LOG_ERR,
				  "xoauth2_plugin: failed to allocate buffer"));
			err = SASL_NOMEM;
			goto out;
		}
		memset(prompt_returned, 0, sizeof(sasl_interact_t) * prompts);
		p = prompt_returned;
		if (authid_wanted) {
			p->id = SASL_CB_AUTHNAME;
			p->challenge = "Authentication Name";
			p->prompt = "Authentication ID";
			p->defresult = NULL;
			++p;
		}

		if (password_wanted) {
			p->id = SASL_CB_PASS;
			p->challenge = "Password";
			p->prompt = "Password";
			p->defresult = NULL;
			++p;
		}
		p->id = SASL_CB_LIST_END;
		p->challenge = NULL;
		p->prompt = NULL;
		p->defresult = NULL;
		err = SASL_INTERACT;
	}
out:
	if (prompt_need) {
		if (*prompt_need) {
			SASL_free(*prompt_need);
			*prompt_need = NULL;
		}
		if (prompt_returned) {
			*prompt_need = prompt_returned;
		}
	}
	free(username);
	return (err);
}

static int xoauth2_plugin_client_mech_step2(void *_context,
					    sasl_client_params_t *params,
					    const char *serverin,
					    unsigned serverin_len,
					    sasl_interact_t **prompt_need,
					    const char **clientout,
					    unsigned *clientout_len,
					    sasl_out_params_t *oparams)
{
	const sasl_utils_t *utils = params->utils;
	struct xoauth2_plugin_client_context *context = _context;

	*clientout = NULL;
	*clientout_len = 0;

	SASL_log((
		utils->conn, SASL_LOG_DEBUG, "xoauth2_plugin: xoauth2: step2"));

	if (!context) {
		return (SASL_BADPROT);
	}

	*clientout = "";
	*clientout_len = 0;

	context->state = 2;
	return (SASL_OK);
}

static int xoauth2_plugin_client_mech_step(void *_context,
					   sasl_client_params_t *params,
					   const char *serverin,
					   unsigned serverin_len,
					   sasl_interact_t **prompt_need,
					   const char **clientout,
					   unsigned *clientout_len,
					   sasl_out_params_t *oparams)
{
	struct xoauth2_plugin_client_context *context = _context;

	switch (context->state) {
	case 0:
		return (xoauth2_plugin_client_mech_step1(context,
							 params,
							 serverin,
							 serverin_len,
							 prompt_need,
							 clientout,
							 clientout_len,
							 oparams));
	case 1:
		return (xoauth2_plugin_client_mech_step2(context,
							 params,
							 serverin,
							 serverin_len,
							 prompt_need,
							 clientout,
							 clientout_len,
							 oparams));
	}
	return (SASL_BADPROT);
}

static void xoauth2_plugin_client_mech_dispose(void *_context,
					       const sasl_utils_t *utils)
{
	struct xoauth2_plugin_client_context *context = _context;

	sasl_config_done();
	load_config_initialized = PTHREAD_ONCE_INIT;

	if (!context) {
		return;
	}

	xoauth2_plugin_str_free(utils, &context->outbuf);
	SASL_free(context);
}

static sasl_client_plug_t xoauth2_client_plugins[] = {{
	"XOAUTH2",					  /* mech_name */
	0,						  /* max_ssf */
	SASL_SEC_NOANONYMOUS | SASL_SEC_PASS_CREDENTIALS, /* security_flags */
	SASL_FEAT_WANT_CLIENT_FIRST | SASL_FEAT_ALLOWS_PROXY, /* features */
	NULL,				     /* required_prompts */
	NULL,				     /* glob_context */
	&xoauth2_plugin_client_mech_new,     /* mech_new */
	&xoauth2_plugin_client_mech_step,    /* mech_step */
	&xoauth2_plugin_client_mech_dispose, /* mech_dispose */
	NULL,				     /* mech_free */
	NULL,				     /* idle */
	NULL,				     /* spare */
	NULL				     /* spare */
} };

int xoauth2_client_plug_init(const sasl_utils_t *utils,
			     int maxversion,
			     int *out_version,
			     sasl_client_plug_t **pluglist,
			     int *plugcount)
{
	if (maxversion < SASL_CLIENT_PLUG_VERSION) {
		SASL_seterror((utils->conn, 0, "xoauth2: version mismatch"));
		return (SASL_BADVERS);
	}
	*out_version = SASL_CLIENT_PLUG_VERSION;
	*pluglist = xoauth2_client_plugins;
	*plugcount = sizeof(xoauth2_client_plugins) /
		     sizeof(*xoauth2_client_plugins);
	load_config_initialized = PTHREAD_ONCE_INIT;

	return (SASL_OK);
}
