/*
** Copyright (C) 2011 - Hagen Paul Pfeifer <hagen@jauu.net>
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License as published by
** the Free Software Foundation; either version 2 of the License, or
** (at your option) any later version.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/

#include "ldnsd.h"
#include "cache.h"

struct cache_data *cache_data_create(uint16_t type, uint16_t class,
		uint32_t ttl, char *key, size_t key_len)
{
	struct cache_data *cd;

	assert(key_len > 0);

	cd = xzalloc(sizeof(*cd));

	cd->type = type;
	cd->class = class;
	cd->ttl = ttl;

	cd->key_len = key_len;
	cd->key = xmalloc(key_len);
	memcpy(cd->key, key, key_len);

	return cd;
}


struct cache_data *cache_data_create_private(uint16_t type, uint16_t class,
		uint32_t ttl, char *key, size_t key_len, void *priv_data)
{
	struct cache_data *cd = cache_data_create(type, class, ttl, key, key_len);
	cache_data_priv(cd) = priv_data;

	return cd;
}


/* key compare function, sufficient for search functions where
 * type, class and key must be equal. The key compare function
 * is independent from type specific data (like MX precedence,
 * where the full compare function compare the whole data set.
 *
 * Return true when equal, false otherwise */
int cache_data_key_cmp(const void *a, const void *b)
{
	const struct cache_data *aa, *bb;
	size_t cmp_len;

	assert(a);
	assert(b);

	aa = a; bb = b;

	if (aa->type != bb->type || aa->class != bb->class)
		return 0;

	/* ignore the trailing dot, if present in
	 * query or database. Later this should be
	 * adjusted depending on the final dot (FQDN)
	 * for queries */
	if (aa->key[aa->key_len - 2] == '.')
		cmp_len = aa->key_len - 3;
	else {
		if (aa->key_len != bb->key_len)
			return 0;

		cmp_len = aa->key_len;
	}

	if (memcmp(aa->key, bb->key, cmp_len))
		return 0;

	return 1;
}


/* full data compare function, used to validate a data set complete
 * like MX precedence and zone name. Every type MUST implement a own
 * compare function */
int cache_data_cmp(const void *a, const void *b)
{
	int ret;
	const struct cache_data *aa, *bb;

	ret = cache_data_key_cmp(a, b);
	if (!ret)
		return 0;

	aa = a;
	bb = b;

	return type_fn_table[type_opts_to_index(aa->type)].cache_cmp(aa, bb);
}


void cache_data_free(void *arg)
{
	struct cache_data *cd = arg;

	assert(arg);
	assert(type_fn_table[type_opts_to_index(cd->type)].free_cache_priv_data);

	type_fn_table[type_opts_to_index(cd->type)].free_cache_priv_data(cd);
	xfree(cd->key);
	xfree(cd);
}


int cache_init(struct ctx *ctx)
{
	switch (ctx->cache_backend) {
		case CACHE_BACKEND_NONE:
			pr_debug("initialize cache backend \"none\"");
			return SUCCESS;
			break;
		case CACHE_BACKEND_MEMORY:
			pr_debug("initialize cache backend \"memory\"");
			return cache_memory_init(ctx);
			break;
		default:
			err_msg_die(EXIT_FAILMISC,
				"programmed error: cache strategy not supported");
	}

	return SUCCESS;
}


int cache_free(struct ctx *ctx)
{
	switch (ctx->cache_backend) {
		case CACHE_BACKEND_NONE:
			pr_debug("free none cache backend");
			return SUCCESS;
			break;
		case CACHE_BACKEND_MEMORY:
			pr_debug("free cache backend \"memory\"");
			return cache_memory_free(ctx);
			break;
		default:
			err_msg_die(EXIT_FAILMISC,
				"programmed error: cache strategy not supported");
	}

	return SUCCESS;
}


int cache_add(struct ctx *ctx, struct cache_data *cd)
{
	switch (ctx->cache_backend) {
		case CACHE_BACKEND_NONE:
			return SUCCESS;
			break;
		case CACHE_BACKEND_MEMORY:
			return cache_memory_add(ctx, cd);
			break;
		default:
			err_msg_die(EXIT_FAILMISC,
				"programmed error: cache strategy not supported");
	}

	return FAILURE;
}


int cache_remove(struct ctx *ctx, struct dns_pdu *key)
{
	switch (ctx->cache_backend) {
		case CACHE_BACKEND_NONE:
			return FAILURE;
			break;
		case CACHE_BACKEND_MEMORY:
			return cache_memory_remove(ctx, key);
			break;
		default:
			err_msg_die(EXIT_FAILMISC,
				"programmed error: cache strategy not supported");
	}

	return SUCCESS;
}


int cache_get(struct ctx *ctx, uint16_t type, uint16_t class,
		char *key, size_t key_len, struct cache_data **cd)
{
	switch (ctx->cache_backend) {
		case CACHE_BACKEND_NONE:
			return FAILURE;
			break;
		case CACHE_BACKEND_MEMORY:
			return cache_memory_get(ctx, type, class, key, key_len, cd);
			break;
		default:
			err_msg_die(EXIT_FAILMISC,
				"programmed error: cache strategy not supported");
	}

	return SUCCESS;
}
