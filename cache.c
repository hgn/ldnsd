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

struct cache_data *cache_data_create(uint16_t type, uint16_t class, uint32_t ttl,
		char *key, size_t key_len)
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


int cache_data_cmp(const void *a, const void *b)
{
	const struct cache_data *aa, *bb;

	assert(a);
	assert(b);

	aa = a; bb = b;

	if (aa->type != bb->type || aa->class != bb->class)
		return 0;

	return type_fn_table[type_opts_to_index(aa->type)].cache_cmp(aa, bb);
}


void cache_data_free(void *arg)
{
	struct cache_data *cd = arg;

	assert(arg);

	/* cd->priv is freed be caller */

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
