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

int cache_add(struct ctx *ctx, struct dns_pdu *key, struct dns_pdu *res)
{
	switch (ctx->cache_backend) {
		case CACHE_BACKEND_NONE:
			return SUCCESS;
			break;
		case CACHE_BACKEND_MEMORY:
			return cache_memory_add(ctx, key, res);
			break;
		default:
			err_msg_die(EXIT_FAILMISC,
				"programmed error: cache strategy not supported");
	}

	return SUCCESS;
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

int cache_get(struct ctx *ctx, struct dns_pdu *key, struct dns_pdu *ret_pdu)
{
	switch (ctx->cache_backend) {
		case CACHE_BACKEND_NONE:
			return FAILURE;
			break;
		case CACHE_BACKEND_MEMORY:
			return cache_memory_get(ctx, key, ret_pdu);
			break;
		default:
			err_msg_die(EXIT_FAILMISC,
				"programmed error: cache strategy not supported");
	}

	return SUCCESS;
}
