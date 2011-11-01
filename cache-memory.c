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

struct cache_memory_private {
	struct list *data_list;
};

int cache_memory_init(struct ctx *ctx)
{
	struct cache_memory_private *cmp;

	assert(!ctx->cache);

	pr_debug("initialize memory cache");

	cmp = xmalloc(sizeof(*cmp));

	ctx->cache = cmp;

	cmp->data_list = list_create(cache_data_cmp, cache_data_free);
	if (!cmp->data_list)
		err_sys_die(EXIT_FAILMEM, "Failed to initialize cache memory backend");

	return SUCCESS;
}

int cache_memory_free(struct ctx *ctx)
{
	struct list *list = ((struct cache_memory_private *)ctx->cache)->data_list;

	list_destroy(list);
	free(ctx->cache);

	return SUCCESS;
}

int cache_memory_add(struct ctx *ctx, struct cache_data *cd)
{
	int ret;
	struct list *data_list;

	data_list = ((struct cache_memory_private *)ctx->cache)->data_list;

	ret = list_insert(data_list, cd);
	if (ret != SUCCESS) {
		err_msg("Failed to add entry to database");
		return FAILURE;
	}

	return SUCCESS;
}


int cache_memory_remove(struct ctx *ctx, struct dns_pdu *key)
{
	(void) ctx;
	(void) key;

	return SUCCESS;
}


int cache_memory_get(struct ctx *ctx,  uint16_t type, uint16_t class,
		char *key, size_t key_len, struct cache_data **cd)
{
	int ret, gret = FAILURE;
	struct list_element *ele;
	struct cache_data *tmp_cd;
	struct list *data_list;
	uint32_t random_ttl;

	data_list = ((struct cache_memory_private *)ctx->cache)->data_list;

	/* ttl is uninteresting here because
	 * in cache_data_key_cmp() only type,
	 * class, key_len and the key is compared.
	 * All other fields, especially record type
	 * specific fields are ignored. Of course:
	 * if we source the cache for a specific key
	 * we search then because we wan't the value. */
	random_ttl = 0;

	tmp_cd = cache_data_create(type, class, random_ttl, key, key_len);
	if (!tmp_cd) {
		err_msg("Cannot create new container type for database");
		return FAILURE;
	}

	for (ele = list_head(data_list); ele != NULL; ele = list_next(ele)) {
		*cd = list_data(ele);
		ret = cache_data_key_cmp((const void *)*cd, (const void *)tmp_cd);
		if (ret == 1) { /* found entry */
			gret = SUCCESS;
			goto out;
		}
	}

out:
	cache_data_free(tmp_cd);
	return gret;
}
