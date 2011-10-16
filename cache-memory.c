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

int cache_memory_init(struct ctx *ctx)
{
	(void) ctx;

	return SUCCESS;
}

int cache_memory_free(struct ctx *ctx)
{
	(void) ctx;

	return SUCCESS;
}

int cache_memory_add(struct ctx *ctx, struct dns_pdu *key, struct dns_pdu *res)
{
	(void) ctx;
	(void) key;
	(void) res;

	return SUCCESS;
}

int cache_memory_remove(struct ctx *ctx, struct dns_pdu *key)
{
	(void) ctx;
	(void) key;

	return SUCCESS;
}

int cache_memory_get(struct ctx *ctx, struct dns_pdu *key, struct dns_pdu *ret_pdu)
{
	(void) ctx;
	(void) key;
	(void) ret_pdu;

	return SUCCESS;
}
