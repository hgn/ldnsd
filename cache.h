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

#ifndef CACHE_H
#define	CACHE_H

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <time.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/types.h>

#include "ldnsd.h"

struct cache_data *cache_data_create(uint16_t, uint16_t, uint32_t, char *, size_t);
struct cache_data *cache_data_create_private(uint16_t, uint16_t, uint32_t, char *, size_t, void *);
void cache_data_free(void *);
int cache_data_cmp(const void *a, const void *b);
int cache_data_key_cmp(const void *a, const void *b);


/* cache-memory.c */
int cache_memory_init(struct ctx *);
int cache_memory_free(struct ctx *);
int cache_memory_add(struct ctx *, struct cache_data *);
int cache_memory_remove(struct ctx *, struct dns_pdu *);
int cache_memory_get(struct ctx *, uint16_t type, uint16_t class, char *key, size_t key_len, struct cache_data **cd);


#endif /* CACHE_H */
