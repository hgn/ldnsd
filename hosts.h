/*
** Copyright (C) 2010 - Hagen Paul Pfeifer <hagen@jauu.net>
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

#ifndef XHOSTS_H
#define	XHOSTS_H

#include <sys/socket.h> /* sockaddr_storage */

enum host_info_type {
	HOST_INFO_TYPE_DOMAIN = 1,
	HOST_INFO_TYPE_ALIAS,
};

struct hosts_info {
	char *name;
	int family;
	struct sockaddr_storage addr;
	socklen_t addr_len;
	char *addr_str;
	int type;
	struct hosts_info *next;
};

int hosts_info_get_by_address(const char *, struct sockaddr_storage *, socklen_t, struct hosts_info **);
int hosts_info_get_by_name(const char *, const char *, size_t, struct hosts_info **);
void hosts_info_free(struct hosts_info *);
const char *hosts_info_strerror(int);

#endif /* XHOSTS_H */
