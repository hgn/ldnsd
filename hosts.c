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

#include "cachefor.h"
#include "hosts.h"

#include <stdio.h>
#include <stdlib.h>

#define	ERROR_CODE_NO_ERROR 0
#define	ERROR_CODE_FILE     1
#define	ERROR_CODE_ARGUMENT 2
#define	ERROR_CODE_MEMORY   3
#define	ERROR_CODE_INTERNAL 4

#define	MAX_LINE_SIZE 4096

#define	MAX_ALIASES 16


static const struct err_code_table {
	const int code;
	const char *str;
} err_code_strings[] =
{
	{ ERROR_CODE_NO_ERROR, "no error" },
	{ ERROR_CODE_FILE,     "error in open file" },
	{ ERROR_CODE_ARGUMENT, "error in argument to this function" },
	{ ERROR_CODE_MEMORY,   "error in allocation memory" },
	{ ERROR_CODE_INTERNAL, "internal error in hosts_info_get_by_name()" },
};


/* hosts_info_get_by_name parses a UNIX like hosts file in
 * the following format:
 * IP_address canonical_hostname [aliases...]
 *
 * see RFC 592 and the manual pages for hosts(5), hostname(1),
 * resolver(3), resolver(5), hostname(7) */
int hosts_info_get_by_name(const char *filename,
		const char *hostname, size_t hostname_len, struct hosts_info **res)
{
	FILE *file;
	int i;
	char line_buf[MAX_LINE_SIZE + 1], white_spaces[] = " \t\n";
	char fileentry[MAX_LINE_SIZE];
	char *buf, *cp;
	char *alias_array[MAX_ALIASES];
	int alias_index;
	char *domain_name, *addr_name;
	struct hosts_info *hi, *hi_prev;

	hi = hi_prev = *res = NULL;

	if (filename == NULL || hostname == NULL || hostname_len <= 0)
		return -ERROR_CODE_ARGUMENT;

	file = fopen(filename, "r");
	if (!file)
		return -ERROR_CODE_FILE;


	while (fgets(line_buf, MAX_LINE_SIZE, file) != NULL) {

		buf = cp = NULL;

		/* skip comments */
		if (line_buf[0] == '#')
			continue;

		cp = strtok_r(line_buf, "#", &buf);
		if (!cp)
			continue;

		memset(fileentry, 0, MAX_LINE_SIZE);
		strncpy(fileentry, cp, MAX_LINE_SIZE);

		/* IPv{4,6} address */
		cp = strtok_r(fileentry, white_spaces, &buf);
		if (!cp)
			continue;

		addr_name = cp;


		/* full domain name */
		cp = strtok_r(NULL, white_spaces, &buf);
		if (!cp)
			continue;

		domain_name = cp;

		if (!strcasecmp(domain_name, hostname)) {
			struct addrinfo hosthints, *hostres;

			hi = xzalloc(sizeof(*hi));
			hi->name = xstrdup(domain_name);
			hi->type = HOST_INFO_TYPE_DOMAIN;
			hi->addr_str = xstrdup(addr_name);

			/* validate address and convert into sockaddr_storage */
			memset(&hosthints, 0, sizeof(hosthints));
			hosthints.ai_family   = AF_UNSPEC;
			hosthints.ai_flags    = AI_NUMERICHOST;

			xgetaddrinfo(addr_name, NULL, &hosthints, &hostres);
			if (hostres != NULL) {
				memcpy(&hi->addr, &hostres->ai_addr, hostres->ai_addrlen);
				hi->addr_len = hostres->ai_addrlen;
				hi->family = hostres->ai_family;
			}

			hi->next = NULL;

			freeaddrinfo(hostres);

			hi_prev = *res = hi;
		}

		/* iterate over all aliases */
		alias_index = 0;
		while (((cp = strtok_r(NULL, white_spaces, &buf)) != NULL) &&
				alias_index < MAX_ALIASES) {

			if (!strcasecmp(cp, hostname)) {
				alias_array[alias_index++] = cp;
			}
		}

		for (i = 0; i < alias_index; i++) {
			struct addrinfo hosthints, *hostres;

			hi = xzalloc(sizeof(*hi));
			hi->name = xstrdup(alias_array[i]);
			hi->type = HOST_INFO_TYPE_ALIAS;
			hi->addr_str = xstrdup(addr_name);

			if (hi_prev)
				hi_prev->next = hi;

			/* validate address and convert into sockaddr_storage */
			memset(&hosthints, 0, sizeof(hosthints));
			hosthints.ai_family   = AF_UNSPEC;
			hosthints.ai_flags    = AI_NUMERICHOST;

			xgetaddrinfo(addr_name, NULL, &hosthints, &hostres);
			if (hostres != NULL) {
				memcpy(&hi->addr, &hostres->ai_addr, hostres->ai_addrlen);
				hi->addr_len = hostres->ai_addrlen;
				hi->family = hostres->ai_family;
			}

			hi->next = NULL;

			freeaddrinfo(hostres);

			if (*res == NULL)
				*res = hi;

			hi_prev = hi;
		}

		hi->next = NULL;

	}

	fclose(file);

	return SUCCESS;
}


int hosts_info_get_by_address(const char *filename,
	struct sockaddr_storage *address, socklen_t address_len, struct hosts_info **res)
{
	return FAILURE;
}


void hosts_info_free(struct hosts_info *hi)
{
	struct hosts_info *hi_tmp, *hi_prev;

	if (!hi)
		return;

	hi_tmp = hi;

	while (hi_tmp != NULL) {

		if (hi_tmp->name) free(hi_tmp->name);
		if (hi_tmp->addr_str) free(hi_tmp->addr_str);

		hi_prev = hi_tmp;

		hi_tmp = hi_tmp->next;

		free(hi_prev); hi_prev = NULL;
	}
}


const char *hosts_info_strerror(int errcode)
{
	errcode = -errcode;

	if (errcode < 0 || errcode >= (int)ARRAY_SIZE(err_code_strings))
		errcode = ERROR_CODE_NO_ERROR;

	return err_code_strings[errcode].str;
}


/* vim: set tw=78 ts=4 sw=4 sts=4 ff=unix noet: */
