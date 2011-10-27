/*
** Copyright (C) 2010,2011 - Hagen Paul Pfeifer <hagen@jauu.net>
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


const char *type_015_mx_text(void)
{
	return "type 015 mx";
}


int type_015_mx_cache_cmp(const struct cache_data *aa,
		const struct cache_data *bb)
{
	if (aa->key_len != bb->key_len)
		return 0;

	/* FIXME: implement a proper MX data handling:
	 * add a precedence field to the data and compare here */

	return !memcmp(aa->key, bb->key, aa->key_len);
}


/* MX +86400 example.net. 10 a.example.net. */
struct cache_data *type_015_mx_zone_parser_to_cache_data(struct ctx *ctx, char *line)
{

	char *ptr = line;
	int ret, n, mx_priority;
	struct cache_data *cd;
        char zone_str[MAX_HOSTNAME_STR + 1];
	char mx_str[INET6_ADDRSTRLEN + 1];
	int timeval = DEFAULT_TTL; /* time in seconds */

	(void) ctx;

	if (ptr[0] == '+')
		ptr = parse_ttl(ptr, &timeval);

        /* parse zonename */
        ret = sscanf(ptr, "%255[^ \t]%n", zone_str, &n);
        if (ret != 1)
                err_msg_die(EXIT_FAILCONF, "malformed zone string: \"%s\"", ptr);

	if (zone_str[n - 1] != '.')
		err_msg_die(EXIT_FAILCONF, "malformed zone: "
				"\"%s\" - trailing dot missing", ptr);

        ptr += n; /* point to the first whitespace */
        ptr = eat_whitespaces(ptr);

        /* parse mx prioryty */
        ret = sscanf(ptr, "%d", &mx_priority);
        if (ret != 1)
                err_msg_die(EXIT_FAILCONF, "malformed prioryty string: \"%s\"", ptr);

        /* parse mx name */
        ret = sscanf(ptr, "%255[^ \t]%n", mx_str, &n);
        if (ret != 1)
                err_msg_die(EXIT_FAILCONF, "malformed mx string: \"%s\"", ptr);

        pr_debug("MX record: ttl: %d zone: %s priority: %d mx server: %s",
			timeval, zone_str, mx_priority, mx_str);

	/* FIXME convert into something valuable */
	cd = cache_data_create(DNS_TYPE_MX, DNS_CLASS_INET, timeval, zone_str, strlen(zone_str) + 1);

	return cd;

}


void type_015_mx_free_cache_data(struct ctx *ctx, struct cache_data *cd)
{
	(void) ctx;
	(void) cd;
}
