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


const char *type_028_aaaa_text(void)
{
	return "type 028 aaaa";
}


/* AAAA +86400 a.example.net. 2001:0DB8:: */
struct cache_data *type_028_aaaa_zone_parser_to_cache_data(struct ctx *ctx, char *line)
{

	int ret, n;
	char *ptr = line;
	struct cache_data *cd;
	char host_str[MAX_HOSTNAME_STR + 1];
	char ip_str[INET6_ADDRSTRLEN + 1];
	int timeval = DEFAULT_TTL; /* time in seconds */

	(void) ctx;

	if (ptr[0] == '+')
		ptr = parse_ttl(ptr, &timeval);

	/* parse hostname */
	ret = sscanf(ptr, "%255[^ \t]%n", host_str, &n);
	if (ret != 1)
		err_msg_die(EXIT_FAILCONF, "malformed hostname string: \"%s\"", ptr);

	if (host_str[n - 1] != '.')
		err_msg_die(EXIT_FAILCONF, "malformed hostname: "
				"\"%s\" - trailing dot missing", ptr);

	ptr += n; /* point to the first whitespace */
	ptr = eat_whitespaces(ptr);

	/* parse ip */
	ret = sscanf(ptr, "%46[^ \t]%n", ip_str, &n);
	if (ret != 1)
		err_msg_die(EXIT_FAILCONF, "malformed IPv6 string: \"%s\"", ptr);

	/* check if the ip is clean */
	if (!(ip_valid_addr(AF_INET6, ip_str)))
		err_msg_die(EXIT_FAILCONF, "malformed ipv6 string: \"%s\"", ip_str);

        pr_debug("AAAA record: ttl: %d hostname: %s ipv6: %s", timeval, host_str, ip_str);

	cd = cache_data_create(DNS_TYPE_AAAA, DNS_CLASS_INET, timeval, host_str, strlen(host_str) + 1);

	return cd;

}


void type_028_aaaa_free_cache_data(struct ctx *ctx, struct cache_data *cd)
{
	(void) ctx;
	(void) cd;
}
