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


const char *type_001_a_text(void)
{
	return "type 001 a";
}


/* A +86400 a.example.net. 192.168.1.1 */
struct cache_data *type_001_a_zone_parser_to_cache_data(struct ctx *ctx, char *line)
{

	char *ptr = line;
	int ret, n;
	struct cache_data *cd;
	struct in_addr addr;
	char host_str[MAX_HOSTNAME_STR + 1];
	char ip_str[INET_ADDRSTRLEN + 1];
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
	ret = sscanf(ptr, "%16[^ \t]%n", ip_str, &n);
	if (ret != 1)
		err_msg_die(EXIT_FAILCONF, "malformed ip string: \"%s\"", ptr);

	ret = inet_pton(AF_INET, ip_str, &addr);
	if (ret <= 0)
		err_msg_die(EXIT_FAILCONF, "malformed ipv4 string: \"%s\"", ip_str);

	pr_debug("A record: ttl: %d hostname: %s ipv4: %s", timeval, host_str, ip_str);

	cd = cache_data_create(DNS_TYPE_A, DNS_CLASS_INET, timeval, host_str, strlen(host_str) + 1);

	/* save IP address */
	memcpy(&cd->v4addr, &addr, sizeof(cd->v4addr));

	return cd;

}


void type_001_a_free_cache_data(struct cache_data *cd)
{
	(void) cd;
}
