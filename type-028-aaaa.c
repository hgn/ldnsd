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

/* cache private data */
struct cache_data_type_aaaa {
	struct in6_addr addr;
};


const char *type_028_aaaa_text(void)
{
	return "type 028 aaaa";
}


/* true if equal, false if unequal */
int type_028_aaaa_cache_cmp(const struct cache_data *a,
		const struct cache_data *b)
{
	struct cache_data_type_aaaa *aa, *bb;


	if (a->key_len != b->key_len)
		return 0;

	if (!strcaseeq(a->key, b->key))
		return 0;

	aa = cache_data_priv(a);
	bb = cache_data_priv(b);

	return !memcmp(&aa->addr, &bb->addr, sizeof(aa->addr));
}



/* AAAA +86400 a.example.net. 2001:0DB8:: */
struct cache_data *type_028_aaaa_zone_parser_to_cache_data(struct ctx *ctx, char *line)
{

	int ret, n;
	char *ptr = line;
	struct cache_data_type_aaaa *cd_aaaa;
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


	cd_aaaa = xmalloc(sizeof(*cd_aaaa));

	ret = inet_pton(AF_INET6, ip_str, &cd_aaaa->addr);
	if (ret <= 0)
		err_msg_die(EXIT_FAILCONF, "malformed ipv6 string: \"%s\"", ip_str);

        pr_debug("AAAA record: ttl: %d hostname: %s ipv6: %s", timeval, host_str, ip_str);

	return cache_data_create_private(DNS_TYPE_AAAA, DNS_CLASS_INET,
			timeval, host_str, strlen(host_str) + 1, cd_aaaa);

}


void type_028_aaaa_free_cache_data(struct cache_data *cd)
{
	struct cache_data_type_aaaa *cd_aaaa;

	assert(cd);

	cd_aaaa = cache_data_priv(cd);
	assert(cd_aaaa);

	xfree(cd_aaaa);
}
