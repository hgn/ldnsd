/*
** Copyright (C) 2010, 2011 - Hagen Paul Pfeifer <hagen@jauu.net>
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

/* fixed size for type AAAA */
#define	DNS_TYPE_AAAA_LEN 16

/* cache private data */
struct cache_data_type_aaaa {
	struct in6_addr addr;
};

struct type_028_aaaa_data {
	uint16_t type;
	uint16_t class;
	uint32_t ttl;
	uint16_t length;
	struct in6_addr addr;
} __attribute__((__packed__));


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

	assert(aa);
	assert(bb);

	return !memcmp(&aa->addr, &bb->addr, sizeof(aa->addr));
}



/* AAAA +86400 a.example.net. 2001:0DB8:: */
struct cache_data *type_028_aaaa_zone_parser_to_cache_data(struct ctx *ctx, char *line)
{

	int ret, n;
	char *ptr = line;
	struct cache_data_type_aaaa *cd_aaaa;
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


	cd_aaaa = xmalloc(sizeof(*cd_aaaa));

	ret = inet_pton(AF_INET6, ip_str, &cd_aaaa->addr);
	if (ret <= 0)
		err_msg_die(EXIT_FAILCONF, "malformed ipv6 string: \"%s\"", ip_str);

	if (IN6_IS_ADDR_UNSPECIFIED(&cd_aaaa->addr))
		err_msg_die(EXIT_FAILCONF, "unspecific ipv6 address not "
				" allowed: \"%s\"", ip_str);

        pr_debug("AAAA record: ttl: %d hostname: %s ipv6: %s", timeval, host_str, ip_str);

	cd = cache_data_create_private(DNS_TYPE_AAAA, DNS_CLASS_INET,
			timeval, host_str, strlen(host_str) + 1, cd_aaaa);

	assert(cache_data_priv(cd));

	cd->rdlength = sizeof(struct in6_addr);

	return cd;
}

int type_028_aaaa_create_sub_section(struct ctx *ctx, struct cache_data *cd,
		struct dns_journey *dnsj)
{
	struct type_028_aaaa_data *type_028_aaaa_data;
	struct cache_data_type_aaaa *cache_data_type_aaaa;


	assert(ctx);
	assert(cd);
	assert(dnsj);

	assert(cd->type == DNS_TYPE_AAAA);

	dnsj->p_res_dns_pdu = alloc_dns_pdu();

	/* FIXME */
	dnsj->p_res_dns_pdu->answers = 1;
	dnsj->p_res_dns_pdu->answers_section = xzalloc(sizeof(struct dns_sub_section *) * 1);
	dnsj->p_res_dns_pdu->answers_section[0] = xzalloc(sizeof(struct dns_sub_section));

	/* a pointer to the entire answer section */
	dnsj->p_res_dns_pdu->answers_section_len = 16 + 12;
	dnsj->p_res_dns_pdu->answer_data = xzalloc(16 + 12);

	dnsj->p_res_dns_pdu->answers_section_ptr = dnsj->p_res_dns_pdu->answer_data;

	/* construct meta-data */
	dnsj->p_res_dns_pdu->answers_section[0]->name = xmalloc(cd->key_len);

	memcpy(dnsj->p_res_dns_pdu->answers_section[0]->name, cd->key, cd->key_len);

	dnsj->p_res_dns_pdu->answers_section[0]->type     = cd->type;
	dnsj->p_res_dns_pdu->answers_section[0]->class    = cd->class;
	dnsj->p_res_dns_pdu->answers_section[0]->ttl      = cd->ttl;
	dnsj->p_res_dns_pdu->answers_section[0]->rdlength = cd->rdlength;

	/* construct wire data, point to question string */
	dnsj->p_res_dns_pdu->answer_data[0] = 0xc0;
	dnsj->p_res_dns_pdu->answer_data[1] = 0x0c;

	type_028_aaaa_data = (struct type_028_aaaa_data *)&dnsj->p_res_dns_pdu->answer_data[2];

	type_028_aaaa_data->type   = htons(DNS_TYPE_AAAA);
	type_028_aaaa_data->class  = htons(DNS_CLASS_INET);
	type_028_aaaa_data->ttl    = htonl(cd->ttl);
	type_028_aaaa_data->length = htons(DNS_TYPE_AAAA_LEN);

	cache_data_type_aaaa = cache_data_priv(cd);

	memcpy(&type_028_aaaa_data->addr, &cache_data_type_aaaa->addr,
			sizeof(type_028_aaaa_data->addr));

	return SUCCESS;
}


void type_028_aaaa_free_cache_data(struct cache_data *cd)
{
	struct cache_data_type_aaaa *cd_aaaa;

	assert(cd);

	/* think about that cache data structures
	 * are used for two purposes:
	 * 1. as a normal storage container
	 * 2. as a temporary search key container where
	 *    no data is attached, just the key. Therefore
	 *    the free function must take care of this. */
	cd_aaaa = cache_data_priv(cd);
	if (cd_aaaa)
		xfree(cd_aaaa);

	xfree(cd_aaaa);
}
