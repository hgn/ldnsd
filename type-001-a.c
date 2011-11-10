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

/* fixed size for type A */
#define	DNS_TYPE_A_LEN 4

struct type_001_a_data {
	uint16_t type;
	uint16_t class;
	uint32_t ttl;
	uint16_t length;
	uint32_t addr;
} __attribute__((__packed__));


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
	cd->rdlength = 4;

	return cd;

}


int type_001_a_create_sub_section(struct ctx *ctx,
		struct cache_data *cd, struct dns_journey *dnsj)
{
	struct type_001_a_data *type_001_a_data;

	assert(ctx);
	assert(cd);
	assert(dnsj);
	assert(cd->type == DNS_TYPE_A);

	dnsj->p_res_dns_pdu = alloc_dns_pdu();

	/* FIXME */
	dnsj->p_res_dns_pdu->answers = 1;
	dnsj->p_res_dns_pdu->answers_section = xzalloc(sizeof(struct dns_sub_section *) * 1);
	dnsj->p_res_dns_pdu->answers_section[0] = xzalloc(sizeof(struct dns_sub_section));

	/* a pointer to the entire answer section */
	dnsj->p_res_dns_pdu->answers_section_len = 16;
	dnsj->p_res_dns_pdu->answer_data = xzalloc(16);

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

	type_001_a_data = (struct type_001_a_data *)&dnsj->p_res_dns_pdu->answer_data[2];

	type_001_a_data->type = htons(DNS_TYPE_A);
	type_001_a_data->class = htons(DNS_CLASS_INET);
	type_001_a_data->ttl = htonl(cd->ttl);
	type_001_a_data->length = htons(DNS_TYPE_A_LEN);
	memcpy(&type_001_a_data->addr, &cd->v4addr, sizeof(cd->v4addr));

	return SUCCESS;
}


void type_001_a_free_cache_data(struct cache_data *cd)
{
	(void) cd;
}
