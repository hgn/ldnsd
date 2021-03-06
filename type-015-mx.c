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
struct cache_data_type_mx {
	char *domain_name;
	uint16_t preference;
};

/* binary, over-the-air encoding */
struct type_015_mx_data {
};


const char *type_015_mx_text(void)
{
	return "type 015 mx";
}


/* true if equal, false if unequal */
int type_015_mx_cache_cmp(const struct cache_data *a,
		const struct cache_data *b)
{
	struct cache_data_type_mx *aa, *bb;


	if (a->key_len != b->key_len)
		return 0;

	if (!strcaseeq(a->key, b->key))
		return 0;

	aa = cache_data_priv(a);
	bb = cache_data_priv(b);

	if (aa->preference != bb->preference)
		return 0;

	assert(aa->domain_name);
	assert(bb->domain_name);

	if (!strcaseeq(aa->domain_name, bb->domain_name))
		return 0;

	return 1;
}


static int check_preference(int preference)
{
	if (preference < 0 || preference > UINT16_MAX)
		return FAILURE;

	return SUCCESS;
}


/* MX +86400 example.net. 10 a.example.net. */
struct cache_data *type_015_mx_zone_parser_to_cache_data(struct ctx *ctx, char *line)
{

	char *ptr = line;
	int ret, n, mx_priority;
	struct cache_data_type_mx *cd_mx;
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

	ret = check_preference(mx_priority);
	if (ret != SUCCESS)
                err_msg_die(EXIT_FAILCONF, "preference value must be a valid "
				" uint16_t: \"%d\"", mx_priority);

        /* parse mx name */
        ret = sscanf(ptr, "%255[^ \t]%n", mx_str, &n);
        if (ret != 1)
                err_msg_die(EXIT_FAILCONF, "malformed mx string: \"%s\"", ptr);

        pr_debug("MX record: ttl: %d zone: %s priority: %d mx server: %s",
			timeval, zone_str, mx_priority, mx_str);

	cd_mx = xmalloc(sizeof(*cd_mx));
	cd_mx->preference = (uint16_t) mx_priority;
	cd_mx->domain_name = xstrdup(mx_str);

	return cache_data_create_private(DNS_TYPE_MX, DNS_CLASS_INET,
			timeval, zone_str, strlen(zone_str) + 1, cd_mx);
}


int type_015_mx_create_sub_section(struct ctx *ctx, struct cache_data *cd,
		struct dns_journey *dnsj)
{
	int ret;
	struct type_015_mx_data *type_015_mx_data;
	struct cache_data_type_mx *cache_data_type_mx;

	assert(ctx);
	assert(cd);
	assert(dnsj);

	assert(cd->type == DNS_TYPE_MX);

	ret = construct_self_crafted_p_res_dns_pdu(ctx, dnsj, 1,
			sizeof(struct type_015_mx_data) + 2);
	if (ret != SUCCESS) {
		err_msg("Failed to contruct self crafted answer pdu");
		return FAILURE;
	}

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

	type_015_mx_data = (struct type_015_mx_data *)&dnsj->p_res_dns_pdu->answer_data[2];

	//FIXME
#if 0
	type_015_mx_data->type   = htons(DNS_TYPE_MX);
	type_015_mx_data->class  = htons(DNS_CLASS_INET);
	type_015_mx_data->ttl    = htonl(cd->ttl);
	type_015_mx_data->length = htons(DNS_TYPE_AAAA_LEN);

	cache_data_type_aaaa = cache_data_priv(cd);

	memcpy(&type_028_aaaa_data->addr, &cache_data_type_aaaa->addr,
			sizeof(type_028_aaaa_data->addr));
#endif

	return SUCCESS;
}


void type_015_mx_free_cache_data(struct cache_data *cd)
{
	struct cache_data_type_mx *cd_mx;

	assert(cd);

	/* think about that cache data structures
	 * are used for two purposes:
	 * 1. as a normal storage container
	 * 2. as a temporary search key container where
	 *    no data is attached, just the key. Therefore
	 *    the free function must take care of this. */
	cd_mx = cache_data_priv(cd);
	if (cd_mx) {
		assert(cd_mx->domain_name);
		xfree(cd_mx->domain_name);
		xfree(cd_mx);
	}
}
