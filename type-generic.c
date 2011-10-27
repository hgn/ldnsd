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

/* XXX: please don't change the ordering! New
 * supported options should appended here and the
 * corresponding index in the type_fn_table array must
 * be defined in ldnsd.h - see TYPE_INDEX_41.
 * Additionaly you must adjust type_opts_to_index()
 * to recognize the new option. Thats all */
struct type_fn_table type_fn_table[] = {
	{
		.text                      = type_001_a_text,
		.parse                     = type_999_generic_parse,
		.construct                 = type_999_generic_construct,
		.destruct                  = type_999_generic_destruct,
		.free                      = type_999_generic_free,
		.zone_parser_to_cache_data = type_001_a_zone_parser_to_cache_data,
		.free_cache_data           = type_001_a_free_cache_data,
		.cache_cmp                 = type_999_generic_cache_cmp
	},
	{ /* MX Records */
		.text                      = type_015_mx_text,
		.parse                     = type_999_generic_parse,
		.construct                 = type_999_generic_construct,
		.destruct                  = type_999_generic_destruct,
		.free                      = type_999_generic_free,
		.zone_parser_to_cache_data = type_015_mx_zone_parser_to_cache_data,
		.free_cache_data           = type_015_mx_free_cache_data,
		.cache_cmp                 = type_015_mx_cache_cmp
	},
	{
		.text                      = type_028_aaaa_text,
		.parse                     = type_999_generic_parse,
		.construct                 = type_999_generic_construct,
		.destruct                  = type_999_generic_destruct,
		.free                      = type_999_generic_free,
		.zone_parser_to_cache_data = type_028_aaaa_zone_parser_to_cache_data,
		.free_cache_data           = type_028_aaaa_free_cache_data,
		.cache_cmp                 = type_999_generic_cache_cmp
	},
	{
		.text      = type_041_opt_text,
		.parse     = type_041_opt_parse,
		.construct = type_041_opt_construct_option,
		.destruct  = type_999_generic_destruct,
		.free      = type_999_generic_free,
		.cache_cmp = type_999_generic_cache_cmp
	},
	{
		.text             = type_999_generic_text,
		.parse            = type_999_generic_parse,
		.construct        = type_999_generic_construct,
		.destruct         = type_999_generic_destruct,
		.free             = type_999_generic_free,
		.free_cache_data  = type_999_generic_free_cache_data,
		.cache_cmp        = type_999_generic_cache_cmp
	}
};

unsigned type_opts_to_index(uint16_t t)
{
	switch (t) {
	case DNS_TYPE_A:
		return TYPE_INDEX_TYPE_A;
		break;
	case DNS_TYPE_MX:
		return TYPE_INDEX_TYPE_MX;
		break;
	case DNS_TYPE_AAAA:
		return TYPE_INDEX_TYPE_AAAA;
		break;
	case DNS_TYPE_OPT:
		return TYPE_INDEX_TYPE_OPT;
		break;
	default:
		return TYPE_INDEX_TYPE_GENERIC;
		break;
	};

	return TYPE_INDEX_TYPE_GENERIC;
}


int str_record_type(const char *str, int str_len)
{
        if (!(strncasecmp(str, "a", str_len)))
                return DNS_TYPE_A;
        if (!(strncasecmp(str, "aaaa", str_len)))
                return DNS_TYPE_AAAA;
        if (!(strncasecmp(str, "ns", str_len)))
                return DNS_TYPE_NS;
        if (!(strncasecmp(str, "cname", str_len)))
                return DNS_TYPE_CNAME;
        if (!(strncasecmp(str, "soa", str_len)))
                return DNS_TYPE_SOA;
        if (!(strncasecmp(str, "ptr", str_len)))
                return DNS_TYPE_PTR;
        if (!(strncasecmp(str, "mx", str_len)))
                return DNS_TYPE_MX;
        if (!(strncasecmp(str, "txt", str_len)))
                return DNS_TYPE_TXT;

        return -EINVAL;
}


const char *type_999_generic_text(void)
{
	return "type 999 generic parser";
}


/* The generic compare function already validate
* that the type and class is identical. Now
* we compare the keys. It is up to the data
* specific compare functions to compare their
* values. See for example mx records */
int type_999_generic_cache_cmp(const struct cache_data *aa,
		const struct cache_data *bb)
{
	if (aa->key_len != bb->key_len)
		return 0;

	return !memcmp(aa->key, bb->key, aa->key_len);
}


int type_999_generic_parse(struct ctx *ctx, struct dns_pdu *dr,
		struct dns_sub_section *dnss, const char *data, int max_len)
{
	(void) ctx;
	(void) dr;
	(void) dnss;
	(void) data;
	(void) max_len;

	return SUCCESS;
}

int type_999_generic_construct(struct ctx *ctx, struct dns_pdu *dp,
		struct dns_sub_section *dss, const char *data, int max_len)
{
	int i = 0;

	(void) ctx;
	(void) dp;

	if (max_len < 0) {
		pr_debug("packet buffer to small");
		return -1;
	}

	/* 1. build the name (labels) */
	i += dnsname_to_labels((char *)data, max_len, i,
			dss->name, strlen(dss->name), NULL);

	/* 2. the type */
	/* 3. the name */
	/* 4. the ttl */
	/* 5. rdlength */
	/* 6. copy the transparent the data, based
	 *    on information found in the rdlength field */

	return 0;
}

/* i is a offset that points to the next byte after the name */
int type_999_generic_destruct(struct ctx *ctx, struct dns_pdu *dp,
		struct dns_sub_section *dss, const char *packet, int offset, int max_len)
{
	int i = offset;

	(void) ctx; (void) dp;

	i += get16(packet, i, max_len, &dss->type);
	i += get16(packet, i, max_len, &dss->class);
	i += getint32_t(packet, i, max_len, &dss->ttl);
	i += get16(packet, i, max_len, &dss->rdlength);

	switch (dss->rdlength) {
		case 1:
			dss->priv_data_u8 = *(uint8_t *)(packet + i);
		case 2:
			/* FIXME: this can cause a SIGBUS */
			dss->priv_data_u16 = *(uint16_t *)(packet + i);
		case 3:
			/* FIXME: 3 byte? -> normally a error and
			 * should be ignored and traced */
			dss->priv_data_u32 = *(uint32_t *)(packet + i);
		case 4:
			dss->priv_data_u32 = *(uint32_t *)(packet + i);
		default:
			dss->priv_data_ptr = xmalloc(dss->rdlength);
			memcpy(dss->priv_data_ptr, (packet + i), dss->rdlength);
	}

	return i + dss->rdlength;
}

/* type_999_generic_free - free related data */
void type_999_generic_free(struct ctx *ctx, struct dns_sub_section *dss)
{
	(void) ctx;
	/* ok it is a little bit complicated here:
	 * we know the actual length of the data section
	 * because rdlength tell us that. Second: we had
	 * a container element that can hold a) a pointer
	 * to a self alllocated memory or b) to a {uint32_t, uint16_t, uint8_t}
	 * datatype.
	 * The idea is simple: if rdlength tell us that the data length
	 * fit into one of this skalar datatypes we dont need no dynamic
	 * allocated and therefore no free afterwards */
	switch (dss->rdlength) {
		case 0: /* fits in the union */
		case 1:
		case 2:
		case 3:
		case 4:
			return;
		default: /* dynamic allocated memory */
			free(dss->priv_data_ptr);
	}
}


int type_999_generic_available(struct dns_pdu *dns_pdu)
{
	(void) dns_pdu;

	return 0;
}

void type_999_generic_free_cache_data(struct ctx *ctx, struct cache_data *cd)
{
	(void) ctx;
	(void) cd;

	abort();
}
