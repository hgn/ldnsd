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
	{ /* A Record */
		.text                      = type_001_a_text,
		.parse                     = type_999_generic_parse,
		.construct                 = type_999_generic_construct,
		.destruct                  = type_999_generic_destruct,
		.free                      = type_999_generic_free,
		.zone_parser_to_cache_data = type_001_a_zone_parser_to_cache_data,
		.free_cache_priv_data      = type_001_a_free_cache_data,
		.cache_cmp                 = type_999_generic_cache_cmp,
		.create_sub_section        = type_001_a_create_sub_section
	},
	{ /* MX Records */
		.text                      = type_015_mx_text,
		.parse                     = type_999_generic_parse,
		.construct                 = type_999_generic_construct,
		.destruct                  = type_999_generic_destruct,
		.free                      = type_999_generic_free,
		.zone_parser_to_cache_data = type_015_mx_zone_parser_to_cache_data,
		.free_cache_priv_data      = type_015_mx_free_cache_data,
		.cache_cmp                 = type_015_mx_cache_cmp
	},
	{ /* AAAA Records */
		.text                      = type_028_aaaa_text,
		.parse                     = type_999_generic_parse,
		.construct                 = type_999_generic_construct,
		.destruct                  = type_999_generic_destruct,
		.free                      = type_999_generic_free,
		.zone_parser_to_cache_data = type_028_aaaa_zone_parser_to_cache_data,
		.free_cache_priv_data      = type_028_aaaa_free_cache_data,
		.cache_cmp                 = type_028_aaaa_cache_cmp
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
		.free_cache_priv_data  = type_999_generic_free_cache_data,
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


/* convert the most common types to names */
const char *type_to_str(uint16_t type)
{
	switch (type) {
		case DNS_TYPE_A:     return "A";
		case DNS_TYPE_AAAA:  return "AAAA";
		case DNS_TYPE_MX:    return "MX";
		case DNS_TYPE_PTR:   return "PTR";
		case DNS_TYPE_SOA:   return "SOA";
		case DNS_TYPE_CNAME: return "CNAME";
		case DNS_TYPE_NS:    return "NS";
		case DNS_TYPE_TXT:   return "TXT";
		case DNS_TYPE_OPT:   return "OPT";
		default:         return "UNKNOWN";
	};
}


int is_valid_type(uint16_t type)
{
	switch (type) {
	case DNS_TYPE_A: case DNS_TYPE_NS: case DNS_TYPE_MD: case DNS_TYPE_MF:
	case DNS_TYPE_CNAME: case DNS_TYPE_SOA: case DNS_TYPE_MB: case DNS_TYPE_MG:
	case DNS_TYPE_MR: case DNS_TYPE_NULL: case DNS_TYPE_WKS: case DNS_TYPE_PTR:
	case DNS_TYPE_HINFO: case DNS_TYPE_MINFO: case DNS_TYPE_MX:
	case DNS_TYPE_TXT: case DNS_TYPE_AAAA: case DNS_TYPE_AFSDB:
	case DNS_TYPE_CERT: case DNS_TYPE_DHCID: case DNS_TYPE_DLV:
	case DNS_TYPE_DNAME: case DNS_TYPE_DNSKEY: case DNS_TYPE_DS: case DNS_TYPE_HIP:
	case DNS_TYPE_IPSECKEY: case DNS_TYPE_KEY: case DNS_TYPE_LOC:
	case DNS_TYPE_NAPTR: case DNS_TYPE_NSEC: case DNS_TYPE_NSEC3:
	case DNS_TYPE_NSEC3PARAM: case DNS_TYPE_RRSIG: case DNS_TYPE_SIG:
	case DNS_TYPE_SPF: case DNS_TYPE_SRV: case DNS_TYPE_SSHFP: case DNS_TYPE_TA:
	case DNS_TYPE_TKEY: case DNS_TYPE_TSIG: case DNS_TYPE_OPT:
		return SUCCESS;
		break;
	default:
		return FAILURE;

	}
	return FAILURE;
}

#define	CLASS_IN 1 /* INET */
/* not supported */
#if 0
#define	CLASS_CS 2 /* CSNET */
#define	CLASS_CH 3 /* CHAOS */
#define	CLASS_HS 4 /* Hesiod */
#endif

const char *class_to_str(uint16_t class)
{
	switch (class) {
		case CLASS_IN: return "IN";
		default:       return "UNKNOWN";
	}
}

int is_valid_class(uint16_t class)
{
	switch (class) {
		case CLASS_IN: return SUCCESS;
		default: return FAILURE;
	};
	return FAILURE;
}

