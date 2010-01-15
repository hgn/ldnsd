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


#define	IS_DNS_QUESTION(x) (x & DNS_FLAG_MASK_QUESTION)
#define	IS_DNS_STANDARD_QUERY(x) (x & DNS_FLAG_STANDARD_QUERY)


/* see http://en.wikipedia.org/wiki/List_of_DNS_record_types */
#define	TYPE_A   1
#define	TYPE_NS  2
#define	TYPE_MD  3
#define	TYPE_MF 4
#define	TYPE_CNAME 5
#define	TYPE_SOA 6
#define	TYPE_MB  7
#define	TYPE_MG 8
#define	TYPE_MR 9
#define	TYPE_NULL 10
#define	TYPE_WKS 11
#define	TYPE_PTR 12
#define	TYPE_HINFO 13
#define	TYPE_MINFO 14
#define	TYPE_MX 15
#define	TYPE_TXT 16

#define	TYPE_AAAA	28
#define	TYPE_AFSDB	18
#define	TYPE_CERT	37
#define	TYPE_DHCID	49
#define	TYPE_DLV	32769
#define	TYPE_DNAME	39
#define	TYPE_DNSKEY		48
#define	TYPE_DS		43
#define	TYPE_HIP	55
#define	TYPE_IPSECKEY	45
#define	TYPE_KEY	25
#define	TYPE_LOC	29
#define	TYPE_NAPTR	35
#define	TYPE_NSEC	47
#define	TYPE_NSEC3	50
#define	TYPE_NSEC3PARAM		51
#define	TYPE_RRSIG	46
#define	TYPE_SIG	24
#define	TYPE_SPF	99
#define	TYPE_SRV	33
#define	TYPE_SSHFP	44
#define	TYPE_TA		32768
#define	TYPE_TKEY	249
#define	TYPE_TSIG	250

/* not supported */
#if 0
#define	TYPE_AXFR	252
#define	TYPE_IXFR	251
#define	TYPE_OPT	41
#endif

/* convert the most common types to names */
static const char *type_to_str(uint16_t type)
{
	switch (type) {
		case TYPE_A:     return "A";
		case TYPE_AAAA:  return "AAAA";
		case TYPE_MX:    return "MX";
		case TYPE_PTR:   return "PTR";
		case TYPE_SOA:   return "SOA";
		case TYPE_CNAME: return "CNAME";
		case TYPE_NS:    return "NS";
		case TYPE_TXT:   return "TXT";
		default:         return "UNKNOWN";
	};
}


static int is_valid_type(uint16_t type)
{
	switch (type) {
		case TYPE_A: case TYPE_NS: case TYPE_MD: case TYPE_MF:
		case TYPE_CNAME: case TYPE_SOA: case TYPE_MB: case TYPE_MG:
		case TYPE_MR: case TYPE_NULL: case TYPE_WKS: case TYPE_PTR:
		case TYPE_HINFO: case TYPE_MINFO: case TYPE_MX:
		case TYPE_TXT: case TYPE_AAAA: case TYPE_AFSDB:
		case TYPE_CERT: case TYPE_DHCID: case TYPE_DLV:
		case TYPE_DNAME: case TYPE_DNSKEY: case TYPE_DS: case TYPE_HIP:
		case TYPE_IPSECKEY: case TYPE_KEY: case TYPE_LOC:
		case TYPE_NAPTR: case TYPE_NSEC: case TYPE_NSEC3:
		case TYPE_NSEC3PARAM: case TYPE_RRSIG: case TYPE_SIG:
		case TYPE_SPF: case TYPE_SRV: case TYPE_SSHFP: case TYPE_TA:
		case TYPE_TKEY: case TYPE_TSIG:
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

static const char *class_to_str(uint16_t class)
{
	switch (class) {
		case CLASS_IN: return "IN";
		default:       return "UNKNOWN";
	}
}

static int is_valid_class(uint16_t class)
{
	switch (class) {
		case CLASS_IN: return SUCCESS;
		default: return FAILURE;
	};
	return FAILURE;
}


static int get8(const char *data, size_t idx, size_t max, uint8_t *ret)
{
	uint16_t tmp;

	if (idx + 1 > max)
		return FAILURE;

	memcpy(&tmp, data + idx, 1);
	*ret = tmp;
	return 1;
}


static int get16(const char *data, size_t idx, size_t max, uint16_t *ret)
{
	uint16_t tmp;

	if (idx + 2 > max)
		return FAILURE;

	memcpy(&tmp, data + idx, 2);
	*ret = ntohs(tmp);
	return 2;
}

#define	PTR_MASK 0xc0
#define	IS_PTR(x) (x & PTR_MASK)

/* this function is a little bit tricky, the DNS packet format provides a
 * mechanism to compress a string. A special pattern signals that the next
 * bytes are a pointer to another place and not a vanilla character array */
static int get_name(const char *data, size_t idx, size_t max,
		char *ret_data, size_t max_data_ret_len)
{
	uint8_t llen = 0, offset_ptr = 0;
	int name_end = -1; /* FIXME: change name of name_end */
	size_t i = idx;
	unsigned jumps = 0;
	char *cp = ret_data;
	const char *const end = ret_data + max_data_ret_len;

	assert(idx <= max);

	while (666) {
		i += get8(data, i, max, &llen);

		pr_debug("label len: %u", llen);

		if (llen == 0) /* reached end of string */
			break;

		if (IS_PTR(llen)) {
			pr_debug("label is pointer");
			i += get8(data, i, max, &offset_ptr);
			if (name_end < 0)
				name_end = i;
			i = (((int)llen & 0x3f) << 8) + offset_ptr;
			if (i > max) {
				err_msg("name format corrupt, skipping it");
				return FAILURE;
			}
			if (jumps++ > max) {
				err_msg("corrupted name, we jump more then characters in the array");
				return FAILURE;
			}

			/* and jump */
			continue;
		}

		if (llen > 63) {
			err_msg("corrupted name format");
			return FAILURE;
		}

		if (cp != ret_data) {
			if (cp + 1 >= end) {
				return FAILURE;
			}
			*cp++ = '.';
		}
		if (cp + llen >= end)
			return FAILURE;
		memcpy(cp, data + i, llen);
		cp += llen;
		i  += llen;
	}

	if (cp >= end)
		return FAILURE;
	*cp = '\0';

	if (name_end < 0) {
		return i;
	} else {
		return name_end;
	}
}


void free_dns_subsection(uint16_t no, struct dns_sub_section **dss)
{
	unsigned i;

	if (no == 0)
		return;

	for (i = 0; i < no; i++) {
		free(dss[i]->name);
		free(dss[i]);
	}
	free(dss);
}


void free_dns_pdu(struct dns_pdu *dr)
{
	/* free sections first */
	free_dns_subsection(dr->questions, dr->questions_section);
	free_dns_subsection(dr->answers, dr->answers_section);
	free_dns_subsection(dr->authority, dr->authority_section);
	free_dns_subsection(dr->additional, dr->additional_section);
	free(dr);
}

#define	MAX_DNS_NAME 256


int parse_dns_packet(struct ctx *ctx, const char *packet, const size_t len,
		struct dns_pdu **dns_pdu)
{
	int i = 0, ii, j;
	struct dns_pdu *dr;

	(void) ctx;

	dr = xzalloc(sizeof(*dr));

	i += get16(packet, i, len, &dr->id);
	i += get16(packet, i, len, &dr->flags);
	i += get16(packet, i, len, &dr->questions);
	i += get16(packet, i, len, &dr->answers);
	i += get16(packet, i, len, &dr->authority);
	i += get16(packet, i, len, &dr->additional);

	pr_debug("process DNS query [packet size: %d id:%u, flags:0x%x, "
			 "questions:%u, answers:%u, authority:%u, additional:%u]",
			 len, dr->id, dr->flags, dr->questions, dr->answers, dr->authority, dr->additional);

	if (dr->answers == 0 && dr->questions == 0 &&
		dr->authority == 0 && dr->additional == 0) {
		free(dr);
		*dns_pdu = NULL;
		return FAILURE;
	}

	/* parse queuestions */
	if (dr->questions > 0) {

		dr->questions_section = xzalloc(sizeof(struct dns_sub_section *) * dr->questions);

		for (j = 0; j < dr->questions; j++) {
			struct dns_sub_section *dnssq;
			char name[MAX_DNS_NAME];

			ii = get_name(packet, i, len, name, MAX_DNS_NAME);
			if (ii == FAILURE) {
				err_msg("corrupted name format");
				return FAILURE;
			}
			i = ii;

			pr_debug("parsed name: %s (new offset: %d)", name, ii);

			dnssq = xzalloc(sizeof(struct dns_sub_section));

			i += get16(packet, i, len, &dnssq->type);
			i += get16(packet, i, len, &dnssq->class);

			pr_debug("parsed type: %s, parsed class: %s",
					type_to_str(dnssq->type), class_to_str(dnssq->class));

			dnssq->name = xzalloc(strlen(name) + 1);

			memcpy(dnssq->name, name, strlen(name) + 1);

			dr->questions_section[j] = dnssq;

			/* XXX: the error check is here to simplify the
			 * error path to free() the allocated memory */
			if (is_valid_type(dnssq->type) != SUCCESS ||
					is_valid_class(dnssq->class) != SUCCESS) {
				err_msg("parsed type %s or class %s is not valid, i ignore this request",
						type_to_str(dnssq->type), class_to_str(dnssq->class));

				/* free all allocated memory */
				for ( ; j >= 0; j--) {
					free(dr->questions_section[j]->name);
					free(dr->questions_section[j]);
				}
				free(dr->questions_section);
				free(dr);
				return FAILURE;
			}
		}
	}

	/* parse answers */
	if (dr->answers > 0) {

		dr->answers_section = xzalloc(sizeof(struct dns_sub_section *) * dr->answers);

		for (j = 0; j < dr->questions; j++) {
			struct dns_sub_section *dnssq;
			char name[MAX_DNS_NAME];

			ii = get_name(packet, i, len, name, MAX_DNS_NAME);
			if (ii == FAILURE) {
				err_msg("corrupted name format");
				return FAILURE;
			}
			i = ii;

			pr_debug("parsed name: %s (new offset: %d)", name, ii);

			dnssq = xzalloc(sizeof(struct dns_sub_section));

			i += get16(packet, i, len, &dnssq->type);
			i += get16(packet, i, len, &dnssq->class);

			pr_debug("parsed type: %s, parsed class: %s",
					type_to_str(dnssq->type), class_to_str(dnssq->class));

			dnssq->name = xzalloc(strlen(name) + 1);

			memcpy(dnssq->name, name, strlen(name) + 1);

			dr->answers_section[j] = dnssq;

			/* XXX: the error check is here to simplify the
			 * error path to free() the allocated memory */
			if (is_valid_type(dnssq->type) != SUCCESS ||
					is_valid_class(dnssq->class) != SUCCESS) {
				err_msg("parsed type %s or class %s is not valid, i ignore this request",
						type_to_str(dnssq->type), class_to_str(dnssq->class));

				/* free all allocated memory */
				for ( ; j >= 0; j--) {
					free(dr->answers_section[j]->name);
					free(dr->answers_section[j]);
				}
				free(dr->answers_section);
				free(dr);
				free_dns_subsection(dr->questions, dr->questions_section);
				return FAILURE;
			}
		}
	}

	/* parse authority */
	if (dr->authority > 0) {

		dr->authority_section = xzalloc(sizeof(struct dns_sub_section *) * dr->authority);

		for (j = 0; j < dr->questions; j++) {
			struct dns_sub_section *dnssq;
			char name[MAX_DNS_NAME];

			ii = get_name(packet, i, len, name, MAX_DNS_NAME);
			if (ii == FAILURE) {
				err_msg("corrupted name format");
				return FAILURE;
			}
			i = ii;

			pr_debug("parsed name: %s (new offset: %d)", name, ii);

			dnssq = xzalloc(sizeof(struct dns_sub_section));

			i += get16(packet, i, len, &dnssq->type);
			i += get16(packet, i, len, &dnssq->class);

			pr_debug("parsed type: %s, parsed class: %s",
					type_to_str(dnssq->type), class_to_str(dnssq->class));

			dnssq->name = xzalloc(strlen(name) + 1);

			memcpy(dnssq->name, name, strlen(name) + 1);

			dr->authority_section[j] = dnssq;

			/* XXX: the error check is here to simplify the
			 * error path to free() the allocated memory */
			if (is_valid_type(dnssq->type) != SUCCESS ||
					is_valid_class(dnssq->class) != SUCCESS) {
				err_msg("parsed type %s or class %s is not valid, i ignore this request",
						type_to_str(dnssq->type), class_to_str(dnssq->class));

				/* free all allocated memory */
				for ( ; j >= 0; j--) {
					free(dr->authority_section[j]->name);
					free(dr->authority_section[j]);
				}
				free(dr->authority_section);
				free(dr);
				free_dns_subsection(dr->questions, dr->questions_section);
				free_dns_subsection(dr->answers, dr->answers_section);
				return FAILURE;
			}
		}
	}

	/* parse additional */
	if (dr->additional > 0) {

		dr->additional_section = xzalloc(sizeof(struct dns_sub_section *) * dr->additional);

		for (j = 0; j < dr->questions; j++) {
			struct dns_sub_section *dnssq;
			char name[MAX_DNS_NAME];

			ii = get_name(packet, i, len, name, MAX_DNS_NAME);
			if (ii == FAILURE) {
				err_msg("corrupted name format");
				return FAILURE;
			}
			i = ii;

			pr_debug("parsed name: %s (new offset: %d)", name, ii);

			dnssq = xzalloc(sizeof(struct dns_sub_section));

			i += get16(packet, i, len, &dnssq->type);
			i += get16(packet, i, len, &dnssq->class);

			pr_debug("parsed type: %s, parsed class: %s",
					type_to_str(dnssq->type), class_to_str(dnssq->class));

			dnssq->name = xzalloc(strlen(name) + 1);

			memcpy(dnssq->name, name, strlen(name) + 1);

			dr->additional_section[j] = dnssq;

			/* XXX: the error check is here to simplify the
			 * error path to free() the allocated memory */
			if (is_valid_type(dnssq->type) != SUCCESS ||
					is_valid_class(dnssq->class) != SUCCESS) {
				err_msg("parsed type %s or class %s is not valid, i ignore this request",
						type_to_str(dnssq->type), class_to_str(dnssq->class));

				/* free all allocated memory */
				for ( ; j >= 0; j--) {
					free(dr->additional_section[j]->name);
					free(dr->additional_section[j]);
				}
				free(dr->additional_section);
				free(dr);
				free_dns_subsection(dr->questions, dr->questions_section);
				free_dns_subsection(dr->answers, dr->answers_section);
				free_dns_subsection(dr->authority, dr->authority_section);
				return FAILURE;
			}
		}
	}

	*dns_pdu = dr;
	return SUCCESS;
}



/* vim: set tw=78 ts=4 sw=4 sts=4 ff=unix noet: */
