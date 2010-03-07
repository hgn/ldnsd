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

#include "ldnsd.h"


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

int clone_dns_pkt(char *packet, size_t len, char **ret_pkt, size_t new_len)
{
	char *new_pkt;

	if (new_len < len)
		return FAILURE;

	new_pkt = xzalloc(new_len);

	memcpy(new_pkt, packet, len);

	*ret_pkt = new_pkt;

	return SUCCESS;
}

void free_dns_journey_list_entry(void *d)
{
	free_dns_journey(d);
}

void free_dns_journey(struct dns_journey *x)
{
	int i;

	pr_debug("free dns_journey");

	if (x->p_req_dns_pdu) {

		if (x->p_req_dns_pdu->questions) {
			for (i = 0; i < x->p_req_dns_pdu->questions; i++) {
				struct dns_sub_section *dns_s = x->p_req_dns_pdu->questions_section[i];
				if (dns_s->name)
					free(dns_s->name);
				free(dns_s);
			}
			free(x->p_req_dns_pdu->questions_section);
		}

		if (x->p_req_dns_pdu->questions) {
			for (i = 0; i < x->p_req_dns_pdu->answers; i++) {
				struct dns_sub_section *dns_s = x->p_req_dns_pdu->answers_section[i];
				if (dns_s->name)
					free(dns_s->name);
				free(dns_s);
			}
			free(x->p_req_dns_pdu->answers_section);
		}

		if (x->p_req_dns_pdu->authority) {
			for (i = 0; i < x->p_req_dns_pdu->authority; i++) {
				struct dns_sub_section *dns_s = x->p_req_dns_pdu->authority_section[i];
				if (dns_s->name)
					free(dns_s->name);
				free(dns_s);
			}
			free(x->p_req_dns_pdu->authority_section);
		}

		if (x->p_req_dns_pdu->additional) {
			for (i = 0; i < x->p_req_dns_pdu->additional; i++) {
				struct dns_sub_section *dns_s = x->p_req_dns_pdu->additional_section[i];
				if (dns_s->name)
					free(dns_s->name);
				free(dns_s);
			}
			free(x->p_req_dns_pdu->additional_section);
		}

		free(x->p_req_packet);
	}


	/* this is our build packet structure to build
	 * the data structure to active sent a packet
	 * to a upstream DNS server */
	if (x->a_req_dns_pdu) {

		if (x->a_req_dns_pdu->questions) {
			for (i = 0; i < x->a_req_dns_pdu->questions; i++) {
				struct dns_sub_section *dns_s = x->a_req_dns_pdu->questions_section[i];
				if (dns_s->name)
					free(dns_s->name);
				free(dns_s);
			}
			free(x->a_req_dns_pdu->questions_section);
		}

		if (x->a_req_dns_pdu->answers) {
			for (i = 0; i < x->a_req_dns_pdu->answers; i++) {
				struct dns_sub_section *dns_s = x->a_req_dns_pdu->answers_section[i];
				if (dns_s->name)
					free(dns_s->name);
				free(dns_s);
			}
			free(x->a_req_dns_pdu->answers_section);
		}

		if (x->a_req_dns_pdu->authority) {
			for (i = 0; i < x->a_req_dns_pdu->authority; i++) {
				struct dns_sub_section *dns_s = x->a_req_dns_pdu->authority_section[i];
				if (dns_s->name)
					free(dns_s->name);
				free(dns_s);
			}
			free(x->a_req_dns_pdu->authority_section);
		}

		if (x->a_req_dns_pdu->additional) {
			for (i = 0; i < x->a_req_dns_pdu->additional; i++) {
				struct dns_sub_section *dns_s = x->a_req_dns_pdu->additional_section[i];
				if (dns_s->name)
					xfree(dns_s->name);
				xfree(dns_s);
			}
			xfree(x->a_req_dns_pdu->additional_section);
		}

		xfree(x->a_req_dns_pdu);
	}

	if (x->p_res_dns_pdu) {

		if (x->p_res_dns_pdu->questions) {
			for (i = 0; i < x->p_res_dns_pdu->questions; i++) {
				struct dns_sub_section *dns_s = x->p_res_dns_pdu->questions_section[i];
				if (dns_s->name)
					xfree(dns_s->name);
				xfree(dns_s);
			}
			xfree(x->p_res_dns_pdu->questions_section);
		}

		if (x->p_res_dns_pdu->answers) {
			for (i = 0; i < x->p_res_dns_pdu->answers; i++) {
				struct dns_sub_section *dns_s = x->p_res_dns_pdu->answers_section[i];
				if (dns_s->name)
					xfree(dns_s->name);
				xfree(dns_s);
			}
			xfree(x->p_res_dns_pdu->answers_section);
		}

		if (x->p_res_dns_pdu->authority) {
			for (i = 0; i < x->p_res_dns_pdu->authority; i++) {
				struct dns_sub_section *dns_s = x->p_res_dns_pdu->authority_section[i];
				if (dns_s->name)
					xfree(dns_s->name);
				xfree(dns_s);
			}
			xfree(x->p_res_dns_pdu->authority_section);
		}

		if (x->p_res_dns_pdu->additional) {
			for (i = 0; i < x->p_res_dns_pdu->additional; i++) {
				struct dns_sub_section *dns_s = x->p_res_dns_pdu->additional_section[i];
				if (dns_s->name)
					xfree(dns_s->name);
				xfree(dns_s);
			}
			xfree(x->p_res_dns_pdu->additional_section);
		}

		xfree(x->p_res_dns_pdu);
	}

	if (x->p_req_dns_pdu)
		xfree(x->p_req_dns_pdu);

	if (x->a_req_packet)
		xfree(x->a_req_packet);

	if (x->a_res_packet)
		xfree(x->a_res_packet);

	xfree(x); x = NULL;
}

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


void pretty_print_flags(FILE *fp, uint16_t flags)
{
	switch ((flags & 0x8000) >> 15) {
		case 1:
			fprintf(fp, "QR set: response, ");
			break;
		case 0:
			fprintf(fp, "QR set: query, ");
			break;
		default:
			fprintf(fp, "QR set: UNKNOWN, ");
			break;
	}

	switch ((flags & 0x7800) >> 11) {
		case 0:
			fprintf(fp, "opcode: standard query, ");
			break;
		case 1:
			fprintf(fp, "opcode: inverse query, ");
			break;
		case 2:
			fprintf(fp, "opcode: server status request, ");
			break;
		default:
			fprintf(fp, "opcode: UNKNOWN, ");
			break;
	}

	switch ((flags & 0x0400) >> 10) {
		case 1:
			fprintf(fp, "AA: authoritative answer, ");
			break;
		case 0:
			fprintf(fp, "AA: non-authoritative answer, ");
			break;
		default: /* could not happened */
			break;
	}

	switch ((flags & 0x0200) >> 9) {
		case 1:
			fprintf(fp, "TC: truncated, ");
			break;
		case 0:
			fprintf(fp, "TC: not truncated, ");
			break;
		default: /* could not happened */
			break;
	}

	switch ((flags & 0x0100) >> 8) {
		case 1:
			fprintf(fp, "RD: recursion desired, ");
			break;
		case 0:
			fprintf(fp, "RD: no recursion desired, ");
			break;
		default: /* could not happened */
			break;
	}

	switch ((flags & 0x0080) >> 7) {
		case 1:
			fprintf(fp, "RA: recursive available, ");
			break;
		case 0:
			fprintf(fp, "RA: recursive not available, ");
			break;
		default: /* could not happened */
			break;
	}

	switch (flags & 0x000f) {
		case 0:
			fprintf(fp, "RCODE: no error, ");
			break;
		case 3:
			fprintf(fp, "RCODE: name error, ");
			break;
		default:
			fprintf(fp, "RCODE: UNKNWON error, ");
			break;
	}

	fprintf(fp, "\n");
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


static int getint32_t(const char *data, size_t idx, size_t max, int32_t *ret)
{
	int32_t tmp;

	if (idx + 4 > max)
		return FAILURE;

	memcpy(&tmp, data + idx, 4);
	*ret = ntohl(tmp);
	return 4;
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
		xfree(dss[i]->name);
		xfree(dss[i]);
	}
	xfree(dss);
}


void free_dns_pdu(struct dns_pdu *dr)
{
	/* free sections first */
	free_dns_subsection(dr->questions, dr->questions_section);
	free_dns_subsection(dr->answers, dr->answers_section);
	free_dns_subsection(dr->authority, dr->authority_section);
	free_dns_subsection(dr->additional, dr->additional_section);
	xfree(dr);
}


/* see 4.1.1. Header section format ( http://tools.ietf.org/html/rfc1035 ) */
void dns_packet_set_rr_entries_number(char *packet, enum rr_section rr_section, uint16_t no)
{
	uint16_t *ptr;
	int offset;

	switch (rr_section) {
		case RR_SECTION_QDCOUNT:
			offset = 4;
			break;
		case RR_SECTION_ANCOUNT:
			offset = 6;
			break;
		case RR_SECTION_NSCOUNT:
			offset = 8;
			break;
		case RR_SECTION_ARCOUNT:
			offset = 10;
			break;
		default:
			err_msg_die(EXIT_FAILINT, "programmed error in rr section setter");
			break;
	}
	ptr = (uint16_t *)(packet + sizeof(char) * offset);
	*ptr = ntohs(no);
}

#define	PACKET_OFFSET_FLAG_FIELD_B1 2
#define	PACKET_OFFSET_FLAG_FIELD_B2 3

/* clear the whole 16 bit flag field */
void packet_flags_clear(char *packet)
{
	packet[PACKET_OFFSET_FLAG_FIELD_B1] = 0;
	packet[3] = 0;
}

void packet_flags_set_qr_response(char *packet)
{
	packet[PACKET_OFFSET_FLAG_FIELD_B1] |= 0x80;
}

void packet_flags_set_qr_query(char *packet)
{
	packet[PACKET_OFFSET_FLAG_FIELD_B1] &= ~0x80;
}

void packet_flags_set_authoritative_answer(char *packet)
{
	packet[PACKET_OFFSET_FLAG_FIELD_B1] |= 0x04;
}

void packet_flags_set_unauthoritative_answer(char *packet)
{
	packet[PACKET_OFFSET_FLAG_FIELD_B1] &= ~0x04;
}

void packet_flags_set_truncated(char *packet)
{
	packet[PACKET_OFFSET_FLAG_FIELD_B1] |= 0x02;
}

void packet_flags_set_untruncated(char *packet)
{
	packet[PACKET_OFFSET_FLAG_FIELD_B1] &= ~0x02;
}

void packet_flags_set_recursion_desired(char *packet)
{
	packet[PACKET_OFFSET_FLAG_FIELD_B1] |= 0x01;
}

void packet_flags_set_recursion_undesired(char *packet)
{
	packet[PACKET_OFFSET_FLAG_FIELD_B1] &= ~0x01;
}

void packet_flags_set_recursion_available(char *packet)
{
	packet[PACKET_OFFSET_FLAG_FIELD_B2] |= 0x80;
}

void packet_flags_set_recursion_unavailable(char *packet)
{
	packet[PACKET_OFFSET_FLAG_FIELD_B2] &= ~0x80;
}

void packet_flags_set_rcode(char *packet, char rcode)
{
	packet[PACKET_OFFSET_FLAG_FIELD_B2] &= ~0x0f;
	packet[PACKET_OFFSET_FLAG_FIELD_B2] |= (rcode & 0x0f);
}

int packet_flags_get_rcode(char *packet)
{
	return packet[3] & 0x0f;
}

#if 0
void dns_packet_set_response_flag(char *packet)
{
	uint16_t *flags = (uint16_t *)(packet + sizeof(char) * 2);
	*flags |= htons(0x8000);
}

void dns_packet_flags_set_reply_code(char *packet, uint16_t code)
{
	uint16_t tmp = code & 0xf;

	uint16_t *flags = (uint16_t *)(packet + sizeof(char) * 2);


}
#endif


#define	MAX_DNS_NAME 256

/* returns the number of bytes for the parsed section
 * or 0 in the case of an error
 */
static unsigned parse_rr_section(struct ctx *ctx, const char *packet,
		unsigned offset, const size_t max_len,
		struct dns_sub_section **dnssq_ret)
{
	int i;
	struct dns_sub_section *dnssq;
	char name[MAX_DNS_NAME];

	(void) ctx;

	i = get_name(packet, offset, max_len, name, MAX_DNS_NAME);
	if (i == FAILURE) {
		err_msg("corrupted name format");
		return FAILURE;
	}

	pr_debug("parsed name: %s (new offset: %d)", name, i);

	dnssq = xzalloc(sizeof(struct dns_sub_section));

	/* save name */
	dnssq->name = xzalloc(strlen(name) + 1);
	memcpy(dnssq->name, name, strlen(name) + 1);

	i += get16(packet, i, max_len, &dnssq->type);
	i += get16(packet, i, max_len, &dnssq->class);
	i += getint32_t(packet, i, max_len, &dnssq->ttl);
	i += get16(packet, i, max_len, &dnssq->rdlength);

	pr_debug("parsed type: %s, parsed class: %s ttl: %u rdlength: %u",
			type_to_str(dnssq->type), class_to_str(dnssq->class),
			dnssq->ttl, dnssq->rdlength);

	/* skip data for offset variable */
	i += dnssq->rdlength;

	*dnssq_ret = dnssq;

	return i;
}


/* parse_dns_packet parses a standard DNS packet and
   fills the dns_pdu structure.

   The format of a DNS packet is specified in
   4.1. Format ( http://tools.ietf.org/html/rfc1035 ):

    +---------------------+
    |        Header       |
    +---------------------+
    |       Question      | the question for the name server
    +---------------------+
    |        Answer       | RRs answering the question
    +---------------------+
    |      Authority      | RRs pointing toward an authority
    +---------------------+
    |      Additional     | RRs holding additional information
    +---------------------+
*/
int parse_dns_packet(struct ctx *ctx, const char *packet, const size_t len,
		struct dns_pdu **dns_pdu)
{
	int i = 0, j;
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
		xfree(dr);
		*dns_pdu = NULL;
		return FAILURE;
	}

	/*
	   See 3.2.1. Format (http://tools.ietf.org/html/rfc1035)

	   1  1  1  1  1  1
	   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
	   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	   |                                               |
	   /                                               /
	   /                      NAME                     /
	   |                                               |
	   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	   |                      TYPE                     |
	   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	   |                     CLASS                     |
	   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	   |                      TTL                      |
	   |                                               |
	   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	   |                   RDLENGTH                    |
	   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
	   /                     RDATA                     /
	   /                                               /
	   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	   */

	/* parse queuestions */
	if (dr->questions > 0) {

		dr->questions_section = xzalloc(sizeof(struct dns_sub_section *) * dr->questions);

		/* save offset of this section */
		dr->questions_section_ptr = packet + i;

		for (j = 0; j < dr->questions; j++) {
			struct dns_sub_section *dnssq;
			char name[MAX_DNS_NAME];

			i = get_name(packet, i, len, name, MAX_DNS_NAME);
			if (i == FAILURE) {
				err_msg("corrupted name format");
				return FAILURE;
			}

			pr_debug("parsed name: %s (new offset: %d)", name, i);

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
					xfree(dr->questions_section[j]->name);
					xfree(dr->questions_section[j]);
				}
				xfree(dr->questions_section);
				xfree(dr);
				return FAILURE;
			}
		}
	}

	dr->questions_section_len = i;

	/* parse answers */
	if (dr->answers > 0) {

		dr->answers_section = xzalloc(sizeof(struct dns_sub_section *) * dr->answers);

		/* save offset of this section */
		dr->answers_section_ptr = packet + i;

		for (j = 0; j < dr->answers; j++) {
			struct dns_sub_section *dnssq;

			i = parse_rr_section(ctx, packet, i, len, &dnssq);
			if (i < 1) {
				err_msg("cannot parse rr section, I skip this packet");
				goto err_answer;
			}

			/* splice this section */
			dr->answers_section[j] = dnssq;

			/* XXX: the error check is here to simplify the
			 * error path to free() the allocated memory */
			if (is_valid_type(dnssq->type) != SUCCESS ||
					is_valid_class(dnssq->class) != SUCCESS) {
				err_msg("parsed type %s(%u) or class %s(%u) is not valid, i ignore this request",
						type_to_str(dnssq->type), dnssq->type,
						class_to_str(dnssq->class), dnssq->class);

err_answer:
				/* free all allocated memory */
				for ( ; j >= 0; j--) {
					xfree(dr->answers_section[j]->name);
					xfree(dr->answers_section[j]);
				}
				xfree(dr->answers_section);
				xfree(dr);
				free_dns_subsection(dr->questions, dr->questions_section);
				return FAILURE;
			}
		}
	}

	dr->answers_section_len = i - dr->questions_section_len;

	/* parse authority */
	if (dr->authority > 0) {

		dr->authority_section = xzalloc(sizeof(struct dns_sub_section *) * dr->authority);

		/* save offset of this section */
		dr->authority_section_ptr = packet + i;

		for (j = 0; j < dr->authority; j++) {
			struct dns_sub_section *dnssq;

			i = parse_rr_section(ctx, packet, i, len, &dnssq);
			if (i < 1) {
				err_msg("cannot parse rr section, I skip this packet");
				goto err_authority;
			}

			dr->authority_section[j] = dnssq;

			/* XXX: the error check is here to simplify the
			 * error path to free() the allocated memory */
			if (is_valid_type(dnssq->type) != SUCCESS ||
					is_valid_class(dnssq->class) != SUCCESS) {
				err_msg("parsed type %s(%u) or class %s(%u) is not valid, i ignore this request",
						type_to_str(dnssq->type), dnssq->type,
						class_to_str(dnssq->class), dnssq->class);

err_authority:
				/* free all allocated memory */
				for ( ; j >= 0; j--) {
					xfree(dr->authority_section[j]->name);
					xfree(dr->authority_section[j]);
				}
				xfree(dr->authority_section);
				xfree(dr);
				free_dns_subsection(dr->questions, dr->questions_section);
				free_dns_subsection(dr->answers, dr->answers_section);
				return FAILURE;
			}
		}
	}

	dr->authority_section_len = i - dr->questions_section_len - dr->answers_section_len;

	/* parse additional */
	if (dr->additional > 0) {

		dr->additional_section = xzalloc(sizeof(struct dns_sub_section *) * dr->additional);

		/* save offset of this section */
		dr->additional_section_ptr = packet + i;

		for (j = 0; j < dr->additional; j++) {
			struct dns_sub_section *dnssq;

			i = parse_rr_section(ctx, packet, i, len, &dnssq);
			if (i < 1) {
				err_msg("cannot parse rr section, I skip this packet");
				goto err_additional;
			}

			dr->additional_section[j] = dnssq;

			/* XXX: the error check is here to simplify the
			 * error path to free() the allocated memory */
			if (is_valid_type(dnssq->type) != SUCCESS ||
					is_valid_class(dnssq->class) != SUCCESS) {
				err_msg("parsed type %s(%u) or class %s(%u) is not valid, i ignore this request",
						type_to_str(dnssq->type), dnssq->type,
						class_to_str(dnssq->class), dnssq->class);

err_additional:
				/* free all allocated memory */
				for ( ; j >= 0; j--) {
					xfree(dr->additional_section[j]->name);
					xfree(dr->additional_section[j]);
				}
				xfree(dr->additional_section);
				xfree(dr);
				free_dns_subsection(dr->questions, dr->questions_section);
				free_dns_subsection(dr->answers, dr->answers_section);
				free_dns_subsection(dr->authority, dr->authority_section);
				return FAILURE;
			}
		}
	}

	dr->additional_section_len = i - dr->questions_section_len -
		dr->answers_section_len - dr->authority_section_len;

	*dns_pdu = dr;
	return SUCCESS;
}



/* vim: set tw=78 ts=4 sw=4 sts=4 ff=unix noet: */
