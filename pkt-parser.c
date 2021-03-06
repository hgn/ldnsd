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


#define	IS_DNS_QUESTION(x) (x & DNS_FLAG_MASK_QUESTION)
#define	IS_DNS_STANDARD_QUERY(x) (x & DNS_FLAG_STANDARD_QUERY)


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


void free_dns_pdu(struct dns_pdu *dr)
{
	/* free sections first */
	free_dns_subsection(dr->questions, dr->questions_section);
	free_dns_subsection(dr->answers, dr->answers_section);
	free_dns_subsection(dr->authority, dr->authority_section);
	free_dns_subsection(dr->additional, dr->additional_section);
	xfree(dr);
}


static void initialize_dns_pdu(struct dns_pdu *dp)
{
	dp->edns0_max_payload = DEFAULT_PDU_MAX_PAYLOAD_SIZE;
	dp->edns0_enabled = EDNS0_DISABLED; /* sure, if the client signals nothing */
}


struct dns_pdu *alloc_dns_pdu(void)
{
	struct dns_pdu *dr;
	dr = xzalloc(sizeof(*dr));
	initialize_dns_pdu(dr);
	return dr;
}


void free_dns_journey_list_entry(void *d)
{
	free_dns_journey(d);
}

static void initialize_dns_journey(struct dns_journey *j)
{
	j->max_payload_size = DEFAULT_PDU_MAX_PAYLOAD_SIZE;
}

struct dns_journey *alloc_dns_journey(void)
{
	struct dns_journey *j;

	j = xzalloc(sizeof(*j));
	initialize_dns_journey(j);

	return j;
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

			if (x->p_req_dns_pdu->answer_data)
				xfree(x->p_req_dns_pdu->answer_data);
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

			if (x->a_req_dns_pdu->answer_data)
				xfree(x->a_req_dns_pdu->answer_data);
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

			if (x->p_res_dns_pdu->answer_data)
				xfree(x->p_res_dns_pdu->answer_data);
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


void pretty_print_flags(FILE *fp, uint16_t flags)
{
	switch ((flags & 0x8000) >> 15) {
	case 1: fprintf(fp, "QR set: response, "); break;
	case 0: fprintf(fp, "QR set: query, "); break;
	default: fprintf(fp, "QR set: UNKNOWN, "); break;
	}

	switch ((flags & 0x7800) >> 11) {
	case 0: fprintf(fp, "opcode: standard query, "); break;
	case 1: fprintf(fp, "opcode: inverse query, "); break;
	case 2: fprintf(fp, "opcode: server status request, "); break;
	default: fprintf(fp, "opcode: UNKNOWN, "); break;
	}

	switch ((flags & 0x0400) >> 10) {
	case 1: fprintf(fp, "AA: authoritative answer, "); break;
	case 0: fprintf(fp, "AA: non-authoritative answer, "); break;
	default: /* could not happened */ break;
	}

	switch ((flags & 0x0200) >> 9) {
	case 1: fprintf(fp, "TC: truncated, "); break;
	case 0: fprintf(fp, "TC: not truncated, "); break;
	default: /* could not happened */ break;
	}

	switch ((flags & 0x0100) >> 8) {
	case 1: fprintf(fp, "RD: recursion desired, "); break;
	case 0: fprintf(fp, "RD: no recursion desired, "); break;
	default: /* could not happened */ break;
	}

	switch ((flags & 0x0080) >> 7) {
	case 1: fprintf(fp, "RA: recursive available, "); break;
	case 0: fprintf(fp, "RA: recursive not available, "); break;
	default: /* could not happened */ break;
	}

	switch (flags & 0x000f) {
	case 0: fprintf(fp, "RCODE: no error, "); break;
	case 3: fprintf(fp, "RCODE: name error, "); break;
	default: fprintf(fp, "RCODE: UNKNWON error, "); break;
	}

	fprintf(fp, "\n");
}


int get8(const char *data, size_t idx, size_t max, uint8_t *ret)
{
	uint16_t tmp;

	if (idx + 1 > max)
		return FAILURE;

	memcpy(&tmp, data + idx, 1);
	*ret = tmp;
	return 1;
}


int get16(const char *data, size_t idx, size_t max, uint16_t *ret)
{
	uint16_t tmp;

	if (idx + 2 > max)
		return FAILURE;

	memcpy(&tmp, data + idx, 2);
	*ret = ntohs(tmp);
	return 2;
}


int getint32_t(const char *data, size_t idx, size_t max, int32_t *ret)
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

void packet_set_transaction_id(char *packet, uint16_t id)
{
	uint16_t *packet_id;

	packet_id = &packet[0];

	*packet_id = id;
}

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

#define	MAX_DNS_NAME 256

/* returns the number of bytes for the parsed section
 * or 0 in the case of an error
 */
static unsigned parse_rr_section(struct ctx *ctx, struct dns_pdu *dr,
		const char *packet,
		unsigned offset, const size_t max_len,
		struct dns_sub_section **dnssq_ret)
{
	int ret, i, type_offset;
	struct dns_sub_section *dnssq;
	char name[MAX_DNS_NAME];

	(void) ctx;

	i = get_name(packet, offset, max_len, name, MAX_DNS_NAME);
	if (i == FAILURE) {
		err_msg("corrupted name format");
		return FAILURE;
	}

	pr_debug("parsed name: \"%s\" (new offset: %d)", name, i);

	dnssq = xzalloc(sizeof(struct dns_sub_section));

	/* save name */
	dnssq->name = xzalloc(strlen(name) + 1);
	memcpy(dnssq->name, name, strlen(name) + 1);

	type_offset = i;

	/* FIXME: There should be a parser for all
	 * types: a, aaaa, aaaaa, aaaaaaaa, ... */
	i += get16(packet, i, max_len, &dnssq->type);
	i += get16(packet, i, max_len, &dnssq->class);
	i += getint32_t(packet, i, max_len, &dnssq->ttl);
	i += get16(packet, i, max_len, &dnssq->rdlength);

	/* FIXME: what if something goes wrong in this section.
	 * Should we skip this section silently, drop the packet
	 * or transparently interpret the data? To be forward
	 * compatible the generic parser function should
	 * transparently save the data. Think about new types
	 * and the situation when the type isn't supported
	 * correctly. ret must be substituted with i as used
	 * in the former calls to getXXX() */
	ret = type_fn_table[type_opts_to_index(dnssq->type)].parse(
			ctx, dr, dnssq, packet + type_offset,
			max_len - type_offset);
	if (ret != SUCCESS) {
		i += dnssq->rdlength;
		free(dnssq->name);
		free(dnssq);
		*dnssq_ret = NULL;
		return -1;
	}

	pr_debug("parsed type: %s(%u), parsed class: %s (%u)ttl: %u rdlength: %u",
			type_to_str(dnssq->type), dnssq->type,
			class_to_str(dnssq->class), dnssq->class,
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

	dr = alloc_dns_pdu();

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
	   4.1.2. Question section format

	   The question section is used to carry the "question" in most queries,
	   i.e., the parameters that define what is being asked.  The section
	   contains QDCOUNT (usually 1) entries, each of the following format:

	   1  1  1  1  1  1
	   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
	   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	   |                                               |
	   /                     QNAME                     /
	   /                                               /
	   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	   |                     QTYPE                     |
	   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	   |                     QCLASS                    |
	   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	   */

	/* parse queuestions */
	if (dr->questions > 0) {

		pr_debug("parse section: questions");

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

	dr->questions_section_len = i - DNS_PDU_HEADER_LEN;

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
	/* parse answers */
	if (dr->answers > 0) {

		pr_debug("parse section: answers");

		dr->answers_section = xzalloc(sizeof(struct dns_sub_section *) * dr->answers);

		/* save offset of this section */
		dr->answers_section_ptr = (char *)packet + i;

		for (j = 0; j < dr->answers; j++) {
			struct dns_sub_section *dnssq;

			i = parse_rr_section(ctx, dr, packet, i, len, &dnssq);
			if (i < 1) {
				err_msg("cannot parse rr section, I skip this packet");
				goto err_answer;
			}

			/* splice this section */
			dr->answers_section[j] = dnssq;

			/* XXX: the error check is here to simplify the
			 * error path to free() the allocated memory */
			if (is_valid_type(dnssq->type) != SUCCESS) {
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

	dr->answers_section_len = i - dr->questions_section_len - DNS_PDU_HEADER_LEN;

	/* parse authority */
	if (dr->authority > 0) {

		pr_debug("parse section: authority");

		dr->authority_section = xzalloc(sizeof(struct dns_sub_section *) * dr->authority);

		/* save offset of this section */
		dr->authority_section_ptr = packet + i;

		for (j = 0; j < dr->authority; j++) {
			struct dns_sub_section *dnssq;

			i = parse_rr_section(ctx, dr, packet, i, len, &dnssq);
			if (i < 1) {
				err_msg("cannot parse rr section, I skip this packet");
				goto err_authority;
			}

			dr->authority_section[j] = dnssq;

			/* XXX: the error check is here to simplify the
			 * error path to free() the allocated memory */
			if (is_valid_type(dnssq->type) != SUCCESS) {
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

	dr->authority_section_len = i - dr->questions_section_len - dr->answers_section_len - DNS_PDU_HEADER_LEN;

	/* parse additional */
	if (dr->additional > 0) {

		pr_debug("parse section: additional");

		dr->additional_section = xzalloc(sizeof(struct dns_sub_section *) * dr->additional);

		/* save offset of this section */
		dr->additional_section_ptr = packet + i;

		for (j = 0; j < dr->additional; j++) {
			struct dns_sub_section *dnssq;

			i = parse_rr_section(ctx, dr, packet, i, len, &dnssq);
			if (i < 1) {
				err_msg("cannot parse rr section, I skip this packet");
				goto err_additional;
			}

			dr->additional_section[j] = dnssq;

			/* XXX: the error check is here to simplify the
			 * error path to free() the allocated memory */
			if (is_valid_type(dnssq->type) != SUCCESS) {
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
		dr->answers_section_len - dr->authority_section_len - DNS_PDU_HEADER_LEN;

	*dns_pdu = dr;
	return SUCCESS;
}

