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



/* return the position of the label in the current message, or -1 if the label */
/* hasn't been used yet. */
static int
dnslabel_table_get_pos(const struct dnslabel_table *table, const char *label)
{
	int i;
	for (i = 0; i < table->n_labels; ++i) {
		if (!strcmp(label, table->labels[i].v))
			return table->labels[i].pos;
	}
	return -1;
}

/* remember that we've used the label at position pos */
static int
dnslabel_table_add(struct dnslabel_table *table, const char *label, off_t pos)
{
	char *v;
	int p;

	if (table->n_labels == MAX_LABELS)
		return -1;

	v = xstrdup(label);
	if (v == NULL)
		return -1;

	p = table->n_labels++;

	table->labels[p].v   = v;
	table->labels[p].pos = pos;

	return 0;
}

/* Converts a string to a length-prefixed set of DNS labels, starting */
/* at buf[j]. name and buf must not overlap. name_len should be the length */
/* of name.	 table is optional, and is used for compression. */
/* */
/* Input: abc.def */
/* Output: <3>abc<3>def<0> */
/* */
/* Returns the first index after the encoded name, or negative on error. */
/*	 -1	 label was > 63 bytes */
/*	 -2	 name too long to fit in buffer. */
/* */
off_t dnsname_to_labels(char *buf, size_t buf_len, off_t j,
				  const char *name, const int name_len,
				  struct dnslabel_table *table) {
	const char *end = name + name_len;
	int ref = 0;
	uint16_t _t;

#define APPEND16(x) do {						\
		if (j + 2 > (off_t)buf_len)				\
			goto overflow;					\
		_t = htons(x);						\
		memcpy(buf + j, &_t, 2);				\
		j += 2;							\
	} while (0)
#define APPEND32(x) do {						\
		if (j + 4 > (off_t)buf_len)				\
			goto overflow;					\
		_t32 = htonl(x);					\
		memcpy(buf + j, &_t32, 4);				\
		j += 4;							\
	} while (0)

	if (name_len > 255) {
		pr_debug("name is longer then 255 characters - "
				" that is now spec conform! ;)");
		return -2;
	}

	for (;;) {
		const char *const start = name;
		if (table && (ref = dnslabel_table_get_pos(table, name)) >= 0) {
			APPEND16(ref | 0xc000);
			return j;
		}
		name = strchr(name, '.');
		if (!name) {
			const unsigned int label_len = end - start;
			if (label_len > 63)
				return -1;

			if ((size_t)(j+label_len+1) > buf_len)
				return -2;

			if (table)
				dnslabel_table_add(table, start, j);

			buf[j++] = label_len;

			memcpy(buf + j, start, end - start);
			j += end - start;
			break;
		} else {
			/* append length of the label. */
			const unsigned int label_len = name - start;
			if (label_len > 63)
				return -1;

			if ((size_t)(j+label_len+1) > buf_len)
				return -2;

			if (table)
				dnslabel_table_add(table, start, j);

			buf[j++] = label_len;

			memcpy(buf + j, start, name - start);
			j += name - start;

			/* hop over the '.' */
			name++;
		}
	}

	/* the labels must be terminated by a 0. */
	/* It's possible that the name ended in a . */
	/* in which case the zero is already there */
	if (!j || buf[j - 1])
		buf[j++] = 0;

	return j;

 overflow:
	return -2;
}


/* pkt_construct_dns_query - construct a DNS packet for DNS
 * forwarder */
int pkt_construct_dns_query(struct ctx *ctx, struct dns_journey *dnsj,
		char *name, int name_len, uint16_t trans_id, uint16_t type,
		uint16_t class, char *buf, size_t buf_len)
{
	off_t j = 0;  /* current offset into buf */
	uint16_t _t;	 /* used by the macros */

	(void) ctx;
	(void) dnsj;

	APPEND16(trans_id);
	APPEND16(0x0100);  /* standard query, recursion needed */
	APPEND16(1);  /* one question */
	APPEND16(0);  /* no answers */
	APPEND16(0);  /* no authority */
	APPEND16(0);  /* no additional */


	dns_packet_set_rr_entries_number(buf, RR_SECTION_QDCOUNT, 1);
	dns_packet_set_rr_entries_number(buf, RR_SECTION_ANCOUNT, 0);
	dns_packet_set_rr_entries_number(buf, RR_SECTION_NSCOUNT, 0);
	dns_packet_set_rr_entries_number(buf, RR_SECTION_ARCOUNT, 0);

	j = dnsname_to_labels(buf, buf_len, j, name, name_len, NULL);
	if (j < 0)
		return j;

	APPEND16(type);
	APPEND16(class);

#if 0
	/* send a EDNS0 enabled DNS request if
	 * our configuration does not explicit disable the
	 * feature - which is nowadays standard. This configuration
	 * is complete independent from the user request ability to
	 * support EDNS0 or not. In the case that the message is
	 * to big we will later remove some parts and signal the
	 * resolver that the message was truncated. */
	if (ctx->cli_opts.edns0_mode == EDNS0_ENABLED) {
		j += type_041_opt_construct_option(dnsj, buf, j, buf_len);
		dns_packet_set_rr_entries_number(buf, RR_SECTION_ARCOUNT, 1);
	}
#endif


	return j;

 overflow:
	return -1;
}
