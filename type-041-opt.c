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

struct edns0_option {
	uint8_t  root;
	uint16_t type;
	uint16_t udp_payload_size;
	uint8_t  high_bit_e_rcode;
	uint8_t  version;
	uint16_t z;
	uint16_t data_len;
} __attribute__((__packed__));

struct edns0_option_r {
	uint16_t type;
	uint16_t udp_payload_size;
	uint8_t  high_bit_e_rcode;
	uint8_t  version;
	uint16_t z;
	uint16_t data_len;
};

const char *type_041_opt_text(void)
{
	return "type 041 option";
}


/* data points to the start of type of the type field.
 * The already parsed name is already saved in dnssq->name */
int type_041_opt_parse(struct ctx *ctx, struct dns_pdu *dr, struct dns_sub_section *dnss,
		const char *data, int max_len)
{
	struct edns0_option_r *o = (struct edns0_option_r *)data;

	(void) ctx;
	(void) dnss;

	pr_debug("parse 041_opt type");

	if (max_len < (int)sizeof(*o)) {
		pr_debug("type RR to small to meet the minimal edns0"
				" length requirements");
		return -1;
	}

	dr->edns0_max_payload = ntohs(o->udp_payload_size);
	dr->edns0_enabled = EDNS0_ENABLED;
	pr_debug("edns0 granted payload size: %u", dr->edns0_max_payload);

	/* FIXME: we must check the version too. If
	 * the received version matches with our version.
	 * What should we do if there is a version mismatch.
	 * I should reread the RFC ... ;-) */

	return sizeof(*o) + ntohs(o->data_len);
}

int type_041_opt_construct_option(struct dns_journey *dnsj,
		char *packet, int offset, size_t max_len)
{
	struct edns0_option *o = (struct edns0_option *)(packet + offset);
	/* we need a pointer to the accurate size.
	 * If not we know something is strange */
	if (max_len < TYPE_041_OPT_LEN)
		return -1;

	o->root             = 0; /* root */
	o->type             = htons(41); /* FIXME: define */
	o->udp_payload_size = htons(dnsj->ctx->buf_max);
	o->high_bit_e_rcode = 0x0;
	o->version          = 0x0;
	o->z                = 0x0;
	o->data_len         = 0x0;

	return TYPE_041_OPT_LEN;
}

int type_041_opt_available(struct dns_pdu *dp)
{
	if (dp->edns0_enabled == EDNS0_ENABLED)
		return 1;
	else
		return 0;
}




/* vim: set tw=78 ts=4 sw=4 sts=4 ff=unix noet: */
