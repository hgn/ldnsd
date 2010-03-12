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

/* XXX: please don't change the ordering! New
 * supported options should appended here and the
 * corresponding index in the type_opts array must
 * be defined in ldnsd.h - see TYPE_INDEX_41.
 * Additionaly you must adjust type_opts_to_index()
 * to recognize the new option. Thats all */
struct type_opts type_opts[] = {
	{ type_041_opt_text, type_041_opt_parse },
	{ type_999_generic_text, type_999_generic_parse }
};

unsigned type_opts_to_index(uint16_t t)
{
	switch (t) {
		case 41:
			return TYPE_INDEX_41;
			break;
		default:
			return TYPE_INDEX_999;
			break;
	};
	return TYPE_INDEX_999;
}


const char *type_999_generic_text(void)
{
	return "type 999 generic parser";
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

int type_999_generic_construct_option(struct dns_journey *dnsj,
		char *packet, int offset, size_t max_len)
{
	(void) dnsj;
	(void) packet;
	(void) offset;
	(void) max_len;

	return 0;
}

int type_999_generic_available(struct dns_pdu *dns_pdu)
{
	(void) dns_pdu;

	return 0;
}

/* vim: set tw=78 ts=4 sw=4 sts=4 ff=unix noet: */
