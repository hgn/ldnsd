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
