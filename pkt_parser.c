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

struct dns_sub_section {
	char *label; /* the already restructed label */
	uint16_t type;
	uint16_t class;
};

struct dns_pdu {

	/* request intrinsic values */
	uint16_t id;
	uint16_t flags;
	uint16_t questions;
	uint16_t answers;
	uint16_t authority;
	uint16_t additional;

	struct dns_sub_section **questions_section;
	struct dns_sub_section **answers_section;
	struct dns_sub_section **authority_section;
	struct dns_sub_section **additional_section;
};


#define	IS_DNS_QUESTION(x) (x & DNS_FLAG_MASK_QUESTION)
#define	IS_DNS_STANDARD_QUERY(x) (x & DNS_FLAG_STANDARD_QUERY)

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

#define	MAX_DNS_NAME 256


int parse_dns_packet(struct ctx *ctx, const char *packet, const size_t len,
		struct dns_pdu **dns_pdu)
{
	int ret, i = 0, ii, j;
	struct dns_pdu *dr;

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
				return;
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
				return;
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
				return;
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
				return;
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
			}
		}
	}

	*dns_pdu = dr;
	return SUCCESS;
}



/* vim: set tw=78 ts=4 sw=4 sts=4 ff=unix noet: */
