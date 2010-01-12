/*
** Copyright (C) 2009,2010 - Hagen Paul Pfeifer <hagen@jauu.net>
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

enum nameserver_status {
	WORKING = 1,
	NON_WORKING,
	UNTESTET,
};


static struct nameserver *nameserver_alloc(void)
{
	return xzalloc(sizeof(struct nameserver));
}


static void nameserver_free(void *ns)
{
	free(ns);
}

const char *ai_family_to_str(int ai_family)
{
	switch (ai_family) {
		case AF_INET:
			return "AF_INET";
			break;
		case AF_INET6:
			return "AF_INET6";
			break;
		default:
			return "unknown";
			break;
	}
}


/* adds a nameserver to the global list of nameservers */
int nameserver_add(struct ctx *ctx, const char *ns_str, const char *ns_port)
{
	int ret, fd;
	struct nameserver *ns;
	struct addrinfo hosthints, *hostres, *addrtmp;
	struct sockaddr_storage ss;
	socklen_t ss_len;

	memset(&ss, 0, sizeof(ss));

	memset(&hosthints, 0, sizeof(hosthints));
	hosthints.ai_socktype = SOCK_DGRAM;
	hosthints.ai_family   = AF_UNSPEC;
	hosthints.ai_flags    = AI_NUMERICHOST;

	xgetaddrinfo(ns_str, ns_port, &hosthints, &hostres);

	for (addrtmp = hostres; addrtmp != NULL ; addrtmp = addrtmp->ai_next) {
		fd = socket(addrtmp->ai_family, addrtmp->ai_socktype, addrtmp->ai_protocol);
		if (fd < 0)
			continue;

		ret = connect(fd, addrtmp->ai_addr, addrtmp->ai_addrlen);
		if (ret == -1) {
			close(fd);
			fd = -1;
			continue;
		}

		pr_debug("found a valuable socket: %s", ai_family_to_str(addrtmp->ai_family));

		/* great, found a valuable socket */
		memcpy(&ss, &addrtmp->ai_addr, addrtmp->ai_addrlen);
		ss_len = addrtmp->ai_addrlen;
		break;

	}

	if (fd < 0) {
		err_msg_die(EXIT_FAILNET,
				"cannot connect to nameserver %s", ns_str);
	}

	freeaddrinfo(hostres);

	pr_debug("successful connect UDP socket with nameserver %s", ns_str);


	ns = nameserver_alloc();

	/* save filedescriptor */
	ns->socket = fd;
	memcpy(&ns->address, &ss, sizeof(ns->address));
	ns->address_len = ss_len;

	ns->status = NS_STATUS_NEW;

	ret = list_insert(ctx->nameserver_list, ns);
	if (ret != SUCCESS) {
		err_msg("cannot insert nameserver into global nameserver list");
		return FAILURE;
	}

	pr_debug("add nameserver %s to the global nameserver list", ns_str);

	return SUCCESS;
}


static struct nameserver *nameserver_first(const struct ctx *ctx)
{
	struct list *ns_list = ctx->nameserver_list;

	if (ns_list->size < 1)
		return NULL;

	return list_data(list_head(ns_list));
}


struct nameserver *nameserver_select(const struct ctx *ctx)
{
	return nameserver_first(ctx);
}


/* return true if both nameservers are equal or
 * false otherwise */
static int nameserver_match(const void *a1, const void *a2)
{
	const struct nameserver *ns1, *ns2;

	ns1 = a1;
	ns2 = a2;

	return !memcmp(ns1, ns2, sizeof(*ns1));
}


int nameserver_init(struct ctx *ctx)
{
	ctx->nameserver_list = list_create(nameserver_match, nameserver_free);

	return SUCCESS;
}




/* vim: set tw=78 ts=4 sw=4 sts=4 ff=unix noet: */