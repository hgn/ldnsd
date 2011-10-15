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

#include "ldnsd.h"
#include "clist.h"

enum nameserver_status {
	WORKING = 1,
	NON_WORKING,
	UNTESTET,
};


static struct nameserver *nameserver_alloc(void)
{
	return xzalloc(sizeof(struct nameserver));
}


static void nameserver_free(void *nsp)
{
	struct nameserver *ns = nsp;
	if (ns->ip)
		free(ns->ip);
	free(ns);
}

static const char *family_str(int ai_family)
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


static int ev_register_ns_socket(struct ctx *ctx, int fd,
		void (*cb)(int, int, void *))
{
	int ret;
	struct ev_entry *ev_entry;

	ev_entry = ev_entry_new(fd, EV_READ, cb, ctx);
	if (!ev_entry) {
		err_msg("Cannot add listening socke to the event handling abstraction");
		return FAILURE;
	}

	ret = ev_add(ctx->ev_hndl, ev_entry);
	if (ret != EV_SUCCESS) {
		err_msg("Cannot add listening socket to the event handling abstraction");
		return FAILURE;
	}

	return SUCCESS;
}


/* adds a nameserver to the global list of nameservers */
int nameserver_add(struct ctx *ctx, const char *ns_str, const char *ns_port,
		void (*cb_read)(int, int, void *))
{
	int ret, fd = -1;
	struct nameserver *ns;
	struct addrinfo hosthints, *hostres, *addrtmp;
	struct sockaddr_storage ss;
	socklen_t ss_len;

	memset(&ss, 0, sizeof(ss));

	pr_debug("try to add nameserver %s:%s", ns_str, ns_port);

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

		pr_debug("found a valuable socket: %s", family_str(addrtmp->ai_family));

		/* great, found a valuable socket */
		memcpy(&ss, addrtmp->ai_addr, addrtmp->ai_addrlen);
		ss_len = addrtmp->ai_addrlen;
		break;

	}

	freeaddrinfo(hostres);


	if (fd < 0) {
		err_msg_die(EXIT_FAILNET,
				"cannot connect to nameserver %s", ns_str);
	}

	pr_debug("successful connect UDP socket with nameserver %s at port %s",
			ns_str, ns_port);


	ns = nameserver_alloc();
	ns->ip = xstrdup(ns_str);

	ret = ev_set_non_blocking(fd);
	if (ret != EV_SUCCESS) {
		err_msg_die(EXIT_FAILNET, "failure to set server socket nonblocking");
	}


	/* save filedescriptor */
	ns->socket = fd;

	memcpy(&ns->address, &ss, sizeof(ss));
	ns->address_len = ss_len;

	ns->status = NS_STATUS_NEW;

	/* register at our event handling machinery */
	ret = ev_register_ns_socket(ctx, fd, cb_read);
	if (ret != SUCCESS) {
		err_msg("cannot register nameserver socket at the event handling machinery");
		nameserver_free(ns);
		return FAILURE;
	}



	ret = list_insert(ctx->nameserver_list, ns);
	if (ret != SUCCESS) {
		err_msg("cannot insert nameserver into global nameserver list");
		nameserver_free(ns);
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


static void nameserver_id(struct nameserver *ns)
{
	return ns->ip;
}


static struct nameserver *nameserver_random(const struct ctx *ctx)
{
	int ret = 0, selected;
	struct nameserver *ns;
	struct list_element *ele;
	struct list *ns_list = ctx->nameserver_list;

	if (ns_list->size < 1)
		return NULL;

	selected = random() % ns_list->size;

	for (ele = list_head(ns_list); ele != NULL;) {
		if (!selected--) {
			ns = list_data(ele);
			pr_debug("select ns %s", ns->ip);
			return ns;
		}
		ele = list_next(ele);
	}

	return list_data(list_head(ns_list));
}


struct nameserver *nameserver_select(const struct ctx *ctx)
{
	pr_debug("select nameserver for query");

	switch (ctx->ns_select_strategy) {
	case FIRST:
		return nameserver_first(ctx);
		break;
	case RANDOM:
		return nameserver_random(ctx);
		break;
	case TIME:
		break;
	case UNSUPPORTED: /* fall-through */
	default:
		err_msg("internal error, nameserver selection stragety unknown");
		/* this should never happend, but we are liberal and
		 * return the first one */
	}

	return nameserver_first(ctx);
}


/* return true if both nameservers are equal or
 * false otherwise */
static int nameserver_match(const void *a1, const void *a2)
{
	const struct nameserver *ns1 = a1, *ns2 = a2;

	if (ns1->address_len != ns2->address_len)
		return 0;

	return !memcmp(&ns1->address, &ns2->address, ns1->address_len);
}

enum ns_select_strategy ns_select_strategy_to_enum(const char *str)
{
	if (!strcmp(str, "first"))
		return FIRST;
	else if (!strcmp(str, "random"))
		return RANDOM;
	else if (!strcmp(str, "time"))
		return TIME;
	else
		return UNSUPPORTED;
}


int nameserver_init(struct ctx *ctx)
{
	ctx->nameserver_list = list_create(nameserver_match, nameserver_free);
	if (!ctx->nameserver_list)
		return FAILURE;

	return SUCCESS;
}

