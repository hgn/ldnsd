/*
** Copyright (C) 2009 - Hagen Paul Pfeifer <hagen@jauu.net>
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



static int initiate_seed(void)
{
	ssize_t ret;
	int rand_fd;
	uint32_t randpool;

	/* set randon pool seed */
	rand_fd = open(RANDPOOLSRC, O_RDONLY);
	if (rand_fd < 0)
		err_sys_die(EXIT_FAILINT,
				"Cannot open random pool file %s", RANDPOOLSRC);

	ret = read(rand_fd, &randpool, sizeof(uint32_t));
	if (ret != sizeof(uint32_t)) {
		srandom(time(NULL) & getpid());
		close(rand_fd);
		return FAILURE;
	}

	/* set global seed */
	srandom(randpool);

	close(rand_fd);

	return SUCCESS;
}


static struct ev* ev_init_hdntl(void)
{
	struct ev *ev;
	ev = ev_new();
	if (!ev) {
		err_msg_die(EXIT_FAILMISC, "Cannot initialize event abstration");
	}

	return ev;
}

static void ev_free_hndl(struct ev *ev)
{
	ev_free(ev);
}


struct ctx *alloc_ctx(void)
{
	return xzalloc(sizeof(struct ctx));
}


void free_ctx(struct ctx *c)
{
	free(c); c = NULL;
}

/* default to google ns */
#define	DEFAULT_NS "8.8.8.8"
#define	DEFAULT_NS_PORT "53"


int main(void)
{
	int ret, flags = 0;
	struct ctx *ctx;

	fprintf(stdout, "cachefor - a lighweight caching and forwarding DNS server (C) 2009\n");

	ret = initiate_seed();
	if (ret == FAILURE) {
		err_msg("PRNG cannot be initialized satisfying (fallback to time(3) and getpid(3))");
	}

	ctx = alloc_ctx();

	ctx->ev_hndl = ev_init_hdntl();

#if 0

	ret = nameserver_init(ctx);
	if (ret == FAILURE) {
		err_msg_die(EXIT_FAILMISC, "cannot initialize nameserver context");
	}

	ret = nameserver_add(ctx, DEFAULT_NS, DEFAULT_NS_PORT);
	if (ret != SUCCESS) {
		err_msg_die(EXIT_FAILMISC, "cannot add default nameserver: %s", DEFAULT_NS);
	}

	ret = adns_request_init(ctx);
	if (ret != SUCCESS) {
		err_msg_die(EXIT_FAILMISC,
				"failure in initialize process of server side request structure");
	}

	ret = active_dns_request_set(ctx, "www.google.de", DNS_TYPE_A, DNS_CLASS_INET);
	if (ret != SUCCESS) {
		err_msg("cannot set active DNS request");
	}

#endif

	ret = init_client_side(ctx);
	if (ret != SUCCESS) {
		err_msg_die(EXIT_FAILMISC, "cannot initialize server socket");
	}

	ev_loop(ctx->ev_hndl, flags);

	fini_server_socket(ctx->client_server_socket);

	ev_free_hndl(ctx->ev_hndl);

	free_ctx(ctx);

	return EXIT_SUCCESS;
}



/* vim: set tw=78 ts=4 sw=4 sts=4 ff=unix noet: */
