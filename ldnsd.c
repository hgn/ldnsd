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

#include "ldnsd.h"
#include "rc.h"



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


static struct ctx *alloc_ctx(void)
{
	return xzalloc(sizeof(struct ctx));
}


static void free_ctx(struct ctx *c)
{
	free(c); c = NULL;
}


int main(int ac, char **av)
{
	int ret, flags = 0;
	struct ctx *ctx;

	fprintf(stdout, "ldnsd - a lighweight caching and forwarding DNS server (C) 2009\n");

	ret = initiate_seed();
	if (ret == FAILURE) {
		err_msg("PRNG cannot be initialized satisfying (fallback to time(3) and getpid(3))");
	}

	ctx = alloc_ctx();

	ctx->ev_hndl = ev_init_hdntl();

	ret = parse_cli_options(ctx, &ctx->cli_opts, ac, av);
	if (ret != SUCCESS)
		err_msg_die(EXIT_FAILOPT, "failure in commandline argument");

	if (ctx->cli_opts.rc_path) {
		/* currently there is no need to specify a configuration
		 * file, the functionality is simple enough to run without
		 * any arguments, if things change we can enfore a configuration
		 * file --HGN */
		ret = parse_rc_file(ctx);
		if (ret != SUCCESS)
			err_msg_die(EXIT_FAILURE, "Can't parse configuration file");
	}

	/* ok, parsing is done - we now need to
	 * allocate the memory for our packet construction
	 * buffer */
	ctx->buf = xmalloc(ctx->cli_opts.edns0_max);
	ctx->buf_max = ctx->cli_opts.edns0_max;
	assert(ctx->buf_max >= 512);

	ret = init_server_side(ctx);
	if (ret != SUCCESS)
		err_msg_die(EXIT_FAILMISC, "cannot initialize server side");

	ret = init_client_side(ctx);
	if (ret != SUCCESS)
		err_msg_die(EXIT_FAILMISC, "cannot initialize client side");

	ev_loop(ctx->ev_hndl, flags);

	fini_server_socket(ctx->client_server_socket);
	ev_free_hndl(ctx->ev_hndl);
	free_cli_opts(&ctx->cli_opts);
	free(ctx->buf);
	free_ctx(ctx);

	return EXIT_SUCCESS;
}



/* vim: set tw=78 ts=4 sw=4 sts=4 ff=unix noet: */
