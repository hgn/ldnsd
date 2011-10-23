/*
** Copyright (C) 2009,2010,2011 - Hagen Paul Pfeifer <hagen@jauu.net>
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

#define DEFAULT_NS_TIME_SELECT_THRESHOLD 100
#define	DEFAULT_TIME_SELECT_RE_THRESHOLD 1000


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
		return -1;
	}

	/* set global seed */
	srandom(randpool);

	close(rand_fd);

	return 0;
}


static struct ev* ev_init_hdntl(void)
{
	struct ev *ev;
	ev = ev_new();
	if (!ev)
		err_msg_die(EXIT_FAILMISC, "Cannot initialize event abstration");

	return ev;
}

static void ev_free_hndl(struct ev *ev)
{
	ev_free(ev);
}


/* return true if both strings are equal or false otherwise */
static int zone_filename_match(const void *a1, const void *a2)
{
	const char *name1 = a1, *name2 = a2;

	return !strncmp(name1, name2, min(strlen(name1), strlen(name2)));
}


static int init_zone_filename_list(struct ctx *ctx)
{
	ctx->zone_filename_list = list_create(zone_filename_match, free);
	if (!ctx->zone_filename_list)
		return FAILURE;

	return SUCCESS;
}


static struct ctx *ctx_init(void)
{
	int ret;

	struct ctx *ctx = xzalloc(sizeof(struct ctx));

	ctx->ns_time_select_threshold = DEFAULT_NS_TIME_SELECT_THRESHOLD;
	ctx->ns_time_select_re_threshold = DEFAULT_TIME_SELECT_RE_THRESHOLD;

	ret = init_zone_filename_list(ctx);
	if (ret != SUCCESS)
		return NULL;

	ctx->mode = DEFAULT_MODE;

	ctx->cache_backend = CACHE_BACKEND_MEMORY;

	return ctx;
}


static void free_ctx(struct ctx *c)
{
	free(c); c = NULL;
}


int main(int ac, char **av)
{
	int ret, flags = 0;
	struct ctx *ctx;

	fprintf(stdout, "ldnsd - a fast and scalable DNS server (C) 2009-2011\n");

	ret = initiate_seed();
	if (ret == FAILURE) {
		err_msg("PRNG cannot be initialized satisfying (fallback to time(3) and getpid(3))");
	}

	ctx = ctx_init();
	if (!ctx)
		err_msg_die(EXIT_FAILMISC, "Cannot initialize context");

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

	ret = cache_init(ctx);
	if (ret != SUCCESS)
		err_msg_die(EXIT_FAILMISC, "cannot initialize cache");

	ret = parse_zonefiles(ctx);
	if (ret != SUCCESS)
		err_msg_die(EXIT_FAILMISC, "Failed to parse zone files");


	/* main loop, normaly never exited */
	ev_loop(ctx->ev_hndl, flags);

	fini_server_socket(ctx->client_server_socket);
	ev_free_hndl(ctx->ev_hndl);
	cache_free(ctx);
	free_cli_opts(&ctx->cli_opts);
	free(ctx->buf);
	free_ctx(ctx);

	return EXIT_SUCCESS;
}
