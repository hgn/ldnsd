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

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <getopt.h>


static void set_default_options(struct cli_opts *opts)
{
	memset(opts, 0, sizeof(*opts));

	opts->port           = xstrdup(DEFAULT_LISTEN_PORT);
	opts->forwarder_addr = xstrdup(DEFAULT_NS);
	opts->forwarder_port = xstrdup(DEFAULT_NS_PORT);
}

void free_cli_opts(struct cli_opts *opts)
{
	if (opts->rc_path)
		free(opts->rc_path);

	if (opts->port)
		free(opts->port);

	if (opts->forwarder_addr)
		free(opts->forwarder_addr);

	if (opts->forwarder_port)
		free(opts->forwarder_port);

	free(opts->me);
}

int parse_cli_options(struct ctx *ctx, struct cli_opts *opts, int ac, char **av)
{
	int ret = SUCCESS, c;

	(void) ctx;

	set_default_options(opts);

	opts->me = xstrdup(av[0]);

	while (1) {
		int option_index = 0;
		static struct option long_options[] = {
			{"verbose",          1, 0, 'v'},
			{"quite",            1, 0, 'q'},
			{"configuration",    1, 0, 'f'},
			{0, 0, 0, 0}
		};

		c = getopt_long(ac, av, "f:vq",
				long_options, &option_index);
		if (c == -1)
			break;

		switch (c) {
		case 'v':
			opts->verbose_level++;
			break;
		case 'q':
			opts->verbose_level = O_QUITSCENT;
			break;
		case 'f':
			opts->rc_path = xstrdup(optarg);
			break;
		case '?':
			break;

		default:
			err_msg("getopt returned character code 0%o ?", c);
			return FAILURE;
		}
	}

	return ret;
}



/* vim: set tw=78 ts=4 sw=4 sts=4 ff=unix noet: */