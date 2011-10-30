/*
** Copyright (C) 2011 - Hagen Paul Pfeifer <hagen@jauu.net>
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
#include "cache.h"

static int sanitze_line(char *line)
{
	/* Comment? */
	if (line[0] == '#')
		return -1;

	/* empty line */
	if (line[0] == '\n')
		return -1;

	/* remove trailing newline */
	if (line[strlen(line) - 1] == '\n')
		line[strlen(line) - 1] = '\0';

	return 0;
}


static int split_and_process(struct ctx *ctx, char *line)
{
	int ret, n, rt;
	char field[16];
	struct cache_data *cd;

	/* parse identifier */
	ret = sscanf(line, "%15[^ \t]%n", field, &n);
	if (ret != 1) {
		err_msg_die(EXIT_FAILCONF, "malformed zone conf %s", line);
		return FAILURE;
	}

	rt = str_record_type(field, n);
	if (rt < 0) {
		err_msg_die(EXIT_FAILCONF, "record %s not supported", field);
		return FAILURE;
	}

	line += n; /* point to the first whitespace */
	line = eat_whitespaces(line);

	if (!type_fn_table[type_opts_to_index(rt)].zone_parser_to_cache_data) {
		err_msg("record type has no registered parser - implementation error");
		return FAILURE;
	}

	cd = type_fn_table[type_opts_to_index(rt)].zone_parser_to_cache_data(ctx, line);
	if (!cd) {
		err_msg("not supported (yet)");
		goto err;
	}


	ret = cache_add(ctx, cd);
	if (ret != SUCCESS) {
		err_msg("Failed to add ressource record to database");
		goto err_mem;
	}

	return SUCCESS;

err_mem:
	cache_data_free(cd);
err:
	return FAILURE;
}


int parse_zonefiles(struct ctx *ctx)
{
	FILE *fp;
	char *line = NULL;
	size_t len = 0;
	ssize_t readn; int ret;
	struct list_element *ele;
	struct list *filename_list = ctx->zone_filename_list;

	pr_debug("parse zone files");

	for (ele = list_head(filename_list); ele != NULL; ele = list_next(ele)) {

		const char *fname = list_data(ele);
		pr_debug("process file \"%s\"", fname);

		fp = fopen(fname, "r");
		if (fp == NULL)
			err_sys_die(EXIT_FAILNET, "Cannot open zone file: %s", fname);

		while ((readn = getline(&line, &len, fp)) != -1) {

			ret = sanitze_line(line);
			if (ret != SUCCESS)
				continue;

			ret = split_and_process(ctx, line);
			if (ret != SUCCESS) {
				wrn_msg("ignore zonefile entry \"%s\" - not critical",
						line);
			}
		}

		free(line);
		fclose(fp);
	}

	return SUCCESS;
}
