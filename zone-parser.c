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

#define MAX_HOSTNAME_STR 255 /* including final dot */

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


static char *eat_whitespaces(const char *p)
{
        char *ptr = (char *)p;

        while (1) {
                /* isspace also test for \n, which is not allowed */
                if (*ptr != ' ' && *ptr != '\t')
                        return ptr;
                ptr++;
        }
}


static int time_modifier(char c)
{
        if (c == 's')
                return 1;
        if (c == 'm')
                return 60;
        if (c == 'h')
                return 60 * 60;
        if (c == 'd')
                return 60 * 60 * 24;
        if (c == 'w')
                return 60 * 60 * 24 * 7;

        return -1;
}


static char *parse_ttl(char *str, int *timeval)
{
        int ret, n, timemod = INT_MAX;
        char field[16];

        str++;

        /* parse identifier */
        ret = sscanf(str, "%15[^ \t]%n", field, &n);
        if (ret != 1)
                err_msg_die(EXIT_FAILCONF, "malformed time string %s", str);

        if (n > 1)
                timemod = time_modifier(field[n - 1]);

        if (timemod < 0 || timemod == INT_MAX) {
                timemod = 1;
        }

        *timeval = atoi(field) * timemod;

	if (*timeval > TTL_MAX) {
		err_msg("ttl of record to high (%d) set to %d", *timeval, DEFAULT_TTL);
		*timeval = DEFAULT_TTL;
	}

	if (*timeval < TTL_MIN) {
		err_msg("ttl of record to low (%d) set to %d", *timeval, DEFAULT_TTL);
		*timeval = DEFAULT_TTL;
	}

        return eat_whitespaces(&str[n]);
}


/* A +86400 a.example.net. 192.168.1.1 */
static int rr_parse_a(char *conf)
{
        char *ptr = conf;
        int ret, n;
        char host_str[MAX_HOSTNAME_STR + 1];
	char ip_str[INET_ADDRSTRLEN + 1];
        int timeval = DEFAULT_TTL; /* time in seconds */

        if (ptr[0] == '+')
                ptr = parse_ttl(ptr, &timeval);

        /* parse hostname */
        ret = sscanf(ptr, "%255[^ \t]%n", host_str, &n);
        if (ret != 1)
                err_msg_die(EXIT_FAILCONF, "malformed hostname string: \"%s\"", ptr);

	if (host_str[n - 1] != '.')
		err_msg_die(EXIT_FAILCONF, "malformed hostname: "
				"\"%s\" - trailing dot missing", ptr);

        ptr += n; /* point to the first whitespace */
        ptr = eat_whitespaces(ptr);

        /* parse ip */
        ret = sscanf(ptr, "%16[^ \t]%n", ip_str, &n);
        if (ret != 1)
                err_msg_die(EXIT_FAILCONF, "malformed ip string: \"%s\"", ptr);

	/* check if the ip is clean */
	if (!(ip_valid_addr(AF_INET, ip_str)))
                err_msg_die(EXIT_FAILCONF, "malformed ip string: \"%s\"", ip_str);

        pr_debug("A record: ttl: %d hostname: %s ipv4: %s", timeval, host_str, ip_str);

        return SUCCESS;
}


/* AAAA +86400 a.example.net. 2001:0DB8:: */
static int rr_parse_aaaa(char *conf)
{
        char *ptr = conf;
        int ret, n;
        char host_str[MAX_HOSTNAME_STR + 1];
	char ip_str[INET6_ADDRSTRLEN + 1];
        int timeval = DEFAULT_TTL; /* time in seconds */

        if (ptr[0] == '+')
                ptr = parse_ttl(ptr, &timeval);

        /* parse hostname */
        ret = sscanf(ptr, "%255[^ \t]%n", host_str, &n);
        if (ret != 1)
                err_msg_die(EXIT_FAILCONF, "malformed hostname string: \"%s\"", ptr);

	if (host_str[n - 1] != '.')
		err_msg_die(EXIT_FAILCONF, "malformed hostname: "
				"\"%s\" - trailing dot missing", ptr);

        ptr += n; /* point to the first whitespace */
        ptr = eat_whitespaces(ptr);

        /* parse ip */
        ret = sscanf(ptr, "%46[^ \t]%n", ip_str, &n);
        if (ret != 1)
                err_msg_die(EXIT_FAILCONF, "malformed ipv6 string: \"%s\"", ptr);

	/* check if the ip is clean */
	if (!(ip_valid_addr(AF_INET6, ip_str)))
                err_msg_die(EXIT_FAILCONF, "malformed ipv6 string: \"%s\"", ip_str);

        pr_debug("AAAA record: ttl: %d hostname: %s ipv6: %s", timeval, host_str, ip_str);

        return SUCCESS;
}


/* MX +86400 example.net. 10 a.example.net. */
static int rr_parse_mx(char *conf)
{
        char *ptr = conf;
        int ret, n, mx_priority;
        char zone_str[MAX_HOSTNAME_STR + 1];
	char mx_str[INET6_ADDRSTRLEN + 1];
        int timeval = DEFAULT_TTL; /* time in seconds */

        if (ptr[0] == '+')
                ptr = parse_ttl(ptr, &timeval);

        /* parse hostname */
        ret = sscanf(ptr, "%255[^ \t]%n", zone_str, &n);
        if (ret != 1)
                err_msg_die(EXIT_FAILCONF, "malformed zone string: \"%s\"", ptr);

	if (zone_str[n - 1] != '.')
		err_msg_die(EXIT_FAILCONF, "malformed zone: "
				"\"%s\" - trailing dot missing", ptr);

        ptr += n; /* point to the first whitespace */
        ptr = eat_whitespaces(ptr);

        /* parse mx prioryty */
        ret = sscanf(ptr, "%d", &mx_priority);
        if (ret != 1)
                err_msg_die(EXIT_FAILCONF, "malformed prioryty string: \"%s\"", ptr);

        /* parse mx name */
        ret = sscanf(ptr, "%255[^ \t]%n", mx_str, &n);
        if (ret != 1)
                err_msg_die(EXIT_FAILCONF, "malformed mx string: \"%s\"", ptr);

        pr_debug("MX record: ttl: %d zone: %s priority: %d mx server: %s",
			timeval, zone_str, mx_priority, mx_str);

        return SUCCESS;
}


static int record_type(const char *str, int str_len)
{
        if (!(strncasecmp(str, "a", str_len)))
                return DNS_TYPE_A;
        if (!(strncasecmp(str, "aaaa", str_len)))
                return DNS_TYPE_AAAA;
        if (!(strncasecmp(str, "ns", str_len)))
                return DNS_TYPE_NS;
        if (!(strncasecmp(str, "cname", str_len)))
                return DNS_TYPE_CNAME;
        if (!(strncasecmp(str, "soa", str_len)))
                return DNS_TYPE_SOA;
        if (!(strncasecmp(str, "ptr", str_len)))
                return DNS_TYPE_PTR;
        if (!(strncasecmp(str, "mx", str_len)))
                return DNS_TYPE_MX;
        if (!(strncasecmp(str, "txt", str_len)))
                return DNS_TYPE_TXT;
        if (!(strncasecmp(str, "aaaa", str_len)))
                return DNS_TYPE_AAAA;

        return -EINVAL;
}


static int split_and_process(char *line)
{
        int ret, n, rt;
        char field[16];

        /* parse identifier */
        ret = sscanf(line, "%15[^ \t]%n", field, &n);
        if (ret != 1) {
                err_msg_die(EXIT_FAILCONF, "malformed zone conf %s", line);
		return FAILURE;
        }

        rt = record_type(field, n);
        if (rt < 0) {
                err_msg_die(EXIT_FAILCONF, "record %s not supported", field);
		return FAILURE;
        }

        line += n; /* point to the first whitespace */
        line = eat_whitespaces(line);

        switch (rt) {
        case DNS_TYPE_A:
                return rr_parse_a(line);
        case DNS_TYPE_AAAA:
                return rr_parse_aaaa(line);
        case DNS_TYPE_MX:
                return rr_parse_mx(line);
        default:
                err_msg("not supported (yet)");
		return FAILURE;
        }


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

			split_and_process(line);
		}

		free(line);
		fclose(fp);
	}

	return SUCCESS;
}
