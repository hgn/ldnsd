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
#include <errno.h>
#include <signal.h>

#define DEFAULT_TCP_STATISTIC_BACKLOG 128
#define DEFAULT_TCP_STATISTIC_PORT "9999"

static void xxx(struct ev *ev, int fd)
{
	struct ev_entry ev_entry;

	ev_entry.fd = fd;

	ev_del(ev, &ev_entry);
}


static void process_established_client_cb(int fd, int what, void *data)
{
	int rret, ret;
	char buf[128];
	struct ctx *ctx;

	(void) what;

	ctx = data;

	fprintf(stdout, "process established client request\n");

	/* No failure catched here, anyway, the loop exit if EWOULDBLOCK
	 * is active too, so this is all we want */
	while ((rret = read(fd, buf, sizeof(buf))) > 0) {
		ret = write(fd, buf, rret);
		if (ret < 0 && errno == EWOULDBLOCK) {
			/* FIXME: this is up to the reader, we should add
			 * the client fd via EV_WRITE, we should defer
			 * therefore write() and later on when buffer is
			 * available we should resend. Currently this is not
			 * catched here */
			fprintf(stderr, "pipe full, would block\n");
			return;
		}

		if (ret < 0 && errno == EPIPE) {
			fprintf(stderr, "broken pipe, remove event structure from event mechanism\n");
			xxx(ctx->ev_hndl, fd);
			return;
		}
	}

	if (rret == 0) {
		/* read comment and handle comment - this is demonstration only code */
		fprintf(stderr, "broken pipe, remove event structure from event mechanism\n");
		xxx(ctx->ev_hndl, fd);
	}

	fprintf(stdout, "process_established_client_cb() return to epoll/select loop\n");

	sleep(1);

	return;
}


static void process_new_client(struct ctx *ctx, int cli_fd)
{
	int ret;
	struct ev_entry *ev_entry;

	fprintf(stdout, "process new client\n");

	/* try to read data from client first */
	process_established_client_cb(cli_fd, EV_READ, ctx);

	/* now we put the cli_fd in the event queue as well */
	ev_entry = ev_entry_new(cli_fd, EV_READ, &process_established_client_cb, ctx);
	if (!ev_entry) {
		fprintf(stderr, "failure in creating ev event structure\n");
		return;
	}

	ret = ev_add(ctx->ev_hndl, ev_entry);
	if (ret != EV_SUCCESS) {
		fprintf(stderr, "Cannot add ev event to event mechanism\n");
		return;
	}
}


static void accept_cb(int fd, int what, void *data)
{
	int cli_fd, ret;
	struct ctx *ctx;
	struct sockaddr_storage sa;
	socklen_t sa_len = sizeof sa;
	char hbuf[NI_MAXHOST], sbuf[NI_MAXSERV];

	(void) what;

	ctx = data;

	fprintf(stdout, "accept callback called\n");

	cli_fd = accept(fd, (struct sockaddr *) &sa, &sa_len);
	if (cli_fd == -1) {
		if (errno == EWOULDBLOCK) {
			fprintf(stderr, "accept return EWOULDBLOCK\n");
			return;
		}

		fprintf(stderr, "accept() error: %s\n", strerror(errno));
		return;
	}

	ret = ev_set_non_blocking(cli_fd);
	if (ret != EV_SUCCESS) {
		fprintf(stderr, "cannot set non-blocking\n");
		return;
	}

	ret = getnameinfo((struct sockaddr *)&sa, sa_len, hbuf,
			NI_MAXHOST, sbuf, NI_MAXSERV, NI_NUMERICHOST | NI_NUMERICSERV);
	if (ret != 0) {
		fprintf(stderr, "getnameinfo error: %s\n",  gai_strerror(ret));
		return;
	}

	fprintf(stdout, "connection established from %s:%s\n", hbuf, sbuf);

	process_new_client(ctx, cli_fd);
}


static int ev_add_tcp_server_socket(struct ctx *ctx, int fd)
{
	int ret;
	struct ev_entry *ev_entry;

	ret = ev_set_non_blocking(fd);
	if (ret != EV_SUCCESS) {
		err_msg("Cannot set server socket to work in a non-blocking manner");
		return FAILURE;
	}

	ev_entry = ev_entry_new(fd, EV_READ, &accept_cb, ctx);
	if (!ev_entry) {
		err_msg("Cannot add listening socke to the event handling abstraction");
		return FAILURE;
	}

	ret = ev_add(ctx->ev_hndl, ev_entry);
	if (ret != EV_SUCCESS) {
		err_msg("Cannot add listening socke to the event handling abstraction");
		return FAILURE;
	}

	return SUCCESS;
}

void destroy_tcp_statistic(struct ctx *ctx)
{
	close(ctx->tcp_statistic_socket);
}


/* open a passive server socket, bind to localhost */
static int open_server_socket(int af_family, const char *port)
{
	int ret, fd = -1, on = 1;
	struct addrinfo hosthints, *hostres, *addrtmp;
	struct protoent *protoent;

	memset(&hosthints, 0, sizeof(struct addrinfo));

	hosthints.ai_family   = af_family;
	hosthints.ai_socktype = SOCK_STREAM;
	hosthints.ai_protocol = IPPROTO_TCP;
	hosthints.ai_flags    = AI_ADDRCONFIG | AI_PASSIVE;

	ret = getaddrinfo(NULL, port, &hosthints, &hostres);
	if (ret != 0) {
		fprintf(stderr, "failure in getaddrinfo: %s\n",
				(ret == EAI_SYSTEM) ?  strerror(errno) : gai_strerror(ret));
		return -1;
	}

	for (addrtmp = hostres; addrtmp != NULL ; addrtmp = addrtmp->ai_next) {
		fd = socket(addrtmp->ai_family, addrtmp->ai_socktype, addrtmp->ai_protocol);
		if (fd < 0)
			continue;

		protoent = getprotobynumber(addrtmp->ai_protocol);
		if (protoent)
			fprintf(stdout, "socket created - protocol %s(%d)\n",
					protoent->p_name, protoent->p_proto);


		ret = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
		if (ret) {
			fprintf(stderr, "failure in setsockopt(): %s\n", strerror(errno));
			return  -1;
		}

		ret = bind(fd, addrtmp->ai_addr, addrtmp->ai_addrlen);
		if (ret) {
			fprintf(stderr, "bind failed: %s\n", strerror(errno));
			close(fd);
			fd = -1;
			continue;
		}

		ret = listen(fd, DEFAULT_TCP_STATISTIC_BACKLOG);
		if (ret < 0) {
			fprintf(stderr, "listen failed: %s\n", strerror(errno));
			close(fd);
			fd = -1;
			continue;
		}

		/* great, found a valuable socket */
		break;
	}

	if (fd < 0) {
		fprintf(stderr, "Don't found a suitable TCP socket to connect to the client"
				", giving up");
		return -1;
	}

	fprintf(stdout, "bind to port %s via TCP using IPPROTO_TCP socket [%s:%s]\n",
			port,
			addrtmp->ai_family == AF_INET ? "0.0.0.0" : "::", port);

	freeaddrinfo(hostres);

	ret = ev_set_non_blocking(fd);
	if (ret != EV_SUCCESS) {
		fprintf(stderr, "cannot set non-blocking\n");
		return -1;
	}

	return fd;

}

int init_tcp_statistic(struct ctx *ctx)
{
	int ret;
        struct sigaction sa = { .sa_handler = SIG_IGN };

	pr_debug("initialize TCP statistic subsystem");

        sigemptyset(&sa.sa_mask);
        sa.sa_flags = 0;

        ret = sigaction(SIGPIPE, &sa, NULL);
        if (ret == -1) {
                fprintf(stderr, "Cannot ignore SIGPIPE: %s\n", strerror(errno));
                return EXIT_FAILURE;
        }

	ctx->tcp_statistic_socket = open_server_socket(AF_UNSPEC, DEFAULT_TCP_STATISTIC_PORT);
	if (ctx->tcp_statistic_socket< 0) {
		fprintf(stderr, "Cannot open server socket\n");
		exit(EXIT_FAILURE);
	}


	ret = ev_add_tcp_server_socket(ctx, ctx->tcp_statistic_socket);
	if (ret != SUCCESS) {
		err_msg("Cannot initialize TCP statistic socket to event framework");
		destroy_tcp_statistic(ctx);
		return FAILURE;
	}

	return SUCCESS;
}


