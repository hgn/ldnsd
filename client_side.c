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


static int socket_bind(struct addrinfo *a)
{
	int ret, on = 1;
	int fd = socket(a->ai_family, a->ai_socktype, a->ai_protocol);
	if (fd < 0)
		return -1;

	xsetsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on), "SO_REUSEADDR");

	ret = bind(fd, a->ai_addr, a->ai_addrlen);
	if (ret) {
		err_msg("bind failed");
		close(fd);
		return -1;
	}
	return fd;
}


static int init_server_socket(int family, int socktype, int protocol, const char *port)
{
	const char *hostname = NULL;
	int fd = -1;
	struct addrinfo hosthints, *hostres, *addrtmp;

	memset(&hosthints, 0, sizeof(struct addrinfo));

	hosthints.ai_family   = family;
	hosthints.ai_socktype = socktype;
	hosthints.ai_protocol = protocol;
	hosthints.ai_flags    = AI_PASSIVE | AI_ADDRCONFIG;

	xgetaddrinfo(hostname, port, &hosthints, &hostres);

	for (addrtmp = hostres; addrtmp != NULL ; addrtmp = addrtmp->ai_next) {
		fd = socket_bind(addrtmp);
		if (fd < 0)
			continue;

		break;
	}

	if (fd < 0)
		err_msg_die(EXIT_FAILNET,
				"Don't found a suitable address for binding,"
				" giving up (TIP: start program with strace(2)"
				" to find the problen\n");

	freeaddrinfo(hostres);

	return fd;
}


void fini_server_socket(int fd)
{
	close(fd);
}


static int enqueue_request(struct dns_pdu_hndl *dns_pdu_hndl)
{
	assert(dns_pdu_hndl);

	/* attach timeout to request */

	/* enqueue request into the global list of requests */

	return SUCCESS;
}

static void process_dns_query(struct ctx *ctx, const char *packet, const size_t len,
		const struct sockaddr_storage *ss, socklen_t ss_len)
{
	int ret;
	struct dns_pdu_hndl *dns_pdu_hndl;

	dns_pdu_hndl = xzalloc(sizeof(*dns_pdu_hndl));

	ret = parse_dns_packet(ctx, packet, len, &dns_pdu_hndl->dns_pdu);
	if (ret != SUCCESS) {
		err_msg("received an malformed DNS packet, skipping this packet");
		free(dns_pdu_hndl);
		return;
	}

	/* splice context to our dns query */
	dns_pdu_hndl->ctx = ctx;

	if (!IS_DNS_QUESTION(dns_pdu_hndl->dns_pdu->flags)) {
		pr_debug("incoming packet is no QUESTION DNS packet (flags: 0x%x, accepted: 0x%x",
				dns_pdu_hndl->dns_pdu->flags, DNS_FLAG_MASK_QUESTION);
		free_dns_pdu(dns_pdu_hndl->dns_pdu);
		free(dns_pdu_hndl);
		return;
	}

	if (dns_pdu_hndl->dns_pdu->questions < 1) {
		err_msg("incoming DNS request does not contain a DNS request");
		free_dns_pdu(dns_pdu_hndl->dns_pdu);
		free(dns_pdu_hndl);
		return;
	}

	if (dns_pdu_hndl->dns_pdu->questions > 1) {
		err_msg("the current implementation support only DNS request"
				" with one question - this request contains %d questions"
				" so i will skip this packet",
				dns_pdu_hndl->dns_pdu->questions);
		free_dns_pdu(dns_pdu_hndl->dns_pdu);
		free(dns_pdu_hndl);
		return;
	}

	if (dns_pdu_hndl->dns_pdu->answers > 0 ||
		dns_pdu_hndl->dns_pdu->authority > 0 ||
		dns_pdu_hndl->dns_pdu->additional > 0) {
		err_msg("the DNS REQUEST comes with unusual additional sections: "
				"answers: %d, authority: %d, additional: %d. I ignore these "
				"sections!", 1, 1, 1); // FIXME: 1  1 1 
	}

	/* save caller address */
	memcpy(&dns_pdu_hndl->src_ss, ss, sizeof(dns_pdu_hndl->src_ss));
	dns_pdu_hndl->src_ss_len = ss_len;

	/* now we do the actual query */
	ret = enqueue_request(dns_pdu_hndl);
	if (ret != SUCCESS) {
		err_msg("Cannot enqueue request in active queue");
		return;
	}

	return; /* SUCCESS */

}


/* if a incoming client request is coming then this
 * function is called */
static void incoming_request(int fd, int what, void *data)
{
	ssize_t rc;
	char packet[MAX_PACKET_LEN];
	struct sockaddr_storage ss;
	socklen_t ss_len = sizeof(struct sockaddr_storage);
	struct ctx *ctx = data;

	(void) what;

	pr_debug("incoming DNS request");

	rc = recvfrom(fd, packet, MAX_PACKET_LEN, 0, (struct sockaddr*) &ss, &ss_len);
	if (rc < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK)
			return;
		err_sys_die(EXIT_FAILMISC, "Failure in read routine for incoming packet");
	}

	process_dns_query(ctx, packet, rc, &ss, ss_len);
}


static int ev_add_server_socket(struct ctx *ctx, int fd)
{
	int ret;
	struct ev_entry *ev_entry;

	ret = ev_set_non_blocking(fd);
	if (ret != EV_SUCCESS) {
		err_msg("Cannot set server socket to work in a non-blocking manner");
		return FAILURE;
	}

	ev_entry = ev_entry_new(fd, EV_READ, incoming_request, ctx);
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


int init_client_side(struct ctx *ctx)
{
	int ret;

	ctx->client_server_socket = init_server_socket(AF_INET, SOCK_DGRAM, 0, DEFAULT_LISTEN_PORT);

	ret = ev_add_server_socket(ctx, ctx->client_server_socket);
	if (ret != SUCCESS) {
		err_msg("Cannot initialize server event handling");
		fini_server_socket(ctx->client_server_socket);
		return FAILURE;
	}

	return SUCCESS;
}



/* vim: set tw=78 ts=4 sw=4 sts=4 ff=unix noet: */
