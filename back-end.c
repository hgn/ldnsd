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


static int socket_bind(struct addrinfo *a)
{
	int ret, on = 1;
	int fd = socket(a->ai_family, a->ai_socktype, a->ai_protocol);
	if (fd < 0)
		return -1;

	xsetsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on), "SO_REUSEADDR");

	ret = bind(fd, a->ai_addr, a->ai_addrlen);
	if (ret) {
		err_sys("bind failed");
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
				" to find the problen)\n");

	pr_debug("listen at port %s", port);

	freeaddrinfo(hostres);

	return fd;
}


void fini_server_socket(int fd)
{
	close(fd);
}


/* this function is called if
 * a) the cache return a positive answer (positive)
 * b) the transmitted request returned (positive)
 * c) the question timed out (negative)
 * d) the server replied negative (also negative)
 *
 * Main task of this function is to generate a
 * new packet and send it to the resolver */
static int response_cb(struct dns_journey *dnsj)
{
	int ret;
	size_t new_pkt_len, offset;
	ssize_t sret;

	pr_debug("got a anwser");

	pr_debug("anwser contains following data: %u questions, %u answers,"
			 " %u authority %u additional, entries",
			 dnsj->p_res_dns_pdu->questions, dnsj->p_res_dns_pdu->answers,
			 dnsj->p_res_dns_pdu->authority, dnsj->p_res_dns_pdu->additional);

	pr_debug("answer section: %u bytes, authority section %u bytes, additional section %u bytes",
			dnsj->p_res_dns_pdu->answers_section_len, dnsj->p_res_dns_pdu->authority_section_len,
			dnsj->p_res_dns_pdu->additional_section_len);

	/* original packet len plus new answer, authority
	 * and additional entries length */
	new_pkt_len = dnsj->p_req_packet_len + dnsj->p_res_dns_pdu->answers_section_len +
		dnsj->p_res_dns_pdu->authority_section_len + dnsj->p_res_dns_pdu->additional_section_len;

	/* generate packet */
	ret = clone_dns_pkt(dnsj->p_req_packet, dnsj->p_req_packet_len,
			&dnsj->a_res_packet, new_pkt_len);
	if (ret != SUCCESS) {
		err_msg_die(EXIT_FAILNET, "cannot generate a answer packet, clone_dns_pkt discovered"
				" a internal error");
	}

	offset = dnsj->p_req_packet_len;

	if (dnsj->p_res_dns_pdu->answers > 0) {
		/* copy the answer at the directly after the and of the question */
		memcpy(dnsj->a_res_packet + offset, dnsj->p_res_dns_pdu->answers_section_ptr,
				dnsj->p_res_dns_pdu->answers_section_len);

		dns_packet_set_rr_entries_number(dnsj->a_res_packet,
				RR_SECTION_ANCOUNT, dnsj->p_res_dns_pdu->answers);

		offset += dnsj->p_res_dns_pdu->answers_section_len;
	}

	if (dnsj->p_res_dns_pdu->authority > 0) {
		memcpy(dnsj->a_res_packet + offset,
				dnsj->p_res_dns_pdu->authority_section_ptr,
				dnsj->p_res_dns_pdu->authority_section_len);

		dns_packet_set_rr_entries_number(dnsj->a_res_packet,
				RR_SECTION_NSCOUNT, dnsj->p_res_dns_pdu->authority);

		offset += dnsj->p_res_dns_pdu->authority_section_len;
	}

	if (dnsj->p_res_dns_pdu->additional > 0) {
		memcpy(dnsj->a_res_packet + offset,
				dnsj->p_res_dns_pdu->additional_section_ptr,
				dnsj->p_res_dns_pdu->additional_section_len);

		dns_packet_set_rr_entries_number(dnsj->a_res_packet,
				RR_SECTION_ARCOUNT, dnsj->p_res_dns_pdu->additional);

		offset += dnsj->p_res_dns_pdu->additional_section_len;
	}

	/* set response flag */
	dns_packet_set_response_flag(dnsj->a_res_packet);

	pr_debug("now send answer to resolver. Packet size: %u",
			offset);

	sret = sendto(dnsj->ctx->client_server_socket, dnsj->a_res_packet,
			offset, 0,
			(struct sockaddr *)&dnsj->p_req_ss, dnsj->p_req_ss_len);
	if (sret < 0) {
		err_sys("failure in send a DNS answer back to the resolver");
	}

	return SUCCESS;
}


/* dns_journey contains exactly one question, not more
 * and not less, so handle this question as it is */
static int enqueue_request(struct ctx *ctx, struct dns_journey *dns_journey)
{
	int ret, i;
	char *name;
	uint16_t type, class;

	assert(dns_journey);
	assert(dns_journey->p_req_dns_pdu->questions == 1);

	/* this loop is a no-op, but prepared for future enhancements */
	for (i = 0; i < dns_journey->p_req_dns_pdu->questions; i++) {
		struct dns_sub_section *dnsss =
			dns_journey->p_req_dns_pdu->questions_section[i];

		/* type and class are already checked
		 * and valid values, no check required here */
		name  = dnsss->name;
		type  = dnsss->type;
		class = dnsss->class;
	}

	/* attach timeout to request */

	/* enqueue request into the global list of requests,
	 * this process also starts a timer function. So after a
	 * predefined timeout the response function is called guaranteed.
	 * It is up to the caller to check the return code to handle negative
	 * responses
	 * The backend, does not hold any state anymore */
	ret = active_dns_request_set(ctx, dns_journey, response_cb);
	if (ret != SUCCESS) {
		err_msg("cannot set active DNS request");
		return FAILURE;
	}

	return SUCCESS;
}

static void process_p_dns_query(struct ctx *ctx, const char *packet, const size_t len,
		const struct sockaddr_storage *ss, socklen_t ss_len)
{
	int ret;
	struct dns_journey *dns_journey;

	dns_journey = xzalloc(sizeof(*dns_journey));

	ret = parse_dns_packet(ctx, packet, len, &dns_journey->p_req_dns_pdu);
	if (ret != SUCCESS) {
		err_msg("received an malformed DNS packet, skipping this packet");
		free_dns_journey(dns_journey);
		return;
	}

	/* splice context to our dns query */
	dns_journey->ctx = ctx;

	if (!IS_DNS_QUESTION(dns_journey->p_req_dns_pdu->flags)) {
		pr_debug("incoming packet is no QUESTION DNS packet (flags: 0x%x, accepted: 0x%x",
				dns_journey->p_req_dns_pdu->flags, DNS_FLAG_MASK_QUESTION);
		free_dns_journey(dns_journey);
		return;
	}

	if (dns_journey->p_req_dns_pdu->questions < 1) {
		err_msg("incoming DNS request does not contain a DNS request");
		free_dns_journey(dns_journey);
		return;
	}

	if (dns_journey->p_req_dns_pdu->questions > 1) {
		err_msg("the current implementation support only DNS request"
				" with one question - this request contains %d questions"
				" so i will skip this packet",
				dns_journey->p_req_dns_pdu->questions);
		free_dns_journey(dns_journey);
		return;
	}

	if (dns_journey->p_req_dns_pdu->answers > 0 ||
		dns_journey->p_req_dns_pdu->authority > 0 ||
		dns_journey->p_req_dns_pdu->additional > 0) {
		err_msg("the DNS REQUEST comes with unusual additional sections: "
				"answers: %d, authority: %d, additional: %d. I ignore these "
				"sections!",
				dns_journey->p_req_dns_pdu->answers,
				dns_journey->p_req_dns_pdu->authority,
				dns_journey->p_req_dns_pdu->additional);
	}

	dns_journey->p_req_name  = dns_journey->p_req_dns_pdu->questions_section[0]->name;
	dns_journey->p_req_type  = dns_journey->p_req_dns_pdu->questions_section[0]->type;
	dns_journey->p_req_class = dns_journey->p_req_dns_pdu->questions_section[0]->class;

	/* save original packet */
	dns_journey->p_req_packet = xmalloc(len);
	memcpy(dns_journey->p_req_packet, packet, len);
	dns_journey->p_req_packet_len = len;

	/* save caller address */
	memcpy(&dns_journey->p_req_ss, ss, sizeof(dns_journey->p_req_ss));
	dns_journey->p_req_ss_len = ss_len;

	pr_debug("packet is a valid DNS REQUEST, I process this question now");

	/* now we do the actual query */
	ret = enqueue_request(ctx, dns_journey);
	if (ret != SUCCESS) {
		/* FIXME: were is the free() ? */
		err_msg("Cannot enqueue request in active queue");
		return;
	}

	return;
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

	if (what != EV_READ) {
		err_msg("server socket event handling returned %d"
				", but a %d (EV_READ) - was required. I"
				" ignore this event", what, EV_READ);
		return;
	}

	while (666) { /* iterate until the kernel rx queue is empty */
		rc = recvfrom(fd, packet, MAX_PACKET_LEN, 0, (struct sockaddr*) &ss, &ss_len);
		if (rc < 0) {
			if (errno == EAGAIN)
				return;
			err_sys_die(EXIT_FAILMISC, "Failure in read routine for incoming packet");
		}
		pr_debug("incoming packet on back-end port %s", ctx->cli_opts.port);
		process_p_dns_query(ctx, packet, rc, &ss, ss_len);
	}
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

	ctx->client_server_socket = init_server_socket(AF_INET, SOCK_DGRAM, 0, ctx->cli_opts.port);

	ret = ev_add_server_socket(ctx, ctx->client_server_socket);
	if (ret != SUCCESS) {
		err_msg("Cannot initialize server event handling");
		fini_server_socket(ctx->client_server_socket);
		return FAILURE;
	}

	return SUCCESS;
}



/* vim: set tw=78 ts=4 sw=4 sts=4 ff=unix noet: */
