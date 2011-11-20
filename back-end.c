/*
** Copyright (C) 2010,2011 - Hagen Paul Pfeifer <hagen@jauu.net>
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

	pr_debug("daemon itself listen at port %s", port);

	freeaddrinfo(hostres);

	return fd;
}


void fini_server_socket(int fd)
{
	close(fd);
}


static void fire_error(struct dns_journey *dnsj)
{
	(void) dnsj;
	/* FIXME: inform sender that a error occured */
	abort();
}


static int construct_header_question_section(struct dns_journey *dnsj,
		char *packet, int offset, int max_len)
{
	off_t j;
	uint16_t *type, *class;
	int len = DNS_PDU_HEADER_LEN + dnsj->p_req_dns_pdu->questions_section_len;

	(void) offset;

	if (len >= max_len) {
		pr_debug("the DNS header plus the question section is at least"
				" as big then the whole packet - thats to big for us");
		return -1;
	}

	pr_debug("header + question section len: %d", len);

	/* generate packet. We clone the original
	 * packet here, but only the header and the
	 * quesion section, the rest is neglected */
	//memcpy(packet, dnsj->p_req_packet, len);

	/* set default response flag */
	packet_set_transaction_id(packet, htons(dnsj->p_req_dns_pdu->id));
	packet_flags_clear(packet);
	packet_flags_set_qr_response(packet);
	packet_flags_set_unauthoritative_answer(packet);
	packet_flags_set_untruncated(packet);
	packet_flags_set_recursion_available(packet);

	dns_packet_set_rr_entries_number(packet, RR_SECTION_QDCOUNT, 1);
	dns_packet_set_rr_entries_number(packet, RR_SECTION_ANCOUNT, 0);
	dns_packet_set_rr_entries_number(packet, RR_SECTION_NSCOUNT, 0);
	dns_packet_set_rr_entries_number(packet, RR_SECTION_ARCOUNT, 0);

	assert(dnsj->p_req_dns_pdu->questions == 1);

	j = dnsname_to_labels(&packet[offset + DNS_PDU_HEADER_LEN],
			max_len - DNS_PDU_HEADER_LEN,
			0,
			dnsj->p_req_dns_pdu->questions_section[0]->name,
			strlen(dnsj->p_req_dns_pdu->questions_section[0]->name),
			NULL);
	if (j < 0) {
		err_msg("Cannot construct DNS answer section label");
		return j;
	}

	type  = (uint16_t *)&packet[DNS_PDU_HEADER_LEN + j];
	class = (uint16_t *)&packet[DNS_PDU_HEADER_LEN + j + sizeof(uint16_t)];

	*type  = htons(dnsj->p_req_dns_pdu->questions_section[0]->type);
	*class = htons(dnsj->p_req_dns_pdu->questions_section[0]->class);

	return len;
}


static int construct_answer_section(struct dns_journey *dnsj,
		char *packet, int offset, int max_len)
{
	int len = dnsj->p_res_dns_pdu->answers_section_len;

	if (unlikely(dnsj->p_res_dns_pdu->answers <= 0))
		return 0;

	if (len > max_len) {
		pr_debug("len (%d) larger the max len (%d)", len, max_len);
		return -1;
	}

	pr_debug("answer section len: %d", len);

	memcpy(packet + offset, dnsj->p_res_dns_pdu->answers_section_ptr, len);

	dns_packet_set_rr_entries_number(packet, RR_SECTION_ANCOUNT,
			dnsj->p_res_dns_pdu->answers);

	return len;
}


static int construct_authority_section(struct dns_journey *dnsj,
		char *packet, int offset, int max_len)
{
	int len = dnsj->p_res_dns_pdu->authority_section_len;

	if (unlikely(dnsj->p_res_dns_pdu->authority <= 0))
		return 0;

	if (len > max_len)
		return -1;

	pr_debug("authority section len: %d", len);

	memcpy(packet + offset, dnsj->p_res_dns_pdu->authority_section_ptr, len);

	dns_packet_set_rr_entries_number(packet, RR_SECTION_NSCOUNT,
			dnsj->p_res_dns_pdu->authority);

	return len;
}


static int construct_additional_section(struct dns_journey *dnsj,
		char *packet, int offset, int max_len)
{
	int i;
	int ret, len;
	uint16_t type;
	uint16_t additional_section_no = dnsj->p_res_dns_pdu->additional;

	ret = 0;

	len = dnsj->p_res_dns_pdu->additional_section_len;

	/* construct the additional section, using the
	 * separated sections */
	for (i = 0; i < additional_section_no; i++) {
		type = dnsj->p_res_dns_pdu->additional_section[i]->type;
		ret += type_fn_table[type_opts_to_index(type)].construct(dnsj->ctx,
				dnsj->p_res_dns_pdu, dnsj->p_res_dns_pdu->additional_section[i],
				packet + offset, max_len);
		if (ret < 0) {
			/* FIXME: error handling is b0rken */
			err_msg_die(EXIT_FAILINT, "ret is smaller (%d, max_len: %d, offset: %d)",
					ret, max_len, offset);
		}
		offset += ret;
	}

	/* FIXME: we only generate a additional section if
	 * the forwarder sent is one - this is not that clever
	 * because we can also decide to construct a own
	 * section without the forwarder */
	if (additional_section_no > 0 && len < max_len) {

		memcpy(packet + offset, dnsj->p_res_dns_pdu->additional_section_ptr, len);
		offset += len;

		dns_packet_set_rr_entries_number(packet, RR_SECTION_ARCOUNT,
				additional_section_no);
	}

#if 0
	/* in the case that the resolver send a edns0 option we
	 * also set this option to signal that we are edns0 aware
	 * if the local configuration does not disable edns0 of course */
	if (type_041_opt_available(dnsj->p_req_dns_pdu) &&
			dnsj->ctx->cli_opts.edns0_mode) {

		pr_debug("construct and add edns0 additional section");

		ret = type_041_opt_construct_option(dnsj, packet, offset, max_len);
		if (ret < 0) {
			/* ok, the packet is to big we return
			 * with the version before the edns0 processing
			 * because we know that these fields already
			 * matched the packet limitations */
			return len;
		}
		offset += ret; len += ret;

		dns_packet_set_rr_entries_number(packet,
				RR_SECTION_ARCOUNT, additional_section_no + 1);

	}
#endif

	return len;
}


/* We determine the maximum len of the outgoing
 * packet. The limit depends on several factors.
 *	1. if the resolver does not not support edns0
 *	   mechanism we fall back to 512 (dnsj->max_payload_size
 *	   is initialized to this value.
 *	2. if the resolver support edns in the request then the
 *	   max_payload_size it set to this value. max_payload_size
 *	   represent therefore the client limit
 *	3. we can also be the limiting instance if the configuration
 *	   disable edns0 mechanism, or
 *	4. if the configuration limit is smaller then the client limit
 *	   dnsj->ctx->buf_max < dnsj->max_payload_size */
static int max_response_packet_len(struct dns_journey *dnsj)
{
	return min_t(int, dnsj->ctx->buf_max, dnsj->p_req_dns_pdu->edns0_max_payload);
}


static size_t construct_active_response_packet(struct dns_journey *dnsj)
{
	int offset, ret, max_len;
	char *packet = dnsj->ctx->buf;
	const char *err_label = "";

	max_len  = max_response_packet_len(dnsj);
	pr_debug("the maximum packet payload size is %d", max_len);

	offset = 0;

	ret = construct_header_question_section(dnsj, packet, offset, max_len);
	if (ret < 0) {
		fire_error(dnsj);
		return FAILURE;
	}
	offset += ret; max_len -= ret;
	pr_debug("after header question: remaining len: %d, offset: %d", max_len, offset);


	ret = construct_answer_section(dnsj, packet, offset, max_len);
	if (ret < 0) {
		fire_error(dnsj);
		return FAILURE;
	}
	offset += ret; max_len -= ret;
	pr_debug("after answer section: remaining len: %d, offset: %d", max_len, offset);


	ret = construct_authority_section(dnsj, packet, offset, max_len);
	if (ret < 0) { /* authority section is to large; sent answer & question */
		err_label = "authority";
		goto fire_packet;
	}
	offset += ret; max_len -= ret;
	pr_debug("after authority question: remaining len: %d, offset: %d", max_len, offset);


	ret = construct_additional_section(dnsj, packet, offset, max_len);
	if (ret < 0) { /* additional section is to large; sent authority, answer, question */
		err_label = "additional";
		goto fire_packet;
	}
	offset += ret; max_len -= ret;
	pr_debug("after additional question: remaining len: %d, offset: %d", max_len, offset);


	pr_debug("cumulative packet size: %d", offset);

	return offset;

fire_packet:
	pr_debug("cannot append section %s because of size restrictions",
			err_label);
	return offset;
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
	size_t ret;
	ssize_t sret;

	pr_debug("generate anwser [data: %u questions (%u bytes),"
			" %u answers (%u bytes)"
			" %u authorities (%u bytes) %u additionals (%u bytes)]",
			 dnsj->p_res_dns_pdu->questions,
			 dnsj->p_res_dns_pdu->questions_section_len,
			 dnsj->p_res_dns_pdu->answers,
			 dnsj->p_res_dns_pdu->answers_section_len,
			 dnsj->p_res_dns_pdu->authority,
			 dnsj->p_res_dns_pdu->authority_section_len,
			 dnsj->p_res_dns_pdu->additional,
			 dnsj->p_res_dns_pdu->additional_section_len);


	ret = construct_active_response_packet(dnsj);
	if (ret <= 0) {
		/* FIXME: the algorithm should _always_ send a packet
		 * back to the originator to inform he */
		err_msg("cannot construct response packet");
		return FAILURE;
	}

	sret = sendto(dnsj->ctx->client_server_socket,
			dnsj->ctx->buf,
			ret,
			0,
			(struct sockaddr *)&dnsj->p_req_ss,
			dnsj->p_req_ss_len);
	if (sret < 0)
		err_sys("failure in send a DNS answer back to the resolver");

	return SUCCESS;
}


/* dns_journey contains exactly one question, not more
 * and not less, so handle this question as it is */
static int enqueue_request(struct ctx *ctx, struct dns_journey *dns_journey)
{
	int ret, i;
	char *name;
	uint16_t type, class;

	(void) class;
	(void) type;
	(void) name;


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


/* this method is called if a new DNS
 * query is send from a resolver */
static void process_p_dns_query(struct ctx *ctx,
		const char *packet, const size_t len,
		const struct sockaddr_storage *ss, socklen_t ss_len)
{
	int ret;
	struct dns_journey *dns_journey;

	dns_journey = alloc_dns_journey();

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
		dns_journey->p_req_dns_pdu->authority > 0) {
		err_msg("the DNS REQUEST comes with unusual additional sections: "
				"answers: %d, authority: %d I ignore these sections!",
				dns_journey->p_req_dns_pdu->answers,
				dns_journey->p_req_dns_pdu->authority);
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
		/* FIXME: were is the free()?
		 * Is is save to call dns_journey_free() at this time? */
		err_msg("Cannot enqueue request in active queue");
		return;
	}

	return;
}


static int is_allowed_ipv4_query(struct ctx *ctx, struct in_addr *addr)
{
	int ret;
	struct list_element *ele;
	struct list *arl = ctx->allowed_resolver_list;

	for (ele = list_head(arl); ele != NULL; ele = list_next(ele)) {
		struct ip_prefix_storage *ipps = list_data(ele);

		if (ipps->af_family != AF_INET)
			continue;

		ret = ipv4_prefix_equal(addr, &ipps->v4_addr, ipps->prefix_len);
		if (ret)
			return 1;
	}

	return 0;
}


static int is_allowed_ipv6_query(struct ctx *ctx, struct in6_addr *addr)
{
	int ret;
	struct list_element *ele;
	struct list *arl = ctx->allowed_resolver_list;

	for (ele = list_head(arl); ele != NULL; ele = list_next(ele)) {
		struct ip_prefix_storage *ipps = list_data(ele);

		if (ipps->af_family != AF_INET6)
			continue;

		ret = ipv6_prefix_equal(addr, &ipps->v6_addr, ipps->prefix_len);
		if (ret)
			return 1;
	}

	return 0;
}


static int is_allowed_query(struct ctx *ctx, struct sockaddr_storage *ss)
{
	/* check if filtering is active, if not then the policy is
	 * to allow queries from all ip's */
	if (!ctx->allowed_resolver_list)
		return 1;

	switch (((struct sockaddr *)ss)->sa_family) {
	case AF_INET:
		return is_allowed_ipv4_query(ctx, &((struct sockaddr_in *)ss)->sin_addr);
		break;
	case AF_INET6:
		return is_allowed_ipv6_query(ctx, &((struct sockaddr_in6 *)ss)->sin6_addr);
		break;
	default:
		err_msg_die(EXIT_FAILINT, "socket family not known");
		break;
	}
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
		rc = recvfrom(fd, packet, MAX_PACKET_LEN, 0, (struct sockaddr *) &ss, &ss_len);
		if (rc < 0) {
			if (errno == EAGAIN)
				return;

			err_sys_die(EXIT_FAILMISC, "Failure in read routine for incoming packet");
		}

		pr_debug("incoming packet on back-end port %s", ctx->cli_opts.port);

		if (!is_allowed_query(ctx, &ss)) {
			pr_debug("query ignored because of active IP filter");
			continue;
		}

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


