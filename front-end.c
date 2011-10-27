/*
** Copyright (C) 2010, 2011 - Hagen Paul Pfeifer <hagen@jauu.net>
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

static int16_t get_random_id(void)
{
	return random();
}


/* send a new request to the server */
static int internal_request_tx(struct ctx *ctx,
		struct dns_journey *dnsj)
{
	ssize_t ret;

	(void) ctx;

	pr_debug("send active pdu request to nameserver via write()");

	/* we now timestamp the packet, this reflect the
	 * time where the request is transmitted. Later at
	 * receive time (response) we can calculate the time
	 * for one DNS RTT */
	gettimeofday(&dnsj->req_time, NULL);

	ret = write(dnsj->ns->socket, dnsj->a_req_packet, dnsj->a_req_packet_len);
	if (ret == (ssize_t)dnsj->a_req_packet_len)
		return SUCCESS;

	if (ret < 0) {
		if (errno == EAGAIN) {
			/* no error, event management framework
			 * will inform us if the socket is again
			 * writeable */
			return FAILURE;
		}
		err_sys("failed to send request PDU to nameserver");
		return FAILURE;
	} else {
		err_msg("short sendto(2) while transmit the request PDU to the nameserver");
		return FAILURE;
	}
}

static int adns_list_add(const struct ctx *ctx, struct dns_journey *dnsj)
{
	if (list_size(ctx->waiting_request_list) > MAX_WAITING_REQUEST_LIST_SIZE) {
		err_msg("the maximum number of waiting DNS REQUESTS is exhaustet"
				" no more requests can enqueued, sorry");
		return FAILURE;
	}

	/* add the new reqest at the end of the list, the impact is
	 * that previously added requests are executed in a FIFO ordering */
	return list_insert_tail(ctx->waiting_request_list, dnsj);
}

/* add the new reqest at the end of the list, the impact is
 * that previously added requests are executed in a FIFO ordering */
static int req_inflight_list_add(const struct ctx *ctx, struct dns_journey *j)
{
	return list_insert_tail(ctx->inflight_request_list, j);
}

/*
 * Here we go:
 * 1. we peek the element of the list (peek == this function ;-)
 * 2. we sent the request
 * 3. if the transmission (write) was successful we dequeue
 *    this element from the waiting_request_list and insert
 *    it in the inflight container
 * 4. if the transmission was not successful we stop the
 *    iterating process and return FAILURE
 */
static int process_all_dnsj_reqeusts(void *req, void *vctx)
{
	int ret;
	struct ctx *ctx = vctx;
	struct dns_journey *dnsj = req;

	if (dnsj->status != ACTIVE_DNS_REQUEST_NEW)
		return SUCCESS; /* not interesting */

	pr_debug("process a new active dns request");

	ret = internal_request_tx(ctx, dnsj);
	if (ret != SUCCESS) {
		err_msg("failure in transmission process");
	}

	pr_debug("successful transmit a DNS REQUEST to a nameserver");

	/* ok, the DNS request is on the wire, fine
	 * we now took the req from the list and
	 * add it to the inflight list */
	ret = list_remove(ctx->waiting_request_list, (void **)&dnsj);
	if (ret != SUCCESS) {
		err_msg_die(EXIT_FAILINT, "critical error: a element is not in "
				"the list, even though it should be there - implemenation error");
		return FAILURE;
	}

	pr_debug("dequeue successful transmitted request from the waiting_request_list");

	ret = req_inflight_list_add(ctx, dnsj);
	if (ret != SUCCESS) {
		err_msg("cannot add DNS REQUEST to inflight list, dropping this packet");
		free_dns_journey(dnsj);
		return FAILURE;
	}

	pr_debug("queued request to the inflight queue");

	return SUCCESS;
}

static void adns_trigger_resolv(const struct ctx *ctx)
{
	int ret;

	/* iterate over the list and send all dns
	 * request who are in the state of ACTIVE_DNS_REQUEST_NEW
	 * and ignore request in state ACTIVE_DNS_REQUEST_IN_FLIGHT */
	ret = list_for_each(ctx->waiting_request_list, process_all_dnsj_reqeusts, (void *)ctx);
	if (ret != SUCCESS) {
		err_msg("failure in iterating over active requst list");
		return;
	}

	return;
}


#define	MAX_REQUEST_PDU_LEN 1024

#define	MIN_DOMAIN_NAME_LEN 2

static int internal_build_dns_request(struct ctx *ctx, struct dns_journey *dnsj)
{
	int rlen;
	char pdu[MAX_REQUEST_PDU_LEN];
	struct dns_pdu *request = dnsj->a_req_dns_pdu;
	char *req_name;
	uint16_t req_class, req_type;

	if (!dnsj->p_req_name || strlen(dnsj->p_req_name) < MIN_DOMAIN_NAME_LEN)
		return FAILURE;

	req_name  = dnsj->p_req_name;
	req_type  = dnsj->p_req_type;
	req_class = dnsj->p_req_class;

	request->id = get_random_id();

	rlen = pkt_construct_dns_query(ctx, dnsj, req_name, strlen(req_name),
			request->id, req_type, req_class, pdu, MAX_REQUEST_PDU_LEN);

	pr_debug("build active dns request packet of size %d, id: %u",
			rlen, request->id);

	dnsj->a_req_packet     = xmalloc(rlen);
	dnsj->a_req_packet_len = rlen;

	memcpy(dnsj->a_req_packet, pdu, rlen);

	return SUCCESS;
}


static int search_cache(struct ctx *ctx,
		struct dns_journey *dnsj, struct cache_data **cd)
{
	int ret;

	pr_debug("search cache");

	ret = cache_get(ctx, dnsj->p_req_type, dnsj->p_req_class,
			dnsj->p_req_name, strlen(dnsj->p_req_name) + 1, cd);
	if (ret != SUCCESS) {
		ctx->statistics.lookup_not_in_cache++;
		return FAILURE;
	}

	pr_debug("found in cache");
	ctx->statistics.lookup_in_cache++;

	return SUCCESS;
}


/* enqueue the query into the active queue */
int active_dns_request_set(struct ctx *ctx,
		struct dns_journey *dnsj,
		int (*cb)(struct dns_journey *))
{
	int ret;
	struct cache_data *cd = NULL;

	assert(dnsj);
	assert(cb);

	/* 1. search local cache first */
	ret = search_cache(ctx, dnsj, &cd);
	if (ret == SUCCESS) {

		assert(cd);

		pr_debug("found data in cache");
		/* in cache, cd pints to the valid cache data */

		dnsj->p_res_dns_pdu = alloc_dns_pdu();

		ret = create_answer_pdu_from_cd(ctx, dnsj, cd);

		(*cb)(dnsj);

		/* now delete/free the journey data structure, everything
		 * is handled and the process for this journey is closed */
		free_dns_journey(dnsj);

		return SUCCESS;
	}


	/* 2. ok we didn't found anything in the
	 *    cache. Now we generate a new request
	 *    and sent it to the server */


	/* cb is called when the nameserver answered or
	 * a timeout occured */
	dnsj->cb = cb;

	dnsj->ns = nameserver_select(ctx);
	if (!dnsj->ns) {
		err_msg("cannot select a nameserver, giving up");
		free_dns_journey(dnsj);
		return FAILURE;
	}
	dnsj->status = ACTIVE_DNS_REQUEST_NEW;

	dnsj->a_req_dns_pdu = xzalloc(sizeof(*dnsj->a_req_dns_pdu));

	ret = internal_build_dns_request(ctx, dnsj);
	if (ret != SUCCESS) {
		free_dns_journey(dnsj);
		return FAILURE;
	}

	ret = adns_list_add(ctx, dnsj);
	if (ret != SUCCESS) {
		free_dns_journey(dnsj);
		return FAILURE;
	}

	/* trigger resolv process */
	adns_trigger_resolv(ctx);

	return SUCCESS;
}


/* danger in robinson: this function must return boolean
 * true if both items matches or false if not - return
 * the internal SUCCESS or FAILURE does not fit these
 * requirement! ;) */
static int adns_request_match(const void *a, const void *b)
{
	const struct dns_journey *adns_req1, *adns_req2;

	adns_req1 = a;
	adns_req2 = b;

	/* FIXME: add values checked */
	if (adns_req1->p_req_type  == adns_req2->p_req_type  &&
		adns_req1->p_req_class == adns_req2->p_req_class &&
		(!strcmp(adns_req1->p_req_name, adns_req2->p_req_name)))
		return 1;

	return 0;
}


int adns_request_init(struct ctx *ctx)
{
	ctx->waiting_request_list  = list_create(adns_request_match, free_dns_journey_list_entry);
	ctx->inflight_request_list = list_create(adns_request_match, free_dns_journey_list_entry);
	return SUCCESS;
}


/* if we found the requested we return FAILURE to signal that
 * the list iteration can stop */
static int search_adns_requests(void *req, void *dns_pdu_tmp)
{
	int i, ret;
	struct dns_journey *dns_j = req;
	struct dns_pdu *dns_pdu_r = dns_pdu_tmp;
	char *q_name, *r_name;
	uint16_t q_type, r_type;
	uint16_t q_class, r_class;

	if (dns_pdu_r->questions != 1)
		err_msg_die(EXIT_FAILINT, "internal error, should never happended"
				", the question section contains %d elements; should be %d",
				dns_pdu_r->questions, 1);

	/* check if type, class and name matches */
	for (i = 0; i < dns_pdu_r->questions; i++) {
		struct dns_sub_section *dnsss = dns_pdu_r->questions_section[i];
		struct dns_journey *dns_j_match;
		struct timeval tv_res;

		/* FIXME: copy and free the name */
		r_name  = dnsss->name;
		r_type  = dnsss->type;
		r_class = dnsss->class;

		q_name  = dns_j->p_req_name;
		q_type  = dns_j->p_req_type;
		q_class = dns_j->p_req_class;

		if ((r_type == q_type)   &&
			(r_class == q_class) &&
			(!strcmp(r_name, q_name))) {

			/* FIXME: validate packet (ID and port) */

			/* ok, we found the element, now break
			 * the list processing */
			dns_j->p_res_dns_pdu = dns_pdu_r;

			/* ok, we timestamp the packet now and update
			 * the timedelta */
			gettimeofday(&dns_j->res_time, NULL);
			assert(dns_j->ns);
			subtime(&dns_j->res_time, &dns_j->req_time, &tv_res);
			nameserver_update_rtt(dns_j->ctx, dns_j->ns, &tv_res);

			/* this calls response_cb() for the server[TM] version
			 * or a user defined callback in the case of a library
			 * use */
			dns_j->cb(dns_j);

			/* ok, now remove the element from the inflight list because we
			 * get the answer from the server.  FIXME: the current list
			 * implementation is a little bit awkward.  The list remove
			 * function iterate over the whole list a second time even though
			 * we had already found the right element - we know it is there
			 * and where it is. This must be fixed  --HGN */
			dns_j_match = dns_j;
			ret = list_remove(dns_j->ctx->inflight_request_list, (void **)&dns_j_match);
			if (ret != SUCCESS || dns_j_match != dns_j)
				err_msg_die(EXIT_FAILINT, "failure in list remove of inflight list");

			/* last but not least we do some statistics */
			dns_j->ctx->succ_req_res++;
			nameserver_update_statistic(dns_j->ctx);

			/* now delete/free the journey data structure, everything
			 * is handled and the process for this journey is closed */
			free_dns_journey(dns_j);

			return FAILURE;
		}

	}

	/* Signals that we did NOT found the searched entry.
	 * That means a nameserver sends a anwser for a questio
	 * we never sent to the server. -- HGN */
	return SUCCESS;
}



/* this function reads a anwser of a nameserver
 * We do the following:
 * a) do some trivial valid checks
 * b) find the entry in the question list (inflight_request_list)
 *   1) if we found it in the list we prepare the awnser and
 *      call the user provided callback function (back-end)
 *   2) if not, we silently discard the packet because we never
 *      request that information or we assume that this packet is a attack! ;-)
 */
static void process_dns_response(struct ctx *ctx, const char *packet, const size_t len,
		const struct sockaddr_storage *ss, socklen_t ss_len)
{
	int ret;
	struct dns_pdu *dns_pdu;

	(void) ss;
	(void) ss_len;

	ret = parse_dns_packet(ctx, packet, len, &dns_pdu);
	if (ret != SUCCESS) {
		err_msg("received an malformed DNS packet, skipping this packet");
		goto err;
	}

	if (dns_pdu->questions != 1) {
		err_msg_die(EXIT_FAILNET, "nor then one question, we never reqest for more"
				" then one question");
	}

	if (!FLAG_IS_QR_RESPONSE(dns_pdu->flags)) {
		err_msg("incoming packet is no response packet");
		goto err;
	}

	/* check for error code - regardless if a error occured
	 * we generate a pdu and encode all values, but we pass
	 * down the error. It is up to the callback routine to
	 * check this error */
	if (!FLAG_IS_RCODE_NO_ERROR(dns_pdu->flags)) {
		/* FIXME: set error code */
		err_msg("NON FATAL: error occured, check this gegen");
	}

	/* now search the inflight list, all relevant processing
	 * is done in search_adns_requests */
	list_for_each(ctx->inflight_request_list,
			search_adns_requests, (void *)dns_pdu);


	return;

err:
	free(dns_pdu);
}

/* a nameserver send us some data
 * 1. we iterate until no more data is queued
 * 2. we do some trivial error checks
 * 3. if we found a entry we delete the entry from
 *    the inflight list
 * 4. we call caching routine to cache the actual
 *    data
 * 5. we call the user provided callback function
 */
static void nameserver_read_event(int fd, int what, void *data)
{
	ssize_t rc;
	char packet[MAX_PACKET_LEN];
	struct sockaddr_storage ss;
	socklen_t ss_len = sizeof(struct sockaddr_storage);
	struct ctx *ctx = data;

	/* FIXME: check for error conditions */
	(void) what;

	while (1) {

		rc = recvfrom(fd, packet, MAX_PACKET_LEN, 0, (struct sockaddr *)&ss, &ss_len);
		if (rc < 0) {
			if (errno == EAGAIN)
				return;
			err_sys_die(EXIT_FAILMISC, "Failure in read routine for incoming packet");
		}

		pr_debug("incoming DNS response of size %d byte", rc);
		process_dns_response(ctx, packet, rc, &ss, ss_len);
	}
}

static int add_nameserver_rc_list(void *ns_str, void *vctx)
{
	int ret;
	char *ns = ns_str;
	struct ctx *ctx = vctx;

	ret = nameserver_add(ctx, ns,
			ctx->cli_opts.forwarder_port, nameserver_read_event);
	if (ret != SUCCESS) {
		err_msg("cannot add default nameserver: %s", ns_str);
		/* we don't break here, because the next one
		 * may be fine. So we iterate over the whole list
		 * and always return SUCCESS */
	}

	return SUCCESS;
}


int init_server_side(struct ctx *ctx)
{
	int ret;

	ret = nameserver_init(ctx);
	if (ret == FAILURE) {
		err_msg("cannot initialize nameserver context");
		return FAILURE;
	}

	ret = list_for_each(ctx->cli_opts.forwarder_list,
			add_nameserver_rc_list, (void *)ctx);
	if (ret != SUCCESS) {
		err_msg("failure in adding nameserver from config file");
		return FAILURE;
	}

	ret = adns_request_init(ctx);
	if (ret != SUCCESS) {
		err_msg("failure in initialize process of server side request structure");
		return FAILURE;
	}

	return SUCCESS;
}


