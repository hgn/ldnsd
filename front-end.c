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

	pr_debug("send active pdu request to nameserver via sendto");

	ret = write(dnsj->ns->socket, dnsj->s_req_packet, dnsj->s_req_packet_len);

	if (ret == (ssize_t)dnsj->s_req_packet_len)
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

static struct active_dns_request *adns_request_alloc(void)
{
	return xzalloc(sizeof(struct active_dns_request));
}


static void adns_request_free(void *req)
{
	struct active_dns_request *adns_req = req;

	if (adns_req->name)
		free(adns_req->name);

	if (adns_req->pdu)
		free(adns_req->pdu);

	free(adns_req);
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


/* This is an inefficient representation; only use it via the dnslabel_table_*
 * functions, so that is can be safely replaced with something smarter later. */
#define MAX_LABELS 128
/* Structures used to implement name compression */
struct dnslabel_entry { char *v; off_t pos; };
struct dnslabel_table {
	int n_labels; /* number of current entries */
	/* map from name to position in message */
	struct dnslabel_entry labels[MAX_LABELS];
};


/* return the position of the label in the current message, or -1 if the label */
/* hasn't been used yet. */
static int
dnslabel_table_get_pos(const struct dnslabel_table *table, const char *label)
{
	int i;
	for (i = 0; i < table->n_labels; ++i) {
		if (!strcmp(label, table->labels[i].v))
			return table->labels[i].pos;
	}
	return -1;
}

/* remember that we've used the label at position pos */
static int
dnslabel_table_add(struct dnslabel_table *table, const char *label, off_t pos)
{
	char *v;
	int p;
	if (table->n_labels == MAX_LABELS)
		return (-1);
	v = xstrdup(label);
	if (v == NULL)
		return (-1);
	p = table->n_labels++;
	table->labels[p].v = v;
	table->labels[p].pos = pos;

	return (0);
}

/* Converts a string to a length-prefixed set of DNS labels, starting */
/* at buf[j]. name and buf must not overlap. name_len should be the length */
/* of name.	 table is optional, and is used for compression. */
/* */
/* Input: abc.def */
/* Output: <3>abc<3>def<0> */
/* */
/* Returns the first index after the encoded name, or negative on error. */
/*	 -1	 label was > 63 bytes */
/*	 -2	 name too long to fit in buffer. */
/* */
static off_t
dnsname_to_labels(uint8_t *const buf, size_t buf_len, off_t j,
				  const char *name, const int name_len,
				  struct dnslabel_table *table) {
	const char *end = name + name_len;
	int ref = 0;
	uint16_t _t;

#define APPEND16(x) do {						\
		if (j + 2 > (off_t)buf_len)				\
			goto overflow;					\
		_t = htons(x);						\
		memcpy(buf + j, &_t, 2);				\
		j += 2;							\
	} while (0)
#define APPEND32(x) do {						\
		if (j + 4 > (off_t)buf_len)				\
			goto overflow;					\
		_t32 = htonl(x);					\
		memcpy(buf + j, &_t32, 4);				\
		j += 4;							\
	} while (0)

	if (name_len > 255) return -2;

	for (;;) {
		const char *const start = name;
		if (table && (ref = dnslabel_table_get_pos(table, name)) >= 0) {
			APPEND16(ref | 0xc000);
			return j;
		}
		name = strchr(name, '.');
		if (!name) {
			const unsigned int label_len = end - start;
			if (label_len > 63) return -1;
			if ((size_t)(j+label_len+1) > buf_len) return -2;
			if (table) dnslabel_table_add(table, start, j);
			buf[j++] = label_len;

			memcpy(buf + j, start, end - start);
			j += end - start;
			break;
		} else {
			/* append length of the label. */
			const unsigned int label_len = name - start;
			if (label_len > 63) return -1;
			if ((size_t)(j+label_len+1) > buf_len) return -2;
			if (table) dnslabel_table_add(table, start, j);
			buf[j++] = label_len;

			memcpy(buf + j, start, name - start);
			j += name - start;
			/* hop over the '.' */
			name++;
		}
	}

	/* the labels must be terminated by a 0. */
	/* It's possible that the name ended in a . */
	/* in which case the zero is already there */
	if (!j || buf[j-1]) buf[j++] = 0;
	return j;
 overflow:
	return (-2);
}


static int evdns_request_data_build(const char *const name, const int name_len,
    const uint16_t trans_id, const uint16_t type, const uint16_t class,
    uint8_t *const buf, size_t buf_len) {
	off_t j = 0;  /* current offset into buf */
	uint16_t _t;	 /* used by the macros */

	APPEND16(trans_id);
	APPEND16(0x0100);  /* standard query, recusion needed */
	APPEND16(1);  /* one question */
	APPEND16(0);  /* no answers */
	APPEND16(0);  /* no authority */
	APPEND16(0);  /* no additional */

	j = dnsname_to_labels(buf, buf_len, j, name, name_len, NULL);
	if (j < 0) {
		return (int)j;
	}

	APPEND16(type);
	APPEND16(class);

	return (int)j;
 overflow:
	return (-1);
}


#define	MAX_REQUEST_PDU_LEN 1024

#define	MIN_DOMAIN_NAME_LEN 2

static int internal_build_dns_request(const struct ctx *ctx, struct dns_journey *dnsj)
{
	int rlen;
	unsigned char pdu[MAX_REQUEST_PDU_LEN];
	struct dns_pdu *request = dnsj->res_dns_pdu;
	const char *req_name;
	uint16_t req_class, req_type;

	(void) ctx;

	if (!dnsj->req_name && strlen(dnsj->req_name) < MIN_DOMAIN_NAME_LEN)
		return FAILURE;

	req_name  = dnsj->req_name;
	req_type  = dnsj->req_type;
	req_class = dnsj->req_class;

	pr_debug("build dns request packet");
	request->id = get_random_id();

	rlen = evdns_request_data_build(req_name, strlen(req_name), request->id,
	    req_type, req_class, pdu, MAX_REQUEST_PDU_LEN);

	pr_debug("build active dns request packet of size %d", rlen);

	dnsj->s_req_packet     = xmalloc(rlen);
	dnsj->s_req_packet_len = rlen;

	memcpy(dnsj->s_req_packet, pdu, rlen);

	return SUCCESS;
}


/* enqueue the query into the active queue */
int active_dns_request_set(const struct ctx *ctx,
		struct dns_journey *dnsj,
		int (*cb)(struct dns_journey *))
{
	int ret;

	assert(dnsj);

	/* 1. search local cache first */


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

	dnsj->res_dns_pdu = xzalloc(sizeof(dnsj->res_dns_pdu));

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
	if (adns_req1->req_type  == adns_req2->req_type  &&
		adns_req1->req_class == adns_req2->req_class &&
		(!strcmp(adns_req1->req_name, adns_req2->req_name)))
		return 1;

	return 0;
}


int adns_request_init(struct ctx *ctx)
{
	ctx->waiting_request_list  = list_create(adns_request_match, adns_request_free);
	ctx->inflight_request_list = list_create(adns_request_match, adns_request_free);
	return SUCCESS;
}


/* if we found the requested we return FAILURE to signal that
 * the list iteration can stop */
static int search_adns_requests(void *req, void *dns_response)
{
	int i;
	struct dns_pdu *dns_pdu_r;
	struct dns_response *dns_r = dns_response;
	struct dns_journey *adns_request = req;
	char *q_name, *r_name;
	uint16_t q_type, r_type;
	uint16_t q_class, r_class;

	dns_pdu_r = dns_r->dns_pdu;

	if (dns_pdu_r->questions != 1)
		err_msg_die(EXIT_FAILINT, "internal error, should never happended"
				", the question section contains %d elements; should be %d",
				dns_pdu_r->questions, 1);

	/* check if type, class and name matches */
	for (i = 0; i < dns_pdu_r->questions; i++) {
		struct dns_sub_section *dnsss = dns_pdu_r->questions_section[i];

		/* FIXME: copy and free the name */
		r_name  = dnsss->name;
		r_type  = dnsss->type;
		r_class = dnsss->class;

		q_name  = adns_request->req_name;
		q_type  = adns_request->req_type;
		q_class = adns_request->req_class;

		if ( (r_type == q_type)   &&
			 (r_class == q_class) &&
			 (!strcmp(r_name, q_name))) {

			fprintf(stderr, "found in inflight list\n");
			/* ok, we found the element, now break
			 * the list processing */
			/* FIXME: at this point we must copy the required
			 * elements from the server response */
			adns_request->cb(adns_request);
			return FAILURE;
		}

	}

	fprintf(stderr, "dont find match");

	/* signals that we did NOT found the searched entry */
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
	struct dns_response *dns_response;

	(void) ss;
	(void) ss_len;

	dns_response = xzalloc(sizeof(*dns_response));

	ret = parse_dns_packet(ctx, packet, len, &dns_pdu);
	if (ret != SUCCESS) {
		err_msg("received an malformed DNS packet, skipping this packet");
		goto err;
	}

	dns_response->dns_pdu = dns_pdu;

	if (dns_pdu->questions != 1) {
		err_msg_die(EXIT_FAILNET, "nor then one question, we never reqest for more"
				" then one question");
	}

	if (!FLAG_IS_QR_RESPONSE(dns_pdu->flags)) {
		err_msg("incoming packet is no response packet");
		goto err;
	}

	/* splice context to our dns query */
	dns_response->ctx = ctx;

	/* remember server error */
	dns_response->err_code = FLAG_RCODE(dns_pdu->flags);

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
			search_adns_requests, (void *)dns_response);


	return;

err:
	free(dns_pdu);
	free(dns_response);
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

		rc = recvfrom(fd, packet, MAX_PACKET_LEN, 0, (struct sockaddr*) &ss, &ss_len);
		if (rc < 0) {
			if (errno == EAGAIN)
				return;
			err_sys_die(EXIT_FAILMISC, "Failure in read routine for incoming packet");
		}

		pr_debug("incoming DNS response of size %d byte", rc);
		process_dns_response(ctx, packet, rc, &ss, ss_len);
	}
}


/* default to google ns */
#define	DEFAULT_NS "8.8.8.8"
#define	DEFAULT_NS_PORT "53"

int init_server_side(struct ctx *ctx)
{
	int ret;

	ret = nameserver_init(ctx);
	if (ret == FAILURE) {
		err_msg("cannot initialize nameserver context");
		return FAILURE;
	}

	ret = nameserver_add(ctx, DEFAULT_NS, DEFAULT_NS_PORT, nameserver_read_event);
	if (ret != SUCCESS) {
		err_msg("cannot add default nameserver: %s", DEFAULT_NS);
		return FAILURE;
	}

	ret = adns_request_init(ctx);
	if (ret != SUCCESS) {
		err_msg( "failure in initialize process of server side request structure");
		return FAILURE;
	}

	return SUCCESS;
}


/* vim: set tw=78 ts=4 sw=4 sts=4 ff=unix noet: */
