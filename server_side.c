/*
** Copyright (C) 20010 - Hagen Paul Pfeifer <hagen@jauu.net>
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
int internal_request_tx(struct ctx *ctx,
		struct active_dns_request *req)
{
	ssize_t ret;

	(void)ctx;

	pr_debug("send active pdu request to nameserver via sendto");

	ret = write(req->ns->socket, req->pdu, req->pdu_len);

	if (ret == (ssize_t)req->pdu_len)
		return SUCCESS;

	if (ret < 0)
		err_sys("failed to send request PDU to nameserver");
	else
		err_msg("short sendto(2) while transmit the request PDU to the nameserver");

	return FAILURE;
}

static int adns_list_add(const struct ctx *ctx, struct active_dns_request *adns_request)
{
	if (list_size(ctx->waiting_request_list) > MAX_WAITING_REQUEST_LIST_SIZE) {
		err_msg("the maximum number of waiting DNS REQUESTS is exhaustet"
				" no more requests can enqueued, sorry");
		return FAILURE;
	}

	/* add the new reqest at the end of the list, the impact is
	 * that previously added requests are executed in a FIFO ordering */
	return list_insert_tail(ctx->waiting_request_list, adns_request);
}

static struct active_dns_request *adns_request_alloc(void)
{
	return xzalloc(sizeof(struct active_dns_request));
}


static int process_all_adns_requsts(void *req, void *vctx)
{
	int ret;
	struct ctx *ctx = vctx;
	struct active_dns_request *adns_request = req;

	if (adns_request->status != ACTIVE_DNS_REQUEST_NEW)
		return SUCCESS; /* not interesting */

	pr_debug("process a new active dns request");

	ret = internal_request_tx(ctx, adns_request);
	if (ret != SUCCESS) {
		err_msg("failure in transmission process");
	}

	return SUCCESS;
}

static void adns_trigger_resolv(const struct ctx *ctx)
{
	int ret;

	/* iterate over the list and send all dns
	 * request who are in the state of ACTIVE_DNS_REQUEST_NEW
	 * and ignore request in state ACTIVE_DNS_REQUEST_IN_FLIGHT */
	ret = list_for_each(ctx->waiting_request_list, process_all_adns_requsts, (void *)ctx);
	if (ret != SUCCESS) {
		err_msg("failure in iterating over active requst list");
		return;
	}

	return;
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


/* FIXME: stollen! */
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
static int
evdns_request_data_build(const char *const name, const int name_len,
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

static int internal_build_dns_request(const struct ctx *ctx,
		struct active_dns_request *adns_request,
		const char *str, int type, int class)
{
	int rlen;
	unsigned char pdu[MAX_REQUEST_PDU_LEN];

	(void) ctx;

	pr_debug("build dns request packet");
	adns_request->id = get_random_id();

	rlen = evdns_request_data_build(str, strlen(str), adns_request->id,
	    type, class, pdu, MAX_REQUEST_PDU_LEN);

	pr_debug("build active dns request packet of size %d", rlen);

	adns_request->pdu = xmalloc(rlen);

	memcpy(adns_request->pdu, pdu, rlen);
	adns_request->pdu_len = rlen;

	return SUCCESS;
}

/* enqueue the query into the active queue */
int active_dns_request_set(const struct ctx *ctx,
		const char *str, int type, int class)
{
	int ret;
	struct active_dns_request *adns_request;

	assert(str);

	/* 1. search local cache first */


	/* 2. ok we didn't found anything in the
	 *    cache. Now we generate a new request
	 *    and sent it to the server */

	adns_request = adns_request_alloc();

	adns_request->ns = nameserver_select(ctx);
	if (!adns_request->ns) {
		err_msg("cannot select a nameserver, giving up");
		adns_request_free(adns_request);
		return FAILURE;
	}
	adns_request->status = ACTIVE_DNS_REQUEST_NEW;

	ret = internal_build_dns_request(ctx, adns_request, str, type, class);
	if (ret != SUCCESS) {
		adns_request_free(adns_request);
		return FAILURE;
	}

	ret = adns_list_add(ctx, adns_request);
	if (ret != SUCCESS) {
		adns_request_free(adns_request);
		return FAILURE;
	}

	/* trigger resolv process */
	adns_trigger_resolv(ctx);

	return SUCCESS;
}

static int adns_request_match(const void *a, const void *b)
{
	const struct active_dns_request *adns_req1, *adns_req2;

	adns_req1 = a;
	adns_req2 = b;

	/* FIXME: add values checked */
	if (adns_req1->type == adns_req2->type)
		return SUCCESS;

	return FAILURE;
}


int adns_request_init(struct ctx *ctx)
{
	ctx->waiting_request_list = list_create(adns_request_match, adns_request_free);
	return SUCCESS;
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

	ret = nameserver_add(ctx, DEFAULT_NS, DEFAULT_NS_PORT);
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
