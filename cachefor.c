/*
** Copyright (C) 2009 - Hagen Paul Pfeifer <hagen@jauu.net>
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



static int initiate_seed(void)
{
	ssize_t ret;
	int rand_fd;
	uint32_t randpool;

	/* set randon pool seed */
	rand_fd = open(RANDPOOLSRC, O_RDONLY);
	if (rand_fd < 0)
		err_sys_die(EXIT_FAILINT,
				"Cannot open random pool file %s", RANDPOOLSRC);

	ret = read(rand_fd, &randpool, sizeof(uint32_t));
	if (ret != sizeof(uint32_t)) {
		srandom(time(NULL) & getpid());
		close(rand_fd);
		return FAILURE;
	}

	/* set global seed */
	srandom(randpool);

	close(rand_fd);

	return SUCCESS;
}


static struct ev* ev_init_hdntl(void)
{
	struct ev *ev;
	ev = ev_new();
	if (!ev) {
		err_msg_die(EXIT_FAILMISC, "Cannot initialize event abstration");
	}

	return ev;
}

static void ev_free_hndl(struct ev *ev)
{
	ev_free(ev);
}

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


static void fini_server_socket(int fd)
{
	close(fd);
}

static int get8(const char *data, size_t idx, size_t max, uint8_t *ret)
{
	uint16_t tmp;

	if (idx + 1 > max)
		return FAILURE;

	memcpy(&tmp, data + idx, 1);
	*ret = tmp;
	return 1;
}

static int get16(const char * data, size_t idx, size_t max, uint16_t *ret)
{
	uint16_t tmp;

	if (idx + 2 > max)
		return FAILURE;

	memcpy(&tmp, data + idx, 2);
	*ret = ntohs(tmp);
	return 2;
}

static int enqueue_request(struct dns_request *dns_request)
{
	(void) dns_request;

	return SUCCESS;
}

#define	PTR_MASK 0xc0
#define	IS_PTR(x) (x & PTR_MASK)

/* this function is a little bit tricky, the DNS packet format provides a
 * mechanism to compress a string. A special pattern signals that the next
 * bytes are a pointer to another place and not a vanilla character array */
static int get_name(const char *data, size_t idx, size_t max,
		char *ret_data, size_t max_data_ret_len)
{
	uint8_t llen, offset_ptr;
	int name_end = -1; /* FIXME: change name of name_end */
	size_t i = idx;
	unsigned jumps = 0;
	char *cp = ret_data;
	const char *const end = ret_data + max_data_ret_len;

	assert(idx <= max);

	while(666) {
		i += get8(data, i, max, &llen);

		pr_debug("label len: %u", llen);

		if (llen == 0) /* reached end of string */
			break;

		if (IS_PTR(llen)) {
			pr_debug("label is pointer");
			i += get8(data, i, max, &offset_ptr);
			if (name_end < 0)
				name_end = i;
			i = (((int)llen & 0x3f) << 8) + offset_ptr;
			if (i > max) {
				err_msg("name format corrupt, skipping it");
				return FAILURE;
			}
			if (jumps++ > max) {
				err_msg("corrupted name, we jump more then characters in the array");
				return FAILURE;
			}

			/* and jump */
			continue;
		}

		if (llen > 63) {
			err_msg("corrupted name format");
			return FAILURE;
		}

		if (cp != ret_data) {
			if (cp + 1 >= end) {
				return FAILURE;
			}
			*cp++ = '.';
		}
		if (cp + llen >= end)
			return FAILURE;
		memcpy(cp, data + i, llen);
		cp += llen;
		i  += llen;
	}

	if (cp >= end)
		return FAILURE;
	*cp = '\0';

	if (name_end < 0) {
		return i;
	} else {
		return name_end;
	}
}

#define	DNS_FLAG_MASK_QUESTION 0x0100
#define	DNS_FLAG_STANDARD_QUERY 0x7800
#define	IS_DNS_QUESTION(x) (x & DNS_FLAG_MASK_QUESTION)
#define	IS_DNS_STANDARD_QUERY(x) (x & DNS_FLAG_STANDARD_QUERY)

static void process_dns_query(const char *packet, const size_t len,
		const struct sockaddr_storage *ss, socklen_t ss_len)
{
	int ret, i = 0, ii, j;
	struct dns_request *dr;

	dr = xzalloc(sizeof(struct dns_request));

	i += get16(packet, i, len, &dr->id);
	i += get16(packet, i, len, &dr->flags);
	i += get16(packet, i, len, &dr->questions);
	i += get16(packet, i, len, &dr->answers);
	i += get16(packet, i, len, &dr->authority);
	i += get16(packet, i, len, &dr->additional);

	pr_debug("process DNS query [packet size: %d id:%u, flags:0x%x, "
			 "questions:%u, answers:%u, authority:%u, additional:%u]",
			 len, dr->id, dr->flags, dr->questions, dr->answers, dr->authority, dr->additional);

	if (!IS_DNS_QUESTION(dr->flags)) {
		pr_debug("incoming packet is no accepted DNS packet (flags: 0x%x, accepted: 0x%x",
				dr->flags, DNS_FLAG_MASK_QUESTION);
		free(dr);
		return;
	}

	/* save caller address */
	memcpy(&dr->src_ss, ss, sizeof(struct sockaddr_storage));
	dr->src_ss_len = ss_len;

	dr->dns_sub_question = xzalloc(sizeof(struct dns_sub_question *) * dr->questions);

#define	MAX_DNS_NAME 256

	for (j = 0; j < dr->questions; j++) {
		struct dns_sub_question *dnssq;
		char name[MAX_DNS_NAME];

		ii = get_name(packet, i, len, name, MAX_DNS_NAME);
		if (ii == FAILURE) {
			err_msg("corrupted name format");
			return;
		}
		i += ii;

		pr_debug("parsed name: %s\n", name);


		dnssq = xzalloc(sizeof(struct dns_sub_question));

		i += get16(packet, i, len, &dnssq->type);
		i += get16(packet, i, len, &dnssq->class);

		dnssq->name = xzalloc(strlen(name) + 1);

		memcpy(dnssq->name, name, strlen(name) + 1);

		dr->dns_sub_question[j] = dnssq;
	}

	if (IS_DNS_STANDARD_QUERY(dr->flags)) {
		pr_debug("only standard queries supportet (flag: 0x%x)\n", dr->flags);
		/* XXX: send a failure packet back to the host */
		return;
	}

	/* now we do the actual query */
	ret = enqueue_request(dr);
	if (ret != SUCCESS) {
		err_msg("Cannot enqueue request in active queue");
		return;
	}
}

#define	MAX_PACKET_LEN 2048

/* if a incoming client request is coming then this
 * function is called */
static void incoming_request(int fd, int what, void *data)
{
	ssize_t rc;
	char packet[MAX_PACKET_LEN];
	struct sockaddr_storage ss;
	socklen_t ss_len = sizeof(struct sockaddr_storage);

	(void) what;
	(void) data;

	pr_debug("incoming DNS request");

	rc = recvfrom(fd, packet, MAX_PACKET_LEN, 0, (struct sockaddr*) &ss, &ss_len);
	if (rc < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK)
			return;
		err_sys_die(EXIT_FAILMISC, "Failure in read routine for incoming packet");
	}

	process_dns_query(packet, rc, &ss, ss_len);
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

	ev_entry = ev_entry_new(fd, EV_READ, incoming_request, NULL);
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


struct ctx *alloc_ctx(void)
{
	return xzalloc(sizeof(struct ctx));
}


void free_ctx(struct ctx *c)
{
	free(c); c = NULL;
}

/* default to google ns */
#define	DEFAULT_NS "8.8.8.8"
#define	DEFAULT_NS_PORT "53"


int main(void)
{
	int ret, server_socket, flags = 0;
	struct ctx *ctx;

	fprintf(stdout, "cachefor - a lighweight caching and forwarding DNS server (C) 2009\n");

	ret = initiate_seed();
	if (ret == FAILURE) {
		err_msg("PRNG cannot be initialized satisfying (fallback to time(3) and getpid(3))");
	}

	ctx = alloc_ctx();

	ctx->ev_hndl = ev_init_hdntl();

	ret = nameserver_init(ctx);
	if (ret == FAILURE) {
		err_msg_die(EXIT_FAILMISC, "cannot initialize nameserver context");
	}

	ret = nameserver_add(ctx, DEFAULT_NS, DEFAULT_NS_PORT);
	if (ret != SUCCESS) {
		err_msg_die(EXIT_FAILMISC, "cannot add default nameserver: %s", DEFAULT_NS);
	}

	ret = adns_request_init(ctx);
	if (ret != SUCCESS) {
		err_msg_die(EXIT_FAILMISC,
				"failure in initialize process of server side request structure");
	}

	ret = active_dns_request_set(ctx, "www.google.de", DNS_TYPE_A, DNS_CLASS_INET);
	if (ret != SUCCESS) {
		err_msg("cannot set active DNS request");
	}






	server_socket = init_server_socket(AF_INET, SOCK_DGRAM, 0, DEFAULT_LISTEN_PORT);

	ret = ev_add_server_socket(ctx, server_socket);
	if (ret != SUCCESS) {
		err_msg("Cannot initialize server event handling");
		fini_server_socket(server_socket);
		ev_free_hndl(ctx->ev_hndl);
		return EXIT_FAILEVENT;
	}

	ev_loop(ctx->ev_hndl, flags);

	fini_server_socket(server_socket);

	ev_free_hndl(ctx->ev_hndl);

	free_ctx(ctx);

	return EXIT_SUCCESS;
}



/* vim: set tw=78 ts=4 sw=4 sts=4 ff=unix noet: */
