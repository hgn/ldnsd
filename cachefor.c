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

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <time.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <assert.h>

#include <netinet/in.h>
#include <netinet/tcp.h>

#include <limits.h>
#include <netdb.h>
#include <stdarg.h>

#include "ev.h"
#include "clist.h"

#ifdef HAVE_RDTSCLL
# include <linux/timex.h>

# ifndef rdtscll
# define rdtscll(val) \
     __asm__ __volatile__("rdtsc" : "=A" (val))
# endif
#endif /* HAVE_RDTSCLL */

#undef __always_inline
#if __GNUC_PREREQ (3,2)
# define __always_inline __inline __attribute__ ((__always_inline__))
#else
# define __always_inline __inline
#endif

#ifndef ULLONG_MAX
# define ULLONG_MAX 18446744073709551615ULL
#endif

#define min(x,y) ({			\
	typeof(x) _x = (x);		\
	typeof(y) _y = (y);		\
	(void) (&_x == &_y);	\
	_x < _y ? _x : _y; })

#define max(x,y) ({			\
	typeof(x) _x = (x);		\
	typeof(y) _y = (y);		\
	(void) (&_x == &_y);	\
	_x > _y ? _x : _y; })

#define TIME_GT(x,y) (x->tv_sec > y->tv_sec || (x->tv_sec == y->tv_sec && x->tv_usec > y->tv_usec))
#define TIME_LT(x,y) (x->tv_sec < y->tv_sec || (x->tv_sec == y->tv_sec && x->tv_usec < y->tv_usec))

#if !defined likely && !defined unlikely
# define likely(x)   __builtin_expect(!!(x), 1)
# define unlikely(x) __builtin_expect(!!(x), 0)
#endif

#define err_msg(format, args...) \
	do { \
		x_err_ret(__FILE__, __LINE__,  format , ## args); \
	} while (0)

#define err_sys(format, args...) \
	do { \
		x_err_sys(__FILE__, __LINE__,  format , ## args); \
	} while (0)

#define err_sys_die(exitcode, format, args...) \
	do { \
		x_err_sys(__FILE__, __LINE__, format , ## args); \
		exit( exitcode ); \
	} while (0)

#define err_msg_die(exitcode, format, args...) \
	do { \
		x_err_ret(__FILE__, __LINE__,  format , ## args); \
		exit( exitcode ); \
	} while (0)

#define	pr_debug(format, args...) \
	do { \
		if (DEBUG) \
			msg(format, ##args); \
	} while (0)

#define	EXIT_OK         EXIT_SUCCESS
#define	EXIT_FAILMEM    1
#define	EXIT_FAILOPT    2
#define	EXIT_FAILMISC   3
#define	EXIT_FAILNET    4
#define	EXIT_FAILHEADER 6
#define	EXIT_FAILEVENT  7
#define	EXIT_FAILINT    8 /* INTernal error */

/* determine the size of an array */
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

#define SUCCESS 0
#define FAILURE -1

#define	DEFAULT_LISTEN_PORT "6666"

#define	RANDPOOLSRC "/dev/urandom"

#define	MAXERRMSG 1024

enum ns_status {
	NS_STATUS_NEW = 1,
	NS_STATUS_ALIVE,
	NS_STATUS_DEAD,
};

struct nameserver {
	int socket; /* a connected UDP socket */
	struct sockaddr_storage address;
	enum ns_status status;
	struct ev_entry *timeout;
};

struct dns_sub_question {
	uint16_t type;
	uint16_t class;
	char *name;
};

/* a incoming request from a resolver */
struct dns_request {
	char *packet;
	size_t len;

	/* caller origin */
	struct sockaddr_storage src_ss;
	socklen_t src_ss_len;

	/* request intrinsic values */
	uint16_t id;
	uint16_t flags;
	uint16_t questions;
	uint16_t answers;
	uint16_t authority;
	uint16_t additional;

	struct dns_sub_question **dns_sub_question;

	unsigned type; /* A, AAAA, PTR */
	struct nameserver *ns; /* a pointer to the used nameserver */
};

struct cachefor {
	struct dns_request pending_dns_requests;
	struct dns_request processed_dns_requests;
};

struct ev *ev_hndl;
struct cachefor *cachefor;

static int subtime(struct timeval *op1, struct timeval *op2,
		struct timeval *result)
{
        int borrow = 0, sign = 0;
        struct timeval *temp_time;

        if (TIME_LT(op1, op2)) {
                temp_time = op1;
                op1  = op2;
                op2  = temp_time;
                sign = 1;
        }

        if (op1->tv_usec >= op2->tv_usec) {
                result->tv_usec = op1->tv_usec-op2->tv_usec;
        } else {
                result->tv_usec = (op1->tv_usec + 1000000) - op2->tv_usec;
                borrow = 1;
        }
        result->tv_sec = (op1->tv_sec-op2->tv_sec) - borrow;

        return sign;
}

void
msg(const char *format, ...)
{
	va_list ap;
	struct timeval tv;

	gettimeofday(&tv, NULL);
	fprintf(stderr, "[%ld.%06ld] ", tv.tv_sec, tv.tv_usec);

	 va_start(ap, format);
	 vfprintf(stderr, format, ap);
	 va_end(ap);

	 fputs("\n", stderr);
}


static void err_doit(int sys_error, const char *file,
		const int line_no, const char *fmt, va_list ap)
{
	int	errno_save;
	char buf[MAXERRMSG];

	errno_save = errno;

	vsnprintf(buf, sizeof(buf) - 1, fmt, ap);
	if (sys_error) {
		size_t len = strlen(buf);
		snprintf(buf + len,  sizeof buf - len, " (%s)", strerror(errno_save));
	}

	fprintf(stderr, "ERROR [%s:%d]: %s\n", file, line_no, buf);
	fflush(NULL);

	errno = errno_save;
}

void x_err_ret(const char *file, int line_no, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	err_doit(0, file, line_no, fmt, ap);
	va_end(ap);
	return;
}


void x_err_sys(const char *file, int line_no, const char *fmt, ...)
{
	va_list		ap;

	va_start(ap, fmt);
	err_doit(1, file, line_no, fmt, ap);
	va_end(ap);
}


static void * xmalloc(size_t size)
{
	void *ptr = malloc(size);
	if (!ptr)
		err_msg_die(EXIT_FAILMEM, "Out of mem: %s!\n", strerror(errno));
	return ptr;
}

static void* xzalloc(size_t size)
{
	void *ptr = xmalloc(size);
	memset(ptr, 0, size);
	return ptr;
}

static void xsetsockopt(int s, int level, int optname,
		const void *optval, socklen_t optlen, const char *str)
{
	int ret = setsockopt(s, level, optname, optval, optlen);
	if (ret)
		err_sys_die(EXIT_FAILNET, "Can't set socketoption %s", str);
}

static int xsnprintf(char *str, size_t size, const char *format, ...)
{
	va_list ap;
	int len;

	va_start(ap, format);
	len = vsnprintf(str, size, format, ap);
	va_end(ap);
        if (len < 0 || ((size_t)len) >= size)
		err_msg_die(EXIT_FAILINT, "buflen %u not sufficient (ret %d)",
								size, len);
	return len;
}


static void xfstat(int filedes, struct stat *buf, const char *s)
{
	if (fstat(filedes, buf))
		err_sys_die(EXIT_FAILMISC, "Can't fstat file %s", s);
}


static void xpipe(int filedes[2])
{
	if (pipe(filedes))
		err_sys_die(EXIT_FAILMISC, "Can't create pipe");
}


static int nodelay(int fd, int flag)
{
	int ret = 0; socklen_t ret_size;

	if (getsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &ret, &ret_size) < 0)
		return -1;

	if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag)) < 0)
		return -1;

	return ret;
}

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

static void xgetaddrinfo(const char *node, const char *service,
		struct addrinfo *hints, struct addrinfo **res)
{
	int ret;

	ret = getaddrinfo(node, service, hints, res);
	if (ret != 0) {
		err_msg_die(EXIT_FAILNET, "Call to getaddrinfo() failed: %s!\n",
				(ret == EAI_SYSTEM) ?  strerror(errno) : gai_strerror(ret));
	}

	return;
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

static int enqueue_request(struct cachefor *cf, struct dns_request *dns_request)
{
	return SUCCESS;
}

static int process_pending_request(struct cachefor *cf)
{
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
		uint16_t type, class;
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
	ret = enqueue_request(cachefor, dr);
	if (ret != SUCCESS) {
		err_msg("Cannot enqueue request in active queue");
		return;
	}
}

#define	MAX_PACKET_LEN 2048

static void incoming_request(int fd, int what, void *data)
{
	ssize_t rc;
	char packet[MAX_PACKET_LEN];
	struct sockaddr_storage ss;
	socklen_t ss_len = sizeof(struct sockaddr_storage);

	pr_debug("incoming DNS request");

	rc = recvfrom(fd, packet, MAX_PACKET_LEN, 0, (struct sockaddr*) &ss, &ss_len);
	if (rc < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK)
			return;
		err_sys_die(EXIT_FAILMISC, "Failure in read routine for incoming packet");
	}

	process_dns_query(packet, rc, &ss, ss_len);
}

static int ev_add_server_socket(int fd)
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

	ret = ev_add(ev_hndl, ev_entry);
	if (ret != EV_SUCCESS) {
		err_msg("Cannot add listening socke to the event handling abstraction");
		return FAILURE;
	}

	return SUCCESS;
}

struct cachefor *init_cachefor(void)
{
	return xzalloc(sizeof(struct cachefor));
}

free_cachefor(struct cachefor *c)
{
	free(c); c = NULL;
}


int main(void)
{
	int ret, server_socket, flags = 0;

	fprintf(stdout, "cachefor - a lighweight caching and forwarding DNS server (C) 2009\n");

	ev_hndl = ev_init_hdntl();

	cachefor = init_cachefor();

	ret = initiate_seed();
	if (ret == FAILURE) {
		err_msg("PRNG cannot be initialized satisfying (fallback to time(3) and getpid(3))");
	}

	server_socket = init_server_socket(AF_INET, SOCK_DGRAM, 0, DEFAULT_LISTEN_PORT);

	ret = ev_add_server_socket(server_socket);
	if (ret != SUCCESS) {
		err_msg("Cannot initialize server event handling");
		fini_server_socket(server_socket);
		ev_free_hndl(ev_hndl);
		free_cachefor(cachefor);
		return EXIT_FAILEVENT;
	}

	ev_loop(ev_hndl, flags);

	fini_server_socket(server_socket);

	ev_free_hndl(ev_hndl);

	free_cachefor(cachefor);

	return EXIT_SUCCESS;
}



/* vim: set tw=78 ts=4 sw=4 sts=4 ff=unix noet: */
