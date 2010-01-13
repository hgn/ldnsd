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

#ifndef CACHEFOR_H
#define	CACHEFOR_H

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

#define DNS_TYPE_A       1
#define DNS_TYPE_NS      2
#define DNS_TYPE_CNAME   5
#define DNS_TYPE_SOA     6
#define DNS_TYPE_PTR    12
#define DNS_TYPE_MX     15
#define DNS_TYPE_TXT    16
#define DNS_TYPE_AAAA   28

#define DNS_CLASS_INET   1


enum ns_status {
	NS_STATUS_NEW = 1,
	NS_STATUS_ALIVE,
	NS_STATUS_DEAD,
};

struct nameserver {
	int socket; /* a connected UDP socket */

	struct sockaddr_storage address;
	socklen_t address_len;

	enum ns_status status;

	/* each request is assosiated with a timeout */
	struct ev_entry *timeout;
};

struct dns_sub_question {
	uint16_t type;
	uint16_t class;
	char *name;
};

enum active_dns_request_status {
	ACTIVE_DNS_REQUEST_NEW = 1,
	ACTIVE_DNS_REQUEST_IN_FLIGHT,
};

/* the dns request wrapper that is transmitted to a nameserver */
struct active_dns_request {

	int type;
	int class;
	char *name;

	int status;

	/* packet specific */
	int16_t id;

	/* the constructed actual packet */
	char *pdu;
	size_t pdu_len;

	/* the used nameserver */
	struct nameserver *ns;
};


struct opts {
	int verbose;
};

struct ctx {
	struct ev *ev_hndl;
	struct list *nameserver_list;
	struct opts opts;
	struct list *active_request_list;

	/* passive side (towards the clients) */
	int client_server_socket;
};

/* a incoming request from a resolver */
struct dns_request {

	/* the correspondent context */
	struct ctx *ctx;

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

	/* the assosiated timeout for this request */
	struct ev_entry *ev_timeout;
};


/* see http://www.ces.clemson.edu/linux/ipw2200_averages.shtml
 * for a comparision between exponential averaging and RC low
 * pass filtering */
#define AVG_ENTRIES 8
struct average {
	int32_t entries[AVG_ENTRIES];
	uint8_t pos;
	uint8_t init;
	uint64_t sum;
};

/* utils.c */
void average_init(struct average *);
int32_t exponential_average(int32_t, int32_t, uint8_t);
void average_add(struct average *, int32_t);
int32_t average_value(struct average *);
unsigned long long xstrtoull(const char *);
void xfstat(int, struct stat *, const char *);
void xsetsockopt(int, int, int, const void *, socklen_t, const char *);
void x_err_sys(const char *, int, const char *, ...);
void x_err_ret(const char *, int, const char *, ...);
void msg(const char *, ...);
double tv_to_sec(struct timeval *);
int subtime(struct timeval *, struct timeval *, struct timeval *);
int xatoi(const char *);
void * xmalloc(size_t);
void *xzalloc(size_t);
int nodelay(int, int);
void xgetaddrinfo(const char *, const char *, struct addrinfo *, struct addrinfo **);
char *xstrdup(const char *);

/* nameserver.c */
int nameserver_add(struct ctx *, const char *, const char *);
struct nameserver *nameserver_select(const struct ctx *);
int nameserver_init(struct ctx *);

/* server_side.c */
int adns_request_init(struct ctx *);
int active_dns_request_set(const struct ctx *, const char *, int, int);
int init_server_side(struct ctx *);

/* client_side.c */
void fini_server_socket(int);
int init_client_side(struct ctx *);

#endif /* CACHEFOR_H */

/* vim: set tw=78 ts=4 sw=4 sts=4 ff=unix noet: */
