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

#ifndef LDNSD_H
#define	LDNSD_H

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

enum res_err_code {
	RES_ERROR_NO_ERROR = 0,
	RES_ERROR_TIMEOUT,
};


enum active_dns_request_status {
	ACTIVE_DNS_REQUEST_NEW = 1,
	ACTIVE_DNS_REQUEST_IN_FLIGHT,
};

struct opts {
	int verbose;
};

struct ctx {
	struct ev *ev_hndl;
	struct list *nameserver_list;
	struct opts opts;

	/* new constructed DNS REQUESTS who are
	 * waiting for transmission are enqueued in
	 * a list. As soon as the nameserver socket is
	 * writeable the list is cleared as long as the
	 * socket is still writeable.
	 * The maximum list length is 1024, if this limit
	 * is reached new request are denied or a negative
	 * RESPONSE DNS packet is sent back to the originator */
#define	MAX_WAITING_REQUEST_LIST_SIZE 1024
	struct list *waiting_request_list;

	/* this list contains all requests that are already
	 * transmitted to the nameserver and wait for a DNS
	 * response packet */
	struct list *inflight_request_list;

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


/* see Stevens TCP/IP Illustrated Vol.1
 * page 192 for a great outline */
#define	DNS_FLAG_MASK_QUESTION 0x0100
#define	DNS_FLAG_STANDARD_QUERY 0x7800
#define	DNS_FLAG_STANDARD_ANSWER 0x8180
#define	IS_DNS_QUESTION(x) (x & DNS_FLAG_MASK_QUESTION)
#define	IS_DNS_ANSWER(x) (x & DNS_FLAG_MASK_QUESTION)
#define	IS_DNS_STANDARD_QUERY(x) (x & DNS_FLAG_STANDARD_QUERY)

#define	FLAG_IS_QR_RESPONSE(x)           (((x & 0x8000) >> 15) == 1)
#define	FLAG_IS_QR_QUERY(x)              (((x & 0x8000) >> 15) == 0)
#define	FLAG_IS_OPCODE_STD_QUERY(x)      (((x & 0x7800) >> 11) == 0)
#define	FLAG_IS_OPCODE_INVERSE_QUERY(x)  (((x & 0x7800) >> 11) == 1)
#define	FLAG_IS_RCODE_NO_ERROR(x)        ((x & 0x000f) == 0)

#define	FLAG_RCODE(x) ((x) & 0x000f)

struct dns_sub_section {
	char *name; /* the already restructed label */
	uint16_t type;
	uint16_t class;

	/* ttl specifies the time interval that the resource record
	 * may be cached before the source of the information should
	 * again be consulted. Zero values are interpreted to mean
	 * that the RR can only be used for the transaction in progress
	 */
	int32_t ttl;
	uint16_t rdlength;
};

struct dns_pdu {

	/* request intrinsic values */
	uint16_t id;
	uint16_t flags;
	uint16_t questions;
	uint16_t answers;
	uint16_t authority;
	uint16_t additional;

	struct dns_sub_section **questions_section;
	/* a pointer in the packet to the start of
	 * the question section plus the length */
	const char *questions_section_ptr;
	size_t questions_section_len;

	struct dns_sub_section **answers_section;
	const char *answers_section_ptr;
	size_t answers_section_len;

	struct dns_sub_section **authority_section;
	const char *authority_section_ptr;
	size_t authority_section_len;

	struct dns_sub_section **additional_section;
	const char *additional_section_ptr;
	size_t additional_section_len;
};

struct dns_pdu_hndl {

	/* the correspondent context */
	struct ctx *ctx;

	char *packet;
	size_t len;

	struct dns_pdu *dns_question_pdu;

	/* caller origin */
	struct sockaddr_storage src_ss;
	socklen_t src_ss_len;

	/* a pointer to the used nameserver */
	struct nameserver *ns;
};


/* this structure is threefolded:
 * one part that is the incoming part from
 * a resolver called a passive request.
 * one part that we generate and send to the
 * server, called a active request
 * one part that we receive from the server
 * and this is called a passive response
 * Last but not least we generate a active
 * respone and send it to the resolver. But
 * this data structure is really temporaer so
 * it is purely build on the stack.
 *
 * The following image illustrates the naming
 * variable naming convention. p denotes passive
 * and a denotes active behavior:
 *
 * Resolver          LDNSD      Foreign Name Server
 *
 *   |                  |                   |
 *   |      p_req       |                   |
 *   |----------------->|                   |
 *   |                  |       a_req       |
 *   |                  |------------------>|
 *   |                  |                   |
 *   |                  |       p_res       |
 *   |                  |<------------------|
 *   |      a_res       |                   |
 *   |<-----------------|                   |
 *   |                  |                   |
 *
 *
 * */
struct dns_journey {

	/* the correspondent context */
	struct ctx *ctx;

	/* +++ Passive Request Section +++ */

	/* the following fields are completed before
	   the request is transmitted to the ns */
	struct dns_pdu *p_req_dns_pdu;

	/* the requested name, class and type */
	char *p_req_name;
	uint16_t p_req_type;
	uint16_t p_req_class;

	char *p_req_packet;
	size_t p_req_packet_len;

	/* caller origin */
	struct sockaddr_storage p_req_ss;
	socklen_t p_req_ss_len;


	/* ###
	 * # Active Request Section */

	char *a_req_packet;
	size_t a_req_packet_len;
	struct dns_pdu *a_req_dns_pdu;

	/* ####
	 * # Passive Response Section */

	struct dns_pdu *p_res_dns_pdu;

	/* ####
	 * # Active Response Section */

	char *a_res_packet;
	size_t len;

	/* ####
	 * # Misc Variables */

	int err_code;

	/* a pointer to the used nameserver */
	struct nameserver *ns;

	/* status for internal processing (new, ...)*/
	int status;

	/* this function is called if the dns request
	 * was successful, failed or a timeout occurred */
	int (*cb)(struct dns_journey *);
};


#define	MAX_PACKET_LEN 2048


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
extern void average_init(struct average *);
extern int32_t exponential_average(int32_t, int32_t, uint8_t);
extern void average_add(struct average *, int32_t);
extern int32_t average_value(struct average *);
extern unsigned long long xstrtoull(const char *);
extern void xfstat(int, struct stat *, const char *);
extern void xsetsockopt(int, int, int, const void *, socklen_t, const char *);
extern void x_err_sys(const char *, int, const char *, ...);
extern void x_err_ret(const char *, int, const char *, ...);
extern void msg(const char *, ...);
extern double tv_to_sec(struct timeval *);
extern int subtime(struct timeval *, struct timeval *, struct timeval *);
extern int xatoi(const char *);
extern void * xmalloc(size_t);
extern void *xzalloc(size_t);
extern int nodelay(int, int);
extern void xgetaddrinfo(const char *, const char *, struct addrinfo *, struct addrinfo **);
extern char *xstrdup(const char *);

/* nameserver.c */
extern int nameserver_add(struct ctx *, const char *, const char *, void (*cb)(int, int, void *));
extern struct nameserver *nameserver_select(const struct ctx *);
extern int nameserver_init(struct ctx *);

/* server_side.c */
extern int adns_request_init(struct ctx *);
extern int active_dns_request_set(const struct ctx *, struct dns_journey *, int (*cb)(struct dns_journey *));
extern int init_server_side(struct ctx *);

/* client_side.c */
extern void fini_server_socket(int);
extern int init_client_side(struct ctx *);

/* pkt_parser.c */
extern int clone_dns_pkt(char *, size_t, char **, size_t);
extern void dns_packet_set_answer_no(char *, uint16_t);
extern int parse_dns_packet(struct ctx *, const char *, const size_t, struct dns_pdu **);
extern void free_dns_subsection(uint16_t, struct dns_sub_section **);
extern void free_dns_pdu(struct dns_pdu *);
extern void pretty_print_flags(FILE *, uint16_t);
extern void free_dns_journey(struct dns_journey *);
extern void free_dns_journey_list_entry(void *);
extern void dns_packet_set_response_flag(char *);

#endif /* LDNSD_H */

/* vim: set tw=78 ts=4 sw=4 sts=4 ff=unix noet: */