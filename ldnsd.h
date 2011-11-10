/*
** Copyright (C) 2009,2010,2011 - Hagen Paul Pfeifer <hagen@jauu.net>
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
#include <arpa/inet.h>

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

/* the following typedefs are for documentation
 * and strict type checking - sometimes we will
 * save some network bytorder encoding instruction
 * that in network byte order to reduce otherwise
 * senseless conversion */
typedef uint16_t le16;
typedef uint16_t be16;
typedef uint32_t le32;
typedef uint32_t be32;
typedef uint64_t le64;
typedef uint64_t be64;

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

#define min_t(type, x, y) ({                    \
        type __min1 = (x);                      \
        type __min2 = (y);                      \
        __min1 < __min2 ? __min1: __min2; })

#define max_t(type, x, y) ({                    \
        type __max1 = (x);                      \
        type __max2 = (y);                      \
        __max1 > __max2 ? __max1: __max2; })

#define stringify(x...) #x
#define streq(a, b) (strcmp((a), (b)) == 0)
#define strcaseeq(a, b) (strcasecmp((a), (b)) == 0)

#define TIME_GT(x,y) (x->tv_sec > y->tv_sec || (x->tv_sec == y->tv_sec && x->tv_usec > y->tv_usec))
#define TIME_LT(x,y) (x->tv_sec < y->tv_sec || (x->tv_sec == y->tv_sec && x->tv_usec < y->tv_usec))

#if !defined likely && !defined unlikely
# define likely(x)   __builtin_expect(!!(x), 1)
# define unlikely(x) __builtin_expect(!!(x), 0)
#endif

#define BUG() do { \
          fprintf(stderr, "BUG: failure at %s:%d/%s()!\n", __FILE__, __LINE__, __func__); \
          abort(); \
  } while (0)

#define BUG_ON(condition) do { if (unlikely(condition)) BUG(); } while(0)

enum {
	MSG_ERROR = 1,
	MSG_WARNING
};

#define wrn_msg(format, args...) \
	do { \
		x_err_ret(MSG_WARNING, __FILE__, __LINE__,  format , ## args); \
	} while (0)

#define wrn_sys(format, args...) \
	do { \
		x_err_sys(MSG_WARNING, __FILE__, __LINE__,  format , ## args); \
	} while (0)

#define err_msg(format, args...) \
	do { \
		x_err_ret(MSG_ERROR, __FILE__, __LINE__,  format , ## args); \
	} while (0)

#define err_sys(format, args...) \
	do { \
		x_err_sys(MSG_ERROR, __FILE__, __LINE__,  format , ## args); \
	} while (0)

#define err_sys_die(exitcode, format, args...) \
	do { \
		x_err_sys(MSG_ERROR, __FILE__, __LINE__, format , ## args); \
		exit(exitcode); \
	} while (0)

#define err_msg_die(exitcode, format, args...) \
	do { \
		x_err_ret(MSG_ERROR, __FILE__, __LINE__,  format , ## args); \
		exit(exitcode); \
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
#define	EXIT_FAILCONF   8
#define	EXIT_FAILINT    9 /* INTernal error */

/* determine the size of an array */
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

#define SUCCESS 0
#define FAILURE -1

#define	DEFAULT_LISTEN_PORT "6666"

/* forwarder defaults (google ns) */
#define	DEFAULT_NS "8.8.8.8"
#define	DEFAULT_NS_PORT "53"

#define DEFAULT_TTL 86400 /* 24 hours */
#define TTL_MIN 10 /* seconds */
#define TTL_MAX (7*86400) /* one weak */

#define	RANDPOOLSRC "/dev/urandom"

#define	MAXERRMSG 1024

#define	DNS_TYPE_A              1
#define	DNS_TYPE_NS             2
#define	DNS_TYPE_MD             3
#define	DNS_TYPE_MF             4
#define	DNS_TYPE_CNAME          5
#define	DNS_TYPE_SOA            6
#define	DNS_TYPE_MB             7
#define	DNS_TYPE_MG             8
#define	DNS_TYPE_MR             9
#define	DNS_TYPE_NULL          10
#define	DNS_TYPE_WKS           11
#define	DNS_TYPE_PTR           12
#define	DNS_TYPE_HINFO         13
#define	DNS_TYPE_MINFO         14
#define	DNS_TYPE_MX            15
#define	DNS_TYPE_TXT           16
#define	DNS_TYPE_AAAA          28
#define	DNS_TYPE_AFSDB         18
#define	DNS_TYPE_CERT          37
#define	DNS_TYPE_DHCID         49
#define	DNS_TYPE_DLV        32769
#define	DNS_TYPE_DNAME         39
#define	DNS_TYPE_OPT           41
#define	DNS_TYPE_DNSKEY        48
#define	DNS_TYPE_DS            43
#define	DNS_TYPE_HIP           55
#define	DNS_TYPE_IPSECKEY      45
#define	DNS_TYPE_KEY           25
#define	DNS_TYPE_LOC           29
#define	DNS_TYPE_NAPTR         35
#define	DNS_TYPE_NSEC          47
#define	DNS_TYPE_NSEC3         50
#define	DNS_TYPE_NSEC3PARAM    51
#define	DNS_TYPE_RRSIG	       46
#define	DNS_TYPE_SIG	       24
#define	DNS_TYPE_SPF           99
#define	DNS_TYPE_SRV           33
#define	DNS_TYPE_SSHFP         44
#define	DNS_TYPE_TKEY         249
#define	DNS_TYPE_TSIG         250
#define	DNS_TYPE_TA         32768

/* not supported */
#if 0
#define	TYPE_AXFR	252
#define	TYPE_IXFR	251
#define	TYPE_OPT	41
#endif


#define	DNS_TYPE_INVALID -1

#define DNS_CLASS_INET   1

#define MAX_HOSTNAME_STR 255 /* including final dot */


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


enum ns_status {
	NS_STATUS_NEW = 1,
	NS_STATUS_ALIVE,
	NS_STATUS_DEAD, /* unoperational */
};

struct nameserver {
	int socket; /* a connected UDP socket */

	char *ip;

	/* rtt stored in ms */
	struct average rtt_average;

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

enum {
	O_QUITSCENT = 0,
	O_GENTLE,
	O_VERBOSE,
	O_DEBUG
};

struct cli_opts {
	/* daemon common values */
	char *me;
	int verbose_level;
	char *rc_path;

	char *port;

	/* where to forward incoming DNS requests */
	struct list *forwarder_list;
	char *forwarder_port;

	/* support for ends0 */
#define	EDNS0_MODE_DEFAULT 1 /* enabled */
	int edns0_mode;
/* we define this limit to prevent user configured failures.
 * In the case that this limit is to small we can adjust this
 * value to something larger */
#define	EDNS0_MAX 16384
#define	EDNS0_DEFAULT 8192
	uint16_t edns0_max;
};

enum {
	CACHE_BACKEND_NONE,
	CACHE_BACKEND_MEMORY
};


/* the first strategy is the default strategy. You
 * can reorder this if you want */
enum ns_select_strategy {
	FIRST = 0,
	RANDOM,
	TIME,

	UNSUPPORTED,
};

enum {
	MODE_RECURSIVE,
	MODE_ITERATIVE
};

#define DEFAULT_MODE MODE_ITERATIVE

struct statistics {
	unsigned long lookup_in_cache;
	unsigned long lookup_not_in_cache;
};

struct ctx {

	int mode;

	struct ev *ev_hndl;

	/* successful request responses */
	unsigned long long succ_req_res;

	struct list *nameserver_list;
	enum ns_select_strategy ns_select_strategy;

	/* only required for strategy "time" */
	int ns_time_select_threshold;
	int ns_time_select_re_threshold;

	/* is selected_ns != NULL then the
	 * selection was successfull */
	struct nameserver *selected_ns;

	struct cli_opts cli_opts;

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

	int cache_backend;
	/* cache backend private data (e.g. struct mm_cachhe_private */
	void *cache;

	struct list *zone_filename_list;

	/* the list is initialized if the first ip
	 * is added to the list, NULL means therefore
	 * all queries are allowed */
	struct list *allowed_resolver_list;

	/* similar, but for DNS updates from resolver */
	struct list *allow_update_list;

	/* a buffer with a allocated memory area at program
	 * start and freed at program end. The purpose is
	 * to provide a place where the outgoing packet is
	 * constructed. The maximum size is specified in
	 * cli_opts->edns0_max (which is per default:
	 * EDNS0_MAX_DEFAULT) */
	char *buf;
	uint16_t buf_max;

	struct statistics statistics;
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
#define	FLAG_IS_RCODE_NO_ERROR(x)         ((x & 0x000f) == 0)

#define	FLAG_RCODE(x) ((x) & 0x000f)

typedef union
{
	void     *ptr;
	uint8_t   u8;
	uint16_t  u16;
	uint32_t  u32;
} dns_sub_section_data_t __attribute__ ((__transparent_union__));


struct dns_sub_section {
	char *name; /* the already restructed label */
	uint16_t type;
	uint16_t class;

	/* ttl specifies the time interval that the resource record
	 * may be cached before the source of the information should
	 * again be consulted. Zero values are interpreted to mean
	 * that the RR can only be used for the transaction in progress */
	int32_t ttl;

	uint16_t rdlength;
	/* priv_data is the data followed directly
	 * after rdlength (if rdlength != 0). But it
	 * can be also other context sensitive data
	 * encoded. The generic handler will save rdlength
	 * lenght data, but more sophisticated ressource records
	 * can lead to a complex structure. Then priv_data
	 * can also reflect this structure. To cover some common
	 * types (A, AAA) we introduced a union type. This speed
	 * up the handling by preventing malloc/free opertions.
	 * XXX: AAAA records should also be handled with this mechanism.
	 * See definition of dns_sub_section_data_t */
	dns_sub_section_data_t priv_data;
#define	priv_data_u8 priv_data.u8
#define	priv_data_u16 priv_data.u16
#define	priv_data_u32 priv_data.u32
#define	priv_data_ptr priv_data.ptr
};

#define	DNS_PDU_HEADER_LEN 12

struct dns_pdu {

	/* request intrinsic values */
	uint16_t id;
	uint16_t flags;
	uint16_t questions;
	uint16_t answers;
	uint16_t authority;
	uint16_t additional;

	size_t questions_section_len;
	struct dns_sub_section **questions_section;
	/* a pointer in the packet to the start of
	 * the question section plus the length */
	const char *questions_section_ptr;

	size_t answers_section_len;
	struct dns_sub_section **answers_section;

	/* answers_section_ptr can point to the packet
	 * data (the received packet) or to a new allocated
	 * answer_data in the case the answer section is created. */
	char *answers_section_ptr;
	char *answer_data;

	size_t authority_section_len;
	struct dns_sub_section **authority_section;
	const char *authority_section_ptr;

	size_t additional_section_len;
	struct dns_sub_section **additional_section;
	const char *additional_section_ptr;

	uint16_t edns0_max_payload;
#define	EDNS0_DISABLED 0
#define	EDNS0_ENABLED 1
	int16_t edns0_enabled;
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

	/* edns0 related variables. Per default
	 * edns0 is disabled to the resolver
	 * and the max payload is restricted to
	 * 512 byte payload. This limitation is
	 * adjusted if the client use EDNS0 and
	 * allow a larger size, the max_payload_size
	 * reflects the user accepted payload. */
#define	DEFAULT_PDU_MAX_PAYLOAD_SIZE 512
	int max_payload_size;

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

	/* for statistics. We timestamp
	 * when we send a packet and we timestamp
	 * when we receive the corresponging response */
	struct timeval req_time;
	struct timeval res_time;

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
	size_t a_res_packet_len;

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


/* main data structure, holding a record. Must be
 * implemented by all caching strategies */
struct cache_data {

	 uint16_t type;  /* DNS_TYPE_*     */
	 uint16_t class; /* DNS_CLASS_INET */

	 uint32_t ttl;

	 char *key;
	 size_t key_len;

	 /* this union should never be larger
	  * as sizeof(void *). Every data element
	  * smaller or equal to 8 byte (we assume
	  * x86_64) can be added to the union. */
	 union {
		void *priv_data;
		struct in_addr v4addr;
	 };

	 /* data of encoded (tranmitted) data,
	  * e.g. 4 byte for an A record */
	 int rdlength;
};

#define cache_data_priv(p) (p->priv_data)


#define	MAX_PACKET_LEN 2048


enum rr_section {
	RR_SECTION_QDCOUNT = 1,
	RR_SECTION_ANCOUNT,
	RR_SECTION_NSCOUNT,
	RR_SECTION_ARCOUNT,
};

/* used for allow/filter list */
struct ip_prefix_storage {
	int af_family;
	union {
		struct in_addr v4_addr;
		struct in6_addr v6_addr;
	};
	unsigned long prefix_len;
};

/* utils.c */
void average_init(struct average *);
int32_t exponential_average(int32_t, int32_t, uint8_t);
void average_add(struct average *, int32_t);
int32_t average_value(struct average *);
unsigned long long xstrtoull(const char *);
void xfstat(int, struct stat *, const char *);
void xsetsockopt(int, int, int, const void *, socklen_t, const char *);
void x_err_sys(int, const char *, int, const char *, ...);
void x_err_ret(int, const char *, int, const char *, ...);
void msg(const char *, ...);
double tv_to_sec(struct timeval *);
int subtime(struct timeval *, struct timeval *, struct timeval *);
int xatoi(const char *);
void * xmalloc(size_t);
void *xzalloc(size_t);
void xfree(void *);
int nodelay(int, int);
void xgetaddrinfo(const char *, const char *, struct addrinfo *, struct addrinfo **);
char *xstrdup(const char *);
void hex_print(char *, size_t);
int ip_valid_addr(int, const char *);
int ipv6_prefix_equal(struct in6_addr *, struct in6_addr *, unsigned int);
int ipv6_addr_cmp(const struct in6_addr *, const struct in6_addr *);
int ipv4_prefix_equal(struct in_addr *, struct in_addr *, int);
int ip_prefix_storage_match(const void *, const void *);
int ip_family(const char *);
int prefix_len_check(int, unsigned int);
char *eat_whitespaces(const char *);
int time_modifier(char);
char *parse_ttl(char *, int *);
void set_bit(int, unsigned long *);
void clear_bit(int, unsigned long *);
int test_bit(unsigned int, const unsigned long *);

/* nameserver.c */
int nameserver_add(struct ctx *, const char *, const char *, void (*cb)(int, int, void *));
struct nameserver *nameserver_select(const struct ctx *);
int nameserver_init(struct ctx *);
enum ns_select_strategy ns_select_strategy_to_enum(const char *);
void nameserver_update_rtt(struct ctx *, struct nameserver *, struct timeval *);
const char *nameserver_id(struct nameserver *);
void nameserver_update_statistic(struct ctx *);
int nameserver_size(struct ctx *);


/* server_side.c */
int adns_request_init(struct ctx *);
int active_dns_request_set(struct ctx *, struct dns_journey *, int (*cb)(struct dns_journey *));
int init_server_side(struct ctx *);

/* client_side.c */
void fini_server_socket(int);
int init_client_side(struct ctx *);

/* pkt-parser.c */
int clone_dns_pkt(char *, size_t, char **, size_t);
int parse_dns_packet(struct ctx *, const char *, const size_t, struct dns_pdu **);
struct dns_journey *alloc_dns_journey(void);
void free_dns_subsection(uint16_t, struct dns_sub_section **);
void free_dns_pdu(struct dns_pdu *);
void pretty_print_flags(FILE *, uint16_t);
void free_dns_journey(struct dns_journey *);
void free_dns_journey_list_entry(void *);
void dns_packet_set_rr_entries_number(char *, enum rr_section, uint16_t);
struct dns_pdu *alloc_dns_pdu(void);
int get8(const char *, size_t, size_t, uint8_t *);
int get16(const char *, size_t, size_t, uint16_t *);
int getint32_t(const char *, size_t, size_t, int32_t *);

/* all packet_flags_* functions have as the very first argument
 * a pointer to the start of a DNS packet blob */
void packet_flags_clear(char *);
void packet_flags_set_qr_response(char *);
void packet_flags_set_qr_query(char *);
void packet_flags_set_authoritative_answer(char *);
void packet_flags_set_unauthoritative_answer(char *);
void packet_flags_set_truncated(char *);
void packet_flags_set_untruncated(char *);
void packet_flags_set_recursion_desired(char *);
void packet_flags_set_recursion_undesired(char *);
void packet_flags_set_recursion_available(char *);
void packet_flags_set_recursion_unavailable(char *);
void packet_flags_set_rcode(char *, char);
void packet_flags_set_rc_no_error(char *);
int packet_flags_get_rcode(char *);

#define	FLAGS_RCODE_NO_ERROR   0
#define	FLAGS_RCODE_NAME_ERROR 3

#define	packet_flags_set_rc_no_error(p)   packet_flags_set_rcode(p, FLAGS_RCODE_NO_ERROR)
#define	packet_flags_set_rc_name_error(p) packet_flags_set_rcode(p, FLAGS_RCODE_NAME_ERROR)


/* cli_opts.c */
int parse_cli_options(struct ctx *, struct cli_opts *, int, char **);
void free_cli_opts(struct cli_opts *);


/* cache.c */
int cache_init(struct ctx *);
int cache_free(struct ctx *);
int cache_add(struct ctx *, struct cache_data *);
int cache_remove(struct ctx *, struct dns_pdu *);
int cache_get(struct ctx *, uint16_t, uint16_t, char *, size_t, struct cache_data **);

/* zone-parser.c */
int parse_zonefiles(struct ctx *);

/* type.c */
unsigned type_opts_to_index(uint16_t);
int str_record_type(const char *, int);
const char *type_999_generic_text(void);
const char *type_to_str(uint16_t);
int is_valid_type(uint16_t);
const char *class_to_str(uint16_t);
int is_valid_class(uint16_t);


/* type-001-a.c */
const char *type_001_a_text(void);
struct cache_data *type_001_a_zone_parser_to_cache_data(struct ctx *, char *);
void type_001_a_free_cache_data(struct cache_data *);
int type_001_a_create_sub_section(struct ctx *, struct cache_data *, struct dns_journey *);

/* type-015-mx.c */
const char *type_015_mx_text(void);
struct cache_data *type_015_mx_zone_parser_to_cache_data(struct ctx *, char *);
void type_015_mx_free_cache_data(struct cache_data *);
int type_015_mx_cache_cmp(const struct cache_data *, const struct cache_data *);

/* type-028-aaaa.c */
const char *type_028_aaaa_text(void);
struct cache_data *type_028_aaaa_zone_parser_to_cache_data(struct ctx *, char *);
void type_028_aaaa_free_cache_data(struct cache_data *);
int type_028_aaaa_cache_cmp(const struct cache_data *, const struct cache_data *);
int type_028_aaaa_create_sub_section(struct ctx *, struct cache_data *, struct dns_journey *);

/* type-041-opt.c */
#define	TYPE_041_OPT_LEN 11 /* fixed len of this option */
const char *type_041_opt_text(void);
int type_041_opt_parse(struct ctx *, struct dns_pdu *, struct dns_sub_section *, const char *, int);
int type_041_opt_construct_option(struct ctx *, struct dns_pdu *, struct dns_sub_section *, const char *, int);
int type_041_opt_available(struct dns_pdu *);

/* type-999-generic.c */
int type_999_generic_parse(struct ctx *, struct dns_pdu *,struct dns_sub_section *, const char *, int);
int type_999_generic_destruct(struct ctx *, struct dns_pdu *, struct dns_sub_section *, const char *, int, int);
int type_999_generic_construct(struct ctx *, struct dns_pdu *, struct dns_sub_section *, const char *, int);
void type_999_generic_free(struct ctx *, struct dns_sub_section *);
int type_999_generic_available(struct dns_pdu *);
struct cache_data *type_999_generic_zone_parser_to_cache_data(struct ctx *, char *);
void type_999_generic_free_cache_data(struct cache_data *);
int type_999_generic_cache_cmp(const struct cache_data *, const struct cache_data *);



/* operation for RR types. The new type
 * must also be actived at type_opts_valid()
 * in type-multiplexer.c */
struct type_fn_table {

	/* returns a description of this type */
	const char *(*text)(void);

	int (*parse)(struct ctx *, struct dns_pdu *, struct dns_sub_section *,
			const char *, int);

	/* construct generates a blob based on the struct dns_sub_section
	 * priv_data section.  Construct return the size of the constructed
	 * data blob or -1 for a error */
	int (*construct)(struct ctx *, struct dns_pdu *, struct dns_sub_section *,
			const char *, int);

	/* destruct parses the packet rr and save relevant information
	 * in priv_data. For A records this are 4 byte in priv_data */
	int (*destruct)(struct ctx *, struct dns_pdu *, struct dns_sub_section *,
			const char *, int, int);

	/* free frees the priv_data pointer, in the
	 * simplest case this is a pointer to free */
	void (*free)(struct ctx *, struct dns_sub_section *);

	/* parse the zone file entry and returns a blob, suitable to
	 * transmission */
	struct cache_data *(*zone_parser_to_cache_data)(struct ctx *, char *);

	/* create from a given cache data entry a dns sub section */
	int (*create_sub_section)(struct ctx *, struct cache_data *, struct dns_journey *);

	/* some types allocate dynamic memory for their data. The rule
	 * is that types which are larger then 8 byte MUST dynamically
	 * allocate memory for private data. The A record type (a 4 byte
	 * ip address) is smaller and therefore saved in the union.
	 *
	 * NOTE: this function MUST only free private data, the cache_data
	 * is freed somewhere else. So don't free them, see type_018_mx.c
	 * for an example. */
	void (*free_cache_priv_data)(struct cache_data *);

	/* compare function for cache data. Every RR type in the zone file
	 * MUST overwrite their own compare function. Please see
	 * type_999_generic_cache_cmp() and type_015_mx_cache_cmp() */
	int (*cache_cmp)(const struct cache_data *, const struct cache_data *);
};

extern struct type_fn_table type_fn_table[];

/* Don't change the ordering! Append new supported values.
 * See type-generic.c for more information. */
enum {
	TYPE_INDEX_TYPE_A,
	TYPE_INDEX_TYPE_MX,
	TYPE_INDEX_TYPE_AAAA,
	TYPE_INDEX_TYPE_OPT,
	TYPE_INDEX_TYPE_GENERIC,
	__TYPE_INDEX_TYPE_MAX
};

#define TYPE_INDEX_TYPE_MAX (__TYPE_INDEX_TYPE_MAX - 1)


#define MAX_LABELS 128
/* Structures used to implement name compression */
struct dnslabel_entry { char *v; off_t pos; };
struct dnslabel_table {
	int n_labels; /* number of current entries */
	/* map from name to position in message */
	struct dnslabel_entry labels[MAX_LABELS];
};


/* pkt-generator.c */
int pkt_construct_dns_query(struct ctx *, struct dns_journey *, char *,
		int, uint16_t, uint16_t , uint16_t, char *, size_t);
off_t dnsname_to_labels(char *, size_t, off_t, const char *, const int, struct dnslabel_table *);


#endif /* LDNSD_H */
