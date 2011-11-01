#include "ldnsd.h"
#include "rc.h"

#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

extern FILE *yyin;
int yyparse(void);


static int open_rc_file(const struct ctx *ctx)
{
	if (ctx->cli_opts.rc_path) {
		yyin = fopen(ctx->cli_opts.rc_path, "r");
		if (yyin == NULL) {
			err_sys_die(EXIT_FAILURE, "cannot open configuration file (%s)",
					ctx->cli_opts.rc_path);
		}
		return SUCCESS;
	}
	/* ok, the user doesn't supplied any configuration
	 * file paths - we search in the standard environment */
	yyin = fopen("/etc/ldnsd.conf", "r");
	if (yyin != NULL) {
		return SUCCESS;
	}

	yyin = fopen("/etc/ldnsd/ldnsd.conf", "r");
	if (yyin != NULL) {
		return SUCCESS;
	}

	return FAILURE;
}


/* see the comments within parse_rc_file() */
static struct ctx *xctx;

int parse_rc_file(struct ctx *ctx)
{
	int ret;

	ret = open_rc_file(ctx);
	if (ret != SUCCESS)
		err_msg_die(EXIT_FAILOPT, "Cannot open a configuration file");

	/* ok, it is a little bit unclean, but anyway:
	 * It is not possible to pass user defined variables
	 * to yyparse(). Therefore within the parser process it is
	 * no possible to get a personal context. This programm,
	 * on the other hand needs a pointer to struct ctx to store
	 * newly determined configuration. The solution is a clumsy hack
	 * to temporary save a pointer to ctx -> xctx even */
	xctx = ctx;

	/* and parse configuration file */
	ret = yyparse();
	if (ret == 1) {
		msg("parsing failed");
		return FAILURE;
	}

	/* we set ctx to NULL to detect any user that now does
	 * derefernce xctx, which can by not valid in any further
	 * release */
	ctx = NULL;

	msg("parsing finished");

	return SUCCESS;
}


#define ON 1
#define OFF 2
static int check_on_off(const char *str)
{
	if (!strcasecmp(str, "on"))
		 return ON;
	else if (!strcasecmp(str, "enable"))
		return ON;
	else if (!strcasecmp(str, "off"))
		return OFF;
	else if (!strcasecmp(str, "disable"))
		return OFF;
	else
		return -1;
}


void rc_set_port(char *port)
{
	int val;

	val = xatoi(port);
	if (val < 0 || val > 65535)
		err_msg_die(EXIT_FAILCONF, "port %d is not valid: range: 0 - 65535");

	msg("configure listening port to %s", port);

	/* per default the port is set, we
	 * must free the memory first */
	if (xctx->cli_opts.port)
		free(xctx->cli_opts.port);

	xctx->cli_opts.port = xstrdup(port);
}


void rc_set_forwarder_addr(char *forwarder)
{
	char *xforwarder;

	msg("listening address: %s", forwarder);

	xforwarder = xstrdup(forwarder);

	list_insert(xctx->cli_opts.forwarder_list, xforwarder);
}


void rc_set_select_ns_strategy(char *strategy)
{
	enum ns_select_strategy s;

	msg("nameserver select strategy: %s", strategy);

	s = ns_select_strategy_to_enum(strategy);
	if (s == UNSUPPORTED)
		err_msg_die(EXIT_FAILCONF, "nameserver strategy not supported");

	xctx->ns_select_strategy = s;
}


void rc_set_forwarder_port(char *port)
{
	if (xctx->cli_opts.forwarder_port)
		free(xctx->cli_opts.forwarder_port);

	xctx->cli_opts.forwarder_port = xstrdup(port);
}


void rc_set_verbose_level(char *level)
{
	(void) level;
	abort();
}


void rc_set_ns_time_select_threshold(char *threshold)
{
	int imax = xatoi(threshold);
	if (imax < 1)
		err_msg_die(EXIT_FAILCONF, "time select threshold option"
				" must be greater then 0");

	xctx->ns_time_select_threshold = imax;
}


void rc_set_ns_time_re_select_threshold(char *threshold)
{
	int imax = xatoi(threshold);
	if (imax < 1)
		err_msg_die(EXIT_FAILCONF, "time select re threshold option"
				" must be greater then 0");

	xctx->ns_time_select_re_threshold = imax;
}


void rc_set_edns0_size(char *size)
{
	uint16_t imax = xatoi(size);
	if (imax < 512) {
		err_msg_die(EXIT_FAILCONF, "edns option max must be greater then 512 byte");
	}

	msg("edns size: %s byte", size);

	if (imax > EDNS0_MAX) {
		err_msg_die(EXIT_FAILCONF, "edns option max is greater then %d",
				" we artificial limit this to prevent user errors",
				"If you need something higher you can send a patch and increase"
				" EDNS0_MAX", EDNS0_MAX);
	}

	xctx->cli_opts.edns0_max = imax;
}


void rc_set_edns0_mode(char *on_off)
{
	if (!strcasecmp(on_off, "off")) {
		 xctx->cli_opts.edns0_mode = 0;
		 return;
	} else if (!strcasecmp(on_off, "disable")) {
		 xctx->cli_opts.edns0_mode = 0;
		 return;
	} else if (!strcasecmp(on_off, "on")) {
		 xctx->cli_opts.edns0_mode = 1;
		 return;
	} else if (!strcasecmp(on_off, "enable")) {
		 xctx->cli_opts.edns0_mode = 1;
		 return;
	} else {
		err_msg_die(EXIT_FAILCONF, "edns0_mode options supports on, off, enable"
				" and disable but not %s", on_off);
	}
}



void rc_set_cache_backend(char *backend)
{
	if (!strcasecmp(backend, "none")) {
		 xctx->cache_backend = CACHE_BACKEND_NONE;
		 return;
	} else if (!strcasecmp(backend, "memory")) {
		 xctx->cache_backend = CACHE_BACKEND_MEMORY;
		 return;
	} else {
		err_msg_die(EXIT_FAILCONF, "cache backend \"%s\" not supported", backend);
	}
}

void rc_set_zonefile(char *zonefile)
{
	int ret;
	char *buf;

	if (strlen(zonefile) < 1)
		err_msg_die(EXIT_FAILCONF, "filename length to small");

	buf = xstrdup(zonefile);

	ret = list_insert(xctx->zone_filename_list, buf);
	if (ret != SUCCESS) {
		err_msg("Cannot add filename to list");
	}

	pr_debug("add file \"%s\" to zone file list", zonefile);
}


void rc_set_mode(char *mode)
{
	switch (check_on_off(mode)) {
	case ON:
		xctx->mode = MODE_RECURSIVE;
		break;
	case OFF:
		xctx->mode = MODE_ITERATIVE;
		break;
	default:
		err_msg_die(EXIT_FAILCONF, "recursive must set to on or off"
				", not \"%s\"", mode);
		break;
	}
}


void rc_set_allow_query(char *conf)
{
	int ret, family, n;
	unsigned int prefix_len;
	char *ptr;
	char ip_str[INET6_ADDRSTRLEN + 1];
	struct ip_prefix_storage *ipps;

	ptr = conf;

	if (!xctx->allowed_resolver_list) {
		xctx->allowed_resolver_list = list_create(ip_prefix_storage_match, free);
		if (!xctx->allowed_resolver_list)
			err_sys_die(EXIT_FAILMEM, "Failed to initialize allowed ip list");
	}

	/* split string: IPv{4,6}/prefix */
        ret = sscanf(ptr, "%16[^/]%n", ip_str, &n);
        if (ret != 1)
                err_msg_die(EXIT_FAILCONF, "malformed ip string: \"%s\"", ptr);

	family = ip_family(ip_str);
	if (family < 0)
		err_sys_die(EXIT_FAILCONF, "Not a valid ip addr");

	ptr += n;
	ptr++; /* eat slash */

	prefix_len = xatoi(ptr);
	if (!prefix_len_check(family, prefix_len)) {
		err_msg_die(EXIT_FAILCONF, "prefix length out of range: \"%d\" for allowed-query", prefix_len);
	}

	/* ok fine, sanity checks passed - allocate struct and
	 * add into allowed query list */

	ipps = xmalloc(sizeof(*ipps));
	ipps->af_family = family;
	ipps->prefix_len = prefix_len;

	switch(ipps->af_family) {
		case AF_INET:
			/* Cannot failed, ip_family() guarantees this */
			inet_pton(AF_INET, ip_str, &ipps->v4_addr);
			break;
		case AF_INET6:
			inet_pton(AF_INET6, ip_str, &ipps->v6_addr);
			break;
		default:
			err_msg_die(EXIT_FAILINT, "programmed error - unknown value");
	}

	ret = list_insert(xctx->allowed_resolver_list, ipps);
	if (ret != SUCCESS) {
		err_msg("IP address/prefixlength duplicate for allowed query, skipping entry");
		free(ipps);
	}

}


void rc_set_allow_update(char *conf)
{
	int ret, family, n;
	unsigned int prefix_len;
	char *ptr;
	char ip_str[INET6_ADDRSTRLEN + 1];
	struct ip_prefix_storage *ipps;

	ptr = conf;

	if (!xctx->allow_update_list) {
		xctx->allow_update_list = list_create(ip_prefix_storage_match, free);
		if (!xctx->allow_update_list)
			err_sys_die(EXIT_FAILMEM, "Failed to initialize allow update list");
	}

	/* split string: IPv{4,6}/prefix */
        ret = sscanf(ptr, "%16[^/]%n", ip_str, &n);
        if (ret != 1)
                err_msg_die(EXIT_FAILCONF, "malformed ip string: \"%s\"", ptr);

	family = ip_family(ip_str);
	if (family < 0)
		err_sys_die(EXIT_FAILCONF, "Not a valid ip addr");

	ptr += n;
	ptr++; /* eat slash */

	prefix_len = xatoi(ptr);
	if (!prefix_len_check(family, prefix_len)) {
		err_msg_die(EXIT_FAILCONF, "prefix length out of range: \"%d\" for allow-update", prefix_len);
	}

	/* ok fine, sanity checks passed - allocate struct and
	 * add into allowed query list */

	ipps = xmalloc(sizeof(*ipps));
	ipps->af_family = family;
	ipps->prefix_len = prefix_len;

	switch(ipps->af_family) {
		case AF_INET:
			/* Cannot failed, ip_family() guarantees this */
			inet_pton(AF_INET, ip_str, &ipps->v4_addr);
			break;
		case AF_INET6:
			inet_pton(AF_INET6, ip_str, &ipps->v6_addr);
			break;
		default:
			err_msg_die(EXIT_FAILINT, "programmed error - unknown value");
	}

	ret = list_insert(xctx->allow_update_list, ipps);
	if (ret != SUCCESS) {
		err_msg("IP address/prefixlength duplicate for allowed query, skipping entry");
		free(ipps);
	}

}
