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

	msg("parse configuration file");

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


void rc_set_port(char *port)
{
	int val;

	val = xatoi(port);
	if (val < 0 || val > 65535)
		err_msg_die(EXIT_FAILCONF, "port %d is not valid: range: 0 - 65535");

	msg("listening port to %s", port);

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

/* vim: set tw=78 ts=4 sw=4 sts=4 ff=unix noet: */
