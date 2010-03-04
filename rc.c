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
	 * on the other hand needs a pointer to struct ospfd to store
	 * newly determined configuration. The solution is a clumsy hack
	 * to temporary save a pointer to ospfd -> xospfd even */
	xctx = ctx;

	/* and parse configuration file */
	ret = yyparse();
	if (ret == 1)
		return FAILURE;

	/* we set ospfd to NULL to detect any user that now does
	 * derefernce xospfd, which can by not valid in any further
	 * release */
	ctx = NULL;

	return SUCCESS;
}


void rc_set_port(char *port)
{
	int val;

	val = xatoi(port);
	if (val < 0 || val > 65535)
		err_msg_die(EXIT_FAILCONF, "port %d is not valid: range: 0 - 65535");

	/* per default the port is set, we
	 * must free the memory first */
	if (xctx->cli_opts.port)
		free(xctx->cli_opts.port);

	xctx->cli_opts.port = xstrdup(port);
}

void rc_set_forwarder_addr(char *forwarder)
{
	/* per default the forwarder is set, we
	 * must free the memory first */
	if (xctx->cli_opts.forwarder_addr)
		free(xctx->cli_opts.forwarder_addr);

	xctx->cli_opts.forwarder_addr = xstrdup(forwarder);
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

/* vim: set tw=78 ts=4 sw=4 sts=4 ff=unix noet: */
