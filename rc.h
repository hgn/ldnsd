#ifndef RC_H
#define	RC_H

#include "ldnsd.h"

int parse_rc_file(struct ctx *);

void rc_set_port(char *);
void rc_set_verbose_level(char *);
void rc_set_forwarder_addr(char *);
void rc_set_forwarder_port(char *);

#endif /* RC_H */

/* vim:set ts=4 sw=4 sts=4 tw=78 ff=unix noet: */
