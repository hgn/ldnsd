#ifndef RC_H
#define	RC_H

#include "ldnsd.h"

int parse_rc_file(struct ctx *);

void rc_set_port(char *);
void rc_set_verbose_level(char *);
void rc_set_forwarder_addr(char *);
void rc_set_forwarder_port(char *);
void rc_set_edns0_size(char *);
void rc_set_edns0_mode(char *);
void rc_set_select_ns_strategy(char *);

#endif /* RC_H */
