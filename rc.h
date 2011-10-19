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
void rc_set_ns_time_select_threshold(char *);
void rc_set_ns_time_re_select_threshold(char *);
void rc_set_cache_backend(char *);
void rc_set_zonefile(char *);
void rc_set_mode(char *);

#endif /* RC_H */
