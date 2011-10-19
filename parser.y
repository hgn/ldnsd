/* declarations */
%{
#include <stdio.h>
#include <string.h>

#include "rc.h"

void yyerror(const char *);
int yywrap(void);

int yywrap(void)
{
        return 1;
}

%}


%{
int yylex(void);
%}

%union {
    char *word;
}

%token PORT EDNS0MODE EDNS0SIZE

%token <word>  WORD VERBOSELEVEL FORWARDERADDR FORWARDERPORT
%token <word>  FORWARDERS
%token <word>  BRACEON
%token <word>  BRACEOFF
%token <word>  FORWARDERSSELECTSTRATEGY
%token <word>  FORWARDERSTIMESELECTTHRESHOLD
%token <word>  FORWARDERSTIMERESELECTTHRESHOLD
%token <word>  CACHEBACKEND
%token <word>  ZONEFILE
%token <word>  RECURSION

/* rules */
%%


commands:
    |        commands command
    ;


command:     PORT WORD    { rc_set_port($2); }
		|        VERBOSELEVEL WORD  { rc_set_verbose_level($2); }
		|        EDNS0MODE WORD  { rc_set_edns0_mode($2); }
		|        EDNS0SIZE WORD  { rc_set_edns0_size($2); }
		|        FORWARDERADDR WORD  { rc_set_forwarder_addr($2); }
		|        FORWARDERPORT WORD  { rc_set_forwarder_port($2); }
		|        FORWARDERSSELECTSTRATEGY WORD  { rc_set_select_ns_strategy($2); }
		|        FORWARDERSTIMESELECTTHRESHOLD WORD  { rc_set_ns_time_select_threshold($2); }
		|        FORWARDERSTIMERESELECTTHRESHOLD WORD  { rc_set_ns_time_re_select_threshold($2); }
		|        CACHEBACKEND WORD  { rc_set_cache_backend($2); }
		|        RECURSION WORD  { rc_set_mode($2); }
		|        ZONEFILE WORD  { rc_set_zonefile($2); }
		|        FORWARDERS BRACEON forwarderlist BRACEOFF
    ;

forwarderlist:
		 | forwarderlist WORD { rc_set_forwarder_addr($2); }



