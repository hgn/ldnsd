/* declarations */
%{
#include <stdio.h>
#include <string.h>

#include "rc.h"

void yyerror(const char *);

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

/* rules */
%%


commands:
    |        commands command
    ;


command:     PORT WORD    { rc_set_port($2); }
		|        VERBOSELEVEL WORD  { rc_set_verbose_level($2); }
		|        FORWARDERADDR WORD  { rc_set_forwarder_addr($2); }
		|        FORWARDERPORT WORD  { rc_set_forwarder_port($2); }
		|        EDNS0MODE WORD  { rc_set_edns0_mode($2); }
		|        EDNS0SIZE WORD  { rc_set_edns0_size($2); }
    ;

