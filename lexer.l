%{
/* definition section */
#include <stdio.h>
#include <stdlib.h>
#include "parser.tab.h"
#include "ldnsd.h"

#define MAXLEXERR 1024

/* error stuff */
char lexerrbuff[MAXLEXERR];
int lineno = 1;
void yyerror(char *s);


%}

%%

#.*                              ;
port                             { return PORT; }
verboselevel                     { return VERBOSELEVEL; }
forwarderaddr                    { return FORWARDERADDR; }
forwarderport                    { return FORWARDERPORT; }
edns0-mode                       { return EDNS0MODE; }
edns0-size                       { return EDNS0SIZE; }
forwarders                       { return FORWARDERS; }
forwarders-select-strategy       { return FORWARDERSSELECTSTRATEGY; }
forwarders-time-select-threshold { return FORWARDERSTIMESELECTTHRESHOLD; }
forwarders-time-re-select-threshold { return FORWARDERSTIMERESELECTTHRESHOLD; }
cache-backend                    { return CACHEBACKEND; }
zonefile                         { return ZONEFILE; }
recursion                        { return RECURSION; }
allow-query                      { return ALLOWQUERY; }
allow-update                     { return ALLOWUPDATE; }
\{                               { return BRACEON; }
\}                               { return BRACEOFF; }
[a-zA-Z0-9./:][a-zA-Z0-9_./:]*   { yylval.word = strdup(yytext); return WORD; }
\n.*                             { strncpy(lexerrbuff, yytext + 1, MAXLEXERR - 1);
                                   lineno++;
                                   yyless(1);
                                 }
[ \t]+                           ;                   /* ignone whitespaces */ 
.                                ;                   /* FIXME: add a catch all rule */  

%%


void
yyerror(char *str)
{
	fprintf(stderr, "Failed to parse configuration file (line %d):%s (%s)\n",
                          lineno, str, lexerrbuff);
}
