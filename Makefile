EPOLL :=1 

CC ?= gcc
AR ?= ar
RM ?= rm -f
TAR ?= tar
FIND ?= find
INSTALL ?= install

EXTRA_WARNINGS += -Wbad-function-cast
EXTRA_WARNINGS += -Wcast-align
EXTRA_WARNINGS += -Wdeclaration-after-statement
EXTRA_WARNINGS += -Wformat
EXTRA_WARNINGS += -Wformat-security
EXTRA_WARNINGS += -Wformat-y2k
EXTRA_WARNINGS += -Wformat=2
EXTRA_WARNINGS += -Winit-self
EXTRA_WARNINGS += -Wmissing-declarations
EXTRA_WARNINGS += -Wmissing-prototypes
EXTRA_WARNINGS += -Wnested-externs
EXTRA_WARNINGS += -Wnested-externs
EXTRA_WARNINGS += -Wno-system-headers
EXTRA_WARNINGS += -Wold-style-definition
EXTRA_WARNINGS += -Wpacked
EXTRA_WARNINGS += -Wredundant-decls
EXTRA_WARNINGS += -Wshadow
EXTRA_WARNINGS += -Wsign-compare
EXTRA_WARNINGS += -Wstack-protector
EXTRA_WARNINGS += -Wstrict-aliasing=3
EXTRA_WARNINGS += -Wstrict-prototypes
EXTRA_WARNINGS += -Wswitch-default
EXTRA_WARNINGS += -Wswitch-enum
EXTRA_WARNINGS += -Wundef
EXTRA_WARNINGS += -Wunused-result
EXTRA_WARNINGS += -Wvolatile-register-var
EXTRA_WARNINGS += -Wwrite-strings

ifeq ("$(origin DEBUG)", "command line")
  LDNSD_DEBUG = $(DEBUG)
endif
ifndef LDNSD_DEBUG
  CFLAGS_OPTIMIZE = -O6
else
	CFLAGS_OPTIMIZE = -O0
endif

EXTRA_CFLAGS := -D_GNU_SOURCE
EXTRA_CFLAGS += -DDEBUG

# enable via "make MUDFLAP=1 all"
ifeq ("$(origin MUDFLAP)", "command line")
	EXTRA_CFLAGS += -fmudflap -lmudflap
endif

OBJ := ev.o \
			 ldnsd.o \
			 clist.o \
			 utils.o \
			 nameserver.o \
			 back-end.o \
			 front-end.o \
			 hosts.o \
			 pkt-parser.o \
			 parser.tab.o \
			 lex.yy.o     \
			 rc.o         \
			 cli-opts.o   \
			 type.o \
			 type-041-opt.o \
			 type-999-generic.o \
			 cache.o \
			 cache-memory.o \
			 zone-parser.o  \
			 type-001-a.o \
			 type-015-mx.o \
			 type-028-aaaa.o \
			 pkt-generator.o

ifeq ("$(origin TCPSTATISTIC)", "command line")
	OBJ += tcp-statistic.o
	EXTRA_CFLAGS += -DTCP_STATISTIC
endif


ifdef EPOLL
				EXTRA_CFLAGS += -DHAVE_EPOLL
endif

CFLAGS += -ggdb3 -Wall -Wextra -std=gnu99 $(CFLAGS_OPTIMIZE) -D_FORTIFY_SOURCE=2 $(EXTRA_WARNINGS) $(EXTRA_CFLAGS)
EXTLIBS = -lrt
ALL_CFLAGS = $(CFLAGS)
ALL_LDFLAGS = $(LDFLAGS)

ifeq ($(shell sh -c "echo 'int foo(void) {char X[2]; return 3;}' | $(CC) -x c -c -Werror -fstack-protector-all - -o /dev/null "$(QUIET_STDERR)" && echo y"), y)
  CFLAGS := $(CFLAGS) -fstack-protector-all
endif

TARGET := ldnsd


.SUFFIXES:
.SUFFIXES: .c .o

all: $(TARGET) ldnsd-ctrl

lex.yy.c: lexer.l
	flex --nounistd lexer.l

parser.tab.c: parser.y
	bison -d parser.y

lex.yy.o: lex.yy.c
	$(CC) -ggdb3 -std=gnu99 $(CFLAGS_OPTIMIZE) -c $< -o $@

parser.tab.o: parser.tab.c
	$(CC) -ggdb3 -std=gnu99 $(CFLAGS_OPTIMIZE) -c $< -o $@

%.o : %.c ldnsd.h hosts.h
	$(CC) -c $(CFLAGS) $(CPPFLAGS) $< -o $@

$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) $(EXTLIBS) -o $(TARGET) $(OBJ)

ldnsd-ctrl: ldnsd-ctrl.c tcp-statistic.h
	$(CC) $(CFLAGS) $(EXTLIBS) -o ldnsd-ctrl ldnsd-ctrl.c

clean:
	$(RM) -f $(OBJ) $(TARGET) core vgcore.* lex.yy.c parser.tab.h parser.tab.c *~

distclean: clean
	$(RM) -f cscope* tags

cscope:
	$(RM) -f cscope*
	$(FIND) . -name '*.[hcS]' -print0 | xargs -0 cscope -b

tags:
	$(RM) tags
	$(FIND) . -name '*.[hcS]' -print | xargs ctags -a

checkstyle:
	 /usr/src/linux/scripts/checkpatch.pl --file --terse $(shell ls *.c)

stackusage:
	objdump -d $(TARGET) | perl /usr/src/linux/scripts/checkstack.pl
