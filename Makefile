EPOLL :=1 

EXTRA_WARNINGS := -Wformat
EXTRA_WARNINGS := $(EXTRA_WARNINGS) -Wall
EXTRA_WARNINGS := $(EXTRA_WARNINGS) -Wextra
EXTRA_WARNINGS := $(EXTRA_WARNINGS) -Wformat-security
EXTRA_WARNINGS := $(EXTRA_WARNINGS) -Wformat-y2k
EXTRA_WARNINGS := $(EXTRA_WARNINGS) -Wshadow
EXTRA_WARNINGS := $(EXTRA_WARNINGS) -Winit-self
EXTRA_WARNINGS := $(EXTRA_WARNINGS) -Wpacked
EXTRA_WARNINGS := $(EXTRA_WARNINGS) -Wredundant-decls
EXTRA_WARNINGS := $(EXTRA_WARNINGS) -Wstack-protector
EXTRA_WARNINGS := $(EXTRA_WARNINGS) -Wstrict-aliasing=3
EXTRA_WARNINGS := $(EXTRA_WARNINGS) -Wswitch-default
EXTRA_WARNINGS := $(EXTRA_WARNINGS) -Wswitch-enum
EXTRA_WARNINGS := $(EXTRA_WARNINGS) -Wno-system-headers
EXTRA_WARNINGS := $(EXTRA_WARNINGS) -Wundef
EXTRA_WARNINGS := $(EXTRA_WARNINGS) -Wvolatile-register-var
EXTRA_WARNINGS := $(EXTRA_WARNINGS) -Wwrite-strings
EXTRA_WARNINGS := $(EXTRA_WARNINGS) -Wbad-function-cast
EXTRA_WARNINGS := $(EXTRA_WARNINGS) -Wmissing-declarations
EXTRA_WARNINGS := $(EXTRA_WARNINGS) -Wmissing-prototypes
EXTRA_WARNINGS := $(EXTRA_WARNINGS) -Wnested-externs
EXTRA_WARNINGS := $(EXTRA_WARNINGS) -Wold-style-definition
EXTRA_WARNINGS := $(EXTRA_WARNINGS) -Wstrict-prototypes
EXTRA_WARNINGS := $(EXTRA_WARNINGS) -Wdeclaration-after-statement

ifeq ("$(origin DEBUG)", "command line")
  PERF_DEBUG = $(DEBUG)
endif
ifndef PERF_DEBUG
  CFLAGS_OPTIMIZE = -O6
endif

EXTRA_CFLAGS := -DDEBUG


ifdef EPOLL
				EXTRA_CFLAGS += -DHAVE_EPOLL
endif

CFLAGS = -ggdb3 -Wall -Wextra -std=gnu99 $(CFLAGS_OPTIMIZE) -D_FORTIFY_SOURCE=2 $(EXTRA_WARNINGS) $(EXTRA_CFLAGS)
EXTLIBS = -lrt
ALL_CFLAGS = $(CFLAGS)
ALL_LDFLAGS = $(LDFLAGS)

ifeq ($(shell sh -c "echo 'int foo(void) {char X[2]; return 3;}' | $(CC) -x c -c -Werror -fstack-protector-all - -o /dev/null "$(QUIET_STDERR)" && echo y"), y)
  CFLAGS := $(CFLAGS) -fstack-protector-all
endif

OBJ := ev.o \
			 cachefor.o \
			 clist.o \
			 utils.o \
			 nameserver.o \
			 back-end.o \
			 front-end.o \
			 hosts.o \
			 pkt-parser.o

TARGET := cachefor


.SUFFIXES:
.SUFFIXES: .c .o

all: $(TARGET)

%.o : %.c cachefor.h hosts.h
	$(CC) -c $(CFLAGS) $(CPPFLAGS) $< -o $@

cachefor: $(OBJ)
	$(CC) $(CFLAGS) $(EXTLIBS) -o $(TARGET) $(OBJ)

clean:
	-rm -f $(OBJ) $(TARGET)

cscope:
	rm -f cscope*
	find . -name '*.[hcS]' -print0 | xargs -0 cscope -b

