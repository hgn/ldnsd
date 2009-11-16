EPOLL :=1 

DEBUG_BUILD := testing

OBJ := ev.o cachefor.o
SRC := ev.c cachefor.c
TARGET := cachefor

LIBS   := -lrt  # for clock_gettime(2)
CFLAGS := -Wall -Wextra -pipe -Wwrite-strings -Wsign-compare \
				 -Wshadow -Wformat=2 -Wundef -Wstrict-prototypes   \
				 -fno-strict-aliasing -fno-common -Wformat-security \
				 -Wformat-y2k -Winit-self -Wpacked -Wredundant-decls \
				 -Wstrict-aliasing=3 -Wswitch-default -Wswitch-enum \
				 -Wno-system-headers -Wundef -Wvolatile-register-var \
				 -Wcast-align -Wbad-function-cast -Wwrite-strings \
				 -Wold-style-definition  -Wdeclaration-after-statement

CFLAGS += -ggdb3 # -Werror

ifdef EPOLL
				EXTRA_CFLAGS := -DHAVE_EPOLL
endif

ifdef DEBUG_BUILD
				EXTRA_CFLAGS += -DDEBUG
endif

all: $(TARGET)

%.o : %.c
	$(CC) -c $(CFLAGS) $(EXTRA_CFLAGS) $(CPPFLAGS) $< -o $@

cachefor: $(OBJ)
	$(CC) $(CFLAGS) $(EXTRA_CFLAGS) $(LIBS) -o $(TARGET) $(OBJ)

clean:
	-rm -f $(OBJ) $(TARGET)
