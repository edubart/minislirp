CC=gcc
AR=ar rcs
CFLAGS=-O2 -fPIC
DEFS=-DBUILDING_LIBSLIRP
DESTDIR=
PREFIX=/usr/local
INSTALL_FILE=install -m0644
MKDIR=mkdir -p
INSTALL_INC_PATH=$(DESTDIR)$(PREFIX)/include/slirp
INSTALL_LIB_PATH=$(DESTDIR)$(PREFIX)/lib
SRCS=$(wildcard *.c)
OBJS=$(patsubst %.c,%.o,$(SRCS))

all: libslirp.a

libslirp.a: $(OBJS)
	$(AR) $@ $^

%.o: %.c
	$(CC) -o $@ -c $< $(DEFS) $(CFLAGS) $(MYCFLAGS)

install: libslirp.a
	$(MKDIR) $(INSTALL_LIB_PATH)
	$(INSTALL_FILE) libslirp.a $(INSTALL_LIB_PATH)/
	$(MKDIR) $(INSTALL_INC_PATH)
	$(INSTALL_FILE) libslirp.h libslirp-version.h $(INSTALL_INC_PATH)/

clean:
	rm -f *.o *.a
