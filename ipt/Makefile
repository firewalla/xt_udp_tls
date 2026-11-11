CFLAGS = -I../src -fPIC
DESTDIR ?= /
XTABLES_LIB=$(shell pkg-config --variable=xtlibdir xtables)
ifeq ($(origin CROSS_COMPILE), environment)
    CC = $(CROSS_COMPILE)gcc
endif

LIB_UDP_TLS = libxt_udp_tls.so

UTILS_SRC = libxt_utils.c

UDP_TLS_SRC = libxt_udp_tls.c

all: $(LIB_UDP_TLS)

$(LIB_UDP_TLS): libxt_udp_tls.o libxt_utils.o
	$(CC) -shared -o $@ $^;

lib%.o: %lib%.c
	$(CC) ${CFLAGS} -D_INIT=lib$*_init -c -o $@ $<;
clean:
	rm -rf libxt_udp_tls.so *.o
install:
	install -D -v -m 644 libxt_udp_tls.so $(DESTDIR)$(XTABLES_LIB)
uninstall:
	rm $(DESTDIR)$(XTABLES_LIB)/libxt_udp_tls.so
