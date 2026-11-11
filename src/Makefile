obj-m += xt_udp_tls.o
xt_udp_tls-objs := xt_udp_tls_main.o hostset_udp_tls.o utils_udp_tls.o crypto.o quic_parser.o firewalla_memory.o aes_nohw.o quic_conversation.o quic_cache.o

KERNELRELEASE ?= $(shell uname -r)
KERNELDIR ?= /lib/modules/$(KERNELRELEASE)/build
PREFIX ?= /usr
DESTDIR ?=
SRCDIR ?= $(PREFIX)/src
DKMSDIR ?= $(SRCDIR)/xt_udp_tls
DEPMOD ?= depmod
DEPMODBASEDIR ?= /

PWD := $(shell pwd)

# crystal-kernel (7.0.x) build workarounds. Override with `make KBUILD_EXTRA=`
# to build normally on other kernels.
#   KCFLAGS=-g0                          -> avoid ld .debug_info bad-reloc link failure
#   CONFIG_DEBUG_INFO_BTF_MODULES= (empty) -> skip BTF generation (no pahole needed)
KBUILD_EXTRA ?= KCFLAGS="-g0" CONFIG_DEBUG_INFO_BTF_MODULES=

all: prepare
	$(MAKE) -C $(KERNELDIR) M=$(PWD) $(KBUILD_EXTRA) modules
	rm -rf hostset_udp_tls.c utils_udp_tls.c


debug: module-debug

prepare:
	cp  hostset.c hostset_udp_tls.c
	cp  utils.c utils_udp_tls.c

module:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) $(KBUILD_EXTRA) modules

module-debug: prepare
	$(MAKE) -C $(KERNELDIR) M=$(PWD) $(KBUILD_EXTRA) CFLAGS_MODULE="-DXT_TLS_DEBUG -DDEBUG" modules
	rm -rf hostset_udp_tls.c utils_udp_tls.c


clean:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) clean
	rm -rf hostset_udp_tls.c utils_udp_tls.c


module-install:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules_install
	$(DEPMOD) -b "$(DEPMODBASEDIR)" -a $(KERNELRELEASE)

install: module-install

reload: all
	(lsmod | grep -w xt_udp_tls && sudo rmmod xt_udp_tls) || true
	sudo insmod xt_udp_tls.ko
