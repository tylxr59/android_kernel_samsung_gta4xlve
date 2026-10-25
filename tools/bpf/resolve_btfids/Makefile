# SPDX-License-Identifier: GPL-2.0-only
# Host-only tool. Supply the manifest-pinned Android external/libbpf checkout.
.DEFAULT_GOAL := all
srctree ?= $(abspath ../../..)
OUTPUT ?= $(CURDIR)/
OUTPUT := $(abspath $(OUTPUT))/
LIBBPF_SRC ?= $(abspath $(srctree)/../../../external/libbpf)
HOSTCC ?= cc
ifneq ($(LLVM),)
HOSTAR ?= llvm-ar
HOSTLD ?= ld.lld
TOOL_LDFLAGS := -fuse-ld=lld
else
HOSTAR ?= ar
HOSTLD ?= ld
endif
LIBBPF := $(OUTPUT)libbpf/libbpf.a
LIBSUBCMD := $(OUTPUT)libsubcmd/libsubcmd.a
INCLUDES := -I$(srctree)/tools/include -I$(srctree)/tools/lib/subcmd \
 -I$(LIBBPF_SRC)/src -I$(LIBBPF_SRC)/include/uapi

.PHONY: all FORCE
all: $(OUTPUT)resolve_btfids

$(LIBBPF): FORCE
	@test -f $(LIBBPF_SRC)/src/btf.h || { echo 'Set LIBBPF_SRC to the pinned Android external/libbpf checkout'; exit 1; }
	@mkdir -p $(OUTPUT)libbpf
	$(MAKE) -C $(LIBBPF_SRC)/src OBJDIR=$(OUTPUT)libbpf BUILD_STATIC_ONLY=1 NO_PKG_CONFIG=1 \
	 CC=$(HOSTCC) AR=$(HOSTAR) LD=$(HOSTLD) CROSS_COMPILE= CFLAGS='-O2 -g' \
	 LDFLAGS= EXTRA_CFLAGS= EXTRA_LDFLAGS= $(LIBBPF)

$(LIBSUBCMD): FORCE
	@mkdir -p $(OUTPUT)libsubcmd
	$(MAKE) -C $(srctree)/tools/lib/subcmd srctree=$(srctree) OUTPUT=$(OUTPUT)libsubcmd/ \
	 CC=$(HOSTCC) AR=$(HOSTAR) LD=$(HOSTLD) CROSS_COMPILE= WERROR=0 LDFLAGS= \
	 EXTRA_CFLAGS= $(LIBSUBCMD)

$(OUTPUT)resolve_btfids: $(CURDIR)/main.c $(LIBBPF) $(LIBSUBCMD)
	$(HOSTCC) -O2 -g $(INCLUDES) $(CURDIR)/main.c \
	 $(srctree)/tools/lib/rbtree.c $(srctree)/tools/lib/str_error_r.c \
	 $(LIBSUBCMD) $(LIBBPF) $(TOOL_LDFLAGS) -lelf -lz -o $@
