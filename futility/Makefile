# Copyright (c) 2013 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

INCLUDES += -I./include \
		-I$(FWDIR)/lib/include \
		-I$(FWDIR)/lib/cgptlib/include \
		-I$(FWDIR)/lib/cryptolib/include \
		-I$(FWDIR)/lib/tpm_lite/include \
		-I$(HOSTDIR)/include
CFLAGS += $(INCLUDES)
CFLAGS += -MMD -MF $@.d
LIBS = $(HOSTLIB)
HOSTCC = cc
CRYPTO_LIBS := $(shell $(PKG_CONFIG) --libs libcrypto)

BUILD_ROOT = ${BUILD}/futility

DESTDIR ?= /usr/bin

LDFLAGS += -static

TARGET_NAMES = futility

TARGET_BINS = $(addprefix ${BUILD_ROOT}/,$(TARGET_NAMES))
ALL_DEPS = $(addsuffix .d,${TARGET_BINS})

all: $(TARGET_BINS)

${BUILD_ROOT}/futility: futility.c $(LIBS)
	$(CC) $(CFLAGS) $(LDFLAGS) $< -o $@ $(LIBS)

install: $(TARGET_BINS)
	mkdir -p $(DESTDIR)
	cp -f $(TARGET_BINS) $(DESTDIR)
	chmod a+rx $(patsubst %,$(DESTDIR)/%,$(TARGET_NAMES))

-include ${ALL_DEPS}
