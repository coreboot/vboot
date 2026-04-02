# Copyright 2026 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# Host library(s)
HOSTLIB = ${BUILD}/libvboot_host.so
HOSTLIB_STATIC = ${BUILD}/libvboot_host.a

# Intermediate library for the vboot_reference utilities to link against.
UTILLIB = ${BUILD}/libvboot_util.a

# For testing purposes files containing some libvboot_host symbols.
HOSTLIB_DEF = ${BUILD}/tests/libvboot_host_def.txt
HOSTLIB_UNDEF = ${BUILD}/tests/libvboot_host_undef.txt

# Maintain behaviour of default on.
USE_FLASHROM ?= 1

ifneq ($(filter-out 0,${USE_FLASHROM}),)
$(info building with libflashrom support)
export VBOOT_TEST_USE_FLASHROM = 1
FLASHROM_LIBS := $(shell ${PKG_CONFIG} --libs flashrom)
COMMONLIB_SRCS += host/lib/flashrom_drv.c
CFLAGS += -DUSE_FLASHROM=1
${HOSTLIB}: LDLIBS += ${FLASHROM_LIBS}
else
COMMONLIB_SRCS += host/lib/flashrom.c
endif

COMMONLIB_SRCS += \
	host/lib/subprocess.c \
	host/lib/cbfstool.c

UTILLIB_SRCS = \
	cgpt/cgpt_add.c \
	cgpt/cgpt_boot.c \
	cgpt/cgpt_common.c \
	cgpt/cgpt_create.c \
	cgpt/cgpt_edit.c \
	cgpt/cgpt_prioritize.c \
	cgpt/cgpt_repair.c \
	cgpt/cgpt_show.c \
	futility/dump_kernel_config_lib.c \
	host/arch/${ARCH_DIR}/lib/crossystem_arch.c \
	host/lib/chromeos_config.c \
	host/lib/crossystem.c \
	host/lib/crypto.c \
	host/lib/file_keys.c \
	$(COMMONLIB_SRCS) \
	host/lib/fmap.c \
	host/lib/gpio_uapi.c \
	host/lib/host_common.c \
	host/lib/host_key2.c \
	host/lib/host_keyblock.c \
	host/lib/host_misc.c \
	host/lib/host_signature.c \
	host/lib/host_signature2.c \
	host/lib/signature_digest.c \
	host/lib/util_misc.c \
	host/lib21/host_common.c \
	host/lib21/host_key.c \
	host/lib21/host_misc.c \
	host/lib21/host_signature.c

ifneq ($(filter-out 0,${HAVE_NSS}),)
UTILLIB_SRCS += \
	host/lib/host_p11.c
else
UTILLIB_SRCS += \
	host/lib/host_p11_stub.c
endif

HOSTLIB_SRCS = \
	cgpt/cgpt_add.c \
	cgpt/cgpt_boot.c \
	cgpt/cgpt_common.c \
	cgpt/cgpt_create.c \
	cgpt/cgpt_edit.c \
	cgpt/cgpt_find.c \
	cgpt/cgpt_prioritize.c \
	cgpt/cgpt_repair.c \
	cgpt/cgpt_show.c \
	firmware/2lib/2common.c \
	firmware/2lib/2context.c \
	firmware/2lib/2crc8.c \
	firmware/2lib/2crypto.c \
	firmware/2lib/2hmac.c \
	firmware/2lib/2nvstorage.c \
	firmware/2lib/2recovery_reasons.c \
	firmware/2lib/2rsa.c \
	firmware/2lib/2sha1.c \
	firmware/2lib/2sha256.c \
	firmware/2lib/2sha512.c \
	firmware/2lib/2sha_utility.c \
	firmware/2lib/2struct.c \
	firmware/2lib/2stub.c \
	firmware/2lib/2stub_hwcrypto.c \
	firmware/lib/cgptlib/cgptlib_internal.c \
	firmware/lib/cgptlib/crc32.c \
	firmware/lib/gpt_misc.c \
	firmware/stub/tpm_lite_stub.c \
	firmware/stub/vboot_api_stub_disk.c \
	futility/dump_kernel_config_lib.c \
	host/arch/${ARCH_DIR}/lib/crossystem_arch.c \
	host/lib/chromeos_config.c \
	host/lib/crossystem.c \
	host/lib/crypto.c \
	host/lib/extract_vmlinuz.c \
	$(COMMONLIB_SRCS) \
	host/lib/fmap.c \
	host/lib/gpio_uapi.c \
	host/lib/host_misc.c \
	host/lib21/host_misc.c \
	${TLCL_SRCS}

UTILLIB_OBJS = ${UTILLIB_SRCS:%.c=${BUILD}/%.o}
HOSTLIB_OBJS = ${HOSTLIB_SRCS:%.c=${BUILD}/%.o}

ALL_OBJS += ${UTILLIB_OBJS} ${HOSTLIB_OBJS}

# Host library rules
${UTILLIB}: ${UTILLIB_OBJS} ${FWLIB_OBJS} ${TLCL_OBJS}
	@${PRINTF} "    RM            $(subst ${BUILD}/,,$@)\n"
	${Q}rm -f $@
	@${PRINTF} "    AR            $(subst ${BUILD}/,,$@)\n"
	${Q}ar qcT $@ $^

.PHONY: utillib
utillib: ${UTILLIB}

${HOSTLIB_STATIC}: ${HOSTLIB_OBJS}
	@${PRINTF} "    RM            $(subst ${BUILD}/,,$@)\n"
	${Q}rm -f $@
	@${PRINTF} "    AR            $(subst ${BUILD}/,,$@)\n"
	${Q}ar qcT $@ $^

${HOSTLIB}: ${HOSTLIB_OBJS}
	@${PRINTF} "    RM            $(subst ${BUILD}/,,$@)\n"
	${Q}rm -f $@
	@${PRINTF} "    LD            $(subst ${BUILD}/,,$@)\n"
	${Q}${LD} ${LDFLAGS} ${LDLIBS} -shared -Wl,-soname,$(subst ${BUILD}/,,$@) $^ -o $@

.PHONY: hostlib
hostlib: ${HOSTLIB} ${HOSTLIB_STATIC}

${HOSTLIB_DEF}: ${HOSTLIB_STATIC}
	@${PRINTF} "    NMd           $(subst ${BUILD}/,,$@)\n"
	${Q}mkdir -p $(dir $@)
	${Q}nm --defined-only --format=just-symbols $^ > $@

${HOSTLIB_UNDEF}: ${HOSTLIB_STATIC}
	@${PRINTF} "    NMu           $(subst ${BUILD}/,,$@)\n"
	${Q}mkdir -p $(dir $@)
	${Q}nm --undefined-only --format=just-symbols $^ > $@

.PHONY: headers_install
headers_install:
	@${PRINTF} "    INSTALL       HEADERS\n"
	${Q}mkdir -p ${UI_DIR}
	${Q}${INSTALL} -t ${UI_DIR} -m644 \
		host/include/* \
		firmware/2lib/include/2crypto.h \
		firmware/2lib/include/2recovery_reasons.h \
		firmware/2lib/include/2sysincludes.h \
		firmware/include/gpt.h \
		firmware/include/tlcl.h \
		firmware/include/tss_constants.h \
		firmware/include/tpm1_tss_constants.h \
		firmware/include/tpm2_tss_constants.h

.PHONY: lib_install
lib_install: ${HOSTLIB} ${HOSTLIB_STATIC}
	@${PRINTF} "    INSTALL       HOSTLIB\n"
	${Q}mkdir -p ${UL_DIR}
	${Q}${INSTALL} -t ${UL_DIR} -m 644 $^

