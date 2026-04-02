# Copyright 2026 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# Firmware library
FWLIB = ${BUILD}/vboot_fw.a

# Separate TPM lightweight command library (TLCL)
TLCL = ${BUILD}/tlcl.a

FWLIB_SRCS = \
	firmware/2lib/2api.c \
	firmware/2lib/2auxfw_sync.c \
	firmware/2lib/2common.c \
	firmware/2lib/2context.c \
	firmware/2lib/2crc8.c \
	firmware/2lib/2crypto.c \
	firmware/2lib/2ec_sync.c \
	firmware/2lib/2firmware.c \
	firmware/2lib/2gbb.c \
	firmware/2lib/2hmac.c \
	firmware/2lib/2kernel.c \
	firmware/2lib/2load_kernel.c \
	firmware/2lib/2misc.c \
	firmware/2lib/2nvstorage.c \
	firmware/2lib/2packed_key.c \
	firmware/2lib/2recovery_reasons.c \
	firmware/2lib/2rsa.c \
	firmware/2lib/2secdata_firmware.c \
	firmware/2lib/2secdata_fwmp.c \
	firmware/2lib/2secdata_kernel.c \
	firmware/2lib/2sha1.c \
	firmware/2lib/2sha256.c \
	firmware/2lib/2sha512.c \
	firmware/2lib/2sha_utility.c \
	firmware/2lib/2struct.c \
	firmware/2lib/2stub_hwcrypto.c \
	firmware/2lib/2tpm_bootmode.c \
	firmware/lib/cgptlib/cgptlib.c \
	firmware/lib/cgptlib/cgptlib_internal.c \
	firmware/lib/cgptlib/crc32.c \
	firmware/lib/gpt_misc.c \
	firmware/lib20/api_kernel.c

# TPM lightweight command library
ifeq ($(filter-out 0,${TPM2_MODE}),)
TLCL_SRCS = \
	firmware/lib/tpm_lite/tlcl.c
else
TLCL_SRCS = \
	firmware/lib/tpm2_lite/tlcl.c \
	firmware/lib/tpm2_lite/marshaling.c
endif

# Support real TPM unless MOCK_TPM is set
ifneq ($(filter-out 0,${MOCK_TPM}),)
FWLIB_SRCS += \
	firmware/lib/tpm_lite/mocked_tlcl.c
endif

ifneq ($(filter-out 0,${X86_SHA_EXT}),)
CFLAGS += -DX86_SHA_EXT
FWLIB_SRCS += \
	firmware/2lib/2hwcrypto.c \
	firmware/2lib/2sha256_x86.c
endif

ifneq ($(filter-out 0,${ARMV8_CRYPTO_EXT}),)
CFLAGS += -DARMV8_CRYPTO_EXT
FWLIB_SRCS += \
	firmware/2lib/2hwcrypto.c \
	firmware/2lib/2sha256_arm.c
FWLIB_ASMS += \
	firmware/2lib/sha256_armv8a_ce_a64.S
endif

ifneq ($(filter-out 0,${ARM64_RSA_ACCELERATION}),)
CFLAGS += -DARM64_RSA_ACCELERATION
FWLIB_SRCS += \
	firmware/2lib/2modpow_neon.c
endif

ifneq ($(filter-out 0,${VB2_X86_RSA_ACCELERATION}),)
CFLAGS += -DVB2_X86_RSA_ACCELERATION
FWLIB_SRCS += \
	firmware/2lib/2modpow_sse2.c
endif

ifneq (,$(filter arm64 x86 x86_64,${ARCH}))
ENABLE_HWCRYPTO_RSA_TESTS := 1
endif

# Even if X86_SHA_EXT is 0 we need cflags since this will be compiled for tests
${BUILD}/firmware/2lib/2sha256_x86.o: CFLAGS += -mssse3 -mno-avx -msha

${BUILD}/firmware/2lib/2modpow_sse2.o: CFLAGS += -msse2 -mno-avx

ifneq (${FIRMWARE_STUB},)
FWLIB_SRCS += \
	firmware/stub/tpm_lite_stub.c \
	firmware/stub/vboot_api_stub_disk.c \
	firmware/stub/vboot_api_stub_stream.c \
	firmware/2lib/2stub.c
endif

FWLIB_OBJS = ${FWLIB_SRCS:%.c=${BUILD}/%.o} ${FWLIB_ASMS:%.S=${BUILD}/%.o}
TLCL_OBJS = ${TLCL_SRCS:%.c=${BUILD}/%.o}

ifneq ($(filter-out 0,${USE_AVB}),)
include firmware/avb/Makefile
FWLIB_SRCS += \
	firmware/2lib/2load_android_kernel.c
endif

ALL_OBJS += ${FWLIB_OBJS} ${TLCL_OBJS}

# Firmware rules
${FWLIB}: ${FWLIB_OBJS}
	@${PRINTF} "    RM            $(subst ${BUILD}/,,$@)\n"
	${Q}rm -f $@
	@${PRINTF} "    AR            $(subst ${BUILD}/,,$@)\n"
	${Q}ar qcT $@ $^

.PHONY: tlcl
tlcl: ${TLCL}

${TLCL}: ${TLCL_OBJS}
	@${PRINTF} "    RM            $(subst ${BUILD}/,,$@)\n"
	${Q}rm -f $@
	@${PRINTF} "    AR            $(subst ${BUILD}/,,$@)\n"
	${Q}ar qcT $@ $^
