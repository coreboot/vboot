# Copyright 2013 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# This Makefile normally builds in a 'build' subdir, but use
#
#    make BUILD=<dir>
#
# to put the output somewhere else.

##############################################################################
# Configuration variables come first.

# We should only run pwd once, not every time we refer to ${BUILD}.
SRCDIR := $(shell pwd)
BUILD = ${SRCDIR}/build
export BUILD
LIBAVB_SRCDIR ?= ../../aosp/external/avb/

# Stuff for 'make install'
INSTALL = install
DESTDIR = /
LIBDIR ?= lib

# Where exactly do the pieces go?
UB_DIR=${DESTDIR}/usr/bin
UL_DIR=${DESTDIR}/usr/${LIBDIR}
ULP_DIR=${UL_DIR}/pkgconfig
UI_DIR=${DESTDIR}/usr/include/vboot
US_DIR=${DESTDIR}/usr/share/vboot
DF_DIR=${DESTDIR}/etc/default
VB_DIR=${US_DIR}/bin
DUT_TEST_DIR=${US_DIR}/tests

# Where to install the (exportable) executables for testing?
TEST_INSTALL_DIR = ${BUILD}/install_for_test

# Set when installing into the SDK instead of building for a board sysroot.
SDK_BUILD ?=

# Verbose? Use V=1
ifeq ($(filter-out 0,${V}),)
Q := @
endif

# Quiet? Use QUIET=1
ifeq ($(filter-out 0,${QUIET}),)
PRINTF := printf
else
PRINTF := :
endif

# ARCH and/or FIRMWARE_ARCH are defined by the ChromiumOS ebuild.
ifeq (${ARCH},)
  ARCH := $(shell uname -m)
endif

ifeq (${ARCH},armv7l)
  override ARCH := arm
else ifeq (${ARCH},aarch64)
  override ARCH := arm64
else ifeq (${ARCH},i386)
  override ARCH := x86
else ifeq (${ARCH},i686)
  override ARCH := x86
else ifeq (${ARCH},amd64)
  override ARCH := x86_64
endif

ifneq (,$(filter arm arm64,${ARCH}))
	ARCH_DIR := arm
else ifneq (,$(filter x86 x86_64,${ARCH}))
	ARCH_DIR := x86
else
	ARCH_DIR := stub
endif

# Compiler flags
DEBUG_FLAGS := $(if $(filter-out 0,${DEBUG}),-g -Og,-Os)
WERROR := -Werror
FIRMWARE_FLAGS := -nostdinc -ffreestanding -fno-builtin -fno-stack-protector
COMMON_FLAGS := -pipe ${WERROR} -Wall -Wstrict-prototypes -Wtype-limits \
	-Wundef -Wmissing-prototypes -Wno-trigraphs -Wredundant-decls -Wshadow \
	-Wwrite-strings -Wstrict-aliasing -Wdate-time \
	-Wint-conversion -ffunction-sections -fdata-sections \
	-Wformat -Wno-format-security -std=gnu11 ${DEBUG_FLAGS} ${CPPFLAGS}

# test_ccflag
# $(1): compiler flags to test
# $(2): code to insert into test snippet
# returns: $(1) if compiler was successful, empty string otherwise
test_ccflag = $(shell \
	printf "$(2)\nvoid _start(void) {}\n" | \
	$(CC) -nostdlib -Werror $(1) -xc -c - -o /dev/null \
	>/dev/null 2>&1 && echo "$(1)")

COMMON_FLAGS += $(call test_ccflag,-Wimplicit-fallthrough)
COMMON_FLAGS += $(call test_ccflag,-Wno-address-of-packed-member)
COMMON_FLAGS += $(call test_ccflag,-Wno-unknown-warning)
COMMON_FLAGS += $(call test_ccflag,-Wincompatible-function-pointer-types)

TEST_FLAGS := $(call test_ccflag,-Wno-address-of-packed-member)

# FIRMWARE_ARCH is only defined by the ChromiumOS ebuild if compiling
# for a firmware target (coreboot or depthcharge). It must map to the same
# consistent set of architectures as the host.
ifeq (${FIRMWARE_ARCH},i386)
  override FIRMWARE_ARCH := x86
else ifeq (${FIRMWARE_ARCH},amd64)
  override FIRMWARE_ARCH := x86_64
else ifneq ($(filter arm64 armv7 armv8 armv8_64,${FIRMWARE_ARCH}),)
  override FIRMWARE_ARCH := arm
endif

ifeq (${FIRMWARE_ARCH},arm)
CC ?= armv7a-cros-linux-gnueabihf-gcc
CFLAGS ?= -march=armv5 -fno-common -ffixed-r8 -mfloat-abi=hard -marm \
	-mabi=aapcs-linux -mno-thumb-interwork ${FIRMWARE_FLAGS} ${COMMON_FLAGS}
else ifeq (${FIRMWARE_ARCH},x86)
CC ?= i686-pc-linux-gnu-gcc
CFLAGS ?= -fvisibility=hidden -fomit-frame-pointer \
	-fno-toplevel-reorder -fno-dwarf2-cfi-asm -mpreferred-stack-boundary=2 \
	${FIRMWARE_FLAGS} ${COMMON_FLAGS}
else ifeq (${FIRMWARE_ARCH},x86_64)
CFLAGS ?= ${FIRMWARE_FLAGS} ${COMMON_FLAGS} -fvisibility=hidden \
	-fomit-frame-pointer
else ifeq (${FIRMWARE_ARCH},riscv)
CC ?= riscv64-linux-gnu-gcc
else ifeq (${FIRMWARE_ARCH},mock)
FIRMWARE_STUB := 1
CFLAGS += ${TEST_FLAGS}
else ifneq (${FIRMWARE_ARCH},)
$(error Unexpected FIRMWARE_ARCH ${FIRMWARE_ARCH})
else
# FIRMWARE_ARCH not defined; assuming local compile.
FIRMWARE_STUB := 1
CC ?= gcc
CFLAGS += -DCHROMEOS_ENVIRONMENT ${COMMON_FLAGS}
endif

LDFLAGS += -Wl,--gc-sections
LDLIBS += -ldl

ifneq ($(filter-out 0,${DEBUG})$(filter-out 0,${TEST_PRINT}),)
CFLAGS += -DVBOOT_DEBUG
endif

ifneq ($(filter-out 0,${NDEBUG}),)
CFLAGS += -DNDEBUG
endif

ifneq ($(filter-out 0,${TPM2_MODE}),)
CFLAGS += -DTPM2_MODE
endif

# Enable EC early firmware selection.
ifneq ($(filter-out 0,${EC_EFS}),)
CFLAGS += -DEC_EFS=1
else
CFLAGS += -DEC_EFS=0
endif

# Some tests need to be disabled when using mocked_secdata_tpm.
ifneq ($(filter-out 0,${MOCK_TPM}),)
CFLAGS += -DMOCK_TPM
endif

# EXTERNAL_TPM_CLEAR_REQUEST indicates whether we want to use the external
# tpm_clear_request tool or not.
ifneq ($(filter-out 0,${EXTERNAL_TPM_CLEAR_REQUEST}),)
CFLAGS += -DEXTERNAL_TPM_CLEAR_REQUEST=1
else
CFLAGS += -DEXTERNAL_TPM_CLEAR_REQUEST=0
endif

# Configurable temporary directory for host tools
VBOOT_TMP_DIR := /tmp
CFLAGS += -DVBOOT_TMP_DIR=\"${VBOOT_TMP_DIR}\"

# Directory used by crossystem to create a lock file
CROSSYSTEM_LOCK_DIR := /run/lock
CFLAGS += -DCROSSYSTEM_LOCK_DIR=\"${CROSSYSTEM_LOCK_DIR}\"

PC_IN_FILES = vboot_host.pc.in

# Create / use dependency files
CFLAGS += -MMD -MF $@.d

ifeq (${FIRMWARE_ARCH},)
CFLAGS += -fPIC
endif

CFLAGS += -D_GNU_SOURCE

# This is required to access large disks and files on 32-bit systems,
# but if the environment doesn't support it, at least compile support
# for what is possible.
# Pass through cflags_use_64bits to evaluate it only once, here.
HASH_CONST := \#
cflags_use_64bits := $(call test_ccflag,$\
		     -D_FILE_OFFSET_BITS=64,$\
		     ${HASH_CONST}include <fts.h>)
CFLAGS += $(cflags_use_64bits)

# Code coverage
ifneq ($(filter-out 0,${COV}),)
  COV_FLAGS = -Og --coverage -DCOVERAGE
  CFLAGS += ${COV_FLAGS}
  LDFLAGS += ${COV_FLAGS}
  COV_INFO = ${BUILD}/coverage.info
endif

ifdef HAVE_MACOS
  CFLAGS += -DHAVE_MACOS -Wno-deprecated-declarations
endif

# Musl doesn't have execinfo.h.
ifndef HAVE_MUSL
  CFLAGS += -DHAVE_EXECINFO_H
endif

LD = ${CC}
CXX ?= g++
PKG_CONFIG ?= pkg-config

ifneq ($(filter-out 0,${STATIC}),)
LDFLAGS += -static
PKG_CONFIG += --static
endif

ifneq (${FUZZ_FLAGS},)
CFLAGS += ${FUZZ_FLAGS}
endif

# Optional Libraries
LIBZIP_VERSION := $(shell ${PKG_CONFIG} --modversion libzip 2>/dev/null)
HAVE_LIBZIP := $(if ${LIBZIP_VERSION},1)
ifneq ($(filter-out 0,${HAVE_LIBZIP}),)
  CFLAGS += -DHAVE_LIBZIP $(shell ${PKG_CONFIG} --cflags libzip)
  LIBZIP_LIBS := $(shell ${PKG_CONFIG} --libs libzip)
endif

LIBARCHIVE_VERSION := $(shell ${PKG_CONFIG} --modversion libarchive 2>/dev/null)
HAVE_LIBARCHIVE := $(if ${LIBARCHIVE_VERSION},1)
ifneq ($(filter-out 0,${HAVE_LIBARCHIVE}),)
  CFLAGS += -DHAVE_LIBARCHIVE $(shell ${PKG_CONFIG} --cflags libarchive)
  LIBARCHIVE_LIBS := $(shell ${PKG_CONFIG} --libs libarchive)
endif

HAVE_CROSID := $(shell ${PKG_CONFIG} --exists crosid && echo 1)
ifeq ($(HAVE_CROSID),1)
  CFLAGS += -DHAVE_CROSID $(shell ${PKG_CONFIG} --cflags crosid)
  CROSID_LIBS := $(shell ${PKG_CONFIG} --libs crosid)
endif

HAVE_NSS := $(shell ${PKG_CONFIG} --exists nss && echo 1)
ifeq ($(HAVE_NSS),1)
  CFLAGS += -DHAVE_NSS $(shell ${PKG_CONFIG} --cflags nss)
else
  $(warning Missing NSS. PKCS11 signing not supported. Install libnss3 to enable this feature.)
endif

# Get major version of openssl (e.g. version 3.0.5 -> "3")
OPENSSL_VERSION := $(shell ${PKG_CONFIG} --modversion openssl | cut -d. -f1)

# A test wrapper can be specified. Tests are run inside the wrapper eg:
# make RUNTEST=env runtests
RUNTEST =

# The Path to the $BUILD inside the runtest wrapper, used by the test scripts.
# The top of the chroot for RUNTEST must be passed in via the SYSROOT
# environment variable.  In the ChromiumOS chroot, this is done automatically by
# the ebuild.
export BUILD_RUN = $(subst ${SYSROOT},,${BUILD})
# Path to the $SRCDIR inside the wrapper, the test scripts rederive this.
SRC_RUN = $(subst ${SYSROOT},,${SRCDIR})

INCLUDES += \
	-Ifirmware/include \
	-Ifirmware/lib/include \
	-Ifirmware/lib/cgptlib/include \
	-Ifirmware/lib/tpm_lite/include \
	-Ifirmware/2lib/include

ifneq (${FIRMWARE_STUB},)
INCLUDES += -Ihost/include -Ihost/lib/include -Ihost/lib21/include
ifeq ($(shell uname -s), OpenBSD)
INCLUDES += -I/usr/local/include
endif
endif

CRYPTO_LIBS := $(shell ${PKG_CONFIG} --libs libcrypto)
ifeq ($(shell uname -s), FreeBSD)
CRYPTO_LIBS += -lcrypto
endif
ifeq ($(shell uname -s), OpenBSD)
LDFLAGS += -Wl,-z,notext
endif

##############################################################################
# Subdirectory inclusion

SUBMODULES = firmware host cgpt utility futility tests scripts

# Initial empty definitions for common accumulation variables
ALL_OBJS =
ALL_DEPS =
TEST_OBJS =
TEST_DEPS =
FWLIB_OBJS =
TLCL_OBJS =
UTILLIB_OBJS =
HOSTLIB_OBJS =
CGPT_OBJS =
FUTIL_OBJS =
LIBS =
OBJS =
COMMONLIB_SRCS =
FWLIB_ASMS =
FWLIB_SRCS =
TLCL_SRCS =
TESTLIB_SRCS =

# Include sub-makefiles only if they exist (for external projects like libpayload)
include $(foreach m,${SUBMODULES},$(wildcard $(m)/Makefile.inc))

##############################################################################
# High-level targets

.PHONY: all
all: fwlib futil utillib hostlib cgpt tlcl util_files \
	$(if $(filter x86_64,${ARCH}),$(if $(filter clang,${CC}),fuzzers)) \
	$(if $(filter-out 0,${COV}),coverage)

.PHONY: clean
clean:
	${Q}/bin/rm -rf "${BUILD}"

.PHONY: install
install: cgpt_install signing_install futil_install pc_files_install \
	lib_install $(if ${SDK_BUILD},,util_install_defaults) \
	$(foreach f,$(if ${SDK_BUILD},${UTIL_FILES_SDK},${UTIL_FILES_BOARD}), \
		util_install-$(patsubst ${BUILD}/%,%,${f}))

.PHONY: install_dev
install_dev: devkeys_install headers_install

.PHONY: install_for_test
install_for_test: override DESTDIR = ${TEST_INSTALL_DIR}
install_for_test: test_setup install \
	$(foreach f,${UTIL_FILES_SDK} ${UTIL_FILES_BOARD}, \
		util_install-$(patsubst ${BUILD}/%,%,${f}))

.PHONY: util_files
util_files: $(if ${SDK_BUILD},${UTIL_FILES_SDK},${UTIL_FILES_BOARD})

.PHONY: fwlib
fwlib: $(if ${FIRMWARE_ARCH},${FWLIB},)

.PHONY: futil
futil: ${FUTIL_BIN}

.PHONY: test_setup
test_setup:: cgpt ${UTIL_FILES_SDK} ${UTIL_FILES_BOARD} futil tests

# Generate test keys
.PHONY: genkeys
genkeys: install_for_test
	${RUNTEST} ${SRC_RUN}/tests/gen_test_keys.sh

# Generate test cases
.PHONY: gentestcases
gentestcases: install_for_test
	${RUNTEST} ${SRC_RUN}/tests/gen_test_cases.sh

# Generate test cases for fuzzing
.PHONY: genfuzztestcases
genfuzztestcases: install_for_test
	${RUNTEST} ${SRC_RUN}/tests/gen_fuzz_test_cases.sh

.SECONDARY:

# ----------------------------------------------------------------------------
# Firmware library

# TPM-specific flags.  These depend on the particular TPM we're targeting for.
# They are needed here only for compiling parts of the firmware code into
# user-level tests.

# TPM_BLOCKING_CONTINUESELFTEST is defined if TPM_ContinueSelfTest blocks until
# the self test has completed.

${TLCL_OBJS}: CFLAGS += -DTPM_BLOCKING_CONTINUESELFTEST

# TPM_MANUAL_SELFTEST is defined if the self test must be started manually
# (with a call to TPM_ContinueSelfTest) instead of starting automatically at
# power on.
#
# We sincerely hope that TPM_BLOCKING_CONTINUESELFTEST and TPM_MANUAL_SELFTEST
# are not both defined at the same time.  (See comment in code.)

# CFLAGS += -DTPM_MANUAL_SELFTEST

# NOTE: UNROLL_LOOPS *only* affects SHA256, *not* SHA512. This seems to have
# been a conscious decision at some point (see b/35501356) but whether it still
# holds up in all situations on all architectures today might need to be
# reevaluated. For now, since we currently always use SHA256 for (non-recovery)
# kernel bodies and don't unroll loops for firmware verification, it's not very
# relevant in practice. To unroll SHA512, UNROLL_LOOPS_SHA512 would need to be
# defined.
ifneq ($(filter-out 0,$(UNROLL_LOOPS)),)
$(info vboot SHA256 built with unrolled loops (faster, larger code size))
CFLAGS += -DUNROLL_LOOPS
else
$(info vboot SHA256 built with tight loops (slower, smaller code size))
endif

##############################################################################
# Generic build rules

${BUILD}/%: ${BUILD}/%.o ${OBJS} ${LIBS}
	@${PRINTF} "    LD            $(subst ${BUILD}/,,$@)\n"
	${Q}${LD} -o $@ ${LDFLAGS} $< ${OBJS} ${LIBS} ${LDLIBS}

${BUILD}/%.o: %.c
	@${PRINTF} "    CC            $(subst ${BUILD}/,,$@)\n"
	${Q}mkdir -p $(dir $@)
	${Q}${CC} ${CFLAGS} ${INCLUDES} -c -o $@ $<

${BUILD}/%.o: ${BUILD}/%.c
	@${PRINTF} "    CC            $(subst ${BUILD}/,,$@)\n"
	${Q}mkdir -p $(dir $@)
	${Q}${CC} ${CFLAGS} ${INCLUDES} -c -o $@ $<

${BUILD}/%.o: %.S
	@${PRINTF} "    CC            $(subst ${BUILD}/,,$@)\n"
	${Q}mkdir -p $(dir $@)
	${Q}${CC} ${CFLAGS} ${INCLUDES} -c -o $@ $<

##############################################################################
# Other targets
.PHONY: devkeys_install
devkeys_install:
	@${PRINTF} "    INSTALL       DEVKEYS\n"
	${Q}mkdir -p ${US_DIR}/devkeys
	${Q}${INSTALL} -t ${US_DIR}/devkeys -m 644 \
		`find tests/devkeys -type f -maxdepth 1`

# Code coverage
.PHONY: coverage
ifeq ($(filter-out 0,${COV}),)
coverage:
	$(error Build coverage like this: make clean && COV=1 make coverage)
else
.PHONY: coverage_init
coverage_init: install_for_test
	rm -f ${COV_INFO}*
	lcov -c -i -d . -b . -o ${COV_INFO}.initial

.PHONY: coverage_html
coverage_html: coverage_init runtests
	lcov -c -d . -b . -o ${COV_INFO}.tests
	lcov -a ${COV_INFO}.initial -a ${COV_INFO}.tests -o ${COV_INFO}.total
	lcov -r ${COV_INFO}.total '/usr/*' -o ${COV_INFO}.local
	genhtml ${COV_INFO}.local -o ${BUILD}/coverage
	lcov -r ${COV_INFO}.local '*/stub/*' -o ${COV_INFO}.nostub
	lcov -e ${COV_INFO}.nostub '${SRCDIR}/firmware/*' -o ${COV_INFO}.firmware

coverage: coverage_init runtests coverage_html
endif

# Dependencies
ALL_DEPS += ${ALL_OBJS:%.o=%.o.d}
TEST_DEPS += ${TEST_OBJS:%.o=%.o.d}
-include ${ALL_DEPS}
-include ${TEST_DEPS}

# Tags and symbols
SRCDIRPAT=$(subst /,\/,${SRCDIR}/)
${BUILD}/cscope.files: all install_for_test
	${Q}rm -f $@
	${Q}cat ${ALL_DEPS} | tr -d ':\\' | tr ' ' '\012' | \
		sed -e "s/${SRCDIRPAT}//" | \
		egrep '\.[chS]$$' | sort | uniq > $@

cmd_etags = etags -o ${BUILD}/TAGS $(shell cat ${BUILD}/cscope.files)
cmd_ctags = ctags -o ${BUILD}/tags $(shell cat ${BUILD}/cscope.files)
run_if_prog = $(if $(shell which $(1) 2>/dev/null),$(2),)

.PHONY: tags TAGS xrefs
tags TAGS xrefs: ${BUILD}/cscope.files
	${Q}\rm -f ${BUILD}/tags ${BUILD}/TAGS
	${Q}$(call run_if_prog,etags,${cmd_etags})
	${Q}$(call run_if_prog,ctags,${cmd_ctags})

PC_FILES = ${PC_IN_FILES:%.pc.in=${BUILD}/%.pc}
${PC_FILES}: ${PC_IN_FILES}
	${Q}sed \
		-e 's:@LDLIBS@:${LDLIBS}:' \
		-e 's:@LIBDIR@:${LIBDIR}:' \
		$< > $@

.PHONY: pc_files_install
pc_files_install: ${PC_FILES}
	${Q}mkdir -p ${ULP_DIR}
	${Q}${INSTALL} -D -m 0644 $< ${ULP_DIR}/$(notdir $<)
