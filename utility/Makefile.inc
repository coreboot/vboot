# Copyright 2026 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# Utility defaults
UTIL_DEFAULTS = ${BUILD}/default/vboot_reference

# Scripts to install directly (not compiled)
UTIL_SCRIPT_NAMES_SDK = \
	utility/dev_make_keypair \
	utility/vbutil_what_keys
UTIL_SCRIPT_NAMES_BOARD = \
	utility/chromeos-tpm-recovery \
	utility/dev_debug_vboot \
	utility/enable_dev_usb_boot \
	utility/tpm-nvsize

UTIL_BIN_NAMES_SDK = \
	utility/dumpRSAPublicKey \
	utility/load_kernel_test \
	utility/pad_digest_utility \
	utility/signature_digest_utility \
	utility/verify_data
UTIL_BIN_NAMES_BOARD = \
	utility/dumpRSAPublicKey \
	utility/tpmc

ifneq ($(filter-out 0,${USE_FLASHROM}),)
UTIL_BIN_NAMES_BOARD += utility/crossystem
endif

UTIL_SCRIPTS_SDK = $(addprefix ${BUILD}/,${UTIL_SCRIPT_NAMES_SDK})
UTIL_SCRIPTS_BOARD = $(addprefix ${BUILD}/,${UTIL_SCRIPT_NAMES_BOARD})
UTIL_BINS_SDK = $(addprefix ${BUILD}/,${UTIL_BIN_NAMES_SDK})
UTIL_BINS_BOARD = $(addprefix ${BUILD}/,${UTIL_BIN_NAMES_BOARD})
UTIL_FILES_SDK = ${UTIL_BINS_SDK} ${UTIL_SCRIPTS_SDK}
UTIL_FILES_BOARD = ${UTIL_BINS_BOARD} ${UTIL_SCRIPTS_BOARD}

ALL_OBJS += $(addsuffix .o,${UTIL_BINS_SDK})
ALL_OBJS += $(addsuffix .o,${UTIL_BINS_BOARD})

# Utility-specific flags and rules
${BUILD}/utility/%: INCLUDES += -Iutility/include

ifeq ($(OPENSSL_VERSION),3)
${BUILD}/utility/%: CFLAGS += -Wno-error=deprecated-declarations
endif

${UTIL_BINS_SDK}: ${UTILLIB}
${UTIL_BINS_SDK}: LIBS = ${UTILLIB}
${UTIL_BINS_BOARD}: ${UTILLIB}
${UTIL_BINS_BOARD}: LIBS = ${UTILLIB}

ifneq ($(filter-out 0,${USE_FLASHROM}),)
${UTIL_BINS_BOARD}: LDLIBS += ${FLASHROM_LIBS}
endif

${UTIL_SCRIPTS_SDK} ${UTIL_SCRIPTS_BOARD}: ${BUILD}/%: %
	${Q}mkdir -p $(dir $@)
	${Q}cp -f $< $@
	${Q}chmod a+rx $@

${BUILD}/utility/dumpRSAPublicKey: LDLIBS += ${CRYPTO_LIBS}
${BUILD}/utility/pad_digest_utility: LDLIBS += ${CRYPTO_LIBS}
${BUILD}/utility/signature_digest_utility: LDLIBS += ${CRYPTO_LIBS}
${BUILD}/utility/verify_data: LDLIBS += ${CRYPTO_LIBS}

# Always create the defaults file, since it depends on input variables
.PHONY: ${UTIL_DEFAULTS}
${UTIL_DEFAULTS}:
	@${PRINTF} "    CREATE        $(subst ${BUILD}/,,$@)\n"
	${Q}rm -f $@
	${Q}mkdir -p $(dir $@)
	${Q}echo '# Generated file. Do not edit.' > $@.tmp
	${Q}echo "DEV_DEBUG_FORCE=${DEV_DEBUG_FORCE}" >> $@.tmp
	${Q}mv -f $@.tmp $@

# Installation templates
define UTIL_INSTALL_template
.PHONY: util_install-$(1)
util_install-$(1): $$(addprefix $${BUILD}/,$(1))
	@$${PRINTF} "    INSTALL       $(1)\n"
	$${Q}mkdir -p $${UB_DIR}
	$${Q}$${INSTALL} -t $${UB_DIR} $$^
endef

# Use sort to remove duplicates
UTIL_INSTALL_NAMES_SDK = $(sort ${UTIL_BIN_NAMES_SDK} ${UTIL_SCRIPT_NAMES_SDK})
UTIL_INSTALL_NAMES_BOARD = $(sort ${UTIL_BIN_NAMES_BOARD} ${UTIL_SCRIPT_NAMES_BOARD})

$(foreach prog,${UTIL_INSTALL_NAMES_SDK}, \
	$(eval $(call UTIL_INSTALL_template,$(prog))))

$(foreach prog,${UTIL_INSTALL_NAMES_BOARD}, \
	$(eval $(call UTIL_INSTALL_template,$(prog))))

.PHONY: util_install_defaults
util_install_defaults: ${UTIL_DEFAULTS}
	${Q}mkdir -p ${DF_DIR}
	${Q}${INSTALL} -t ${DF_DIR} -m 'u=rw,go=r,a-s' ${UTIL_DEFAULTS}

