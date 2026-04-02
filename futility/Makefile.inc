# Copyright 2026 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

FUTIL_BIN = ${BUILD}/futility/futility

FUTIL_SYMLINKS = \
	dump_fmap \
	dump_kernel_config \
	gbb_utility \
	vbutil_firmware \
	vbutil_kernel \
	vbutil_key \
	vbutil_keyblock

FUTIL_SRCS = \
	futility/futility.c \
	futility/cmd_create.c \
	futility/cmd_dump_fmap.c \
	futility/cmd_dump_kernel_config.c \
	futility/cmd_flash_util.c \
	futility/cmd_gbb_utility.c \
	futility/cmd_gscvd.c \
	futility/cmd_load_fmap.c \
	futility/cmd_pcr.c \
	futility/cmd_read.c \
	futility/cmd_show.c \
	futility/cmd_sign.c \
	futility/cmd_update.c \
	futility/cmd_vbutil_firmware.c \
	futility/cmd_vbutil_kernel.c \
	futility/cmd_vbutil_key.c \
	futility/cmd_vbutil_keyblock.c \
	futility/file_type_bios.c \
	futility/file_type.c \
	futility/file_type_ro_chksum.c \
	futility/file_type_rwsig.c \
	futility/file_type_usbpd1.c \
	futility/flash_helpers.c \
	futility/gscvd.c \
	futility/platform_csme.c \
	futility/misc.c \
	futility/vb1_helper.c \
	futility/vb2_helper.c

ifneq ($(filter-out 0,${USE_FLASHROM}),)
FUTIL_SRCS += host/lib/flashrom_drv.c \
	futility/archive/updater_archive_fallback.c \
	futility/updater_archive.c \
	futility/updater_dut.c \
	futility/updater_manifest.c \
	futility/updater_quirks.c \
	futility/updater_utils.c \
	futility/updater.c

ifneq ($(filter-out 0,${HAVE_LIBARCHIVE}),)
FUTIL_SRCS += futility/archive/updater_archive_libarchive.c
endif

ifneq ($(filter-out 0,${HAVE_LIBZIP}),)
FUTIL_SRCS += futility/archive/updater_archive_libzip.c
endif
endif

FUTIL_CMD_LIST = ${BUILD}/gen/futility_cmds.c
FUTIL_OBJS = ${FUTIL_SRCS:%.c=${BUILD}/%.o} ${FUTIL_CMD_LIST:%.c=%.o}

${FUTIL_OBJS}: INCLUDES += -Ihost/lib21/include -Ifutility

ifeq ($(OPENSSL_VERSION),3)
${FUTIL_OBJS}: CFLAGS += -Wno-error=deprecated-declarations
endif

ALL_OBJS += ${FUTIL_OBJS}

# Futility rules
FUTIL_LIBS = ${CROSID_LIBS} ${CRYPTO_LIBS} ${LIBZIP_LIBS} ${LIBARCHIVE_LIBS} \
	${FLASHROM_LIBS}

${FUTIL_BIN}: LDLIBS += ${FUTIL_LIBS}
${FUTIL_BIN}: ${FUTIL_OBJS} ${UTILLIB}
	@${PRINTF} "    LD            $(subst ${BUILD}/,,$@)\n"
	${Q}${LD} -o $@ ${LDFLAGS} $^ ${LDLIBS}

${FUTIL_CMD_LIST}: ${FUTIL_SRCS}
	@${PRINTF} "    GEN           $(subst ${BUILD}/,,$@)\n"
	${Q}rm -f $@ $@_t $@_commands
	${Q}mkdir -p ${BUILD}/gen
	${Q}grep -hoRE '^DECLARE_FUTIL_COMMAND\([^,]+' $^ \
		| sed 's/DECLARE_FUTIL_COMMAND(\(.*\)/_CMD(\1)/' \
		| sort >>$@_commands
	${Q}./scripts/getversion.sh >> $@_t
	${Q}echo '#define _CMD(NAME) extern const struct' \
		'futil_cmd_t __cmd_##NAME;' >> $@_t
	${Q}cat $@_commands >> $@_t
	${Q}echo '#undef _CMD' >> $@_t
	${Q}echo '#define _CMD(NAME) &__cmd_##NAME,' >> $@_t
	${Q}echo 'const struct futil_cmd_t *const futil_cmds[] = {' >> $@_t
	${Q}cat $@_commands >> $@_t
	${Q}echo '0};  /* null-terminated */' >> $@_t
	${Q}echo '#undef _CMD' >> $@_t
	${Q}mv $@_t $@
	${Q}rm -f $@_commands

.PHONY: futil_install
futil_install: ${FUTIL_BIN}
	@${PRINTF} "    INSTALL       futility\n"
	${Q}mkdir -p ${UB_DIR}
	${Q}${INSTALL} -t ${UB_DIR} ${FUTIL_BIN}
	${Q}for prog in ${FUTIL_SYMLINKS}; do \
		ln -sf futility "${UB_DIR}/$$prog"; done
