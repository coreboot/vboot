# Copyright 2024 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
#
# Simple Makefile to integrate libavb build with vboot build system


# Add file with callbacks implementation
FWLIB_SRCS += \
	firmware/avb/vboot_avb_ops.c \
	firmware/avb/vboot_avb_sysdeps.c

# Compile necessary libavb srcs
LIBAVB_SRCS += \
	${LIBAVB_SRCDIR}/libavb/avb_chain_partition_descriptor.c \
	${LIBAVB_SRCDIR}/libavb/avb_cmdline.c \
	${LIBAVB_SRCDIR}/libavb/avb_crc32.c \
	${LIBAVB_SRCDIR}/libavb/avb_crypto.c \
	${LIBAVB_SRCDIR}/libavb/avb_descriptor.c \
	${LIBAVB_SRCDIR}/libavb/avb_footer.c \
	${LIBAVB_SRCDIR}/libavb/avb_hash_descriptor.c \
	${LIBAVB_SRCDIR}/libavb/avb_hashtree_descriptor.c \
	${LIBAVB_SRCDIR}/libavb/avb_kernel_cmdline_descriptor.c \
	${LIBAVB_SRCDIR}/libavb/avb_property_descriptor.c \
	${LIBAVB_SRCDIR}/libavb/avb_rsa.c \
	${LIBAVB_SRCDIR}/libavb/avb_slot_verify.c \
	${LIBAVB_SRCDIR}/libavb/avb_util.c \
	${LIBAVB_SRCDIR}/libavb/avb_vbmeta_image.c \
	${LIBAVB_SRCDIR}/libavb/avb_version.c \
	${LIBAVB_SRCDIR}/libavb/sha/sha256_impl.c \
	${LIBAVB_SRCDIR}/libavb/sha/sha512_impl.c

CFLAGS += -DUSE_LIBAVB -Ifirmware/avb -I${LIBAVB_SRCDIR} -I${LIBAVB_SRCDIR}/libavb
AVB_CFLAGS += -DAVB_COMPILATION -I${LIBAVB_SRCDIR}/libavb/sha

# TODO(b/329135129): Fix maybe uninitialized variables in upstream libavb
AVB_CFLAGS += -Wno-maybe-uninitialized

# TODO(b/329411445): Fix func declaration without a prototype in upstream libavb
AVB_CFLAGS += -Wno-strict-prototypes

# Add avb-related objects to the fwlib library
LIBAVB_OBJS = ${LIBAVB_SRCS:${LIBAVB_SRCDIR}/libavb/%.c=${BUILD}/libavb/%.o}
FWLIB_OBJS += ${LIBAVB_OBJS}

# Catch all avb-related objects and append extra cflags
${BUILD}/libavb/%.o: $(addprefix ${LIBAVB_SRCDIR}/libavb/,%.c)
	@${PRINTF} "    CC            $(subst ${BUILD}/,,$@)\n"
	${Q}mkdir -p $(dir $@)
	${Q}${CC} ${CFLAGS} ${AVB_CFLAGS} ${INCLUDES} -c -o $@ $<
