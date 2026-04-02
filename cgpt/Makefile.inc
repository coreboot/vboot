# Copyright 2026 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

CGPT = ${BUILD}/cgpt/cgpt
CGPT_WRAPPER = ${BUILD}/cgpt/cgpt_wrapper

CGPT_SRCS = \
	cgpt/cgpt.c \
	cgpt/cgpt_add.c \
	cgpt/cgpt_boot.c \
	cgpt/cgpt_common.c \
	cgpt/cgpt_create.c \
	cgpt/cgpt_edit.c \
	cgpt/cgpt_find.c \
	cgpt/cgpt_legacy.c \
	cgpt/cgpt_prioritize.c \
	cgpt/cgpt_repair.c \
	cgpt/cgpt_show.c \
	cgpt/cmd_add.c \
	cgpt/cmd_boot.c \
	cgpt/cmd_create.c \
	cgpt/cmd_edit.c \
	cgpt/cmd_find.c \
	cgpt/cmd_legacy.c \
	cgpt/cmd_prioritize.c \
	cgpt/cmd_repair.c \
	cgpt/cmd_show.c

CGPT_OBJS = ${CGPT_SRCS:%.c=${BUILD}/%.o}

ALL_OBJS += ${CGPT_OBJS}

# CGPT rules
${CGPT}: LDLIBS += -luuid
${CGPT}: ${CGPT_OBJS} ${UTILLIB}
	@${PRINTF} "    LDcgpt        $(subst ${BUILD}/,,$@)\n"
	${Q}${LD} -o ${CGPT} ${LDFLAGS} $^ ${LDLIBS}

.PHONY: cgpt
cgpt: ${CGPT}

.PHONY: cgpt_install
cgpt_install: ${CGPT}
	@${PRINTF} "    INSTALL       CGPT\n"
	${Q}mkdir -p ${UB_DIR}
	${Q}${INSTALL} -t ${UB_DIR} $^
