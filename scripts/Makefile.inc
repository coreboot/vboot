# Copyright 2026 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# Signing scripts that are also useful on DUTs.
SIGNING_SCRIPTS_BOARD = \
	scripts/image_signing/make_dev_firmware.sh \
	scripts/image_signing/make_dev_ssd.sh \
	scripts/image_signing/resign_firmwarefd.sh \
	scripts/image_signing/swap_ec_rw \
	scripts/image_signing/common_minimal.sh

# SDK installations have some extra scripts.
SIGNING_SCRIPTS_SDK = \
	scripts/image_signing/make_dev_firmware.sh \
	scripts/image_signing/make_dev_ssd.sh \
	scripts/image_signing/resign_firmwarefd.sh \
	scripts/image_signing/swap_ec_rw \
	scripts/image_signing/common_minimal.sh

.PHONY: signing_install
signing_install: $(if ${SDK_BUILD},${SIGNING_SCRIPTS_SDK},${SIGNING_SCRIPTS_BOARD})
	@${PRINTF} "    INSTALL       SIGNING\n"
	${Q}mkdir -p ${VB_DIR}
	${Q}${INSTALL} -t ${VB_DIR} $^
