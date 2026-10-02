# Copyright 2026 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# Signing scripts installed into both SDK and board builds.
SIGNING_SCRIPTS = \
	scripts/image_signing/make_dev_firmware.sh \
	scripts/image_signing/make_dev_ssd.sh \
	scripts/image_signing/resign_firmwarefd.sh \
	scripts/image_signing/swap_ec_rw \
	scripts/image_signing/common_minimal.sh

.PHONY: signing_install
signing_install: ${SIGNING_SCRIPTS}
	@${PRINTF} "    INSTALL       SIGNING\n"
	${Q}mkdir -p ${VB_DIR}
	${Q}${INSTALL} -t ${VB_DIR} $^
