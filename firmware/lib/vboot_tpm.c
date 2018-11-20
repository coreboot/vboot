/* Copyright 2018 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * TPM functions implemented in vboot_reference and exposed to depthcharge.
 */

#include "tlcl.h"
#include "vboot_api.h"

uint32_t VbSaveTpmState(void) {
	return TlclSaveState();
}
