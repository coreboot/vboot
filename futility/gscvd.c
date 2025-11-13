/* Copyright 2025 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include <stdbool.h>

#include "futility.h"
#include "gsc_ro.h"

bool futil_valid_gscvd_header(const struct gsc_verification_data *gscvd,
			      uint32_t len)
{
	if (len < sizeof(*gscvd)) {
		ERROR("Too small gscvd size %u\n", len);
		return false;
	}

	if (gscvd->gv_magic != GSC_VD_MAGIC) {
		ERROR("Incorrect gscvd magic %x\n", gscvd->gv_magic);
		return false;
	}

	if (gscvd->size > len) {
		ERROR("Incorrect gscvd size %u\n", gscvd->size);
		return false;
	}

	if (!gscvd->range_count || (gscvd->range_count > MAX_RANGES)) {
		ERROR("Incorrect gscvd range count %d\n", gscvd->range_count);
		return false;
	}

	if (vb2_verify_signature_inside(gscvd, gscvd->size,
					&gscvd->sig_header)) {
		ERROR("Corrupted signature header in gscvd\n");
		return false;
	}

	if (vb2_verify_packed_key_inside(gscvd, gscvd->size,
					 &gscvd->root_key_header)) {
		ERROR("Corrupted root key header in gscvd\n");
		return false;
	}

	return true;
}
