/* Copyright (c) 2013 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * High-level firmware API for loading and verifying rewritable firmware.
 * (Firmware portion)
 */

#include "2sysincludes.h"
#include "2common.h"
#include "2misc.h"

#include "sysincludes.h"
#include "gbb_access.h"
#include "load_kernel_fw.h"
#include "utility.h"
#include "vboot_api.h"
#include "vboot_struct.h"

static VbError_t VbGbbReadData(struct vb2_context *ctx,
			       uint32_t offset, uint32_t size, void *buf)
{
	if (vb2ex_read_resource(ctx, VB2_RES_GBB, offset, buf, size))
		return VBERROR_INVALID_GBB;
	return VBERROR_SUCCESS;
}

VbError_t VbGbbReadHWID(struct vb2_context *ctx, char *hwid, uint32_t max_size)
{
	struct vb2_gbb_header *gbb = vb2_get_gbb(ctx);

	if (!max_size)
		return VBERROR_INVALID_PARAMETER;
	*hwid = '\0';
	StrnAppend(hwid, "{INVALID}", max_size);
	if (!ctx)
		return VBERROR_INVALID_GBB;

	if (0 == gbb->hwid_size) {
		VB2_DEBUG("VbHWID(): invalid hwid size\n");
		return VBERROR_SUCCESS; /* oddly enough! */
	}

	if (gbb->hwid_size > max_size) {
		VB2_DEBUG("VbDisplayDebugInfo(): invalid hwid offset/size\n");
		return VBERROR_INVALID_PARAMETER;
	}

	return VbGbbReadData(ctx, gbb->hwid_offset,
			     gbb->hwid_size, hwid);
}

static VbError_t VbGbbReadKey(struct vb2_context *ctx, uint32_t offset,
			      VbPublicKey **keyp)
{
	VbPublicKey hdr, *key;
	VbError_t ret;
	uint32_t size;

	ret = VbGbbReadData(ctx, offset, sizeof(VbPublicKey), &hdr);
	if (ret)
		return ret;

	/* Deal with a zero-size key (used in testing) */
	size = hdr.key_offset + hdr.key_size;
	if (size < sizeof(hdr))
		size = sizeof(hdr);
	key = malloc(size);
	ret = VbGbbReadData(ctx, offset, size, key);
	if (ret) {
		free(key);
		return ret;
	}

	*keyp = key;
	return VBERROR_SUCCESS;
}

VbError_t VbGbbReadRootKey(struct vb2_context *ctx, VbPublicKey **keyp)
{
	struct vb2_gbb_header *gbb = vb2_get_gbb(ctx);

	return VbGbbReadKey(ctx, gbb->rootkey_offset, keyp);
}

VbError_t VbGbbReadRecoveryKey(struct vb2_context *ctx, VbPublicKey **keyp)
{
	struct vb2_gbb_header *gbb = vb2_get_gbb(ctx);

	return VbGbbReadKey(ctx, gbb->recovery_key_offset, keyp);
}
