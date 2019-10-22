/* Copyright 2019 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Auxiliary firmware sync routines for vboot
 */

#include "2common.h"
#include "2misc.h"
#include "2nvstorage.h"
#include "2sysincludes.h"
#include "vboot_api.h"
#include "vboot_common.h"
#include "vboot_display.h"

/**
 * If no display is available, set DISPLAY_REQUEST in NV space
 */
static int check_reboot_for_display(struct vb2_context *ctx)
{
	if (!(vb2_get_sd(ctx)->flags & VB2_SD_FLAG_DISPLAY_AVAILABLE)) {
		VB2_DEBUG("Reboot to initialize display\n");
		vb2_nv_set(ctx, VB2_NV_DISPLAY_REQUEST, 1);
		return 1;
	}
	return 0;
}

/**
 * Display the WAIT screen
 */
static void display_wait_screen(struct vb2_context *ctx)
{
	VB2_DEBUG("AUX FW update is slow. Show WAIT screen.\n");
	VbDisplayScreen(ctx, VB_SCREEN_WAIT, 0, NULL);
}

/**
 * Determine if we are allowed to update auxfw
 *
 * @param ctx		Vboot2 context
 * @return boolean (true iff we can update auxfw)
 */
static int auxfw_sync_allowed(struct vb2_context *ctx)
{
	struct vb2_shared_data *sd = vb2_get_sd(ctx);
	struct vb2_gbb_header *gbb = vb2_get_gbb(ctx);

	/* Reasons not to do sync at all */
	if (!(ctx->flags & VB2_CONTEXT_EC_SYNC_SUPPORTED))
		return 0;
	if (gbb->flags & VB2_GBB_FLAG_DISABLE_EC_SOFTWARE_SYNC)
		return 0;
	if (gbb->flags & VB2_GBB_FLAG_DISABLE_AUXFW_SOFTWARE_SYNC)
		return 0;
	if (sd->recovery_reason)
		return 0;
	return 1;
}

/**
 * Update the specified Aux FW and verify the update succeeded
 *
 * @param ctx		Vboot2 context
 * @return VB2_SUCCESS, or non-zero error code.
 */
static vb2_error_t update_auxfw(struct vb2_context *ctx)
{
	vb2_error_t rv;

	VB2_DEBUG("Updating auxfw\n");

	/*
	 * The underlying platform is expected to know how and where to find the
	 * firmware image for all auxfw devices.
	 */
	rv = vb2ex_auxfw_update();
	if (rv != VB2_SUCCESS) {
		VB2_DEBUG("vb2ex_auxfw_update() returned %d\n", rv);

		/*
		 * The device may need a reboot.  It may need to unprotect the
		 * region before updating, or may need to reboot after updating.
		 * Either way, it's not an error requiring recovery mode.
		 *
		 * If we fail for any other reason, trigger recovery mode.
		 */
		if (rv != VBERROR_EC_REBOOT_TO_RO_REQUIRED)
			vb2api_fail(ctx, VB2_RECOVERY_AUX_FW_UPDATE, rv);
	}

	return rv;
}

/**
 * Decides if auxfw sync is allowed to be performed
 *
 * If sync is allowed, invokes the external callback,
 * vb2ex_auxfw_check() to allow the client to decide on the auxfw
 * update severity.
 *
 * @param ctx		Vboot2 context
 * @return VB2_SUCCESS, or non-zero error code.
 */
static vb2_error_t auxfw_sync_check_update(struct vb2_context *ctx,
					   enum vb2_auxfw_update_severity *severity)
{
	if (!auxfw_sync_allowed(ctx)) {
		*severity = VB_AUX_FW_NO_UPDATE;
		return VB2_SUCCESS;
	}

	return vb2ex_auxfw_check(severity);
}

vb2_error_t vb2api_auxfw_sync(struct vb2_context *ctx)
{
	enum vb2_auxfw_update_severity fw_update = VB_AUX_FW_NO_UPDATE;
	vb2_error_t rv;

	/* Check for update severity */
	rv = auxfw_sync_check_update(ctx, &fw_update);
	if (rv)
		return rv;

	/* If AUX FW update is slow display the wait screen */
	if (fw_update == VB_AUX_FW_SLOW_UPDATE) {
		/* Display should be available, but better check again */
		if (check_reboot_for_display(ctx))
			return VBERROR_REBOOT_REQUIRED;
		display_wait_screen(ctx);
	}

	if (fw_update > VB_AUX_FW_NO_UPDATE) {
		rv = update_auxfw(ctx);
		if (rv)
			return rv;
		/*
		 * AUX FW Update is applied successfully. Request EC reboot to
		 * RO, so that the chips that had FW update get reset to a
		 * clean state.
		 */
		return VBERROR_EC_REBOOT_TO_RO_REQUIRED;
	}

	return vb2ex_auxfw_finalize(ctx);
}
