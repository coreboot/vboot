/* Copyright (c) 2013 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * EC software sync routines for vboot
 */

#include "2sysincludes.h"
#include "2common.h"
#include "2misc.h"
#include "2nvstorage.h"

#include "sysincludes.h"
#include "ec_sync.h"
#include "vboot_api.h"
#include "vboot_common.h"
#include "vboot_display.h"
#include "vboot_kernel.h"

static VbError_t ec_sync_disable_display(struct vb2_context *ctx,
					 int need_wait_screen)
{
	/*
	 * Reboot to disable display initialization
	 * - we displayed the EC wait screen (otherwise we may be interfering
	 *   with some other vboot feature requesting display initialization)
	 * - vboot requested display to be initialized on this boot
	 * - the system is NOT in developer mode (which will also need display)
	 */
	if (need_wait_screen &&
	    vb2_nv_get(ctx, VB2_NV_DISPLAY_REQUEST) &&
	    !(vb2_get_sd(ctx)->vbsd->flags & VBSD_BOOT_DEV_SWITCH_ON)) {
		VB2_DEBUG("Reboot to undo display initialization\n");
		vb2_nv_set(ctx, VB2_NV_DISPLAY_REQUEST, 0);
		return VBERROR_REBOOT_REQUIRED;
	}
	return VBERROR_SUCCESS;
}

static int check_reboot_for_display(struct vb2_context *ctx,
					struct vb2_shared_data *sd)
{
	if (!(sd->flags & VB2_SD_FLAG_DISPLAY_AVAILABLE)) {
		VB2_DEBUG("Reboot to initialize display\n");
		vb2_nv_set(ctx, VB2_NV_DISPLAY_REQUEST, 1);
		return 1;
	}
	return 0;
}

static void display_wait_screen(struct vb2_context *ctx, const char *fw_name)
{
	VB2_DEBUG("%s update is slow. Show WAIT screen.\n", fw_name);
	VbDisplayScreen(ctx, VB_SCREEN_WAIT, 0, NULL);
}

VbError_t ec_sync_all(struct vb2_context *ctx)
{
	struct vb2_shared_data *sd = vb2_get_sd(ctx);
	VbAuxFwUpdateSeverity_t fw_update = VB_AUX_FW_NO_UPDATE;
	VbError_t rv;

	/* Phase 1; this determines if we need an update */
	VbError_t phase1_rv = ec_sync_phase1(ctx);
	int need_wait_screen = ec_will_update_slowly(ctx);

	/* Check if EC SW Sync Phase1 needs reboot */
	if (phase1_rv) {
		ec_sync_check_aux_fw(ctx, &fw_update);
		/* It does -- speculatively check if we need display as well */
		if (need_wait_screen || fw_update == VB_AUX_FW_SLOW_UPDATE)
			check_reboot_for_display(ctx, sd);
		return VBERROR_EC_REBOOT_TO_RO_REQUIRED;
	}

	/* Is EC already in RO and needs slow update? */
	if (need_wait_screen) {
		/* Might still need display in that case */
		if (check_reboot_for_display(ctx, sd))
			return VBERROR_REBOOT_REQUIRED;
		/* Display is available, so pop up the wait screen */
		display_wait_screen(ctx, "EC FW");
	}

	/* Phase 2; Applies update and/or jumps to the correct EC image */
	rv = ec_sync_phase2(ctx);
	if (rv)
		return rv;

	/* EC in RW, now we can check the severity of the AUX FW update */
	rv = ec_sync_check_aux_fw(ctx, &fw_update);
	if (rv)
		return rv;

	/* If AUX FW update is slow display the wait screen */
	if (fw_update == VB_AUX_FW_SLOW_UPDATE) {
		need_wait_screen = 1;
		/* Display should be available, but better check again */
		if (check_reboot_for_display(ctx, sd))
			return VBERROR_REBOOT_REQUIRED;
		display_wait_screen(ctx, "AUX FW");
	}

	/*
	 * Do Aux FW software sync and protect devices tunneled through the EC.
	 * Aux FW update may request RO reboot to force EC cold reset so also
	 * disable display request if needed to prevent a second reboot.
	 */
	rv = ec_sync_update_aux_fw(ctx);
	if (rv) {
		ec_sync_disable_display(ctx, need_wait_screen);
		return rv;
	}

	/* Reboot to disable display initialization if needed */
	rv = ec_sync_disable_display(ctx, need_wait_screen);
	if (rv)
		return rv;

	/* Phase 3; Completes sync and handles battery cutoff */
	rv = ec_sync_phase3(ctx);
	if (rv)
		return rv;

	return VBERROR_SUCCESS;
}
