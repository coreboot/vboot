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

VbError_t ec_sync_all(struct vb2_context *ctx)
{
	struct vb2_shared_data *sd = vb2_get_sd(ctx);
	VbAuxFwUpdateSeverity_t fw_update;
	VbError_t rv;

	rv = ec_sync_check_aux_fw(ctx, &fw_update);
	if (rv)
		return rv;

	/* Phase 1; this determines if we need an update */
	VbError_t phase1_rv = ec_sync_phase1(ctx);
	int need_wait_screen = ec_will_update_slowly(ctx) ||
		(fw_update == VB_AUX_FW_SLOW_UPDATE);

	/*
	 * Check if we need to reboot to initialize the display before we can
	 * display the WAIT screen.
	 *
	 * Do this before we check if ec_sync_phase1() requires a reboot for
	 * some other reason, since there's no reason to reboot twice.
	 */
	int reboot_for_display = (need_wait_screen &&
				  !(sd->flags & VB2_SD_FLAG_DISPLAY_AVAILABLE));
	if (reboot_for_display) {
		VB2_DEBUG("Reboot to initialize display\n");
		vb2_nv_set(ctx, VB2_NV_DISPLAY_REQUEST, 1);
	}

	/* Reboot if phase 1 needed it, or if we need to initialize display */
	if (phase1_rv)
		return VBERROR_EC_REBOOT_TO_RO_REQUIRED;
	if (reboot_for_display)
		return VBERROR_REBOOT_REQUIRED;

	/* Display the wait screen if we need it */
	if (need_wait_screen) {
		VB2_DEBUG("EC is slow. Show WAIT screen.\n");
		VbDisplayScreen(ctx, VB_SCREEN_WAIT, 0, NULL);
	}

	/* Phase 2; Applies update and/or jumps to the correct EC image */
	rv = ec_sync_phase2(ctx);
	if (rv)
		return rv;

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
