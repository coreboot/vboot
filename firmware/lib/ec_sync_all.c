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

static VbError_t ec_sync_unload_oprom(struct vb2_context *ctx,
				      VbSharedDataHeader *shared,
				      int need_wait_screen)
{
	/*
	 * Reboot to unload VGA Option ROM if:
	 * - we displayed the wait screen
	 * - the system has slow EC update flag set
	 * - the VGA Option ROM was needed and loaded
	 * - the system is NOT in developer mode (that'll also need the ROM)
	 */
	if (need_wait_screen &&
	    (shared->flags & VBSD_OPROM_MATTERS) &&
	    (shared->flags & VBSD_OPROM_LOADED) &&
	    !(shared->flags & VBSD_BOOT_DEV_SWITCH_ON)) {
		VB2_DEBUG("Reboot to unload VGA Option ROM\n");
		vb2_nv_set(ctx, VB2_NV_OPROM_NEEDED, 0);
		return VBERROR_VGA_OPROM_MISMATCH;
	}
	return VBERROR_SUCCESS;
}

static int check_reboot_for_oprom(struct vb2_context *ctx,
				  VbSharedDataHeader *shared)
{
	int reboot_for_oprom = shared->flags & VBSD_OPROM_MATTERS &&
				!(shared->flags & VBSD_OPROM_LOADED);

	if (reboot_for_oprom) {
		VB2_DEBUG("Reboot to load VGA Option ROM\n");
		vb2_nv_set(ctx, VB2_NV_OPROM_NEEDED, 1);
		return 1;
	}
	return 0;
}

static void display_wait_screen(struct vb2_context *ctx, const char *fw_name)
{
	VB2_DEBUG("%s update is slow. Show WAIT screen.\n", fw_name);
	VbDisplayScreen(ctx, VB_SCREEN_WAIT, 0);
}

VbError_t ec_sync_all(struct vb2_context *ctx)
{
	struct vb2_shared_data *sd = vb2_get_sd(ctx);
	VbSharedDataHeader *shared = sd->vbsd;
	VbAuxFwUpdateSeverity_t fw_update = VB_AUX_FW_NO_UPDATE;
	VbError_t rv, update_aux_fw_rv = VBERROR_SUCCESS;

	/* Phase 1; this determines if we need an update */
	VbError_t phase1_rv = ec_sync_phase1(ctx);
	int need_wait_screen = ec_will_update_slowly(ctx);

	/* Check if EC SW Sync Phase1 needs reboot */
	if (phase1_rv) {
		ec_sync_check_aux_fw(ctx, &fw_update);
		/* It does -- speculatively check if we need display as well */
		if (need_wait_screen || fw_update == VB_AUX_FW_SLOW_UPDATE)
			check_reboot_for_oprom(ctx, shared);
		return VBERROR_EC_REBOOT_TO_RO_REQUIRED;
	}

	/* Is EC already in RO and needs slow update? */
	if (need_wait_screen) {
		/* Might still need display in that case */
		if (check_reboot_for_oprom(ctx, shared))
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
		if (check_reboot_for_oprom(ctx, shared))
			return VBERROR_REBOOT_REQUIRED;
		display_wait_screen(ctx, "AUX FW");
	}

	/* Do Aux FW software sync */
	if (fw_update > VB_AUX_FW_NO_UPDATE) {
		update_aux_fw_rv = ec_sync_update_aux_fw(ctx);
		/*
		 * If requesting EC reboot to RO (because some tunnels are
		 * protected), do not disable the display to avoid reboot
		 * during display re-init.
		 */
		if (update_aux_fw_rv == VBERROR_EC_REBOOT_TO_RO_REQUIRED)
			return update_aux_fw_rv;
	}

	/* Reboot to unload VGA Option ROM for both slow EC & AUX FW updates */
	rv = ec_sync_unload_oprom(ctx, shared, need_wait_screen);
	/* Something went wrong during AUX FW update */
	if (update_aux_fw_rv)
		return update_aux_fw_rv;
	/*
	 * AUX FW Update is applied successfully. Request EC reboot to RO,
	 * so that the chips that had FW update gets reset to a clean state.
	 */
	if (fw_update > VB_AUX_FW_NO_UPDATE)
		return VBERROR_EC_REBOOT_TO_RO_REQUIRED;
	if (rv)
		return rv;

	/* Phase 3; Completes sync and handles battery cutoff */
	rv = ec_sync_phase3(ctx);
	if (rv)
		return rv;

	return VBERROR_SUCCESS;
}
