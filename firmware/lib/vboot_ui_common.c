/* Copyright 2018 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * High-level firmware wrapper API - user interface for RW firmware
 */

#include "2common.h"
#include "2sysincludes.h"
#include "secdata_tpm.h"
#include "vboot_api.h"
#include "vboot_kernel.h"
#include "vboot_ui_common.h"

/* One or two beeps to notify that attempted action was disallowed. */
void vb2_error_beep(enum vb2_beep_type beep)
{
	switch (beep) {
	case VB_BEEP_FAILED:
		VbExBeep(250, 200);
		break;
	default:
	case VB_BEEP_NOT_ALLOWED:
		VbExBeep(120, 400);
		VbExSleepMs(120);
		VbExBeep(120, 400);
		break;
	}
}

void vb2_error_notify(const char *print_msg,
		      const char *log_msg,
		      enum vb2_beep_type beep)
{
	if (print_msg)
		VbExDisplayDebugInfo(print_msg, 0);
	if (!log_msg)
		log_msg = print_msg;
	if (log_msg)
		VB2_DEBUG(log_msg);
	vb2_error_beep(beep);
}

void vb2_error_no_altfw(void)
{
	VB2_DEBUG("Legacy boot is disabled\n");
	VbExDisplayDebugInfo("WARNING: Booting legacy BIOS has not been "
			     "enabled. Refer to the developer-mode "
			     "documentation for details.\n", 0);
	vb2_error_beep(VB_BEEP_NOT_ALLOWED);
}

/**
 * Run alternative firmware
 *
 * This will only return if vboot data fails to commit, secdata_kernel fails to
 * lock, or the bootloader cannot be found / fails to start.
 *
 * @param ctx		Context pointer
 * @param altfw_num	Number of bootloader to start (0=any, 1=first, etc.)
 */
void vb2_try_altfw(struct vb2_context *ctx, int allowed,
		   enum VbAltFwIndex_t altfw_num)
{
	if (!allowed) {
		vb2_error_no_altfw();
		return;
	}

	if (vb2_commit_data(ctx)) {
		vb2_error_notify("Error committing data on legacy boot.\n",
				 NULL, VB_BEEP_FAILED);
		return;
	}

	if (secdata_kernel_lock(ctx)) {
		vb2_error_notify("Error locking kernel versions on legacy "
				 "boot.\n", NULL, VB_BEEP_FAILED);
		return;
	}

	/* Will not return if successful */
	VbExLegacy(altfw_num);

	vb2_error_notify("Legacy boot failed. Missing BIOS?\n", NULL,
			 VB_BEEP_FAILED);
}
