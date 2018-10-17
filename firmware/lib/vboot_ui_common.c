/* Copyright 2018 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * High-level firmware wrapper API - user interface for RW firmware
 */

#include "sysincludes.h"

#include "2sysincludes.h"
#include "2common.h"

#include "rollback_index.h"
#include "vboot_api.h"
#include "vboot_ui_common.h"

/* Two short beeps to notify the user that attempted action was disallowed. */
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

void vb2_run_altfw(int altfw_num)
{
	if (RollbackKernelLock(0))
		VB2_DEBUG("Error locking kernel versions on legacy boot.\n");
	else
		VbExLegacy(altfw_num);	/* will not return if found */
	vb2_error_beep(VB_BEEP_FAILED);
}

void vb2_error_no_altfw(void)
{
	VB2_DEBUG("Legacy boot is disabled\n");
	VbExDisplayDebugInfo("WARNING: Booting legacy BIOS has not been "
			     "enabled. Refer to the developer-mode "
			     "documentation for details.\n");
	vb2_error_beep(VB_BEEP_NOT_ALLOWED);
}

void vb2_try_alt_fw(int allowed, int altfw_num)
{
	if (allowed)
		vb2_run_altfw(altfw_num);	/* will not return if found */
	else
		vb2_error_no_altfw();
}
