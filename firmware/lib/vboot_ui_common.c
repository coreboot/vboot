/* Copyright 2018 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * High-level firmware wrapper API - user interface for RW firmware
 */

#include "sysincludes.h"

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
