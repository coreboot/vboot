/* Copyright 2018 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Common code used by both vboot_ui and vboot_ui_menu.
 */

#ifndef VBOOT_REFERENCE_VBOOT_UI_COMMON_H_
#define VBOOT_REFERENCE_VBOOT_UI_COMMON_H_

enum vb2_beep_type {
	VB_BEEP_FAILED,		/* Permitted but the operation failed */
	VB_BEEP_NOT_ALLOWED,	/* Operation disabled by user setting */
};

/**
 * Emit beeps to indicate an error
 */
void vb2_error_beep(enum vb2_beep_type beep);

#endif  /* VBOOT_REFERENCE_VBOOT_UI_COMMON_H_ */
