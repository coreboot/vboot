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

/**
 * Run alternative firmware if allowed
 *
 * This will only return if it is not allowed, or the bootloader fails to
 * cannot be found / fails to start
 *
 * @altfw_num	Number of bootloader to start (0=any, 1=first, etc.)
 */
void vb2_run_altfw(int altfw_num);

/** Display an error and beep to indicate that altfw is not available */
void vb2_error_no_altfw(void);

/**
 * Jump to a bootloader if possible
 *
 * This checks if the operation is permitted. If it is, then it jumps to the
 * selected bootloader and execution continues there, never returning.
 *
 * If the operation is not permitted, or it is permitted but the bootloader
 * cannot be found, it beeps and returns.
 *
 * @allowed	1 if allowed, 0 if not allowed
 * @altfw_num	Number of bootloader to start (0=any, 1=first, etc.)
 */
void vb2_try_alt_fw(int allowed, int altfw_num);

#endif  /* VBOOT_REFERENCE_VBOOT_UI_COMMON_H_ */
