/* Copyright 2020 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * User interfaces for developer and recovery mode menus.
 */

#ifndef VBOOT_REFERENCE_2UI_H_
#define VBOOT_REFERENCE_2UI_H_

#include <2api.h>
#include <2sysincludes.h>

/*****************************************************************************/
/* Data structures */

struct vb2_screen_info {
	/* Screen id */
	enum vb2_screen id;
	/* Screen name for printing to console only */
	const char *name;
	/* Number of menu items */
	uint16_t num_items;
	/* List of menu items */
	const struct vb2_menu_item *items;
};

struct vb2_menu_item {
	/* Text description */
	const char *text;
	/* Target screen */
	enum vb2_screen target;
};

struct vb2_screen_state {
	const struct vb2_screen_info *screen;
	uint32_t locale_id;
	uint32_t selected_item;
	uint32_t disabled_item_mask;
};

struct vb2_ui_context {
	struct vb2_context *ctx;
	const struct vb2_screen_info *root_screen;
	struct vb2_screen_state state;
	uint32_t key;
};

/**
 * Get info struct of a screen.
 *
 * @param screen	Screen from enum vb2_screen
 *
 * @return screen info struct on success, NULL on error.
 */
const struct vb2_screen_info *vb2_get_screen_info(enum vb2_screen id);

/*****************************************************************************/
/* UI loops */

/**
 * UI for a developer-mode boot.
 *
 * Enter the developer menu, which provides options to switch out of developer
 * mode, boot from external media, use legacy bootloader, or boot Chrome OS from
 * disk.
 *
 * If a timeout occurs, take the default boot action.
 *
 * @param ctx		Vboot context
 * @returns VB2_SUCCESS, or non-zero error code.
 */
vb2_error_t vb2_developer_menu(struct vb2_context *ctx);

/**
 * UI for a non-manual recovery ("BROKEN").
 *
 * Enter the recovery menu, which shows that an unrecoverable error was
 * encountered last boot. Wait for the user to physically reset or shut down.
 *
 * @param ctx		Vboot context
 * @returns VB2_SUCCESS, or non-zero error code.
 */
vb2_error_t vb2_broken_recovery_menu(struct vb2_context *ctx);

/**
 * UI for a manual recovery-mode boot.
 *
 * Enter the recovery menu, which prompts the user to insert recovery media,
 * navigate the step-by-step recovery, or enter developer mode if allowed.
 *
 * @param ctx		Vboot context
 * @returns VB2_SUCCESS, or non-zero error code.
 */
vb2_error_t vb2_manual_recovery_menu(struct vb2_context *ctx);

#endif  /* VBOOT_REFERENCE_2UI_H_ */
