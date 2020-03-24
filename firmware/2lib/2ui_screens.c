/* Copyright 2020 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Firmware screen definitions.
 */

#include "2common.h"
#include "2ui.h"

#define MENU_ITEMS(a) \
	.num_items = ARRAY_SIZE(a), \
	.items = a

static const struct vb2_menu_item empty_menu[] = { };

/******************************************************************************/
/* VB2_SCREEN_BLANK */

static const struct vb2_screen_info blank_screen = {
	.id = VB2_SCREEN_BLANK,
	.name = "Blank",
	MENU_ITEMS(empty_menu),
};

/******************************************************************************/
/* VB2_SCREEN_RECOVERY_BROKEN */

static const struct vb2_screen_info recovery_broken_screen = {
	.id = VB2_SCREEN_RECOVERY_BROKEN,
	.name = "Recover broken device",
	MENU_ITEMS(empty_menu),
};

/******************************************************************************/
/* VB2_SCREEN_RECOVERY_SELECT */

static const struct vb2_menu_item recovery_select_items[] = {
	{
		.text = "Recovery using phone",
		.target = VB2_SCREEN_RECOVERY_PHONE_STEP1,
	},
	{
		.text = "Recovery using external disk",
		.target = VB2_SCREEN_RECOVERY_DISK_STEP1,
	},
};

static const struct vb2_screen_info recovery_select_screen = {
	.id = VB2_SCREEN_RECOVERY_SELECT,
	.name = "Recovery method selection",
	MENU_ITEMS(recovery_select_items),
};

/******************************************************************************/
/* VB2_SCREEN_RECOVERY_INVALID */

static const struct vb2_screen_info recovery_invalid_screen = {
	.id = VB2_SCREEN_RECOVERY_INVALID,
	.name = "Invalid recovery inserted",
	MENU_ITEMS(empty_menu),
};

/******************************************************************************/
/* VB2_SCREEN_RECOVERY_PHONE_STEP1 */

static const struct vb2_screen_info recovery_phone_step1_screen = {
	.id = VB2_SCREEN_RECOVERY_PHONE_STEP1,
	.name = "Phone recovery step 1",
	MENU_ITEMS(empty_menu),
};

/******************************************************************************/
/* VB2_SCREEN_RECOVERY_DISK_STEP1 */

static const struct vb2_screen_info recovery_disk_step1_screen = {
	.id = VB2_SCREEN_RECOVERY_DISK_STEP1,
	.name = "Disk recovery step 1",
	MENU_ITEMS(empty_menu),
};

/******************************************************************************/
/*
 * TODO(chromium:1035800): Refactor UI code across vboot and depthcharge.
 * Currently vboot and depthcharge maintain their own copies of menus/screens.
 * vboot detects keyboard input and controls the navigation among different menu
 * items and screens, while depthcharge performs the actual rendering of each
 * screen, based on the menu information passed from vboot.
 */
static const struct vb2_screen_info *screens[] = {
	&blank_screen,
	&recovery_broken_screen,
	&recovery_select_screen,
	&recovery_invalid_screen,
	&recovery_phone_step1_screen,
	&recovery_disk_step1_screen,
};

const struct vb2_screen_info *vb2_get_screen_info(enum vb2_screen id)
{
	int i;
	for (i = 0; i < ARRAY_SIZE(screens); i++) {
		if (screens[i]->id == id)
			return screens[i];
	}
	return NULL;
}
