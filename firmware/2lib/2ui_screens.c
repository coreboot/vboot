/* Copyright 2020 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Firmware screen definitions.
 */

#include "2common.h"
#include "2misc.h"
#include "2nvstorage.h"
#include "2ui.h"
#include "2ui_private.h"
#include "vboot_api.h"  /* for VB_KEY_ */

#define MENU_ITEMS(a) \
	.num_items = ARRAY_SIZE(a), \
	.items = a

#define ADVANCED_OPTIONS_ITEM { \
	.text = "Advanced options", \
	.target = VB2_SCREEN_ADVANCED_OPTIONS, \
}

/******************************************************************************/
/* VB2_SCREEN_BLANK */

static const struct vb2_screen_info blank_screen = {
	.id = VB2_SCREEN_BLANK,
	.name = "Blank",
};

/******************************************************************************/
/* VB2_SCREEN_RECOVERY_BROKEN */

static const struct vb2_menu_item recovery_broken_items[] = {
	ADVANCED_OPTIONS_ITEM,
};

static const struct vb2_screen_info recovery_broken_screen = {
	.id = VB2_SCREEN_RECOVERY_BROKEN,
	.name = "Recover broken device",
	MENU_ITEMS(recovery_broken_items),
};

/******************************************************************************/
/* VB2_SCREEN_ADVANCED_OPTIONS */

static const struct vb2_menu_item advanced_options_items[] = {
	{
		.text = "Developer mode",
		.target = VB2_SCREEN_RECOVERY_TO_DEV,
	},
	{
		.text = "Back",
		.action = vb2_ui_back_action,
	},
};

static const struct vb2_screen_info advanced_options_screen = {
	.id = VB2_SCREEN_ADVANCED_OPTIONS,
	.name = "Advanced options",
	MENU_ITEMS(advanced_options_items),
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
	ADVANCED_OPTIONS_ITEM,
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
};

/******************************************************************************/
/* VB2_SCREEN_RECOVERY_TO_DEV */

#define RECOVERY_TO_DEV_ITEM_CONFIRM 0

vb2_error_t recovery_to_dev_init(struct vb2_ui_context *ui)
{
	if (vb2_get_sd(ui->ctx)->flags & VB2_SD_FLAG_DEV_MODE_ENABLED) {
		VB2_DEBUG("Dev mode already enabled?\n");
		return vb2_ui_back_action(ui);
	}

	if (!PHYSICAL_PRESENCE_KEYBOARD && vb2ex_physical_presence_pressed()) {
		VB2_DEBUG("Presence button stuck?\n");
		return vb2_ui_back_action(ui);
	}

	/* Disable "Confirm" button for other physical presence types. */
	if (!PHYSICAL_PRESENCE_KEYBOARD)
		ui->state.disabled_item_mask =
			1 << RECOVERY_TO_DEV_ITEM_CONFIRM;

	return VB2_REQUEST_UI_CONTINUE;
}

vb2_error_t vb2_ui_recovery_to_dev_action(struct vb2_ui_context *ui)
{
	static int pressed_last;
	int pressed;

	if (ui->state.screen->id != VB2_SCREEN_RECOVERY_TO_DEV) {
		VB2_DEBUG("Action needs RECOVERY_TO_DEV screen\n");
		return VB2_REQUEST_UI_CONTINUE;
	}

	if (ui->key == ' ') {
		VB2_DEBUG("SPACE means cancel dev mode transition\n");
		return vb2_ui_back_action(ui);
	}

	if (PHYSICAL_PRESENCE_KEYBOARD) {
		if (ui->key != VB_KEY_ENTER &&
		    ui->key != VB_BUTTON_POWER_SHORT_PRESS)
			return VB2_REQUEST_UI_CONTINUE;
		if (!ui->key_trusted) {
			VB2_DEBUG("Reject untrusted %s confirmation\n",
				  ui->key == VB_KEY_ENTER ?
				  "ENTER" : "POWER");
			return VB2_REQUEST_UI_CONTINUE;
		}
	} else {
		pressed = vb2ex_physical_presence_pressed();
		if (pressed) {
			VB2_DEBUG("Physical presence button pressed, "
				 "awaiting release\n");
			pressed_last = 1;
			return VB2_REQUEST_UI_CONTINUE;
		}
		if (!pressed_last)
			return VB2_REQUEST_UI_CONTINUE;
		VB2_DEBUG("Physical presence button released\n");
	}
	VB2_DEBUG("Physical presence confirmed!\n");

	/* Sanity check, should never happen. */
	if ((vb2_get_sd(ui->ctx)->flags & VB2_SD_FLAG_DEV_MODE_ENABLED) ||
	    !vb2_allow_recovery(ui->ctx)) {
		VB2_DEBUG("ERROR: dev transition sanity check failed\n");
		return VB2_REQUEST_UI_CONTINUE;
	}

	VB2_DEBUG("Enabling dev mode and rebooting...\n");
	vb2_enable_developer_mode(ui->ctx);
	return VB2_REQUEST_REBOOT_EC_TO_RO;
}

static const struct vb2_menu_item recovery_to_dev_items[] = {
	[RECOVERY_TO_DEV_ITEM_CONFIRM] = {
		.text = "Confirm",
		.action = vb2_ui_recovery_to_dev_action,
	},
	{
		.text = "Cancel",
		.action = vb2_ui_back_action,
	},
};

static const struct vb2_screen_info recovery_to_dev_screen = {
	.id = VB2_SCREEN_RECOVERY_TO_DEV,
	.name = "Transition to developer mode",
	.init = recovery_to_dev_init,
	.action = vb2_ui_recovery_to_dev_action,
	MENU_ITEMS(recovery_to_dev_items),
};

/******************************************************************************/
/* VB2_SCREEN_RECOVERY_PHONE_STEP1 */

static const struct vb2_screen_info recovery_phone_step1_screen = {
	.id = VB2_SCREEN_RECOVERY_PHONE_STEP1,
	.name = "Phone recovery step 1",
};

/******************************************************************************/
/* VB2_SCREEN_RECOVERY_DISK_STEP1 */

static const struct vb2_screen_info recovery_disk_step1_screen = {
	.id = VB2_SCREEN_RECOVERY_DISK_STEP1,
	.name = "Disk recovery step 1",
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
	&advanced_options_screen,
	&recovery_select_screen,
	&recovery_invalid_screen,
	&recovery_to_dev_screen,
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
