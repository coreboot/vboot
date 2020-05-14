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
#include "vboot_api.h"
#include "vboot_kernel.h"

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

#define ADVANCED_OPTIONS_ITEM_DEVELOPER_MODE 0
#define ADVANCED_OPTIONS_ITEM_BACK 1

vb2_error_t advanced_options_init(struct vb2_ui_context *ui)
{
	if (vb2_get_sd(ui->ctx)->flags & VB2_SD_FLAG_DEV_MODE_ENABLED) {
		ui->state.disabled_item_mask |=
			1 << ADVANCED_OPTIONS_ITEM_DEVELOPER_MODE;
		ui->state.selected_item = ADVANCED_OPTIONS_ITEM_BACK;
	}

	return VB2_REQUEST_UI_CONTINUE;
}

static const struct vb2_menu_item advanced_options_items[] = {
	[ADVANCED_OPTIONS_ITEM_DEVELOPER_MODE] = {
		.text = "Enable developer mode",
		.target = VB2_SCREEN_RECOVERY_TO_DEV,
	},
	[ADVANCED_OPTIONS_ITEM_BACK] = {
		.text = "Back",
		.action = vb2_ui_back_action,
	},
};

static const struct vb2_screen_info advanced_options_screen = {
	.id = VB2_SCREEN_ADVANCED_OPTIONS,
	.name = "Advanced options",
	.init = advanced_options_init,
	MENU_ITEMS(advanced_options_items),
};

/******************************************************************************/
/* VB2_SCREEN_RECOVERY_SELECT */

#define RECOVERY_SELECT_ITEM_PHONE 0
#define RECOVERY_SELECT_ITEM_EXTERNAL_DISK 1

vb2_error_t recovery_select_init(struct vb2_ui_context *ui)
{
	if (!vb2api_phone_recovery_enabled(ui->ctx)) {
		VB2_DEBUG("WARNING: Phone recovery not available\n");
		ui->state.disabled_item_mask |=
			1 << RECOVERY_SELECT_ITEM_PHONE;
		ui->state.selected_item = RECOVERY_SELECT_ITEM_EXTERNAL_DISK;
	}
	return VB2_REQUEST_UI_CONTINUE;
}

static const struct vb2_menu_item recovery_select_items[] = {
	[RECOVERY_SELECT_ITEM_PHONE] = {
		.text = "Recovery using phone",
		.target = VB2_SCREEN_RECOVERY_PHONE_STEP1,
	},
	[RECOVERY_SELECT_ITEM_EXTERNAL_DISK] = {
		.text = "Recovery using external disk",
		.target = VB2_SCREEN_RECOVERY_DISK_STEP1,
	},
	ADVANCED_OPTIONS_ITEM,
};

static const struct vb2_screen_info recovery_select_screen = {
	.id = VB2_SCREEN_RECOVERY_SELECT,
	.name = "Recovery method selection",
	.init = recovery_select_init,
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
#define RECOVERY_TO_DEV_ITEM_CANCEL 1

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
	if (!PHYSICAL_PRESENCE_KEYBOARD) {
		ui->state.disabled_item_mask |=
			1 << RECOVERY_TO_DEV_ITEM_CONFIRM;
		ui->state.selected_item = RECOVERY_TO_DEV_ITEM_CANCEL;
	}

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
		VB2_DEBUG("ERROR: Dev transition sanity check failed\n");
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
	[RECOVERY_TO_DEV_ITEM_CANCEL] = {
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
/* VB2_SCREEN_DEVELOPER_MODE */

#define DEVELOPER_MODE_ITEM_RETURN_TO_SECURE 0
#define DEVELOPER_MODE_ITEM_BOOT_INTERNAL 1
#define DEVELOPER_MODE_ITEM_BOOT_EXTERNAL 2

vb2_error_t developer_mode_init(struct vb2_ui_context *ui)
{
	enum vb2_dev_default_boot default_boot =
		vb2_get_dev_boot_target(ui->ctx);

	/* Get me outta here! */
	if (!vb2_dev_boot_allowed(ui->ctx))
		vb2_ui_change_screen(ui, VB2_SCREEN_DEVELOPER_TO_NORM);

	/* Don't show "Return to secure mode" button if GBB forces dev mode. */
	if (vb2_get_gbb(ui->ctx)->flags & VB2_GBB_FLAG_FORCE_DEV_SWITCH_ON)
		ui->state.disabled_item_mask |=
			1 << DEVELOPER_MODE_ITEM_RETURN_TO_SECURE;

	/* Don't show "Boot from external disk" button if not allowed. */
	if (!vb2_dev_boot_usb_allowed(ui->ctx))
		ui->state.disabled_item_mask |=
			1 << DEVELOPER_MODE_ITEM_BOOT_EXTERNAL;

	/* Choose the default selection. */
	switch (default_boot) {
	case VB2_DEV_DEFAULT_BOOT_USB:
		ui->state.selected_item = DEVELOPER_MODE_ITEM_BOOT_EXTERNAL;
		break;
	default:
		ui->state.selected_item = DEVELOPER_MODE_ITEM_BOOT_INTERNAL;
		break;
	}

	ui->start_time = VbExGetTimer();

	return VB2_REQUEST_UI_CONTINUE;
}

vb2_error_t vb2_ui_developer_mode_boot_internal_action(
	struct vb2_ui_context *ui)
{
	if (!(ui->ctx->flags & VB2_CONTEXT_DEVELOPER_MODE) ||
	    !vb2_dev_boot_allowed(ui->ctx)) {
		VB2_DEBUG("ERROR: Dev mode internal boot not allowed\n");
		return VB2_REQUEST_UI_CONTINUE;
	}

	if (VbTryLoadKernel(ui->ctx, VB_DISK_FLAG_FIXED)) {
		VB2_DEBUG("ERROR: Dev mode internal boot failed\n");
		return VB2_REQUEST_UI_CONTINUE;
	}

	return VB2_SUCCESS;
}

vb2_error_t vb2_ui_developer_mode_boot_external_action(
	struct vb2_ui_context *ui)
{
	/* Sanity check, should never happen. */
	if (!(ui->ctx->flags & VB2_CONTEXT_DEVELOPER_MODE) ||
	    !vb2_dev_boot_allowed(ui->ctx) ||
	    !vb2_dev_boot_usb_allowed(ui->ctx)) {
		VB2_DEBUG("ERROR: Dev mode external boot not allowed\n");
		return VB2_REQUEST_UI_CONTINUE;
	}

	if (VbTryLoadKernel(ui->ctx, VB_DISK_FLAG_REMOVABLE)) {
		VB2_DEBUG("ERROR: Dev mode external boot failed\n");
		return VB2_REQUEST_UI_CONTINUE;
	}

	return VB2_SUCCESS;
}

vb2_error_t developer_mode_action(struct vb2_ui_context *ui)
{
	struct vb2_gbb_header *gbb = vb2_get_gbb(ui->ctx);
	const int use_short = gbb->flags & VB2_GBB_FLAG_DEV_SCREEN_SHORT_DELAY;
	uint64_t elapsed;

	/* Once any user interaction occurs, stop the timer. */
	if (ui->key)
		ui->disable_timer = 1;
	if (ui->disable_timer)
		return VB2_REQUEST_UI_CONTINUE;

	elapsed = VbExGetTimer() - ui->start_time;

	/* If we're using short delay, wait 2 seconds and don't beep. */
	if (use_short && elapsed > 2 * VB_USEC_PER_SEC) {
		VB2_DEBUG("Booting default target after 2s\n");
		ui->disable_timer = 1;
		return vb2_ui_menu_select_action(ui);
	}

	/* Otherwise, beep at 20 and 20.5 seconds. */
	if ((ui->beep_count == 0 && elapsed > 20 * VB_USEC_PER_SEC) ||
	    (ui->beep_count == 1 && elapsed > 20500 * VB_USEC_PER_MSEC)) {
		VbExBeep(250, 400);
		ui->beep_count++;
	}

	/* Stop after 30 seconds. */
	if (elapsed > 30 * VB_USEC_PER_SEC) {
		VB2_DEBUG("Booting default target after 30s\n");
		ui->disable_timer = 1;
		return vb2_ui_menu_select_action(ui);
	}

	return VB2_REQUEST_UI_CONTINUE;
}

static const struct vb2_menu_item developer_mode_items[] = {
	[DEVELOPER_MODE_ITEM_RETURN_TO_SECURE] = {
		.text = "Return to secure mode",
		.target = VB2_SCREEN_DEVELOPER_TO_NORM,
	},
	[DEVELOPER_MODE_ITEM_BOOT_INTERNAL] = {
		.text = "Boot from internal disk",
		.action = vb2_ui_developer_mode_boot_internal_action,
	},
	[DEVELOPER_MODE_ITEM_BOOT_EXTERNAL] = {
		.text = "Boot from external disk",
		.action = vb2_ui_developer_mode_boot_external_action,
	},
	ADVANCED_OPTIONS_ITEM,
};

static const struct vb2_screen_info developer_mode_screen = {
	.id = VB2_SCREEN_DEVELOPER_MODE,
	.name = "Developer mode",
	.init = developer_mode_init,
	.action = developer_mode_action,
	MENU_ITEMS(developer_mode_items),
};

/******************************************************************************/
/* VB2_SCREEN_DEVELOPER_TO_NORM */

vb2_error_t developer_to_norm_action(struct vb2_ui_context *ui)
{
	if (vb2_get_gbb(ui->ctx)->flags & VB2_GBB_FLAG_FORCE_DEV_SWITCH_ON) {
		VB2_DEBUG("ERROR: dev mode forced by GBB flag\n");
		return VB2_REQUEST_UI_CONTINUE;
	}

	VB2_DEBUG("Leaving dev mode\n");
	vb2_nv_set(ui->ctx, VB2_NV_DISABLE_DEV_REQUEST, 1);
	return VB2_REQUEST_REBOOT;
}

static const struct vb2_menu_item developer_to_norm_items[] = {
	{
		.text = "Confirm",
		.action = developer_to_norm_action,
	},
	{
		.text = "Cancel",
		.action = vb2_ui_back_action,
	},
};

static const struct vb2_screen_info developer_to_norm_screen = {
	.id = VB2_SCREEN_DEVELOPER_TO_NORM,
	.name = "Transition to normal mode",
	MENU_ITEMS(developer_to_norm_items),
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
	&developer_mode_screen,
	&developer_to_norm_screen,
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
