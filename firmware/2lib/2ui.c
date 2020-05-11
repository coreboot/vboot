/* Copyright 2020 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * User interfaces for developer and recovery mode menus.
 */

#include "2api.h"
#include "2common.h"
#include "2misc.h"
#include "2nvstorage.h"
#include "2return_codes.h"
#include "2secdata.h"
#include "2ui.h"
#include "2ui_private.h"
#include "vboot_api.h"  /* For VB_SHUTDOWN_REQUEST_POWER_BUTTON */
#include "vboot_kernel.h"

#define KEY_DELAY_MS 20  /* Delay between key scans in UI loops */

/*****************************************************************************/
/* Global variables */

enum power_button_state power_button;
int invalid_disk_last = -1;

/*****************************************************************************/
/* Utility functions */

/**
 * Checks GBB flags against VbExIsShutdownRequested() shutdown request to
 * determine if a shutdown is required.
 *
 * @param ctx		Context pointer
 * @param key		Pressed key (VB_BUTTON_POWER_SHORT_PRESS)
 * @return true if a shutdown is required, or false otherwise.
 */
int shutdown_required(struct vb2_context *ctx, uint32_t key)
{
	struct vb2_gbb_header *gbb = vb2_get_gbb(ctx);
	uint32_t shutdown_request = VbExIsShutdownRequested();

	/*
	 * Ignore power button push until after we have seen it released.
	 * This avoids shutting down immediately if the power button is still
	 * being held on startup. After we've recognized a valid power button
	 * push then don't report the event until after the button is released.
	 */
	if (shutdown_request & VB_SHUTDOWN_REQUEST_POWER_BUTTON) {
		shutdown_request &= ~VB_SHUTDOWN_REQUEST_POWER_BUTTON;
		if (power_button == POWER_BUTTON_RELEASED)
			power_button = POWER_BUTTON_PRESSED;
	} else {
		if (power_button == POWER_BUTTON_PRESSED)
			shutdown_request |= VB_SHUTDOWN_REQUEST_POWER_BUTTON;
		power_button = POWER_BUTTON_RELEASED;
	}

	if (key == VB_BUTTON_POWER_SHORT_PRESS)
		shutdown_request |= VB_SHUTDOWN_REQUEST_POWER_BUTTON;

	/* If desired, ignore shutdown request due to lid closure. */
	if (gbb->flags & VB2_GBB_FLAG_DISABLE_LID_SHUTDOWN)
		shutdown_request &= ~VB_SHUTDOWN_REQUEST_LID_CLOSED;

	/*
	 * In detachables, disable shutdown due to power button.
	 * It is used for menu selection instead.
	 */
	if (DETACHABLE)
		shutdown_request &= ~VB_SHUTDOWN_REQUEST_POWER_BUTTON;

	return !!shutdown_request;
}

/*****************************************************************************/
/* Menu navigation actions */

/**
 * Update selected_item, taking into account disabled indices (from
 * disabled_item_mask).  The selection does not wrap, meaning that we block
 * on the 0 or max index when we hit the top or bottom of the menu.
 */
vb2_error_t menu_up_action(struct vb2_ui_context *ui)
{
	int item;

	if (!DETACHABLE && ui->key == VB_BUTTON_VOL_UP_SHORT_PRESS)
		return VB2_REQUEST_UI_CONTINUE;

	item = ui->state.selected_item - 1;
	while (item >= 0 &&
	       ((1 << item) & ui->state.disabled_item_mask))
		item--;
	/* Only update if item is valid */
	if (item >= 0)
		ui->state.selected_item = item;

	return VB2_REQUEST_UI_CONTINUE;
}

vb2_error_t menu_down_action(struct vb2_ui_context *ui)
{
	int item;

	if (!DETACHABLE && ui->key == VB_BUTTON_VOL_DOWN_SHORT_PRESS)
		return VB2_REQUEST_UI_CONTINUE;

	item = ui->state.selected_item + 1;
	while (item < ui->state.screen->num_items &&
	       ((1 << item) & ui->state.disabled_item_mask))
		item++;
	/* Only update if item is valid */
	if (item < ui->state.screen->num_items)
		ui->state.selected_item = item;

	return VB2_REQUEST_UI_CONTINUE;
}

/**
 * Navigate to the target screen of the current menu item selection.
 */
vb2_error_t vb2_ui_menu_select_action(struct vb2_ui_context *ui)
{
	const struct vb2_menu_item *menu_item;

	if (!DETACHABLE && ui->key == VB_BUTTON_POWER_SHORT_PRESS)
		return VB2_REQUEST_UI_CONTINUE;

	if (ui->state.screen->num_items == 0)
		return VB2_REQUEST_UI_CONTINUE;

	menu_item = &ui->state.screen->items[ui->state.selected_item];

	if (menu_item->action) {
		VB2_DEBUG("Menu item <%s> run action\n", menu_item->text);
		return menu_item->action(ui);
	} else if (menu_item->target) {
		VB2_DEBUG("Menu item <%s> to target screen %#x\n",
			  menu_item->text, menu_item->target);
		return vb2_ui_change_screen(ui, menu_item->target);
	}

	VB2_DEBUG("Menu item <%s> no action or target screen\n",
		  menu_item->text);
	return VB2_REQUEST_UI_CONTINUE;
}

/**
 * Return back to the previous screen.
 */
vb2_error_t vb2_ui_back_action(struct vb2_ui_context *ui)
{
	/* TODO(kitching): Return to previous screen instead of root screen. */
	return vb2_ui_change_screen(ui, ui->root_screen->id);
}

/**
 * Context-dependent keyboard shortcut Ctrl+D.
 *
 * - Manual recovery mode: Change to dev mode transition screen.
 * - Developer mode: Boot from internal disk.
 */
vb2_error_t ctrl_d_action(struct vb2_ui_context *ui)
{
	if (vb2_allow_recovery(ui->ctx))
		return change_to_dev_screen_action(ui);
	else if (ui->ctx->flags & VB2_CONTEXT_DEVELOPER_MODE)
		return vb2_ui_developer_mode_boot_internal_action(ui);

	return VB2_REQUEST_UI_CONTINUE;
}

vb2_error_t change_to_dev_screen_action(struct vb2_ui_context *ui)
{
	if (vb2_allow_recovery(ui->ctx))
		return vb2_ui_change_screen(ui, VB2_SCREEN_RECOVERY_TO_DEV);

	return VB2_REQUEST_UI_CONTINUE;
}

/*****************************************************************************/
/* Action lookup tables */

static struct input_action action_table[] = {
	{ VB_KEY_UP,				menu_up_action },
	{ VB_KEY_DOWN,				menu_down_action },
	{ VB_KEY_ENTER,  			vb2_ui_menu_select_action },
	{ VB_BUTTON_VOL_UP_SHORT_PRESS, 	menu_up_action },
	{ VB_BUTTON_VOL_DOWN_SHORT_PRESS, 	menu_down_action },
	{ VB_BUTTON_POWER_SHORT_PRESS, 		vb2_ui_menu_select_action },
	{ VB_KEY_ESC, 			 	vb2_ui_back_action },
	{ VB_KEY_CTRL('D'),		 	ctrl_d_action },
	{ VB_BUTTON_VOL_DOWN_LONG_PRESS,
	  vb2_ui_developer_mode_boot_internal_action },
	{ VB_BUTTON_VOL_UP_DOWN_COMBO_PRESS,	change_to_dev_screen_action },
	{ ' ',					vb2_ui_recovery_to_dev_action },
	{ VB_KEY_CTRL('U'),
	  vb2_ui_developer_mode_boot_external_action },
	{ VB_BUTTON_VOL_UP_LONG_PRESS,
	  vb2_ui_developer_mode_boot_external_action },
};

vb2_error_t (*input_action_lookup(int key))(struct vb2_ui_context *ui)
{
	int i;
	for (i = 0; i < ARRAY_SIZE(action_table); i++)
		if (action_table[i].key == key)
			return action_table[i].action;
	return NULL;
}

/*****************************************************************************/
/* Core UI functions */

vb2_error_t vb2_ui_change_screen(struct vb2_ui_context *ui, enum vb2_screen id)
{
	const struct vb2_screen_info *new_screen_info = vb2_get_screen_info(id);

	if (new_screen_info == NULL) {
		VB2_DEBUG("ERROR: Screen entry %#x not found; ignoring\n", id);
		return VB2_REQUEST_UI_CONTINUE;
	}

	memset(&ui->state, 0, sizeof(ui->state));
	ui->state.screen = new_screen_info;

	if (ui->state.screen->init)
		return ui->state.screen->init(ui);

	return VB2_REQUEST_UI_CONTINUE;
}

vb2_error_t ui_loop(struct vb2_context *ctx, enum vb2_screen root_screen_id,
		    vb2_error_t (*global_action)(struct vb2_ui_context *ui))
{
	struct vb2_ui_context ui;
	struct vb2_screen_state prev_state;
	uint32_t key_flags;
	vb2_error_t (*action)(struct vb2_ui_context *ui);
	vb2_error_t rv;

	memset(&ui, 0, sizeof(ui));
	ui.ctx = ctx;
	ui.root_screen = vb2_get_screen_info(root_screen_id);
	if (ui.root_screen == NULL)
		VB2_DIE("Root screen not found.\n");
	rv = vb2_ui_change_screen(&ui, ui.root_screen->id);
	if (rv != VB2_REQUEST_UI_CONTINUE)
		return rv;
	memset(&prev_state, 0, sizeof(prev_state));

	while (1) {
		/* Draw if there are state changes. */
		if (memcmp(&prev_state, &ui.state, sizeof(ui.state))) {
			memcpy(&prev_state, &ui.state, sizeof(ui.state));

			VB2_DEBUG("<%s> menu item <%s>\n",
				  ui.state.screen->name,
				  ui.state.screen->num_items ?
				  ui.state.screen->items[
				  ui.state.selected_item].text : "null");

			vb2ex_display_ui(ui.state.screen->id, ui.locale_id,
					 ui.state.selected_item,
					 ui.state.disabled_item_mask);
		}

		/* Run screen action. */
		if (ui.state.screen->action) {
			rv = ui.state.screen->action(&ui);
			if (rv != VB2_REQUEST_UI_CONTINUE)
				return rv;
		}

		/* Grab new keyboard input. */
		ui.key = VbExKeyboardReadWithFlags(&key_flags);
		ui.key_trusted = !!(key_flags & VB_KEY_FLAG_TRUSTED_KEYBOARD);

		/* Check for shutdown request. */
		if (shutdown_required(ctx, ui.key)) {
			VB2_DEBUG("Shutdown required!\n");
			return VB2_REQUEST_SHUTDOWN;
		}

		/* Run input action function if found. */
		action = input_action_lookup(ui.key);
		if (action) {
			rv = action(&ui);
			if (rv != VB2_REQUEST_UI_CONTINUE)
				return rv;
		} else if (ui.key) {
			VB2_DEBUG("Pressed key %#x, trusted? %d\n",
				  ui.key, ui.key_trusted);
		}

		/* Reset keyboard input. */
		ui.key = 0;
		ui.key_trusted = 0;

		/* Run global action function if available. */
		if (global_action) {
			rv = global_action(&ui);
			if (rv != VB2_REQUEST_UI_CONTINUE)
				return rv;
		}

		/* Delay. */
		VbExSleepMs(KEY_DELAY_MS);
	}

	return VB2_SUCCESS;
}

/*****************************************************************************/
/* Developer mode */

vb2_error_t vb2_developer_menu(struct vb2_context *ctx)
{
	return ui_loop(ctx, VB2_SCREEN_DEVELOPER_MODE, NULL);
}

/*****************************************************************************/
/* Broken recovery */

vb2_error_t vb2_broken_recovery_menu(struct vb2_context *ctx)
{
	return ui_loop(ctx, VB2_SCREEN_RECOVERY_BROKEN, NULL);
}

/*****************************************************************************/
/* Manual recovery */

vb2_error_t vb2_manual_recovery_menu(struct vb2_context *ctx)
{
	return ui_loop(ctx, VB2_SCREEN_RECOVERY_SELECT, try_recovery_action);
}

vb2_error_t try_recovery_action(struct vb2_ui_context *ui)
{
	int invalid_disk;
	vb2_error_t rv = VbTryLoadKernel(ui->ctx, VB_DISK_FLAG_REMOVABLE);

	if (rv == VB2_SUCCESS)
		return rv;

	/* If disk validity state changed, switch to appropriate screen. */
	invalid_disk = rv != VB2_ERROR_LK_NO_DISK_FOUND;
	if (invalid_disk_last != invalid_disk) {
		invalid_disk_last = invalid_disk;
		return vb2_ui_change_screen(ui, invalid_disk ?
					    VB2_SCREEN_RECOVERY_INVALID :
					    VB2_SCREEN_RECOVERY_SELECT);
	}

	return VB2_REQUEST_UI_CONTINUE;
}
