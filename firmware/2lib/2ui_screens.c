/* Copyright 2020 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Firmware screen definitions.
 */

#include "2api.h"
#include "2common.h"
#include "2misc.h"
#include "2nvstorage.h"
#include "2ui.h"
#include "2ui_private.h"
#include "vboot_api.h"

#define MENU_ITEMS(a) ((struct vb2_menu){ \
	.num_items = ARRAY_SIZE(a), \
	.items = a, \
})

#define LANGUAGE_SELECT_ITEM ((struct vb2_menu_item){ \
	.text = "Language selection", \
	.target = VB2_SCREEN_LANGUAGE_SELECT, \
	.is_language_select = 1, \
})

#define NEXT_ITEM(target_screen) ((struct vb2_menu_item){ \
	.text = "Next", \
	.target = (target_screen), \
})

#define BACK_ITEM ((struct vb2_menu_item){ \
	.text = "Back", \
	.action = vb2_ui_screen_back, \
})

#define ADVANCED_OPTIONS_ITEM ((struct vb2_menu_item){ \
	.text = "Advanced options", \
	.target = VB2_SCREEN_ADVANCED_OPTIONS, \
})

/* Action that will power off the device. */
static vb2_error_t power_off_action(struct vb2_ui_context *ui)
{
	return VB2_REQUEST_SHUTDOWN;
}

#define POWER_OFF_ITEM ((struct vb2_menu_item){ \
	.text = "Power off", \
	.action = power_off_action, \
})

/******************************************************************************/
/*
 * Functions for ui error handling
 */

static vb2_error_t set_ui_error(struct vb2_ui_context *ui,
				enum vb2_ui_error error_code)
{
	/* Keep the first occurring error. */
	if (ui->error_code)
		VB2_DEBUG("When handling ui error %#x, another ui error "
			  "occurred: %#x",
			  ui->error_code, error_code);
	else
		ui->error_code = error_code;
	/* Return to the ui loop to show the error code. */
	return VB2_REQUEST_UI_CONTINUE;
}

static vb2_error_t set_ui_error_and_go_back(struct vb2_ui_context *ui,
					    enum vb2_ui_error error_code)
{
	set_ui_error(ui, error_code);
	return vb2_ui_screen_back(ui);
}

/******************************************************************************/
/*
 * Functions used for log screens
 *
 * Expects that the page_count is valid and page_up_item and page_down_item are
 * assigned to correct menu item indices in all three functions, the
 * current_page is valid in prev and next actions, and the back_item is assigned
 * to a correct menu item index.
 */

static vb2_error_t log_page_update(struct vb2_ui_context *ui,
				   const char *new_log_string)
{
	const struct vb2_screen_info *screen = ui->state->screen;

	if (new_log_string) {
		ui->state->page_count = vb2ex_prepare_log_screen(
			screen->id, ui->locale_id, new_log_string);
		if (ui->state->page_count == 0) {
			VB2_DEBUG("vb2ex_prepare_log_screen failed\n");
			return VB2_ERROR_UI_LOG_INIT;
		}
		if (ui->state->current_page >= ui->state->page_count)
			ui->state->current_page = ui->state->page_count - 1;
		ui->force_display = 1;
	}
	VB2_CLR_BIT(ui->state->disabled_item_mask, screen->page_up_item);
	VB2_CLR_BIT(ui->state->disabled_item_mask, screen->page_down_item);
	if (ui->state->current_page == 0)
		VB2_SET_BIT(ui->state->disabled_item_mask,
			    screen->page_up_item);
	if (ui->state->current_page == ui->state->page_count - 1)
		VB2_SET_BIT(ui->state->disabled_item_mask,
			    screen->page_down_item);

	return VB2_SUCCESS;
}

static vb2_error_t log_page_reset_to_top(struct vb2_ui_context *ui)
{
	const struct vb2_screen_info *screen = ui->state->screen;

	ui->state->current_page = 0;
	ui->state->selected_item = ui->state->page_count > 1
					   ? screen->page_down_item
					   : screen->back_item;
	return log_page_update(ui, NULL);
}

static vb2_error_t log_page_prev_action(struct vb2_ui_context *ui)
{
	/* Validity check. */
	if (ui->state->current_page == 0)
		return VB2_SUCCESS;

	ui->state->current_page--;
	return log_page_update(ui, NULL);
}

static vb2_error_t log_page_next_action(struct vb2_ui_context *ui)
{
	/* Validity check. */
	if (ui->state->current_page == ui->state->page_count - 1)
		return VB2_SUCCESS;

	ui->state->current_page++;
	return log_page_update(ui, NULL);
}

#define PAGE_UP_ITEM ((struct vb2_menu_item){ \
	.text = "Page up", \
	.action = log_page_prev_action, \
})

#define PAGE_DOWN_ITEM ((struct vb2_menu_item){ \
	.text = "Page down", \
	.action = log_page_next_action, \
})

/******************************************************************************/
/* VB2_SCREEN_LANGUAGE_SELECT */

static vb2_error_t language_select_action(struct vb2_ui_context *ui)
{
	vb2_error_t rv;
	ui->locale_id = ui->state->selected_item;
	VB2_DEBUG("Locale changed to %u\n", ui->locale_id);

	/* Write locale id back to nvdata. */
	vb2api_set_locale_id(ui->ctx, ui->locale_id);

	/* Commit nvdata changes immediately, in case of three-finger salute
	   reboot.  Ignore commit errors in recovery mode. */
	rv = vb2ex_commit_data(ui->ctx);
	if (rv && !(ui->ctx->flags & VB2_CONTEXT_RECOVERY_MODE))
		return rv;

	return vb2_ui_screen_back(ui);
}

const struct vb2_menu *vb2_get_language_menu(struct vb2_ui_context *ui)
{
	int i;
	uint32_t num_locales;
	struct vb2_menu_item *items;

	if (ui->language_menu.num_items > 0)
		return &ui->language_menu;

	num_locales = vb2ex_get_locale_count();
	if (num_locales == 0) {
		VB2_DEBUG("WARNING: No locales available; assuming 1 locale\n");
		num_locales = 1;
	}

	items = malloc(num_locales * sizeof(struct vb2_menu_item));
	if (!items) {
		VB2_DEBUG("ERROR: malloc failed for language items\n");
		return NULL;
	}

	for (i = 0; i < num_locales; i++) {
		items[i].text = "Some language";
		items[i].action = language_select_action;
	}

	ui->language_menu.num_items = num_locales;
	ui->language_menu.items = items;
	return &ui->language_menu;
}

static vb2_error_t language_select_init(struct vb2_ui_context *ui)
{
	const struct vb2_menu *menu = vb2_get_menu(ui);
	if (menu->num_items == 0) {
		VB2_DEBUG("ERROR: No menu items found; "
			  "rejecting entering language selection screen\n");
		return vb2_ui_screen_back(ui);
	}
	if (ui->locale_id < menu->num_items) {
		ui->state->selected_item = ui->locale_id;
	} else {
		VB2_DEBUG("WARNING: Current locale not found in menu items; "
			  "initializing selected_item to 0\n");
		ui->state->selected_item = 0;
	}
	return VB2_SUCCESS;
}

static const struct vb2_screen_info language_select_screen = {
	.id = VB2_SCREEN_LANGUAGE_SELECT,
	.name = "Language selection screen",
	.init = language_select_init,
	.get_menu = vb2_get_language_menu,
};

/******************************************************************************/
/* VB2_SCREEN_ADVANCED_OPTIONS */

#define ADVANCED_OPTIONS_ITEM_DEVELOPER_MODE 1
#define ADVANCED_OPTIONS_ITEM_DEBUG_INFO 2

vb2_error_t vb2_advanced_options_init(struct vb2_ui_context *ui)
{
	ui->state->selected_item = ADVANCED_OPTIONS_ITEM_DEVELOPER_MODE;
	if (vb2_get_sd(ui->ctx)->flags & VB2_SD_FLAG_DEV_MODE_ENABLED ||
	    !vb2api_allow_recovery(ui->ctx)) {
		VB2_SET_BIT(ui->state->hidden_item_mask,
			    ADVANCED_OPTIONS_ITEM_DEVELOPER_MODE);
		ui->state->selected_item = ADVANCED_OPTIONS_ITEM_DEBUG_INFO;
	}

	return VB2_SUCCESS;
}

static const struct vb2_menu_item advanced_options_items[] = {
	LANGUAGE_SELECT_ITEM,
	[ADVANCED_OPTIONS_ITEM_DEVELOPER_MODE] = {
		.text = "Enable developer mode",
		.target = VB2_SCREEN_RECOVERY_TO_DEV,
	},
	[ADVANCED_OPTIONS_ITEM_DEBUG_INFO] = {
		.text = "Debug info",
		.target = VB2_SCREEN_DEBUG_INFO,
	},
	{
		.text = "Firmware log",
		.target = VB2_SCREEN_FIRMWARE_LOG,
	},
	BACK_ITEM,
	POWER_OFF_ITEM,
};

static const struct vb2_screen_info advanced_options_screen = {
	.id = VB2_SCREEN_ADVANCED_OPTIONS,
	.name = "Advanced options",
	.init = vb2_advanced_options_init,
	.menu = MENU_ITEMS(advanced_options_items),
};

/******************************************************************************/
/* VB2_SCREEN_DEBUG_INFO */

#define DEBUG_INFO_ITEM_PAGE_UP 1
#define DEBUG_INFO_ITEM_PAGE_DOWN 2
#define DEBUG_INFO_ITEM_BACK 3

static vb2_error_t debug_info_set_content(struct vb2_ui_context *ui)
{
	const char *log_string = vb2ex_get_debug_info(ui->ctx);
	if (!log_string)
		return set_ui_error_and_go_back(ui, VB2_UI_ERROR_DEBUG_LOG);
	if (vb2_is_error(log_page_update(ui, log_string)))
		return set_ui_error_and_go_back(ui, VB2_UI_ERROR_DEBUG_LOG);
	return VB2_SUCCESS;
}

static vb2_error_t debug_info_init(struct vb2_ui_context *ui)
{
	VB2_TRY(debug_info_set_content(ui));
	if (vb2_is_error(log_page_reset_to_top(ui)))
		return set_ui_error_and_go_back(ui, VB2_UI_ERROR_DEBUG_LOG);
	return VB2_SUCCESS;
}

static vb2_error_t debug_info_reinit(struct vb2_ui_context *ui)
{
	return debug_info_set_content(ui);
}

static const struct vb2_menu_item debug_info_items[] = {
	LANGUAGE_SELECT_ITEM,
	[DEBUG_INFO_ITEM_PAGE_UP] = PAGE_UP_ITEM,
	[DEBUG_INFO_ITEM_PAGE_DOWN] = PAGE_DOWN_ITEM,
	[DEBUG_INFO_ITEM_BACK] = BACK_ITEM,
	POWER_OFF_ITEM,
};

static const struct vb2_screen_info debug_info_screen = {
	.id = VB2_SCREEN_DEBUG_INFO,
	.name = "Debug info",
	.init = debug_info_init,
	.reinit = debug_info_reinit,
	.menu = MENU_ITEMS(debug_info_items),
	.page_up_item = DEBUG_INFO_ITEM_PAGE_UP,
	.page_down_item = DEBUG_INFO_ITEM_PAGE_DOWN,
	.back_item = DEBUG_INFO_ITEM_BACK,
};

/******************************************************************************/
/* VB2_SCREEN_FIRMWARE_LOG */

#define FIRMWARE_LOG_ITEM_PAGE_UP 1
#define FIRMWARE_LOG_ITEM_PAGE_DOWN 2
#define FIRMWARE_LOG_ITEM_BACK 3

static vb2_error_t firmware_log_set_content(struct vb2_ui_context *ui,
					    int reset)
{
	const char *log_string = vb2ex_get_firmware_log(reset);
	if (!log_string)
		return set_ui_error_and_go_back(ui, VB2_UI_ERROR_FIRMWARE_LOG);
	if (vb2_is_error(log_page_update(ui, log_string)))
		return set_ui_error_and_go_back(ui, VB2_UI_ERROR_FIRMWARE_LOG);
	return VB2_SUCCESS;
}

static vb2_error_t firmware_log_init(struct vb2_ui_context *ui)
{
	VB2_TRY(firmware_log_set_content(ui, 1));
	if (vb2_is_error(log_page_reset_to_top(ui)))
		return set_ui_error_and_go_back(ui, VB2_UI_ERROR_FIRMWARE_LOG);
	return VB2_SUCCESS;
}

static vb2_error_t firmware_log_reinit(struct vb2_ui_context *ui)
{
	return firmware_log_set_content(ui, 0);
}

static const struct vb2_menu_item firmware_log_items[] = {
	LANGUAGE_SELECT_ITEM,
	[FIRMWARE_LOG_ITEM_PAGE_UP] = PAGE_UP_ITEM,
	[FIRMWARE_LOG_ITEM_PAGE_DOWN] = PAGE_DOWN_ITEM,
	[FIRMWARE_LOG_ITEM_BACK] = BACK_ITEM,
	POWER_OFF_ITEM,
};

static const struct vb2_screen_info firmware_log_screen = {
	.id = VB2_SCREEN_FIRMWARE_LOG,
	.name = "Firmware log",
	.init = firmware_log_init,
	.reinit = firmware_log_reinit,
	.menu = MENU_ITEMS(firmware_log_items),
	.page_up_item = FIRMWARE_LOG_ITEM_PAGE_UP,
	.page_down_item = FIRMWARE_LOG_ITEM_PAGE_DOWN,
	.back_item = FIRMWARE_LOG_ITEM_BACK,
};

/******************************************************************************/
/* VB2_SCREEN_RECOVERY_TO_DEV */

#define RECOVERY_TO_DEV_ITEM_CONFIRM 1
#define RECOVERY_TO_DEV_ITEM_CANCEL 2

vb2_error_t recovery_to_dev_init(struct vb2_ui_context *ui)
{
	if (vb2_get_sd(ui->ctx)->flags & VB2_SD_FLAG_DEV_MODE_ENABLED)
		/* We're in dev mode, so let user know they can't transition */
		return set_ui_error_and_go_back(
			ui, VB2_UI_ERROR_DEV_MODE_ALREADY_ENABLED);

	if (!PHYSICAL_PRESENCE_KEYBOARD && vb2ex_physical_presence_pressed()) {
		VB2_DEBUG("Presence button stuck?\n");
		return vb2_ui_screen_back(ui);
	}

	ui->state->selected_item = RECOVERY_TO_DEV_ITEM_CONFIRM;

	/* Disable "Confirm" button for other physical presence types. */
	if (!PHYSICAL_PRESENCE_KEYBOARD) {
		VB2_SET_BIT(ui->state->hidden_item_mask,
			    RECOVERY_TO_DEV_ITEM_CONFIRM);
		ui->state->selected_item = RECOVERY_TO_DEV_ITEM_CANCEL;
	}

	ui->physical_presence_button_pressed = 0;

	return VB2_SUCCESS;
}

static vb2_error_t recovery_to_dev_finalize(struct vb2_ui_context *ui)
{
	VB2_DEBUG("Physical presence confirmed!\n");

	/* Validity check, should never happen. */
	if (ui->state->screen->id != VB2_SCREEN_RECOVERY_TO_DEV ||
	    (vb2_get_sd(ui->ctx)->flags & VB2_SD_FLAG_DEV_MODE_ENABLED) ||
	    !vb2api_allow_recovery(ui->ctx)) {
		VB2_DEBUG("ERROR: Dev transition validity check failed\n");
		return VB2_SUCCESS;
	}

	VB2_DEBUG("Enabling dev mode and rebooting...\n");

	if (vb2api_enable_developer_mode(ui->ctx) != VB2_SUCCESS) {
		VB2_DEBUG("Enable developer mode failed\n");
		return VB2_SUCCESS;
	}

	return VB2_REQUEST_REBOOT_EC_TO_RO;
}

vb2_error_t recovery_to_dev_confirm_action(struct vb2_ui_context *ui)
{
	if (!ui->key_trusted) {
		VB2_DEBUG("Reject untrusted %s confirmation\n",
			  ui->key == VB_KEY_ENTER ? "ENTER" : "POWER");
		/*
		 * If physical presence is confirmed using the keyboard,
		 * beep and notify the user when the ENTER key comes
		 * from an untrusted keyboard.
		 */
		if (PHYSICAL_PRESENCE_KEYBOARD && ui->key == VB_KEY_ENTER)
			return set_ui_error(
				ui, VB2_UI_ERROR_UNTRUSTED_CONFIRMATION);
		return VB2_SUCCESS;
	}
	return recovery_to_dev_finalize(ui);
}

vb2_error_t recovery_to_dev_action(struct vb2_ui_context *ui)
{
	int pressed;

	if (ui->key == ' ') {
		VB2_DEBUG("SPACE means cancel dev mode transition\n");
		return vb2_ui_screen_back(ui);
	}

	/* Keyboard physical presence case covered by "Confirm" action. */
	if (PHYSICAL_PRESENCE_KEYBOARD)
		return VB2_SUCCESS;

	pressed = vb2ex_physical_presence_pressed();
	if (pressed) {
		VB2_DEBUG("Physical presence button pressed, "
			  "awaiting release\n");
		ui->physical_presence_button_pressed = 1;
		return VB2_SUCCESS;
	}
	if (!ui->physical_presence_button_pressed)
		return VB2_SUCCESS;
	VB2_DEBUG("Physical presence button released\n");

	return recovery_to_dev_finalize(ui);
}

static const struct vb2_menu_item recovery_to_dev_items[] = {
	LANGUAGE_SELECT_ITEM,
	[RECOVERY_TO_DEV_ITEM_CONFIRM] = {
		.text = "Confirm",
		.action = recovery_to_dev_confirm_action,
	},
	[RECOVERY_TO_DEV_ITEM_CANCEL] = {
		.text = "Cancel",
		.action = vb2_ui_screen_back,
	},
	POWER_OFF_ITEM,
};

static const struct vb2_screen_info recovery_to_dev_screen = {
	.id = VB2_SCREEN_RECOVERY_TO_DEV,
	.name = "Transition to developer mode",
	.init = recovery_to_dev_init,
	.action = recovery_to_dev_action,
	.menu = MENU_ITEMS(recovery_to_dev_items),
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
	&language_select_screen,
	&advanced_options_screen,
	&debug_info_screen,
	&firmware_log_screen,
	&recovery_to_dev_screen,
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
