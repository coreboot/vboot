/* Copyright 2020 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Tests for UI related actions.
 */

#include "2api.h"
#include "2common.h"
#include "2misc.h"
#include "2nvstorage.h"
#include "2ui.h"
#include "2ui_private.h"
#include "test_common.h"
#include "vboot_kernel.h"

/* Fixed value for ignoring some checks. */
#define MOCK_IGNORE 0xffffu

/* Mock screen index for testing screen utility functions. */
#define MOCK_NO_SCREEN 0xef0
#define MOCK_SCREEN_BASE 0xeff
#define MOCK_SCREEN_MENU 0xfff
#define MOCK_SCREEN_TARGET0 0xff0
#define MOCK_SCREEN_TARGET1 0xff1
#define MOCK_SCREEN_TARGET2 0xff2
#define MOCK_SCREEN_TARGET3 0xff3
#define MOCK_SCREEN_TARGET4 0xff4

/* Mock data */
struct display_call {
	const struct vb2_screen_info *screen;
	uint32_t locale_id;
	uint32_t selected_item;
	uint32_t disabled_item_mask;
};

static uint8_t workbuf[VB2_KERNEL_WORKBUF_RECOMMENDED_SIZE]
	__attribute__((aligned(VB2_WORKBUF_ALIGN)));
static struct vb2_context *ctx;
static struct vb2_gbb_header gbb;

static int mock_calls_until_shutdown;

static struct vb2_ui_context mock_ui_context;
static struct vb2_screen_state *mock_state;

static struct display_call mock_displayed[64];
static int mock_displayed_count;
static int mock_displayed_i;

static uint32_t mock_key[64];
static int mock_key_trusted[64];
static int mock_key_count;
static int mock_key_total;

static enum vb2_screen mock_get_screen_info_last;

static vb2_error_t mock_vbtlk_retval;
static uint32_t mock_vbtlk_expected_flag;

/* Mock screens */
const struct vb2_menu_item mock_empty_menu[] = {};
struct vb2_screen_info mock_screen_blank = {
	.id = VB2_SCREEN_BLANK,
	.name = "mock_screen_blank",
	.num_items = ARRAY_SIZE(mock_empty_menu),
	.items = mock_empty_menu,
};
struct vb2_screen_info mock_screen_base = {
	.id = MOCK_SCREEN_BASE,
	.name = "mock_screen_base: menuless screen",
	.num_items = ARRAY_SIZE(mock_empty_menu),
	.items = mock_empty_menu,
};
struct vb2_menu_item mock_screen_menu_items[] = {
	{
		.text = "option 0",
		.target = MOCK_SCREEN_TARGET0,
	},
	{
		.text = "option 1",
		.target = MOCK_SCREEN_TARGET1,
	},
	{
		.text = "option 2",
		.target = MOCK_SCREEN_TARGET2,
	},
	{
		.text = "option 3",
		.target = MOCK_SCREEN_TARGET3,
	},
	{
		.text = "option 4 (no target)",
	},
};
const struct vb2_screen_info mock_screen_menu = {
	.id = MOCK_SCREEN_MENU,
	.name = "mock_screen_menu: screen with 5 options",
	.num_items = ARRAY_SIZE(mock_screen_menu_items),
	.items = mock_screen_menu_items,
};
const struct vb2_screen_info mock_screen_target0 = {
	.id = MOCK_SCREEN_TARGET0,
	.name = "mock_screen_target0",
	.num_items = ARRAY_SIZE(mock_empty_menu),
	.items = mock_empty_menu,
};
const struct vb2_screen_info mock_screen_target1 = {
	.id = MOCK_SCREEN_TARGET1,
	.name = "mock_screen_target1",
	.num_items = ARRAY_SIZE(mock_empty_menu),
	.items = mock_empty_menu,
};
const struct vb2_screen_info mock_screen_target2 = {
	.id = MOCK_SCREEN_TARGET2,
	.name = "mock_screen_target2",
	.num_items = ARRAY_SIZE(mock_empty_menu),
	.items = mock_empty_menu,
};
const struct vb2_screen_info mock_screen_target3 = {
	.id = MOCK_SCREEN_TARGET3,
	.name = "mock_screen_target3",
	.num_items = ARRAY_SIZE(mock_empty_menu),
	.items = mock_empty_menu,
};
const struct vb2_screen_info mock_screen_target4 = {
	.id = MOCK_SCREEN_TARGET4,
	.name = "mock_screen_target4",
	.num_items = ARRAY_SIZE(mock_empty_menu),
	.items = mock_empty_menu,
};

/* Mock actions */
static uint32_t global_action_called;
static vb2_error_t global_action_countdown(struct vb2_ui_context *ui)
{
	if (++global_action_called >= 10)
		return VB2_SUCCESS;
	return VB2_REQUEST_UI_CONTINUE;
}

static vb2_error_t global_action_change_screen(struct vb2_ui_context *ui)
{
	vb2_ui_change_screen(ui, MOCK_SCREEN_BASE);
	return VB2_REQUEST_UI_CONTINUE;
}

static void screen_state_eq(const struct vb2_screen_state *state,
			    enum vb2_screen screen,
			    uint32_t selected_item,
			    uint32_t disabled_item_mask)
{
	if (screen != MOCK_IGNORE) {
		if (state->screen == NULL)
			TEST_TRUE(0, "  state.screen does not exist");
		else
			TEST_EQ(state->screen->id, screen, "  state.screen");
	}
	if (selected_item != MOCK_IGNORE)
		TEST_EQ(state->selected_item,
			selected_item, "  state.selected_item");
	if (disabled_item_mask != MOCK_IGNORE)
		TEST_EQ(state->disabled_item_mask,
			disabled_item_mask, "  state.disabled_item_mask");
}

static void add_mock_key(uint32_t press, int trusted)
{
	if (mock_key_total >= ARRAY_SIZE(mock_key) ||
	    mock_key_total >= ARRAY_SIZE(mock_key_trusted)) {
		TEST_TRUE(0, "  mock_key ran out of entries!");
		return;
	}

	mock_key[mock_key_total] = press;
	mock_key_trusted[mock_key_total] = trusted;
	mock_key_total++;
}

static void add_mock_keypress(uint32_t press)
{
	add_mock_key(press, 0);
}


static void set_mock_vbtlk(vb2_error_t retval, uint32_t get_info_flags)
{
	mock_vbtlk_retval = retval;
	mock_vbtlk_expected_flag = get_info_flags;
}

static void displayed_eq(const char *text,
			 enum vb2_screen screen,
			 uint32_t locale_id,
			 uint32_t selected_item,
			 uint32_t disabled_item_mask)
{
	char text_buf[256];

	if (mock_displayed_i >= mock_displayed_count) {
		sprintf(text_buf, "  missing screen %s", text);
		TEST_TRUE(0, text_buf);
		return;
	}

	if (screen != MOCK_IGNORE) {
		sprintf(text_buf, "  screen of %s", text);
		TEST_EQ(mock_displayed[mock_displayed_i].screen->id, screen,
			text_buf);
	}
	if (locale_id != MOCK_IGNORE) {
		sprintf(text_buf, "  locale_id of %s", text);
		TEST_EQ(mock_displayed[mock_displayed_i].locale_id, locale_id,
			text_buf);
	}
	if (selected_item != MOCK_IGNORE) {
		sprintf(text_buf, "  selected_item of %s", text);
		TEST_EQ(mock_displayed[mock_displayed_i].selected_item,
			selected_item, text_buf);
	}
	if (disabled_item_mask != MOCK_IGNORE) {
		sprintf(text_buf, "  disabled_item_mask of %s", text);
		TEST_EQ(mock_displayed[mock_displayed_i].disabled_item_mask,
			disabled_item_mask, text_buf);
	}
	mock_displayed_i++;
}

static void displayed_no_extra(void)
{
	if (mock_displayed_i == 0)
		TEST_EQ(mock_displayed_count, 0, "  no screen");
	else
		TEST_EQ(mock_displayed_count, mock_displayed_i,
			"  no extra screens");
}

/* Reset mock data (for use before each test) */
static void reset_common_data(void)
{
	TEST_SUCC(vb2api_init(workbuf, sizeof(workbuf), &ctx),
		  "vb2api_init failed");

	memset(&gbb, 0, sizeof(gbb));

	vb2_nv_init(ctx);

	/* For check_shutdown_request */
	mock_calls_until_shutdown = 10;

	/* Mock ui_context based on mock screens */
	mock_ui_context = (struct vb2_ui_context){
		.ctx = ctx,
		.root_screen = &mock_screen_blank,
		.state = (struct vb2_screen_state){
			.screen = &mock_screen_blank,
			.selected_item = 0,
			.disabled_item_mask = 0,
		},
		.locale_id = 0,
		.key = 0,

	};
	mock_state = &mock_ui_context.state;

	/* For vb2ex_display_ui */
	memset(mock_displayed, 0, sizeof(mock_displayed));
	mock_displayed_count = 0;
	mock_displayed_i = 0;

	/* For VbExKeyboardRead */
	memset(mock_key, 0, sizeof(mock_key));
	memset(mock_key_trusted, 0, sizeof(mock_key_trusted));
	mock_key_count = 0;
	mock_key_total = 0;

	/* For global actions */
	global_action_called = 0;

	/* For vb2_get_screen_info */
	mock_get_screen_info_last = -1;

	/* For VbTryLoadKernel */
	mock_vbtlk_retval = VB2_ERROR_MOCK;
	mock_vbtlk_expected_flag = MOCK_IGNORE;
}

/* Mock functions */
struct vb2_gbb_header *vb2_get_gbb(struct vb2_context *c)
{
	return &gbb;
}

uint32_t VbExIsShutdownRequested(void)
{
	if (mock_calls_until_shutdown < 0)  /* Never request shutdown */
		return 0;
	if (mock_calls_until_shutdown == 0)
		return 1;
	mock_calls_until_shutdown--;

	return 0;
}

const struct vb2_screen_info *vb2_get_screen_info(enum vb2_screen screen)
{
	mock_get_screen_info_last = screen;

	switch ((int)screen) {
	case VB2_SCREEN_BLANK:
		return &mock_screen_blank;
	case MOCK_SCREEN_BASE:
		return &mock_screen_base;
	case MOCK_SCREEN_MENU:
		return &mock_screen_menu;
	case MOCK_SCREEN_TARGET0:
		return &mock_screen_target0;
	case MOCK_SCREEN_TARGET1:
		return &mock_screen_target1;
	case MOCK_SCREEN_TARGET2:
		return &mock_screen_target2;
	case MOCK_SCREEN_TARGET3:
		return &mock_screen_target3;
	case MOCK_SCREEN_TARGET4:
		return &mock_screen_target4;
	case MOCK_NO_SCREEN:
		return NULL;
	default:
		return &mock_screen_blank;
	}
}

vb2_error_t vb2ex_display_ui(enum vb2_screen screen,
			     uint32_t locale_id,
			     uint32_t selected_item,
			     uint32_t disabled_item_mask)
{
	VB2_DEBUG("displayed %d: screen = %#x, locale_id = %u, "
		  "selected_item = %u, disabled_item_mask = %#x\n",
		  mock_displayed_count, screen, locale_id, selected_item,
		  disabled_item_mask);

	if (mock_displayed_count >= ARRAY_SIZE(mock_displayed)) {
		TEST_TRUE(0, "  mock vb2ex_display_ui ran out of entries!");
		return VB2_ERROR_MOCK;
	}

	mock_displayed[mock_displayed_count] = (struct display_call){
		.screen = vb2_get_screen_info(screen),
		.locale_id = locale_id,
		.selected_item = selected_item,
		.disabled_item_mask = disabled_item_mask,
	};
	mock_displayed_count++;

	return VB2_SUCCESS;
}

uint32_t VbExKeyboardRead(void)
{
	return VbExKeyboardReadWithFlags(NULL);
}

uint32_t VbExKeyboardReadWithFlags(uint32_t *key_flags)
{
	if (mock_key_count < mock_key_total) {
		if (key_flags != NULL) {
			if (mock_key_trusted[mock_key_count])
				*key_flags = VB_KEY_FLAG_TRUSTED_KEYBOARD;
			else
				*key_flags = 0;
		}
		return mock_key[mock_key_count++];
	}

	return 0;
}

vb2_error_t VbTryLoadKernel(struct vb2_context *c, uint32_t get_info_flags)
{
	TEST_EQ(mock_vbtlk_expected_flag, get_info_flags,
		"  unexpected get_info_flags");

	return mock_vbtlk_retval;
}

/* Tests */
static void menu_action_tests(void)
{
	int i, target_id;
	char test_name[256];

	VB2_DEBUG("Testing menu actions...\n");

	/* Valid menu_up_action */
	reset_common_data();
	mock_state->screen = &mock_screen_menu;
	mock_state->selected_item = 2;
	mock_ui_context.key = VB_KEY_UP;
	TEST_EQ(menu_up_action(&mock_ui_context), VB2_REQUEST_UI_CONTINUE,
		"valid menu_up_action");
	screen_state_eq(mock_state, MOCK_SCREEN_MENU, 1, MOCK_IGNORE);

	/* Valid menu_up_action with mask */
	reset_common_data();
	mock_state->screen = &mock_screen_menu;
	mock_state->selected_item = 2;
	mock_state->disabled_item_mask = 0x0a;  /* 0b01010 */
	mock_ui_context.key = VB_KEY_UP;
	TEST_EQ(menu_up_action(&mock_ui_context), VB2_REQUEST_UI_CONTINUE,
		"valid menu_up_action with mask");
	screen_state_eq(mock_state, MOCK_SCREEN_MENU, 0, MOCK_IGNORE);

	/* Invalid menu_up_action (blocked) */
	reset_common_data();
	mock_state->screen = &mock_screen_menu;
	mock_state->selected_item = 0;
	mock_ui_context.key = VB_KEY_UP;
	TEST_EQ(menu_up_action(&mock_ui_context), VB2_REQUEST_UI_CONTINUE,
		"invalid menu_up_action (blocked)");
	screen_state_eq(mock_state, MOCK_SCREEN_MENU, 0, MOCK_IGNORE);

	/* Invalid menu_up_action (blocked by mask) */
	reset_common_data();
	mock_state->screen = &mock_screen_menu;
	mock_state->selected_item = 2;
	mock_state->disabled_item_mask = 0x0b;  /* 0b01011 */
	mock_ui_context.key = VB_KEY_UP;
	TEST_EQ(menu_up_action(&mock_ui_context), VB2_REQUEST_UI_CONTINUE,
		"invalid menu_up_action (blocked by mask)");
	screen_state_eq(mock_state, MOCK_SCREEN_MENU, 2, MOCK_IGNORE);

	/* Ignore volume-up when not DETACHABLE */
	if (!DETACHABLE) {
		reset_common_data();
		mock_state->screen = &mock_screen_menu;
		mock_state->selected_item = 2;
		mock_ui_context.key = VB_BUTTON_VOL_UP_SHORT_PRESS;
		TEST_EQ(menu_up_action(&mock_ui_context),
			VB2_REQUEST_UI_CONTINUE,
			"ignore volume-up when not DETACHABLE");
		screen_state_eq(mock_state, MOCK_SCREEN_MENU, 2, MOCK_IGNORE);
	}

	/* Valid menu_down_action */
	reset_common_data();
	mock_state->screen = &mock_screen_menu;
	mock_state->selected_item = 2;
	mock_ui_context.key = VB_KEY_DOWN;
	TEST_EQ(menu_down_action(&mock_ui_context), VB2_REQUEST_UI_CONTINUE,
		"valid menu_down_action");
	screen_state_eq(mock_state, MOCK_SCREEN_MENU, 3, MOCK_IGNORE);

	/* Valid menu_down_action with mask */
	reset_common_data();
	mock_state->screen = &mock_screen_menu;
	mock_state->selected_item = 2;
	mock_state->disabled_item_mask = 0x0a;  /* 0b01010 */
	mock_ui_context.key = VB_KEY_DOWN;
	TEST_EQ(menu_down_action(&mock_ui_context), VB2_REQUEST_UI_CONTINUE,
		"valid menu_down_action with mask");
	screen_state_eq(mock_state, MOCK_SCREEN_MENU, 4, MOCK_IGNORE);

	/* Invalid menu_down_action (blocked) */
	reset_common_data();
	mock_state->screen = &mock_screen_menu;
	mock_state->selected_item = 4;
	mock_ui_context.key = VB_KEY_DOWN;
	TEST_EQ(menu_down_action(&mock_ui_context), VB2_REQUEST_UI_CONTINUE,
		"invalid menu_down_action (blocked)");
	screen_state_eq(mock_state, MOCK_SCREEN_MENU, 4, MOCK_IGNORE);

	/* Invalid menu_down_action (blocked by mask) */
	reset_common_data();
	mock_state->screen = &mock_screen_menu;
	mock_state->selected_item = 2;
	mock_state->disabled_item_mask = 0x1a;  /* 0b11010 */
	mock_ui_context.key = VB_KEY_DOWN;
	TEST_EQ(menu_down_action(&mock_ui_context), VB2_REQUEST_UI_CONTINUE,
		"invalid menu_down_action (blocked by mask)");
	screen_state_eq(mock_state, MOCK_SCREEN_MENU, 2, MOCK_IGNORE);

	/* Ignore volume-down when not DETACHABLE */
	if (!DETACHABLE) {
		reset_common_data();
		mock_state->screen = &mock_screen_menu;
		mock_state->selected_item = 2;
		mock_ui_context.key = VB_BUTTON_VOL_DOWN_SHORT_PRESS;
		TEST_EQ(menu_down_action(&mock_ui_context),
			VB2_REQUEST_UI_CONTINUE,
			"ignore volume-down when not DETACHABLE");
		screen_state_eq(mock_state, MOCK_SCREEN_MENU, 2, MOCK_IGNORE);
	}

	/* menu_select_action with no item screen */
	reset_common_data();
	mock_state->screen = &mock_screen_base;
	mock_ui_context.key = VB_KEY_ENTER;
	TEST_EQ(vb2_ui_menu_select_action(&mock_ui_context),
		VB2_REQUEST_UI_CONTINUE,
		"menu_select_action with no item screen");
	screen_state_eq(mock_state, MOCK_SCREEN_BASE, 0, MOCK_IGNORE);

	/* Try to select target 0..3 */
	for (i = 0; i <= 3; i++) {
		sprintf(test_name, "select target %d", i);
		target_id = MOCK_SCREEN_TARGET0 + i;
		reset_common_data();
		mock_state->screen = &mock_screen_menu;
		mock_state->selected_item = i;
		mock_ui_context.key = VB_KEY_ENTER;
		TEST_EQ(vb2_ui_menu_select_action(&mock_ui_context),
			VB2_REQUEST_UI_CONTINUE, test_name);
		screen_state_eq(mock_state, target_id, 0, MOCK_IGNORE);
	}

	/* Try to select no target item */
	reset_common_data();
	mock_state->screen = &mock_screen_menu;
	mock_state->selected_item = 4;
	mock_ui_context.key = VB_KEY_ENTER;
	TEST_EQ(vb2_ui_menu_select_action(&mock_ui_context),
		VB2_REQUEST_UI_CONTINUE,
		"select no target");
	screen_state_eq(mock_state, MOCK_SCREEN_MENU, 4, MOCK_IGNORE);

	/* Ignore power button short press when not DETACHABLE */
	if (!DETACHABLE) {
		reset_common_data();
		mock_state->screen = &mock_screen_menu;
		mock_state->selected_item = 1;
		mock_ui_context.key = VB_BUTTON_POWER_SHORT_PRESS;
		TEST_EQ(vb2_ui_menu_select_action(&mock_ui_context),
			VB2_REQUEST_UI_CONTINUE,
			"ignore power button short press when not DETACHABLE");
		screen_state_eq(mock_state, MOCK_SCREEN_MENU, 1, MOCK_IGNORE);
	}

	/* vb2_ui_back_action */
	reset_common_data();
	mock_ui_context.key = VB_KEY_ESC;
	TEST_EQ(vb2_ui_back_action(&mock_ui_context), VB2_REQUEST_UI_CONTINUE,
		"vb2_ui_back_action");
	screen_state_eq(mock_state, VB2_SCREEN_BLANK, 0, MOCK_IGNORE);

	VB2_DEBUG("...done.\n");
}

static void ui_loop_tests(void)
{
	VB2_DEBUG("Testing ui_loop...\n");

	/* Die if no root screen */
	reset_common_data();
	TEST_ABORT(ui_loop(ctx, MOCK_NO_SCREEN, NULL),
		   "die if no root screen");
	displayed_no_extra();

	/* Shutdown if requested */
	reset_common_data();
	TEST_EQ(ui_loop(ctx, MOCK_SCREEN_BASE, NULL),
		VB2_REQUEST_SHUTDOWN, "shutdown if requested");
	TEST_EQ(mock_calls_until_shutdown, 0, "  used up shutdown request");
	displayed_eq("mock_screen_base", MOCK_SCREEN_BASE, MOCK_IGNORE,
		     MOCK_IGNORE, MOCK_IGNORE);
	displayed_no_extra();

	/* Global action */
	reset_common_data();
	mock_calls_until_shutdown = -1;
	TEST_EQ(ui_loop(ctx, VB2_SCREEN_BLANK, global_action_countdown),
		VB2_SUCCESS, "global action");
	TEST_EQ(global_action_called, 10, "  global action called");

	/* Global action can change screen */
	reset_common_data();
	TEST_EQ(ui_loop(ctx, VB2_SCREEN_BLANK, global_action_change_screen),
		VB2_REQUEST_SHUTDOWN, "global action can change screen");
	displayed_eq("pass", MOCK_IGNORE, MOCK_IGNORE, MOCK_IGNORE,
		     MOCK_IGNORE);
	displayed_eq("change to mock_screen_base", MOCK_IGNORE, MOCK_IGNORE,
		     MOCK_IGNORE, MOCK_IGNORE);

	/* KEY_UP, KEY_DOWN, and KEY_ENTER navigation */
	reset_common_data();
	add_mock_keypress(VB_KEY_UP);  /* (blocked) */
	add_mock_keypress(VB_KEY_DOWN);
	add_mock_keypress(VB_KEY_DOWN);
	add_mock_keypress(VB_KEY_DOWN);
	add_mock_keypress(VB_KEY_DOWN);
	add_mock_keypress(VB_KEY_DOWN);  /* (blocked) */
	add_mock_keypress(VB_KEY_UP);
	add_mock_keypress(VB_KEY_ENTER);
	TEST_EQ(ui_loop(ctx, MOCK_SCREEN_MENU, NULL),
		VB2_REQUEST_SHUTDOWN, "KEY_UP, KEY_DOWN, and KEY_ENTER");
	displayed_eq("mock_screen_menu", MOCK_SCREEN_MENU, MOCK_IGNORE, 0,
		     MOCK_IGNORE);
	displayed_eq("mock_screen_menu", MOCK_SCREEN_MENU, MOCK_IGNORE, 1,
		     MOCK_IGNORE);
	displayed_eq("mock_screen_menu", MOCK_SCREEN_MENU, MOCK_IGNORE, 2,
		     MOCK_IGNORE);
	displayed_eq("mock_screen_menu", MOCK_SCREEN_MENU, MOCK_IGNORE, 3,
		     MOCK_IGNORE);
	displayed_eq("mock_screen_menu", MOCK_SCREEN_MENU, MOCK_IGNORE, 4,
		     MOCK_IGNORE);
	displayed_eq("mock_screen_menu", MOCK_SCREEN_MENU, MOCK_IGNORE, 3,
		     MOCK_IGNORE);
	displayed_eq("mock_screen_target_3", MOCK_SCREEN_TARGET3, MOCK_IGNORE,
		     MOCK_IGNORE, MOCK_IGNORE);
	displayed_no_extra();

	/* For DETACHABLE */
	if (DETACHABLE) {
		reset_common_data();
		add_mock_keypress(VB_BUTTON_VOL_UP_SHORT_PRESS);
		add_mock_keypress(VB_BUTTON_VOL_DOWN_SHORT_PRESS);
		add_mock_keypress(VB_BUTTON_VOL_DOWN_SHORT_PRESS);
		add_mock_keypress(VB_BUTTON_VOL_DOWN_SHORT_PRESS);
		add_mock_keypress(VB_BUTTON_VOL_DOWN_SHORT_PRESS);
		add_mock_keypress(VB_BUTTON_VOL_DOWN_SHORT_PRESS);
		add_mock_keypress(VB_BUTTON_VOL_UP_SHORT_PRESS);
		add_mock_keypress(VB_BUTTON_POWER_SHORT_PRESS);
		TEST_EQ(ui_loop(ctx, MOCK_SCREEN_MENU, NULL),
			VB2_REQUEST_SHUTDOWN, "DETACHABLE");
		displayed_eq("mock_screen_menu", MOCK_SCREEN_MENU, MOCK_IGNORE,
			     0, MOCK_IGNORE);
		displayed_eq("mock_screen_menu", MOCK_SCREEN_MENU, MOCK_IGNORE,
			     1, MOCK_IGNORE);
		displayed_eq("mock_screen_menu", MOCK_SCREEN_MENU, MOCK_IGNORE,
			     2, MOCK_IGNORE);
		displayed_eq("mock_screen_menu", MOCK_SCREEN_MENU, MOCK_IGNORE,
			     3, MOCK_IGNORE);
		displayed_eq("mock_screen_menu", MOCK_SCREEN_MENU, MOCK_IGNORE,
			     4, MOCK_IGNORE);
		displayed_eq("mock_screen_menu", MOCK_SCREEN_MENU, MOCK_IGNORE,
			     3, MOCK_IGNORE);
		displayed_eq("mock_screen_target_3", MOCK_SCREEN_TARGET3,
			     MOCK_IGNORE, MOCK_IGNORE, MOCK_IGNORE);
		displayed_no_extra();
	}

	VB2_DEBUG("...done.\n");
}

static void try_recovery_action_tests(void)
{
	VB2_DEBUG("Testing try recovery action...\n");

	/* SUCCESS */
	reset_common_data();
	set_mock_vbtlk(VB2_SUCCESS, VB_DISK_FLAG_REMOVABLE);
	TEST_EQ(try_recovery_action(&mock_ui_context), VB2_SUCCESS,
		"SUCCESS");
	TEST_EQ(mock_get_screen_info_last, -1, "  no change_screen");

	/* NO_DISK_FOUND */
	reset_common_data();
	set_mock_vbtlk(VB2_ERROR_LK_NO_DISK_FOUND, VB_DISK_FLAG_REMOVABLE);
	TEST_EQ(try_recovery_action(&mock_ui_context), VB2_REQUEST_UI_CONTINUE,
		"NO_DISK_FOUND");
	TEST_EQ(mock_get_screen_info_last, VB2_SCREEN_RECOVERY_SELECT,
		"  recovery select screen");

	/* NO_DISK_FOUND -> INVALID_KERNEL -> SUCCESS */
	reset_common_data();
	set_mock_vbtlk(VB2_ERROR_LK_NO_DISK_FOUND, VB_DISK_FLAG_REMOVABLE);
	TEST_EQ(try_recovery_action(&mock_ui_context), VB2_REQUEST_UI_CONTINUE,
		"NO_DISK_FOUND");
	set_mock_vbtlk(VB2_ERROR_LK_INVALID_KERNEL_FOUND,
		       VB_DISK_FLAG_REMOVABLE);
	TEST_EQ(try_recovery_action(&mock_ui_context), VB2_REQUEST_UI_CONTINUE,
		"INVALID_KERNEL");
	set_mock_vbtlk(VB2_SUCCESS, VB_DISK_FLAG_REMOVABLE);
	TEST_EQ(try_recovery_action(&mock_ui_context), VB2_SUCCESS, "SUCCESS");
	TEST_EQ(mock_get_screen_info_last, VB2_SCREEN_RECOVERY_INVALID,
		"  recovery invalid screen");

	/* INVALID_KERNEL */
	reset_common_data();
	set_mock_vbtlk(VB2_ERROR_LK_INVALID_KERNEL_FOUND,
		       VB_DISK_FLAG_REMOVABLE);
	TEST_EQ(try_recovery_action(&mock_ui_context), VB2_REQUEST_UI_CONTINUE,
		"INVALID_KERNEL");
	TEST_EQ(mock_get_screen_info_last, VB2_SCREEN_RECOVERY_INVALID,
		"  recovery invalid screen");

	/* INVALID_KERNEL -> NO_DISK_FOUND -> SUCCESS */
	reset_common_data();
	set_mock_vbtlk(VB2_ERROR_LK_INVALID_KERNEL_FOUND,
		       VB_DISK_FLAG_REMOVABLE);
	TEST_EQ(try_recovery_action(&mock_ui_context), VB2_REQUEST_UI_CONTINUE,
		"INVALID_KERNEL");
	set_mock_vbtlk(VB2_ERROR_LK_NO_DISK_FOUND, VB_DISK_FLAG_REMOVABLE);
	TEST_EQ(try_recovery_action(&mock_ui_context), VB2_REQUEST_UI_CONTINUE,
		"NO_DISK_FOUND");
	set_mock_vbtlk(VB2_SUCCESS, VB_DISK_FLAG_REMOVABLE);
	TEST_EQ(try_recovery_action(&mock_ui_context), VB2_SUCCESS, "SUCCESS");
	TEST_EQ(mock_get_screen_info_last, VB2_SCREEN_RECOVERY_SELECT,
		"  recovery select screen");

	VB2_DEBUG("...done.\n");
}

int main(void)
{
	menu_action_tests();
	ui_loop_tests();
	try_recovery_action_tests();

	return gTestSuccess ? 0 : 255;
}
