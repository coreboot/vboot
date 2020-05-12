/* Copyright 2020 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Tests for UI utility functions.
 */

#include "2api.h"
#include "2common.h"
#include "2misc.h"
#include "2nvstorage.h"
#include "2ui.h"
#include "2ui_private.h"
#include "test_common.h"
#include "vboot_api.h"

/* Fixed value for ignoring some checks. */
#define MOCK_IGNORE 0xffffu

/* Mock screen index for testing screen utility functions. */
#define MOCK_NO_SCREEN 0xef0
#define MOCK_SCREEN_BASE 0xeff
#define MOCK_SCREEN_MENU 0xfff

/* Mock data */
static uint8_t workbuf[VB2_KERNEL_WORKBUF_RECOMMENDED_SIZE]
	__attribute__((aligned(VB2_WORKBUF_ALIGN)));
static struct vb2_context *ctx;
static struct vb2_gbb_header gbb;

static int mock_shutdown_request;

static struct vb2_ui_context mock_ui_context;
static struct vb2_screen_state *mock_state;

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
	},
	{
		.text = "option 1",
	},
	{
		.text = "option 2",
	},
	{
		.text = "option 3",
	},
	{
		.text = "option 4",
	},
};
const struct vb2_screen_info mock_screen_menu = {
	.id = MOCK_SCREEN_MENU,
	.name = "mock_screen_menu: screen with 5 options",
	.num_items = ARRAY_SIZE(mock_screen_menu_items),
	.items = mock_screen_menu_items,
};

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

/* Reset mock data (for use before each test) */
static void reset_common_data(void)
{
	TEST_SUCC(vb2api_init(workbuf, sizeof(workbuf), &ctx),
		  "vb2api_init failed");

	memset(&gbb, 0, sizeof(gbb));

	vb2_nv_init(ctx);

	/* For shutdown_required */
	power_button = POWER_BUTTON_HELD_SINCE_BOOT;
	mock_shutdown_request = MOCK_IGNORE;

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
}

/* Mock functions */
struct vb2_gbb_header *vb2_get_gbb(struct vb2_context *c)
{
	return &gbb;
}

uint32_t VbExIsShutdownRequested(void)
{
	if (mock_shutdown_request != MOCK_IGNORE)
		return mock_shutdown_request;

	return 0;
}

const struct vb2_screen_info *vb2_get_screen_info(enum vb2_screen screen)
{
	switch ((int)screen) {
	case VB2_SCREEN_BLANK:
		return &mock_screen_blank;
	case MOCK_SCREEN_BASE:
		return &mock_screen_base;
	case MOCK_SCREEN_MENU:
		return &mock_screen_menu;
	default:
		return NULL;
	}
}

/* Tests */
static void shutdown_required_tests(void)
{
	VB2_DEBUG("Testing shutdown_required...\n");

	/* Release, press, hold, and release */
	if (!DETACHABLE) {
		reset_common_data();
		mock_shutdown_request = 0;
		TEST_EQ(shutdown_required(ctx, 0), 0,
			"release, press, hold, and release");
		mock_shutdown_request = VB_SHUTDOWN_REQUEST_POWER_BUTTON;
		TEST_EQ(shutdown_required(ctx, 0), 0, "  press");
		TEST_EQ(shutdown_required(ctx, 0), 0, "  hold");
		mock_shutdown_request = 0;
		TEST_EQ(shutdown_required(ctx, 0), 1, "  release");
	}

	/* Press is ignored because we may held since boot */
	if (!DETACHABLE) {
		reset_common_data();
		mock_shutdown_request = VB_SHUTDOWN_REQUEST_POWER_BUTTON;
		TEST_EQ(shutdown_required(ctx, 0), 0, "press is ignored");
	}

	/* Power button short press from key */
	if (!DETACHABLE) {
		reset_common_data();
		mock_shutdown_request = 0;
		TEST_EQ(shutdown_required(ctx, VB_BUTTON_POWER_SHORT_PRESS), 1,
			"power button short press");
	}

	/* Lid closure = shutdown request anyway */
	reset_common_data();
	mock_shutdown_request = VB_SHUTDOWN_REQUEST_LID_CLOSED;
	TEST_EQ(shutdown_required(ctx, 0), 1, "lid closure");
	TEST_EQ(shutdown_required(ctx, 'A'), 1, "  lidsw + random key");

	/* Lid ignored by GBB flags */
	reset_common_data();
	gbb.flags |= VB2_GBB_FLAG_DISABLE_LID_SHUTDOWN;
	mock_shutdown_request = VB_SHUTDOWN_REQUEST_LID_CLOSED;
	TEST_EQ(shutdown_required(ctx, 0), 0, "lid ignored");
	if (!DETACHABLE) {  /* Power button works for non DETACHABLE */
		mock_shutdown_request = VB_SHUTDOWN_REQUEST_LID_CLOSED |
					VB_SHUTDOWN_REQUEST_POWER_BUTTON;
		TEST_EQ(shutdown_required(ctx, 0), 0, "  lidsw + pwdsw");
		mock_shutdown_request = 0;
		TEST_EQ(shutdown_required(ctx, 0), 1, "  pwdsw release");
	}

	/* Lid ignored; power button short pressed */
	if (!DETACHABLE) {
		reset_common_data();
		gbb.flags |= VB2_GBB_FLAG_DISABLE_LID_SHUTDOWN;
		mock_shutdown_request = VB_SHUTDOWN_REQUEST_LID_CLOSED;
		TEST_EQ(shutdown_required(ctx, VB_BUTTON_POWER_SHORT_PRESS), 1,
			"lid ignored; power button short pressed");
	}

	/* DETACHABLE ignore power button */
	if (DETACHABLE) {
		/* Flag pwdsw */
		reset_common_data();
		mock_shutdown_request = VB_SHUTDOWN_REQUEST_POWER_BUTTON;
		TEST_EQ(shutdown_required(ctx, 0), 0,
			"DETACHABLE: ignore pwdsw");
		mock_shutdown_request = 0;
		TEST_EQ(shutdown_required(ctx, 0), 0,
			"  ignore on release");

		/* Power button short press */
		reset_common_data();
		mock_shutdown_request = 0;
		TEST_EQ(shutdown_required(
		    ctx, VB_BUTTON_POWER_SHORT_PRESS), 0,
		    "DETACHABLE: ignore power button short press");
	}

	VB2_DEBUG("...done.\n");
}

static void change_screen_tests(void)
{
	VB2_DEBUG("Testing change_screen...\n");

	/* Changing screen will clear screen state */
	reset_common_data();
	mock_state->screen = &mock_screen_menu;
	mock_state->selected_item = 2;
	mock_state->disabled_item_mask = 0x10;
	TEST_EQ(change_screen(&mock_ui_context, MOCK_SCREEN_BASE),
		VB2_REQUEST_UI_CONTINUE,
		"change_screen will clear screen state");
	screen_state_eq(mock_state, MOCK_SCREEN_BASE, 0, 0);

	/* Change to screen which does not exist */
	reset_common_data();
	mock_state->screen = &mock_screen_menu;
	TEST_EQ(change_screen(&mock_ui_context, MOCK_NO_SCREEN),
		VB2_REQUEST_UI_CONTINUE,
		"change to screen which does not exist");
	screen_state_eq(mock_state, MOCK_SCREEN_MENU, MOCK_IGNORE, MOCK_IGNORE);

	/* TODO: Change to screen with init */

	VB2_DEBUG("...done.\n");
}

int main(void)
{
	shutdown_required_tests();
	change_screen_tests();

	return gTestSuccess ? 0 : 255;
}
