/* Copyright 2020 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Tests for developer and recovery mode UIs.
 */

#include "2api.h"
#include "2common.h"
#include "2misc.h"
#include "2nvstorage.h"
#include "2struct.h"
#include "2ui.h"
#include "2ui_private.h"
#include "test_common.h"
#include "vboot_kernel.h"

/* Fixed value for ignoring some checks */
#define MOCK_IGNORE 0xffffu

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
static struct vb2_shared_data *sd;
static struct vb2_gbb_header gbb;

static struct vb2_ui_context mock_ui_context;
static struct vb2_screen_state *mock_state;

static struct display_call mock_displayed[64];
static int mock_displayed_count;
static int mock_displayed_i;

static uint32_t mock_locale_count;

static int mock_calls_until_shutdown;

/* Iteration counter starts from 0
   Mock inputs should response according to this */
static int mock_iters;

static uint32_t mock_key[64];
static int mock_key_trusted[64];
static int mock_key_total;

static uint32_t mock_get_timer_last;
static uint32_t mock_time;
static const uint32_t mock_time_start = 31ULL * VB2_MSEC_PER_SEC;
static int mock_vbexbeep_called;

static enum vb2_dev_default_boot_target mock_default_boot;
static int mock_dev_boot_allowed;
static int mock_dev_boot_legacy_allowed;
static int mock_dev_boot_external_allowed;

static int mock_vbexlegacy_called;
static enum VbAltFwIndex_t mock_altfw_num_last;

static vb2_error_t mock_vbtlk_retval[32];
static uint32_t mock_vbtlk_expected_flag[32];
static int mock_vbtlk_total;

static int mock_allow_recovery;

/* mock_pp_* = mock data for physical presence button */
static int mock_pp_pressed[64];
static int mock_pp_pressed_total;

static int mock_enable_dev_mode;

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

static void add_mock_vbtlk(vb2_error_t retval, uint32_t get_info_flags)
{
	if (mock_vbtlk_total >= ARRAY_SIZE(mock_vbtlk_retval) ||
	    mock_vbtlk_total >= ARRAY_SIZE(mock_vbtlk_expected_flag)) {
		TEST_TRUE(0, "  mock_vbtlk ran out of entries!");
		return;
	}

	mock_vbtlk_retval[mock_vbtlk_total] = retval;
	mock_vbtlk_expected_flag[mock_vbtlk_total] = get_info_flags;
	mock_vbtlk_total++;
}

static void add_mock_pp_pressed(int pressed)
{
	if (mock_pp_pressed_total >= ARRAY_SIZE(mock_pp_pressed)) {
		TEST_TRUE(0, "  mock_pp ran out of entries!");
		return;
	}

	mock_pp_pressed[mock_pp_pressed_total++] = pressed;
}

static void extend_calls_until_shutdown(void)
{
	if (mock_calls_until_shutdown < mock_key_total)
		mock_calls_until_shutdown = mock_key_total;
	if (mock_calls_until_shutdown < mock_vbtlk_total)
		mock_calls_until_shutdown = mock_vbtlk_total;
	if (mock_calls_until_shutdown < mock_pp_pressed_total)
		mock_calls_until_shutdown = mock_pp_pressed_total;
	mock_calls_until_shutdown++;
}

static void displayed_eq(const char *text,
			 enum vb2_screen screen,
			 uint32_t locale_id,
			 uint32_t selected_item,
			 uint32_t disabled_item_mask,
			 int line)
{
	char text_info[32], text_buf[128];

	sprintf(text_info, "(line #%d, displayed #%d)", line, mock_displayed_i);

	if (mock_displayed_i >= mock_displayed_count) {
		sprintf(text_buf, "  %s missing screen %s",
			text_info, text);
		TEST_TRUE(0, text_buf);
		return;
	}

	if (screen != MOCK_IGNORE) {
		sprintf(text_buf, "  %s screen of %s", text_info, text);
		TEST_EQ(mock_displayed[mock_displayed_i].screen->id, screen,
			text_buf);
	}
	if (locale_id != MOCK_IGNORE) {
		sprintf(text_buf, "  %s locale_id of %s", text_info, text);
		TEST_EQ(mock_displayed[mock_displayed_i].locale_id, locale_id,
			text_buf);
	}
	if (selected_item != MOCK_IGNORE) {
		sprintf(text_buf, "  %s selected_item of %s",
			text_info, text);
		TEST_EQ(mock_displayed[mock_displayed_i].selected_item,
			selected_item, text_buf);
	}
	if (disabled_item_mask != MOCK_IGNORE) {
		sprintf(text_buf, "  %s disabled_item_mask of %s",
			text_info, text);
		TEST_EQ(mock_displayed[mock_displayed_i].disabled_item_mask,
			disabled_item_mask, text_buf);
	}
	mock_displayed_i++;
}

static void displayed_no_extra(int line)
{
	char text_info[32], text_buf[128];

	sprintf(text_info, "(line #%d)", line);

	if (mock_displayed_i == 0)
		sprintf(text_buf, "  %s no screen", text_info);
	else
		sprintf(text_buf, "  %s no extra screens", text_info);
	TEST_EQ(mock_displayed_count, mock_displayed_i, text_buf);
}

#define DISPLAYED_EQ(...) displayed_eq(__VA_ARGS__, __LINE__)

#define DISPLAYED_PASS() \
	displayed_eq("", MOCK_IGNORE, MOCK_IGNORE, MOCK_IGNORE, MOCK_IGNORE, \
		     __LINE__)

#define DISPLAYED_NO_EXTRA() displayed_no_extra(__LINE__)

/* Type of test to reset for */
enum reset_type {
	FOR_DEVELOPER,
	FOR_BROKEN_RECOVERY,
	FOR_MANUAL_RECOVERY,
};

/* Reset mock data (for use before each test) */
static void reset_common_data(enum reset_type t)
{
	TEST_SUCC(vb2api_init(workbuf, sizeof(workbuf), &ctx),
		  "vb2api_init failed");

	memset(&gbb, 0, sizeof(gbb));

	vb2_nv_init(ctx);

	sd = vb2_get_sd(ctx);
	sd->status |= VB2_SD_STATUS_SECDATA_KERNEL_INIT;

	if (t == FOR_DEVELOPER) {
		ctx->flags |= VB2_CONTEXT_DEVELOPER_MODE;
		sd->flags |= VB2_SD_FLAG_DEV_MODE_ENABLED;
	}

	/* Mock ui_context based on real screens */
	memset(&mock_ui_context, 0, sizeof(mock_ui_context));
	mock_ui_context.ctx = ctx;
	mock_state = &mock_ui_context.state;

	/* For vb2ex_display_ui */
	memset(mock_displayed, 0, sizeof(mock_displayed));
	mock_displayed_count = 0;
	mock_displayed_i = 0;

	/* For vb2ex_get_locale_count */
	mock_locale_count = 1;

	/* For check_shutdown_request */
	if (t == FOR_DEVELOPER)
		mock_calls_until_shutdown = 2000;  /* Larger than 30s */
	else
		mock_calls_until_shutdown = 10;

	/* For iteration counter */
	mock_iters = -1;  /* Accumulates at the beginning of iterations */

	/* For VbExKeyboardRead */
	memset(mock_key, 0, sizeof(mock_key));
	memset(mock_key_trusted, 0, sizeof(mock_key_trusted));
	mock_key_total = 0;

	/* For vboot_audio.h */
	mock_get_timer_last = 0;
	mock_time = mock_time_start;
	mock_vbexbeep_called = 0;

	/* For dev_boot* in 2misc.h */
	mock_default_boot = VB2_DEV_DEFAULT_BOOT_TARGET_INTERNAL;
	mock_dev_boot_allowed = 1;
	mock_dev_boot_legacy_allowed = 0;
	mock_dev_boot_external_allowed = 0;

	/* For VbExLegacy */
	mock_vbexlegacy_called = 0;
	mock_altfw_num_last = -100;

	/* For VbTryLoadKernel */
	memset(mock_vbtlk_retval, 0, sizeof(mock_vbtlk_retval));
	memset(mock_vbtlk_expected_flag, 0, sizeof(mock_vbtlk_expected_flag));
	mock_vbtlk_total = 0;

	/* For vb2_allow_recovery */
	mock_allow_recovery = t == FOR_MANUAL_RECOVERY;

	/* For vb2ex_physical_presence_pressed */
	memset(mock_pp_pressed, 0, sizeof(mock_pp_pressed));
	mock_pp_pressed_total = 0;

	/* For vb2_enable_developer_mode */
	mock_enable_dev_mode = 0;

	/* Avoid Iteration #0 */
	add_mock_keypress(0);
	if (t == FOR_MANUAL_RECOVERY)
		add_mock_vbtlk(VB2_ERROR_LK_NO_DISK_FOUND,
			       VB_DISK_FLAG_REMOVABLE);
	else
		add_mock_vbtlk(VB2_ERROR_MOCK, 0);
	add_mock_pp_pressed(0);
}

/* Mock functions */
struct vb2_gbb_header *vb2_get_gbb(struct vb2_context *c)
{
	return &gbb;
}

vb2_error_t vb2ex_display_ui(enum vb2_screen screen,
			     uint32_t locale_id,
			     uint32_t selected_item,
			     uint32_t disabled_item_mask)
{
	struct display_call displayed = (struct display_call){
		.screen = vb2_get_screen_info(screen),
		.locale_id = locale_id,
		.selected_item = selected_item,
		.disabled_item_mask = disabled_item_mask,
	};

	/* Ignore repeated calls with same arguments */
	if (mock_displayed_count > 0 &&
	    !memcmp(&mock_displayed[mock_displayed_count - 1], &displayed,
		    sizeof(struct display_call)))
		return VB2_SUCCESS;

	VB2_DEBUG("displayed %d: screen = %#x, locale_id = %u, "
		  "selected_item = %u, disabled_item_mask = %#x\n",
		  mock_displayed_count, screen, locale_id, selected_item,
		  disabled_item_mask);

	if (mock_displayed_count >= ARRAY_SIZE(mock_displayed)) {
		TEST_TRUE(0, "  mock vb2ex_display_ui ran out of entries!");
		return VB2_ERROR_MOCK;
	}

	mock_displayed[mock_displayed_count++] = displayed;

	return VB2_SUCCESS;
}

uint32_t vb2ex_get_locale_count(void)
{
	return mock_locale_count;
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

uint32_t VbExKeyboardRead(void)
{
	return VbExKeyboardReadWithFlags(NULL);
}

uint32_t VbExKeyboardReadWithFlags(uint32_t *key_flags)
{
	mock_iters++;
	if (mock_iters < mock_key_total) {
		if (key_flags != NULL) {
			if (mock_key_trusted[mock_iters])
				*key_flags = VB_KEY_FLAG_TRUSTED_KEYBOARD;
			else
				*key_flags = 0;
		}
		return mock_key[mock_iters];
	}

	return 0;
}

uint32_t vb2ex_mtime(void)
{
	mock_get_timer_last = mock_time;
	return mock_time;
}

void vb2ex_msleep(uint32_t msec)
{
	mock_time += msec;
}

void vb2ex_beep(uint32_t msec, uint32_t frequency)
{
	mock_vbexbeep_called++;
}

enum vb2_dev_default_boot_target vb2api_get_dev_default_boot_target(
	struct vb2_context *c)
{
	return mock_default_boot;
}

int vb2_dev_boot_allowed(struct vb2_context *c)
{
	return mock_dev_boot_allowed;
}

int vb2_dev_boot_legacy_allowed(struct vb2_context *c)
{
	return mock_dev_boot_legacy_allowed;
}

int vb2_dev_boot_external_allowed(struct vb2_context *c)
{
	return mock_dev_boot_external_allowed;
}

vb2_error_t VbExLegacy(enum VbAltFwIndex_t altfw_num)
{
	mock_vbexlegacy_called++;
	mock_altfw_num_last = altfw_num;

	return VB2_SUCCESS;
}

vb2_error_t VbTryLoadKernel(struct vb2_context *c, uint32_t get_info_flags)
{
	int i = mock_iters;

	/* Return last entry if called too many times */
	if (i >= mock_vbtlk_total)
		i = mock_vbtlk_total - 1;

	TEST_EQ(mock_vbtlk_expected_flag[i], get_info_flags,
		"  unexpected get_info_flags");

	return mock_vbtlk_retval[i];
}

int vb2_allow_recovery(struct vb2_context *c)
{
	return mock_allow_recovery;
}

int vb2ex_physical_presence_pressed(void)
{
	if (mock_iters >= mock_pp_pressed_total)
		return 0;

	return mock_pp_pressed[mock_iters];
}

void vb2_enable_developer_mode(struct vb2_context *c)
{
	mock_enable_dev_mode = 1;
}

/* Tests */
static void developer_tests(void)
{
	VB2_DEBUG("Testing developer mode...\n");

	/* Proceed to internal disk after timeout */
	reset_common_data(FOR_DEVELOPER);
	add_mock_vbtlk(VB2_SUCCESS, VB_DISK_FLAG_FIXED);
	TEST_EQ(vb2_developer_menu(ctx), VB2_SUCCESS,
		"proceed to internal disk after timeout");
	TEST_TRUE(mock_get_timer_last - mock_time_start >=
		  30 * VB2_MSEC_PER_SEC, "  finished delay");
	TEST_EQ(mock_vbexbeep_called, 2, "  beeped twice");
	TEST_TRUE(mock_iters >= mock_vbtlk_total, "  used up mock_vbtlk");

	/* Proceed to external disk after timeout */
	reset_common_data(FOR_DEVELOPER);
	add_mock_vbtlk(VB2_SUCCESS, VB_DISK_FLAG_REMOVABLE);
	mock_default_boot = VB2_DEV_DEFAULT_BOOT_TARGET_EXTERNAL;
	mock_dev_boot_external_allowed = 1;
	TEST_EQ(vb2_developer_menu(ctx), VB2_SUCCESS,
		"proceed to external disk after timeout");
	TEST_TRUE(mock_get_timer_last - mock_time_start >=
		  30 * VB2_MSEC_PER_SEC, "  finished delay");
	TEST_EQ(mock_vbexbeep_called, 2, "  beeped twice");
	TEST_TRUE(mock_iters >= mock_vbtlk_total, "  used up mock_vbtlk");

	/* Default boot from external not allowed, don't boot */
	reset_common_data(FOR_DEVELOPER);
	mock_default_boot = VB2_DEV_DEFAULT_BOOT_TARGET_EXTERNAL;
	TEST_EQ(vb2_developer_menu(ctx), VB2_REQUEST_SHUTDOWN,
		"default boot from external not allowed, don't boot");
	TEST_TRUE(mock_get_timer_last - mock_time_start >=
		  30 * VB2_MSEC_PER_SEC, "  finished delay");
	TEST_EQ(mock_vbexbeep_called, 2, "  beeped twice");
	TEST_TRUE(mock_iters >= mock_vbtlk_total, "  used up mock_vbtlk");

	VB2_DEBUG("...done.\n");
}

static void broken_recovery_tests(void)
{
	VB2_DEBUG("Testing broken recovery mode...\n");

	/* BROKEN screen shutdown request */
	if (!DETACHABLE) {
		reset_common_data(FOR_BROKEN_RECOVERY);
		add_mock_keypress(VB_BUTTON_POWER_SHORT_PRESS);
		mock_calls_until_shutdown = -1;
		TEST_EQ(vb2_broken_recovery_menu(ctx),
			VB2_REQUEST_SHUTDOWN,
			"power button short pressed = shutdown");
	}

	/* Shortcuts that are always ignored in BROKEN */
	reset_common_data(FOR_BROKEN_RECOVERY);
	add_mock_key(VB_KEY_CTRL('D'), 1);
	add_mock_key(VB_KEY_CTRL('U'), 1);
	add_mock_key(VB_KEY_CTRL('L'), 1);
	add_mock_key(VB_BUTTON_VOL_UP_DOWN_COMBO_PRESS, 1);
	add_mock_key(VB_BUTTON_VOL_UP_LONG_PRESS, 1);
	add_mock_key(VB_BUTTON_VOL_DOWN_LONG_PRESS, 1);
	TEST_EQ(vb2_broken_recovery_menu(ctx), VB2_REQUEST_SHUTDOWN,
		"Shortcuts ignored in BROKEN");
	TEST_EQ(mock_calls_until_shutdown, 0, "  loop forever");
	TEST_EQ(mock_displayed_count, 1, "  root screen only");

	VB2_DEBUG("...done.\n");
}

static void manual_recovery_tests(void)
{
	VB2_DEBUG("Testing manual recovery mode...\n");

	/* Timeout, shutdown */
	reset_common_data(FOR_MANUAL_RECOVERY);
	TEST_EQ(vb2_manual_recovery_menu(ctx), VB2_REQUEST_SHUTDOWN,
		"timeout, shutdown");
	TEST_EQ(mock_displayed_count, 1, "  root screen only");

	/* Power button short pressed = shutdown request */
	if (!DETACHABLE) {
		reset_common_data(FOR_MANUAL_RECOVERY);
		add_mock_keypress(VB_BUTTON_POWER_SHORT_PRESS);
		TEST_EQ(vb2_manual_recovery_menu(ctx),
			VB2_REQUEST_SHUTDOWN,
			"power button short pressed = shutdown");
	}

	/* Boots if we have a valid image on first try */
	reset_common_data(FOR_MANUAL_RECOVERY);
	add_mock_vbtlk(VB2_SUCCESS, VB_DISK_FLAG_REMOVABLE);
	add_mock_vbtlk(VB2_ERROR_MOCK, VB_DISK_FLAG_REMOVABLE);
	TEST_EQ(vb2_manual_recovery_menu(ctx), VB2_SUCCESS,
		"boots if valid on first try");

	/* Boots eventually if we get a valid image later */
	reset_common_data(FOR_MANUAL_RECOVERY);
	add_mock_vbtlk(VB2_ERROR_LK_NO_DISK_FOUND, VB_DISK_FLAG_REMOVABLE);
	add_mock_vbtlk(VB2_ERROR_LK_NO_DISK_FOUND, VB_DISK_FLAG_REMOVABLE);
	add_mock_vbtlk(VB2_SUCCESS, VB_DISK_FLAG_REMOVABLE);
	add_mock_vbtlk(VB2_ERROR_MOCK, VB_DISK_FLAG_REMOVABLE);
	TEST_EQ(vb2_manual_recovery_menu(ctx), VB2_SUCCESS,
		"boots after valid image appears");

	/* Invalid image, then remove, then valid image */
	reset_common_data(FOR_MANUAL_RECOVERY);
	add_mock_vbtlk(VB2_ERROR_MOCK, VB_DISK_FLAG_REMOVABLE);
	add_mock_vbtlk(VB2_ERROR_LK_NO_DISK_FOUND, VB_DISK_FLAG_REMOVABLE);
	add_mock_vbtlk(VB2_ERROR_LK_NO_DISK_FOUND, VB_DISK_FLAG_REMOVABLE);
	add_mock_vbtlk(VB2_SUCCESS, VB_DISK_FLAG_REMOVABLE);
	add_mock_vbtlk(VB2_ERROR_MOCK, VB_DISK_FLAG_REMOVABLE);
	TEST_EQ(vb2_manual_recovery_menu(ctx), VB2_SUCCESS,
		"boots after valid image appears");
	DISPLAYED_EQ("recovery select", VB2_SCREEN_RECOVERY_SELECT,
		     MOCK_IGNORE, MOCK_IGNORE, MOCK_IGNORE);
	DISPLAYED_EQ("recovery invalid", VB2_SCREEN_RECOVERY_INVALID,
		     MOCK_IGNORE, MOCK_IGNORE, MOCK_IGNORE);
	DISPLAYED_EQ("recovery select", VB2_SCREEN_RECOVERY_SELECT,
		     MOCK_IGNORE, MOCK_IGNORE, MOCK_IGNORE);
	DISPLAYED_NO_EXTRA();

	/* Ctrl+D = to_dev; space = cancel */
	reset_common_data(FOR_MANUAL_RECOVERY);
	add_mock_key(VB_KEY_CTRL('D'), 1);
	add_mock_keypress(' ');
	TEST_EQ(vb2_manual_recovery_menu(ctx), VB2_REQUEST_SHUTDOWN,
		"ctrl+D = to_dev; space = cancel");
	TEST_EQ(mock_enable_dev_mode, 0, "  dev mode not enabled");
	DISPLAYED_EQ("recovery select", VB2_SCREEN_RECOVERY_SELECT,
		     MOCK_IGNORE, MOCK_IGNORE, MOCK_IGNORE);
	DISPLAYED_EQ("to_dev", VB2_SCREEN_RECOVERY_TO_DEV,
		     MOCK_IGNORE, MOCK_IGNORE, MOCK_IGNORE);
	DISPLAYED_EQ("recovery select", VB2_SCREEN_RECOVERY_SELECT,
		     MOCK_IGNORE, MOCK_IGNORE, MOCK_IGNORE);
	DISPLAYED_NO_EXTRA();

	/* Cancel */
	reset_common_data(FOR_MANUAL_RECOVERY);
	add_mock_key(VB_KEY_CTRL('D'), 1);
	if (PHYSICAL_PRESENCE_KEYBOARD)
		add_mock_keypress(VB_KEY_DOWN);
	add_mock_keypress(VB_KEY_ENTER);
	TEST_EQ(vb2_manual_recovery_menu(ctx), VB2_REQUEST_SHUTDOWN, "cancel");
	TEST_EQ(mock_enable_dev_mode, 0, "  dev mode not enabled");

	/* Confirm */
	reset_common_data(FOR_MANUAL_RECOVERY);
	add_mock_key(VB_KEY_CTRL('D'), 1);
	if (PHYSICAL_PRESENCE_KEYBOARD) {
		add_mock_key(VB_KEY_ENTER, 1);
	} else {
		add_mock_pp_pressed(0);
		add_mock_pp_pressed(1);
		add_mock_pp_pressed(1);
		add_mock_pp_pressed(0);
	}
	TEST_EQ(vb2_manual_recovery_menu(ctx), VB2_REQUEST_REBOOT_EC_TO_RO,
		"confirm");
	if (!PHYSICAL_PRESENCE_KEYBOARD)
		TEST_TRUE(mock_iters >= mock_pp_pressed_total - 1,
			  "  used up mock_pp_pressed");
	TEST_EQ(mock_enable_dev_mode, 1, "  dev mode enabled");

	/* Cannot confirm physical presence by untrusted keyboard */
	if (PHYSICAL_PRESENCE_KEYBOARD) {
		reset_common_data(FOR_MANUAL_RECOVERY);
		add_mock_key(VB_KEY_CTRL('D'), 1);
		add_mock_key(VB_KEY_ENTER, 0);
		TEST_EQ(vb2_manual_recovery_menu(ctx), VB2_REQUEST_SHUTDOWN,
			"cannot confirm physical presence"
			" by untrusted keyboard");
		TEST_EQ(mock_enable_dev_mode, 0, "  dev mode not enabled");
	}

	/* Cannot enable dev mode if already enabled */
	reset_common_data(FOR_MANUAL_RECOVERY);
	sd->flags |= VB2_SD_FLAG_DEV_MODE_ENABLED;
	add_mock_key(VB_KEY_CTRL('D'), 1);
	if (PHYSICAL_PRESENCE_KEYBOARD) {
		add_mock_key(VB_KEY_ENTER, 1);
	} else {
		add_mock_pp_pressed(0);
		add_mock_pp_pressed(1);
		add_mock_pp_pressed(0);
	}
	TEST_EQ(vb2_manual_recovery_menu(ctx), VB2_REQUEST_SHUTDOWN,
		"cannot enable dev mode if already enabled");
	TEST_EQ(mock_enable_dev_mode, 0, "  dev mode already on");

	/* Physical presence button tests */
	if (!PHYSICAL_PRESENCE_KEYBOARD) {
		/* Physical presence button stuck? */
		reset_common_data(FOR_MANUAL_RECOVERY);
		add_mock_key(VB_KEY_CTRL('D'), 1);
		add_mock_pp_pressed(1);  /* Hold since boot */
		add_mock_pp_pressed(0);
		TEST_EQ(vb2_manual_recovery_menu(ctx), VB2_REQUEST_SHUTDOWN,
			"physical presence button stuck?");
		TEST_EQ(mock_enable_dev_mode, 0, "  dev mode not enabled");
		DISPLAYED_EQ("recovery select", VB2_SCREEN_RECOVERY_SELECT,
			     MOCK_IGNORE, MOCK_IGNORE, MOCK_IGNORE);
		DISPLAYED_NO_EXTRA();

		/* Button stuck, enter to_dev again */
		reset_common_data(FOR_MANUAL_RECOVERY);
		add_mock_key(VB_KEY_CTRL('D'), 1);
		add_mock_key(VB_KEY_CTRL('D'), 1);
		add_mock_pp_pressed(1);  /* Hold since boot */
		add_mock_pp_pressed(0);
		add_mock_pp_pressed(1);  /* Press again */
		add_mock_pp_pressed(0);
		TEST_EQ(vb2_manual_recovery_menu(ctx),
			VB2_REQUEST_REBOOT_EC_TO_RO,
			"button stuck, enter to_dev again");
		TEST_TRUE(mock_iters >= mock_pp_pressed_total - 1,
			  "  used up mock_pp_pressed");
		TEST_EQ(mock_enable_dev_mode, 1, "  dev mode enabled");
		DISPLAYED_EQ("recovery select", VB2_SCREEN_RECOVERY_SELECT,
			     MOCK_IGNORE, MOCK_IGNORE, MOCK_IGNORE);
		DISPLAYED_EQ("to_dev", VB2_SCREEN_RECOVERY_TO_DEV,
			     MOCK_IGNORE, MOCK_IGNORE, MOCK_IGNORE);
		DISPLAYED_NO_EXTRA();

		/* Cancel with holding pp button, enter again */
		reset_common_data(FOR_MANUAL_RECOVERY);
		/* Enter to_dev */
		add_mock_key(VB_KEY_CTRL('D'), 1);
		add_mock_pp_pressed(0);
		/* Press pp button */
		add_mock_keypress(0);
		add_mock_pp_pressed(1);
		/* Space = back */
		add_mock_keypress(' ');
		add_mock_pp_pressed(1);
		/* Wait */
		add_mock_keypress(0);
		add_mock_pp_pressed(0);
		/* Enter to_dev again */
		add_mock_key(VB_KEY_CTRL('D'), 1);
		add_mock_pp_pressed(0);
		/* Press pp button again */
		add_mock_pp_pressed(1);
		/* Release */
		add_mock_pp_pressed(0);
		TEST_EQ(vb2_manual_recovery_menu(ctx),
			VB2_REQUEST_REBOOT_EC_TO_RO,
			"cancel with holding pp button, enter again");
		TEST_TRUE(mock_iters >= mock_pp_pressed_total - 1,
			  "  used up mock_pp_pressed");
		TEST_EQ(mock_enable_dev_mode, 1, "  dev mode enabled");
		DISPLAYED_EQ("recovery select", VB2_SCREEN_RECOVERY_SELECT,
			     MOCK_IGNORE, MOCK_IGNORE, MOCK_IGNORE);
		DISPLAYED_EQ("to_dev", VB2_SCREEN_RECOVERY_TO_DEV,
			     MOCK_IGNORE, MOCK_IGNORE, MOCK_IGNORE);
		DISPLAYED_EQ("recovery select", VB2_SCREEN_RECOVERY_SELECT,
			     MOCK_IGNORE, MOCK_IGNORE, MOCK_IGNORE);
		DISPLAYED_EQ("to_dev", VB2_SCREEN_RECOVERY_TO_DEV,
			     MOCK_IGNORE, MOCK_IGNORE, MOCK_IGNORE);
		DISPLAYED_NO_EXTRA();
	}

	VB2_DEBUG("...done.\n");
}

static void language_selection_tests(void)
{
	VB2_DEBUG("Testing language selection...\n");

	/* Enter language menu and change language */
	reset_common_data(FOR_MANUAL_RECOVERY);
	mock_locale_count = 100;
	vb2_nv_set(ctx, VB2_NV_LOCALIZATION_INDEX, 23);
	add_mock_keypress(VB_KEY_UP);
	add_mock_keypress(VB_KEY_ENTER);	/* select language */
	add_mock_keypress(VB_KEY_DOWN);
	add_mock_keypress(VB_KEY_ENTER);	/* select locale 24 */
	add_mock_vbtlk(VB2_ERROR_LK_NO_DISK_FOUND, VB_DISK_FLAG_REMOVABLE);
	TEST_EQ(vb2_manual_recovery_menu(ctx), VB2_REQUEST_SHUTDOWN,
		"change language");
	DISPLAYED_EQ("RECOVERY_SELECT default", VB2_SCREEN_RECOVERY_SELECT,
		     23, MOCK_IGNORE, MOCK_IGNORE);
	DISPLAYED_EQ("RECOVERY_SELECT lang", VB2_SCREEN_RECOVERY_SELECT,
		     23, 0, MOCK_IGNORE);
	DISPLAYED_EQ("LANGUAGE_SELECT 23", VB2_SCREEN_LANGUAGE_SELECT,
		     23, 23, MOCK_IGNORE);
	DISPLAYED_EQ("LANGUAGE_SELECT 24", VB2_SCREEN_LANGUAGE_SELECT,
		     23, 24, MOCK_IGNORE);
	DISPLAYED_EQ("RECOVERY_SELECT new locale", VB2_SCREEN_RECOVERY_SELECT,
		     24, MOCK_IGNORE, MOCK_IGNORE);
	DISPLAYED_NO_EXTRA();
	TEST_EQ(vb2_nv_get(ctx, VB2_NV_LOCALIZATION_INDEX), 24,
		"  locale 24 saved to nvdata");

	/* Locale count = 0 */
	reset_common_data(FOR_MANUAL_RECOVERY);
	mock_locale_count = 0;
	vb2_nv_set(ctx, VB2_NV_LOCALIZATION_INDEX, 23);
	add_mock_keypress(VB_KEY_UP);
	add_mock_keypress(VB_KEY_ENTER);	/* select language */
	add_mock_keypress(VB_KEY_ENTER);	/* select locale 0 */
	add_mock_vbtlk(VB2_ERROR_LK_NO_DISK_FOUND, VB_DISK_FLAG_REMOVABLE);
	TEST_EQ(vb2_manual_recovery_menu(ctx), VB2_REQUEST_SHUTDOWN,
		"enter language menu");
	DISPLAYED_EQ("RECOVERY_SELECT default", VB2_SCREEN_RECOVERY_SELECT,
		     23, MOCK_IGNORE, MOCK_IGNORE);
	DISPLAYED_EQ("RECOVERY_SELECT lang", VB2_SCREEN_RECOVERY_SELECT,
		     23, 0, MOCK_IGNORE);
	DISPLAYED_EQ("LANGUAGE_SELECT index 0", VB2_SCREEN_LANGUAGE_SELECT,
		     23, 0, MOCK_IGNORE);
	DISPLAYED_EQ("RECOVERY_SELECT locale 0", VB2_SCREEN_RECOVERY_SELECT,
		     0, MOCK_IGNORE, MOCK_IGNORE);
	DISPLAYED_NO_EXTRA();

	VB2_DEBUG("...done.\n");
}

static void developer_screen_tests(void)
{
	VB2_DEBUG("Testing developer mode screens...\n");

	/* Dev mode screen */
	/* TODO: Check items */
	reset_common_data(FOR_DEVELOPER);
	add_mock_vbtlk(VB2_SUCCESS, VB_DISK_FLAG_FIXED);
	TEST_EQ(vb2_developer_menu(ctx), VB2_SUCCESS,
		"dev mode screen");
	DISPLAYED_EQ("dev mode screen", VB2_SCREEN_DEVELOPER_MODE,
		     MOCK_IGNORE, MOCK_IGNORE, MOCK_IGNORE);
	DISPLAYED_NO_EXTRA();

	/* Advanced options screen */
	reset_common_data(FOR_DEVELOPER);
	add_mock_vbtlk(VB2_SUCCESS, VB_DISK_FLAG_FIXED);
	add_mock_keypress(VB_KEY_DOWN);
	add_mock_keypress(VB_KEY_ENTER);
	/* #0: Language menu */
	add_mock_keypress(VB_KEY_UP);
	add_mock_keypress(VB_KEY_ENTER);
	/* #1: (Disabled) */
	/* #2: Back */
	add_mock_keypress(VB_KEY_ESC);
	add_mock_keypress(VB_KEY_DOWN);
	add_mock_keypress(VB_KEY_ENTER);
	add_mock_keypress(VB_KEY_ENTER);
	/* End of menu */
	add_mock_keypress(VB_KEY_DOWN);
	add_mock_keypress(VB_KEY_ENTER);
	add_mock_keypress(VB_KEY_DOWN);
	extend_calls_until_shutdown();
	TEST_EQ(vb2_developer_menu(ctx), VB2_REQUEST_SHUTDOWN,
		"advanced options screen");
	DISPLAYED_PASS();
	DISPLAYED_PASS();
	/* #0: Language menu */
	DISPLAYED_PASS();
	DISPLAYED_EQ("advanced options", VB2_SCREEN_ADVANCED_OPTIONS,
		     MOCK_IGNORE, 0, 0x2);
	DISPLAYED_EQ("#0: language menu", VB2_SCREEN_LANGUAGE_SELECT,
		     MOCK_IGNORE, MOCK_IGNORE, MOCK_IGNORE);
	/* #1: (Disabled) */
	/* #2: Back */
	DISPLAYED_PASS();
	DISPLAYED_PASS();
	DISPLAYED_EQ("advanced options", VB2_SCREEN_ADVANCED_OPTIONS,
		     MOCK_IGNORE, 2, 0x2);
	DISPLAYED_EQ("#2: back", VB2_SCREEN_DEVELOPER_MODE,
		     MOCK_IGNORE, MOCK_IGNORE, MOCK_IGNORE);
	/* End of menu */
	DISPLAYED_PASS();
	DISPLAYED_EQ("end of menu", VB2_SCREEN_ADVANCED_OPTIONS,
		     MOCK_IGNORE, 2, MOCK_IGNORE);
	DISPLAYED_NO_EXTRA();

	VB2_DEBUG("...done.\n");
}

static void broken_recovery_screen_tests(void)
{
	/* Broken screen */
	reset_common_data(FOR_BROKEN_RECOVERY);
	/* #0: Language menu */
	add_mock_keypress(VB_KEY_UP);
	add_mock_keypress(VB_KEY_ENTER);
	/* #1: Advanced options */
	add_mock_keypress(VB_KEY_ESC);
	add_mock_keypress(VB_KEY_ENTER);
	/* End of menu */
	add_mock_keypress(VB_KEY_ESC);
	add_mock_keypress(VB_KEY_DOWN);  /* Blocked */
	extend_calls_until_shutdown();
	TEST_EQ(vb2_broken_recovery_menu(ctx), VB2_REQUEST_SHUTDOWN,
		"broken screen");
	/* #0: Language menu */
	DISPLAYED_PASS();
	DISPLAYED_EQ("broken screen", VB2_SCREEN_RECOVERY_BROKEN,
		     MOCK_IGNORE, 0, 0x0);
	DISPLAYED_EQ("#0: language menu", VB2_SCREEN_LANGUAGE_SELECT,
		     MOCK_IGNORE, MOCK_IGNORE, MOCK_IGNORE);
	/* #1: Advanced options */
	DISPLAYED_EQ("broken screen", VB2_SCREEN_RECOVERY_BROKEN,
		     MOCK_IGNORE, 1, 0x0);
	DISPLAYED_EQ("#1: advanced options", VB2_SCREEN_ADVANCED_OPTIONS,
		     MOCK_IGNORE, MOCK_IGNORE, MOCK_IGNORE);
	/* End of menu */
	DISPLAYED_EQ("end of menu", VB2_SCREEN_RECOVERY_BROKEN,
		     MOCK_IGNORE, 1, MOCK_IGNORE);
	DISPLAYED_NO_EXTRA();

	/* Advanced options screen */
	reset_common_data(FOR_BROKEN_RECOVERY);
	add_mock_keypress(VB_KEY_ENTER);
	/* #0: Language menu */
	add_mock_keypress(VB_KEY_UP);
	add_mock_keypress(VB_KEY_ENTER);
	/* #1: (Disabled) */
	/* #2: Back */
	add_mock_keypress(VB_KEY_ESC);
	add_mock_keypress(VB_KEY_ENTER);
	add_mock_keypress(VB_KEY_ENTER);
	/* End of menu */
	add_mock_keypress(VB_KEY_ENTER);
	add_mock_keypress(VB_KEY_DOWN);  /* Blocked */
	extend_calls_until_shutdown();
	TEST_EQ(vb2_broken_recovery_menu(ctx), VB2_REQUEST_SHUTDOWN,
		"advanced options screen");
	DISPLAYED_PASS();
	/* #0: Language menu */
	DISPLAYED_PASS();
	DISPLAYED_EQ("advanced options", VB2_SCREEN_ADVANCED_OPTIONS,
		     MOCK_IGNORE, 0, 0x2);
	DISPLAYED_EQ("#0: language menu", VB2_SCREEN_LANGUAGE_SELECT,
		     MOCK_IGNORE, MOCK_IGNORE, MOCK_IGNORE);
	/* #1: (Disabled) */
	/* #2: Back */
	DISPLAYED_PASS();
	DISPLAYED_EQ("advanced options", VB2_SCREEN_ADVANCED_OPTIONS,
		     MOCK_IGNORE, 2, 0x2);
	DISPLAYED_EQ("#2: back", VB2_SCREEN_RECOVERY_BROKEN,
		     MOCK_IGNORE, MOCK_IGNORE, MOCK_IGNORE);
	/* End of menu */
	DISPLAYED_EQ("end of menu", VB2_SCREEN_ADVANCED_OPTIONS,
		     MOCK_IGNORE, 2, MOCK_IGNORE);
	DISPLAYED_NO_EXTRA();

	VB2_DEBUG("...done.\n");
}

static void manual_recovery_screen_tests(void)
{
	/* Recovery select screen */
	reset_common_data(FOR_MANUAL_RECOVERY);
	/* #0: Language menu */
	add_mock_keypress(VB_KEY_UP);
	add_mock_keypress(VB_KEY_ENTER);
	/* #1: Phone recovery */
	add_mock_keypress(VB_KEY_ESC);
	add_mock_keypress(VB_KEY_ENTER);
	/* #2: External disk recovery */
	add_mock_keypress(VB_KEY_ESC);
	add_mock_keypress(VB_KEY_DOWN);
	add_mock_keypress(VB_KEY_ENTER);
	/* #3: Advanced options */
	add_mock_keypress(VB_KEY_ESC);
	add_mock_keypress(VB_KEY_DOWN);
	add_mock_keypress(VB_KEY_DOWN);
	add_mock_keypress(VB_KEY_ENTER);
	/* End of menu */
	add_mock_keypress(VB_KEY_ESC);
	add_mock_keypress(VB_KEY_DOWN);
	add_mock_keypress(VB_KEY_DOWN);
	add_mock_keypress(VB_KEY_DOWN);  /* Blocked */
	extend_calls_until_shutdown();
	TEST_EQ(vb2_manual_recovery_menu(ctx), VB2_REQUEST_SHUTDOWN,
		"recovery select screen");
	/* #0: Language menu */
	DISPLAYED_PASS();
	DISPLAYED_EQ("recovery select", VB2_SCREEN_RECOVERY_SELECT,
		     MOCK_IGNORE, 0, 0x0);
	DISPLAYED_EQ("#0: language menu", VB2_SCREEN_LANGUAGE_SELECT,
		     MOCK_IGNORE, MOCK_IGNORE, MOCK_IGNORE);
	/* #1: Phone recovery */
	DISPLAYED_EQ("recovery select", VB2_SCREEN_RECOVERY_SELECT,
		     MOCK_IGNORE, 1, 0x0);
	DISPLAYED_EQ("#1: phone recovery", VB2_SCREEN_RECOVERY_PHONE_STEP1,
		     MOCK_IGNORE, MOCK_IGNORE, MOCK_IGNORE);
	/* #2: External disk recovery */
	DISPLAYED_PASS();
	DISPLAYED_EQ("recovery select", VB2_SCREEN_RECOVERY_SELECT,
		     MOCK_IGNORE, 2, 0x0);
	DISPLAYED_EQ("#2: disk recovery", VB2_SCREEN_RECOVERY_DISK_STEP1,
		     MOCK_IGNORE, MOCK_IGNORE, MOCK_IGNORE);
	/* #3: Advanced options */
	DISPLAYED_PASS();
	DISPLAYED_PASS();
	DISPLAYED_EQ("recovery select", VB2_SCREEN_RECOVERY_SELECT,
		     MOCK_IGNORE, 3, 0x0);
	DISPLAYED_EQ("#3: advanced options", VB2_SCREEN_ADVANCED_OPTIONS,
		     MOCK_IGNORE, MOCK_IGNORE, MOCK_IGNORE);
	/* End of menu */
	DISPLAYED_PASS();
	DISPLAYED_PASS();
	DISPLAYED_EQ("end of menu", VB2_SCREEN_RECOVERY_SELECT,
		     MOCK_IGNORE, 3, MOCK_IGNORE);
	DISPLAYED_NO_EXTRA();

	/* Advanced options screen */
	reset_common_data(FOR_MANUAL_RECOVERY);
	/* #0: Language menu */
	add_mock_keypress(VB_KEY_DOWN);
	add_mock_keypress(VB_KEY_DOWN);
	add_mock_keypress(VB_KEY_ENTER);
	add_mock_keypress(VB_KEY_UP);
	add_mock_keypress(VB_KEY_ENTER);
	/* #1: Enable dev mode */
	add_mock_keypress(VB_KEY_ESC);
	add_mock_keypress(VB_KEY_DOWN);
	add_mock_keypress(VB_KEY_DOWN);
	add_mock_keypress(VB_KEY_ENTER);
	add_mock_keypress(VB_KEY_ENTER);
	/* #2: Back */
	add_mock_keypress(VB_KEY_ESC);
	add_mock_keypress(VB_KEY_DOWN);
	add_mock_keypress(VB_KEY_DOWN);
	add_mock_keypress(VB_KEY_ENTER);
	add_mock_keypress(VB_KEY_DOWN);
	add_mock_keypress(VB_KEY_ENTER);
	/* End of menu */
	add_mock_keypress(VB_KEY_DOWN);
	add_mock_keypress(VB_KEY_DOWN);
	add_mock_keypress(VB_KEY_ENTER);
	add_mock_keypress(VB_KEY_DOWN);
	add_mock_keypress(VB_KEY_DOWN);  /* Blocked */
	extend_calls_until_shutdown();
	TEST_EQ(vb2_manual_recovery_menu(ctx), VB2_REQUEST_SHUTDOWN,
		"advanced options screen");
	DISPLAYED_PASS();
	DISPLAYED_PASS();
	DISPLAYED_PASS();
	/* #0: Language menu */
	DISPLAYED_PASS();
	DISPLAYED_EQ("advanced options", VB2_SCREEN_ADVANCED_OPTIONS,
		     MOCK_IGNORE, 0, 0x0);
	DISPLAYED_EQ("#0: language menu", VB2_SCREEN_LANGUAGE_SELECT,
		     MOCK_IGNORE, MOCK_IGNORE, MOCK_IGNORE);
	/* #1: Enable dev mode */
	DISPLAYED_PASS();
	DISPLAYED_PASS();
	DISPLAYED_PASS();
	DISPLAYED_EQ("advanced options", VB2_SCREEN_ADVANCED_OPTIONS,
		     MOCK_IGNORE, 1, 0x0);
	DISPLAYED_EQ("#1: enable dev mode", VB2_SCREEN_RECOVERY_TO_DEV,
		     MOCK_IGNORE, MOCK_IGNORE, MOCK_IGNORE);
	/* #2: Back */
	DISPLAYED_PASS();
	DISPLAYED_PASS();
	DISPLAYED_PASS();
	DISPLAYED_PASS();
	DISPLAYED_EQ("advanced options", VB2_SCREEN_ADVANCED_OPTIONS,
		     MOCK_IGNORE, 2, 0x0);
	DISPLAYED_EQ("#2: back", VB2_SCREEN_RECOVERY_SELECT,
		     MOCK_IGNORE, MOCK_IGNORE, MOCK_IGNORE);
	/* End of menu */
	DISPLAYED_PASS();
	DISPLAYED_PASS();
	DISPLAYED_PASS();
	DISPLAYED_EQ("end of menu", VB2_SCREEN_ADVANCED_OPTIONS,
		     MOCK_IGNORE, 2, 0x0);
	DISPLAYED_NO_EXTRA();

	VB2_DEBUG("...done.\n");
}

int main(void)
{
	developer_tests();
	broken_recovery_tests();
	manual_recovery_tests();
	language_selection_tests();

	/* Screen displayed */
	developer_screen_tests();
	broken_recovery_screen_tests();
	manual_recovery_screen_tests();

	return gTestSuccess ? 0 : 255;
}
