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
#include "vboot_api.h"

/* Fixed value for ignoring some checks */
#define MOCK_IGNORE 0xffffu

/* Fuzzy matches for check_time() */
#define FUZZ_MS 200

/* Mock data */
/* TODO(b/156448738): Add tests for timer_disabled and error_code */
struct display_call {
	const struct vb2_screen_info *screen;
	uint32_t locale_id;
	uint32_t selected_item;
	uint32_t disabled_item_mask;
	uint32_t hidden_item_mask;
	int timer_disabled;
	uint32_t current_page;
	enum vb2_ui_error error_code;
} __attribute__((packed));

struct beep_call {
	uint32_t msec;
	uint32_t frequency;
	uint32_t time_expected;
};

static uint8_t workbuf[VB2_KERNEL_WORKBUF_RECOMMENDED_SIZE]
	__attribute__((aligned(VB2_WORKBUF_ALIGN)));
static struct vb2_context *ctx;
static struct vb2_shared_data *sd;
static struct vb2_gbb_header gbb;

static struct vb2_ui_context mock_ui_context;
static struct vb2_screen_state mock_state;

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

static uint32_t mock_time_ms;
static const uint32_t mock_time_start_ms = 31ULL * VB2_MSEC_PER_SEC;

static struct beep_call mock_beep[8];
static int mock_beep_count;
static int mock_beep_total;

static enum vb2_dev_default_boot_target mock_default_boot;

static int mock_run_altfw_called;
static uint32_t mock_altfw_last;
static uint32_t mock_altfw_count;

static vb2_error_t mock_vbtlk_retval[32];
static uint32_t mock_vbtlk_expected_flag[32];
static int mock_vbtlk_total;

static int mock_allow_recovery;

/* mock_pp_* = mock data for physical presence button */
static int mock_pp_pressed[64];
static int mock_pp_pressed_total;

static int mock_enable_dev_mode;

#define MOCK_PREPARE_LOG_SIZE 32

static int mock_snapshot_count;
static char mock_prepare_log[64][MOCK_PREPARE_LOG_SIZE];
static int mock_prepare_log_count;
static uint32_t mock_log_page_count;

static vb2_error_t mock_diag_storage_test_rv;

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

static void add_mock_vbtlk(vb2_error_t retval, uint32_t disk_flags)
{
	if (mock_vbtlk_total >= ARRAY_SIZE(mock_vbtlk_retval) ||
	    mock_vbtlk_total >= ARRAY_SIZE(mock_vbtlk_expected_flag)) {
		TEST_TRUE(0, "  mock_vbtlk ran out of entries!");
		return;
	}

	mock_vbtlk_retval[mock_vbtlk_total] = retval;
	mock_vbtlk_expected_flag[mock_vbtlk_total] = disk_flags;
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

static void displayed_eq(const char *text,
			 enum vb2_screen screen,
			 uint32_t locale_id,
			 uint32_t selected_item,
			 uint32_t disabled_item_mask,
			 uint32_t hidden_item_mask,
			 uint32_t current_page,
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
	if (hidden_item_mask != MOCK_IGNORE) {
		sprintf(text_buf, "  %s hidden_item_mask of %s",
			text_info, text);
		TEST_EQ(mock_displayed[mock_displayed_i].hidden_item_mask,
			hidden_item_mask, text_buf);
	}
	if (current_page != MOCK_IGNORE) {
		sprintf(text_buf, "  %s current_page of %s",
			text_info, text);
		TEST_EQ(mock_displayed[mock_displayed_i].current_page,
			current_page, text_buf);
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
		     MOCK_IGNORE, MOCK_IGNORE, __LINE__)

#define DISPLAYED_NO_EXTRA() displayed_no_extra(__LINE__)

/* Check if the result time falls in range [expected, expected + FUZZ_MS) */
static void check_time(uint32_t result, uint32_t expected, const char *desc)
{
	TEST_TRUE(result >= expected, desc);
	TEST_TRUE(result - expected < FUZZ_MS, "  within FUZZ_MS");
}

/* Type of test to reset for */
enum reset_type {
	FOR_DEVELOPER,
	FOR_BROKEN_RECOVERY,
	FOR_MANUAL_RECOVERY,
	FOR_DIAGNOSTICS,
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

	ctx->flags |= VB2_CONTEXT_DEV_BOOT_ALLOWED;
	ctx->flags |= VB2_CONTEXT_DEV_BOOT_EXTERNAL_ALLOWED;

	/* Mock ui_context based on real screens */
	memset(&mock_ui_context, 0, sizeof(mock_ui_context));
	mock_ui_context.ctx = ctx;
	mock_ui_context.state = &mock_state;

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

	/* For vb2ex_mtime and vb2ex_msleep  */
	mock_time_ms = mock_time_start_ms;

	/* For vb2ex_beep */
	memset(mock_beep, 0, sizeof(mock_beep));
	mock_beep_count = 0;
	mock_beep_total = 0;

	/* For dev_boot* in 2misc.h */
	mock_default_boot = VB2_DEV_DEFAULT_BOOT_TARGET_INTERNAL;

	/* For vb2ex_run_altfw */
	mock_run_altfw_called = 0;
	mock_altfw_last = -100;
	mock_altfw_count = 2;

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

	/* For vb2ex_prepare_log_screen */
	mock_snapshot_count = 0;
	mock_prepare_log_count = 0;
	mock_log_page_count = 1;

	/* Avoid Iteration #0 */
	add_mock_keypress(0);
	if (t == FOR_MANUAL_RECOVERY)
		add_mock_vbtlk(VB2_ERROR_LK_NO_DISK_FOUND,
			       VB_DISK_FLAG_REMOVABLE);
	else
		add_mock_vbtlk(VB2_ERROR_MOCK, 0);
	add_mock_pp_pressed(0);

	mock_diag_storage_test_rv = VB2_SUCCESS;
}

/* Mock functions */
struct vb2_gbb_header *vb2_get_gbb(struct vb2_context *c)
{
	return &gbb;
}

vb2_error_t vb2ex_display_ui(enum vb2_screen screen,
			     uint32_t locale_id,
			     uint32_t selected_item,
			     uint32_t disabled_item_mask,
			     uint32_t hidden_item_mask,
			     int timer_disabled,
			     uint32_t current_page,
			     enum vb2_ui_error error_code)
{
	struct display_call displayed = (struct display_call){
		.screen = vb2_get_screen_info(screen),
		.locale_id = locale_id,
		.selected_item = selected_item,
		.disabled_item_mask = disabled_item_mask,
		.hidden_item_mask = hidden_item_mask,
		.timer_disabled = timer_disabled,
		.current_page = current_page,
		.error_code = error_code,
	};

	/* Ignore repeated calls with same arguments */
	if (mock_displayed_count > 0 &&
	    !memcmp(&mock_displayed[mock_displayed_count - 1], &displayed,
		    sizeof(struct display_call)))
		return VB2_SUCCESS;

	VB2_DEBUG("displayed %d: screen=%#x, locale_id=%u, selected_item=%u, "
		  "disabled_item_mask=%#x, hidden_item_mask=%#x, "
		  "timer_disabled=%d, current_page=%u, error=%#x\n",
		  mock_displayed_count, screen, locale_id, selected_item,
		  disabled_item_mask, hidden_item_mask,
		  timer_disabled, current_page, error_code);

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
	return mock_time_ms;
}

void vb2ex_msleep(uint32_t msec)
{
	mock_time_ms += msec;
}

void vb2ex_beep(uint32_t msec, uint32_t frequency)
{
	struct beep_call *beep;
	uint32_t cur_time = mock_time_ms - mock_time_start_ms;

	VB2_DEBUG("beep %d: msec = %d, frequency = %d at %d msec\n",
		  mock_beep_count, msec, frequency, cur_time);

	if (mock_beep_total > 0) {
		TEST_TRUE(mock_beep_count < mock_beep_total,
			  "  too many beep calls!");

		beep = &mock_beep[mock_beep_count];

		VB2_DEBUG("beep expected: msec = %d, frequency = %d, "
			  "at %d msec\n",
			  beep->msec, beep->frequency, beep->time_expected);

		TEST_EQ(msec, beep->msec, "  beep duration");
		TEST_EQ(frequency, beep->frequency, "  beep frequency");
		check_time(cur_time, beep->time_expected,
			   "  beep started after expected time");
	}

	mock_time_ms += msec;
	mock_beep_count++;
}

enum vb2_dev_default_boot_target vb2api_get_dev_default_boot_target(
	struct vb2_context *c)
{
	return mock_default_boot;
}

vb2_error_t vb2ex_run_altfw(uint32_t altfw_id)
{
	mock_run_altfw_called++;
	mock_altfw_last = altfw_id;

	return VB2_SUCCESS;
}

uint32_t vb2ex_get_altfw_count(void)
{
	return mock_altfw_count;
}

vb2_error_t VbTryLoadKernel(struct vb2_context *c, uint32_t disk_flags)
{
	int i = mock_iters;

	/* Return last entry if called too many times */
	if (i >= mock_vbtlk_total)
		i = mock_vbtlk_total - 1;

	TEST_EQ(mock_vbtlk_expected_flag[i], disk_flags,
		"  unexpected disk_flags");

	return mock_vbtlk_retval[i];
}

int vb2api_allow_recovery(struct vb2_context *c)
{
	return mock_allow_recovery;
}

int vb2ex_physical_presence_pressed(void)
{
	if (mock_iters >= mock_pp_pressed_total)
		return 0;

	return mock_pp_pressed[mock_iters];
}

vb2_error_t vb2api_enable_developer_mode(struct vb2_context *c)
{
	mock_enable_dev_mode = 1;
	return VB2_SUCCESS;
}

const char *vb2ex_get_debug_info(struct vb2_context *c)
{
	return "mocked debug info";
}

const char *vb2ex_get_firmware_log(int reset)
{
	static char mock_firmware_log_buf[MOCK_PREPARE_LOG_SIZE];
	if (reset)
		mock_snapshot_count++;
	snprintf(mock_firmware_log_buf, MOCK_PREPARE_LOG_SIZE,
		 "%d", mock_snapshot_count);
	return mock_firmware_log_buf;
}

uint32_t vb2ex_prepare_log_screen(enum vb2_screen screen, uint32_t locale_id,
				  const char *str)
{
	if (mock_prepare_log_count < ARRAY_SIZE(mock_prepare_log))
		strncpy(mock_prepare_log[mock_prepare_log_count],
			str, MOCK_PREPARE_LOG_SIZE);
	mock_prepare_log_count++;

	return mock_log_page_count;
}

vb2_error_t vb2ex_diag_get_storage_test_log(const char **log)
{
	*log = "mock";
	return mock_diag_storage_test_rv;
}

/* Tests */
static void diagnostics_screen_tests(void)
{
	VB2_DEBUG("Testing diagnostic screens...\n");

	/* Diagnostics screen: disabled and hidden item mask */
	reset_common_data(FOR_DIAGNOSTICS);
	TEST_EQ(vb2_diagnostic_menu(ctx), VB2_REQUEST_SHUTDOWN,
		"diagnostic screen: no disabled or hidden item");
	DISPLAYED_EQ("diagnostic menu", VB2_SCREEN_DIAGNOSTICS, MOCK_IGNORE,
		     MOCK_IGNORE, 0x0, 0x0, MOCK_IGNORE);

	/* Diagnostics screen */
	reset_common_data(FOR_DIAGNOSTICS);

	/* #0: Language menu */
	add_mock_keypress(VB_KEY_UP);
	add_mock_keypress(VB_KEY_ENTER);
	add_mock_keypress(VB_KEY_ESC);
	/* #1: Storage health screen */
	add_mock_keypress(VB_KEY_DOWN);
	add_mock_keypress(VB_KEY_ENTER);
	add_mock_keypress(VB_KEY_ESC);
	/* #2: Short storage self-test screen */
	add_mock_keypress(VB_KEY_DOWN);
	add_mock_keypress(VB_KEY_ENTER);
	add_mock_keypress(VB_KEY_ESC);
	/* #3: Extended storage self-test screen */
	add_mock_keypress(VB_KEY_DOWN);
	add_mock_keypress(VB_KEY_ENTER);
	add_mock_keypress(VB_KEY_ESC);
	/* #4: Quick memory test screen */
	add_mock_keypress(VB_KEY_DOWN);
	add_mock_keypress(VB_KEY_ENTER);
	add_mock_keypress(VB_KEY_ESC);
	/* #5: Full memory test screen */
	add_mock_keypress(VB_KEY_DOWN);
	add_mock_keypress(VB_KEY_ENTER);
	add_mock_keypress(VB_KEY_ESC);
	/* #6: Power off (End of menu) */
	add_mock_keypress(VB_KEY_DOWN);
	add_mock_keypress(VB_KEY_ENTER);
	mock_calls_until_shutdown = -1;
	TEST_EQ(vb2_diagnostic_menu(ctx), VB2_REQUEST_SHUTDOWN,
		"diagnostic screen");

	DISPLAYED_EQ("default on first button of menu", VB2_SCREEN_DIAGNOSTICS,
		     MOCK_IGNORE, 1, MOCK_IGNORE, MOCK_IGNORE, MOCK_IGNORE);
	/* #0: Language menu */
	DISPLAYED_EQ("language selection", VB2_SCREEN_DIAGNOSTICS, MOCK_IGNORE,
		     0, MOCK_IGNORE, MOCK_IGNORE, MOCK_IGNORE);
	DISPLAYED_EQ("#0: language menu", VB2_SCREEN_LANGUAGE_SELECT,
		     MOCK_IGNORE, MOCK_IGNORE, MOCK_IGNORE, MOCK_IGNORE,
		     MOCK_IGNORE);
	DISPLAYED_PASS();
	/* #1: Storage health screen */
	DISPLAYED_EQ("storage health button", VB2_SCREEN_DIAGNOSTICS,
		     MOCK_IGNORE, 1, MOCK_IGNORE, MOCK_IGNORE, MOCK_IGNORE);
	DISPLAYED_EQ("#1: storage screen",
		     VB2_SCREEN_DIAGNOSTICS_STORAGE_HEALTH, MOCK_IGNORE,
		     MOCK_IGNORE, MOCK_IGNORE, MOCK_IGNORE, MOCK_IGNORE);
	DISPLAYED_PASS();
	/* #2: Short storage self-test screen */
	DISPLAYED_EQ("short storage self-test button", VB2_SCREEN_DIAGNOSTICS,
		     MOCK_IGNORE, 2, MOCK_IGNORE, MOCK_IGNORE, MOCK_IGNORE);
	DISPLAYED_EQ("#2: short storage self-test screen",
		     VB2_SCREEN_DIAGNOSTICS_STORAGE_TEST_SHORT, MOCK_IGNORE,
		     MOCK_IGNORE, MOCK_IGNORE, MOCK_IGNORE, MOCK_IGNORE);
	DISPLAYED_PASS();
	/* #3: Extended storage self-test screen */
	DISPLAYED_EQ("extended storage self-test button",
		     VB2_SCREEN_DIAGNOSTICS, MOCK_IGNORE, 3, MOCK_IGNORE,
		     MOCK_IGNORE, MOCK_IGNORE);
	DISPLAYED_EQ("#3: extended storage self-test screen",
		     VB2_SCREEN_DIAGNOSTICS_STORAGE_TEST_EXTENDED, MOCK_IGNORE,
		     MOCK_IGNORE, MOCK_IGNORE, MOCK_IGNORE, MOCK_IGNORE);
	DISPLAYED_PASS();
	/* #4: Quick memory test screen */
	DISPLAYED_EQ("quick memory test button", VB2_SCREEN_DIAGNOSTICS,
		     MOCK_IGNORE, 4, MOCK_IGNORE, MOCK_IGNORE, MOCK_IGNORE);
	DISPLAYED_EQ("#4: quick memory test screen",
		     VB2_SCREEN_DIAGNOSTICS_MEMORY_QUICK, MOCK_IGNORE,
		     MOCK_IGNORE, MOCK_IGNORE, MOCK_IGNORE, MOCK_IGNORE);
	DISPLAYED_PASS();
	/* #5: Full memory test screen */
	DISPLAYED_EQ("full memory test button", VB2_SCREEN_DIAGNOSTICS,
		     MOCK_IGNORE, 5, MOCK_IGNORE, MOCK_IGNORE, MOCK_IGNORE);
	DISPLAYED_EQ("#5: full memory test screen",
		     VB2_SCREEN_DIAGNOSTICS_MEMORY_FULL, MOCK_IGNORE,
		     MOCK_IGNORE, MOCK_IGNORE, MOCK_IGNORE, MOCK_IGNORE);
	DISPLAYED_PASS();
	/* #6: Power of (End of menu) */
	DISPLAYED_EQ("power off", VB2_SCREEN_DIAGNOSTICS, MOCK_IGNORE, 6,
		     MOCK_IGNORE, MOCK_IGNORE, MOCK_IGNORE);
	DISPLAYED_NO_EXTRA();

	/* Diagnostics screen: no nvme */
	reset_common_data(FOR_DIAGNOSTICS);
	/* Non-nvme storage returns UNIMPLEMENTED. */
	mock_diag_storage_test_rv = VB2_ERROR_EX_UNIMPLEMENTED;
	TEST_EQ(vb2_diagnostic_menu(ctx), VB2_REQUEST_SHUTDOWN,
		"diagnostic screen: check disabled item");
	DISPLAYED_EQ("diagnostic menu: self-test disabled",
		     VB2_SCREEN_DIAGNOSTICS, MOCK_IGNORE, MOCK_IGNORE, 0xc, 0x0,
		     MOCK_IGNORE);

	VB2_DEBUG("...done.\n");
}

int main(void)
{
	/* Screen displayed */
	diagnostics_screen_tests();

	return gTestSuccess ? 0 : 255;
}
